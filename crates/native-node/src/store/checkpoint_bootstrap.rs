//! Staged engineering checkpoint recovery from authenticated permanent records.
//! Prefix reconstruction is not proof verification: its authority is the pinned
//! quorum plus the exact authenticated prefix digest. Tail blocks always pass
//! through the production state transition and its supplied proof verifier.
use super::public_replay::reconstruct_public_effects;
use super::*;
use crate::{
    compact::CompactBlock,
    engineering_checkpoint::{CONFIRMATIONS, Certificate, Cursor, Roster},
    identity::NativeIdentity,
    p2p::Binding,
    storage_policy::{self, Role},
    wire::Hash,
};
use siworld_core::pow::Work;

const STAGED: TableDefinition<u64, &[u8]> = TableDefinition::new("checkpoint-bootstrap-records-v1");
const PREFIX_DOMAIN: &str = "siworld verified local proof retention v1";

/// Local resource limits, never chain-validity or proof-retention rules.
#[derive(Clone, Copy)]
pub struct BootstrapLimits {
    pub max_height: u64,
    pub max_download_bytes: u64,
    pub max_tail_blocks: u64,
}
impl Default for BootstrapLimits {
    fn default() -> Self {
        Self {
            max_height: 1_000_000,
            max_download_bytes: 16 * 1024 * 1024 * 1024,
            max_tail_blocks: 2048,
        }
    }
}

/// An absent, caller-selected staging database holds at most one decoded block
/// in memory. Dropping it removes only the same temporary file it created.
struct Staging {
    database: Option<Database>,
    path: std::path::PathBuf,
    file_identity: Option<File>,
}
impl Staging {
    fn new(path: &Path) -> Result<Self, String> {
        let (file, created) = open_regular_file(path, true)?;
        if !created {
            return Err("checkpoint staging path must be absent".into());
        }
        let mut staging = Self {
            database: None,
            path: path.to_owned(),
            file_identity: Some(file),
        };
        let backend_file = staging
            .file_identity
            .as_ref()
            .expect("new staging owner")
            .try_clone()
            .map_err(|_| "checkpoint staging identity unavailable")?;
        let backend = redb::backends::FileBackend::new(backend_file)
            .map_err(|_| "checkpoint staging backend unavailable")?;
        let mut builder = Database::builder();
        builder.set_cache_size(16 * 1024 * 1024);
        staging.database = Some(
            builder
                .create_with_backend(backend)
                .map_err(|_| "checkpoint staging database unavailable")?,
        );
        Ok(staging)
    }

    fn database(&self) -> &Database {
        self.database.as_ref().expect("live staging owner")
    }
    fn insert(&self, height: u64, bytes: &[u8], fingerprint: Hash) -> Result<(), String> {
        let mut record = Vec::with_capacity(bytes.len() + 32);
        record.extend_from_slice(bytes);
        record.extend_from_slice(&fingerprint);
        let transaction = self
            .database()
            .begin_write()
            .map_err(|_| "checkpoint staging write unavailable")?;
        transaction
            .open_table(STAGED)
            .map_err(|_| "checkpoint staging table unavailable")?
            .insert(height, record.as_slice())
            .map_err(|_| "checkpoint staging write failed")?;
        transaction
            .commit()
            .map_err(|_| "checkpoint staging commit failed".into())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        drop(self.database.take());
        // Close all handles before removing the file on Windows. Capture the
        // final identity through the still-open handle, never through its path.
        let opened = self
            .file_identity
            .take()
            .and_then(|file| file.metadata().ok());
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && opened
                    .as_ref()
                    .is_some_and(|before| same_file(before, &metadata))
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct CheckpointBootstrap {
    staging: Staging,
    roster: Roster,
    certificate: Certificate,
    state: State,
    checkpoint_state: Option<State>,
    prefix: blake3::Hasher,
    minimum_work: Work,
    limits: BootstrapLimits,
    downloaded: u64,
    failed: bool,
}
impl CheckpointBootstrap {
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        staging_path: &Path,
        config: Config,
        certificate: Certificate,
        roster: Roster,
        previous: Option<Cursor>,
        now: u64,
        minimum_work: Work,
        limits: BootstrapLimits,
    ) -> Result<Self, String> {
        let authenticated = certificate.authenticate(&roster, previous, now)?;
        if !authenticated.pruning_fresh(now)
            || certificate.statement.binding != Binding::new(&config)
            || certificate.statement.height > limits.max_height
            || limits.max_download_bytes == 0
            || limits.max_tail_blocks < CONFIRMATIONS
        {
            return Err("checkpoint bootstrap context, freshness or resource limit".into());
        }
        let initial = blake3::derive_key(
            "siworld engineering checkpoint permanent prefix v1",
            &config.genesis_id(),
        );
        let mut prefix =
            blake3::Hasher::new_derive_key("siworld engineering checkpoint permanent records v1");
        prefix.update(&initial);
        Ok(Self {
            staging: Staging::new(staging_path)?,
            roster,
            certificate,
            state: State::new(config)?,
            checkpoint_state: None,
            prefix,
            minimum_work,
            limits,
            downloaded: 0,
            failed: false,
        })
    }
    fn account(&mut self, bytes: usize) -> Result<(), String> {
        self.downloaded = self
            .downloaded
            .checked_add(bytes as u64)
            .filter(|n| *n <= self.limits.max_download_bytes)
            .ok_or("checkpoint download resource limit")?;
        Ok(())
    }
    /// Accept exactly one consecutive proof-free permanent record. The final
    /// prefix record must reproduce every signed summary field, not a remote
    /// serialized State cache. Any failure permanently poisons this session.
    pub fn push_permanent(&mut self, bytes: &[u8]) -> Result<(), String> {
        let result = self.push_permanent_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_permanent_inner(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.failed || self.checkpoint_state.is_some() {
            return Err("checkpoint prefix session is unavailable or complete".into());
        }
        self.account(bytes.len())?;
        let compact = CompactBlock::decode(bytes)?;
        let mut state = self.state.clone();
        reconstruct_public_effects(&mut state, &compact)?;
        self.prefix.update(&state.height.to_le_bytes());
        self.prefix.update(blake3::hash(bytes).as_bytes());
        if state.height == self.certificate.statement.height {
            let expected = engineering_checkpoint::summary(
                &state,
                &self.roster,
                self.certificate.statement.sequence,
                self.certificate.statement.issued_unix_seconds,
                *self.prefix.finalize().as_bytes(),
            )?;
            if expected.statement() != &self.certificate.statement {
                return Err("urgent checkpoint permanent reconstruction mismatch".into());
            }
            self.checkpoint_state = Some(state.clone());
        }
        self.staging
            .insert(state.height, bytes, state.fingerprint())?;
        self.state = state;
        Ok(())
    }
    /// Proofs beyond the checkpoint are never skipped or replaced by signatures.
    pub fn push_tail(
        &mut self,
        block: &Block,
        verifier: &impl BlockVerifier,
    ) -> Result<(), String> {
        let result = self.push_tail_inner(block, verifier);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_tail_inner(
        &mut self,
        block: &Block,
        verifier: &impl BlockVerifier,
    ) -> Result<(), String> {
        if self.failed || self.checkpoint_state.is_none() {
            return Err("checkpoint prefix has not been reconstructed".into());
        }
        if block.height > self.limits.max_height
            || block
                .height
                .saturating_sub(self.certificate.statement.height)
                > self.limits.max_tail_blocks
        {
            return Err("checkpoint tail resource limit".into());
        }
        let bytes = block.encode()?;
        self.account(bytes.len())?;
        let mut state = self.state.clone();
        state.apply(block, verifier)?;
        self.staging
            .insert(state.height, &bytes, state.fingerprint())?;
        self.state = state;
        Ok(())
    }
    pub fn progress(&self) -> (u64, u64, u64) {
        (
            self.state.height,
            self.certificate.statement.height,
            self.downloaded,
        )
    }
    /// Measure the authenticated prefix representation without adopting it or
    /// treating the incomplete proof tail as a usable node state.
    pub fn verified_prefix_metrics(&self) -> Result<serde_json::Value, String> {
        let state = self
            .checkpoint_state
            .as_ref()
            .filter(|_| !self.failed)
            .ok_or("checkpoint prefix has not been authenticated")?;
        let start = std::time::Instant::now();
        let bytes = checkpoint::encode(state)?;
        Ok(
            serde_json::json!({"height":state.height,"state_bytes":bytes.len(),
            "state_encode_ms":start.elapsed().as_millis(),"prefix_bytes":self.downloaded,
            "state_fingerprint":crate::local::hex(&state.fingerprint()),"tail_verified":false}),
        )
    }
    /// Staged progress only; this state has no adoption capability until finish.
    #[cfg(feature = "native-p2p")]
    pub(crate) fn staged_state(&self) -> &State {
        &self.state
    }
    /// Select only a verified branch exceeding the caller's best observed work.
    /// No network protocol can demonstrate the absence of an unseen stronger
    /// branch; callers keep ordinary peer/work comparison active after adoption.
    pub fn finish(self) -> Result<VerifiedBootstrap, String> {
        if self.failed
            || self.checkpoint_state.is_none()
            || self
                .state
                .height
                .saturating_sub(self.certificate.statement.height)
                < CONFIRMATIONS
            || self.state.cumulative_work <= self.minimum_work
        {
            return Err("checkpoint tail is incomplete or not the greatest observed work".into());
        }
        Ok(VerifiedBootstrap {
            staging: self.staging,
            certificate: self.certificate,
            state: self.state,
            checkpoint_state: self.checkpoint_state.expect("checked reconstructed prefix"),
            downloaded: self.downloaded,
        })
    }
}

/// Opaque capability produced only by quorum authentication, prefix
/// reconstruction, independently verified work and complete proof-tail replay.
pub struct VerifiedBootstrap {
    staging: Staging,
    certificate: Certificate,
    state: State,
    checkpoint_state: State,
    downloaded: u64,
}
impl VerifiedBootstrap {
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn downloaded_bytes(&self) -> u64 {
        self.downloaded
    }
    pub fn checkpoint_height(&self) -> u64 {
        self.checkpoint_state.height
    }
}

impl Store {
    /// Qualify an existing legacy store without replaying proofs covered by a
    /// pinned checkpoint quorum. The public prefix is reconstructed and its
    /// complete signed summary checked; every checkpoint-to-head proof is
    /// verified. The resulting state must exactly match the existing committed
    /// head. Canonical history, proof retention and rewards are not rewritten.
    /// The caller must hold the exclusive service lease for this directory.
    #[allow(clippy::too_many_arguments)]
    pub fn qualify_restart_existing(
        path: &Path,
        config: Config,
        certificate: Certificate,
        roster: Roster,
        now: u64,
        staging_path: &Path,
        mut permanent: impl FnMut(u64) -> Result<Vec<u8>, String>,
        verifier: &impl BlockVerifier,
    ) -> Result<serde_json::Value, String> {
        config.validate()?;
        let (file, _) = open_regular_file(path, false)?;
        let receipt_owner = receipts::Owner::bind(path, &file)?;
        let mut builder = Database::builder();
        builder.set_cache_size(32 * 1024 * 1024);
        builder.set_repair_callback(|session| session.abort());
        let database = builder
            .create_with_backend(
                redb::backends::FileBackend::new(file)
                    .map_err(|_| "restart qualification backend unavailable")?,
            )
            .map_err(|_| "restart qualification database is active or damaged")?;
        let context = resume::Context::new(path, &config)?
            .ok_or("restart qualification requires existing persistent identity")?;
        if resume::load(&database, path, &config)?.is_some() {
            return Err("store already has an authenticated restart record".into());
        }
        let mut store = Self {
            database,
            state: State::new(config.clone())?,
            receipt_owner,
            path: path.to_owned(),
            storage_base: None,
            retention_clock_started: false,
            checkpoint_pruning: storage_policy::CheckpointPruning::default(),
            resume_cache: None,
        };
        let previous = store.checkpoint_cursor()?;
        let mut session = CheckpointBootstrap::begin(
            staging_path,
            config.clone(),
            certificate.clone(),
            roster,
            previous,
            now,
            Work::zero(),
            BootstrapLimits::default(),
        )?;
        let transaction = store
            .database
            .begin_read()
            .map_err(|_| "restart qualification read unavailable")?;
        let indexed = validate_tables(
            transaction
                .list_tables()
                .map_err(|_| "restart schema unreadable")?,
            transaction
                .list_multimap_tables()
                .map_err(|_| "restart schema unreadable")?
                .next()
                .is_some(),
        )?;
        if !indexed {
            return Err("restart qualification requires indexed local rewards".into());
        }
        let meta = transaction
            .open_table(META)
            .map_err(|_| "restart metadata unavailable")?;
        check_index_marker(&meta, indexed)?;
        if meta
            .get("config")
            .map_err(|_| "restart configuration unavailable")?
            .ok_or("restart configuration missing")?
            .value()
            != configuration(&config)
        {
            return Err("restart qualification configuration mismatch".into());
        }
        let saved = meta
            .get("head")
            .map_err(|_| "restart committed head unavailable")?
            .ok_or("restart committed head missing")?;
        let saved: [u8; HEAD_BYTES] = saved
            .value()
            .try_into()
            .map_err(|_| "restart committed head invalid")?;
        let height = u64::from_le_bytes(saved[..8].try_into().expect("bounded height"));
        let checkpoint_height = certificate.statement.height;
        if height > BootstrapLimits::default().max_height
            || height < checkpoint_height.saturating_add(CONFIRMATIONS)
        {
            return Err("restart qualification head is outside checkpoint tail limits".into());
        }
        let blocks = transaction
            .open_table(BLOCKS)
            .map_err(|_| "restart history unavailable")?;
        if blocks
            .len()
            .map_err(|_| "restart history count unavailable")?
            != height
        {
            return Err("restart history count differs from committed head".into());
        }
        for next in 1..=checkpoint_height {
            session.push_permanent(&permanent(next)?)?;
        }
        for next in checkpoint_height + 1..=height {
            let row = blocks
                .get(next)
                .map_err(|_| "restart tail unreadable")?
                .ok_or("restart tail missing")?;
            let (bytes, fingerprint) = split_record(row.value())?;
            let block = Block::decode(bytes, &config.network)?;
            session.push_tail(&block, verifier)?;
            if session.state.fingerprint().as_slice() != fingerprint {
                return Err("restart qualification tail fingerprint mismatch".into());
            }
        }
        let bootstrap = session.finish()?;
        if head(&bootstrap.state) != saved {
            return Err("restart qualification differs from exact committed head".into());
        }
        // Independently bind the anchor to the local row, not an export cursor.
        let row = blocks
            .get(height)
            .map_err(|_| "restart head anchor unavailable")?
            .ok_or("restart head anchor missing")?;
        if public_record(split_record(row.value())?.0, &config.network)?.1 != bootstrap.state.tip {
            return Err("restart qualification local head identity mismatch".into());
        }
        store.state = bootstrap.state.clone();
        let mut context = context;
        let source = bootstrap
            .staging
            .database()
            .begin_read()
            .map_err(|_| "restart verified prefix unavailable")?;
        let staged = source
            .open_table(STAGED)
            .map_err(|_| "restart verified records unavailable")?;
        context.collect_rewards_from(&store, &staged)?;
        store.resume_cache = Some(context);
        // persist_resume checks the exact head again in the immediate write.
        store.persist_resume()?;
        if store.resume_cache.is_none() {
            return Err("qualified state exceeds optional restart capacity".into());
        }
        let (sealed_state, sealed_context) = resume::load(&store.database, path, &config)?
            .ok_or("qualified restart record missing after commit")?;
        if head(&sealed_state) != head(&store.state) {
            return Err("qualified restart record changed after commit".into());
        }
        for reward in sealed_context.rewards.values() {
            reward.validate(&store)?;
        }
        let cache_read = store
            .database
            .begin_read()
            .map_err(|_| "restart metrics unavailable")?;
        let cache_table = cache_read
            .open_table(resume::RESUME)
            .map_err(|_| "restart metrics unavailable")?;
        let state_bytes = cache_table
            .get("state")
            .map_err(|_| "restart metrics unavailable")?
            .ok_or("restart state missing")?
            .value()
            .len();
        let reward_bytes = cache_table
            .get("rewards")
            .map_err(|_| "restart metrics unavailable")?
            .ok_or("restart rewards missing")?
            .value()
            .len();
        Ok(
            serde_json::json!({"schema":1,"height":height,"checkpoint_height":checkpoint_height,
            "verified_tail_blocks":height-checkpoint_height,"local_reward_witnesses":store.resume_cache.as_ref().expect("qualified cache").rewards.len(),
            "state_fingerprint":crate::local::hex(&store.state.fingerprint()),"canonical_history_rewritten":false,
            "tip":crate::local::hex(&store.state.tip),"cumulative_work":crate::local::hex(&store.state.cumulative_work.to_big_endian()),
            "restart_cache_verified":true,
            "restart_state_bytes":state_bytes,"restart_reward_bytes":reward_bytes}),
        )
    }

    /// Atomically adopt a fresh or genuinely stale local node. A running node
    /// never uses a checkpoint to overwrite a divergent locally verified state.
    /// Existing local reward ownership and all permanent records remain intact.
    pub fn adopt_engineering_bootstrap(
        &mut self,
        bootstrap: VerifiedBootstrap,
        now: u64,
    ) -> Result<u64, String> {
        if bootstrap.state.config != self.state.config
            || bootstrap.state.cumulative_work <= self.state.cumulative_work
            || now
                .checked_sub(bootstrap.certificate.statement.issued_unix_seconds)
                .is_none_or(|age| age > crate::engineering_checkpoint::MAX_AGE_SECONDS)
        {
            return Err("checkpoint adoption context, work or freshness mismatch".into());
        }
        if let Some(previous) = self.latest_engineering_checkpoint()? {
            let before = &previous.statement;
            let after = &bootstrap.certificate.statement;
            if after.sequence < before.sequence
                || after.height < before.height
                || (after.sequence == before.sequence && after.digest() != before.digest())
            {
                return Err("checkpoint adoption sequence rollback or equivocation".into());
            }
        }
        let role = self.storage_role()?.unwrap_or(Role::Ordinary);
        let keep = self
            .local_proof_blocks()?
            .unwrap_or(storage_policy::LOCAL_PROOF_BLOCKS);
        if self.state.height > 0
            && (self.state.height > bootstrap.checkpoint_state.height
                || (!role.serves_historical_proofs()
                    && self
                        .state
                        .height
                        .checked_add(keep)
                        .is_none_or(|n| n > bootstrap.state.height)))
        {
            return Err("checkpoint adoption would replace a protected proof window; use ordinary synchronization".into());
        }
        self.verify_local_rewards()?;
        let source = bootstrap
            .staging
            .database()
            .begin_read()
            .map_err(|_| "checkpoint staging read unavailable")?;
        let staged = source
            .open_table(STAGED)
            .map_err(|_| "checkpoint staging records unavailable")?;
        // Require exact overlap. A signed competing checkpoint is an alarm,
        // never an automatic reorganization of this node's already verified state.
        for height in 1..=self.state.height {
            let row = staged
                .get(height)
                .map_err(|_| "checkpoint overlap unavailable")?
                .ok_or("checkpoint overlap missing")?;
            let (_, id) = public_record(split_record(row.value())?.0, &self.state.config.network)?;
            if id != self.canonical_id(height)? {
                return Err(
                    "urgent checkpoint differs from independently verified local history".into(),
                );
            }
        }
        let signer = NativeIdentity::load(
            self.path
                .parent()
                .ok_or("checkpoint identity parent unavailable")?,
            &Binding::new(&self.state.config),
        )
        .map_err(|_| "checkpoint adoption requires existing persistent identity")?;
        let mut prefix = blake3::derive_key(PREFIX_DOMAIN, &self.state.config.genesis_id());
        for height in 1..=bootstrap.checkpoint_state.height {
            let row = staged
                .get(height)
                .map_err(|_| "checkpoint prefix unavailable")?
                .ok_or("checkpoint prefix missing")?;
            let mut hash = blake3::Hasher::new_derive_key(PREFIX_DOMAIN);
            hash.update(&prefix);
            hash.update(&height.to_le_bytes());
            hash.update(blake3::hash(row.value()).as_bytes());
            prefix = *hash.finalize().as_bytes();
        }
        let encoding = checkpoint::encode(&bootstrap.checkpoint_state)?;
        let mut payload = role.name().as_bytes().to_vec();
        payload.push(0);
        payload.extend_from_slice(&prefix);
        payload.extend_from_slice(&encoding);
        let seal = signer
            .seal_local_storage(blake3::derive_key(PREFIX_DOMAIN, &payload))
            .map_err(|_| "checkpoint adoption local seal failed")?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "checkpoint adoption transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "checkpoint adoption durability unavailable")?;
        {
            let mut blocks = transaction
                .open_table(BLOCKS)
                .map_err(|_| "checkpoint adoption history unavailable")?;
            let mut finality = transaction
                .open_table(retention::FINALITY)
                .map_err(|_| "checkpoint adoption finality unavailable")?;
            let preserve = role.serves_historical_proofs() && self.state.height > 0;
            let mut protected = if preserve {
                Some(
                    transaction
                        .open_table(super::protected_history::PROTECTED)
                        .map_err(|_| "checkpoint protected history unavailable")?,
                )
            } else {
                None
            };
            if let Some(index) = protected.as_mut() {
                // Conservatively restart the service clock at recovery. No
                // unobserved offline time can shorten a retained proof window.
                index
                    .insert(0, now.max(1).to_le_bytes().as_slice())
                    .map_err(|_| "checkpoint protected recovery clock write failed")?;
            }
            for row in staged
                .iter()
                .map_err(|_| "checkpoint staging iteration unavailable")?
            {
                let (height, row) = row.map_err(|_| "checkpoint staging row unavailable")?;
                let height = height.value();
                let (bytes, _) = split_record(row.value())?;
                let (block, id) = public_record(bytes, &self.state.config.network)?;
                let previous = if preserve && height <= self.state.height {
                    Some(
                        blocks
                            .get(height)
                            .map_err(|_| "checkpoint retained history unavailable")?
                            .ok_or("checkpoint retained history missing")?
                            .value()
                            .to_vec(),
                    )
                } else {
                    None
                };
                let protected_bytes = if let Some(previous) = previous
                    .as_deref()
                    .filter(|record| !record.starts_with(b"SWLC0001"))
                {
                    let (normalized, old_id) =
                        super::protected_history::normalized_record(previous)?;
                    if normalized != row.value() || old_id != id {
                        return Err(
                            "checkpoint retained proof differs from verified state fingerprint"
                                .into(),
                        );
                    }
                    let accounting = finality
                        .get(height)
                        .map_err(|_| "checkpoint retained proof accounting unavailable")?
                        .ok_or("checkpoint retained proof accounting missing")?;
                    if accounting.value().len() != 48 || accounting.value()[..32] != id {
                        return Err("checkpoint retained proof accounting mismatch".into());
                    }
                    let proof_bytes = u64::from_le_bytes(
                        accounting.value()[40..48]
                            .try_into()
                            .expect("checked accounting"),
                    );
                    if proof_bytes == 0 {
                        return Err("checkpoint retained proof accounting is empty".into());
                    }
                    protected
                        .as_mut()
                        .expect("service proof preservation")
                        .insert(
                            height,
                            super::protected_history::marker(&normalized, id).as_slice(),
                        )
                        .map_err(|_| "checkpoint protected history write failed")?;
                    Some(proof_bytes)
                } else {
                    None
                };
                if protected_bytes.is_none() {
                    blocks
                        .insert(height, row.value())
                        .map_err(|_| "checkpoint history write failed")?;
                }
                let proof_bytes = if let Some(bytes) = protected_bytes {
                    bytes
                } else if height <= bootstrap.checkpoint_state.height {
                    0
                } else {
                    block
                        .transactions
                        .iter()
                        .map(|tx| tx.proof.len() as u64)
                        .chain(block.issuances.iter().map(|item| item.proof.len() as u64))
                        .try_fold(block.settlement_proof.len() as u64, |a, b| a.checked_add(b))
                        .ok_or("checkpoint proof accounting overflow")?
                };
                let mut observation = id.to_vec();
                observation.extend_from_slice(
                    &if protected_bytes.is_some() {
                        now.max(1)
                    } else {
                        0
                    }
                    .to_le_bytes(),
                );
                observation.extend_from_slice(&proof_bytes.to_le_bytes());
                finality
                    .insert(height, observation.as_slice())
                    .map_err(|_| "checkpoint finality write failed")?;
            }
        }
        {
            let mut storage = transaction
                .open_table(retention::STORAGE)
                .map_err(|_| "checkpoint storage policy unavailable")?;
            for (key, bytes) in [
                ("role", role.name().as_bytes()),
                ("prefix", prefix.as_slice()),
                ("base", encoding.as_slice()),
                ("seal", seal.as_slice()),
                ("last_clock", &now.to_le_bytes()),
            ] {
                storage
                    .insert(key, bytes)
                    .map_err(|_| "checkpoint storage policy write failed")?;
            }
        }
        transaction
            .open_table(engineering_checkpoint::ATTESTATIONS)
            .map_err(|_| "checkpoint attestation storage unavailable")?
            .insert("accepted", bootstrap.certificate.encode()?.as_slice())
            .map_err(|_| "checkpoint attestation write failed")?;
        transaction
            .open_table(META)
            .map_err(|_| "checkpoint head unavailable")?
            .insert("head", head(&bootstrap.state).as_slice())
            .map_err(|_| "checkpoint head write failed")?;
        let mut next_rewards = self
            .resume_cache
            .as_ref()
            .map(|cache| cache.rewards.clone());
        if let Some(rewards) = &mut next_rewards {
            for reward in rewards.values_mut() {
                reward.canonical = staged
                    .get(reward.height)
                    .map_err(|_| "checkpoint restart reward unavailable")?
                    .map(|row| {
                        public_record(split_record(row.value())?.0, &self.state.config.network)
                    })
                    .transpose()?
                    .is_some_and(|(_, id)| id == reward.id);
            }
        }
        let persisted = if let (Some(cache), Some(rewards)) = (&self.resume_cache, &next_rewards) {
            cache.write(&transaction, &bootstrap.state, rewards)?
        } else {
            false
        };
        transaction
            .commit()
            .map_err(|_| "checkpoint adoption commit failed")?;
        self.state = bootstrap.state;
        if !persisted {
            self.resume_cache = None;
        } else if let (Some(cache), Some(rewards)) = (&mut self.resume_cache, next_rewards) {
            cache.rewards = rewards;
        }
        self.storage_base = Some(bootstrap.checkpoint_state);
        self.retention_clock_started = false;
        Ok(bootstrap.downloaded)
    }
}

#[cfg(test)]
mod tests;
