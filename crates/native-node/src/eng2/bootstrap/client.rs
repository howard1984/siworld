//! Explicit signed-bootstrap acquisition. Quarantine and verified header work
//! never become accepted state; only native verification and durable install do.
use super::{
    MAX_CHUNK_BYTES, Manifest, Object,
    cache::{HeaderHistory, Quarantine},
};
use crate::{
    eng2::{
        admission::AdmissionPlan,
        body,
        genesis::{FeeMode, Genesis},
        import::{self, Installation},
        network::{BootstrapPull, Error},
        selection::{HeaderRules, VerifiedHeaders},
        store::Store,
        transport::ChunkRequest,
    },
    wire::Hash,
};
use siworld_core::pow::Work;
use std::{
    io::{Read, Write},
    path::Path,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Headers { next: u64, total: u64 },
    Snapshot { received: u64, total: u64 },
    Receipts { next: u64, total: u64 },
    NativeTail { next: u64, total: u64 },
    Downloaded,
}

/// A supplied candidate is immutable for the lifetime of this acquisition.
/// Reconnects must use the exact manifest required by Quarantine::reopen.
pub struct Candidate {
    cache: Quarantine,
    next_header: u64,
    import_policy: import::Policy,
    body_policy: body::Policy,
    binding: crate::p2p::Binding,
}

impl Candidate {
    pub fn new(
        cache: Quarantine,
        genesis: &Genesis,
        import_policy: import::Policy,
        body_policy: body::Policy,
    ) -> Result<Self, String> {
        if genesis.fee_mode() != FeeMode::LegacyMiner
            || import_policy.max_headers == 0
            || import_policy.max_verification_bytes == 0
            || body_policy.profile != crate::proofs::protocol_profile_fingerprint()
            || body_policy.max_body_bytes == 0
            || body_policy.max_settlement_proof_bytes == 0
        {
            return Err("signed bootstrap client policy or genesis mode rejected".into());
        }
        let manifest = Manifest::decode(&cache.manifest().encode()?, genesis, import_policy.state)?;
        if manifest.tip_height > import_policy.max_headers as u64 {
            return Err("bootstrap candidate exceeds complete header limit".into());
        }
        let next_header = cache.next_header()?;
        Ok(Self {
            cache,
            next_header,
            import_policy,
            body_policy,
            binding: genesis.peer_binding(),
        })
    }
    pub fn manifest(&self) -> &Manifest {
        self.cache.manifest()
    }
    pub fn progress(&self) -> Progress {
        Progress::Headers {
            next: self.next_header,
            total: self.manifest().tip_height,
        }
    }
    /// Exactly one ordinary request. The caller always completes the ordinary,
    /// checkpoint and transaction phases before scheduling the next step.
    pub fn pull_header<S: Read + Write>(
        &mut self,
        pull: &mut BootstrapPull<'_, S>,
    ) -> Result<(), Error> {
        if self.next_header > self.manifest().tip_height {
            return Ok(());
        }
        let header = pull.header(self.next_header)?.ok_or(Error::Unavailable)?;
        if header.height != self.next_header {
            return Err(Error::Protocol);
        }
        self.cache.put_header(&header).map_err(Error::Owner)?;
        self.next_header += 1;
        Ok(())
    }
    /// Validate the complete acquired PoW history, including every difficulty
    /// transition. This still grants no snapshot, certificate or state authority.
    pub fn prepare(self, genesis: &Genesis, floor: Work) -> Result<Prepared, String> {
        if self.next_header <= self.manifest().tip_height {
            return Err("bootstrap complete header acquisition is unfinished".into());
        }
        let history = self.cache.headers()?;
        let config = genesis.config();
        let headers = VerifiedHeaders::verify(
            HeaderRules {
                network: config.network,
                genesis: genesis.id(),
                genesis_timestamp: config.genesis_timestamp,
                genesis_target: config.genesis_target,
                target_interval: config.target_interval,
                pow_iterations: config.pow_iterations,
                max_headers: self.import_policy.max_headers,
            },
            history.headers.clone(),
        )
        .map_err(|_| "bootstrap complete header history rejected")?;
        let manifest = self.manifest();
        if headers.height() != manifest.tip_height
            || headers
                .id(headers.height())
                .map_err(|_| "bootstrap header tip unavailable")?
                != manifest.tip_id
            || headers.cumulative_work() != manifest.cumulative_work
        {
            return Err("bootstrap advertised work or tip differs from verified headers".into());
        }
        let plan = AdmissionPlan::select_signed(&[&headers], floor)
            .and_then(|p| {
                p.at_checkpoint(
                    manifest.checkpoint_height(),
                    manifest.checkpoint_height() + 1,
                    manifest.tip_height,
                )
            })
            .map_err(|_| "bootstrap checkpoint range or local work floor rejected")?;
        Ok(Prepared {
            candidate: self,
            plan,
            _history: history,
        })
    }
}

pub struct Prepared {
    candidate: Candidate,
    plan: AdmissionPlan,
    // Keep the original acquisition charge while verified plans own headers.
    _history: HeaderHistory,
}

/// Selection is explicit over all supplied complete candidates. Equal-work
/// forks fail closed; an invalid selected certificate never causes a silent
/// fallback to a lower-work candidate.
pub fn select(candidates: Vec<Prepared>, floor: Work) -> Result<Client, String> {
    if candidates.is_empty() || candidates.len() > 64 {
        return Err("bootstrap candidate count exceeds selection bound".into());
    }
    let headers: Vec<_> = candidates.iter().map(|c| c.plan.headers()).collect();
    let selected = AdmissionPlan::select_signed(&headers, floor)
        .map_err(|_| "bootstrap greatest-work candidate selection rejected")?;
    let tip = selected.pin().tip_id;
    let prepared = candidates
        .into_iter()
        .filter(|p| p.plan.pin().tip_id == tip)
        .max_by_key(|p| p.candidate.manifest().checkpoint_height())
        .ok_or("bootstrap selected candidate unavailable")?;
    let manifest = prepared.candidate.manifest();
    let plan = selected
        .at_checkpoint(
            manifest.checkpoint_height(),
            manifest.checkpoint_height() + 1,
            manifest.tip_height,
        )
        .map_err(|_| "bootstrap selected checkpoint availability rejected")?;
    let mut client = Client {
        candidate: prepared.candidate,
        plan,
        _history: prepared._history,
        next_object: 0,
        body_scope: None,
        current_body: None,
    };
    client.advance()?;
    Ok(client)
}

/// Downloaded data remains unadmitted and cannot expose an accepted Store,
/// signing handle, mining readiness or a nonzero advertised chain head.
pub struct Client {
    candidate: Candidate,
    plan: AdmissionPlan,
    _history: HeaderHistory,
    next_object: u64,
    body_scope: Option<crate::p2p::BodyScope>,
    current_body: Option<crate::p2p::BodyAuthorization>,
}
pub struct Admission {
    pub installation: Installation,
    /// Logical importer inputs, excluding headers and installation rereads.
    pub verification_bytes: u64,
    /// All cache object rereads, including preparation and installation. This
    /// value excludes network I/O and is never reported as downloaded bytes.
    pub local_reread_bytes: u64,
    pub verification_ms: u128,
    pub installation_ms: u128,
    pub authenticated_reopen_ms: u128,
}
impl Client {
    /// Bind one explicit acquisition operation after immutable plan selection.
    /// Reconnects and repeated pull steps retain this original deadline.
    pub fn bind_body_operation(
        &mut self,
        budget: &crate::p2p::Budget,
        expires: Instant,
    ) -> Result<(), String> {
        if self.body_scope.is_some() || self.current_body.is_some() {
            return Err("bootstrap body operation already bound".into());
        }
        self.body_scope = Some(
            budget
                .bootstrap_body_scope(expires)
                .map_err(|_| "bootstrap original body operation unavailable")?,
        );
        Ok(())
    }
    /// End the original operation without refunding or reopening its accounts.
    pub fn cancel_body_operation(&mut self) {
        if let Some(scope) = &self.body_scope {
            scope.close();
        }
        self.current_body = None;
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn operation_body_scope(&self) -> Result<crate::p2p::BodyScope, String> {
        self.body_scope
            .clone()
            .ok_or("bootstrap body operation not bound".into())
    }
    pub fn manifest(&self) -> &Manifest {
        self.candidate.manifest()
    }
    pub fn selected_tip(&self) -> (u64, Hash) {
        (self.plan.pin().tip_height, self.plan.pin().tip_id)
    }
    pub fn progress(&self) -> Result<Progress, String> {
        if self.next_object == 0 {
            return Ok(Progress::Snapshot {
                received: self.candidate.cache.progress(Object::Snapshot)?,
                total: self.manifest().snapshot.length,
            });
        }
        if self.next_object <= self.manifest().checkpoint_height() {
            return Ok(Progress::Receipts {
                next: self.next_object,
                total: self.manifest().checkpoint_height(),
            });
        }
        if self.next_object <= self.plan.pin().tip_height {
            return Ok(Progress::NativeTail {
                next: self.next_object,
                total: self.plan.pin().tip_height,
            });
        }
        Ok(Progress::Downloaded)
    }
    fn advance(&mut self) -> Result<(), String> {
        while self.next_object <= self.plan.pin().tip_height {
            if !self
                .candidate
                .cache
                .progress_at(self.next_object)?
                .is_some_and(|(received, total)| received == total && total > 0)
            {
                break;
            }
            self.next_object += 1;
        }
        Ok(())
    }
    pub fn pull_step<S: Read + Write>(
        &mut self,
        pull: &mut BootstrapPull<'_, S>,
    ) -> Result<Progress, Error> {
        let progress = self.progress().map_err(Error::Owner)?;
        let object = match progress {
            Progress::Snapshot { .. } => Some(Object::Snapshot),
            Progress::Receipts { next, .. } => Some(Object::Receipt {
                height: next,
                id: self.plan.headers().id(next).map_err(|_| Error::Protocol)?,
            }),
            Progress::NativeTail { next, .. } => {
                let header = self.plan.headers().header(next).ok_or(Error::Protocol)?;
                if self.current_body.is_none() {
                    let scope = self.body_scope.as_ref().ok_or(Error::Protocol)?;
                    self.current_body =
                        Some(pull.authorize_body(scope, self.candidate.binding, header)?);
                }
                let authorization = self.current_body.as_ref().ok_or(Error::Protocol)?;
                let body = pull
                    .body_authorized(header, authorization)?
                    .ok_or(Error::Unavailable)?;
                let encoded = body
                    .body
                    .encode(self.candidate.body_policy)
                    .map_err(Error::Owner)?;
                body.ownership.check_active()?;
                self.candidate
                    .cache
                    .put_body(header, &encoded)
                    .map_err(Error::Owner)?;
                body.ownership.complete();
                drop(body);
                self.current_body = None;
                None
            }
            Progress::Downloaded => None,
            Progress::Headers { .. } => return Err(Error::Protocol),
        };
        if let Some(object) = object {
            let offset = self
                .candidate
                .cache
                .progress(object)
                .map_err(Error::Owner)?;
            let received = pull
                .chunk(ChunkRequest {
                    bundle: self.manifest().bundle(),
                    object,
                    offset,
                    maximum: MAX_CHUNK_BYTES as u32,
                })?
                .ok_or(Error::Unavailable)?;
            self.candidate
                .cache
                .push(object, offset, &received.chunk)
                .map_err(Error::Owner)?;
        }
        self.advance().map_err(Error::Owner)?;
        self.progress().map_err(Error::Owner)
    }
    /// Durable success additionally requires authenticated canonical reopen.
    /// This grants no network readiness; the caller must catch up through the
    /// normal native round before attaching mining. Errors preserve quarantine.
    pub fn verify_and_install(
        mut self,
        genesis: &Genesis,
        directory: &Path,
        canceled: impl Fn() -> bool,
    ) -> Result<Admission, String> {
        if self.progress()? != Progress::Downloaded {
            return Err("bootstrap artifact acquisition is unfinished".into());
        }
        let snapshot = self.candidate.cache.snapshot()?;
        let certificate = self
            .manifest()
            .certificate
            .encode()
            .map_err(|_| "bootstrap certificate encoding rejected")?;
        let witness = self
            .manifest()
            .witness
            .encode(self.candidate.import_policy.state.chain.max_component_bytes)
            .map_err(|_| "bootstrap witness encoding rejected")?;
        let genesis_bytes = genesis.encode()?;
        let (installation, verification_bytes, verification_ms, installation_ms) = {
            let mut source = self.candidate.cache.source()?;
            let started = Instant::now();
            let verified = import::verify(
                import::Input {
                    genesis: &genesis_bytes,
                    pinned_genesis: genesis.id(),
                    plan: &self.plan,
                    certificate: &certificate,
                    witness: &witness,
                    snapshot: &snapshot.bytes,
                },
                &mut source,
                self.candidate.import_policy,
                &canceled,
            )?;
            let verification_ms = started.elapsed().as_millis();
            let verification_bytes = verified.verification_bytes();
            let started = Instant::now();
            let installation = verified.install(directory, &mut source, canceled)?;
            (
                installation,
                verification_bytes,
                verification_ms,
                started.elapsed().as_millis(),
            )
        };
        // Installation has crossed the no-replace boundary. A failed reopen is
        // never a retryable input error or permission to replace canonical data.
        let reopen_started = Instant::now();
        let installation = match installation {
            Installation::DurabilityUnconfirmed => Installation::DurabilityUnconfirmed,
            Installation::Durable(store) => {
                drop(store);
                let reopened = (|| {
                    let store = Store::resume_existing(
                        &directory.join("chain.redb"),
                        Genesis::decode(&genesis_bytes)?,
                        self.candidate.import_policy.state.chain,
                    )?;
                    let pin = self.plan.pin();
                    let state = store.engine().state();
                    let expected = self
                        .plan
                        .headers()
                        .header(pin.tip_height)
                        .ok_or("bootstrap selected final header unavailable")?;
                    if state.height() != pin.tip_height
                        || state.tip() != pin.tip_id
                        || state.chain().cumulative_work != pin.cumulative_work
                        || store.header(pin.tip_height)? != *expected
                        || store.imported_checkpoint_height() != Some(pin.anchor_height)
                    {
                        return Err("bootstrap authenticated reopened state differs".to_owned());
                    }
                    Ok(store)
                })();
                match reopened {
                    Ok(store) => Installation::Durable(Box::new(store)),
                    Err(_) => Installation::DurabilityUnconfirmed,
                }
            }
        };
        Ok(Admission {
            installation,
            verification_bytes,
            local_reread_bytes: self.candidate.cache.local_reread_bytes(),
            verification_ms,
            installation_ms,
            authenticated_reopen_ms: reopen_started.elapsed().as_millis(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eng2::{
            bootstrap::{Chunk, Descriptor, cache},
            header::Header,
        },
        p2p,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "signed-client-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(!path.exists());
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if self.0.exists() {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }
    // Header/framing fixtures have no valid native proofs or checkpoint
    // signatures. They cannot stand in for a completed admission rehearsal.
    fn fixture(directory: &Directory, count: u64, tag: u8) -> (Genesis, Candidate) {
        fixture_claim(directory, count, tag, Work::from(count))
    }
    fn fixture_claim(
        directory: &Directory,
        count: u64,
        tag: u8,
        claimed: Work,
    ) -> (Genesis, Candidate) {
        fixture_content(directory, count, tag, claimed, 1024 * 1024, false)
    }
    fn fixture_content(
        directory: &Directory,
        count: u64,
        tag: u8,
        claimed: Work,
        cache_body_limit: usize,
        framed_tail: bool,
    ) -> (Genesis, Candidate) {
        let (genesis, limits, mut manifest) = super::super::tests::framing_fixture();
        let config = genesis.config();
        let mut parent = genesis.id();
        let headers: Vec<_> = (1..=count)
            .map(|height| {
                let header = Header {
                    network: config.network,
                    height,
                    parent,
                    timestamp: config.genesis_timestamp + 300 * height,
                    target: [255; 32],
                    execution_commitment: [tag; 32],
                    body_commitment: if framed_tail && height > 72 {
                        tail_body(&genesis, height)
                            .commitment(tail_policy())
                            .unwrap()
                    } else {
                        [tag; 32]
                    },
                    nonce: 0,
                };
                parent = header.id().unwrap();
                header
            })
            .collect();
        manifest.tip_height = count;
        manifest.tip_id = parent;
        manifest.cumulative_work = claimed;
        manifest.certificate.statement.checkpoint_block = headers[71].id().unwrap();
        manifest.certificate.statement.authorization_block = headers[95].id().unwrap();
        manifest.bundle = *blake3::hash(&manifest.prefix().unwrap()).as_bytes();
        let cache = Quarantine::create(
            &directory.0,
            manifest,
            cache::Policy {
                max_bytes: if framed_tail {
                    // Include the complete synthetic tail in this fixture's
                    // quarantine byte budget without changing production limits.
                    (count - 72)
                        * tail_body(&genesis, 73).encoded_len(tail_policy()).unwrap() as u64
                        + count * crate::eng2::header::HEADER_BYTES as u64
                        + 1024 * 1024
                } else {
                    4 * 1024 * 1024
                },
                max_chunks_per_object: 16,
                max_body_bytes: cache_body_limit,
            },
            p2p::Budget::new(64 * 1024 * 1024),
        )
        .unwrap();
        for header in headers {
            cache.put_header(&header).unwrap();
        }
        let candidate = Candidate::new(
            cache,
            &genesis,
            import::Policy {
                state: limits,
                max_headers: 1000,
                max_verification_bytes: 8 * 1024 * 1024,
            },
            body::Policy {
                profile: crate::proofs::protocol_profile_fingerprint(),
                max_body_bytes: 1024 * 1024,
                slot_rule: crate::wire::SlotRule::Legacy,
                max_settlement_proof_bytes: 4096,
            },
        )
        .unwrap();
        (genesis, candidate)
    }

    fn tail_policy() -> body::Policy {
        body::Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: 1024 * 1024,
            slot_rule: crate::wire::SlotRule::Legacy,
            max_settlement_proof_bytes: 4096,
        }
    }
    fn tail_body(genesis: &Genesis, height: u64) -> body::Body {
        let mut body = body::tests::body();
        body.network = genesis.config().network;
        body.height = height;
        body.profile = tail_policy().profile;
        body.governance.clear();
        body.fund_claims.clear();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        body
    }
    #[test]
    fn cold_client_recomputes_work_selects_greatest_and_rejects_equal_forks() {
        let a = Directory::new();
        let b = Directory::new();
        let (genesis, short) = fixture(&a, 96, 1);
        let (_, long) = fixture(&b, 97, 2);
        let short = short.prepare(&genesis, Work::one()).unwrap();
        let long = long.prepare(&genesis, Work::one()).unwrap();
        let client = select(vec![short, long], Work::one()).unwrap();
        assert_eq!(client.selected_tip().0, 97);
        assert_eq!(
            client.progress().unwrap(),
            Progress::Snapshot {
                received: 0,
                total: 7
            }
        );
        drop(client);
        let c = Directory::new();
        let d = Directory::new();
        let (_, left) = fixture(&c, 96, 1);
        let (_, right) = fixture(&d, 96, 2);
        assert!(
            select(
                vec![
                    left.prepare(&genesis, Work::one()).unwrap(),
                    right.prepare(&genesis, Work::one()).unwrap()
                ],
                Work::one()
            )
            .is_err()
        );
        let e = Directory::new();
        let (_, liar) = fixture_claim(&e, 96, 1, Work::from(97));
        assert!(liar.prepare(&genesis, Work::one()).is_err());
    }
    #[test]
    fn downloaded_framing_never_admits_forged_certificate_or_creates_destination() {
        let directory = Directory::new();
        let destination = Directory::new();
        let (genesis, candidate) = fixture(&directory, 96, 1);
        let prepared = candidate.prepare(&genesis, Work::one()).unwrap();
        let mut client = select(vec![prepared], Work::one()).unwrap();
        client
            .candidate
            .cache
            .push(
                Object::Snapshot,
                0,
                &Chunk {
                    descriptor: client.manifest().snapshot,
                    bytes: b"fixture".to_vec(),
                },
            )
            .unwrap();
        for height in 1..=72 {
            let bytes = b"synthetic receipt";
            client
                .candidate
                .cache
                .push(
                    Object::Receipt {
                        height,
                        id: client.plan.headers().id(height).unwrap(),
                    },
                    0,
                    &Chunk {
                        descriptor: Descriptor {
                            length: bytes.len() as u64,
                            digest: *blake3::hash(bytes).as_bytes(),
                        },
                        bytes: bytes.to_vec(),
                    },
                )
                .unwrap();
        }
        for height in 73..=96 {
            client
                .candidate
                .cache
                .put_body(
                    client.plan.headers().header(height).unwrap(),
                    b"synthetic body",
                )
                .unwrap();
        }
        client.advance().unwrap();
        assert_eq!(client.progress().unwrap(), Progress::Downloaded);
        assert!(
            client
                .verify_and_install(&genesis, &destination.0, || false)
                .is_err()
        );
        assert!(!destination.0.exists());
        assert!(directory.0.join("bootstrap-quarantine.redb").exists());
    }
    #[cfg(unix)]
    mod tail_tests {
        include!("client/tail_tests.rs");
    }
}
