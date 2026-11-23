//! Bounded candidate jobs shared by existing authenticated body-lane workers.
use super::super::propagation::pipeline::{DescriptorLedger, Limits as TransferLimits, Transfer};
use super::super::transport::propagation::Metadata;
use super::*;

type Batch = (Arc<Job>, Vec<super::super::propagation::pipeline::Request>);
const CAPACITY: usize = 4;
pub(super) struct Job {
    pub(super) transfer: Arc<Mutex<Transfer>>,
    pub(super) ownership: p2p::BodyClaim,
    pub(super) download: header_lane::Download,
    pub(super) validation: Option<Arc<super::super::native_pipeline::Pipeline>>,
    source_session: u64,
    forwarded: Mutex<std::collections::BTreeSet<Hash>>,
    path: Vec<super::super::header::Header>,
    _charge: p2p::Reservation,
}
pub(super) struct Forwarding {
    pub(super) transfer: Arc<Mutex<Transfer>>,
    pub(super) header: super::super::header::Header,
    pub(super) deadline: p2p::Deadline,
    job: std::sync::Weak<Job>,
    _charge: p2p::Reservation,
}
impl Forwarding {
    pub(super) fn forwarding_deferred(&self, peer: Hash) {
        let Some(job) = self.job.upgrade() else {
            return;
        };
        if let Ok(mut forwarded) = job.forwarded.lock() {
            forwarded.remove(&peer);
        }
    }
}
pub(super) struct Transfers {
    jobs: Mutex<Vec<Arc<Job>>>,
    configured: Vec<Hash>,
    budget: p2p::Budget,
    completed: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    _charge: p2p::Reservation,
}
impl Transfers {
    #[cfg(test)]
    pub(super) fn test_job(&self, id: Hash) -> Arc<Job> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .find(|job| job.transfer.lock().unwrap().block() == id)
            .unwrap()
            .clone()
    }
    pub(super) fn new(
        config: &config::Configuration,
        budget: &p2p::Budget,
    ) -> Result<Self, String> {
        let configured = config
            .peers
            .iter()
            .map(|p| p.expected.fingerprint())
            .filter(|peer| config.fixed_relay_peers.contains(peer))
            .chain(
                config
                    .peers
                    .iter()
                    .map(|p| p.expected.fingerprint())
                    .filter(|peer| !config.fixed_relay_peers.contains(peer)),
            )
            .take(8)
            .collect();
        Ok(Self {
            jobs: Mutex::new(Vec::with_capacity(CAPACITY)),
            configured,
            budget: budget.clone(),
            completed: std::sync::atomic::AtomicU64::new(0),
            failed: std::sync::atomic::AtomicU64::new(0),
            _charge: budget
                .reserve(
                    std::mem::size_of::<Self>()
                        + CAPACITY * std::mem::size_of::<Arc<Job>>()
                        + 8 * 32,
                )
                .map_err(|_| "piece job registry memory unavailable")?,
        })
    }
    pub(super) fn ledger(
        &self,
        header: &super::super::header::Header,
        deadline: &p2p::Deadline,
        maximum_body: usize,
    ) -> Result<DescriptorLedger, String> {
        let wire = super::super::transport::propagation::maximum_wire(maximum_body)
            .map_err(|_| "piece wire ceiling unavailable")?;
        let now = Instant::now();
        let lifetime = deadline
            .expires_at()
            .checked_duration_since(now)
            .ok_or("piece candidate expired")?;
        DescriptorLedger::new(
            header.id().map_err(|_| "piece header identity rejected")?,
            &self.configured,
            TransferLimits {
                requests: 4,
                wire_bytes: wire.checked_mul(4).ok_or("piece wire ceiling overflow")?,
                peer_requests: 1,
                peer_wire_bytes: wire,
                parallel: 3,
                lifetime,
            },
            now,
        )
        .map_err(|_| "piece descriptor ledger rejected".into())
    }
    pub(super) fn capture(
        &self,
        shared: &Shared,
        download: &header_lane::Download,
    ) -> Option<Arc<super::super::native_pipeline::Pipeline>> {
        let owner = shared.owner.lock().ok()?;
        owner
            .capture_verification(&shared.budget)
            .ok()?
            .start(&download.header, &shared.budget, &download.deadline)
            .ok()
    }
    pub(super) fn metadata_observed(
        &self,
        shared: &Shared,
        download: &header_lane::Download,
        ledger: &DescriptorLedger,
        authenticated: bool,
    ) {
        let timing = super::super::accept_observation::FetchTiming {
            attempt: download
                .ownership()
                .ok()
                .and_then(|owner| owner.progress_attempt())
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            start: Some(ledger.started()),
            body_start: authenticated.then(Instant::now),
            end: Some(Instant::now()),
            ..Default::default()
        };
        for source in ledger.observed_sources() {
            shared.block_events.piece_source(
                &download.header,
                source,
                timing,
                if authenticated {
                    "metadata_authenticated"
                } else {
                    "metadata_failed"
                },
            );
        }
    }
    pub(super) fn insert(
        &self,
        mut download: header_lane::Download,
        metadata: Metadata,
        ledger: DescriptorLedger,
        validation: Option<Arc<super::super::native_pipeline::Pipeline>>,
        source_session: u64,
        shared: &Shared,
    ) -> Result<Arc<Job>, String> {
        let path = shared.headers.path(&download.header)?;
        let charge = shared
            .budget
            .reserve(
                std::mem::size_of::<Job>()
                    + std::mem::size_of::<Mutex<Transfer>>()
                    + 64
                    + 8 * 64
                    + path.len() * std::mem::size_of::<super::super::header::Header>(),
            )
            .map_err(|_| "piece job memory unavailable")?;
        let mut transfer = metadata
            .into_transfer(ledger, &shared.budget)
            .map_err(|_| "piece assembly allocation rejected")?;
        transfer.bind_forwarding_candidate(download.forwarding_candidate.clone());
        if let Some(pipeline) = &validation {
            let _ = pipeline.observe(&transfer);
        }
        let ownership = download.take_ownership()?;
        let job = Arc::new(Job {
            transfer: Arc::new(Mutex::new(transfer)),
            ownership,
            download,
            validation,
            source_session,
            forwarded: Mutex::new(Default::default()),
            path,
            _charge: charge,
        });
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| "piece job registry lock poisoned")?;
        if jobs.len() >= CAPACITY {
            return Err("piece job registry full".into());
        }
        jobs.push(job.clone());
        Ok(job)
    }
    pub(super) fn forwarding(
        &self,
        peer: Hash,
        shutdown: p2p::Cancellation,
    ) -> Result<Option<Forwarding>, String> {
        if !self.configured.contains(&peer) {
            return Ok(None);
        }
        let jobs = self
            .jobs
            .lock()
            .map_err(|_| "piece job registry lock poisoned")?
            .clone();
        for job in jobs {
            if job.download.cancel.is_cancelled() || job.ownership.deadline().check().is_err() {
                continue;
            }
            let transfer = job
                .transfer
                .lock()
                .map_err(|_| "piece transfer lock poisoned")?;
            if transfer.confirmed_source(peer) || transfer.verified_bytes() == 0 {
                continue;
            }
            let deadline = transfer.forwarding_deadline(shutdown.clone());
            drop(transfer);
            let mut forwarded = job
                .forwarded
                .lock()
                .map_err(|_| "piece forwarding lock poisoned")?;
            if forwarded.len() < 8 && forwarded.insert(peer) {
                drop(forwarded);
                // References keep both Arc allocations after Job is reaped.
                // Retain those bounded metadata charges without retaining the
                // admission owner or allocating another body buffer.
                let charge = match self.budget.reserve(
                    std::mem::size_of::<Forwarding>()
                        + std::mem::size_of::<Job>()
                        + std::mem::size_of::<Mutex<Transfer>>()
                        + 128,
                ) {
                    Ok(charge) => charge,
                    Err(_) => {
                        job.forwarded
                            .lock()
                            .map_err(|_| "piece forwarding lock poisoned")?
                            .remove(&peer);
                        return Ok(None);
                    }
                };
                return Ok(Some(Forwarding {
                    transfer: job.transfer.clone(),
                    header: job.download.header.clone(),
                    deadline,
                    job: Arc::downgrade(&job),
                    _charge: charge,
                }));
            }
        }
        Ok(None)
    }
    pub(super) fn cancel(&self) {
        if let Ok(jobs) = self.jobs.lock() {
            for job in jobs.iter() {
                job.download.cancel.cancel();
                if let Ok(mut transfer) = job.transfer.lock() {
                    transfer.cancel();
                }
            }
        }
    }
    pub(super) fn batch(
        &self,
        peer: Hash,
        session: u64,
        headers: &header_lane::Hub,
        connected: &std::collections::BTreeSet<Hash>,
    ) -> Result<Option<Batch>, String> {
        let jobs = self
            .jobs
            .lock()
            .map_err(|_| "piece job registry lock poisoned")?
            .clone();
        for job in jobs {
            if job.ownership.deadline().check().is_err() || job.download.cancel.is_cancelled() {
                continue;
            }
            let id = job
                .download
                .header
                .id()
                .map_err(|_| "piece header identity rejected")?;
            let holders = headers.piece_sources(id, peer, session, connected)?;
            let mut transfer = job
                .transfer
                .lock()
                .map_err(|_| "piece transfer lock poisoned")?;
            if !(job.source_session == session && transfer.confirmed_source(peer)
                || holders.contains(&peer))
                || !job.ownership.can_query(peer, 1)
            {
                continue;
            }
            let maximum =
                transfer.qualified_batch_capacity(peer, connected, &holders, &job.ownership);
            if maximum == 0 {
                continue;
            }
            let requests = match transfer.next_batch(peer, None, maximum, Instant::now()) {
                Ok(requests) => requests,
                Err(_) => continue,
            };
            drop(transfer);
            if !requests.is_empty() {
                return Ok(Some((job, requests)));
            }
        }
        Ok(None)
    }
    pub(super) fn reap(&self, shared: &Shared) -> Result<(), String> {
        let mut ready = Vec::with_capacity(CAPACITY);
        {
            let mut jobs = self
                .jobs
                .lock()
                .map_err(|_| "piece job registry lock poisoned")?;
            let mut index = 0;
            while index < jobs.len() {
                let job = &jobs[index];
                let transfer = job
                    .transfer
                    .lock()
                    .map_err(|_| "piece transfer lock poisoned")?;
                let complete = transfer.verified_bytes() == transfer.body_bytes();
                let exhausted = transfer.sources().iter().map(|s| s.queries).sum::<u64>() >= 4;
                let cancelled =
                    job.download.cancel.is_cancelled() || job.ownership.deadline().check().is_err();
                let streaming = transfer.stream_active();
                drop(transfer);
                if (complete || cancelled || exhausted) && !streaming && Arc::strong_count(job) == 1
                {
                    ready.push(jobs.remove(index));
                } else {
                    index += 1;
                }
            }
        }
        for job in ready {
            let Ok(job) = Arc::try_unwrap(job) else {
                continue;
            };
            let Job {
                transfer,
                ownership,
                download,
                validation,
                source_session: _,
                forwarded: _,
                path,
                _charge,
            } = job;
            let mut transfer = transfer
                .lock()
                .map_err(|_| "piece transfer lock poisoned")?;
            let timing = transfer.fetch_timing(&download.header, &ownership);
            // Four actual queries bound this fixed snapshot even when all eight
            // configured peers exist. Unused configured peers emit no record.
            let mut sources = [None; 4];
            for (slot, source) in sources.iter_mut().zip(transfer.observed_sources()) {
                *slot = Some(source);
            }
            let record = |outcome, timing| {
                for source in sources.iter().flatten() {
                    shared
                        .block_events
                        .piece_source(&download.header, *source, timing, outcome);
                }
            };
            if transfer.verified_bytes() != transfer.body_bytes()
                || download.cancel.is_cancelled()
                || ownership.deadline().check().is_err()
            {
                record("incomplete_or_cancelled", timing);
                download.cancel.cancel();
                self.failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            let receipts = validation.and_then(|pipeline| pipeline.finish(&transfer).ok());
            match transfer.finish_retained(
                &download.header,
                shared.headers.body_policy(),
                Instant::now(),
                ownership,
            ) {
                Ok(mut received) if !download.cancel.is_cancelled() => {
                    record(
                        "authenticated_body_decoded",
                        received
                            .observation
                            .and_then(|frame| frame.fetch_timing())
                            .unwrap_or(timing),
                    );
                    received.receipts = receipts;
                    download.decoded();
                    shared.bodies.submit(body_admission::Ready {
                        download,
                        received,
                        path,
                    });
                    self.completed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {
                    let mut timing = timing;
                    timing.end = Some(Instant::now());
                    record("decode_rejected_or_cancelled", timing);
                    self.failed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }
    pub(super) fn diagnostic(&self) -> Value {
        json!({"scope":"piece_candidate_jobs","capacity":CAPACITY,
            "active":self.jobs.lock().map(|jobs|jobs.len()).ok(),
            "decoded":self.completed.load(std::sync::atomic::Ordering::Relaxed),
            "failed":self.failed.load(std::sync::atomic::Ordering::Relaxed),"native_acceptance_not_implied":true})
    }
}
