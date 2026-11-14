//! Typed observations of completed native proof rejection at owner admission.
//!
//! Diagnostics do not grant admission, validity, readiness or rollback authority.
mod native_verifier;

use super::header::Header;
use crate::wire::Hash;
use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Relation {
    Transaction,
    LegacySettlement,
    Issuance,
}
impl Relation {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Transaction => "transaction-proof-invalid",
            Self::LegacySettlement => "settlement-proof-invalid",
            Self::Issuance => "issuance-proof-invalid",
        }
    }
    fn original_error(self) -> &'static str {
        match self {
            Self::Transaction => "native transaction proof verification failed",
            Self::LegacySettlement => "native settlement proof verification failed",
            Self::Issuance => "native issuance proof verification failed",
        }
    }
}

/// No constructor accepts an error string, invalidity flag or missing event.
#[derive(Debug)]
pub(crate) struct CompletedNativeRejection {
    relation: Relation,
}
impl CompletedNativeRejection {
    pub(crate) fn relation(&self) -> Relation {
        self.relation
    }
    pub(crate) fn code(&self) -> &'static str {
        self.relation().code()
    }
}

/// Non-native categories without a current admission edge are test fixtures only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OtherClass {
    ProofStructure,
    CandidateValidation,
    #[cfg(test)]
    Deferred,
    #[cfg(test)]
    Timeout,
    #[cfg(test)]
    Resource,
    #[cfg(test)]
    WorkerUnavailable,
    #[cfg(test)]
    ProtocolRead,
    Storage,
    #[cfg(test)]
    Publication,
    Unclassified,
}
/// Protocol and publication failures are currently modeled only by fixtures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    #[cfg(test)]
    Protocol,
    ProofPreparation,
    NativeVerification,
    Execution,
    Storage,
    #[cfg(test)]
    Publication,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitKnowledge {
    NotReached,
    /// Writer errors remain Unknown; committed outcomes are negative fixtures.
    #[cfg(test)]
    Committed,
    Unknown,
}

/// The original product error is retained without using its text as evidence.
#[derive(Debug)]
pub(crate) struct Failure {
    original: String,
    native: Option<CompletedNativeRejection>,
    class: OtherClass,
    phase: Phase,
    commit: CommitKnowledge,
}
impl Failure {
    pub(crate) fn other(
        original: String,
        class: OtherClass,
        phase: Phase,
        commit: CommitKnowledge,
    ) -> Self {
        Self {
            original,
            native: None,
            class,
            phase,
            commit,
        }
    }
    pub(crate) fn native_rejection(&self) -> Option<&CompletedNativeRejection> {
        self.native.as_ref()
    }
    pub(crate) fn into_original(self) -> String {
        self.original
    }
    pub(crate) fn class(&self) -> Option<OtherClass> {
        if self.native.is_some() {
            None
        } else {
            Some(self.class)
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    pub(crate) fn commit(&self) -> CommitKnowledge {
        self.commit
    }
    pub(crate) fn unclassified(original: String) -> Self {
        Self::other(
            original,
            OtherClass::Unclassified,
            Phase::Execution,
            CommitKnowledge::Unknown,
        )
    }
    /// Only the native verifier's private-field evidence can enter this path.
    pub(crate) fn from_native_verifier(evidence: crate::proofs::NativeRejectionEvidence) -> Self {
        let relation = evidence.relation();
        Self {
            original: relation.original_error().into(),
            native: Some(CompletedNativeRejection { relation }),
            class: OtherClass::Unclassified,
            phase: Phase::NativeVerification,
            commit: CommitKnowledge::NotReached,
        }
    }
}

/// Synthetic unit-test fixture; absent from production builds and interfaces.
#[cfg(test)]
fn synthetic_native_failure(relation: Relation) -> Failure {
    Failure {
        original: relation.original_error().into(),
        native: Some(CompletedNativeRejection { relation }),
        class: OtherClass::Unclassified,
        phase: Phase::NativeVerification,
        commit: CommitKnowledge::NotReached,
    }
}

/// Identity of complete canonical bytes received through an authenticated peer.
/// No proof bytes are retained and no second complete frame is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameIdentity {
    peer: Hash,
    network: Hash,
    height: u64,
    header: Hash,
    body: Hash,
    bytes: u64,
    frame: Hash,
    fetch: Option<FetchTiming>,
}
impl FrameIdentity {
    /// The transport invokes this after its actual authenticated read and decode.
    /// A failed diagnostic capture must not replace the original transport result.
    pub(super) fn after_authenticated_decode(
        peer: Hash,
        header: &Header,
        canonical_body: &[u8],
        maximum: usize,
    ) -> Option<Self> {
        header.verify_body(canonical_body, maximum).ok()?;
        let encoded_header = header.encode().ok()?;
        let bytes = u64::try_from(canonical_body.len()).ok()?;
        let mut digest =
            blake3::Hasher::new_derive_key("siworld native admission frame observation v1");
        digest.update(&encoded_header);
        digest.update(&bytes.to_le_bytes());
        digest.update(canonical_body);
        Some(Self {
            peer,
            network: header.network,
            height: header.height,
            header: header.id().ok()?,
            body: header.body_commitment,
            bytes,
            frame: *digest.finalize().as_bytes(),
            fetch: None,
        })
    }
    pub(super) fn with_fetch_timing(mut self, timing: FetchTiming) -> Self {
        self.fetch = Some(timing);
        self
    }
    #[cfg(test)]
    pub(crate) fn fetch_timing(self) -> Option<FetchTiming> {
        self.fetch
    }
    fn matches(&self, header: &Header) -> bool {
        self.network == header.network
            && self.height == header.height
            && self.body == header.body_commitment
            && header.id().ok() == Some(self.header)
    }
    pub(crate) fn peer_id(&self) -> Hash {
        self.peer
    }
    pub(crate) fn header_id(&self) -> Hash {
        self.header
    }
    pub(crate) fn body_commitment(&self) -> Hash {
        self.body
    }
    pub(crate) fn frame_id(&self) -> Hash {
        self.frame
    }
    pub(crate) fn body_bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn height(&self) -> u64 {
        self.height
    }
}

/// Fixed once from the actual resident startup, never supplied with a verdict.
pub(crate) struct RunIdentity {
    network: Hash,
    genesis: Hash,
    node: Hash,
    run: Hash,
    binary: Hash,
}
impl RunIdentity {
    pub(super) fn from_resident(
        network: Hash,
        genesis: Hash,
        node: Option<Hash>,
        run: &str,
        binary: &str,
    ) -> Option<Self> {
        Some(Self {
            network,
            genesis,
            node: node?,
            run: hex32(run)?,
            binary: hex32(binary)?,
        })
    }
    pub(crate) fn network(&self) -> Hash {
        self.network
    }
    pub(crate) fn genesis(&self) -> Hash {
        self.genesis
    }
    pub(crate) fn node(&self) -> Hash {
        self.node
    }
    pub(crate) fn run(&self) -> Hash {
        self.run
    }
    pub(crate) fn binary(&self) -> Hash {
        self.binary
    }
}
fn hex32(value: &str) -> Option<Hash> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0; 32];
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(result)
}

pub(crate) struct Attempt {
    number: u64,
    frame: FrameIdentity,
}

/// Process-local diagnostics only; zero ordinals mean unavailable identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FetchTiming {
    pub connection: u64,
    pub attempt: u64,
    pub height: u64,
    pub block: Hash,
    pub bytes: u64,
    pub received_bytes: u64,
    pub start: Option<Instant>,
    pub body_start: Option<Instant>,
    pub chunks_end: Option<Instant>,
    pub decoded: Option<Instant>,
    pub end: Option<Instant>,
    pub outcome: u8,
    pub transport_error: u8,
}
pub(crate) fn monotonic_ns(instant: Option<Instant>, origin: Instant) -> Option<String> {
    instant?
        .checked_duration_since(origin)
        .map(|value| value.as_nanos().to_string())
}
impl FetchTiming {
    pub(crate) fn json(self, origin: Instant) -> serde_json::Value {
        serde_json::json!({"connection":self.connection,"attempt":self.attempt,
            "height":self.height,"block":crate::local::hex(&self.block),"announced_bytes":self.bytes,"received_bytes":self.received_bytes,
            "start":monotonic_ns(self.start,origin),"body_start":monotonic_ns(self.body_start,origin),
            "chunks_end":monotonic_ns(self.chunks_end,origin),"decoded":monotonic_ns(self.decoded,origin),
            "end":monotonic_ns(self.end,origin),"outcome":self.outcome,
            "transport_error":match self.transport_error {1=>Some("invalid_protocol"),2=>Some("unavailable"),3=>Some("resource_exhausted"),4=>Some("unconfigured"),_=>None},
            "ordinal_available":self.connection!=0 && self.attempt!=0})
    }
}
#[derive(Clone, Copy, Default)]
pub(crate) struct ValidationTiming {
    pub start: Option<Instant>,
    pub end: Option<Instant>,
}
#[derive(Clone, Copy)]
struct AdmissionTiming {
    attempt: u64,
    block: Hash,
    fetch: Option<FetchTiming>,
    validation: ValidationTiming,
    end: Instant,
    outcome: u8,
}
const _: () = assert!(std::mem::size_of::<AdmissionTiming>() <= 512);
pub(crate) const fn diagnostic_storage_bytes() -> usize {
    // Conservatively include the entire owner observer, plus peer-local trace
    // slots and the additional trace attached to each bounded received body.
    std::mem::size_of::<Observation>()
        + 8 * (2 * std::mem::size_of::<Option<FetchTiming>>() + 3 * std::mem::size_of::<u64>())
}
pub(crate) struct Rejection<'a> {
    pub(crate) run: &'a RunIdentity,
    pub(crate) attempt: u64,
    pub(crate) frame: &'a FrameIdentity,
    pub(crate) native: &'a CompletedNativeRejection,
    pub(crate) event_unix_ms: Option<u64>,
    pub(crate) event_instant: Instant,
    pub(crate) dropped_before: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiagnosticError {
    Binding,
    Attempt,
    Frame,
    Output,
}
impl DiagnosticError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Binding => "native_rejection_binding_unavailable",
            Self::Attempt => "native_rejection_attempt_unavailable",
            Self::Frame => "native_rejection_frame_unavailable",
            Self::Output => "native_rejection_output_unavailable",
        }
    }
}

/// The runtime sink must keep bounded output and its existing loss counters.
/// IO, encoding and lock failures return Output rather than a product error.
pub(crate) trait Observer: Send + Sync {
    fn rejected(&self, event: &Rejection<'_>) -> Result<(), DiagnosticError>;
}

/// Owner-local diagnostic sequence only; it carries no last verifier result.
#[derive(Default)]
pub(crate) struct Observation {
    binding: Option<RunIdentity>,
    observer: Option<Arc<dyn Observer>>,
    sequence: u64,
    dropped: u64,
    error: Option<DiagnosticError>,
    recent: [Option<AdmissionTiming>; 8],
    next_recent: usize,
    overwritten: u64,
}
impl Observation {
    /// Outcomes: 1 committed, 2 rejected before commit, 3 commit unknown,
    /// 4 committed with a later finishing error. No outcome grants authority.
    pub(crate) fn completed(
        &mut self,
        attempt: Option<&Attempt>,
        validation: ValidationTiming,
        outcome: u8,
    ) {
        let Some(attempt) = attempt else {
            return;
        };
        if self.recent[self.next_recent].is_some() {
            self.overwritten = self.overwritten.saturating_add(1);
        }
        self.recent[self.next_recent] = Some(AdmissionTiming {
            attempt: attempt.number,
            block: attempt.frame.header,
            fetch: attempt.frame.fetch,
            validation,
            end: Instant::now(),
            outcome,
        });
        self.next_recent = (self.next_recent + 1) % self.recent.len();
    }
    pub(crate) fn timing_json(&self, origin: Instant) -> serde_json::Value {
        let recent: Vec<_> = (0..8)
            .filter_map(|offset| self.recent[(self.next_recent + offset) % 8])
            .map(|item| {
                serde_json::json!({"attempt":item.attempt,"block":crate::local::hex(&item.block),
                "fetch":item.fetch.map(|fetch|fetch.json(origin)),
                "validation_start":monotonic_ns(item.validation.start,origin),
                "validation_end":monotonic_ns(item.validation.end,origin),
                "end":monotonic_ns(Some(item.end),origin),"outcome":item.outcome})
            })
            .collect();
        serde_json::json!({"recent":recent,"overwritten":self.overwritten,
            "scope":"ordinary-forward-admission","exact_readiness_transitions":false})
    }
    pub(crate) fn attach(&mut self, run: RunIdentity, observer: Arc<dyn Observer>) -> bool {
        if self.binding.is_some() || self.observer.is_some() {
            self.unavailable(DiagnosticError::Binding);
            return false;
        }
        self.binding = Some(run);
        self.observer = Some(observer);
        true
    }
    fn unavailable(&mut self, error: DiagnosticError) {
        self.dropped = self.dropped.saturating_add(1);
        self.error.get_or_insert(error);
    }
    pub(crate) fn begin(
        &mut self,
        header: &Header,
        frame: Option<FrameIdentity>,
    ) -> Option<Attempt> {
        self.observer.as_ref()?;
        let Some(binding) = self.binding.as_ref() else {
            self.unavailable(DiagnosticError::Binding);
            return None;
        };
        if header.network != binding.network {
            self.unavailable(DiagnosticError::Binding);
            return None;
        }
        let Some(number) = self.sequence.checked_add(1) else {
            self.unavailable(DiagnosticError::Attempt);
            return None;
        };
        self.sequence = number;
        let Some(frame) = frame.filter(|frame| frame.matches(header)) else {
            self.unavailable(DiagnosticError::Frame);
            return None;
        };
        Some(Attempt { number, frame })
    }
    /// Called at the actual Driver.accept error edge before its original return.
    /// Failures here are confined to diagnostics; the caller returns its error.
    pub(crate) fn rejected(&mut self, attempt: Option<&Attempt>, failure: &Failure) {
        let event_instant = Instant::now();
        if failure.class().is_some()
            || failure.phase() != Phase::NativeVerification
            || failure.commit() != CommitKnowledge::NotReached
        {
            return;
        }
        let Some(native) = failure.native_rejection() else {
            return;
        };
        if self.observer.is_none() {
            if self.binding.is_some() {
                self.unavailable(DiagnosticError::Output);
            }
            return;
        }
        let Some(attempt) = attempt else {
            self.unavailable(DiagnosticError::Attempt);
            return;
        };
        let Some(run) = self.binding.as_ref() else {
            self.unavailable(DiagnosticError::Binding);
            return;
        };
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_millis()).ok());
        let event = Rejection {
            run,
            attempt: attempt.number,
            frame: &attempt.frame,
            native,
            event_unix_ms: wall,
            event_instant,
            dropped_before: self.dropped,
        };
        if self
            .observer
            .as_ref()
            .is_some_and(|observer| observer.rejected(&event).is_err())
        {
            self.unavailable(DiagnosticError::Output);
            self.observer = None;
        }
    }
    pub(crate) fn enabled(&self) -> bool {
        self.binding.is_some() && self.observer.is_some()
    }
    pub(crate) fn diagnostic(&self) -> (u64, Option<DiagnosticError>) {
        (self.dropped, self.error)
    }
}

#[cfg(test)]
mod tests;
