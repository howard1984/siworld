//! Local process isolation for a separately integrated CompleteFee verifier.
//!
//! This module does not select verification keys, rebuild statements, perform
//! proof verification, or admit a block. A trusted child adapter must do the
//! verification and emit a bound receipt. Admission must recheck the captured
//! canonical context. Timeouts and process failures are local deferrals.

use super::{FRAME_BYTES, MAX_FEE_PROOF_BYTES, Relation, admit_declared_size};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const INPUT_MAGIC: &[u8; 8] = b"SWFGIN01";
const RECEIPT_MAGIC: &[u8; 8] = b"SWFGRP01";
const BINDING_BYTES: usize = 9 * 32;
const INPUT_HEADER_BYTES: usize = 28 + BINDING_BYTES;
pub const RECEIPT_BYTES: usize = 12 + BINDING_BYTES;
pub const REQUEST_ENV: &str = "SIWORLD_FEE_GUARD_REQUEST";
pub const RECEIPT_ENV: &str = "SIWORLD_FEE_GUARD_RECEIPT";

/// Obtain this token before receiving or allocating the declared fee frame.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeclaredLength(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthError {
    TooShort,
    Oversize,
}

pub fn preflight_declared_length(bytes: u64) -> Result<DeclaredLength, LengthError> {
    if bytes <= FRAME_BYTES as u64 {
        return Err(LengthError::TooShort);
    }
    if bytes > MAX_FEE_PROOF_BYTES as u64 {
        return Err(LengthError::Oversize);
    }
    let bytes = bytes as usize;
    admit_declared_size(Relation::CompleteFee, bytes, MAX_FEE_PROOF_BYTES)
        .map_err(|_| LengthError::Oversize)?;
    Ok(DeclaredLength(bytes))
}

impl DeclaredLength {
    pub fn bytes(self) -> usize {
        self.0
    }
}

/// Every field comes from the trusted caller, never from a proof frame.
/// The attempt identifier must be unique within the private scratch space.
/// Digests deliberately have no Debug implementation or automatic logging.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RequestBinding {
    pub attempt: [u8; 32],
    pub network: [u8; 32],
    pub genesis: [u8; 32],
    pub rules: [u8; 32],
    pub profile: [u8; 32],
    pub verifier_keys: [u8; 32],
    pub statement: [u8; 32],
    pub proof: [u8; 32],
    pub canonical_context: [u8; 32],
}

impl RequestBinding {
    fn encode(self, bytes: &mut [u8]) {
        for (out, value) in bytes.as_chunks_mut::<32>().0.iter_mut().zip([
            self.attempt,
            self.network,
            self.genesis,
            self.rules,
            self.profile,
            self.verifier_keys,
            self.statement,
            self.proof,
            self.canonical_context,
        ]) {
            out.copy_from_slice(&value);
        }
    }

    fn decode(bytes: &[u8]) -> Self {
        let field =
            |index: usize| -> [u8; 32] { bytes[index * 32..(index + 1) * 32].try_into().unwrap() };
        Self {
            attempt: field(0),
            network: field(1),
            genesis: field(2),
            rules: field(3),
            profile: field(4),
            verifier_keys: field(5),
            statement: field(6),
            proof: field(7),
            canonical_context: field(8),
        }
    }
}

pub fn proof_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("siworld guarded complete fee proof v1");
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

pub fn statement_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("siworld guarded complete fee statement v1");
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

pub struct VerificationInput<'a> {
    pub declared: DeclaredLength,
    pub proof: &'a [u8],
    /// The independently reconstructed, canonically encoded public statement.
    pub statement: &'a [u8],
    pub binding: RequestBinding,
}

#[derive(Clone, Copy)]
pub struct GuardPolicy {
    /// Provisional local resource policy, not a consensus validity rule.
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub max_statement_bytes: usize,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(10),
            max_statement_bytes: 1024 * 1024,
        }
    }
}

/// Select only a fixed, trusted verification executable and adapter mode.
/// A proof, peer, or receipt must never choose this command or its environment.
pub struct ChildCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Deferred {
    Busy,
    InputMismatch,
    ScratchUnavailable,
    InputStaging,
    Spawn,
    Timeout,
    OutputLimit,
    OutputMalformed,
    BindingMismatch,
    ChildFailed,
    ProcessControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildVerdict {
    Verified,
    Rejected,
}

/// A process result is not a canonical-admission capability. Rejected here
/// means the trusted adapter's semantic result, not a timeout or machine limit.
pub struct CheckedReceipt {
    binding: RequestBinding,
    verdict: ChildVerdict,
}

impl CheckedReceipt {
    pub fn binding(&self) -> &RequestBinding {
        &self.binding
    }

    pub fn verdict(&self) -> ChildVerdict {
        self.verdict
    }
}

pub enum Outcome {
    Checked(Box<CheckedReceipt>),
    Deferred(Deferred),
}

/// Clones share one permit. No waiting queue or second child is created.
#[derive(Clone)]
pub struct FeeGuard {
    occupied: Arc<AtomicBool>,
    policy: GuardPolicy,
}

impl FeeGuard {
    pub fn new(policy: GuardPolicy) -> Result<Self, &'static str> {
        if policy.timeout.is_zero()
            || policy.poll_interval.is_zero()
            || policy.poll_interval > policy.timeout
            || policy.max_statement_bytes == 0
        {
            return Err("invalid local fee verification policy");
        }
        Ok(Self {
            occupied: Arc::new(AtomicBool::new(false)),
            policy,
        })
    }

    /// Run outside every canonical owner lock. Hashing, input staging, child
    /// startup, verification, exit, and receipt admission share one deadline.
    /// Private scratch ACLs must be prepared by the platform
    /// layer; new job directories inherit them on Windows and use 0700 on Unix.
    /// The trusted child adapter must not spawn subprocesses.
    pub fn verify(
        &self,
        input: VerificationInput<'_>,
        command: &ChildCommand,
        private_scratch: &Path,
    ) -> Outcome {
        if input.proof.len() != input.declared.bytes()
            || input.statement.is_empty()
            || input.statement.len() > self.policy.max_statement_bytes
        {
            return Outcome::Deferred(Deferred::InputMismatch);
        }
        if self
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Outcome::Deferred(Deferred::Busy);
        }
        let permit = Permit {
            occupied: self.occupied.clone(),
            reusable: true,
        };
        let start = Instant::now();
        let proof = proof_digest(input.proof);
        let statement = statement_digest(input.statement);
        if start.elapsed() >= self.policy.timeout {
            return Outcome::Deferred(Deferred::Timeout);
        }
        if input.binding.proof != proof || input.binding.statement != statement {
            return Outcome::Deferred(Deferred::InputMismatch);
        }
        let mut job = match JobDirectory::create(private_scratch, input.binding.attempt) {
            Ok(job) => job,
            Err(_) => return Outcome::Deferred(Deferred::ScratchUnavailable),
        };
        if write_input(&job.request, &input).is_err() {
            return Outcome::Deferred(Deferred::InputStaging);
        }
        if start.elapsed() >= self.policy.timeout {
            return Outcome::Deferred(Deferred::Timeout);
        }
        let mut child_command = Command::new(&command.executable);
        child_command
            .args(&command.arguments)
            .env_clear()
            .envs(
                command
                    .environment
                    .iter()
                    .map(|(name, value)| (name, value)),
            )
            .env(REQUEST_ENV, &job.request)
            .env(RECEIPT_ENV, &job.receipt)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Windows system libraries may consult this fixed OS setting. The
        // adapter receives no inherited application credentials or log flags.
        if let Some(root) = std::env::var_os("SystemRoot") {
            child_command.env("SystemRoot", root);
        }
        let child = match child_command.spawn() {
            Ok(child) => child,
            Err(_) => return Outcome::Deferred(Deferred::Spawn),
        };
        job.cleanup = false;
        let mut process = GuardedChild::new(child, permit);
        let mut outcome = loop {
            if start.elapsed() >= self.policy.timeout {
                break Outcome::Deferred(Deferred::Timeout);
            }
            match fs::symlink_metadata(&job.receipt) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                    break Outcome::Deferred(Deferred::OutputMalformed);
                }
                Ok(meta) if meta.len() > RECEIPT_BYTES as u64 => {
                    break Outcome::Deferred(Deferred::OutputLimit);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => break Outcome::Deferred(Deferred::OutputMalformed),
            }
            match process.child.try_wait() {
                Ok(Some(status)) => {
                    process.mark_reaped();
                    if start.elapsed() >= self.policy.timeout {
                        break Outcome::Deferred(Deferred::Timeout);
                    }
                    if !status.success() {
                        break Outcome::Deferred(Deferred::ChildFailed);
                    }
                    let receipt = match read_receipt(&job.receipt) {
                        Ok(receipt) => receipt,
                        Err(reason) => break Outcome::Deferred(reason),
                    };
                    if receipt.binding != input.binding {
                        break Outcome::Deferred(Deferred::BindingMismatch);
                    }
                    if start.elapsed() >= self.policy.timeout {
                        break Outcome::Deferred(Deferred::Timeout);
                    }
                    break Outcome::Checked(Box::new(CheckedReceipt {
                        binding: receipt.binding,
                        verdict: receipt.verdict,
                    }));
                }
                Ok(None) => {}
                Err(_) => break Outcome::Deferred(Deferred::ProcessControl),
            }
            std::thread::sleep(
                self.policy
                    .poll_interval
                    .min(self.policy.timeout.saturating_sub(start.elapsed())),
            );
        };
        if !process.reaped && !process.terminate() {
            outcome = Outcome::Deferred(Deferred::ProcessControl);
        }
        job.cleanup = process.reaped;
        // If termination/reaping could not be confirmed, the shared permit
        // remains latched. Another proof must not overlap the unknown process.
        outcome
    }
}

struct Permit {
    occupied: Arc<AtomicBool>,
    reusable: bool,
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.reusable {
            self.occupied.store(false, Ordering::Release);
        }
    }
}

struct GuardedChild {
    child: Child,
    permit: Permit,
    reaped: bool,
}

impl GuardedChild {
    fn new(child: Child, mut permit: Permit) -> Self {
        permit.reusable = false;
        Self {
            child,
            permit,
            reaped: false,
        }
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
        self.permit.reusable = true;
    }

    fn terminate(&mut self) -> bool {
        if self.reaped {
            return true;
        }
        if self.child.kill().is_ok() {
            if self.child.wait().is_ok() {
                self.mark_reaped();
            }
        } else if matches!(self.child.try_wait(), Ok(Some(_))) {
            self.mark_reaped();
        }
        self.reaped
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct JobDirectory {
    directory: PathBuf,
    request: PathBuf,
    receipt: PathBuf,
    cleanup: bool,
}

impl JobDirectory {
    fn create(base: &Path, attempt: [u8; 32]) -> std::io::Result<Self> {
        let meta = fs::symlink_metadata(base)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
        }
        let name: String = attempt.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = base.join(name);
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&directory)?;
        Ok(Self {
            request: directory.join("request.bin"),
            receipt: directory.join("receipt.bin"),
            directory,
            cleanup: true,
        })
    }
}

impl Drop for JobDirectory {
    fn drop(&mut self) {
        if self.cleanup {
            // Only these newly created local request/receipt paths are owned.
            // Never recursively delete caller data or an unexpected child file.
            let _ = fs::remove_file(&self.request);
            let _ = fs::remove_file(&self.receipt);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}

fn new_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_input(path: &Path, input: &VerificationInput<'_>) -> std::io::Result<()> {
    let mut header = [0; INPUT_HEADER_BYTES];
    header[..8].copy_from_slice(INPUT_MAGIC);
    header[8..10].copy_from_slice(&1u16.to_le_bytes());
    header[12..20].copy_from_slice(&(input.declared.bytes() as u64).to_le_bytes());
    header[20..28].copy_from_slice(&(input.statement.len() as u64).to_le_bytes());
    input.binding.encode(&mut header[28..]);
    let mut file = new_private_file(path)?;
    file.write_all(&header)?;
    file.write_all(input.proof)?;
    file.write_all(input.statement)?;
    file.sync_all()
}

/// Bounded input decoder for the future trusted child adapter. It does not
/// load keys or verify a proof. Check declared sizes before either allocation.
pub struct ChildInput {
    pub proof: Vec<u8>,
    pub statement: Vec<u8>,
    pub binding: RequestBinding,
}

pub fn read_child_input(
    path: &Path,
    max_statement_bytes: usize,
) -> Result<ChildInput, &'static str> {
    let mut file = File::open(path).map_err(|_| "guard input unavailable")?;
    let mut header = [0; INPUT_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|_| "guard input header")?;
    if &header[..8] != INPUT_MAGIC
        || header[8..10] != 1u16.to_le_bytes()
        || header[10..12] != [0; 2]
    {
        return Err("guard input header");
    }
    let declared = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let declared = preflight_declared_length(declared).map_err(|_| "guard input fee length")?;
    let statement_len = u64::from_le_bytes(header[20..28].try_into().unwrap());
    if statement_len == 0 || statement_len > max_statement_bytes as u64 {
        return Err("guard input statement length");
    }
    let expected = (INPUT_HEADER_BYTES as u64)
        .checked_add(declared.bytes() as u64)
        .and_then(|n| n.checked_add(statement_len))
        .ok_or("guard input length overflow")?;
    if file.metadata().map_err(|_| "guard input metadata")?.len() != expected {
        return Err("guard input length");
    }
    let binding = RequestBinding::decode(&header[28..]);
    let mut proof = vec![0; declared.bytes()];
    let mut statement = vec![0; statement_len as usize];
    file.read_exact(&mut proof)
        .and_then(|_| file.read_exact(&mut statement))
        .map_err(|_| "guard input body")?;
    if binding.proof != proof_digest(&proof) || binding.statement != statement_digest(&statement) {
        return Err("guard input binding");
    }
    Ok(ChildInput {
        proof,
        statement,
        binding,
    })
}

/// Invoke only after the trusted child has verified the exact reconstructed
/// statement with the expected keys and profile. This encoder proves nothing.
pub fn write_child_receipt(
    path: &Path,
    binding: RequestBinding,
    verdict: ChildVerdict,
) -> std::io::Result<()> {
    let mut bytes = [0; RECEIPT_BYTES];
    bytes[..8].copy_from_slice(RECEIPT_MAGIC);
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10] = match verdict {
        ChildVerdict::Verified => 1,
        ChildVerdict::Rejected => 2,
    };
    binding.encode(&mut bytes[12..]);
    let mut file = new_private_file(path)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

struct Receipt {
    binding: RequestBinding,
    verdict: ChildVerdict,
}

fn read_receipt(path: &Path) -> Result<Receipt, Deferred> {
    let meta = fs::symlink_metadata(path).map_err(|_| Deferred::OutputMalformed)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Deferred::OutputMalformed);
    }
    if meta.len() > RECEIPT_BYTES as u64 {
        return Err(Deferred::OutputLimit);
    }
    if meta.len() != RECEIPT_BYTES as u64 {
        return Err(Deferred::OutputMalformed);
    }
    let mut file = File::open(path).map_err(|_| Deferred::OutputMalformed)?;
    let mut bytes = [0; RECEIPT_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| Deferred::OutputMalformed)?;
    let mut extra = [0; 1];
    if file
        .read(&mut extra)
        .map_err(|_| Deferred::OutputMalformed)?
        != 0
    {
        return Err(Deferred::OutputLimit);
    }
    if &bytes[..8] != RECEIPT_MAGIC || bytes[8..10] != 1u16.to_le_bytes() || bytes[11] != 0 {
        return Err(Deferred::OutputMalformed);
    }
    let verdict = match bytes[10] {
        1 => ChildVerdict::Verified,
        2 => ChildVerdict::Rejected,
        _ => return Err(Deferred::OutputMalformed),
    };
    Ok(Receipt {
        binding: RequestBinding::decode(&bytes[12..]),
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::sync::atomic::AtomicUsize;

    static NEXT: AtomicUsize = AtomicUsize::new(1);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-fee-guard-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // This is a uniquely created synthetic fixture directory only.
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn command(mode: &str) -> ChildCommand {
        let module = module_path!().split_once("::").unwrap().1;
        ChildCommand {
            executable: std::env::current_exe().unwrap(),
            arguments: [
                OsString::from("--exact"),
                OsString::from(format!("{module}::synthetic_child")),
                OsString::from("--ignored"),
                OsString::from("--test-threads=1"),
            ]
            .into(),
            environment: vec![(OsString::from("SIWORLD_FEE_GUARD_FIXTURE"), mode.into())],
        }
    }

    fn input(attempt: u8) -> VerificationInput<'static> {
        let proof = b"synthetic bounded fee frame bytes for process tests; not a valid proof";
        let statement = b"synthetic public statement";
        VerificationInput {
            declared: preflight_declared_length(proof.len() as u64).unwrap(),
            proof,
            statement,
            binding: RequestBinding {
                attempt: [attempt; 32],
                network: [2; 32],
                genesis: [3; 32],
                rules: [4; 32],
                profile: [5; 32],
                verifier_keys: [6; 32],
                statement: statement_digest(statement),
                proof: proof_digest(proof),
                canonical_context: [9; 32],
            },
        }
    }

    fn guard(timeout: Duration) -> FeeGuard {
        FeeGuard::new(GuardPolicy {
            timeout,
            poll_interval: Duration::from_millis(2),
            ..GuardPolicy::default()
        })
        .unwrap()
    }

    #[test]
    fn declared_oversize_is_rejected_before_receiving_a_body() {
        assert!(matches!(
            preflight_declared_length(MAX_FEE_PROOF_BYTES as u64 + 1),
            Err(LengthError::Oversize)
        ));
        assert!(matches!(
            preflight_declared_length(u64::MAX),
            Err(LengthError::Oversize)
        ));
        for length in 0..=FRAME_BYTES as u64 {
            assert!(matches!(
                preflight_declared_length(length),
                Err(LengthError::TooShort)
            ));
        }
        assert!(preflight_declared_length(FRAME_BYTES as u64 + 1).is_ok());
        assert_eq!(
            preflight_declared_length(MAX_FEE_PROOF_BYTES as u64)
                .unwrap()
                .bytes(),
            MAX_FEE_PROOF_BYTES
        );
    }

    #[test]
    fn exact_bound_receipt_is_checked_but_each_changed_binding_is_deferred() {
        let fixture = Fixture::new();
        let guard = guard(Duration::from_secs(2));
        let expected = input(1).binding;
        let Outcome::Checked(receipt) = guard.verify(input(1), &command("valid"), &fixture.0)
        else {
            panic!("synthetic receipt was not checked")
        };
        assert!(receipt.binding() == &expected);
        assert_eq!(receipt.verdict(), ChildVerdict::Verified);
        for field in 0..9 {
            assert!(matches!(
                guard.verify(
                    input(field + 2),
                    &command(&format!("binding-{field}")),
                    &fixture.0
                ),
                Outcome::Deferred(Deferred::BindingMismatch)
            ));
        }
        assert_eq!(fixture.0.read_dir().unwrap().count(), 0);
    }

    #[test]
    fn hard_timeout_reaps_child_and_releases_single_slot() {
        let fixture = Fixture::new();
        let guard = guard(Duration::from_millis(100));
        let start = Instant::now();
        assert!(matches!(
            guard.verify(input(20), &command("late"), &fixture.0),
            Outcome::Deferred(Deferred::Timeout)
        ));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!guard.occupied.load(Ordering::Acquire));
        assert_eq!(fixture.0.read_dir().unwrap().count(), 0);
        assert!(matches!(
            guard.verify(input(21), &command("valid"), &fixture.0),
            Outcome::Checked(_)
        ));
    }

    #[test]
    fn oversized_output_is_rejected_and_child_is_reaped() {
        let fixture = Fixture::new();
        let guard = guard(Duration::from_secs(2));
        assert!(matches!(
            guard.verify(input(30), &command("oversize"), &fixture.0),
            Outcome::Deferred(Deferred::OutputLimit)
        ));
        assert!(!guard.occupied.load(Ordering::Acquire));
    }

    #[test]
    fn a_success_receipt_without_timely_child_exit_cannot_be_admitted() {
        let fixture = Fixture::new();
        let guard = guard(Duration::from_millis(100));
        assert!(matches!(
            guard.verify(input(40), &command("receipt-then-late-exit"), &fixture.0),
            Outcome::Deferred(Deferred::Timeout)
        ));
        assert_eq!(fixture.0.read_dir().unwrap().count(), 0);
    }

    #[test]
    fn one_shared_slot_refuses_a_concurrent_child() {
        let fixture = Fixture::new();
        let guard = guard(Duration::from_millis(300));
        let other = guard.clone();
        let base = fixture.0.clone();
        let handle = std::thread::spawn(move || other.verify(input(50), &command("late"), &base));
        let limit = Instant::now() + Duration::from_secs(2);
        while !guard.occupied.load(Ordering::Acquire) {
            assert!(Instant::now() < limit);
            std::thread::yield_now();
        }
        let mut second = input(51);
        second.binding.proof = [0; 32];
        assert!(matches!(
            guard.verify(second, &command("valid"), &fixture.0),
            Outcome::Deferred(Deferred::Busy)
        ));
        assert!(matches!(
            handle.join().unwrap(),
            Outcome::Deferred(Deferred::Timeout)
        ));
    }

    #[test]
    fn the_shared_deadline_also_covers_input_hashing_and_staging() {
        let fixture = Fixture::new();
        let guard = FeeGuard::new(GuardPolicy {
            timeout: Duration::from_nanos(1),
            poll_interval: Duration::from_nanos(1),
            ..GuardPolicy::default()
        })
        .unwrap();
        assert!(matches!(
            guard.verify(input(60), &command("valid"), &fixture.0),
            Outcome::Deferred(Deferred::Timeout)
        ));
        assert!(!guard.occupied.load(Ordering::Acquire));
        assert_eq!(fixture.0.read_dir().unwrap().count(), 0);
    }

    #[test]
    #[ignore = "explicit synthetic child mode only; never verifies a real proof"]
    fn synthetic_child() {
        let Some(mode) = std::env::var_os("SIWORLD_FEE_GUARD_FIXTURE") else {
            panic!("explicit synthetic mode required")
        };
        let request = PathBuf::from(std::env::var_os(REQUEST_ENV).unwrap());
        let receipt = PathBuf::from(std::env::var_os(RECEIPT_ENV).unwrap());
        let mut input = read_child_input(&request, 1024 * 1024).unwrap();
        assert!(!input.proof.is_empty() && !input.statement.is_empty());
        if mode == OsStr::new("late") {
            std::thread::sleep(Duration::from_secs(3));
        }
        if mode == OsStr::new("oversize") {
            let mut file = new_private_file(&receipt).unwrap();
            file.write_all(&[0; RECEIPT_BYTES + 1]).unwrap();
            file.sync_all().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            return;
        }
        if let Some(field) = mode.to_str().unwrap().strip_prefix("binding-") {
            let field: usize = field.parse().unwrap();
            let mut bytes = [0; BINDING_BYTES];
            input.binding.encode(&mut bytes);
            bytes[field * 32] ^= 1;
            input.binding = RequestBinding::decode(&bytes);
        }
        write_child_receipt(&receipt, input.binding, ChildVerdict::Verified).unwrap();
        if mode == OsStr::new("receipt-then-late-exit") {
            std::thread::sleep(Duration::from_secs(3));
        }
    }
}
