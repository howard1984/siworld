//! Bounded owner-local public requests, never transaction or signing authority.
use super::*;
use crate::{
    eng2::execution::CommittedBlock, eng2_operations::PendingOperations, issuance::IssuanceRecord,
};
mod io;
#[cfg(test)]
mod tests;

const MAX_BUNDLE_BYTES: usize = crate::eng2_operations::MAX_INPUT_BYTES
    + 2 * crate::issuance::RECORDS_CODEC_LIMIT * crate::issuance::MAX_RECORD_BYTES
    + 4096;
const MAX_REQUEST_BYTES: usize = MAX_BUNDLE_BYTES + 2048;
const MAX_RESULT_BYTES: usize = 2048;
const REQUEST: &str = "request.json";
const RESULT: &str = "result.json";

fn exact(value: &Value, fields: &[&str]) -> Result<(), String> {
    if value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|key| object.contains_key(*key))
    }) {
        Ok(())
    } else {
        Err("operations object fields differ".into())
    }
}
fn canonical(bytes: &[u8], limit: usize) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("operations input byte bound".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "operations input JSON rejected")?;
    if serde_json::to_vec(&value).map_err(|_| "operations JSON encoding failed")? != bytes {
        return Err("operations input must use canonical compact JSON".into());
    }
    Ok(value)
}
fn hash(text: &str) -> Result<Hash, String> {
    crate::eng2_operations::public_bytes(&json!(text), 32)?
        .try_into()
        .map_err(|_| "operations binding requires a complete lowercase digest".into())
}
fn height(text: &str) -> Result<u64, String> {
    let value = text
        .parse::<u64>()
        .map_err(|_| "operations height rejected")?;
    if value == 0 || value.to_string() != text {
        return Err("operations height must be positive canonical decimal".into());
    }
    Ok(value)
}
fn decode_bundle(
    value: &Value,
    network: Hash,
    next: u64,
) -> Result<(Option<PendingOperations>, Vec<IssuanceRecord>), String> {
    exact(value, &["version", "operations", "issuances"])?;
    if value["version"] != 1 {
        return Err("operations bundle version rejected".into());
    }
    let operations = if value["operations"].is_null() {
        None
    } else {
        Some(PendingOperations::decode(
            &serde_json::to_vec(&value["operations"])
                .map_err(|_| "public operations encoding failed")?,
            network,
            next,
        )?)
    };
    let records = value["issuances"]
        .as_array()
        .ok_or("expected bounded public issuance list")?;
    if records.len() > crate::issuance::RECORDS_CODEC_LIMIT
        || (operations.is_none() && records.is_empty())
    {
        return Err("operations bundle must contain bounded public input".into());
    }
    if records.is_empty()
        && value["operations"]["fund_claims"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && value["operations"]["governance"]
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        return Err("operations bundle contains no public operations".into());
    }
    let issuances = records
        .iter()
        .map(|record| {
            let bytes =
                crate::eng2_operations::public_bytes(record, crate::issuance::MAX_RECORD_BYTES)?;
            let decoded = IssuanceRecord::decode(&bytes)?;
            if decoded.signed.declaration.network != network || decoded.encode()? != bytes {
                return Err("public issuance context or canonical encoding rejected".into());
            }
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if issuances
        .windows(2)
        .any(|pair| pair[0].signed.declaration.binding() >= pair[1].signed.declaration.binding())
    {
        return Err("public issuance order or uniqueness rejected".into());
    }
    Ok((operations, issuances))
}

struct Active {
    id: String,
    run: String,
    parent: Hash,
    height: u64,
    operations: Option<PendingOperations>,
    issuances: Vec<IssuanceRecord>,
    _reservation: p2p::Reservation,
}
/// A request remains charged through preparation, proving, work and commit.
/// Every abandoned path records an interrupted outcome, never a submission.
pub(super) struct Submission<'a> {
    mailbox: &'a Mailbox,
    active: Active,
    finished: bool,
}
impl Submission<'_> {
    pub(super) fn inputs(&mut self) -> (Option<PendingOperations>, Vec<IssuanceRecord>) {
        (
            self.active.operations.take(),
            std::mem::take(&mut self.active.issuances),
        )
    }
    pub(super) fn fail(&mut self, outcome: &'static str) {
        self.mailbox.fail(&self.active, outcome);
        self.finished = true;
    }
    pub(super) fn committed(&mut self, committed: &CommittedBlock, store: &Store) {
        self.mailbox.committed(&self.active, committed, store);
        self.finished = true;
    }
}
impl Drop for Submission<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.mailbox.fail(&self.active, "production_interrupted");
        }
    }
}
pub(super) struct Mailbox {
    files: io::Files,
    run: String,
    network: Hash,
    genesis: Hash,
    error: Mutex<Option<&'static str>>,
}
impl Mailbox {
    pub(super) fn open(
        directory: &Path,
        run: &str,
        network: Hash,
        genesis: Hash,
    ) -> Result<Self, String> {
        hash(run)?;
        let value = Self {
            files: io::Files::open(directory)?,
            run: run.into(),
            network,
            genesis,
            error: Mutex::new(None),
        };
        // A restart never retries an old request or rewrites its signed height.
        let _lock = value.files.lock()?;
        if let Some(bytes) = value.files.read(RESULT, MAX_RESULT_BYTES)? {
            let mut result = canonical(&bytes, MAX_RESULT_BYTES)?;
            if matches!(result["outcome"].as_str(), Some("queued" | "preparing")) {
                result["outcome"] = json!("interrupted");
                value.files.replace(
                    RESULT,
                    &serde_json::to_vec(&result)
                        .map_err(|_| "operations result encoding failed")?,
                    MAX_RESULT_BYTES,
                )?;
            }
        }
        value.files.remove(REQUEST, MAX_REQUEST_BYTES)?;
        Ok(value)
    }
    pub(super) fn error(&self) -> Option<&'static str> {
        self.error.lock().ok().and_then(|value| *value)
    }
    pub(super) fn alarm(&self) {
        if let Ok(mut error) = self.error.lock() {
            *error = Some("local_operations_unavailable");
        }
    }
    fn write_result(
        &self,
        id: &str,
        selected_run: &str,
        next: u64,
        outcome: &str,
        block: Option<Hash>,
    ) -> Result<(), String> {
        let value = json!({"version":1,"request_id":id,"run_id":selected_run,
            "height":next.to_string(),"outcome":outcome,"block_id":block.map(|id|crate::local::hex(&id))});
        self.files.replace(
            RESULT,
            &serde_json::to_vec(&value).map_err(|_| "operations result encoding failed")?,
            MAX_RESULT_BYTES,
        )
    }
    pub(super) fn take(
        &self,
        head: &super::super::driver::Head,
        budget: &p2p::Budget,
    ) -> Result<Option<Submission<'_>>, String> {
        let _lock = self.files.lock()?;
        let reservation = budget
            .reserve(3 * MAX_REQUEST_BYTES + 65536)
            .map_err(|_| "operations memory budget unavailable")?;
        let Some(bytes) = self.files.read(REQUEST, MAX_REQUEST_BYTES)? else {
            return Ok(None);
        };
        let id = crate::local::hex(blake3::hash(&bytes).as_bytes());
        let parsed = (|| {
            let value = canonical(&bytes, MAX_REQUEST_BYTES)?;
            exact(
                &value,
                &[
                    "version", "run_id", "network", "genesis", "parent", "height", "bundle",
                ],
            )?;
            if value["version"] != 1
                || value["run_id"] != self.run
                || value["network"] != crate::local::hex(&self.network)
                || value["genesis"] != crate::local::hex(&self.genesis)
                || value["parent"] != crate::local::hex(&head.id)
                || head.network != self.network
                || head.genesis != self.genesis
            {
                return Err("operations run or parent is stale".to_owned());
            }
            let next = height(
                value["height"]
                    .as_str()
                    .ok_or("operations height missing")?,
            )?;
            if head.height.checked_add(1) != Some(next) {
                return Err("operations height is stale".into());
            }
            let (operations, issuances) = decode_bundle(&value["bundle"], self.network, next)?;
            Ok(Active {
                id: id.clone(),
                run: self.run.clone(),
                parent: head.id,
                height: next,
                operations,
                issuances,
                _reservation: reservation,
            })
        })();
        match parsed {
            Ok(active) => {
                self.write_result(&id, &self.run, active.height, "preparing", None)?;
                self.files.remove(REQUEST, MAX_REQUEST_BYTES)?;
                Ok(Some(Submission {
                    mailbox: self,
                    active,
                    finished: false,
                }))
            }
            Err(_) => {
                self.write_result(
                    &id,
                    &self.run,
                    head.height.saturating_add(1),
                    "request_rejected",
                    None,
                )?;
                self.files.remove(REQUEST, MAX_REQUEST_BYTES)?;
                Ok(None)
            }
        }
    }
    fn fail(&self, active: &Active, outcome: &'static str) {
        let result = (|| {
            let _lock = self.files.lock()?;
            self.write_result(&active.id, &active.run, active.height, outcome, None)
        })();
        if result.is_err() {
            self.alarm();
        }
    }
    /// An Engine capability alone does not assert disk durability. Check the
    /// actual Store's authenticated header before publishing a committed result.
    fn committed(&self, active: &Active, committed: &CommittedBlock, store: &Store) {
        let result = (|| {
            store.ensure_exportable()?;
            let header = store.header(active.height)?;
            if committed.height() != active.height
                || committed.network() != self.network
                || header.parent != active.parent
                || header.id().map_err(|_| "committed header invalid")? != committed.id()
                || store.engine().genesis().id() != self.genesis
                || active.run != self.run
            {
                return Err("operations durable inclusion differs".to_owned());
            }
            let _lock = self.files.lock()?;
            self.write_result(
                &active.id,
                &active.run,
                active.height,
                "committed",
                Some(committed.id()),
            )
        })();
        if result.is_err() {
            self.alarm();
        }
    }
}

pub fn submit(
    directory: &Path,
    public_bundle: &Path,
    run: &str,
    parent: &str,
    next: &str,
    expected: &str,
) -> Result<Value, String> {
    let genesis = load_genesis(directory, expected)?;
    hash(run)?;
    hash(parent)?;
    let next_height = height(next)?;
    let mut bytes = Vec::new();
    // This is the only caller-selected input. No custody or sidecar path is derived.
    crate::local::regular_read(public_bundle, false, MAX_BUNDLE_BYTES)?
        .take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "explicit public operations bundle read failed")?;
    let bundle = canonical(&bytes, MAX_BUNDLE_BYTES)?;
    decode_bundle(&bundle, genesis.config().network, next_height)?;
    let files = io::Files::open(directory)?;
    let _lock = files.lock()?;
    let status = service::exported_status(directory)?;
    let now = unix_ms()?;
    let updated = status["updated_unix_ms"]
        .as_u64()
        .ok_or("fresh resident status required")?;
    if status["schema_version"] != 2
        || status["run_id"] != run
        || status["tip"] != parent
        || status["height"].as_u64().and_then(|h| h.checked_add(1)) != Some(next_height)
        || status["genesis_id"] != expected
        || status["network_id"] != crate::local::hex(&genesis.config().network)
        || status["mining_enabled"] != true
        || status["ready"] != true
        || !status["operations_error"].is_null()
        || matches!(
            status["phase"].as_str(),
            None | Some("stopped" | "stopping" | "error")
        )
        || updated > now.saturating_add(1000)
        || now.saturating_sub(updated) > 15_000
    {
        return Err("fresh mining status with exact run, parent and next height required".into());
    }
    if files.read(REQUEST, MAX_REQUEST_BYTES)?.is_some() {
        return Err("operations single request slot occupied".into());
    }
    if let Some(bytes) = files.read(RESULT, MAX_RESULT_BYTES)? {
        let result = canonical(&bytes, MAX_RESULT_BYTES)?;
        if result["run_id"] == run
            && matches!(result["outcome"].as_str(), Some("queued" | "preparing"))
        {
            return Err("operations request is already active".into());
        }
    }
    let request = json!({"version":1,"run_id":run,"network":crate::local::hex(&genesis.config().network),
        "genesis":expected,"parent":parent,"height":next,"bundle":bundle});
    let encoded = serde_json::to_vec(&request).map_err(|_| "operations request encoding failed")?;
    let id = crate::local::hex(blake3::hash(&encoded).as_bytes());
    let result = json!({"version":1,"request_id":id,"run_id":run,"height":next,"outcome":"queued","block_id":null});
    files.replace(
        RESULT,
        &serde_json::to_vec(&result).map_err(|_| "operations result encoding failed")?,
        MAX_RESULT_BYTES,
    )?;
    files.replace(REQUEST, &encoded, MAX_REQUEST_BYTES)?;
    Ok(result)
}
pub fn result(directory: &Path, run: &str) -> Result<Value, String> {
    hash(run)?;
    let files = io::Files::open(directory)?;
    let _lock = files.lock()?;
    let bytes = files
        .read(RESULT, MAX_RESULT_BYTES)?
        .ok_or("operations result unavailable")?;
    let result = canonical(&bytes, MAX_RESULT_BYTES)?;
    if result["run_id"] != run {
        return Err("operations result belongs to another run".into());
    }
    Ok(result)
}
