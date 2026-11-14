//! Explicit complete-history bounds for an existing stopped business owner.
//! This does not replace the caller's hard process resource guard or lease.
use super::*;
use crate::eng2::{
    header::{HEADER_BYTES, Header},
    store::BodyAvailability,
};
use crate::p2p::{Budget as MemoryBudget, Reservation};

const GIB: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * GIB;
const MAX_DECODE_BYTES: u64 = 4 * GIB;
const MIN_DISK_FREE_BYTES: u64 = 128 * GIB;
const OUTPUT_METADATA_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryBudget {
    version: u32,
    height: u64,
    tip: String,
    maximum_total_frame_bytes: u64,
    maximum_frame_bytes: u64,
    maximum_decode_bytes: u64,
    deadline_seconds: u64,
    minimum_disk_free_bytes: u64,
}
impl HistoryBudget {
    fn validate(
        &self,
        height: u64,
        tip: &str,
        frame_limit: u64,
        deadline: u64,
    ) -> Result<(), String> {
        let minimum = height
            .checked_mul(HEADER_BYTES as u64)
            .ok_or("business history height overflow")?;
        if self.version != 1
            || !(1..=super::super::full_history::MAX_HISTORY_HEIGHT - MAX_STEPS as u64)
                .contains(&height)
            || self.height != height
            || self.tip != tip
            || !hex(&self.tip, 32)
            || self.maximum_total_frame_bytes < minimum
            || self.maximum_total_frame_bytes > MAX_TOTAL_BYTES
            || self.maximum_frame_bytes <= HEADER_BYTES as u64
            || self.maximum_frame_bytes > frame_limit
            || self.maximum_frame_bytes > self.maximum_total_frame_bytes
            || !(65536..=MAX_DECODE_BYTES).contains(&self.maximum_decode_bytes)
            || !(1..=deadline).contains(&self.deadline_seconds)
            || self.minimum_disk_free_bytes < MIN_DISK_FREE_BYTES
        {
            return Err("business explicit complete-history budget rejected".into());
        }
        Ok(())
    }
    fn tick(&self, started: Instant) -> Result<(), String> {
        if started.elapsed().as_secs() >= self.deadline_seconds {
            return Err("business complete-history deadline exhausted".into());
        }
        Ok(())
    }
    fn add_frame(&self, total: u64, bytes: u64) -> Result<u64, String> {
        if bytes <= HEADER_BYTES as u64 || bytes > self.maximum_frame_bytes {
            return Err("business original frame exceeds explicit per-frame bound".into());
        }
        total
            .checked_add(bytes)
            .filter(|n| *n <= self.maximum_total_frame_bytes)
            .ok_or_else(|| "business complete original prefix exceeds total byte budget".into())
    }
}
struct FrozenFrame {
    header: Header,
    bytes: u64,
}
pub(super) struct FrozenPrefix {
    budget: HistoryBudget,
    budget_bytes: Vec<u8>,
    budget_path: PathBuf,
    budget_pin: String,
    frames: Vec<FrozenFrame>,
    total_frame_bytes: u64,
    memory: MemoryBudget,
    _metadata: Reservation,
    output_parent: PathBuf,
    started: Instant,
}
fn disk(path: &Path, minimum: u64, additional: u64) -> Result<(), String> {
    let stat = rustix::fs::statvfs(path).map_err(|_| "business history disk observation failed")?;
    let free = u64::try_from(stat.f_bavail as u128 * stat.f_frsize as u128)
        .map_err(|_| "business history disk observation overflow")?;
    if free
        < minimum
            .checked_add(additional)
            .ok_or("business history disk reservation overflow")?
    {
        return Err("business history disk free floor would be crossed".into());
    }
    Ok(())
}
fn frame_charge(bytes: u64) -> Result<usize, String> {
    usize::try_from(
        bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(65536))
            .ok_or("business original frame allocation overflow")?,
    )
    .map_err(|_| "business original frame allocation width".into())
}
impl FrozenPrefix {
    pub(super) fn prepare(
        context: &Context,
        store: &Store,
        plan: &Plan,
        output: &Path,
        started: Instant,
        custody: &mut impl Custody,
    ) -> Result<Self, String> {
        let input = &plan.history_budget;
        if input.path.len() > 2048 || !hex(&input.sha256, 32) {
            return Err("business complete-history budget input rejected".into());
        }
        let budget_path = PathBuf::from(&input.path);
        let budget_bytes = read(&budget_path, 4096)?;
        context.check_manifest_pin(&budget_bytes, &input.sha256)?;
        let budget: HistoryBudget = serde_json::from_slice(&budget_bytes)
            .map_err(|_| "business complete-history budget schema rejected")?;
        let frame_limit = HEADER_BYTES
            .checked_add(store.engine().body_policy().max_body_bytes)
            .ok_or("business history native frame bound overflow")?;
        budget.validate(
            plan.start_height,
            &plan.start_tip,
            frame_limit as u64,
            plan.deadline_seconds,
        )?;
        let output_parent = output
            .parent()
            .ok_or("business output parent missing")?
            .to_path_buf();
        disk(
            &output_parent,
            budget.minimum_disk_free_bytes,
            plan.max_output_bytes,
        )?;
        super::super::full_history::check_database(Path::new(&plan.isolated_directory))?;
        let memory = MemoryBudget::new(
            usize::try_from(budget.maximum_decode_bytes)
                .map_err(|_| "business history memory budget width")?,
        );
        let count =
            usize::try_from(budget.height).map_err(|_| "business history frame count width")?;
        let metadata_bytes = count
            .checked_mul(std::mem::size_of::<FrozenFrame>())
            .and_then(|n| n.checked_add(65536))
            .ok_or("business history metadata bound overflow")?;
        let metadata = memory
            .reserve(metadata_bytes)
            .map_err(|_| "business history metadata reservation unavailable")?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(count)
            .map_err(|_| "business history metadata allocation unavailable")?;
        let mut parent = store.engine().genesis().id();
        let mut total = 0u64;
        for height in 1..=budget.height {
            gate(started, plan, custody, "before_original_prefix_metadata")?;
            budget.tick(started)?;
            let header = store.header(height)?;
            let body_bytes = store.block_size(height)?;
            if header.height != height
                || header.parent != parent
                || store.body_availability(height)?
                    != (BodyAvailability::Full {
                        encoded_body_bytes: body_bytes,
                    })
            {
                return Err("business requires every original contiguous canonical body".into());
            }
            let bytes = (HEADER_BYTES as u64)
                .checked_add(body_bytes as u64)
                .ok_or("business original frame byte overflow")?;
            total = budget.add_frame(total, bytes)?;
            let required = frame_charge(bytes)?;
            let _probe = memory
                .reserve(required)
                .map_err(|_| "business original frame exceeds decode reservation")?;
            parent = header
                .id()
                .map_err(|_| "business original header identity rejected")?;
            frames.push(FrozenFrame { header, bytes });
        }
        if crate::local::hex(&parent) != plan.start_tip {
            return Err("business complete original prefix tip differs".into());
        }
        // Reserve complete original frames, four maximum native frames and bounded
        // metadata before any proof or append can make output failure irreversible.
        let required_output = (frame_limit as u64)
            .checked_mul(MAX_STEPS as u64)
            .and_then(|n| n.checked_add(total))
            .and_then(|n| n.checked_add(OUTPUT_METADATA_BYTES))
            .ok_or("business complete output reservation overflow")?;
        if required_output > plan.max_output_bytes {
            return Err("business output budget cannot retain original prefix and campaign".into());
        }
        let result = Self {
            budget,
            budget_bytes,
            budget_path,
            budget_pin: input.sha256.clone(),
            frames,
            total_frame_bytes: total,
            memory,
            _metadata: metadata,
            output_parent,
            started,
        };
        result.check_head(store)?;
        Ok(result)
    }
    pub(super) fn check_head(&self, store: &Store) -> Result<(), String> {
        self.budget.tick(self.started)?;
        store.ensure_exportable()?;
        if store.engine().state().height() != self.budget.height
            || crate::local::hex(&store.engine().state().tip()) != self.budget.tip
        {
            return Err("business exact original head changed before append".into());
        }
        Ok(())
    }
    pub(super) fn before_frame(&self, store: &Store, height: u64) -> Result<Reservation, String> {
        self.check_head(store)?;
        let expected = self.at(height)?;
        if store.header(height)? != expected.header
            || store.block_size(height)? as u64 + HEADER_BYTES as u64 != expected.bytes
        {
            return Err("business frozen original frame metadata changed".into());
        }
        disk(
            &self.output_parent,
            self.budget.minimum_disk_free_bytes,
            expected.bytes,
        )?;
        self.memory
            .reserve(frame_charge(expected.bytes)?)
            .map_err(|_| "business original frame memory reservation unavailable".into())
    }
    fn at(&self, height: u64) -> Result<&FrozenFrame, String> {
        height
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.frames.get(n))
            .ok_or_else(|| "business original frame outside complete prefix".into())
    }
    pub(super) fn check_frame(&self, header: &Header, bytes: usize) -> Result<(), String> {
        let expected = self.at(header.height)?;
        if header != &expected.header || bytes as u64 != expected.bytes {
            return Err("business decoded original frame differs from frozen prefix".into());
        }
        self.budget.tick(self.started)
    }
    pub(super) fn budget_bytes(&self) -> &[u8] {
        &self.budget_bytes
    }
    pub(super) fn check_input_unchanged(&self) -> Result<(), String> {
        if read(&self.budget_path, 4096)? != self.budget_bytes {
            return Err("business pinned original history budget changed".into());
        }
        Ok(())
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"version":1,"height":self.budget.height,"tip":self.budget.tip,
            "history_budget_sha256":self.budget_pin,"original_frame_count":self.frames.len(),
            "original_total_frame_bytes":self.total_frame_bytes,"complete_genesis_prefix":true,
            "frame_memory_reservations_performed":true,"hard_process_guard_verified":false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> HistoryBudget {
        HistoryBudget {
            version: 1,
            height: 151,
            tip: "01".repeat(32),
            maximum_total_frame_bytes: 151 * 4096,
            maximum_frame_bytes: 4096,
            maximum_decode_bytes: 16 * 1024 * 1024,
            deadline_seconds: 900,
            minimum_disk_free_bytes: MIN_DISK_FREE_BYTES,
        }
    }
    #[test]
    fn explicit_history_budget_accepts_exact_head_above_old_prefix_limit() {
        let b = budget();
        assert!(b.validate(151, &"01".repeat(32), 8192, 900).is_ok());
        assert!(b.validate(150, &b.tip, 8192, 900).is_err());
        assert!(b.validate(151, &"02".repeat(32), 8192, 900).is_err());
        assert!(b.validate(151, &b.tip, 2048, 900).is_err());
        assert!(b.validate(151, &b.tip, 8192, 899).is_err());
    }
    #[test]
    fn complete_frame_accounting_never_truncates_or_overflows() {
        let b = budget();
        assert_eq!(b.add_frame(150 * 4096, 4096).unwrap(), 151 * 4096);
        assert!(b.add_frame(151 * 4096, 4096).is_err());
        assert!(b.add_frame(u64::MAX, 4096).is_err());
        assert!(b.add_frame(0, 4097).is_err());
        assert!(b.add_frame(0, HEADER_BYTES as u64).is_err());
        assert!(frame_charge(u64::MAX).is_err());
    }
}
