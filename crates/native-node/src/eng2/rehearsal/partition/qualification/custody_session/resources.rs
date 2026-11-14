//! Actual cgroup/disk/run-root observations; process death/deadline uses the owner guardian.
use super::*;
use std::os::unix::fs::MetadataExt;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourcePlan {
    pub run_root: PathBuf,
    cgroup: String,
    maximum_memory_bytes: u64,
    maximum_pids: u64,
    maximum_run_bytes: u64,
    maximum_run_entries: u64,
    minimum_disk_free_bytes: u64,
    pub deadline_seconds: u64,
    pub maximum_frame_bytes: u64,
    pub maximum_total_frame_bytes: u64,
    pub maximum_decode_bytes: u64,
}
pub(super) struct Guard<'a> {
    plan: &'a ResourcePlan,
    started: Instant,
    device: u64,
    inode: u64,
    group: PathBuf,
    events: Vec<u8>,
}
fn number(path: &Path) -> Result<u64> {
    let s = fs::read_to_string(path).map_err(|_| "custody_resource_unavailable")?;
    if s.len() > 65536 {
        return Err("custody_resource_rejected".into());
    }
    s.trim()
        .parse()
        .map_err(|_| "custody_resource_rejected".into())
}
impl<'a> Guard<'a> {
    pub fn new(plan: &'a ResourcePlan) -> Result<Self> {
        canonical_private(&plan.run_root)?;
        if !cfg!(target_os = "linux")
            || plan.cgroup == "/"
            || !plan.cgroup.starts_with('/')
            || Path::new(&plan.cgroup).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || !(1..=32 * 1024 * 1024 * 1024u64).contains(&plan.maximum_memory_bytes)
            || !(1..=64).contains(&plan.maximum_pids)
            || !(1..=64 * 1024 * 1024 * 1024u64).contains(&plan.maximum_run_bytes)
            || !(1..=200000).contains(&plan.maximum_run_entries)
            || plan.minimum_disk_free_bytes < 128 * 1024 * 1024 * 1024u64
            || !(1..=3600).contains(&plan.deadline_seconds)
            || plan.maximum_frame_bytes < 190
            || plan.maximum_total_frame_bytes < plan.maximum_frame_bytes
            || plan.maximum_total_frame_bytes > 16 * 1024 * 1024 * 1024u64
            || !(65536..=4 * 1024 * 1024 * 1024u64).contains(&plan.maximum_decode_bytes)
        {
            return Err("custody_resource_plan_rejected".into());
        }
        let group = Path::new("/sys/fs/cgroup").join(plan.cgroup.trim_start_matches('/'));
        if group.canonicalize().ok().as_deref() != Some(group.as_path()) {
            return Err("custody_cgroup_path_rejected".into());
        }
        let meta =
            fs::symlink_metadata(&plan.run_root).map_err(|_| "custody_resource_unavailable")?;
        let events =
            fs::read(group.join("memory.events")).map_err(|_| "custody_resource_unavailable")?;
        if events.len() > 65536 {
            return Err("custody_resource_rejected".into());
        }
        let g = Self {
            plan,
            started: Instant::now(),
            device: meta.dev(),
            inode: meta.ino(),
            group,
            events,
        };
        g.check()?;
        Ok(g)
    }
    pub fn check(&self) -> Result<()> {
        if self.started.elapsed().as_secs() >= self.plan.deadline_seconds {
            return Err("custody_deadline".into());
        }
        let membership =
            fs::read_to_string("/proc/self/cgroup").map_err(|_| "custody_resource_unavailable")?;
        if membership.len() > 65536
            || membership
                .lines()
                .filter_map(|l| l.strip_prefix("0::"))
                .collect::<Vec<_>>()
                != [self.plan.cgroup.as_str()]
            || !(1..=self.plan.maximum_memory_bytes)
                .contains(&number(&self.group.join("memory.max"))?)
            || number(&self.group.join("memory.current"))? > self.plan.maximum_memory_bytes
            || !(1..=self.plan.maximum_pids).contains(&number(&self.group.join("pids.max"))?)
            || number(&self.group.join("pids.current"))? > self.plan.maximum_pids
            || number(&self.group.join("memory.swap.max"))? != 0
            || number(&self.group.join("memory.swap.current"))? != 0
            || fs::read(self.group.join("memory.events"))
                .map_err(|_| "custody_resource_unavailable")?
                != self.events
        {
            return Err("custody_actual_cgroup_rejected".into());
        }
        let meta = fs::symlink_metadata(&self.plan.run_root)
            .map_err(|_| "custody_resource_unavailable")?;
        if meta.dev() != self.device || meta.ino() != self.inode {
            return Err("custody_run_root_changed".into());
        }
        let stat =
            rustix::fs::statvfs(&self.plan.run_root).map_err(|_| "custody_resource_unavailable")?;
        let free = (stat.f_bavail as u128) * (stat.f_frsize as u128);
        if free < u128::from(self.plan.minimum_disk_free_bytes) {
            return Err("custody_disk_floor".into());
        }
        let (mut bytes, mut entries) = (0u64, 0u64);
        self.walk(&self.plan.run_root, 0, &mut bytes, &mut entries)
    }
    fn walk(&self, path: &Path, depth: u32, bytes: &mut u64, entries: &mut u64) -> Result<()> {
        if self.started.elapsed().as_secs() >= self.plan.deadline_seconds || depth > 64 {
            return Err("custody_resource_deadline".into());
        }
        *entries = entries.checked_add(1).ok_or("custody_resource_overflow")?;
        let m = fs::symlink_metadata(path).map_err(|_| "custody_resource_unavailable")?;
        if *entries > self.plan.maximum_run_entries
            || m.dev() != self.device
            || !(m.is_dir() || m.is_file())
            || m.is_file() && m.nlink() != 1
        {
            return Err("custody_run_inventory_rejected".into());
        }
        if m.is_file() {
            *bytes = bytes
                .checked_add(m.len())
                .ok_or("custody_resource_overflow")?;
            if *bytes > self.plan.maximum_run_bytes {
                return Err("custody_run_bytes_exhausted".into());
            }
        } else {
            for item in fs::read_dir(path).map_err(|_| "custody_resource_unavailable")? {
                self.walk(
                    &item.map_err(|_| "custody_resource_unavailable")?.path(),
                    depth + 1,
                    bytes,
                    entries,
                )?;
            }
        }
        Ok(())
    }
}
