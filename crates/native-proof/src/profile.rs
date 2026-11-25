//! Fixed-label events for the isolated benchmark. Never emits proof inputs.
use std::sync::OnceLock;
use std::time::Instant;

pub struct Span(&'static str);

impl Span {
    pub fn new(name: &'static str) -> Self {
        emit(name, "start");
        Self(name)
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        emit(self.0, "end");
    }
}

fn emit(name: &str, event: &str) {
    if std::env::var_os("SIWORLD_BENCH_PROFILE").is_none() {
        return;
    }
    static START: OnceLock<Instant> = OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_nanos();
    eprintln!(
        "{{\"phase\":\"{name}\",\"event\":\"{event}\",\"ns\":{elapsed},\"thread\":\"{:?}\"}}",
        std::thread::current().id()
    );
}

/// Cumulative process CPU ticks, including all threads in this process.
/// Child process CPU is measured separately by the cgroup supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCpuTicks {
    pub user: u64,
    pub system: u64,
}

impl ProcessCpuTicks {
    pub fn elapsed_since(self, start: Self) -> Option<Self> {
        Some(Self {
            user: self.user.checked_sub(start.user)?,
            system: self.system.checked_sub(start.system)?,
        })
    }
}

fn parse_process_cpu_ticks(stat: &str) -> Option<ProcessCpuTicks> {
    // The comm field can contain spaces and parentheses. Fields after its
    // final closing parenthesis start at field 3 (the process state).
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();
    let user = fields.nth(11)?.parse().ok()?;
    let system = fields.next()?.parse().ok()?;
    Some(ProcessCpuTicks { user, system })
}

/// Linux process CPU accounting is unavailable on other hosts.
pub fn process_cpu_ticks() -> Option<ProcessCpuTicks> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    parse_process_cpu_ticks(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

/// Resolve the Linux accounting tick frequency once, before timed proof work.
pub fn clock_ticks_per_second() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    static FREQUENCY: OnceLock<Option<u64>> = OnceLock::new();
    *FREQUENCY.get_or_init(|| {
        let output = std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = std::str::from_utf8(&output.stdout)
            .ok()?
            .trim()
            .parse()
            .ok()?;
        (value > 0).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::{ProcessCpuTicks, parse_process_cpu_ticks};

    #[test]
    fn process_stat_accounts_for_parentheses_and_spaces_in_comm() {
        let stat = "42 (proof ) worker) R 1 2 3 4 5 6 7 8 9 10 123 45 0 0";
        assert_eq!(
            parse_process_cpu_ticks(stat),
            Some(ProcessCpuTicks {
                user: 123,
                system: 45
            })
        );
        assert_eq!(parse_process_cpu_ticks("42 (truncated) R 1"), None);
        assert_eq!(parse_process_cpu_ticks("invalid"), None);
    }

    #[test]
    fn cpu_tick_deltas_reject_counter_regression() {
        let start = ProcessCpuTicks {
            user: 100,
            system: 10,
        };
        assert_eq!(
            ProcessCpuTicks {
                user: 130,
                system: 14
            }
            .elapsed_since(start),
            Some(ProcessCpuTicks {
                user: 30,
                system: 4
            })
        );
        assert_eq!(
            ProcessCpuTicks {
                user: 99,
                system: 14
            }
            .elapsed_since(start),
            None
        );
    }
}
