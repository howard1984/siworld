//! Read-only monotonic bounds around one progress snapshot.
use serde_json::Value;
#[cfg(any(target_os = "linux", test))]
use serde_json::json;

/// One event timestamp with its kernel boot binding. Unsupported hosts do not
/// produce a timestamp in the Linux monotonic clock domain.
pub(super) fn stamp() -> Option<(u64, String)> {
    #[cfg(target_os = "linux")]
    {
        Some((monotonic_ns()?, linux_boot_id_sha256()?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub(super) fn snapshot<T>(sample: impl FnOnce() -> T) -> (T, Value) {
    #[cfg(target_os = "linux")]
    {
        snapshot_with(monotonic_ns, linux_boot_id_sha256, sample)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (sample(), Value::Null)
    }
}

#[cfg(any(target_os = "linux", test))]
fn snapshot_with<T>(
    mut clock: impl FnMut() -> Option<u64>,
    boot: impl FnOnce() -> Option<String>,
    sample: impl FnOnce() -> T,
) -> (T, Value) {
    let boot = boot();
    let before = clock();
    let value = sample();
    let after = clock();
    let diagnostic = match (before, after, boot) {
        (Some(start), Some(end), Some(boot_id_sha256))
            if start <= end
                && boot_id_sha256.len() == 64
                && boot_id_sha256
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) =>
        {
            json!({"scope":"linux_clock_monotonic","boot_id_sha256":boot_id_sha256,
                "sample_start_ns":start.to_string(),"sample_end_ns":end.to_string()})
        }
        _ => Value::Null,
    };
    (value, diagnostic)
}

#[cfg(any(target_os = "linux", test))]
fn monotonic_ns() -> Option<u64> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanos = u64::try_from(value.tv_nsec)
        .ok()
        .filter(|v| *v < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

#[cfg(target_os = "linux")]
fn linux_boot_id_sha256() -> Option<String> {
    use sha2::{Digest as _, Sha256};
    use std::sync::OnceLock;
    static BOOT: OnceLock<String> = OnceLock::new();
    cached_boot_hash(&BOOT, || {
        let raw = std::fs::read("/proc/sys/kernel/random/boot_id").ok()?;
        let normalized = normalized_boot_id(&raw)?;
        Some(crate::local::hex(&Sha256::digest(normalized)))
    })
}

#[cfg(any(target_os = "linux", test))]
fn cached_boot_hash(
    cache: &std::sync::OnceLock<String>,
    read: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if let Some(value) = cache.get() {
        return Some(value.clone());
    }
    let value = read()?;
    Some(cache.get_or_init(|| value).clone())
}

#[cfg(any(target_os = "linux", test))]
fn normalized_boot_id(raw: &[u8]) -> Option<&[u8]> {
    let raw = match raw {
        [value @ .., b'\n'] => value,
        value => value,
    };
    if raw.len() != 36 {
        return None;
    }
    for (index, value) in raw.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if value != b'-' {
                return None;
            }
        } else if !value.is_ascii_hexdigit() || value.is_ascii_uppercase() {
            return None;
        }
    }
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn monotonic_progress_clock_brackets_the_actual_sample() {
        let time = Cell::new(100u64);
        let (value, clock) = snapshot_with(
            || Some(time.get()),
            || Some("11".repeat(32)),
            || {
                time.set(120);
                7
            },
        );
        assert_eq!(value, 7);
        assert_eq!(clock["scope"], "linux_clock_monotonic");
        assert_eq!(clock["sample_start_ns"], "100");
        assert_eq!(clock["sample_end_ns"], "120");
    }

    #[test]
    fn monotonic_progress_clock_failures_never_invent_a_timestamp_or_drop_the_sample() {
        for mode in 0..4 {
            let count = Cell::new(0);
            let (sample, clock) = snapshot_with(
                || {
                    let n = count.get();
                    count.set(n + 1);
                    match mode {
                        0 if n == 0 => None,
                        1 if n == 1 => None,
                        2 => Some(2 - n),
                        _ => Some(1),
                    }
                },
                || {
                    if mode == 3 {
                        None
                    } else {
                        Some("11".repeat(32))
                    }
                },
                || 9,
            );
            assert_eq!(sample, 9);
            assert!(clock.is_null());
        }
    }

    #[test]
    fn monotonic_progress_clock_retries_failed_boot_read_and_caches_only_success() {
        let cache = std::sync::OnceLock::new();
        assert!(cached_boot_hash(&cache, || None).is_none());
        let expected = "11".repeat(32);
        assert_eq!(
            cached_boot_hash(&cache, || Some(expected.clone())),
            Some(expected.clone())
        );
        assert_eq!(
            cached_boot_hash(&cache, || panic!("successful boot hash must be cached")),
            Some(expected)
        );
    }

    #[test]
    fn monotonic_progress_clock_boot_normalization_is_strict() {
        let id = b"12345678-1234-1234-1234-123456789abc";
        assert_eq!(normalized_boot_id(id), Some(id.as_slice()));
        let newline = [id.as_slice(), b"\n"].concat();
        assert_eq!(normalized_boot_id(&newline), Some(id.as_slice()));
        assert!(normalized_boot_id(b"12345678-1234-1234-1234-123456789ABC").is_none());
        assert!(normalized_boot_id(&[id.as_slice(), b"\n\n"].concat()).is_none());
        assert!(normalized_boot_id(b"unavailable").is_none());
    }

    #[test]
    fn monotonic_progress_clock_invalid_boot_binding_is_unavailable() {
        let (_, clock) = snapshot_with(|| Some(1), || Some("unknown".into()), || ());
        assert!(clock.is_null());
    }

    #[test]
    fn monotonic_progress_clock_actual_host_source_is_monotonic() {
        let before = monotonic_ns().unwrap();
        let after = monotonic_ns().unwrap();
        assert!(before <= after);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn monotonic_progress_clock_unsupported_host_preserves_value_without_clock_claim() {
        let (value, clock) = snapshot(|| 42);
        assert_eq!(value, 42);
        assert!(clock.is_null());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monotonic_progress_clock_linux_matches_the_kernel_clock_and_boot() {
        let before = monotonic_ns().unwrap();
        let (_, clock) = snapshot(|| ());
        let after = monotonic_ns().unwrap();
        assert!(
            before
                <= clock["sample_start_ns"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
        );
        assert!(
            clock["sample_end_ns"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                <= after
        );
        assert_eq!(clock["boot_id_sha256"], linux_boot_id_sha256().unwrap());
    }
}
