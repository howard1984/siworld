//! Narrow OS boundary. No networking, wallet derivation or consensus behavior.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

pub const MIN_VISIBLE_MEMORY: u64 = 30 * 1024 * 1024 * 1024;

pub fn check_memory(visible: u64) -> Result<(), String> {
    if visible < MIN_VISIBLE_MEMORY {
        return Err(format!(
            "Insufficient memory: at least 30 GiB of OS-visible physical memory is required (install 32 GB or more); detected {} MiB.",
            visible / 1024 / 1024
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_boundary_is_inclusive_and_english() {
        assert!(check_memory(MIN_VISIBLE_MEMORY).is_ok());
        assert!(check_memory(u64::MAX).is_ok());
        let error = check_memory(MIN_VISIBLE_MEMORY - 1).unwrap_err();
        assert!(error.is_ascii());
        assert!(error.contains("Insufficient memory"));
        assert!(check_memory(0).is_err());
    }
}
