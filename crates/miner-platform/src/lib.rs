//! Narrow OS boundary. No networking, wallet derivation or consensus behavior.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

pub const MIN_VISIBLE_MEMORY: u64 = 30 * 1024 * 1024 * 1024;

pub fn check_memory(visible: u64) -> Result<(), String> {
    if visible < MIN_VISIBLE_MEMORY {
        return Err(format!(
            "\u{5185}\u{5b58}\u{4e0d}\u{8db3}：\u{7cfb}\u{7edf}\u{53ef}\u{89c1}\u{7269}\u{7406}\u{5185}\u{5b58}\u{81f3}\u{5c11}\u{9700}\u{8981} 30 GiB\u{ff08}\u{5efa}\u{8bae}\u{5b89}\u{88c5} 32 GB \u{6216}\u{66f4}\u{591a}\u{ff09}\u{ff0c}\u{68c0}\u{6d4b}\u{5230} {} MiB\u{3002}\nInsufficient memory: at least 30 GiB of OS-visible physical memory is required (install 32 GB or more); detected {} MiB.",
            visible / 1024 / 1024,
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
    fn memory_boundary_is_inclusive_and_bilingual() {
        assert!(check_memory(MIN_VISIBLE_MEMORY).is_ok());
        assert!(check_memory(u64::MAX).is_ok());
        let error = check_memory(MIN_VISIBLE_MEMORY - 1).unwrap_err();
        assert!(error.contains("\u{5185}\u{5b58}\u{4e0d}\u{8db3}"));
        assert!(error.contains("Insufficient memory"));
        assert!(check_memory(0).is_err());
    }
}
