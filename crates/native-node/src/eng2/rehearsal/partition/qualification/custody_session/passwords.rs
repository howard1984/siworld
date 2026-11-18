//! Private, bounded stdin framing. No secret is included in an error value.
use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;
pub(super) const MAX_BYTES: usize = 8 + 5 * (2 + 1024);
pub(super) struct Passwords(pub [Zeroizing<String>; 5]);
fn parse(bytes: &[u8], terminal: bool) -> Result<Passwords, String> {
    if terminal || bytes.len() > MAX_BYTES || !bytes.starts_with(b"SWE2PWD1") {
        return Err("custody_private_input_rejected".into());
    }
    let mut at = 8usize;
    let mut words = Vec::with_capacity(5);
    for _ in 0..5 {
        let end = at.checked_add(2).ok_or("custody_private_input_rejected")?;
        let width: [u8; 2] = bytes
            .get(at..end)
            .ok_or("custody_private_input_rejected")?
            .try_into()
            .map_err(|_| "custody_private_input_rejected")?;
        let size = usize::from(u16::from_le_bytes(width));
        if !(12..=1024).contains(&size) {
            return Err("custody_private_input_rejected".into());
        }
        at = end;
        let end = at
            .checked_add(size)
            .ok_or("custody_private_input_rejected")?;
        let raw = bytes.get(at..end).ok_or("custody_private_input_rejected")?;
        if raw.iter().any(|b| matches!(b, 0 | 10 | 13)) {
            return Err("custody_private_input_rejected".into());
        }
        let word = std::str::from_utf8(raw).map_err(|_| "custody_private_input_rejected")?;
        words.push(Zeroizing::new(word.to_owned()));
        at = end;
    }
    if at != bytes.len() {
        return Err("custody_private_input_rejected".into());
    }
    Ok(Passwords(
        words
            .try_into()
            .map_err(|_| "custody_private_input_rejected")?,
    ))
}
pub(super) fn read() -> Result<Passwords, String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err("custody_private_input_rejected".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    stdin
        .lock()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "custody_private_input_rejected")?;
    parse(&bytes, false)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet(size: usize) -> Vec<u8> {
        let mut b = b"SWE2PWD1".to_vec();
        for _ in 0..5 {
            b.extend_from_slice(&(size as u16).to_le_bytes());
            b.extend(std::iter::repeat_n(b'x', size));
        }
        b
    }
    #[test]
    fn exact_private_frames_require_eof_and_reject_every_extra_byte() {
        let b = packet(12);
        assert!(parse(&b, false).is_ok());
        assert!(parse(&b, true).is_err());
        for extra in [0, 10, 13, 255] {
            let mut c = b.clone();
            c.push(extra);
            assert!(parse(&c, false).is_err());
        }
        for end in 0..b.len() {
            assert!(parse(&b[..end], false).is_err());
        }
        let mut bad = b;
        bad[10] = 255;
        assert!(parse(&bad, false).is_err());
    }
    #[test]
    fn maximum_private_packet_and_invalid_widths_are_bounded() {
        let mut b = packet(1024);
        assert_eq!(b.len(), MAX_BYTES);
        assert!(parse(&b, false).is_ok());
        b.push(b'x');
        assert!(parse(&b, false).is_err());
        for n in [0, 11, 1025] {
            assert!(parse(&packet(n), false).is_err());
        }
        let mut b = packet(12);
        b[10] = 10;
        assert_eq!(
            parse(&b, false).err().unwrap(),
            "custody_private_input_rejected"
        );
    }
}
