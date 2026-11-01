use super::*;
use std::io::{Cursor, Error, ErrorKind};

#[test]
fn uppercase_payment_token_allows_only_horizontal_ascii_padding_and_line_endings() {
    for line in [
        b"PAY\n".as_slice(),
        b"PAY\r\n".as_slice(),
        b" PAY\n".as_slice(),
        b"PAY \n".as_slice(),
        b"\t PAY \t\r\n".as_slice(),
    ] {
        assert!(authorize_payment(line).is_ok());
    }
}

#[test]
fn payment_confirmation_rejects_lowercase_blank_other_and_non_ascii_input() {
    for line in [
        b"\n".as_slice(),
        b" \t\r\n".as_slice(),
        b"pay\n".as_slice(),
        b"Pay\n".as_slice(),
        b"STOP\n".as_slice(),
        b"yes\n".as_slice(),
        b"P AY\n".as_slice(),
        b"PAY\0\n".as_slice(),
        b"PAY\r\r\n".as_slice(),
        b"PAY\n\n".as_slice(),
        b"\x0bPAY\n".as_slice(),
        b"PAY\x0c\n".as_slice(),
        "\u{00a0}PAY\n".as_bytes(),
        b"\xffPAY\n".as_slice(),
    ] {
        let error = authorize_payment(line).unwrap_err();
        assert!(error.contains("uppercase PAY"));
        assert!(error.contains("no reservation was created"));
        assert!(!error.contains("STOP"));
        assert!(!error.contains("yes"));
    }
}

#[test]
fn parser_requires_enter_and_enforces_the_complete_line_limit() {
    for line in [b"".as_slice(), b"PAY".as_slice(), b" PAY\t".as_slice()] {
        assert!(authorize_payment(line).is_err());
    }
    let mut longest = vec![b' '; MAX_CONFIRMATION_LINE_BYTES - 4];
    longest.extend_from_slice(b"PAY\n");
    assert_eq!(longest.len(), MAX_CONFIRMATION_LINE_BYTES);
    assert!(authorize_payment(&longest).is_ok());
    longest.insert(0, b' ');
    assert!(authorize_payment(&longest).is_err());
}

#[test]
fn bounded_reader_accepts_lf_crlf_and_the_exact_maximum() {
    for ending in [b"\n".as_slice(), b"\r\n".as_slice()] {
        let mut line = vec![b'\t'; MAX_CONFIRMATION_LINE_BYTES - 3 - ending.len()];
        line.extend_from_slice(b"PAY");
        line.extend_from_slice(ending);
        let mut reader = Cursor::new(line);
        assert!(read_payment_confirmation(&mut reader).is_ok());
        assert_eq!(reader.position(), MAX_CONFIRMATION_LINE_BYTES as u64);
    }
}

#[test]
fn reader_stops_after_one_line_without_accepting_a_later_confirmation() {
    for (line, accepted, consumed) in [
        (b"PAY\nSTOP\n".as_slice(), true, 4),
        (b"pay\nPAY\n".as_slice(), false, 4),
        (b"\nPAY\n".as_slice(), false, 1),
    ] {
        let mut reader = Cursor::new(line);
        assert_eq!(read_payment_confirmation(&mut reader).is_ok(), accepted);
        assert_eq!(reader.position(), consumed);
    }
}

struct CountingReader {
    bytes: Cursor<Vec<u8>>,
    calls: usize,
    maximum_request: usize,
}
impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.maximum_request = self.maximum_request.max(buffer.len());
        self.bytes.read(buffer)
    }
}

#[test]
fn overlong_input_reads_at_most_the_hard_bound_and_has_no_retry() {
    let mut reader = CountingReader {
        bytes: Cursor::new(vec![b'X'; MAX_CONFIRMATION_LINE_BYTES * 4]),
        calls: 0,
        maximum_request: 0,
    };
    let error = read_payment_confirmation(&mut reader).unwrap_err();
    assert!(error.contains("payment confirmation line exceeds 64 bytes"));
    assert!(error.contains("no reservation was created"));
    assert!(!error.contains('X'));
    assert_eq!(reader.bytes.position(), MAX_CONFIRMATION_LINE_BYTES as u64);
    assert_eq!(reader.calls, MAX_CONFIRMATION_LINE_BYTES);
    assert_eq!(reader.maximum_request, 1);
}

#[test]
fn eof_rejects_even_an_otherwise_valid_token_without_enter() {
    for line in [b"".as_slice(), b"PAY".as_slice(), b"\tPAY \r".as_slice()] {
        let error = read_payment_confirmation(&mut Cursor::new(line)).unwrap_err();
        assert!(error.contains("payment confirmation ended before Enter"));
        assert!(error.contains("no reservation was created"));
    }
}

struct FaultyReader {
    interruptions: usize,
    data: Cursor<Vec<u8>>,
    fail: bool,
}
impl Read for FaultyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.interruptions > 0 {
            self.interruptions -= 1;
            return Err(Error::from(ErrorKind::Interrupted));
        }
        if self.fail {
            return Err(Error::other("synthetic input content must not escape"));
        }
        self.data.read(buffer)
    }
}

#[test]
fn interrupted_reads_preserve_the_same_line_and_io_errors_do_not_expose_contents() {
    let mut reader = FaultyReader {
        interruptions: 1,
        data: Cursor::new(b"PAY\n".to_vec()),
        fail: false,
    };
    assert!(read_payment_confirmation(&mut reader).is_ok());
    reader.fail = true;
    let error = read_payment_confirmation(&mut reader).unwrap_err();
    assert_eq!(
        error,
        "cannot read payment confirmation; no reservation was created"
    );
}

struct SyntheticTerminal {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    flushed: bool,
    read_started: bool,
    fail_write: bool,
    fail_flush: bool,
}
impl SyntheticTerminal {
    fn new(line: &[u8]) -> Self {
        Self {
            input: Cursor::new(line.to_vec()),
            output: Vec::new(),
            flushed: false,
            read_started: false,
            fail_write: false,
            fail_flush: false,
        }
    }
}
impl Read for SyntheticTerminal {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        assert_eq!(
            self.output.as_slice(),
            PAYMENT_CONFIRMATION_PROMPT.as_bytes()
        );
        assert!(self.flushed);
        self.read_started = true;
        self.input.read(buffer)
    }
}
impl Write for SyntheticTerminal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail_write {
            return Err(Error::other("synthetic output failure"));
        }
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_flush {
            return Err(Error::other("synthetic flush failure"));
        }
        self.flushed = true;
        Ok(())
    }
}

#[test]
fn public_confirmation_prompt_is_visible_and_flushed_before_input() {
    let mut tty = SyntheticTerminal::new(b"PAY\n");
    assert!(confirm_payment(&mut tty).is_ok());
    assert!(tty.read_started);
    let prompt = String::from_utf8(tty.output).unwrap();
    assert!(prompt.contains("uppercase PAY"));
    assert!(prompt.contains("visible"));
    assert!(prompt.contains("press Enter"));
}

#[test]
fn failed_prompt_or_flush_does_not_begin_confirmation_input() {
    for fail_write in [true, false] {
        let mut tty = SyntheticTerminal::new(b"PAY\n");
        tty.fail_write = fail_write;
        tty.fail_flush = !fail_write;
        let error = confirm_payment(&mut tty).unwrap_err();
        assert_eq!(
            error,
            "cannot display payment confirmation; no reservation was created"
        );
        assert!(!tty.read_started);
        assert_eq!(tty.input.position(), 0);
    }
}

#[test]
#[ignore = "requires an explicitly enabled synthetic controlling-terminal probe"]
fn synthetic_controlling_terminal_confirmation_probe() {
    assert_eq!(
        std::env::var("SIWORLD_SYNTHETIC_PAY_CONFIRMATION_PROBE").as_deref(),
        Ok("1"),
        "explicit synthetic payment-confirmation probe opt-in is required"
    );
    let expected = match std::env::var("SIWORLD_SYNTHETIC_PAY_CONFIRMATION_EXPECTED").as_deref() {
        Ok("accepted") => true,
        Ok("rejected") => false,
        _ => panic!("synthetic confirmation expectation must be accepted or rejected"),
    };
    let mut tty =
        super::super::terminal().expect("synthetic probe requires a controlling terminal");
    let accepted = confirm_payment(&mut tty).is_ok();
    assert_eq!(
        accepted, expected,
        "synthetic confirmation outcome did not match expectation"
    );
    println!(
        "{}",
        if accepted {
            "synthetic_payment_confirmation_accepted"
        } else {
            "synthetic_payment_confirmation_rejected"
        }
    );
}
