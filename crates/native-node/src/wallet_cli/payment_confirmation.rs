//! Public, single-attempt payment confirmation on the controlling terminal.
//! Passphrase and recovery-word input continue to use the hidden reader.

use std::io::{ErrorKind, Read, Write};

const MAX_CONFIRMATION_LINE_BYTES: usize = 64;
const PAYMENT_CONFIRMATION_PROMPT: &str =
    "Type uppercase PAY and press Enter (confirmation is visible): ";
const REJECTED: &str =
    "payment confirmation rejected: type uppercase PAY and press Enter; no reservation was created";
const TOO_LONG: &str = "payment confirmation line exceeds 64 bytes; no reservation was created";
const ENDED: &str = "payment confirmation ended before Enter; no reservation was created";

fn authorize_payment(line: &[u8]) -> Result<(), String> {
    if line.len() > MAX_CONFIRMATION_LINE_BYTES {
        return Err(TOO_LONG.into());
    }
    let Some(content) = line.strip_suffix(b"\n") else {
        return Err(ENDED.into());
    };
    let content = content.strip_suffix(b"\r").unwrap_or(content);
    let (mut start, mut end) = (0, content.len());
    while start < end && matches!(content[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(content[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    if &content[start..end] == b"PAY" {
        Ok(())
    } else {
        Err(REJECTED.into())
    }
}

fn read_payment_confirmation<R: Read>(reader: &mut R) -> Result<(), String> {
    // The complete line, including LF or CRLF, must fit this stack buffer.
    // An invalid first line is never replaced by a later confirmation attempt.
    let mut line = [0; MAX_CONFIRMATION_LINE_BYTES];
    for index in 0..line.len() {
        loop {
            match reader.read(&mut line[index..index + 1]) {
                Ok(0) => return Err(ENDED.into()),
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(
                        "cannot read payment confirmation; no reservation was created".into(),
                    );
                }
            }
        }
        if line[index] == b'\n' {
            return authorize_payment(&line[..=index]);
        }
    }
    Err(TOO_LONG.into())
}

/// The caller supplies its already validated controlling terminal. This public
/// token uses ordinary terminal input and never invokes the hidden input path.
/// Success authorizes the caller to proceed; no wallet or payment state is used.
pub(super) fn confirm_payment<T: Read + Write>(tty: &mut T) -> Result<(), String> {
    tty.write_all(PAYMENT_CONFIRMATION_PROMPT.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|_| "cannot display payment confirmation; no reservation was created")?;
    read_payment_confirmation(tty)
}

#[cfg(test)]
mod tests;
