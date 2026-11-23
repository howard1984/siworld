//! Bounded framing for noncredential messages on an inherited stream.
//! This framing neither authenticates a peer nor establishes a channel binding.

use std::io::{self, Read, Write};

use crate::message::{CodecError, MAX_MESSAGE_BYTES, Message};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidLength,
    Codec(CodecError),
}

pub fn read(reader: &mut impl Read) -> Result<Option<Message>, Error> {
    let mut prefix = [0; 4];
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        }
    }
    reader.read_exact(&mut prefix[1..]).map_err(Error::Io)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::InvalidLength)?;
    if !(1..=MAX_MESSAGE_BYTES).contains(&length) {
        return Err(Error::InvalidLength);
    }
    let mut frame = [0; MAX_MESSAGE_BYTES];
    reader.read_exact(&mut frame[..length]).map_err(Error::Io)?;
    Message::decode(&frame[..length])
        .map(Some)
        .map_err(Error::Codec)
}

pub fn write(writer: &mut impl Write, message: &Message) -> Result<(), Error> {
    let bytes = message.encode().map_err(Error::Codec)?;
    let length = u32::try_from(bytes.len()).map_err(|_| Error::InvalidLength)?;
    writer.write_all(&length.to_be_bytes()).map_err(Error::Io)?;
    writer.write_all(&bytes).map_err(Error::Io)?;
    writer.flush().map_err(Error::Io)
}
