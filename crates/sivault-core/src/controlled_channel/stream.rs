//! Bounded transport over a connected byte stream.
//! The caller must set IO deadlines and drop the stream after one exchange.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::{
    CLIENT_LEN, Channel, MAX_PAYLOAD, MLDSA65Signature, PendingClient, RECORD_OVERHEAD,
    ReleaserIdentity, SERVER_LEN, Word,
};
use crate::{Error, Result, controlled_credential::ChannelBinding};

pub struct Session<R, W> {
    reader: R,
    writer: W,
    channel: Option<Channel>,
}

impl<R: Read, W: Write> Session<R, W> {
    pub fn connect(mut reader: R, mut writer: W, pending: PendingClient) -> Result<Self> {
        write_frame(&mut writer, pending.hello())?;
        let len = SERVER_LEN + MLDSA65Signature::len();
        let hello = read_frame(&mut reader, len, len)?;
        let channel = pending.finish(&hello)?;
        Ok(Self {
            reader,
            writer,
            channel: Some(channel),
        })
    }

    pub fn accept(
        mut reader: R,
        mut writer: W,
        deployment: &Word,
        identity: &ReleaserIdentity,
    ) -> Result<Self> {
        let hello = read_frame(&mut reader, CLIENT_LEN, CLIENT_LEN)?;
        let (reply, channel) = identity.accept(deployment, &hello)?;
        write_frame(&mut writer, &reply)?;
        Ok(Self {
            reader,
            writer,
            channel: Some(channel),
        })
    }

    pub fn binding(&self) -> Result<ChannelBinding> {
        Ok(self
            .channel
            .as_ref()
            .ok_or(Error::Authentication)?
            .binding())
    }

    pub fn claimed_folder_key(&self) -> Result<&Word> {
        Ok(self
            .channel
            .as_ref()
            .ok_or(Error::Authentication)?
            .claimed_folder_key())
    }

    pub fn send(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        let mut channel = self.channel.take().ok_or(Error::Authentication)?;
        write_frame(&mut self.writer, &channel.seal(kind, payload)?)?;
        self.channel = Some(channel);
        Ok(())
    }

    pub fn receive(&mut self, kind: u8) -> Result<Zeroizing<Vec<u8>>> {
        let mut channel = self.channel.take().ok_or(Error::Authentication)?;
        let bytes = read_frame(
            &mut self.reader,
            RECORD_OVERHEAD,
            MAX_PAYLOAD + RECORD_OVERHEAD,
        )?;
        let payload = channel.open(kind, &bytes)?;
        self.channel = Some(channel);
        Ok(payload)
    }
}

fn read_frame(reader: &mut impl Read, min: usize, max: usize) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let len = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::InvalidFormat)?;
    if !(min..=max).contains(&len) {
        return Err(Error::InvalidFormat);
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame)?;
    Ok(frame)
}

fn write_frame(writer: &mut impl Write, frame: &[u8]) -> Result<()> {
    let len = u32::try_from(frame.len()).map_err(|_| Error::InvalidFormat)?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversize_and_truncated_frames() {
        let mut oversized = [255; 4].as_slice();
        assert!(matches!(
            read_frame(&mut oversized, 1, 100),
            Err(Error::InvalidFormat)
        ));
        let mut truncated = [0, 0, 0, 2, 5].as_slice();
        assert!(matches!(
            read_frame(&mut truncated, 1, 100),
            Err(Error::Io(_))
        ));
    }
}
