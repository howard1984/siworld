//! Optional lanes are advertised through a legacy-safe reserved height query.
use super::*;
use std::time::Duration;
pub const CAPABILITY_HEIGHT: u64 = u64::MAX;
pub const HEADER_LANE_HEIGHT: u64 = u64::MAX - 1;
pub const BODY_LANE_HEIGHT: u64 = u64::MAX - 2;
const CAPABILITIES: u8 = 18;
const READY: u8 = 19;
const HEADERS: u8 = 20;
const VERSION: u8 = 1;
const MAX_HEADERS: usize = 8;
const MAX_PACKET: usize = 3 + MAX_HEADERS * super::super::header::HEADER_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Headers = 1,
    Bodies = 2,
}
impl Lane {
    pub fn reserved_height(self) -> u64 {
        match self {
            Self::Headers => HEADER_LANE_HEIGHT,
            Self::Bodies => BODY_LANE_HEIGHT,
        }
    }
    pub fn from_height(height: u64) -> Option<Self> {
        match height {
            HEADER_LANE_HEIGHT => Some(Self::Headers),
            BODY_LANE_HEIGHT => Some(Self::Bodies),
            _ => None,
        }
    }
}
impl<S: Read + Write> Peer<S> {
    pub fn lanes_supported(&self) -> bool {
        self.lanes == Some(true)
    }
    pub fn probe_lanes(&mut self, request: u64) -> Result<bool, p2p::Error> {
        if let Some(available) = self.lanes {
            return Ok(available);
        }
        let mut bytes = [0; 9];
        bytes[0] = GET_HEADER;
        bytes[1..].copy_from_slice(&CAPABILITY_HEIGHT.to_le_bytes());
        self.send(request, &bytes)?;
        let (response, bytes, _charge) = self.receive()?;
        if response != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        let available = if bytes.as_slice() == [CAPABILITIES, VERSION, 3] {
            true
        } else if bytes.len() == 9
            && bytes[0] == UNAVAILABLE
            && number(&bytes[1..]) == CAPABILITY_HEIGHT
        {
            false
        } else {
            return Err(p2p::Error::InvalidProtocol);
        };
        self.lanes = Some(available);
        Ok(available)
    }
    pub fn send_lane_capabilities(&mut self, request: u64) -> Result<(), p2p::Error> {
        self.send(request, &[CAPABILITIES, VERSION, 3])
    }
    /// Called only after a positive capability on the existing ordinary peer.
    pub fn open_lane(&mut self, request: u64, lane: Lane) -> Result<(), p2p::Error> {
        let mut bytes = [0; 9];
        bytes[0] = GET_HEADER;
        bytes[1..].copy_from_slice(&lane.reserved_height().to_le_bytes());
        self.send(request, &bytes)?;
        let (response, bytes, _charge) = self.receive()?;
        if response != request || bytes.as_slice() != [READY, VERSION, lane as u8] {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(())
    }
    pub fn accept_lane(&mut self, request: u64, lane: Lane) -> Result<(), p2p::Error> {
        self.send(request, &[READY, VERSION, lane as u8])
    }
    pub fn send_headers(&mut self, request: u64, headers: &[Header]) -> Result<(), p2p::Error> {
        if headers.len() > MAX_HEADERS {
            return Err(p2p::Error::ResourceExhausted);
        }
        let mut bytes = Vec::with_capacity(3 + headers.len() * super::super::header::HEADER_BYTES);
        bytes.extend_from_slice(&[HEADERS, VERSION, headers.len() as u8]);
        for header in headers {
            if header.network != self.session.binding().network || header.height == 0 {
                return Err(p2p::Error::InvalidProtocol);
            }
            bytes.extend_from_slice(&header.encode().map_err(|_| p2p::Error::InvalidProtocol)?);
        }
        self.send_application_before(request, &bytes, &p2p::Deadline::new(Duration::from_secs(2)))
    }
    pub fn receive_headers(&mut self) -> Result<(u64, Vec<Header>), p2p::Error> {
        let (request, bytes, _charge) = self
            .receive_application_before(&p2p::Deadline::new(Duration::from_secs(2)), MAX_PACKET)?;
        if bytes.len() < 3
            || bytes[0] != HEADERS
            || bytes[1] != VERSION
            || bytes[2] as usize > MAX_HEADERS
            || bytes.len() != 3 + bytes[2] as usize * super::super::header::HEADER_BYTES
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let headers = bytes[3..]
            .as_chunks::<{ super::super::header::HEADER_BYTES }>()
            .0
            .iter()
            .map(|bytes| {
                Header::decode(bytes, &self.session.binding().network)
                    .map_err(|_| p2p::Error::InvalidProtocol)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if headers.iter().any(|h| h.height == 0) {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok((request, headers))
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(crate) fn retain_initial_request(
        &mut self,
        request: (u64, Request),
    ) -> Result<(), p2p::Error> {
        if self.initial_request.replace(request).is_some() {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(())
    }
}
