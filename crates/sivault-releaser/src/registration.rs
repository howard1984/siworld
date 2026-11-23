//! Owner-side storage for an acknowledged single-slot loopback enrollment.
//! The envelope is ciphertext. No verifier, share, or plaintext key is stored.
//! Before unwrap, only the peer's pinned identity can be authenticated. The
//! registration tag is checked with the recovered key before exposing files.

use std::{net::Ipv4Addr, net::SocketAddrV4, path::Path};

use serde::{Deserialize, Serialize};
use sivault_core::{
    Error, Result,
    controlled_credential::Envelope,
    crypto::{self, Secret},
    standard::{MAX_CONTROLLED_REGISTRATION, Safe},
};

use crate::{message::Id, opening::OpeningRecord};

const HEADER: &[u8; 8] = b"SVREG001";
const TAG_LEN: usize = 32;
const AUTH_LABEL: &[u8] = b"SVREG001/record-authentication";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub peer: Id,
    pub port: u16,
    pub scope: OpeningRecord,
    pub allowance: u64,
    pub enrollment_ack: Id,
    pub nonce: [u8; 24],
    pub wrapped_key: Vec<u8>,
}

impl Registration {
    fn validate(&self) -> Result<()> {
        if self.peer == Id::default()
            || self.port == 0
            || self.scope.record.generation == 0
            || self.allowance == 0
            || self.enrollment_ack == Id::default()
            || self.wrapped_key.len() != 48
        {
            return Err(Error::InvalidFormat);
        }
        Ok(())
    }

    pub fn address(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
    }

    pub fn envelope(&self) -> Result<Envelope> {
        Ok(Envelope {
            nonce: self.nonce,
            ciphertext: self
                .wrapped_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidFormat)?,
        })
    }

    fn authentication_key(&self, key: &Secret) -> Secret {
        let mut safe_id = [0; 16];
        safe_id.copy_from_slice(&self.scope.slot.safe.0[..16]);
        crypto::derive(key, &safe_id, AUTH_LABEL)
    }

    pub fn publish(&self, safe: &Safe, key: &Secret) -> Result<()> {
        self.validate()?;
        let mut bytes = HEADER.to_vec();
        serde_json::to_writer(&mut bytes, self).map_err(|_| Error::InvalidFormat)?;
        let auth_key = self.authentication_key(key);
        let tag = crypto::mac(&auth_key, &bytes);
        bytes.extend_from_slice(&tag);
        safe.publish_controlled_registration(&bytes)
    }
}

pub struct StoredRegistration {
    bytes: Vec<u8>,
    registration: Registration,
}

impl StoredRegistration {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = Safe::read_controlled_registration(path)?;
        Self::decode(bytes)
    }

    fn decode(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() <= HEADER.len() + TAG_LEN
            || bytes.len() > MAX_CONTROLLED_REGISTRATION
            || !bytes.starts_with(HEADER)
        {
            return Err(Error::InvalidFormat);
        }
        let registration: Registration =
            serde_json::from_slice(&bytes[HEADER.len()..bytes.len() - TAG_LEN])
                .map_err(|_| Error::InvalidFormat)?;
        registration.validate()?;
        Ok(Self {
            bytes,
            registration,
        })
    }

    /// Routing and credential context only; an opening must authenticate this
    /// record after unwrap and must never treat this as an enrollment receipt.
    pub fn untrusted(&self) -> &Registration {
        &self.registration
    }

    pub fn authenticate(&self, key: &Secret) -> Result<()> {
        let (record, tag) = self.bytes.split_at(self.bytes.len() - TAG_LEN);
        let auth_key = self.registration.authentication_key(key);
        crypto::verify_mac(&auth_key, record, tag)
    }
}
