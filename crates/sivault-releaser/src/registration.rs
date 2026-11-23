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
    owner::{OwnerIdentity, verify_command},
    standard::{MAX_CONTROLLED_REGISTRATION, Safe},
};

use crate::{message::Id, opening::OpeningRecord};

const HEADER: &[u8; 8] = b"SVREG001";
const PORTABLE_HEADER: &[u8; 8] = b"SVREG002";
const TAG_LEN: usize = 32;
const AUTH_LABEL: &[u8] = b"SVREG001/record-authentication";
const SIGNED_LABEL: &[u8] = b"SVREG002/owner-authorization";
const SIGNATURE_LEN: usize = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::len();

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub peer: Id,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Ipv4Addr>,
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
            || self
                .endpoint
                .is_some_and(|address| !crate::transport::in_tailnet(address))
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
        SocketAddrV4::new(self.endpoint.unwrap_or(Ipv4Addr::LOCALHOST), self.port)
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
        self.publish_inner(safe, key, None)
    }

    pub fn publish_portable(
        &self,
        safe: &Safe,
        key: &Secret,
        folder_secret: &Secret,
        owner: &OwnerIdentity,
    ) -> Result<()> {
        self.publish_inner(safe, key, Some((folder_secret, owner)))
    }

    fn publish_inner(
        &self,
        safe: &Safe,
        key: &Secret,
        portable: Option<(&Secret, &OwnerIdentity)>,
    ) -> Result<()> {
        self.validate()?;
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(MAX_CONTROLLED_REGISTRATION));
        if let Some((folder_secret, _)) = portable {
            bytes.extend_from_slice(PORTABLE_HEADER);
            bytes.extend_from_slice(folder_secret.as_ref());
        } else {
            bytes.extend_from_slice(HEADER);
        }
        serde_json::to_writer(&mut *bytes, self).map_err(|_| Error::InvalidFormat)?;
        if let Some((_, owner)) = portable {
            let signature = owner.sign_command(&signature_input(&bytes))?;
            bytes.extend_from_slice(signature.as_slice());
        }
        let auth_key = self.authentication_key(key);
        let tag = crypto::mac(&auth_key, &bytes);
        bytes.extend_from_slice(&tag);
        safe.publish_controlled_registration(&bytes)
    }
}

pub struct StoredRegistration {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    registration: Registration,
}

impl StoredRegistration {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = Safe::read_controlled_registration(path)?;
        Self::decode(bytes)
    }

    fn decode(bytes: Vec<u8>) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(bytes);
        let (offset, trailer) = if bytes.starts_with(PORTABLE_HEADER) {
            (PORTABLE_HEADER.len() + 32, SIGNATURE_LEN + TAG_LEN)
        } else if bytes.starts_with(HEADER) {
            (HEADER.len(), TAG_LEN)
        } else {
            return Err(Error::InvalidFormat);
        };
        if bytes.len() <= offset + trailer || bytes.len() > MAX_CONTROLLED_REGISTRATION {
            return Err(Error::InvalidFormat);
        }
        let registration: Registration =
            serde_json::from_slice(&bytes[offset..bytes.len() - trailer])
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

    /// Before unwrap this is only an input to the online opening protocol.
    /// Authenticate the entire record with the unwrapped key before use.
    pub fn folder_secret(&self) -> Result<Secret> {
        if !self.bytes.starts_with(PORTABLE_HEADER) {
            return Err(Error::InvalidFormat);
        }
        Ok(Secret::new(
            self.bytes[8..40]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?,
        ))
    }

    /// Bind administrative targeting to data signed by this owner at enrollment.
    pub fn authenticate_owner(&self, owner: &OwnerIdentity) -> Result<()> {
        use libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature;

        if !self.bytes.starts_with(PORTABLE_HEADER) {
            return Err(Error::Authentication);
        }
        let end = self.bytes.len() - TAG_LEN;
        let start = end - SIGNATURE_LEN;
        verify_command(
            owner.verification_key(),
            &signature_input(&self.bytes[..start]),
            &MLDSA65Signature::new(
                self.bytes[start..end]
                    .try_into()
                    .map_err(|_| Error::InvalidFormat)?,
            ),
        )
    }

    pub fn authenticate(&self, key: &Secret) -> Result<()> {
        let (record, tag) = self.bytes.split_at(self.bytes.len() - TAG_LEN);
        let auth_key = self.registration.authentication_key(key);
        crypto::verify_mac(&auth_key, record, tag)
    }
}

fn signature_input(bytes: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut input = zeroize::Zeroizing::new(Vec::with_capacity(SIGNED_LABEL.len() + bytes.len()));
    input.extend_from_slice(SIGNED_LABEL);
    input.extend_from_slice(bytes);
    input
}
