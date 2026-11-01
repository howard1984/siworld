//! Private-key custody adapters for the inactive TLS candidate.

use super::NativeIdentity;
use ed25519_dalek::Signer as _;
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;
use x509_parser::prelude::{FromDer, TbsCertificate};

pub(crate) const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";
pub(crate) const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
];

pub(crate) fn spki(public: &[u8; 32]) -> [u8; 44] {
    let mut bytes = [0; 44];
    bytes[..12].copy_from_slice(&SPKI_PREFIX);
    bytes[12..].copy_from_slice(public);
    bytes
}

pub(crate) fn certificate_verify_message(message: &[u8], context: &[u8]) -> bool {
    message.len() == 64 + context.len() + 1 + 32
        && message[..64] == [b' '; 64]
        && &message[64..64 + context.len()] == context
        && message[64 + context.len()] == 0
}

pub(crate) fn signing_key(identity: Arc<NativeIdentity>) -> Arc<dyn SigningKey> {
    Arc::new(TlsSigningKey::new(identity))
}

#[derive(Debug)]
struct TlsSigningKey {
    identity: Arc<NativeIdentity>,
    spki: [u8; 44],
}
impl TlsSigningKey {
    fn new(identity: Arc<NativeIdentity>) -> Self {
        let spki = spki(&identity.ed25519.verifying_key().to_bytes());
        Self { identity, spki }
    }
}
impl SigningKey for TlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(TlsSigner(self.identity.clone())) as Box<dyn Signer>)
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
struct TlsSigner(Arc<NativeIdentity>);
impl Signer for TlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        if !certificate_verify_message(message, CLIENT_CONTEXT)
            && !certificate_verify_message(message, SERVER_CONTEXT)
        {
            return Err(rustls::Error::General("TLS authentication failed".into()));
        }
        Ok(self.0.ed25519.sign(message).to_bytes().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

struct CertificateKey {
    identity: Arc<NativeIdentity>,
    public: [u8; 32],
}
impl rcgen::RemoteKeyPair for CertificateKey {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Keep rcgen's private-key adapter confined to bounded, self-issued
        // X.509 TBS messages carrying this identity's exact Ed25519 SPKI.
        if message.len() > 2048 {
            return Err(rcgen::Error::RemoteKeyError);
        }
        let (remaining, tbs) =
            TbsCertificate::from_der(message).map_err(|_| rcgen::Error::RemoteKeyError)?;
        if !remaining.is_empty()
            || tbs.subject_pki.raw != spki(&self.public)
            || tbs.issuer != tbs.subject
            || tbs.signature.algorithm.to_id_string() != "1.3.101.112"
            || tbs.signature.parameters.is_some()
        {
            return Err(rcgen::Error::RemoteKeyError);
        }
        Ok(self.identity.ed25519.sign(message).to_bytes().to_vec())
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// rcgen receives a signing callback, never PKCS#8 or a private seed.
pub(crate) fn self_signed(
    identity: Arc<NativeIdentity>,
    params: rcgen::CertificateParams,
) -> Result<CertificateDer<'static>, rcgen::Error> {
    let public = identity.ed25519.verifying_key().to_bytes();
    let key = rcgen::KeyPair::from_remote(Box::new(CertificateKey { identity, public }))?;
    Ok(params.self_signed(&key)?.der().clone())
}

#[cfg(test)]
pub(crate) fn test_identity(seed: u8) -> std::sync::Arc<super::NativeIdentity> {
    std::sync::Arc::new(super::NativeIdentity::from_seeds(
        crate::p2p::Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        },
        &[seed; 32],
        &[seed.wrapping_add(1); 32],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::SigningKey;

    #[test]
    fn tls_signer_only_accepts_ed25519_certificate_verify_messages() {
        let key = TlsSigningKey::new(test_identity(7));
        assert!(
            key.choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let signer = key
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .unwrap();
        assert!(
            signer
                .sign(b"siworld native peer identity descriptor v1\0")
                .is_err()
        );
        for context in [CLIENT_CONTEXT, SERVER_CONTEXT] {
            let mut message = vec![b' '; 64];
            message.extend_from_slice(context);
            message.push(0);
            message.extend_from_slice(&[9; 32]);
            assert_eq!(signer.sign(&message).unwrap().len(), 64);
            message.push(0);
            assert!(signer.sign(&message).is_err());
        }
    }
}
