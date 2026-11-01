//! Bounded, pinned leaf certificates for the inactive TLS candidate.

use super::Error;
use crate::identity::{NativeIdentity, tls_signer};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::{ASN1Time, AlgorithmIdentifier, FromDer, X509Certificate, X509Version};

pub(super) const MAX_CERTIFICATE_BYTES: usize = 2048;
const CLOCK_SKEW_SECONDS: u64 = 300;
const CERTIFICATE_LIFETIME_SECONDS: u64 = 86_400;
const NAME_DER: &[u8] = b"\x30\x1e\x31\x1c\x30\x1a\x06\x03\x55\x04\x03\x0c\x13SIWORLD native peer";
const ED25519_ALGORITHM_DER: &[u8] = b"\x30\x05\x06\x03\x2b\x65\x70";
const VERSION_DER: &[u8] = b"\xa0\x03\x02\x01\x02";

type DerElement<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Return an element, its body and the remaining input. The small certificate
/// bound permits at most two minimal, definite length octets.
fn element(input: &[u8], tag: u8) -> Option<DerElement<'_>> {
    if input.first().copied()? != tag {
        return None;
    }
    let first = *input.get(1)?;
    let (header, length) = if first < 0x80 {
        (2usize, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        if !(1..=2).contains(&count) || *input.get(2)? == 0 {
            return None;
        }
        let encoded = input.get(2..2 + count)?;
        let length = encoded
            .iter()
            .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
        if length < 128 || (count == 2 && length < 256) {
            return None;
        }
        (2 + count, length)
    };
    let end = header.checked_add(length)?;
    Some((
        input.get(..end)?,
        input.get(header..end)?,
        input.get(end..)?,
    ))
}

fn time_element(input: &[u8]) -> Option<&[u8]> {
    let tag = *input.first()?;
    let expected = match tag {
        0x17 => 13,
        0x18 => 15,
        _ => return None,
    };
    let (_, body, remaining) = element(input, tag)?;
    if body.len() != expected
        || body.last().copied()? != b'Z'
        || !body[..body.len() - 1].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    Some(remaining)
}

/// X.509 parsers may ignore an inner sequence's unconsumed remainder. Check
/// the complete minimal template before invoking the semantic parser.
fn strict_envelope(bytes: &[u8], public: &[u8; 32]) -> bool {
    let parse = || -> Option<()> {
        let (_, outer, remaining) = element(bytes, 0x30)?;
        if !remaining.is_empty() {
            return None;
        }
        let (_, tbs, rest) = element(outer, 0x30)?;
        let (algorithm, _, rest) = element(rest, 0x30)?;
        let (_, signature, rest) = element(rest, 0x03)?;
        if algorithm != ED25519_ALGORITHM_DER
            || signature.len() != 65
            || signature[0] != 0
            || !rest.is_empty()
        {
            return None;
        }
        let (version, _, rest) = element(tbs, 0xa0)?;
        let (_, _, rest) = element(rest, 0x02)?;
        let (algorithm, _, rest) = element(rest, 0x30)?;
        let (issuer, _, rest) = element(rest, 0x30)?;
        let (_, validity, rest) = element(rest, 0x30)?;
        let (subject, _, rest) = element(rest, 0x30)?;
        let (spki, _, rest) = element(rest, 0x30)?;
        if version != VERSION_DER
            || algorithm != ED25519_ALGORITHM_DER
            || issuer != NAME_DER
            || subject != NAME_DER
            || spki != tls_signer::spki(public)
            || !rest.is_empty()
            || !time_element(time_element(validity)?)?.is_empty()
        {
            return None;
        }
        Some(())
    };
    parse().is_some()
}

pub(super) fn credentials(
    identity: Arc<NativeIdentity>,
) -> Result<(CertificateDer<'static>, Arc<dyn rustls::sign::SigningKey>), Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Authentication)?
        .as_secs();
    let certificate = certificate_at(identity.clone(), now)?;
    Ok((certificate, tls_signer::signing_key(identity)))
}

fn parameters(now: u64) -> Result<rcgen::CertificateParams, Error> {
    let before = now
        .checked_sub(CLOCK_SKEW_SECONDS)
        .ok_or(Error::Authentication)?;
    let after = now
        .checked_add(CERTIFICATE_LIFETIME_SECONDS)
        .ok_or(Error::Authentication)?;
    let timestamp = |seconds: u64| {
        ASN1Time::from_timestamp(i64::try_from(seconds).map_err(|_| Error::Authentication)?)
            .map(|value| value.to_datetime())
            .map_err(|_| Error::Authentication)
    };
    let mut distinguished_name = rcgen::DistinguishedName::new();
    distinguished_name.push(rcgen::DnType::CommonName, "SIWORLD native peer");
    let mut params = rcgen::CertificateParams::default();
    params.not_before = timestamp(before)?;
    params.not_after = timestamp(after)?;
    params.distinguished_name = distinguished_name;
    Ok(params)
}

fn certificate_at(
    identity: Arc<NativeIdentity>,
    now: u64,
) -> Result<CertificateDer<'static>, Error> {
    let certificate =
        tls_signer::self_signed(identity, parameters(now)?).map_err(|_| Error::Authentication)?;
    if certificate.as_ref().len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::Authentication);
    }
    Ok(certificate)
}

/// The caller supplies the Ed25519 key from an independently pinned and
/// verified dual-identity descriptor. DNS names and public Web PKI are unused.
#[derive(Debug)]
pub(super) struct Verifier {
    public: [u8; 32],
}
impl Verifier {
    pub(super) fn new(public: [u8; 32]) -> Self {
        Self { public }
    }

    fn leaf<'a>(
        &self,
        der: &'a CertificateDer<'_>,
        now: Option<UnixTime>,
    ) -> Result<X509Certificate<'a>, rustls::Error> {
        if der.as_ref().len() > MAX_CERTIFICATE_BYTES
            || !strict_envelope(der.as_ref(), &self.public)
        {
            return Err(rejected());
        }
        let (remaining, cert) = X509Certificate::from_der(der.as_ref()).map_err(|_| rejected())?;
        let tbs = &cert.tbs_certificate;
        let validity = cert.validity();
        let span = validity
            .not_after
            .timestamp()
            .checked_sub(validity.not_before.timestamp())
            .ok_or_else(rejected)?;
        if !remaining.is_empty()
            || tbs.version != X509Version::V3
            || !ed25519_algorithm(&cert.signature_algorithm)
            || !ed25519_algorithm(&tbs.signature)
            || tbs.subject_pki.raw != tls_signer::spki(&self.public)
            || cert.subject().as_raw() != NAME_DER
            || cert.issuer().as_raw() != NAME_DER
            || !cert.extensions().is_empty()
            || tbs.issuer_uid.is_some()
            || tbs.subject_uid.is_some()
            || cert.raw_serial().is_empty()
            || cert.raw_serial().len() > 20
            || cert.raw_serial().iter().all(|byte| *byte == 0)
            || cert.raw_serial()[0] & 0x80 != 0
            || (cert.raw_serial().len() > 1
                && cert.raw_serial()[0] == 0
                && cert.raw_serial()[1] & 0x80 == 0)
            || cert.signature_value.unused_bits != 0
            || span <= 0
            || span > (CERTIFICATE_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS) as i64
        {
            return Err(rejected());
        }
        if let Some(now) = now {
            let seconds = i64::try_from(now.as_secs()).map_err(|_| rejected())?;
            let instant = ASN1Time::from_timestamp(seconds).map_err(|_| rejected())?;
            if !validity.is_valid_at(instant) {
                return Err(rejected());
            }
        }
        let signature =
            Signature::from_slice(&cert.signature_value.data).map_err(|_| rejected())?;
        let public = VerifyingKey::from_bytes(&self.public).map_err(|_| rejected())?;
        public
            .verify_strict(tbs.as_ref(), &signature)
            .map_err(|_| rejected())?;
        Ok(cert)
    }

    fn verify_signature(
        &self,
        cert: &CertificateDer<'_>,
        message: &[u8],
        scheme: SignatureScheme,
        signature: &[u8],
        context: &[u8],
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if scheme != SignatureScheme::ED25519
            || !tls_signer::certificate_verify_message(message, context)
        {
            return Err(rejected());
        }
        self.leaf(cert, None)?;
        let public = VerifyingKey::from_bytes(&self.public).map_err(|_| rejected())?;
        let signature = Signature::from_slice(signature).map_err(|_| rejected())?;
        public
            .verify_strict(message, &signature)
            .map_err(|_| rejected())?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn ed25519_algorithm(algorithm: &AlgorithmIdentifier<'_>) -> bool {
    algorithm.algorithm.to_id_string() == "1.3.101.112" && algorithm.parameters.is_none()
}

fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() || !ocsp_response.is_empty() {
            return Err(rejected());
        }
        self.leaf(end_entity, Some(now))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rejected())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(
            cert,
            message,
            dss.scheme,
            dss.signature(),
            tls_signer::SERVER_CONTEXT,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rejected());
        }
        self.leaf(end_entity, Some(now))?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rejected())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(
            cert,
            message,
            dss.scheme,
            dss.signature(),
            tls_signer::CLIENT_CONTEXT,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tls_signer;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::server::danger::ClientCertVerifier;
    use std::time::Duration;

    const NOW: u64 = 1_800_000_000;

    fn fixture() -> (CertificateDer<'static>, Verifier) {
        let identity = tls_signer::test_identity(7);
        let public = *identity.descriptor().unwrap().ed25519_public();
        let cert = certificate_at(identity, NOW).unwrap();
        (cert, Verifier::new(public))
    }

    fn now(seconds: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(seconds))
    }

    #[test]
    fn pinned_leaf_is_bounded_and_valid_for_both_tls_roles() {
        let (cert, verifier) = fixture();
        assert!(cert.as_ref().len() <= MAX_CERTIFICATE_BYTES);
        assert!(verifier.offer_client_auth());
        assert!(verifier.client_auth_mandatory());
        assert!(ClientCertVerifier::root_hint_subjects(&verifier).is_empty());
        let name = ServerName::try_from("unused.invalid").unwrap();
        verifier
            .verify_server_cert(&cert, &[], &name, &[], now(NOW))
            .unwrap();
        verifier.verify_client_cert(&cert, &[], now(NOW)).unwrap();
        assert_eq!(
            ServerCertVerifier::supported_verify_schemes(&verifier),
            vec![SignatureScheme::ED25519]
        );
    }

    #[test]
    fn wrong_pin_chains_ocsp_time_and_trailing_der_are_rejected() {
        let (cert, verifier) = fixture();
        let name = ServerName::try_from("unused.invalid").unwrap();
        assert!(
            Verifier::new([9; 32])
                .verify_client_cert(&cert, &[], now(NOW))
                .is_err()
        );
        assert!(
            verifier
                .verify_client_cert(&cert, std::slice::from_ref(&cert), now(NOW))
                .is_err()
        );
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[1], now(NOW))
                .is_err()
        );
        assert!(
            verifier
                .verify_client_cert(&cert, &[], now(NOW - CLOCK_SKEW_SECONDS - 1))
                .is_err()
        );
        assert!(
            verifier
                .verify_client_cert(&cert, &[], now(NOW + CERTIFICATE_LIFETIME_SECONDS + 1))
                .is_err()
        );
        let mut extra = cert.as_ref().to_vec();
        extra.push(0);
        assert!(
            verifier
                .verify_client_cert(&CertificateDer::from(extra), &[], now(NOW))
                .is_err()
        );
        let oversized = CertificateDer::from(vec![0; MAX_CERTIFICATE_BYTES + 1]);
        assert!(
            verifier
                .verify_client_cert(&oversized, &[], now(NOW))
                .is_err()
        );
        for offset in [0, cert.as_ref().len() - 1] {
            let mut changed = cert.as_ref().to_vec();
            changed[offset] ^= 1;
            assert!(
                verifier
                    .verify_client_cert(&CertificateDer::from(changed), &[], now(NOW))
                    .is_err()
            );
        }
    }

    fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        match body.len() {
            0..=127 => encoded.push(body.len() as u8),
            128..=255 => encoded.extend_from_slice(&[0x81, body.len() as u8]),
            _ => encoded.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]),
        }
        encoded.extend_from_slice(body);
        encoded
    }

    #[test]
    fn unconsumed_inner_der_and_nonminimal_lengths_are_rejected() {
        let (cert, verifier) = fixture();
        let (_, body, _) = element(cert.as_ref(), 0x30).unwrap();
        let mut extra = body.to_vec();
        extra.extend_from_slice(&[0x05, 0]);
        let trailing_inner = CertificateDer::from(wrap(0x30, &extra));
        assert!(
            verifier
                .verify_client_cert(&trailing_inner, &[], now(NOW))
                .is_err()
        );

        let (tbs, _, rest) = element(body, 0x30).unwrap();
        let (_, algorithm, signature) = element(rest, 0x30).unwrap();
        let mut bad_algorithm = algorithm.to_vec();
        bad_algorithm.push(0);
        let mut changed = tbs.to_vec();
        changed.extend_from_slice(&wrap(0x30, &bad_algorithm));
        changed.extend_from_slice(signature);
        let trailing_algorithm = CertificateDer::from(wrap(0x30, &changed));
        assert!(
            verifier
                .verify_client_cert(&trailing_algorithm, &[], now(NOW))
                .is_err()
        );

        assert!(element(&[0x30, 0x81, 1, 0], 0x30).is_none());
        assert!(element(&[0x30, 0x82, 0, 0x80], 0x30).is_none());
        assert!(element(&[0x30, 0x80, 0, 0], 0x30).is_none());
    }

    #[test]
    fn certificate_extensions_and_excessive_lifetime_are_rejected() {
        let identity = tls_signer::test_identity(7);
        let verifier = Verifier::new(*identity.descriptor().unwrap().ed25519_public());
        for case in 0..3 {
            let mut params = parameters(NOW).unwrap();
            match case {
                0 => params.subject_alt_names.push(rcgen::SanType::DnsName(
                    "unused.invalid".try_into().unwrap(),
                )),
                1 => {
                    params.not_after =
                        ASN1Time::from_timestamp((NOW + CERTIFICATE_LIFETIME_SECONDS + 1) as i64)
                            .unwrap()
                            .to_datetime()
                }
                _ => params
                    .distinguished_name
                    .push(rcgen::DnType::OrganizationName, "unexpected"),
            }
            let cert = tls_signer::self_signed(identity.clone(), params).unwrap();
            assert!(verifier.verify_client_cert(&cert, &[], now(NOW)).is_err());
        }
    }

    #[test]
    fn tls_signature_checks_bind_role_and_pinned_leaf() {
        let identity = tls_signer::test_identity(7);
        let cert = certificate_at(identity.clone(), NOW).unwrap();
        let verifier = Verifier::new(*identity.descriptor().unwrap().ed25519_public());
        let key = tls_signer::signing_key(identity);
        let signer = key.choose_scheme(&[SignatureScheme::ED25519]).unwrap();
        let mut message = vec![b' '; 64];
        message.extend_from_slice(tls_signer::SERVER_CONTEXT);
        message.push(0);
        message.extend_from_slice(&[3; 32]);
        let signature = signer.sign(&message).unwrap();
        verifier
            .verify_signature(
                &cert,
                &message,
                SignatureScheme::ED25519,
                &signature,
                tls_signer::SERVER_CONTEXT,
            )
            .unwrap();
        assert!(
            verifier
                .verify_signature(
                    &cert,
                    &message,
                    SignatureScheme::ED25519,
                    &signature,
                    tls_signer::CLIENT_CONTEXT
                )
                .is_err()
        );
        assert!(
            verifier
                .verify_signature(
                    &cert,
                    &message,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    &signature,
                    tls_signer::SERVER_CONTEXT
                )
                .is_err()
        );
        let last = message.len() - 1;
        message[last] ^= 1;
        assert!(
            verifier
                .verify_signature(
                    &cert,
                    &message,
                    SignatureScheme::ED25519,
                    &signature,
                    tls_signer::SERVER_CONTEXT
                )
                .is_err()
        );
    }
}
