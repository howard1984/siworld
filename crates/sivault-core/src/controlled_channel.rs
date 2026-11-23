//! Authenticated releaser channel. The folder key identifier is still only a
//! claim here; credential evaluation requires a separate possession proof.

use std::time::{Duration, Instant};

use hkdf::Hkdf;
use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result, controlled_credential::ChannelBinding, crypto};

pub mod stream;

type Word = [u8; 32];
const CLIENT: &[u8; 9] = b"SVCH\0\x01\0\x01\x01";
const SERVER: &[u8; 9] = b"SVCH\0\x01\0\x01\x02";
const CLIENT_LEN: usize = CLIENT.len() + 5 * 32 + 1184 + 1088;
const SERVER_LEN: usize = SERVER.len() + 4 * 32 + 1088;
const MAX_PAYLOAD: usize = 8192;
const RECORD_OVERHEAD: usize = 26;
const LIFETIME: Duration = Duration::from_secs(120);

struct KemPrivate(MlKem768PrivateKey);
impl Drop for KemPrivate {
    fn drop(&mut self) {
        self.0[..MlKem768PrivateKey::len()].zeroize();
    }
}

pub struct ReleaserIdentity {
    kem: KemPrivate,
    signing: MLDSA65SigningKey,
    pins: ReleaserPins,
}

#[derive(Clone)]
pub struct ReleaserPins {
    pub kem: MlKem768PublicKey,
    pub verification: MLDSA65VerificationKey,
}

impl ReleaserPins {
    fn ids(&self) -> (Word, Word) {
        (
            hash(b"kem-id", &[self.kem.as_slice()]),
            hash(b"signing-id", &[self.verification.as_slice()]),
        )
    }
}

impl ReleaserIdentity {
    pub fn generate() -> Result<Self> {
        let kem = Zeroizing::new(crypto::random()?);
        let signing = Zeroizing::new(crypto::random()?);
        Ok(Self::from_seeds(&kem, &signing))
    }

    pub fn from_seeds(kem: &Zeroizing<[u8; 64]>, signing: &Zeroizing<Word>) -> Self {
        let (private, public) = mlkem768::generate_key_pair(**kem).into_parts();
        let keys = ml_dsa_65::generate_key_pair(**signing);
        Self {
            kem: KemPrivate(private),
            signing: keys.signing_key,
            pins: ReleaserPins {
                kem: public,
                verification: keys.verification_key,
            },
        }
    }

    pub fn pins(&self) -> ReleaserPins {
        self.pins.clone()
    }

    pub fn accept(&self, deployment: &Word, client: &[u8]) -> Result<(Vec<u8>, Channel)> {
        if client.len() != CLIENT_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut input = client;
        let (kem_id, signing_id) = self.pins.ids();
        if take::<9>(&mut input) != CLIENT
            || take::<32>(&mut input) != deployment
            || take::<32>(&mut input) != &kem_id
            || take::<32>(&mut input) != &signing_id
        {
            return Err(Error::Authentication);
        }
        let folder_key = *take::<32>(&mut input);
        let _client_nonce = take::<32>(&mut input);
        let reply_key = MlKem768PublicKey::from(take::<1184>(&mut input));
        if !mlkem768::validate_public_key(&reply_key) {
            return Err(Error::Authentication);
        }
        let first = Zeroizing::new(mlkem768::decapsulate(
            &self.kem.0,
            &MlKem768Ciphertext::from(take::<1088>(&mut input)),
        ));
        let entropy = Zeroizing::new(crypto::random()?);
        let (ciphertext, second) = mlkem768::encapsulate(&reply_key, *entropy);
        let second = Zeroizing::new(second);
        let nonce = crypto::random::<32>()?;
        let digest = hash(b"client-hello", &[client]);
        let mut server = join(&[
            SERVER,
            &kem_id,
            &signing_id,
            &nonce,
            &digest,
            ciphertext.as_slice(),
        ]);
        let signature = ml_dsa_65::sign(
            &self.signing,
            &frame(b"releaser-signature", &[client, &server]),
            b"",
            crypto::random()?,
        )
        .map_err(|_| Error::Authentication)?;
        server.extend_from_slice(signature.as_slice());
        let binding = hash(b"binding", &[client, &server]);
        Ok((
            server,
            Channel::derive(binding, folder_key, &first, &second, 2),
        ))
    }
}

impl Drop for ReleaserIdentity {
    fn drop(&mut self) {
        self.signing.as_mut_slice().zeroize();
    }
}

pub struct PendingClient {
    pins: ReleaserPins,
    hello: Vec<u8>,
    folder_key: Word,
    first: crypto::Secret,
    reply: KemPrivate,
    started: Instant,
}

impl PendingClient {
    pub fn start(pins: ReleaserPins, deployment: &Word, folder_key: Word) -> Result<Self> {
        if !mlkem768::validate_public_key(&pins.kem) {
            return Err(Error::Authentication);
        }
        let nonce = crypto::random::<32>()?;
        let reply_entropy = Zeroizing::new(crypto::random()?);
        let kem_entropy = Zeroizing::new(crypto::random()?);
        let (reply, key) = mlkem768::generate_key_pair(*reply_entropy).into_parts();
        let (ciphertext, first) = mlkem768::encapsulate(&pins.kem, *kem_entropy);
        let (kem_id, signing_id) = pins.ids();
        let hello = join(&[
            CLIENT,
            deployment,
            &kem_id,
            &signing_id,
            &folder_key,
            &nonce,
            key.as_slice(),
            ciphertext.as_slice(),
        ]);
        Ok(Self {
            pins,
            hello,
            folder_key,
            first: Zeroizing::new(first),
            reply: KemPrivate(reply),
            started: Instant::now(),
        })
    }

    pub fn hello(&self) -> &[u8] {
        &self.hello
    }

    pub fn finish(self, server: &[u8]) -> Result<Channel> {
        if self.started.elapsed() >= LIFETIME
            || server.len() != SERVER_LEN + MLDSA65Signature::len()
        {
            return Err(Error::InvalidFormat);
        }
        let (mut input, signature) = server.split_at(SERVER_LEN);
        let (kem_id, signing_id) = self.pins.ids();
        if take::<9>(&mut input) != SERVER
            || take::<32>(&mut input) != &kem_id
            || take::<32>(&mut input) != &signing_id
        {
            return Err(Error::Authentication);
        }
        let _server_nonce = take::<32>(&mut input);
        if take::<32>(&mut input) != &hash(b"client-hello", &[&self.hello]) {
            return Err(Error::Authentication);
        }
        let signature =
            MLDSA65Signature::new(signature.try_into().map_err(|_| Error::InvalidFormat)?);
        ml_dsa_65::verify(
            &self.pins.verification,
            &frame(b"releaser-signature", &[&self.hello, &server[..SERVER_LEN]]),
            b"",
            &signature,
        )
        .map_err(|_| Error::Authentication)?;
        let second = Zeroizing::new(mlkem768::decapsulate(
            &self.reply.0,
            &MlKem768Ciphertext::from(take::<1088>(&mut input)),
        ));
        let binding = hash(b"binding", &[&self.hello, server]);
        Ok(Channel::derive(
            binding,
            self.folder_key,
            &self.first,
            &second,
            1,
        ))
    }
}

/// A short-lived channel for one application exchange. Drop it after the
/// terminal response. An invalid record destroys both traffic keys.
///
/// Channel creation from a caller-selected binding is not available to
/// downstream crates. This check also runs with the release profile.
///
/// ```compile_fail,E0624
/// use sivault_core::controlled_channel::Channel;
/// let _ = Channel::derive([0; 32], [0; 32], &[0; 32], &[0; 32], 1);
/// ```
pub struct Channel {
    binding: ChannelBinding,
    folder_key: Word,
    traffic: Option<[crypto::Secret; 2]>,
    counters: [u64; 2],
    outgoing: u8,
    started: Instant,
}

impl Channel {
    fn derive(binding: Word, folder_key: Word, first: &Word, second: &Word, outgoing: u8) -> Self {
        let mut secrets = Zeroizing::new([0; 64]);
        secrets[..32].copy_from_slice(first);
        secrets[32..].copy_from_slice(second);
        let hkdf = Hkdf::<Sha256>::new(Some(&binding), secrets.as_ref());
        let traffic = [b"client-to-releaser".as_slice(), b"releaser-to-client"].map(|label| {
            let mut key = Zeroizing::new([0; 32]);
            hkdf.expand(&frame(b"traffic-key", &[label]), key.as_mut())
                .expect("32-byte HKDF output");
            key
        });
        Self {
            binding: ChannelBinding::authenticated(binding),
            folder_key,
            traffic: Some(traffic),
            counters: [0; 2],
            outgoing,
            started: Instant::now(),
        }
    }

    pub fn binding(&self) -> ChannelBinding {
        self.binding
    }

    pub fn claimed_folder_key(&self) -> &Word {
        &self.folder_key
    }

    pub fn seal(&mut self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let result = if plaintext.len() <= MAX_PAYLOAD && kind != 0 {
            self.record(self.outgoing, |key, nonce, header| {
                let aad = frame(b"record", &[self.binding.as_bytes(), &[kind], header]);
                let ciphertext = crypto::seal(key, nonce, &aad, plaintext)?;
                Ok(join(&[&[kind], header, &ciphertext]))
            })
        } else {
            Err(Error::InvalidFormat)
        };
        self.advance(self.outgoing, result)
    }

    pub fn open(&mut self, kind: u8, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let direction = 3 - self.outgoing;
        let result = if (RECORD_OVERHEAD..=MAX_PAYLOAD + RECORD_OVERHEAD).contains(&bytes.len())
            && kind != 0
            && bytes[0] == kind
        {
            self.record(direction, |key, nonce, header| {
                if header != &bytes[1..10] {
                    return Err(Error::Authentication);
                }
                let aad = frame(b"record", &[self.binding.as_bytes(), &[kind], header]);
                crypto::unseal(key, nonce, &aad, &bytes[10..])
            })
        } else {
            Err(Error::InvalidFormat)
        };
        self.advance(direction, result)
    }

    fn record<T>(
        &self,
        direction: u8,
        f: impl FnOnce(&Word, &[u8; 24], &[u8; 9]) -> Result<T>,
    ) -> Result<T> {
        let traffic = self.traffic.as_ref().ok_or(Error::Authentication)?;
        let index = usize::from(direction - 1);
        let counter = self.counters[index];
        if counter == u64::MAX || self.started.elapsed() >= LIFETIME {
            return Err(Error::Authentication);
        }
        let mut header = [direction; 9];
        header[1..].copy_from_slice(&counter.to_be_bytes());
        let mut nonce = [0; 24];
        nonce[16..].copy_from_slice(&header[1..]);
        f(&traffic[index], &nonce, &header)
    }

    fn advance<T>(&mut self, direction: u8, result: Result<T>) -> Result<T> {
        if result.is_ok() {
            self.counters[usize::from(direction - 1)] += 1;
        } else {
            self.traffic = None;
        }
        result
    }
}

// Only used after exact-size verification of a canonical fixed-width hello.
fn take<'a, const N: usize>(input: &mut &'a [u8]) -> &'a [u8; N] {
    let (field, rest) = input.split_at(N);
    *input = rest;
    field.try_into().expect("fixed field width")
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn frame(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut output = b"sivault/controlled-channel/v1\0".to_vec();
    for part in std::iter::once(label).chain(parts.iter().copied()) {
        output.extend_from_slice(&(part.len() as u32).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

fn hash(label: &[u8], parts: &[&[u8]]) -> Word {
    Sha256::digest(frame(label, parts)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT: Word = [7; 32];
    const FOLDER: Word = [8; 32];

    fn identity(seed: u8) -> ReleaserIdentity {
        ReleaserIdentity::from_seeds(&Zeroizing::new([seed; 64]), &Zeroizing::new([seed; 32]))
    }

    fn pair() -> (Channel, Channel) {
        let releaser = identity(3);
        let pending = PendingClient::start(releaser.pins(), &DEPLOYMENT, FOLDER).unwrap();
        let (hello, server) = releaser.accept(&DEPLOYMENT, pending.hello()).unwrap();
        (pending.finish(&hello).unwrap(), server)
    }

    #[test]
    fn authenticates_both_directions_and_closes_on_duplicate() {
        let (mut client, mut server) = pair();
        assert_eq!(client.binding(), server.binding());
        assert_eq!(server.claimed_folder_key(), &FOLDER);
        let request = client.seal(1, b"request").unwrap();
        assert_eq!(&**server.open(1, &request).unwrap(), b"request");
        let response = server.seal(2, b"response").unwrap();
        assert_eq!(&**client.open(2, &response).unwrap(), b"response");
        assert!(server.open(1, &request).is_err());
        assert!(server.seal(2, b"closed").is_err());
    }

    #[test]
    fn rejects_changed_hellos_and_pins() {
        let releaser = identity(3);
        let pending = PendingClient::start(releaser.pins(), &DEPLOYMENT, FOLDER).unwrap();
        assert!(releaser.accept(&[9; 32], pending.hello()).is_err());
        assert!(identity(4).accept(&DEPLOYMENT, pending.hello()).is_err());
        let (mut hello, _) = releaser.accept(&DEPLOYMENT, pending.hello()).unwrap();
        hello[SERVER_LEN] ^= 1;
        assert!(pending.finish(&hello).is_err());
    }

    #[test]
    fn a_replayed_hello_does_not_reuse_traffic_keys() {
        let releaser = identity(3);
        let pending = PendingClient::start(releaser.pins(), &DEPLOYMENT, FOLDER).unwrap();
        let (hello, mut original) = releaser.accept(&DEPLOYMENT, pending.hello()).unwrap();
        let (_, mut replay) = releaser.accept(&DEPLOYMENT, pending.hello()).unwrap();
        assert_ne!(original.binding(), replay.binding());
        let frame = pending.finish(&hello).unwrap().seal(1, b"request").unwrap();
        assert!(replay.open(1, &frame).is_err());
        assert!(original.open(1, &frame).is_ok());
    }

    #[test]
    fn rejects_wrong_kind_ciphertext_and_counter_gap() {
        let (mut client, mut server) = pair();
        let valid = client.seal(1, b"message").unwrap();
        assert!(server.open(2, &valid).is_err());

        let (mut client, mut server) = pair();
        let mut corrupted = client.seal(1, b"message").unwrap();
        corrupted[10] ^= 1;
        assert!(server.open(1, &corrupted).is_err());

        let (mut client, mut server) = pair();
        client.seal(1, b"lost").unwrap();
        let ahead = client.seal(1, b"gap").unwrap();
        assert!(server.open(1, &ahead).is_err());
    }

    #[test]
    fn expires_and_never_wraps_a_counter() {
        let (mut client, mut server) = pair();
        client.started -= LIFETIME;
        assert!(client.seal(1, b"late").is_err());
        server.counters[1] = u64::MAX;
        assert!(server.seal(2, b"overflow").is_err());
    }
}
