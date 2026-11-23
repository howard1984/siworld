//! Synthetic integration fixture. This is not the desktop wire protocol or a
//! platform marker-store adapter.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

#[cfg(not(target_arch = "wasm32"))]
#[path = "support/mod.rs"]
mod support;

#[cfg(not(target_arch = "wasm32"))]
mod fixture {
    use std::{
        env, fs, io,
        io::Read,
        path::Path,
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
    use sha2::{Digest, Sha256};
    use sivault_core::{
        controlled_channel::{PendingClient, ReleaserIdentity, stream::Session},
        controlled_credential::{
            ClientCredential, ReleaserVerifier, sign_possession, verify_possession,
        },
        crypto::{Secret, random},
    };
    use sivault_releaser::{
        journal::{Checkpoint, MarkerStore},
        ledger::{AuthorityError, Event, SlotIdentity},
        message::{Id, Message},
        opening::{self, OpeningRecord, ReleaseMaterial},
        slot_store::{self, SlotMaterial},
    };
    use zeroize::Zeroizing;

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    use sivault_releaser::registration::{Registration, StoredRegistration};

    use super::support::*;

    const CHILD: &str = "--synthetic-releaser";
    const RESTARTED: &str = "--synthetic-releaser-restarted";
    const ENROLL: u8 = 1;
    const INIT: u8 = 3;
    const OWNER: u8 = 8;
    const RESULT: u8 = 64;
    const OK: u8 = 1;
    const WRONG: u8 = 2;
    const EXHAUSTED: u8 = 3;
    const RETIRED: u8 = 4;
    const PASSWORD: &str = "synthetic integration test password";
    const STORAGE_PASSWORD: &str = "synthetic releaser storage password";

    // Test-only checkpoint storage, independent of the slot directory.
    struct Marker<'a>(&'a Path);

    impl MarkerStore for Marker<'_> {
        fn load(&mut self, slot: SlotIdentity) -> Result<Option<Checkpoint>, AuthorityError> {
            assert_eq!(slot, super::support::slot());
            let bytes = match fs::read(self.0) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(AuthorityError::Unavailable),
            };
            let bytes: [u8; 64] = bytes
                .try_into()
                .map_err(|_| AuthorityError::InvalidEvidence)?;
            Ok(Some(Checkpoint {
                instance: Id(bytes[..32].try_into().unwrap()),
                head: Id(bytes[32..].try_into().unwrap()),
            }))
        }

        fn compare_and_store(
            &mut self,
            slot: SlotIdentity,
            expected: Option<Checkpoint>,
            next: Checkpoint,
        ) -> Result<(), AuthorityError> {
            if self.load(slot)? != expected {
                return Err(AuthorityError::Stale);
            }
            let mut bytes = next.instance.0.to_vec();
            bytes.extend_from_slice(&next.head.0);
            fs::write(self.0, bytes).map_err(|_| AuthorityError::Unavailable)
        }
    }

    fn identity() -> ReleaserIdentity {
        ReleaserIdentity::from_seeds(&Zeroizing::new([72; 64]), &Secret::new([73; 32]))
    }

    fn digest(bytes: &[u8]) -> Id {
        Id(Sha256::digest(bytes).into())
    }

    fn scope() -> OpeningRecord {
        OpeningRecord {
            slot: slot(),
            record: record(),
            record_id: attempt(0).selected_record,
            salt: id(74),
        }
    }

    fn signed_bytes<R: io::Read, W: io::Write>(
        session: &Session<R, W>,
        kind: u8,
        body: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"sivault synthetic journal fixture v1".to_vec());
        bytes.push(kind);
        bytes.extend_from_slice(session.binding().unwrap().as_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn signed_body<'a, R: io::Read, W: io::Write>(
        session: &Session<R, W>,
        kind: u8,
        bytes: &'a [u8],
        key: &MLDSA65VerificationKey,
    ) -> &'a [u8] {
        let (body, signature) = bytes.split_at(bytes.len() - MLDSA65Signature::len());
        verify_possession(
            key,
            &signed_bytes(session, kind, body),
            &MLDSA65Signature::new(signature.try_into().unwrap()),
        )
        .unwrap();
        body
    }

    fn enroll(path: &Path) {
        let identity = identity();
        let owner = ml_dsa_65::generate_key_pair([75; 32]).verification_key;
        let folder = ml_dsa_65::generate_key_pair([76; 32]).verification_key;
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let mut session =
            Session::accept(&mut input, &mut output, &slot().network.0, &identity).unwrap();
        let signed = session.receive(ENROLL).unwrap();
        let body = signed_body(&session, ENROLL, &signed, &owner);
        assert_eq!(
            &body[..32],
            digest(&scope().context().encode()).0.as_slice()
        );
        let verifier = ReleaserVerifier {
            stored_key: body[32..64].try_into().unwrap(),
            server_key: Secret::new(body[64..96].try_into().unwrap()),
        };
        let share = Secret::new(body[96..].try_into().unwrap());
        let material = ReleaseMaterial {
            scope: scope(),
            folder_key: folder,
            verifier,
            share,
        };
        let material = SlotMaterial {
            port: 31337,
            release: material,
            owner_key: owner,
            identity_kem_seed: Zeroizing::new([72; 64]),
            identity_signing_seed: Secret::new([73; 32]),
        };
        drop(
            slot_store::provision(
                &path.join("slot"),
                Marker(&path.join("checkpoint")),
                &material,
                2,
                STORAGE_PASSWORD,
            )
            .unwrap(),
        );
        session.send(RESULT, &[OK]).unwrap();
    }

    fn resume(path: &Path) {
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let mut start = [0; 1];
        input.read_exact(&mut start).unwrap();
        assert_eq!(start, [OK]);
        let checkpoint = path.join("checkpoint");
        let slot_path = path.join("slot");
        assert!(
            slot_store::open(&slot_path, Marker(&checkpoint), "wrong storage password").is_err()
        );

        let (material, mut service) =
            slot_store::open(&slot_path, Marker(&checkpoint), STORAGE_PASSWORD).unwrap();
        assert_eq!(material.port, 31337);
        let identity = material.identity();
        for (kind, spent) in [
            (INIT, 1),
            (INIT, 2),
            (INIT, 2),
            (OWNER, 2),
            (INIT, 3),
            (OWNER, 3),
            (INIT, 3),
        ] {
            let mut session =
                Session::accept(&mut input, &mut output, &slot().network.0, &identity).unwrap();
            if kind == OWNER {
                let payload = session.receive(kind).unwrap();
                let bytes = signed_body(&session, kind, &payload, &material.owner_key);
                service
                    .apply(Event::Owner {
                        message: Box::new(Message::decode(bytes).unwrap()),
                        digest: digest(bytes),
                        now: 3,
                    })
                    .unwrap();
                session.send(RESULT, &[OK]).unwrap();
                continue;
            }
            opening::serve(session, &mut service, &material.release).unwrap();
            assert_eq!(service.snapshot().unwrap().spent(), spent);
        }
        drop(service);
        let file = slot_path.join("material-v1");
        let original = fs::read(&file).unwrap();
        let replacement_path = path.join("replacement");
        drop(
            slot_store::provision(
                &replacement_path,
                Marker(&path.join("replacement-checkpoint")),
                &material,
                2,
                STORAGE_PASSWORD,
            )
            .unwrap(),
        );
        fs::copy(replacement_path.join("material-v1"), &file).unwrap();
        assert!(slot_store::open(&slot_path, Marker(&checkpoint), STORAGE_PASSWORD).is_err());
        fs::write(file, original).unwrap();
        let (_, service) =
            slot_store::open(&slot_path, Marker(&checkpoint), STORAGE_PASSWORD).unwrap();
        assert!(!service.snapshot().unwrap().is_serving());
    }

    fn owner<R: io::Read, W: io::Write>(
        mut input: R,
        mut output: W,
        restarted: impl FnOnce() -> (R, W),
    ) {
        let owner = ml_dsa_65::generate_key_pair([75; 32]);
        let folder = ml_dsa_65::generate_key_pair([76; 32]);
        let folder_id = opening::folder_key_id(&folder.verification_key).0;
        let pins = identity().pins();
        let pending = || PendingClient::start(pins.clone(), &slot().network.0, folder_id).unwrap();
        let folder_secret = Secret::new(random().unwrap());
        let share = Secret::new(random().unwrap());
        let generation_key = Secret::new(random().unwrap());
        let scope = scope();
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        let (payload_directory, payload_id, payload) = {
            let directory = tempfile::tempdir().unwrap();
            let id = scope.slot.safe.0[..16].try_into().unwrap();
            let mut safe = sivault_core::standard::Safe::create_controlled(
                directory.path().join("safe"),
                id,
                generation_key.clone(),
            )
            .unwrap();
            safe.create_directory("Synthetic files", None).unwrap();
            (directory, id, safe)
        };
        let context = scope.context();
        let correct = ClientCredential::new(PASSWORD, &folder_secret, &context).unwrap();
        let envelope = correct.wrap(&context, &share, &generation_key).unwrap();
        let verifier = correct.enrollment_verifier();
        let mut body = Zeroizing::new(digest(&context.encode()).0.to_vec());
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        let enroll_digest = digest(&body);
        body.extend_from_slice(&verifier.stored_key);
        body.extend_from_slice(verifier.server_key.as_ref());
        body.extend_from_slice(share.as_ref());
        let mut session = Session::connect(&mut input, &mut output, pending()).unwrap();
        let signature =
            sign_possession(&owner.signing_key, &signed_bytes(&session, ENROLL, &body)).unwrap();
        body.extend_from_slice(signature.as_slice());
        session.send(ENROLL, &body).unwrap();
        assert_eq!(&**session.receive(RESULT).unwrap(), &[OK]);
        drop(session);
        assert_eq!(
            input.read(&mut [0]).unwrap(),
            0,
            "enrollment process must exit"
        );
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            Registration {
                peer: Id(identity().pins().identifier()),
                port: 31337,
                scope,
                allowance: 2,
                enrollment_ack: enroll_digest,
                nonce: envelope.nonce,
                wrapped_key: envelope.ciphertext.to_vec(),
            }
            .publish(&payload, &generation_key)
            .unwrap();
            drop(payload);
        }

        let (mut input, mut output) = restarted();
        output.write_all(&[OK]).unwrap();
        output.flush().unwrap();
        let cases = [
            (OK, None),
            (WRONG, None),
            (EXHAUSTED, None),
            (OK, Some(refill(1, 2, 2))),
            (OK, None),
            (OK, Some(retire(2))),
            (RETIRED, None),
        ];
        for (expected, command) in cases {
            let mut session = Session::connect(&mut input, &mut output, pending()).unwrap();
            if let Some(message) = command {
                let mut bytes = message.encode().unwrap();
                let signature =
                    sign_possession(&owner.signing_key, &signed_bytes(&session, OWNER, &bytes))
                        .unwrap();
                bytes.extend_from_slice(signature.as_slice());
                session.send(OWNER, &bytes).unwrap();
                assert_eq!(&**session.receive(RESULT).unwrap(), &[OK]);
                continue;
            }
            let password = if expected == WRONG {
                "synthetic wrong password"
            } else {
                PASSWORD
            };
            #[cfg(any(target_os = "linux", target_vendor = "apple"))]
            let (persisted, scope, envelope) = {
                let persisted =
                    StoredRegistration::read(&payload_directory.path().join("safe")).unwrap();
                let scope = persisted.untrusted().scope.clone();
                let envelope = persisted.untrusted().envelope().unwrap();
                assert_eq!(persisted.untrusted().allowance, 2);
                assert_eq!(persisted.untrusted().peer.0, identity().pins().identifier());
                (persisted, scope, envelope)
            };
            let credential =
                ClientCredential::new(password, &folder_secret, &scope.context()).unwrap();
            let result = opening::open(session, &scope, credential, &folder.signing_key, &envelope);
            if expected == OK {
                let key = result.unwrap();
                assert_eq!(*key, *generation_key);
                #[cfg(any(target_os = "linux", target_vendor = "apple"))]
                {
                    assert!(
                        persisted
                            .authenticate(&Secret::new(random().unwrap()))
                            .is_err()
                    );
                    persisted.authenticate(&key).unwrap();
                    let safe = sivault_core::standard::Safe::open_controlled(
                        payload_directory.path().join("safe"),
                        payload_id,
                        key,
                        true,
                    )
                    .unwrap();
                    assert_eq!(safe.entries()[0].name, "Synthetic files");
                }
            } else {
                assert!(matches!(result, Err(opening::Error::Denied)));
            }
        }
    }

    pub fn run() {
        let mut args = env::args_os().skip(1);
        match args.next() {
            Some(mode) if mode == CHILD => return enroll(Path::new(&args.next().unwrap())),
            Some(mode) if mode == RESTARTED => return resume(Path::new(&args.next().unwrap())),
            _ => {}
        }
        let directory = tempfile::tempdir().unwrap();
        let spawn = |mode| {
            let mut child = Command::new(env::current_exe().unwrap())
                .arg(mode)
                .arg(directory.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let input = child.stdout.take().unwrap();
            let output = child.stdin.take().unwrap();
            (child, input, output)
        };
        let (mut child, input, output) = spawn(CHILD);
        let (mut restarted, second_input, second_output) = spawn(RESTARTED);
        let (done, outcome) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            owner(input, output, || (second_input, second_output));
            done.send(()).unwrap();
        });
        let outcome = outcome.recv_timeout(Duration::from_secs(15));
        if outcome.is_err() {
            let _ = child.kill();
            let _ = restarted.kill();
        }
        let status = child.wait().unwrap();
        let restart_status = restarted.wait().unwrap();
        worker.join().unwrap();
        outcome.unwrap();
        assert!(status.success() && restart_status.success());
        println!(
            "Controlled credential lifecycle passed after releaser process restart with an encrypted slot and file-backed journal"
        );
    }
}

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    fixture::run();
}
