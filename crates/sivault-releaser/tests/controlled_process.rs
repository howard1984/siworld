//! Synthetic integration fixture. This is not the desktop wire protocol or a
//! platform marker-store adapter.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

#[cfg(not(target_arch = "wasm32"))]
#[path = "support/mod.rs"]
mod support;

#[cfg(not(target_arch = "wasm32"))]
mod fixture {
    use std::{
        env, io,
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
        journal::{Checkpoint, Journal, MarkerStore},
        ledger::{AuthorityError, Event, Releaser, SlotIdentity},
        message::{Id, Message},
        opening::{self, OpeningRecord, ReleaseMaterial},
    };
    use zeroize::Zeroizing;

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    use sivault_releaser::registration::{Registration, StoredRegistration};

    use super::support::*;

    const CHILD: &str = "--synthetic-releaser";
    const ENROLL: u8 = 1;
    const INIT: u8 = 3;
    const OWNER: u8 = 8;
    const RESULT: u8 = 64;
    const OK: u8 = 1;
    const WRONG: u8 = 2;
    const EXHAUSTED: u8 = 3;
    const RETIRED: u8 = 4;
    const PASSWORD: &str = "synthetic integration test password";

    #[derive(Default)]
    struct Marker(Option<Checkpoint>);

    impl MarkerStore for &mut Marker {
        fn load(&mut self, _: SlotIdentity) -> Result<Option<Checkpoint>, AuthorityError> {
            Ok(self.0)
        }

        fn compare_and_store(
            &mut self,
            _: SlotIdentity,
            expected: Option<Checkpoint>,
            next: Checkpoint,
        ) -> Result<(), AuthorityError> {
            if self.0 != expected {
                return Err(AuthorityError::Stale);
            }
            self.0 = Some(next);
            Ok(())
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

    fn releaser(path: &Path) {
        let identity = identity();
        let owner = ml_dsa_65::generate_key_pair([75; 32]).verification_key;
        let folder = ml_dsa_65::generate_key_pair([76; 32]).verification_key;
        let mut input = io::stdin().lock();
        let mut output = io::stdout().lock();
        let mut marker = Marker::default();
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
        let journal = Journal::provision(
            path,
            &mut marker,
            slot(),
            Id(random().unwrap()),
            2,
            record(),
        )
        .unwrap();
        session.send(RESULT, &[OK]).unwrap();
        drop(journal);
        drop(session);

        // Reopen and replay the journal for each new authenticated exchange.
        for (kind, spent) in [
            (INIT, 1),
            (INIT, 2),
            (INIT, 2),
            (OWNER, 2),
            (INIT, 3),
            (OWNER, 3),
            (INIT, 3),
        ] {
            let journal = Journal::open(path, &mut marker, slot()).unwrap();
            let mut service = Releaser::new(journal);
            service.recover(slot()).unwrap();
            let mut session =
                Session::accept(&mut input, &mut output, &slot().network.0, &identity).unwrap();
            if kind == OWNER {
                let payload = session.receive(kind).unwrap();
                let bytes = signed_body(&session, kind, &payload, &owner);
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
            opening::serve(session, &mut service, &material).unwrap();
            assert_eq!(service.snapshot().unwrap().spent(), spent);
        }
    }

    fn owner<R: io::Read, W: io::Write>(mut input: R, mut output: W) {
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
        if args.next().as_deref() == Some(CHILD.as_ref()) {
            releaser(Path::new(&args.next().unwrap()));
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new(env::current_exe().unwrap())
            .arg(CHILD)
            .arg(directory.path().join("journal"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdout.take().unwrap();
        let output = child.stdin.take().unwrap();
        let (done, outcome) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            owner(input, output);
            done.send(()).unwrap();
        });
        let outcome = outcome.recv_timeout(Duration::from_secs(15));
        if outcome.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        worker.join().unwrap();
        outcome.unwrap();
        assert!(status.success());
        println!(
            "Controlled credential lifecycle passed between independent processes with a file-backed journal"
        );
    }
}

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    fixture::run();
}
