#[cfg(not(target_arch = "wasm32"))]
mod fixture {
    use std::{
        env, io,
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use sivault_core::controlled_channel::{PendingClient, ReleaserIdentity, stream::Session};
    use zeroize::Zeroizing;

    const DEPLOYMENT: [u8; 32] = [13; 32];
    const FOLDER: [u8; 32] = [42; 32];
    const CHILD: &str = "--synthetic-releaser";

    fn identity() -> ReleaserIdentity {
        ReleaserIdentity::from_seeds(&Zeroizing::new([7; 64]), &Zeroizing::new([9; 32]))
    }

    fn releaser() {
        let mut session = Session::accept(
            io::stdin().lock(),
            io::stdout().lock(),
            &DEPLOYMENT,
            &identity(),
        )
        .unwrap();
        assert_eq!(session.claimed_folder_key().unwrap(), &FOLDER);
        assert_eq!(&**session.receive(1).unwrap(), b"synthetic request");
        let mut response = b"synthetic response".to_vec();
        response.extend_from_slice(session.binding().unwrap().as_bytes());
        session.send(2, &response).unwrap();
    }

    pub fn run() {
        if env::args().nth(1).as_deref() == Some(CHILD) {
            releaser();
            return;
        }
        let mut child = Command::new(env::current_exe().unwrap())
            .arg(CHILD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let reader = child.stdout.take().unwrap();
        let writer = child.stdin.take().unwrap();
        let (done, outcome) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let pending = PendingClient::start(identity().pins(), &DEPLOYMENT, FOLDER).unwrap();
            let mut session = Session::connect(reader, writer, pending).unwrap();
            session.send(1, b"synthetic request").unwrap();
            let reply = session.receive(2).unwrap();
            let mut expected = b"synthetic response".to_vec();
            expected.extend_from_slice(session.binding().unwrap().as_bytes());
            assert_eq!(*reply, expected);
            done.send(()).unwrap();
        });
        let outcome = outcome.recv_timeout(Duration::from_secs(5));
        if outcome.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        worker.join().unwrap();
        outcome.unwrap();
        assert!(status.success());
        println!("Authenticated channel exchanged bounded frames between independent processes");
    }
}

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    fixture::run();
}
