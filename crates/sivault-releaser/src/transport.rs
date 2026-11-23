//! A connection boundary for an explicitly configured, one-peer tailnet demo.
//! Address filtering does not authenticate the peer. An authenticated SIVault
//! channel is required on every accepted connection.

use std::{
    io,
    net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::Path;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use sivault_core::controlled_channel::{ReleaserIdentity, stream::Session};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::{
    journal::{Journal, platform::PlatformMarker},
    ledger::Releaser,
    opening::{self, ReleaseMaterial},
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub struct TailnetListener {
    listener: TcpListener,
    peer: Ipv4Addr,
}

impl TailnetListener {
    /// Serve normal opens for an already-provisioned slot. The marker store
    /// and journal must agree before the listener starts accepting requests.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn run_openings(
        self,
        journal_path: &Path,
        marker_dir: &Path,
        identity: ReleaserIdentity,
        material: ReleaseMaterial,
    ) -> io::Result<Worker> {
        let unavailable = |_| io::Error::other("Releaser journal is unavailable");
        let slot = material.scope.slot;
        let marker = PlatformMarker::new(marker_dir).map_err(unavailable)?;
        let journal = Journal::open(journal_path, marker, slot).map_err(unavailable)?;
        let mut releaser = Releaser::new(journal);
        releaser
            .recover(slot)
            .map_err(|_| io::Error::other("Releaser is quarantined"))?;
        if !releaser
            .snapshot()
            .is_some_and(|state| state.is_serving() && state.active() == material.scope.record)
        {
            return Err(io::Error::other("Releaser record is not active"));
        }
        self.run(move |mut stream| {
            if let Ok(input) = stream.try_clone()
                && let Ok(session) = Session::accept(input, &mut stream, &slot.network.0, &identity)
            {
                let _ = opening::serve(session, &mut releaser, &material);
            }
        })
    }

    /// Bind only the local Tailscale IPv4 address, never all interfaces. The
    /// caller obtains the actual interface addresses from the deployment.
    pub fn bind(local: SocketAddrV4, peer: Ipv4Addr) -> io::Result<Self> {
        if !in_tailnet(*local.ip()) || !in_tailnet(peer) || local.ip() == &peer || local.port() == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid tailnet endpoint",
            ));
        }
        let listener = TcpListener::bind(local)?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, peer })
    }

    /// Nonblocking. Rejected peers are dropped before any protocol bytes are
    /// received. The caller may keep exactly one live exchange at a time.
    pub fn poll(&self) -> io::Result<Option<TcpStream>> {
        accept_from(&self.listener, self.peer)
    }

    /// Own the listener and execute at most one authenticated exchange at a
    /// time. The exchange must not detach work or duplicate the socket into
    /// another process; the caller stops this worker on lock and exit.
    pub fn run(self, exchange: impl FnMut(TcpStream) + Send + 'static) -> io::Result<Worker> {
        Worker::spawn(move || self.poll(), exchange)
    }
}

fn accept_from(listener: &TcpListener, peer: Ipv4Addr) -> io::Result<Option<TcpStream>> {
    let (stream, source) = match listener.accept() {
        Ok(pair) => pair,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(error) => return Err(error),
    };
    if !matches!(source, SocketAddr::V4(address) if *address.ip() == peer) {
        return Ok(None);
    }
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(Some(stream))
}

#[derive(Default)]
struct State {
    stopping: bool,
    active: Option<TcpStream>,
}

pub struct Worker {
    state: Arc<Mutex<State>>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// Listen only on IPv4 loopback, using an ephemeral local port.
    pub fn loopback(
        exchange: impl FnMut(TcpStream) + Send + 'static,
    ) -> io::Result<(SocketAddr, Self)> {
        Self::loopback_on(0, exchange)
    }

    /// Bind the previously enrolled local port, or allocate a port if zero.
    pub fn loopback_on(
        port: u16,
        exchange: impl FnMut(TcpStream) + Send + 'static,
    ) -> io::Result<(SocketAddr, Self)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let worker = Self::spawn(
            move || accept_from(&listener, Ipv4Addr::LOCALHOST),
            exchange,
        )?;
        Ok((address, worker))
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    fn spawn(
        mut accept: impl FnMut() -> io::Result<Option<TcpStream>> + Send + 'static,
        mut exchange: impl FnMut(TcpStream) + Send + 'static,
    ) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(State::default()));
        let worker_state = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("sivault-releaser".into())
            .spawn(move || {
                loop {
                    let Ok(mut state) = worker_state.lock() else {
                        break;
                    };
                    if state.stopping {
                        break;
                    }
                    match accept() {
                        Ok(Some(stream)) => {
                            let Ok(handle) = stream.try_clone() else {
                                continue;
                            };
                            state.active = Some(handle);
                            drop(state);
                            exchange(stream);
                            let Ok(mut state) = worker_state.lock() else {
                                break;
                            };
                            state.active = None;
                        }
                        Ok(None) => {
                            drop(state);
                            thread::park_timeout(POLL_INTERVAL);
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            state,
            thread: Some(thread),
        })
    }

    /// Close the active connection before joining, without waiting on the peer
    /// to send another byte. After return no exchange or listener remains.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.stopping = true;
            if let Some(stream) = state.active.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        thread.thread().unpark();
        let _ = thread.join();
    }
}

fn in_tailnet(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 100 && (64..128).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, sync::mpsc};

    #[test]
    fn stopping_closes_an_inflight_exchange_and_the_listener() {
        let (entered, ready) = mpsc::sync_channel(1);
        let (address, worker) = Worker::loopback(move |mut stream| {
            entered.send(()).unwrap();
            let _ = stream.read_exact(&mut [0]);
        })
        .unwrap();
        assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
        assert!(worker.is_running());
        let mut client = TcpStream::connect(address).unwrap();
        client.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        ready.recv_timeout(IO_TIMEOUT).unwrap();
        let start = std::time::Instant::now();
        worker.stop();
        assert!(start.elapsed() < IO_TIMEOUT);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert!(TcpStream::connect(address).is_err());
    }

    #[test]
    fn only_explicit_shared_range_addresses_can_bind() {
        let allowed = Ipv4Addr::new(100, 100, 0, 1);
        assert!(in_tailnet(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(in_tailnet(Ipv4Addr::new(100, 127, 255, 255)));
        for invalid in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 0),
        ] {
            assert!(!in_tailnet(invalid));
            assert!(
                matches!(TailnetListener::bind(SocketAddrV4::new(invalid, 31337), allowed), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
            );
        }
    }
}
