use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    sync::Mutex,
    time::Duration,
};

use serde::Serialize;
use sivault_core::controlled_channel::{
    PendingClient, ReleaserIdentity, ReleaserPins, stream::Session,
};
use sivault_releaser::transport::Worker;
use tauri::State;
#[cfg(any(target_os = "macos", windows))]
use tauri::{AppHandle, Manager};

use crate::adapter::{BridgeError, Result};

const LOOPBACK_DEPLOYMENT: [u8; 32] = *b"sivault/local-controlled-safe/v1";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

struct Listening {
    address: SocketAddr,
    identifier: [u8; 32],
    worker: Worker,
    enrolled: bool,
}

#[derive(Default)]
struct Lifecycle {
    listener: Option<Listening>,
    exiting: bool,
    epoch: u64,
}

#[derive(Default)]
pub struct ReleaserState(Mutex<Lifecycle>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaserStatus {
    address: Option<String>,
    identifier: Option<String>,
    enrolled: bool,
}

impl ReleaserState {
    fn set_running(&self, enabled: bool) -> Result<ReleaserStatus> {
        self.set_running_at(enabled, None)
    }

    fn set_running_at(&self, enabled: bool, epoch: Option<u64>) -> Result<ReleaserStatus> {
        let mut state = self.0.lock().map_err(|_| unavailable())?;
        if enabled && (state.exiting || epoch.is_some_and(|epoch| epoch != state.epoch)) {
            return Err(unavailable());
        }
        if !enabled || address(&state).is_none() {
            // Keep the state lock until the old worker and socket are gone.
            drop(state.listener.take());
            state.epoch = state.epoch.wrapping_add(1);
        }
        if enabled && state.listener.is_none() {
            let identity = ReleaserIdentity::generate().map_err(|_| unavailable())?;
            let pins = identity.pins();
            let identifier = pins.identifier();
            let advertised = pins.encode();
            let (address, worker) = Worker::loopback(move |mut stream| {
                if stream.write_all(&advertised).is_ok()
                    && let Ok(reader) = stream.try_clone()
                {
                    // No slot has been enrolled in this process. Do not accept
                    // requests or issue any reply that appears to approve one.
                    let _ = Session::accept(reader, &mut stream, &LOOPBACK_DEPLOYMENT, &identity);
                }
            })
            .map_err(|_| unavailable())?;
            state.listener = Some(Listening {
                address,
                identifier,
                worker,
                enrolled: false,
            });
        }
        Ok(status(&state))
    }

    pub fn stop(&self, exiting: bool) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.exiting |= exiting;
        state.epoch = state.epoch.wrapping_add(1);
        drop(state.listener.take());
    }

    #[cfg(any(target_os = "macos", windows))]
    fn resume(&self, data: &std::path::Path, password: &str, epoch: u64) -> Result<ReleaserStatus> {
        use sivault_releaser::{journal::platform::PlatformMarker, opening, slot_store};
        let marker_dir = data.join("releaser-marker-locks");
        std::fs::create_dir_all(&marker_dir).map_err(|_| unavailable())?;
        let marker = PlatformMarker::new(&marker_dir).map_err(|_| unavailable())?;
        let (material, mut service) =
            slot_store::open(&data.join("releaser-slot"), marker, password)
                .map_err(|_| unavailable())?;
        let network = material.release.scope.slot.network.0;
        if network != LOOPBACK_DEPLOYMENT
            || !service.snapshot().is_some_and(|view| {
                view.is_serving() && view.active() == material.release.scope.record
            })
        {
            return Err(unavailable());
        }
        let identity = material.identity();
        let pins = identity.pins();
        let identifier = pins.identifier();
        let advertised = pins.encode();
        let mut state = self.0.lock().map_err(|_| unavailable())?;
        if state.exiting || state.epoch != epoch || state.listener.is_some() {
            return Err(unavailable());
        }
        let (address, worker) = Worker::loopback_on(material.port, move |mut stream| {
            if stream.write_all(&advertised).is_ok()
                && let Ok(reader) = stream.try_clone()
                && let Ok(session) = Session::accept(reader, &mut stream, &network, &identity)
            {
                let _ = opening::serve(session, &mut service, &material.release);
            }
        })
        .map_err(|_| unavailable())?;
        state.listener = Some(Listening {
            address,
            identifier,
            worker,
            enrolled: true,
        });
        Ok(status(&state))
    }
}

fn address(state: &Lifecycle) -> Option<SocketAddr> {
    listening(state).map(|listener| listener.address)
}

fn listening(state: &Lifecycle) -> Option<&Listening> {
    state
        .listener
        .as_ref()
        .filter(|listener| listener.worker.is_running())
}

fn status(state: &Lifecycle) -> ReleaserStatus {
    ReleaserStatus {
        address: address(state).map(|addr| addr.to_string()),
        identifier: listening(state).map(|listener| {
            let mut value = String::with_capacity(64);
            for byte in listener.identifier {
                use std::fmt::Write;
                let _ = write!(value, "{byte:02x}");
            }
            value
        }),
        enrolled: listening(state).is_some_and(|listener| listener.enrolled),
    }
}

fn invalid_peer() -> BridgeError {
    BridgeError::new(
        "RELEASER_INVALID_PEER",
        "Enter a releaser identifier and a local address.",
    )
}

struct LocalPeer {
    address: SocketAddrV4,
    identifier: [u8; 32],
}

impl LocalPeer {
    fn parse(address: &str, identifier: &str) -> Result<Self> {
        let address: SocketAddrV4 = address.trim().parse().map_err(|_| invalid_peer())?;
        let value = identifier.trim();
        if *address.ip() != Ipv4Addr::LOCALHOST
            || address.port() == 0
            || value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_peer());
        }
        let mut identifier = [0; 32];
        for (byte, pair) in identifier.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let hex = std::str::from_utf8(pair).map_err(|_| invalid_peer())?;
            *byte = u8::from_str_radix(hex, 16).map_err(|_| invalid_peer())?;
        }
        Ok(Self {
            address,
            identifier,
        })
    }

    fn connect(&self, folder: [u8; 32]) -> Result<Session<TcpStream, TcpStream>> {
        let mut stream = TcpStream::connect_timeout(&self.address.into(), CONNECT_TIMEOUT)
            .map_err(|_| unavailable())?;
        stream
            .set_read_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|_| unavailable())?;
        stream
            .set_write_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|_| unavailable())?;
        let mut advertised = [0; ReleaserPins::ENCODED_LEN];
        stream
            .read_exact(&mut advertised)
            .map_err(|_| unavailable())?;
        let pins = ReleaserPins::decode_pinned(&advertised, &self.identifier).map_err(|_| {
            BridgeError::new(
                "RELEASER_IDENTITY",
                "The address did not provide the expected releaser identity.",
            )
        })?;
        let pending =
            PendingClient::start(pins, &LOOPBACK_DEPLOYMENT, folder).map_err(|_| unavailable())?;
        let reader = stream.try_clone().map_err(|_| unavailable())?;
        Session::connect(reader, stream, pending).map_err(|_| {
            BridgeError::new(
                "RELEASER_IDENTITY",
                "The address did not prove the expected releaser identity.",
            )
        })
    }
}

fn unavailable() -> BridgeError {
    BridgeError::new("RELEASER_UNAVAILABLE", "The local releaser is unavailable.")
}

#[tauri::command]
pub fn releaser_status(state: State<'_, ReleaserState>) -> Result<ReleaserStatus> {
    let state = state.0.lock().map_err(|_| unavailable())?;
    Ok(status(&state))
}

#[tauri::command]
pub async fn releaser_verify(address: String, identifier: String) -> Result<()> {
    let peer = LocalPeer::parse(&address, &identifier)?;
    tauri::async_runtime::spawn_blocking(move || peer.connect([0; 32]).map(drop))
        .await
        .map_err(|_| unavailable())?
}

#[cfg(not(any(target_os = "macos", windows)))]
#[tauri::command]
pub fn releaser_set_running(
    state: State<'_, ReleaserState>,
    enabled: bool,
) -> Result<ReleaserStatus> {
    state.set_running(enabled)
}

#[cfg(any(target_os = "macos", windows))]
#[tauri::command]
pub async fn releaser_set_running(app: AppHandle, enabled: bool) -> Result<ReleaserStatus> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<ReleaserState>();
        if !enabled {
            return state.set_running(false);
        }
        let data = app.path().app_local_data_dir().map_err(|_| unavailable())?;
        let epoch = {
            let mut lifecycle = state.0.lock().map_err(|_| unavailable())?;
            if lifecycle.exiting {
                return Err(unavailable());
            }
            if address(&lifecycle).is_some() {
                return Ok(status(&lifecycle));
            }
            drop(lifecycle.listener.take());
            lifecycle.epoch = lifecycle.epoch.wrapping_add(1);
            lifecycle.epoch
        };
        match std::fs::symlink_metadata(data.join("releaser-slot")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                state.set_running_at(true, Some(epoch))
            }
            Ok(metadata) if metadata.is_dir() => {
                let Some(password) = crate::password::prompt_releaser(&app)? else {
                    return releaser_status(state);
                };
                state.resume(&data, &password, epoch)
            }
            _ => Err(unavailable()),
        }
    })
    .await
    .map_err(|_| unavailable())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    #[ignore = "requires permission to bind a loopback TCP socket"]
    fn desktop_releaser_defaults_off_and_closes_on_lock_and_exit() {
        let state = ReleaserState::default();
        assert!(address(&state.0.lock().unwrap()).is_none());
        let first = state.set_running(true).unwrap().address.unwrap();
        assert!(first.starts_with("127.0.0.1:"));
        assert_eq!(
            state.set_running(true).unwrap().address,
            Some(first.clone())
        );
        let _peer = TcpStream::connect(&first).unwrap();
        state.stop(false);
        assert!(TcpStream::connect(&first).is_err());
        let second = state.set_running(true).unwrap().address.unwrap();
        state.stop(true);
        assert!(TcpStream::connect(&second).is_err());
        assert!(state.set_running(true).is_err());
    }

    #[test]
    fn peer_input_only_accepts_loopback_and_a_full_identifier() {
        let identifier = "10".repeat(32);
        assert!(LocalPeer::parse("127.0.0.1:31337", &identifier).is_ok());
        assert!(LocalPeer::parse("127.0.0.1:0", &identifier).is_err());
        assert!(LocalPeer::parse("0.0.0.0:31337", &identifier).is_err());
        assert!(LocalPeer::parse("localhost:31337", &identifier).is_err());
        assert!(LocalPeer::parse("127.0.0.1:31337", "10").is_err());
        assert!(LocalPeer::parse("127.0.0.1:31337", &"GG".repeat(32)).is_err());
    }

    #[test]
    #[ignore = "requires permission to bind a loopback TCP socket"]
    fn owner_checks_the_pin_and_authenticated_handshake() {
        let releaser = ReleaserState::default();
        let status = releaser.set_running(true).unwrap();
        let address = status.address.unwrap();
        let identifier = status.identifier.unwrap();
        let wrong = LocalPeer::parse(&address, &"00".repeat(32)).unwrap();
        assert!(wrong.connect([0; 32]).is_err());
        let peer = LocalPeer::parse(&address, &identifier).unwrap();
        assert!(peer.connect([1; 32]).is_ok());
    }
}
