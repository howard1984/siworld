use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
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

pub(crate) const LOOPBACK_DEPLOYMENT: [u8; 32] = *b"sivault/local-controlled-safe/v1";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(any(target_os = "macos", windows))]
fn listen(
    saved_port: Option<u16>,
    exchange: impl FnMut(TcpStream) + Send + 'static,
) -> Result<(SocketAddr, Worker)> {
    #[cfg(all(feature = "desktop-e2e", debug_assertions))]
    {
        let local = std::env::var_os("SIVAULT_TEST_RELEASER_BIND");
        let peer = std::env::var_os("SIVAULT_TEST_RELEASER_PEER");
        match (local, peer) {
            (Some(local), Some(peer)) => {
                let local: SocketAddrV4 = local
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(unavailable)?;
                let peer: Ipv4Addr = peer
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(unavailable)?;
                if saved_port.is_some_and(|port| port != local.port()) {
                    return Err(unavailable());
                }
                let listener = sivault_releaser::transport::TailnetListener::bind(local, peer)
                    .map_err(|_| unavailable())?;
                let worker = listener.run(exchange).map_err(|_| unavailable())?;
                return Ok((local.into(), worker));
            }
            (None, None) => (),
            _ => return Err(unavailable()),
        }
    }
    Worker::loopback_on(saved_port.unwrap_or(0), exchange).map_err(|_| unavailable())
}

fn safe_endpoint(address: SocketAddrV4) -> bool {
    address.port() != 0
        && (*address.ip() == Ipv4Addr::LOCALHOST
            || (cfg!(all(feature = "desktop-e2e", debug_assertions))
                && sivault_releaser::transport::in_tailnet(*address.ip())))
}

struct Listening {
    address: SocketAddr,
    identifier: [u8; 32],
    worker: Worker,
    enrolled: Arc<AtomicBool>,
    #[cfg(any(target_os = "macos", windows))]
    authorization: Option<Arc<Mutex<Option<Authorization>>>>,
}

#[cfg(any(target_os = "macos", windows))]
struct Authorization {
    owner: [u8; 32],
    allowance: u64,
    until: std::time::Instant,
    password: zeroize::Zeroizing<String>,
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
    #[cfg(all(
        feature = "desktop-e2e",
        debug_assertions,
        any(target_os = "macos", windows)
    ))]
    pub(crate) fn start_test_service(
        &self,
        data: std::path::PathBuf,
        password: &str,
        owner: [u8; 32],
    ) -> Result<String> {
        let status = if data.join("releaser-slot").is_dir() {
            self.resume(&data, password, 0)?
        } else {
            let status = self.start_enrollment(data, 0)?;
            let state = self.0.lock().map_err(|_| unavailable())?;
            let authorization = listening(&state)
                .and_then(|listener| listener.authorization.as_ref())
                .ok_or_else(unavailable)?;
            *authorization.lock().map_err(|_| unavailable())? = Some(Authorization {
                owner,
                allowance: 2,
                until: std::time::Instant::now() + Duration::from_secs(30),
                password: zeroize::Zeroizing::new(password.into()),
            });
            status
        };
        Ok(format!(
            "{} {}",
            status.address.ok_or_else(unavailable)?,
            status.identifier.ok_or_else(unavailable)?
        ))
    }

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
                enrolled: Arc::new(AtomicBool::new(false)),
                #[cfg(any(target_os = "macos", windows))]
                authorization: None,
            });
        }
        Ok(status(&state))
    }

    #[cfg(any(target_os = "macos", windows))]
    fn start_enrollment(&self, data: std::path::PathBuf, epoch: u64) -> Result<ReleaserStatus> {
        use sivault_core::{crypto, owner};
        use sivault_releaser::{
            administration::Service,
            enrollment,
            journal::platform::PlatformMarker,
            message::{Id, Kind},
            slot_store,
        };
        use zeroize::Zeroizing;

        let mut lifecycle = self.0.lock().map_err(|_| unavailable())?;
        if lifecycle.exiting || lifecycle.epoch != epoch || lifecycle.listener.is_some() {
            return Err(unavailable());
        }
        let marker_dir = data.join("releaser-marker-locks");
        std::fs::create_dir_all(&marker_dir).map_err(|_| unavailable())?;
        let slot_path = data.join("releaser-slot");
        let kem = Zeroizing::new(crypto::random().map_err(|_| unavailable())?);
        let signing = Zeroizing::new(crypto::random().map_err(|_| unavailable())?);
        let identity = ReleaserIdentity::from_seeds(&kem, &signing);
        let pins = identity.pins();
        let identifier = pins.identifier();
        let advertised = pins.encode();
        let enrolled = Arc::new(AtomicBool::new(false));
        let serving = Arc::clone(&enrolled);
        let authorization = Arc::new(Mutex::new(None::<Authorization>));
        let permitted = Arc::clone(&authorization);
        let mut active = None::<Service<PlatformMarker>>;
        let (address, worker) = listen(None, move |mut stream| {
            let Ok(local) = stream.local_addr() else {
                return;
            };
            if stream.write_all(&advertised).is_err() {
                return;
            }
            let Ok(reader) = stream.try_clone() else {
                return;
            };
            let Ok(mut session) =
                Session::accept(reader, &mut stream, &LOOPBACK_DEPLOYMENT, &identity)
            else {
                return;
            };
            let Ok((kind, payload)) = session.receive_message() else {
                return;
            };
            if let Some(service) = &mut active {
                if let Ok(now) = unix_now() {
                    let _ = service.serve(session, kind, &payload, &identity, &slot_path, now);
                }
                return;
            }
            if kind != Kind::Enroll as u8 {
                return;
            }
            let (Ok(binding), Ok(folder), Ok(now)) =
                (session.binding(), session.claimed_folder_key(), unix_now())
            else {
                return;
            };
            let Ok(accepted) = enrollment::verify(
                &payload,
                &binding,
                Id(LOOPBACK_DEPLOYMENT),
                Id(identifier),
                Id(*folder),
                now,
            ) else {
                return;
            };
            drop(payload);
            let allow = permitted.lock().ok().and_then(|mut pending| {
                if pending
                    .as_ref()
                    .is_some_and(|entry| entry.until <= std::time::Instant::now())
                {
                    *pending = None;
                }
                if pending.as_ref().is_some_and(|entry| {
                    entry.owner == owner::key_id(&accepted.owner_key)
                        && entry.allowance == accepted.allowance
                }) {
                    pending.take()
                } else {
                    None
                }
            });
            let Some(allow) = allow else { return };
            let Ok(marker) = PlatformMarker::new(&marker_dir) else {
                return;
            };
            let stored = slot_store::SlotMaterial {
                port: local.port(),
                release: accepted.release,
                owner_key: accepted.owner_key,
                identity_kem_seed: kem.clone(),
                identity_signing_seed: signing.clone(),
            };
            let Ok((service, head)) = slot_store::provision_with_head(
                &slot_path,
                marker,
                &stored,
                accepted.allowance,
                &allow.password,
            ) else {
                return;
            };
            drop(allow);
            let accepted = enrollment::VerifiedEnrollment {
                release: stored.release,
                owner_key: stored.owner_key,
                ..accepted
            };
            let _ = enrollment::acknowledge(&mut session, &identity, &accepted, head);
            active = Some(Service::new(service, accepted.release, accepted.owner_key));
            serving.store(true, Ordering::Release);
        })?;
        lifecycle.listener = Some(Listening {
            address,
            identifier,
            worker,
            enrolled,
            authorization: Some(authorization),
        });
        Ok(status(&lifecycle))
    }

    pub fn stop(&self, exiting: bool) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.exiting |= exiting;
        state.epoch = state.epoch.wrapping_add(1);
        drop(state.listener.take());
    }

    #[cfg(any(target_os = "macos", windows))]
    fn resume(&self, data: &std::path::Path, password: &str, epoch: u64) -> Result<ReleaserStatus> {
        use sivault_releaser::{
            administration::Service, journal::platform::PlatformMarker, slot_store,
        };
        let marker_dir = data.join("releaser-marker-locks");
        std::fs::create_dir_all(&marker_dir).map_err(|_| unavailable())?;
        let marker = PlatformMarker::new(&marker_dir).map_err(|_| unavailable())?;
        let slot_path = data.join("releaser-slot");
        let (material, service) =
            slot_store::open(&slot_path, marker, password).map_err(|_| unavailable())?;
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
        let mut service = Service::new(service, material.release, material.owner_key);
        let mut state = self.0.lock().map_err(|_| unavailable())?;
        if state.exiting || state.epoch != epoch || state.listener.is_some() {
            return Err(unavailable());
        }
        let (address, worker) = listen(Some(material.port), move |mut stream| {
            if stream.write_all(&advertised).is_ok()
                && let Ok(reader) = stream.try_clone()
                && let Ok(mut session) = Session::accept(reader, &mut stream, &network, &identity)
                && let Ok((kind, payload)) = session.receive_message()
                && let Ok(now) = unix_now()
            {
                let _ = service.serve(session, kind, &payload, &identity, &slot_path, now);
            }
        })?;
        state.listener = Some(Listening {
            address,
            identifier,
            worker,
            enrolled: Arc::new(AtomicBool::new(true)),
            authorization: None,
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
        enrolled: listening(state)
            .is_some_and(|listener| listener.enrolled.load(Ordering::Acquire)),
    }
}

fn invalid_peer() -> BridgeError {
    BridgeError::new(
        "RELEASER_INVALID_PEER",
        "Enter a releaser identifier and a supported IPv4 address.",
    )
}

pub(crate) struct LocalPeer {
    pub(crate) address: SocketAddrV4,
    pub(crate) identifier: [u8; 32],
}

impl LocalPeer {
    pub(crate) fn parse(address: &str, identifier: &str) -> Result<Self> {
        let address: SocketAddrV4 = address.trim().parse().map_err(|_| invalid_peer())?;
        let identifier = parse_identifier(identifier)?;
        if !safe_endpoint(address) {
            return Err(invalid_peer());
        }
        Ok(Self {
            address,
            identifier,
        })
    }

    pub(crate) fn connect(
        &self,
        folder: [u8; 32],
    ) -> Result<(Session<TcpStream, TcpStream>, ReleaserPins)> {
        if !safe_endpoint(self.address) {
            return Err(invalid_peer());
        }
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
        let pending = PendingClient::start(pins.clone(), &LOOPBACK_DEPLOYMENT, folder)
            .map_err(|_| unavailable())?;
        let reader = stream.try_clone().map_err(|_| unavailable())?;
        Session::connect(reader, stream, pending)
            .map(|session| (session, pins))
            .map_err(|_| {
                BridgeError::new(
                    "RELEASER_IDENTITY",
                    "The address did not prove the expected releaser identity.",
                )
            })
    }
}

fn parse_identifier(identifier: &str) -> Result<[u8; 32]> {
    let value = identifier.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_peer());
    }
    let mut identifier = [0; 32];
    for (byte, pair) in identifier
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0)
    {
        let hex = std::str::from_utf8(pair).map_err(|_| invalid_peer())?;
        *byte = u8::from_str_radix(hex, 16).map_err(|_| invalid_peer())?;
    }
    Ok(identifier)
}

pub(crate) fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| unavailable())
}

fn unavailable() -> BridgeError {
    BridgeError::new("RELEASER_UNAVAILABLE", "The local releaser is unavailable.")
}

#[tauri::command]
pub fn releaser_status(state: State<'_, ReleaserState>) -> Result<ReleaserStatus> {
    let state = state.0.lock().map_err(|_| unavailable())?;
    Ok(status(&state))
}

#[cfg(any(target_os = "macos", windows))]
#[tauri::command]
pub async fn releaser_authorize(app: AppHandle, owner: String, allowance: u64) -> Result<bool> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    tauri::async_runtime::spawn_blocking(move || {
        let expected = parse_identifier(&owner)?;
        if expected == [0; 32] || !(1..=1000).contains(&allowance) {
            return Err(invalid_peer());
        }
        let state = app.state::<ReleaserState>();
        let (epoch, pending) = {
            let lifecycle = state.0.lock().map_err(|_| unavailable())?;
            let listener = listening(&lifecycle).ok_or_else(unavailable)?;
            let pending = listener
                .authorization
                .as_ref()
                .cloned()
                .ok_or_else(unavailable)?;
            if listener.enrolled.load(Ordering::Acquire) {
                return Err(unavailable());
            }
            (lifecycle.epoch, pending)
        };
        if !app
            .dialog()
            .message(crate::locale::enrollment_approval(owner.trim(), allowance))
            .title(crate::locale::APPROVE_ENROLLMENT)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show()
        {
            return Ok(false);
        }
        let Some(password) = crate::password::set_releaser_storage_password(&app)? else {
            return Ok(false);
        };
        let lifecycle = state.0.lock().map_err(|_| unavailable())?;
        if lifecycle.exiting
            || lifecycle.epoch != epoch
            || listening(&lifecycle)
                .is_none_or(|listener| listener.enrolled.load(Ordering::Acquire))
        {
            return Err(unavailable());
        }
        let until = std::time::Instant::now() + Duration::from_secs(120);
        *pending.lock().map_err(|_| unavailable())? = Some(Authorization {
            owner: expected,
            allowance,
            until,
            password,
        });
        let weak = Arc::downgrade(&pending);
        tauri::async_runtime::spawn(async move {
            tokio_sleep(until).await;
            if let Some(pending) = weak.upgrade()
                && let Ok(mut entry) = pending.lock()
                && entry.as_ref().is_some_and(|entry| entry.until == until)
            {
                *entry = None;
            }
        });
        Ok(true)
    })
    .await
    .map_err(|_| unavailable())?
}

#[cfg(not(any(target_os = "macos", windows)))]
#[tauri::command]
pub fn releaser_authorize(_owner: String, _allowance: u64) -> Result<bool> {
    Err(unavailable())
}

#[cfg(any(target_os = "macos", windows))]
async fn tokio_sleep(until: std::time::Instant) {
    // The expiry check during enrollment remains authoritative.
    let _ = tauri::async_runtime::spawn_blocking(move || {
        std::thread::sleep(until.saturating_duration_since(std::time::Instant::now()));
    })
    .await;
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
                state.start_enrollment(data, epoch)
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
        assert!(LocalPeer::parse("192.0.2.3:31337", &identifier).is_err());
        assert_eq!(
            LocalPeer::parse("100.127.255.254:31337", &identifier).is_ok(),
            cfg!(all(feature = "desktop-e2e", debug_assertions))
        );
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
