use std::{net::SocketAddr, sync::Mutex};

use serde::Serialize;
use sivault_core::controlled_channel::{ReleaserIdentity, stream::Session};
use sivault_releaser::transport::Worker;
use tauri::State;

use crate::adapter::{BridgeError, Result};

const LOOPBACK_DEPLOYMENT: [u8; 32] = *b"sivault/local-controlled-safe/v1";

struct Listening {
    address: SocketAddr,
    worker: Worker,
}

#[derive(Default)]
struct Lifecycle {
    listener: Option<Listening>,
    exiting: bool,
}

#[derive(Default)]
pub struct ReleaserState(Mutex<Lifecycle>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaserStatus {
    address: Option<String>,
}

impl ReleaserState {
    fn set_running(&self, enabled: bool) -> Result<ReleaserStatus> {
        let mut state = self.0.lock().map_err(|_| unavailable())?;
        if enabled && state.exiting {
            return Err(unavailable());
        }
        if !enabled || address(&state).is_none() {
            // Keep the state lock until the old worker and socket are gone.
            drop(state.listener.take());
        }
        if enabled && state.listener.is_none() {
            let identity = ReleaserIdentity::generate().map_err(|_| unavailable())?;
            let (address, worker) = Worker::loopback(move |mut stream| {
                if let Ok(reader) = stream.try_clone() {
                    // No slot has been enrolled in this process. Do not accept
                    // requests or issue any reply that appears to approve one.
                    let _ = Session::accept(reader, &mut stream, &LOOPBACK_DEPLOYMENT, &identity);
                }
            })
            .map_err(|_| unavailable())?;
            state.listener = Some(Listening { address, worker });
        }
        Ok(ReleaserStatus {
            address: address(&state).map(|addr| addr.to_string()),
        })
    }

    pub fn stop(&self, exiting: bool) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.exiting |= exiting;
        drop(state.listener.take());
    }
}

fn address(state: &Lifecycle) -> Option<SocketAddr> {
    state
        .listener
        .as_ref()
        .filter(|listener| listener.worker.is_running())
        .map(|listener| listener.address)
}

fn unavailable() -> BridgeError {
    BridgeError::new("RELEASER_UNAVAILABLE", "The local releaser is unavailable.")
}

#[tauri::command]
pub fn releaser_status(state: State<'_, ReleaserState>) -> Result<ReleaserStatus> {
    let state = state.0.lock().map_err(|_| unavailable())?;
    Ok(ReleaserStatus {
        address: address(&state).map(|addr| addr.to_string()),
    })
}

#[tauri::command]
pub fn releaser_set_running(
    state: State<'_, ReleaserState>,
    enabled: bool,
) -> Result<ReleaserStatus> {
    state.set_running(enabled)
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
}
