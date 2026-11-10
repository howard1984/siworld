//! Explicit local endpoints and independently pinned bootstrap identities.

use super::*;
use crate::{
    identity::{Descriptor, PeerPin},
    p2p::ExpectedPeer,
};
use std::{collections::BTreeSet, net::SocketAddr};

pub(super) struct Destination {
    pub endpoint: SocketAddr,
    pub dial: bool,
    pub expected: ExpectedPeer,
}
pub(super) struct Configuration {
    pub role: p2p::Role,
    pub listen: Option<SocketAddr>,
    pub mining: bool,
    pub peers: Vec<Destination>,
    pub checkpoint_key: Option<PathBuf>,
    pub digest: String,
}
fn unhex<const N: usize>(value: &Value) -> Result<[u8; N], String> {
    let text = value
        .as_str()
        .ok_or("missing hexadecimal public configuration field")?;
    if text.len() != N * 2 {
        return Err("public configuration field width differs".into());
    }
    crate::eng2_operations::public_bytes(value, N)?
        .try_into()
        .map_err(|_| "public configuration field width differs".into())
}
impl Configuration {
    pub fn load(
        directory: &Path,
        path: &Path,
        genesis: &Genesis,
        identity: &NativeIdentity,
    ) -> Result<Self, String> {
        let mut bytes = Vec::new();
        crate::local::regular_read(path, true, 1024 * 1024)?
            .read_to_end(&mut bytes)
            .map_err(|_| "resident peer configuration read failed")?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid resident peer configuration")?;
        let object = value
            .as_object()
            .ok_or("resident configuration requires an object")?;
        if object.len() != 7 || value["version"] != 2 || value["engineering"] != true {
            return Err("explicit version 2 engineering configuration required".into());
        }
        let role = match value["role"].as_str() {
            Some("bootstrap") => p2p::Role::Bootstrap,
            Some("validator") => p2p::Role::Validator,
            Some("miner") => p2p::Role::Miner,
            Some("ordinary") => p2p::Role::Wallet,
            _ => {
                return Err(
                    "explicit bootstrap, validator, miner or ordinary role required".into(),
                );
            }
        };
        let mining = value["mining"]
            .as_bool()
            .ok_or("explicit mining selection required")?;
        let listen = match value.get("listen") {
            Some(Value::Null) => None,
            Some(Value::String(text)) => {
                let endpoint: SocketAddr = text
                    .parse()
                    .map_err(|_| "invalid resident listen endpoint")?;
                if endpoint.port() == 0 || endpoint.ip().is_multicast() {
                    return Err("invalid resident listen endpoint".into());
                }
                Some(endpoint)
            }
            _ => return Err("explicit listener selection required".into()),
        };
        if (mining && role != p2p::Role::Miner) || (role == p2p::Role::Miner && listen.is_some()) {
            return Err("mining requires an outbound-only miner role".into());
        }
        let checkpoint_key = match value.get("checkpoint_key") {
            Some(Value::Null) => None,
            Some(Value::String(text)) if !text.is_empty() && text.len() <= 2048 => {
                if !matches!(
                    role,
                    p2p::Role::Bootstrap | p2p::Role::Validator | p2p::Role::Miner
                ) {
                    return Err(
                        "only an independently validating node can load an existing checkpoint key"
                            .into(),
                    );
                }
                let requested = Path::new(text);
                Some(if requested.is_absolute() {
                    requested.to_path_buf()
                } else {
                    directory.join(requested)
                })
            }
            _ => return Err("explicit checkpoint key selection required".into()),
        };
        let entries = value["peers"]
            .as_array()
            .ok_or("explicit pinned peers required")?;
        if entries.len() > 16 {
            return Err("resident pinned peer limit".into());
        }
        let local = identity
            .descriptor()
            .map_err(|_| "local descriptor unavailable")?
            .fingerprint();
        let mut fingerprints = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        let mut peers = Vec::new();
        for entry in entries {
            let object = entry.as_object().ok_or("invalid resident peer entry")?;
            if object.len() != 4 {
                return Err(
                    "resident peer requires endpoint, dial, fingerprint and descriptor".into(),
                );
            }
            let endpoint: SocketAddr = entry["endpoint"]
                .as_str()
                .ok_or("missing peer endpoint")?
                .parse()
                .map_err(|_| "invalid peer endpoint")?;
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || !endpoints.insert(endpoint)
            {
                return Err("invalid or duplicate peer endpoint".into());
            }
            let dial = entry["dial"]
                .as_bool()
                .ok_or("explicit peer dial selection required")?;
            let fingerprint = unhex::<32>(&entry["fingerprint"])?;
            if fingerprint == local || !fingerprints.insert(fingerprint) {
                return Err("duplicate or local peer fingerprint".into());
            }
            let descriptor = Descriptor::decode(
                &unhex::<{ crate::identity::DESCRIPTOR_BYTES }>(&entry["descriptor"])?,
                &genesis.peer_binding(),
            )
            .map_err(|_| "peer descriptor rejected")?;
            let pin = PeerPin::load(directory, fingerprint, &genesis.peer_binding())
                .map_err(|_| "independently checked peer pin required")?;
            let expected =
                ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin)
                    .map_err(|_| "configured peer identity differs from pin")?;
            peers.push(Destination {
                endpoint,
                dial,
                expected,
            });
        }
        Ok(Self {
            role,
            listen,
            mining,
            peers,
            checkpoint_key,
            digest: crate::local::hex(&Sha256::digest(&bytes)),
        })
    }
}
