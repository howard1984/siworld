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
    pub checkpoint_reference: bool,
    pub expected: ExpectedPeer,
}
pub(super) struct Configuration {
    pub role: p2p::Role,
    pub proof_retention: Option<super::super::proof_retention::Policy>,
    pub listen: Option<SocketAddr>,
    pub mining: bool,
    pub peers: Vec<Destination>,
    pub fixed_relay_peers: BTreeSet<Hash>,
    pub checkpoint_key: Option<PathBuf>,
    pub legacy_checkpoint_peers: BTreeSet<Hash>,
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
fn fixed_relay_role(entry: &Value, local: p2p::Role) -> Result<bool, String> {
    match entry.get("fixed_relay_role") {
        None => Ok(false),
        Some(Value::String(role))
            if (local == p2p::Role::Miner && role == "service")
                || (matches!(local, p2p::Role::Bootstrap | p2p::Role::Validator)
                    && role == "miner") =>
        {
            Ok(true)
        }
        _ => Err("fixed relay requires an explicitly pinned opposite miner or service role".into()),
    }
}
fn checkpoint_reference(entry: &Value) -> Result<bool, String> {
    match entry.get("checkpoint_reference") {
        None => Ok(true),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "peer checkpoint reference selection requires a boolean".into()),
    }
}
impl Configuration {
    pub(super) fn outbound_peers(&self) -> impl Iterator<Item = &Destination> {
        self.peers.iter().filter(|peer| peer.dial)
    }

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
        if object.len()
            != 7 + usize::from(object.contains_key("legacy_checkpoint_peers"))
                + usize::from(object.contains_key("proof_retention"))
            || value["version"] != 2
            || value["engineering"] != true
        {
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
        let mut fixed_relay_peers = BTreeSet::new();
        for entry in entries {
            let object = entry.as_object().ok_or("invalid resident peer entry")?;
            if object.len()
                != 4 + usize::from(object.contains_key("checkpoint_reference"))
                    + usize::from(object.contains_key("fixed_relay_role"))
            {
                return Err(
                    "resident peer requires endpoint, dial, fingerprint and descriptor with optional checkpoint_reference".into(),
                );
            }
            let endpoint: SocketAddr = entry["endpoint"]
                .as_str()
                .ok_or("missing peer endpoint")?
                .parse()
                .map_err(|_| "invalid peer endpoint")?;
            let dial = entry["dial"]
                .as_bool()
                .ok_or("explicit peer dial selection required")?;
            let checkpoint_reference = checkpoint_reference(entry)?;
            let fixed_relay = fixed_relay_role(entry, role)?;
            let passive_fixed_miner =
                !dial && fixed_relay && matches!(role, p2p::Role::Bootstrap | p2p::Role::Validator);
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || (!passive_fixed_miner && !endpoints.insert(endpoint))
            {
                return Err("invalid or duplicate peer endpoint".into());
            }
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
            if fixed_relay {
                fixed_relay_peers.insert(fingerprint);
            }
            peers.push(Destination {
                endpoint,
                dial,
                checkpoint_reference,
                expected,
            });
        }
        let mut legacy_checkpoint_peers = BTreeSet::new();
        if let Some(entries) = object.get("legacy_checkpoint_peers") {
            let entries = entries
                .as_array()
                .ok_or("legacy checkpoint peers require an array")?;
            if entries.len() > 16 {
                return Err("legacy checkpoint peer limit".into());
            }
            // This set only suppresses incompatible advertisements after peer
            // authentication. Configured destinations still require PeerPins.
            for entry in entries {
                let fingerprint = unhex::<32>(entry)?;
                if fingerprint == local || !legacy_checkpoint_peers.insert(fingerprint) {
                    return Err("duplicate or local legacy checkpoint peer".into());
                }
            }
        }
        let proof_retention =
            super::super::proof_retention::configured(object.get("proof_retention"), role)?;
        Ok(Self {
            role,
            proof_retention,
            listen,
            mining,
            peers,
            checkpoint_key,
            fixed_relay_peers,
            legacy_checkpoint_peers,
            digest: crate::local::hex(&Sha256::digest(&bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_roles_are_explicit_opposite_roles_and_unknown_values_fail_closed() {
        assert!(!fixed_relay_role(&json!({}), p2p::Role::Miner).unwrap());
        assert!(
            fixed_relay_role(&json!({"fixed_relay_role":"service"}), p2p::Role::Miner).unwrap()
        );
        assert!(
            fixed_relay_role(&json!({"fixed_relay_role":"miner"}), p2p::Role::Validator).unwrap()
        );
        for value in [Value::Null, json!(true), json!("validator"), json!("miner")] {
            assert!(
                fixed_relay_role(&json!({"fixed_relay_role":value}), p2p::Role::Miner).is_err()
            );
        }
        assert!(fixed_relay_role(&json!({"fixed_relay_role":"miner"}), p2p::Role::Wallet).is_err());
    }
    #[test]
    fn checkpoint_reference_selection_preserves_existing_peers_and_rejects_ambiguous_values() {
        assert!(checkpoint_reference(&json!({})).unwrap());
        assert!(checkpoint_reference(&json!({"checkpoint_reference": true})).unwrap());
        assert!(!checkpoint_reference(&json!({"checkpoint_reference": false})).unwrap());
        for value in [Value::Null, json!(0), json!("false"), json!([])] {
            assert!(checkpoint_reference(&json!({"checkpoint_reference": value})).is_err());
        }
    }
}
