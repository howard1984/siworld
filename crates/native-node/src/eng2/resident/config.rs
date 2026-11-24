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
    #[cfg(any(unix, test))]
    pub checkpoint_worker_budget_bytes: Option<usize>,
    pub listen: Option<SocketAddr>,
    pub mining: bool,
    pub pow_search_threads: Option<usize>,
    pub peers: Vec<Destination>,
    pub fixed_relay_peers: BTreeSet<Hash>,
    pub service_relay_peers: BTreeSet<Hash>,
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
fn fixed_relay_role(entry: &Value, local: p2p::Role, streaming: bool) -> Result<bool, String> {
    match entry.get("fixed_relay_role") {
        None => Ok(false),
        Some(Value::String(role))
            if (local == p2p::Role::Miner && role == "service")
                || (matches!(local, p2p::Role::Bootstrap | p2p::Role::Validator)
                    && (role == "miner" || streaming && role == "service")) =>
        {
            Ok(true)
        }
        _ => Err("fixed relay role is not permitted by the local role and genesis profile".into()),
    }
}
fn require_three_direct_push_targets(
    option: Option<&Value>,
    mining: bool,
    streaming: bool,
    selected: usize,
    dialable: usize,
    dialable_total: usize,
) -> Result<(), String> {
    match option {
        None | Some(Value::Bool(false)) => Ok(()),
        Some(Value::Bool(true))
            if mining && streaming && selected == 3 && dialable == 3
                && dialable_total <= peers::MAX_WORKERS => Ok(()),
        Some(Value::Bool(true)) => Err(
            "three direct push targets require streaming mining, exactly three dialable pinned services and capacity for every configured dial".into(),
        ),
        Some(_) => Err("require_three_direct_push_targets requires a boolean".into()),
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
/// A separate explicit bound is supported by the Unix checkpoint worker.
/// Unchanged configurations use the existing shared budget.
fn checkpoint_worker_budget(
    value: Option<&Value>,
    supported: bool,
) -> Result<Option<usize>, String> {
    match (value, supported) {
        (None, _) => Ok(None),
        (Some(value), true) => value
            .as_u64()
            .and_then(|bytes| usize::try_from(bytes).ok())
            .filter(|bytes| *bytes > 0)
            .map(Some)
            .ok_or_else(|| "checkpoint worker budget must be positive bytes".into()),
        (Some(_), false) => Err("checkpoint worker budget is unavailable on this platform".into()),
    }
}
const MAX_POW_SEARCH_THREADS: usize = 256;

fn pow_search_threads(
    value: Option<&Value>,
    mining: bool,
    available: usize,
) -> Result<Option<usize>, String> {
    match (value, mining) {
        (None, false) => Ok(None),
        (None, true) => Ok(Some(
            available.saturating_sub(2).clamp(1, MAX_POW_SEARCH_THREADS),
        )),
        (Some(value), true) => value
            .as_u64()
            .and_then(|threads| usize::try_from(threads).ok())
            .filter(|threads| (1..=MAX_POW_SEARCH_THREADS).contains(threads))
            .map(Some)
            .ok_or_else(|| "PoW search threads must be an integer from 1 through 256".into()),
        (Some(_), false) => Err("PoW search threads require enabled mining".into()),
    }
}

impl Configuration {
    pub(super) fn outbound_peers(&self) -> impl Iterator<Item = &Destination> {
        // A long general peer list must not occupy all of a miner's bounded
        // connection workers ahead of its explicit direct-push service routes.
        let primary = |peer: &Destination| {
            self.role == p2p::Role::Miner
                && self
                    .fixed_relay_peers
                    .contains(&peer.expected.fingerprint())
        };
        self.peers
            .iter()
            .filter(move |peer| peer.dial && primary(peer))
            .chain(
                self.peers
                    .iter()
                    .filter(move |peer| peer.dial && !primary(peer)),
            )
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
                + usize::from(object.contains_key("checkpoint_worker_budget_bytes"))
                + usize::from(object.contains_key("pow_search_threads"))
                + usize::from(object.contains_key("require_three_direct_push_targets"))
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
        let pow_search_threads = pow_search_threads(
            object.get("pow_search_threads"),
            mining,
            std::thread::available_parallelism().map_or(1, usize::from),
        )?;
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
        let mut service_relay_peers = BTreeSet::new();
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
            let fixed_relay = fixed_relay_role(
                entry,
                role,
                crate::eng2::transport::propagation_profile(genesis),
            )?;
            let passive_fixed_miner = !dial
                && fixed_relay
                && entry["fixed_relay_role"] == "miner"
                && matches!(role, p2p::Role::Bootstrap | p2p::Role::Validator);
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
                if entry["fixed_relay_role"] == "service"
                    && matches!(role, p2p::Role::Bootstrap | p2p::Role::Validator)
                {
                    service_relay_peers.insert(fingerprint);
                }
            }
            peers.push(Destination {
                endpoint,
                dial,
                checkpoint_reference,
                expected,
            });
        }
        require_three_direct_push_targets(
            object.get("require_three_direct_push_targets"),
            mining,
            crate::eng2::transport::propagation_profile(genesis),
            fixed_relay_peers.len(),
            peers
                .iter()
                .filter(|peer| {
                    peer.dial && fixed_relay_peers.contains(&peer.expected.fingerprint())
                })
                .count(),
            peers.iter().filter(|peer| peer.dial).count(),
        )?;
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
        let worker_budget =
            checkpoint_worker_budget(object.get("checkpoint_worker_budget_bytes"), cfg!(unix))?;
        #[cfg(not(any(unix, test)))]
        let _ = worker_budget;
        Ok(Self {
            role,
            proof_retention,
            #[cfg(any(unix, test))]
            checkpoint_worker_budget_bytes: worker_budget,
            listen,
            mining,
            pow_search_threads,
            peers,
            checkpoint_key,
            fixed_relay_peers,
            service_relay_peers,
            legacy_checkpoint_peers,
            digest: crate::local::hex(&Sha256::digest(&bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mining_workers_default_to_effective_parallelism_minus_one_and_validate_overrides() {
        assert_eq!(pow_search_threads(None, true, 1).unwrap(), Some(1));
        assert_eq!(pow_search_threads(None, true, 2).unwrap(), Some(1));
        assert_eq!(pow_search_threads(None, true, 3).unwrap(), Some(1));
        assert_eq!(pow_search_threads(None, true, 16).unwrap(), Some(14));
        assert_eq!(pow_search_threads(None, true, 512).unwrap(), Some(256));
        assert_eq!(pow_search_threads(None, false, 16).unwrap(), None);
        assert_eq!(
            pow_search_threads(Some(&json!(2)), true, 16).unwrap(),
            Some(2)
        );
        assert!(pow_search_threads(Some(&json!(1)), false, 16).is_err());
        for value in [json!(0), json!(257), json!(1.2), json!("4"), Value::Null] {
            assert!(pow_search_threads(Some(&value), true, 16).is_err());
        }
    }

    #[test]
    fn direct_push_gate_requires_three_dialable_streaming_targets() {
        let enabled = Value::Bool(true);
        assert!(require_three_direct_push_targets(Some(&enabled), true, true, 3, 3, 8).is_ok());
        assert!(require_three_direct_push_targets(None, false, false, 0, 0, 0).is_ok());
        for (mining, streaming, selected, dialable, dialable_total) in [
            (true, true, 2, 2, 8),
            (true, true, 3, 2, 8),
            (true, true, 4, 4, 8),
            (true, true, 3, 3, 9),
            (true, false, 3, 3, 8),
            (false, true, 3, 3, 8),
        ] {
            assert!(
                require_three_direct_push_targets(
                    Some(&enabled),
                    mining,
                    streaming,
                    selected,
                    dialable,
                    dialable_total,
                )
                .is_err()
            );
        }
        assert!(
            require_three_direct_push_targets(Some(&Value::Null), true, true, 3, 3, 8).is_err()
        );
    }

    #[test]
    fn checkpoint_worker_budget_requires_positive_bytes_and_platform_support() {
        assert_eq!(checkpoint_worker_budget(None, true).unwrap(), None);
        assert_eq!(checkpoint_worker_budget(None, false).unwrap(), None);
        assert!(checkpoint_worker_budget(Some(&json!(0)), true).is_err());
        assert!(checkpoint_worker_budget(Some(&json!(-1)), true).is_err());
        assert!(checkpoint_worker_budget(Some(&Value::Null), true).is_err());
        assert!(checkpoint_worker_budget(Some(&json!(128)), false).is_err());
        assert_eq!(
            checkpoint_worker_budget(Some(&json!(128)), true).unwrap(),
            Some(128)
        );
    }

    #[test]
    fn relay_roles_are_explicit_opposite_roles_and_unknown_values_fail_closed() {
        assert!(!fixed_relay_role(&json!({}), p2p::Role::Miner, false).unwrap());
        assert!(
            fixed_relay_role(
                &json!({"fixed_relay_role":"service"}),
                p2p::Role::Miner,
                false
            )
            .unwrap()
        );
        assert!(
            fixed_relay_role(
                &json!({"fixed_relay_role":"miner"}),
                p2p::Role::Validator,
                false
            )
            .unwrap()
        );
        for value in [Value::Null, json!(true), json!("validator"), json!("miner")] {
            assert!(
                fixed_relay_role(&json!({"fixed_relay_role":value}), p2p::Role::Miner, false)
                    .is_err()
            );
        }
        assert!(
            fixed_relay_role(
                &json!({"fixed_relay_role":"miner"}),
                p2p::Role::Wallet,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn service_forwarding_requires_the_distinct_genesis_profile() {
        for local in [p2p::Role::Bootstrap, p2p::Role::Validator] {
            let entry = json!({"fixed_relay_role": "service"});
            assert!(fixed_relay_role(&entry, local, false).is_err());
            assert!(fixed_relay_role(&entry, local, true).unwrap());
        }
        assert!(
            fixed_relay_role(
                &json!({"fixed_relay_role":"service"}),
                p2p::Role::Wallet,
                true
            )
            .is_err()
        );
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
