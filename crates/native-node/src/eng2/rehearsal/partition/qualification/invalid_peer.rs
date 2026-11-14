//! One bounded owner-operated raw-frame sender over real pinned authentication.
//!
//! Input classification is declared by the owner. A sent frame or a closed
//! connection does not prove native rejection or unchanged receiver state.
use super::Context;
use crate::{
    eng2::{
        connector::Connector,
        execution::Engine,
        genesis::Genesis,
        header::{HEADER_BYTES, Header},
    },
    identity::{Descriptor, NativeIdentity, PeerPin},
    p2p::{self, Budget, Cancellation, ExpectedPeer, Role},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::Read,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub mod branch;

const MAX_PLAN: usize = 16 * 1024;
const MAX_REQUESTS: usize = 4;
const PHASE: Duration = Duration::from_secs(180);
// Existing eng2 application wire version; the normal receiver remains intact.
const GET_HEADER: u8 = 2;
const HEADER: u8 = 3;
const GET_BODY: u8 = 4;
const BODY_START: u8 = 5;
const BODY_CHUNK: u8 = 6;
const ROUND_DONE: u8 = 9;
const GET_TIP: u8 = 8;
const TIP: u8 = 1;
const CHUNK: usize = p2p::MAX_CONTROL_BYTES - 9;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputKind {
    ValidControl,
    NegativeInput,
}
impl InputKind {
    fn name(&self) -> &'static str {
        match self {
            Self::ValidControl => "valid_control",
            Self::NegativeInput => "negative_input",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    endpoint: String,
    receiver_descriptor: String,
    receiver_fingerprint: String,
    receiver_role: String,
    receiver_height: u64,
    receiver_tip: String,
    local_fingerprint: String,
    frame: String,
    frame_sha256: String,
    input_kind: InputKind,
}
fn hash(text: &str) -> Result<[u8; 32], String> {
    crate::eng2::genesis_tool::parse_hash(text).map_err(String::from)
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, false, bound)?
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "qualification public input read failed")?;
    if bytes.len() > bound {
        return Err("qualification public input byte bound".into());
    }
    Ok(bytes)
}
fn parse(bytes: &[u8]) -> Result<Plan, String> {
    let plan: Plan =
        serde_json::from_slice(bytes).map_err(|_| "invalid-peer plan schema rejected")?;
    if plan.version != 1
        || plan.endpoint.len() > 128
        || plan.receiver_descriptor.len() > 2048
        || plan.frame.len() > 2048
        || !matches!(plan.receiver_role.as_str(), "bootstrap" | "validator")
        || [
            plan.receiver_fingerprint.as_str(),
            plan.receiver_tip.as_str(),
            plan.local_fingerprint.as_str(),
            plan.frame_sha256.as_str(),
        ]
        .into_iter()
        .any(|v| hash(v).is_err())
        || plan.receiver_fingerprint == plan.local_fingerprint
        || plan.receiver_height == u64::MAX
    {
        return Err("invalid-peer plan context rejected".into());
    }
    let endpoint: SocketAddr = plan
        .endpoint
        .parse()
        .map_err(|_| "invalid-peer endpoint rejected")?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err("invalid-peer endpoint rejected".into());
    }
    Ok(plan)
}

/// Use an existing stopped local identity and an independently installed peer
/// pin. This function creates neither an identity, peer pin nor a listener.
/// The owner must separately bind the target run and collect rejection/state
/// evidence. No invocation grants G1/G2 acceptance or proves an input invalid.
pub fn send(
    directory: &Path,
    plan_path: &Path,
    plan_pin: &str,
    binding: &Path,
    binding_pin: &str,
) -> Result<Value, String> {
    let context = Context::load(binding, binding_pin)?;
    if directory.canonicalize().ok().as_deref() != Some(directory) {
        return Err("invalid-peer identity directory must be canonical".into());
    }
    let bytes = read(plan_path, MAX_PLAN)?;
    context.check_manifest_pin(&bytes, plan_pin)?;
    let plan = parse(&bytes)?;
    let _lease = crate::service::Lease::acquire(directory)?;
    let genesis = Arc::new(Genesis::decode(&read(
        &directory.join("genesis.bin"),
        1024 * 1024,
    )?)?);
    context.check_genesis(&genesis)?;
    let identity = Arc::new(
        NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing invalid-peer identity unavailable")?,
    );
    let local = identity
        .descriptor()
        .map_err(|_| "invalid-peer local descriptor unavailable")?;
    if crate::local::hex(&local.fingerprint()) != plan.local_fingerprint {
        return Err("invalid-peer local identity differs".into());
    }
    let receiver_bytes: [u8; crate::identity::DESCRIPTOR_BYTES] = read(
        Path::new(&plan.receiver_descriptor),
        crate::identity::DESCRIPTOR_BYTES,
    )?
    .try_into()
    .map_err(|_| "invalid-peer receiver descriptor width differs")?;
    let descriptor = Descriptor::decode(&receiver_bytes, &genesis.peer_binding())
        .map_err(|_| "invalid-peer receiver descriptor rejected")?;
    let receiver = hash(&plan.receiver_fingerprint)?;
    if descriptor.fingerprint() != receiver {
        return Err("invalid-peer receiver identity differs".into());
    }
    let pin = PeerPin::load(directory, receiver, &genesis.peer_binding())
        .map_err(|_| "independently installed receiver pin required")?;
    let expected = ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin)
        .map_err(|_| "invalid-peer receiver pin differs")?;
    let limits = crate::eng2::state_components::Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let engine = Engine::new(Genesis::decode(&genesis.encode()?)?, limits)?;
    let policy = engine.body_policy();
    let frame_bound = HEADER_BYTES
        .checked_add(policy.max_body_bytes)
        .ok_or("invalid-peer frame bound overflow")?;
    let budget = Budget::new(p2p::CONNECTION_BYTES);
    let input = crate::local::regular_read(Path::new(&plan.frame), false, frame_bound)?;
    let length = usize::try_from(
        input
            .metadata()
            .map_err(|_| "invalid-peer frame metadata unavailable")?
            .len(),
    )
    .map_err(|_| "invalid-peer frame length overflow")?;
    if length <= HEADER_BYTES || length > frame_bound {
        return Err("invalid-peer complete frame length exceeds bound".into());
    }
    let read_length = length
        .checked_add(1)
        .ok_or("invalid-peer frame sentinel length overflow")?;
    let _frame_charge = budget
        .reserve(
            read_length
                .checked_mul(4)
                .and_then(|v| v.checked_add(65536))
                .ok_or("invalid-peer frame charge overflow")?,
        )
        .map_err(|_| "invalid-peer frame budget unavailable")?;
    let mut input = input;
    let frame = read_frame_bytes(&mut input, length)?;
    context.check_manifest_pin(&frame, &plan.frame_sha256)?;
    if frame.len() <= HEADER_BYTES {
        return Err("invalid-peer complete input frame required".into());
    }
    let header = Header::decode(&frame[..HEADER_BYTES], &genesis.config().network)
        .map_err(|_| "invalid-peer sender requires a syntactically canonical native header")?;
    let receiver_tip = hash(&plan.receiver_tip)?;
    if header.height != plan.receiver_height + 1 || header.parent != receiver_tip {
        return Err("invalid-peer frame must extend the explicitly pinned receiver head".into());
    }
    let id = header
        .id()
        .map_err(|_| "invalid-peer header identity rejected")?;
    let connector = Connector::new(genesis, identity, vec![expected], budget, policy)
        .map_err(|_| "invalid-peer connector rejected")?;
    let began = Instant::now();
    let endpoint: SocketAddr = plan
        .endpoint
        .parse()
        .map_err(|_| "invalid-peer endpoint rejected")?;
    let mut peer = connector
        .connect(endpoint, receiver, Role::Miner, Cancellation::default())
        .map_err(|error| format!("invalid-peer authenticated connection failed: {error:?}"))?;
    let expected_role = if plan.receiver_role == "validator" {
        Role::Validator
    } else {
        Role::Bootstrap
    };
    if peer.peer() != receiver || peer.role() != expected_role {
        return Err("invalid-peer authenticated receiver role differs".into());
    }
    let remaining = PHASE
        .checked_sub(began.elapsed())
        .ok_or("invalid-peer phase deadline")?;
    let deadline = p2p::Deadline::new(remaining);
    peer.send_application_before(1, &[GET_TIP], &deadline)
        .map_err(|error| format!("invalid-peer baseline query failed: {error:?}"))?;
    let (request, tip, _tip_charge) = peer
        .receive_application_before(&deadline, 41)
        .map_err(|error| format!("invalid-peer baseline exchange failed: {error:?}"))?;
    if request != 1
        || tip.len() != 41
        || tip[0] != TIP
        || u64::from_le_bytes(tip[1..9].try_into().expect("checked tip width"))
            != plan.receiver_height
        || tip[9..] != receiver_tip
    {
        return Err("invalid-peer receiver moved from the pinned baseline".into());
    }
    let mut notice = [0; 41];
    notice[0] = TIP;
    notice[1..9].copy_from_slice(&header.height.to_le_bytes());
    notice[9..].copy_from_slice(&id);
    peer.send_application_before(2, &notice, &deadline)
        .map_err(|error| format!("invalid-peer notice failed: {error:?}"))?;
    let mut header_sent = false;
    let mut body_sent = false;
    let mut outcome = "request_limit";
    let mut messages = 0;
    for _ in 0..MAX_REQUESTS {
        let (request, message, _charge) = match peer.receive_application_before(&deadline, 1024) {
            Ok(value) => value,
            Err(error) => {
                if !header_sent {
                    return Err(format!(
                        "invalid-peer input header not requested: {error:?}"
                    ));
                }
                outcome = match error {
                    p2p::Error::Unavailable => "connection_unavailable_after_input",
                    p2p::Error::InvalidProtocol => "protocol_error_after_input",
                    _ => "transport_resource_error_after_input",
                };
                break;
            }
        };
        messages += 1;
        if message == [ROUND_DONE] && request == 2 {
            outcome = "round_completed";
            break;
        }
        if message.len() == 9
            && message[0] == GET_HEADER
            && !header_sent
            && u64::from_le_bytes(message[1..].try_into().expect("fixed query height"))
                == header.height
        {
            let mut encoded_header = [0; 1 + HEADER_BYTES];
            encoded_header[0] = HEADER;
            encoded_header[1..].copy_from_slice(
                &header
                    .encode()
                    .map_err(|_| "invalid-peer response header rejected")?,
            );
            peer.send_application_before(request, &encoded_header, &deadline)
                .map_err(|error| format!("invalid-peer header write failed: {error:?}"))?;
            header_sent = true;
        } else if message.len() == 41
            && message[0] == GET_BODY
            && header_sent
            && !body_sent
            && u64::from_le_bytes(message[1..9].try_into().expect("fixed query height"))
                == header.height
            && message[9..] == id
        {
            let body = &frame[HEADER_BYTES..];
            let mut start = [0u8; 49];
            start[0] = BODY_START;
            start[1..9].copy_from_slice(&header.height.to_le_bytes());
            start[9..41].copy_from_slice(&id);
            start[41..].copy_from_slice(&(body.len() as u64).to_le_bytes());
            peer.send_application_before(request, &start, &deadline)
                .map_err(|error| format!("invalid-peer body start failed: {error:?}"))?;
            for (index, part) in body.chunks(CHUNK).enumerate() {
                let mut chunk = Vec::with_capacity(9 + part.len());
                chunk.push(BODY_CHUNK);
                chunk.extend_from_slice(&((index * CHUNK) as u64).to_le_bytes());
                chunk.extend_from_slice(part);
                peer.send_application_before(request, &chunk, &deadline)
                    .map_err(|error| format!("invalid-peer body write failed: {error:?}"))?;
            }
            body_sent = true;
        } else {
            return Err("invalid-peer receiver request outside the single-frame exchange".into());
        }
    }
    Ok(
        json!({"version":1,"scope":"owner-authenticated-native-input-submission",
        "qualification":context.receipt(),"plan_sha256":plan_pin,
        "local_fingerprint":plan.local_fingerprint,"receiver_fingerprint":plan.receiver_fingerprint,
        "receiver_role":plan.receiver_role,"receiver_baseline_height":plan.receiver_height,
        "receiver_baseline_tip":plan.receiver_tip,"frame_sha256":plan.frame_sha256,
        "frame_bytes":frame.len(),"height":header.height,"id":crate::local::hex(&id),
        "declared_input_kind":plan.input_kind.name(),"input_invalidity_verified":false,
        "real_pinned_authentication":true,"header_sent":header_sent,"body_sent":body_sent,
        "messages":messages,"exchange_outcome":outcome,"elapsed_ms":began.elapsed().as_millis().to_string(),
        "receiver_rejection_proven":false,"receiver_unchanged_state_proven":false,
        "proofs_generated":false,"mining_started":false,"listeners_started":false,
        "identities_created":false,"g1_passed":false,"g2_passed":false}),
    )
}

/// The caller reserves the metadata length plus one sentinel before this call.
/// Fixed slices bound actual reads and prevent allocator growth on input growth.
fn read_frame_bytes(input: &mut impl Read, length: usize) -> Result<Vec<u8>, String> {
    let read_length = length
        .checked_add(1)
        .ok_or("invalid-peer frame sentinel overflow")?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(read_length)
        .map_err(|_| "invalid-peer frame allocation unavailable")?;
    frame.resize(read_length, 0);
    let mut filled = 0;
    while filled < read_length {
        let count = input
            .read(&mut frame[filled..])
            .map_err(|_| "invalid-peer frame read failed")?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    frame.truncate(filled);
    if frame.len() != length {
        return Err("invalid-peer frame length changed".into());
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn growing_frame_is_read_only_through_its_charged_sentinel() {
        let mut growing = std::io::Cursor::new(vec![7; 128]);
        assert!(read_frame_bytes(&mut growing, 3).is_err());
        assert_eq!(growing.position(), 4);
        let mut exact = std::io::Cursor::new(vec![7; 3]);
        assert_eq!(read_frame_bytes(&mut exact, 3).unwrap(), vec![7; 3]);
        let mut truncated = std::io::Cursor::new(vec![7; 2]);
        assert!(read_frame_bytes(&mut truncated, 3).is_err());
    }
    #[test]
    fn invalid_peer_plan_rejects_unknown_input_kinds_unpinned_roles_and_unbounded_baseline() {
        let value = json!({"version":1,"endpoint":"127.0.0.1:40201",
            "receiver_descriptor":"receiver.bin","receiver_fingerprint":"01".repeat(32),
            "receiver_role":"validator","receiver_height":1,"receiver_tip":"02".repeat(32),
            "local_fingerprint":"03".repeat(32),"frame":"negative.frame",
            "frame_sha256":"04".repeat(32),"input_kind":"negative_input"});
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        for (field, item) in [
            ("input_kind", json!("valid")),
            ("receiver_role", json!("miner")),
            ("receiver_height", json!(u64::MAX)),
            ("endpoint", json!("0.0.0.0:40201")),
            ("secret", json!("excluded")),
        ] {
            let mut changed = value.clone();
            changed[field] = item;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
    }
}
