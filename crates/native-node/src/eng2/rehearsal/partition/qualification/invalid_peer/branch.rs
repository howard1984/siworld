//! Explicit raw competing-branch submission. Supplied artifacts are never edited.
use super::*;
use crate::eng2::{checkpoint_exchange, transport::Peer};
use std::{collections::BTreeSet, io::Write};

const PLAN_BOUND: usize = 64 * 1024;
const MAX_FRAMES: usize = 64;
const MAX_ROUNDS: u16 = 16;
const MAX_MESSAGES: usize = 1024;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const EXACT_HEADER: u8 = 15;
const CAPABILITIES: u8 = 17;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    path: String,
    sha256: String,
    bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchPlan {
    version: u32,
    endpoint: String,
    receiver_descriptor: String,
    receiver_fingerprint: String,
    receiver_role: String,
    receiver_height: u64,
    receiver_tip: String,
    local_fingerprint: String,
    source_fingerprint: String,
    source_manifest: String,
    source_manifest_sha256: String,
    ancestor_height: u64,
    ancestor_id: String,
    rollback_depth: u64,
    candidate_height: u64,
    candidate_tip: String,
    frames: Vec<Frame>,
    total_frame_bytes: u64,
    maximum_transmitted_body_bytes: u64,
    maximum_rounds: u16,
    input_kind: InputKind,
}
fn parse_branch(bytes: &[u8]) -> Result<BranchPlan, String> {
    let p: BranchPlan = serde_json::from_slice(bytes).map_err(|_| "branch sender plan schema")?;
    if p.version != 1
        || p.endpoint.len() > 128
        || p.receiver_descriptor.len() > 2048
        || p.source_manifest.len() > 2048
        || !matches!(p.receiver_role.as_str(), "bootstrap" | "validator")
        || p.receiver_fingerprint == p.local_fingerprint
        || p.receiver_height == u64::MAX
        || p.receiver_height.checked_sub(p.ancestor_height) != Some(p.rollback_depth)
        || !(1..=25).contains(&p.rollback_depth)
        || p.candidate_height <= p.receiver_height
        || p.candidate_height.checked_sub(p.ancestor_height) != Some(p.frames.len() as u64)
        || p.frames.is_empty()
        || p.frames.len() > MAX_FRAMES
        || !(1..=MAX_ROUNDS).contains(&p.maximum_rounds)
        || p.total_frame_bytes == 0
        || p.total_frame_bytes > MAX_BYTES
        || p.maximum_transmitted_body_bytes == 0
        || p.maximum_transmitted_body_bytes > MAX_BYTES
        || [
            p.receiver_fingerprint.as_str(),
            p.receiver_tip.as_str(),
            p.local_fingerprint.as_str(),
            p.source_fingerprint.as_str(),
            p.source_manifest_sha256.as_str(),
            p.ancestor_id.as_str(),
            p.candidate_tip.as_str(),
        ]
        .into_iter()
        .any(|v| hash(v).is_err())
    {
        return Err("branch sender plan context".into());
    }
    let endpoint: SocketAddr = p.endpoint.parse().map_err(|_| "branch sender endpoint")?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err("branch sender endpoint".into());
    }
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for f in &p.frames {
        if f.path.is_empty()
            || f.path.len() > 2048
            || !paths.insert(&f.path)
            || f.bytes <= HEADER_BYTES as u64
            || hash(&f.sha256).is_err()
        {
            return Err("branch sender frame declaration".into());
        }
        total = total
            .checked_add(f.bytes)
            .ok_or("branch sender total overflow")?;
    }
    if total != p.total_frame_bytes {
        return Err("branch sender frame total differs".into());
    }
    Ok(p)
}
fn load_frame(
    context: &Context,
    f: &Frame,
    bound: usize,
    budget: &Budget,
) -> Result<(Vec<u8>, p2p::Reservation), String> {
    let length = usize::try_from(f.bytes).map_err(|_| "branch sender frame width")?;
    if length <= HEADER_BYTES || length > bound {
        return Err("branch sender frame bound".into());
    }
    let charge = budget
        .reserve(
            length
                .checked_add(1)
                .and_then(|n| n.checked_mul(4))
                .and_then(|n| n.checked_add(65536))
                .ok_or("branch sender frame charge overflow")?,
        )
        .map_err(|_| "branch sender frame budget")?;
    let mut input = crate::local::regular_read(Path::new(&f.path), false, bound)?;
    if input
        .metadata()
        .map_err(|_| "branch sender frame metadata")?
        .len()
        != f.bytes
    {
        return Err("branch sender frame length differs".into());
    }
    let bytes = read_frame_bytes(&mut input, length)?;
    context.check_manifest_pin(&bytes, &f.sha256)?;
    Ok((bytes, charge))
}
fn linked_headers(headers: &[Header], p: &BranchPlan) -> Result<(), String> {
    if headers.len() != p.frames.len() {
        return Err("branch sender header inventory differs".into());
    }
    let mut parent = hash(&p.ancestor_id)?;
    for (index, h) in headers.iter().enumerate() {
        if h.height != p.ancestor_height + index as u64 + 1 || h.parent != parent {
            return Err("branch sender noncontiguous new branch".into());
        }
        parent = h.id().map_err(|_| "branch sender header identity")?;
    }
    if parent != hash(&p.candidate_tip)? || parent == hash(&p.receiver_tip)? {
        return Err("branch sender candidate identity differs".into());
    }
    Ok(())
}
fn send_bytes<S: Read + Write>(
    peer: &mut Peer<S>,
    request: u64,
    bytes: &[u8],
    deadline: &p2p::Deadline,
) -> Result<(), String> {
    peer.send_application_before(request, bytes, deadline)
        .map_err(|e| format!("branch sender write: {e:?}"))
}
fn query_tip<S: Read + Write>(
    peer: &mut Peer<S>,
    request: u64,
    deadline: &p2p::Deadline,
) -> Result<(u64, [u8; 32]), String> {
    send_bytes(peer, request, &[GET_TIP], deadline)?;
    let (actual, b, _charge) = peer
        .receive_application_before(deadline, 41)
        .map_err(|e| format!("branch sender tip query: {e:?}"))?;
    if actual != request || b.len() != 41 || b[0] != TIP {
        return Err("branch sender tip framing".into());
    }
    Ok((
        u64::from_le_bytes(b[1..9].try_into().expect("fixed height")),
        b[9..].try_into().expect("fixed identity"),
    ))
}
fn query_header<S: Read + Write>(
    peer: &mut Peer<S>,
    request: u64,
    height: u64,
    network: &[u8; 32],
    deadline: &p2p::Deadline,
) -> Result<Header, String> {
    let mut query = vec![GET_HEADER];
    query.extend_from_slice(&height.to_le_bytes());
    send_bytes(peer, request, &query, deadline)?;
    let (actual, bytes, _charge) = peer
        .receive_application_before(deadline, 1 + HEADER_BYTES)
        .map_err(|e| format!("branch sender baseline header: {e:?}"))?;
    if actual != request || bytes.len() != 1 + HEADER_BYTES || bytes[0] != HEADER {
        return Err("branch sender baseline header unavailable".into());
    }
    let h = Header::decode(&bytes[1..], network)
        .map_err(|_| "branch sender baseline header encoding")?;
    if h.height != height {
        return Err("branch sender baseline header height".into());
    }
    Ok(h)
}
/// Complete an empty pending-transaction exchange without requesting packets.
/// Inventory identities are decoded and bounded; none are admitted or retained.
fn empty_transactions<S: Read + Write>(
    peer: &mut Peer<S>,
    deadline: &p2p::Deadline,
) -> Result<(), String> {
    send_bytes(peer, 0, &[0x30, 1, 0, 0], deadline)?;
    let (request, wanted, charge) = peer
        .receive_application_before(deadline, 4)
        .map_err(|e| format!("branch sender transaction request: {e:?}"))?;
    if request != 0 || wanted != [0x31, 1, 0, 0] {
        return Err("branch sender unexpected transaction request".into());
    }
    drop(wanted);
    drop(charge);
    let (request, inventory, charge) = peer
        .receive_application_before(deadline, 4 + 32 * 128)
        .map_err(|e| format!("branch sender transaction inventory: {e:?}"))?;
    if request != 0 || inventory.len() < 4 || inventory[..2] != [0x30, 1] {
        return Err("branch sender transaction inventory framing".into());
    }
    let n = u16::from_le_bytes(inventory[2..4].try_into().expect("fixed count")) as usize;
    if n > 128
        || inventory.len() != 4 + 32 * n
        || inventory[4..]
            .as_chunks::<32>()
            .0
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != n
    {
        return Err("branch sender transaction inventory bound".into());
    }
    drop(inventory);
    drop(charge);
    send_bytes(peer, 0, &[0x31, 1, 0, 0], deadline)
}

/// Serve only owner-pinned contiguous competing material over normal discovery.
/// The caller separately supplies creation provenance and receiver acceptance.
pub fn send(
    directory: &Path,
    plan_path: &Path,
    plan_pin: &str,
    binding: &Path,
    binding_pin: &str,
) -> Result<Value, String> {
    let began = Instant::now();
    let context = Context::load(binding, binding_pin)?;
    if directory.canonicalize().ok().as_deref() != Some(directory) {
        return Err("branch sender identity directory must be canonical".into());
    }
    let bytes = read(plan_path, PLAN_BOUND)?;
    context.check_manifest_pin(&bytes, plan_pin)?;
    let p = parse_branch(&bytes)?;
    let source = read(Path::new(&p.source_manifest), 1024 * 1024)?;
    context.check_manifest_pin(&source, &p.source_manifest_sha256)?;
    let _lease = crate::service::Lease::acquire(directory)?;
    let genesis = Arc::new(Genesis::decode(&read(
        &directory.join("genesis.bin"),
        1024 * 1024,
    )?)?);
    context.check_genesis(&genesis)?;
    let network = genesis.config().network;
    let identity = Arc::new(
        NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing branch sender identity unavailable")?,
    );
    if crate::local::hex(
        &identity
            .descriptor()
            .map_err(|_| "branch sender descriptor")?
            .fingerprint(),
    ) != p.local_fingerprint
    {
        return Err("branch sender local identity differs".into());
    }
    let receiver_bytes: [u8; crate::identity::DESCRIPTOR_BYTES] = read(
        Path::new(&p.receiver_descriptor),
        crate::identity::DESCRIPTOR_BYTES,
    )?
    .try_into()
    .map_err(|_| "branch sender descriptor width")?;
    let descriptor = Descriptor::decode(&receiver_bytes, &genesis.peer_binding())
        .map_err(|_| "branch sender receiver descriptor")?;
    let receiver = hash(&p.receiver_fingerprint)?;
    if descriptor.fingerprint() != receiver {
        return Err("branch sender receiver identity".into());
    }
    let pin = PeerPin::load(directory, receiver, &genesis.peer_binding())
        .map_err(|_| "branch sender requires installed receiver pin")?;
    let expected = ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin)
        .map_err(|_| "branch sender receiver pin")?;
    let engine = Engine::new(
        Genesis::decode(&genesis.encode()?)?,
        crate::eng2::state_components::Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )?;
    let policy = engine.body_policy();
    let bound = HEADER_BYTES
        .checked_add(policy.max_body_bytes)
        .ok_or("branch sender frame bound")?;
    let budget = Budget::new(p2p::CONNECTION_BYTES);
    let _metadata_charge = budget
        .reserve(8 * 1024 * 1024)
        .map_err(|_| "branch sender metadata budget")?;
    let mut headers = Vec::with_capacity(p.frames.len());
    for f in &p.frames {
        let (frame, _charge) = load_frame(&context, f, bound, &budget)?;
        headers.push(
            Header::decode(&frame[..HEADER_BYTES], &network)
                .map_err(|_| "branch sender canonical header")?,
        );
        if began.elapsed() >= PHASE {
            return Err("branch sender preflight deadline".into());
        }
    }
    linked_headers(&headers, &p)?;
    let connector = Connector::new(
        genesis.clone(),
        identity,
        vec![expected],
        budget.clone(),
        policy,
    )
    .map_err(|_| "branch sender connector")?;
    let endpoint = p.endpoint.parse().map_err(|_| "branch sender endpoint")?;
    let mut peer = connector
        .connect(endpoint, receiver, Role::Miner, Cancellation::default())
        .map_err(|e| format!("branch sender authentication: {e:?}"))?;
    let role = if p.receiver_role == "validator" {
        Role::Validator
    } else {
        Role::Bootstrap
    };
    if peer.peer() != receiver || peer.role() != role {
        return Err("branch sender receiver role".into());
    }
    let deadline = p2p::Deadline::new(
        PHASE
            .checked_sub(began.elapsed())
            .ok_or("branch sender deadline")?,
    );
    let baseline = (p.receiver_height, hash(&p.receiver_tip)?);
    if query_tip(&mut peer, 1, &deadline)? != baseline {
        return Err("branch sender receiver baseline moved".into());
    }
    if p.ancestor_height == 0 {
        if genesis.id() != hash(&p.ancestor_id)? {
            return Err("branch sender genesis ancestor differs".into());
        }
    } else {
        let h = query_header(&mut peer, 2, p.ancestor_height, &network, &deadline)?;
        if h.id().map_err(|_| "branch sender ancestor identity")? != hash(&p.ancestor_id)? {
            return Err("branch sender receiver ancestor differs".into());
        }
    }
    let receiver_next = query_header(&mut peer, 3, p.ancestor_height + 1, &network, &deadline)?;
    if receiver_next
        .id()
        .map_err(|_| "branch sender receiver divergence identity")?
        == headers[0]
            .id()
            .map_err(|_| "branch sender candidate divergence identity")?
    {
        return Err("branch sender declared depth does not match actual divergence".into());
    }
    if query_tip(&mut peer, 4, &deadline)? != baseline {
        return Err("branch sender baseline changed during preflight".into());
    }
    let mut events = Vec::with_capacity(MAX_MESSAGES * 2);
    let mut messages = 0usize;
    let mut transmitted = 0u64;
    let mut completed = 0u16;
    let mut outcome = "round_limit".to_owned();
    let exchange = (|| -> Result<(), String> {
        for round in 0..p.maximum_rounds {
            let notice_request = 5 + u64::from(round);
            let mut notice = vec![TIP];
            notice.extend_from_slice(&p.candidate_height.to_le_bytes());
            notice.extend_from_slice(&hash(&p.candidate_tip)?);
            send_bytes(&mut peer, notice_request, &notice, &deadline)?;
            loop {
                if messages >= MAX_MESSAGES {
                    return Err("branch sender request limit".into());
                }
                let (request, message, _charge) = peer
                    .receive_application_before(&deadline, 1024)
                    .map_err(|e| format!("branch sender request read: {e:?}"))?;
                messages += 1;
                if message == [ROUND_DONE] && request == notice_request {
                    break;
                }
                if message.len() == 9 && message[0] == GET_HEADER && message[1..] == [0; 8] {
                    send_bytes(&mut peer, request, &[CAPABILITIES, 1, 0, 1], &deadline)?;
                    events.push(json!({"round":round,"request":request,"kind":"exact_capability"}));
                    continue;
                }
                let ordinary = message.len() == 9 && message[0] == GET_HEADER;
                let exact = message.len() == 41 && message[0] == EXACT_HEADER;
                let body = message.len() == 41 && message[0] == GET_BODY;
                if !ordinary && !exact && !body {
                    return Err("branch sender unexpected request".into());
                }
                let height =
                    u64::from_le_bytes(message[1..9].try_into().expect("fixed query height"));
                let index = height
                    .checked_sub(p.ancestor_height + 1)
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| *n < headers.len())
                    .ok_or("branch sender request outside supplied branch")?;
                let header = &headers[index];
                let id = header
                    .id()
                    .map_err(|_| "branch sender requested identity")?;
                if (exact || body) && message[9..] != id {
                    return Err("branch sender requested identity differs".into());
                }
                if body {
                    let f = &p.frames[index];
                    let next = transmitted
                        .checked_add(f.bytes - HEADER_BYTES as u64)
                        .ok_or("branch sender transfer overflow")?;
                    if next > p.maximum_transmitted_body_bytes {
                        return Err("branch sender transfer bound".into());
                    }
                    let (frame, _frame_charge) = load_frame(&context, f, bound, &budget)?;
                    if Header::decode(&frame[..HEADER_BYTES], &network)
                        .map_err(|_| "branch sender reread header")?
                        != *header
                    {
                        return Err("branch sender frame changed".into());
                    }
                    let bytes = &frame[HEADER_BYTES..];
                    let mut start = vec![BODY_START];
                    start.extend_from_slice(&height.to_le_bytes());
                    start.extend_from_slice(&id);
                    start.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                    send_bytes(&mut peer, request, &start, &deadline)?;
                    events.push(json!({"round":round,"request":request,"kind":"body_started","height":height,"id":crate::local::hex(&id),"frame_sha256":f.sha256,"body_bytes":bytes.len()}));
                    for (index, part) in bytes.chunks(CHUNK).enumerate() {
                        let mut chunk = vec![BODY_CHUNK];
                        chunk.extend_from_slice(&((index * CHUNK) as u64).to_le_bytes());
                        chunk.extend_from_slice(part);
                        send_bytes(&mut peer, request, &chunk, &deadline)?;
                        transmitted += part.len() as u64;
                    }
                    events.push(json!({"round":round,"request":request,"kind":"body_completed","height":height,"id":crate::local::hex(&id)}));
                } else {
                    let mut bytes = vec![HEADER];
                    bytes.extend_from_slice(
                        &header
                            .encode()
                            .map_err(|_| "branch sender header encoding")?,
                    );
                    send_bytes(&mut peer, request, &bytes, &deadline)?;
                    events.push(json!({"round":round,"request":request,"kind":if exact {"exact_header"} else {"header"},"height":height,"id":crate::local::hex(&id)}));
                }
            }
            drop(
                checkpoint_exchange::initiate_before(&mut peer, &[], network, &deadline)
                    .map_err(|e| format!("branch sender checkpoint phase: {e:?}"))?,
            );
            empty_transactions(&mut peer, &deadline)?;
            completed += 1;
        }
        Ok(())
    })();
    if let Err(error) = exchange {
        outcome = format!("exchange_stopped: {error}");
    }
    let inventory: Vec<_> = p.frames.iter().zip(&headers).map(|(f,h)| json!({"height":h.height,
        "id":crate::local::hex(&h.id().expect("preflight identity")),"frame_sha256":f.sha256,"frame_bytes":f.bytes})).collect();
    Ok(
        json!({"version":1,"scope":"owner-authenticated-native-branch-submission",
        "qualification":context.receipt(),"plan_sha256":plan_pin,"local_fingerprint":p.local_fingerprint,
        "receiver_fingerprint":p.receiver_fingerprint,"receiver_role":p.receiver_role,
        "receiver_baseline_height":p.receiver_height,"receiver_baseline_tip":p.receiver_tip,
        "receiver_ancestor_checked":true,"receiver_divergence_checked":true,"ancestor_height":p.ancestor_height,"ancestor_id":p.ancestor_id,
        "rollback_depth":p.rollback_depth,"candidate_height":p.candidate_height,"candidate_tip":p.candidate_tip,
        "declared_source_fingerprint":p.source_fingerprint,"source_manifest_sha256":p.source_manifest_sha256,
        "source_manifest_pin_verified":true,"source_creation_provenance_verified":false,"artifacts_modified":false,
        "declared_input_kind":p.input_kind.name(),"input_invalidity_verified":false,"real_pinned_authentication":true,
        "frames":inventory,"events":events,"messages":messages,"complete_rounds":completed,
        "successfully_written_body_chunk_bytes":transmitted,"exchange_outcome":outcome,"elapsed_ms":began.elapsed().as_millis().to_string(),
        "receiver_rejection_proven":false,"receiver_unchanged_state_proven":false,
        "proofs_generated":false,"mining_started":false,"listeners_started":false,"identities_created":false,
        "g1_passed":false,"g2_passed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Value {
        json!({"version":1,"endpoint":"127.0.0.1:40201",
            "receiver_descriptor":"receiver.bin","receiver_fingerprint":"01".repeat(32),
            "receiver_role":"validator","receiver_height":25,"receiver_tip":"02".repeat(32),
            "local_fingerprint":"03".repeat(32),"source_fingerprint":"04".repeat(32),
            "source_manifest":"source.json","source_manifest_sha256":"05".repeat(32),
            "ancestor_height":0,"ancestor_id":"06".repeat(32),"rollback_depth":25,
            "candidate_height":26,"candidate_tip":"07".repeat(32),
            "frames":(0..26).map(|i| json!({"path":format!("branch-{i}.frame"),
                "sha256":"08".repeat(32),"bytes":191})).collect::<Vec<_>>(),
            "total_frame_bytes":26*191,"maximum_transmitted_body_bytes":1024,
            "maximum_rounds":16,"input_kind":"negative_input"})
    }
    #[test]
    fn plan_binds_depth_inventory_and_resource_bounds() {
        let value = plan();
        assert!(parse_branch(&serde_json::to_vec(&value).unwrap()).is_ok());
        for (field, item) in [
            ("rollback_depth", json!(24)),
            ("candidate_height", json!(25)),
            ("total_frame_bytes", json!(26 * 191 + 1)),
            ("maximum_rounds", json!(17)),
            ("maximum_transmitted_body_bytes", json!(MAX_BYTES + 1)),
            ("receiver_role", json!("miner")),
            ("extra", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = item;
            assert!(
                parse_branch(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut duplicate = value.clone();
        duplicate["frames"][1]["path"] = duplicate["frames"][0]["path"].clone();
        assert!(parse_branch(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }
    #[test]
    fn supplied_headers_must_link_from_pinned_ancestor_to_exact_tip() {
        let mut p = parse_branch(&serde_json::to_vec(&plan()).unwrap()).unwrap();
        let mut parent = hash(&p.ancestor_id).unwrap();
        let mut headers = Vec::new();
        for height in 1..=26 {
            let h = Header {
                network: [9; 32],
                height,
                parent,
                timestamp: height,
                target: [255; 32],
                execution_commitment: [10; 32],
                body_commitment: [11; 32],
                nonce: 0,
            };
            parent = h.id().unwrap();
            headers.push(h);
        }
        p.candidate_tip = crate::local::hex(&parent);
        assert!(linked_headers(&headers, &p).is_ok());
        let mut disconnected = headers.clone();
        disconnected[7].parent = [12; 32];
        assert!(linked_headers(&disconnected, &p).is_err());
        let mut gap = headers.clone();
        gap[7].height += 1;
        assert!(linked_headers(&gap, &p).is_err());
        p.candidate_tip = "13".repeat(32);
        assert!(linked_headers(&headers, &p).is_err());
    }
}
