//! Private eng2 scan cache. The caller must authenticate its local ciphertext.
use super::*;
use crate::{issuance::AssetRegistry, state::CommitmentTree};
use native::multi_asset::TREE_DEPTH;

pub const MAX_CACHE: usize = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"SWE2LC01";
impl Eng2LightState {
    /// Private notes and membership paths; never publish or send to a service.
    pub fn local_cache(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(MAGIC.to_vec());
        out.extend(binding(&self.context));
        let address = self.wallet.address();
        out.extend_from_slice(&encode_digest(&address.owner()));
        out.extend_from_slice(address.encapsulation_key());
        let mut headers = Vec::with_capacity(self.headers.len() * HEADER_BYTES);
        for header in &self.headers {
            headers.extend(
                header
                    .encode()
                    .map_err(|_| "eng2 cache header encoding rejected")?,
            );
        }
        part(&mut out, &headers)?;
        out.extend_from_slice(&self.state.tree.count.to_le_bytes());
        out.extend_from_slice(&encode_digest(&self.state.tree.root()));
        for value in self.state.tree.cache_frontier() {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&(self.state.snapshots.len() as u16).to_le_bytes());
        for snapshot in &self.state.snapshots {
            out.extend_from_slice(&snapshot.selector.height.to_le_bytes());
            out.extend_from_slice(&snapshot.selector.block_id);
            out.extend_from_slice(&snapshot.commitment_root);
            out.extend_from_slice(&snapshot.recent_root);
        }
        let mut assets = Vec::new();
        self.state
            .assets
            .visit_encoding(&mut |bytes| assets.extend_from_slice(bytes));
        part(&mut out, &assets)?;
        part(&mut out, &self.wallet.local_receipt_cache()?)?;
        part(&mut out, &self.paths.cache_owned())?;
        let checksum = *blake3::hash(&out).as_bytes();
        if out
            .len()
            .checked_add(32)
            .is_none_or(|size| size > MAX_CACHE)
        {
            return Err("eng2 private cache capacity exceeded".into());
        }
        out.extend_from_slice(&checksum);
        Ok(out)
    }
    /// Accept only a same-wallet, authenticated local envelope. This API is
    /// never a network checkpoint/state-snapshot admission path.
    pub fn open_local(
        genesis: &[u8],
        expected: Hash,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() < 32 || bytes.len() > MAX_CACHE {
            return Err("eng2 cache byte limit rejected".into());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if blake3::hash(body).as_bytes() != checksum {
            return Err("eng2 cache checksum rejected".into());
        }
        let mut input = body;
        let mut result = Self::new(genesis, expected, seed, account)?;
        if take(&mut input, 8)? != MAGIC || take(&mut input, 129)? != binding(&result.context) {
            return Err("eng2 cache network, genesis, rules, profile or fee mode differs".into());
        }
        let address = result.wallet.address();
        if take(&mut input, 48)? != encode_digest(&address.owner())
            || take(&mut input, address.encapsulation_key().len())? != address.encapsulation_key()
        {
            return Err("eng2 cache wallet identity differs".into());
        }
        let headers = section(&mut input)?;
        if !headers.len().is_multiple_of(HEADER_BYTES) || headers.len() / HEADER_BYTES > MAX_HEADERS
        {
            return Err("eng2 cache header history bound rejected".into());
        }
        for raw in headers.as_chunks::<HEADER_BYTES>().0 {
            let header = Header::decode(raw, &result.context.config().network)
                .map_err(|_| "eng2 cached header rejected")?;
            verify_header(&result.state, &header)?;
            advance_header(&mut result.state, &header)?;
            result.headers.push(header);
        }
        let count = u64::from_le_bytes(take(&mut input, 8)?.try_into().expect("fixed leaf count"));
        let root = take(&mut input, 48)?.try_into().expect("fixed tree root");
        let frontier = (0..TREE_DEPTH)
            .map(|_| {
                take(&mut input, 48)?
                    .try_into()
                    .map_err(|_| "eng2 frontier width rejected".to_owned())
            })
            .collect::<Result<Vec<DigestBytes>, String>>()?;
        result.state.tree = CommitmentTree::from_local_cache(count, &frontier, root)?;
        let snapshots = usize::from(u16::from_le_bytes(
            take(&mut input, 2)?
                .try_into()
                .expect("fixed snapshot count"),
        ));
        if snapshots != (result.height() + 1).min(SNAPSHOT_WINDOW as u64) as usize {
            return Err("eng2 cache snapshot window rejected".into());
        }
        result.state.snapshots.clear();
        for index in 0..snapshots {
            let height = u64::from_le_bytes(
                take(&mut input, 8)?
                    .try_into()
                    .expect("fixed snapshot height"),
            );
            let block_id = take(&mut input, 32)?
                .try_into()
                .expect("fixed snapshot identity");
            let commitment_root = take(&mut input, 48)?
                .try_into()
                .expect("fixed snapshot root");
            let recent_root = take(&mut input, 48)?.try_into().expect("fixed recent root");
            if height != result.height() + 1 - snapshots as u64 + index as u64
                || block_id != result.id_at(height)?
            {
                return Err("eng2 cache snapshot history differs".into());
            }
            let _ = decode_digest(&commitment_root)
                .map_err(|_| "eng2 cached commitment root rejected")?;
            let _ = decode_digest(&recent_root).map_err(|_| "eng2 cached recent root rejected")?;
            result.state.snapshots.push_back(CanonicalSnapshot {
                selector: Snapshot { height, block_id },
                commitment_root,
                recent_root,
            });
        }
        let last = result
            .state
            .snapshots
            .back()
            .ok_or("eng2 cache snapshot absent")?;
        let hasher = Hasher::new();
        let mut roots = RecentRoots::new();
        for snapshot in &result.state.snapshots {
            roots.insert(
                &hasher,
                snapshot.selector.height,
                &decode_digest(&snapshot.commitment_root)
                    .map_err(|_| "eng2 cached root rejected")?,
                base_fee(snapshot.selector.height),
            );
        }
        if last.commitment_root != root
            || last.recent_root != encode_digest(&roots.tree(&hasher).root())
        {
            return Err("eng2 cache current tree or recent-root commitment differs".into());
        }
        if result.height() == 0
            && (count != 0 || result.state.tree.root() != CommitmentTree::new().root())
        {
            return Err("eng2 cache genesis frontier differs".into());
        }
        result.state.assets =
            AssetRegistry::from_local_encoding(section(&mut input)?, result.height())?;
        result
            .wallet
            .open_local_receipts(&mut result.state, section(&mut input)?)?;
        for receipt in result.wallet.receipts() {
            if receipt.block_id != result.id_at(receipt.height)? {
                return Err("eng2 cache receipt header identity differs".into());
            }
        }
        result.paths = OwnedPaths::from_tree_cache(count, &frontier, root)?;
        result.paths.open_local_owned(section(&mut input)?)?;
        let expected_paths = result
            .wallet
            .receipts()
            .iter()
            .filter(|row| !row.spent && row.note().value > 0)
            .map(|row| row.commitment)
            .collect::<BTreeSet<_>>();
        if expected_paths != result.paths.all_paths().into_keys().collect() || !input.is_empty() {
            return Err("eng2 cache paths or trailing bytes differ".into());
        }
        Ok(result)
    }
    fn id_at(&self, height: u64) -> Result<Hash, String> {
        if height == 0 {
            return Ok(self.context.genesis());
        }
        self.header(height)
            .ok_or("eng2 cached receipt height absent")?
            .id()
            .map_err(|_| "eng2 cached receipt identity rejected".into())
    }
}
fn part(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if out
        .len()
        .checked_add(bytes.len() + 4)
        .is_none_or(|size| size > MAX_CACHE)
        || bytes.len() > u32::MAX as usize
    {
        return Err("eng2 private cache capacity exceeded".into());
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], String> {
    let (value, rest) = input
        .split_at_checked(count)
        .ok_or("eng2 private cache truncated")?;
    *input = rest;
    Ok(value)
}
fn section<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let count =
        u32::from_le_bytes(take(input, 4)?.try_into().expect("fixed section length")) as usize;
    take(input, count)
}
