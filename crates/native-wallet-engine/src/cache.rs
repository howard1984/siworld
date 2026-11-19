//! Bounded private scan state. Callers authenticate the local envelope first.
use super::*;
use crate::{history::CommitmentHistory, issuance::AssetRegistry, paths::OwnedPaths};

pub const MAX_CACHE: usize = 64 * 1024 * 1024;

impl LightWallet {
    /// Includes private receipts and their paths. Never return these bytes to a page or server.
    pub fn local_cache(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(b"SWLW0001".to_vec());
        let address = self.wallet.address();
        out.extend_from_slice(&encode_digest(&address.owner()));
        out.extend_from_slice(address.encapsulation_key());
        let history = CommitmentHistory {
            state: self.state.clone(),
        }
        .cache()?;
        part(&mut out, &history)?;
        let roots = self
            .state
            .snapshots
            .iter()
            .flat_map(|s| s.recent_root)
            .collect::<Vec<_>>();
        part(&mut out, &roots)?;
        let mut assets = Vec::new();
        self.state
            .assets
            .visit_encoding(&mut |bytes| assets.extend_from_slice(bytes));
        part(&mut out, &assets)?;
        part(&mut out, &self.wallet.local_receipt_cache()?)?;
        part(&mut out, &self.paths.cache_owned())?;
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        if out.len() > MAX_CACHE {
            return Err("Local scan cache capacity exceeded.".into());
        }
        Ok(out)
    }

    /// Only for a previously authenticated local envelope; not a network snapshot interface.
    pub fn open_local(
        config: Config,
        seed: Zeroizing<[u8; 32]>,
        account: u32,
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() < 32 || bytes.len() > MAX_CACHE {
            return Err("Local scan cache size differs.".into());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if blake3::hash(body).as_bytes() != checksum {
            return Err("Local scan cache checksum differs.".into());
        }
        let mut input = body;
        if take(&mut input, 8)? != b"SWLW0001" {
            return Err("Local scan cache version differs.".into());
        }
        let mut result = Self::new(config.clone(), seed, account)?;
        let address = result.wallet.address();
        if take(&mut input, 48)? != encode_digest(&address.owner())
            || take(&mut input, address.encapsulation_key().len())? != address.encapsulation_key()
        {
            return Err("Local scan cache belongs to another wallet.".into());
        }
        result.state = CommitmentHistory::open_local(config, section(&mut input)?)?.state;
        let roots = section(&mut input)?;
        if roots.len() != result.state.snapshots.len() * 48 {
            return Err("Cached recent-root window differs.".into());
        }
        for (row, bytes) in result
            .state
            .snapshots
            .iter_mut()
            .zip(roots.as_chunks::<48>().0.iter())
        {
            row.recent_root = *bytes;
            let _ = decode_digest(&row.recent_root).map_err(|_| "Invalid cached recent root.")?;
        }
        result.state.assets =
            AssetRegistry::from_local_encoding(section(&mut input)?, result.state.height)?;
        result
            .wallet
            .open_local_receipts(&mut result.state, section(&mut input)?)?;
        result.paths = OwnedPaths::from_tree_cache(
            result.state.tree.count,
            &result.state.tree.cache_frontier(),
            encode_digest(&result.state.tree.root()),
        )?;
        result.paths.open_local_owned(section(&mut input)?)?;
        if !input.is_empty() {
            return Err("Trailing local scan cache bytes.".into());
        }
        let paths = result.paths.all_paths();
        let required = result
            .wallet
            .receipts()
            .iter()
            .filter(|r| !r.spent && r.note().value > 0)
            .map(|r| r.commitment)
            .collect::<std::collections::BTreeSet<_>>();
        if required != paths.into_keys().collect() {
            return Err("Local receipt and path sets differ.".into());
        }
        Ok(result)
    }
}

fn part(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if out
        .len()
        .checked_add(bytes.len() + 4)
        .is_none_or(|size| size > MAX_CACHE)
    {
        return Err("Local scan cache capacity exceeded.".into());
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    let (part, rest) = input
        .split_at_checked(n)
        .ok_or("Truncated local scan cache.")?;
    *input = rest;
    Ok(part)
}
fn section<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let len = u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize;
    take(input, len)
}
