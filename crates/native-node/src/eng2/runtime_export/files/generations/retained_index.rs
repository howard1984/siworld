// Bounded retained pins independent of the small current advertisement cache.
const MAX_RETAINED_PINS: usize = 256;
const RETAINED_PREFIX_BYTES: usize = 8 + wire::BINDING_BYTES + 2;
const RETAINED_ENTRY_BYTES: usize = 80;
const RETAINED_INDEX_BYTES: usize =
    RETAINED_PREFIX_BYTES + MAX_RETAINED_PINS * RETAINED_ENTRY_BYTES;
const RETAINED_INDEX_NAME: &str = "wallet-retained-generations.bin";
#[derive(Clone, Debug, Default)]
struct RetainedIndex {
    entries: Vec<Entry>,
}
impl RetainedIndex {
    fn encode(&self, binding: &Binding) -> Result<Vec<u8>, String> {
        if self.entries.len() > MAX_RETAINED_PINS {
            return Err("wallet retained pin index full".into());
        }
        let mut bytes =
            Vec::with_capacity(RETAINED_PREFIX_BYTES + self.entries.len() * RETAINED_ENTRY_BYTES);
        bytes.extend_from_slice(b"SWE2WRI1");
        bytes.extend_from_slice(&binding.0);
        bytes.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            if entry.height > wire::MAX_HEIGHT || entry.expires == 0 || entry.expires >= 1 << 53 {
                return Err("wallet retained pin fields rejected".into());
            }
            bytes.extend_from_slice(&entry.height.to_le_bytes());
            bytes.extend_from_slice(&entry.tip);
            bytes.extend_from_slice(&entry.digest);
            bytes.extend_from_slice(&entry.expires.to_le_bytes());
        }
        Ok(bytes)
    }
    fn decode(binding: &Binding, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < RETAINED_PREFIX_BYTES
            || bytes.len() > RETAINED_INDEX_BYTES
            || &bytes[..8] != b"SWE2WRI1"
            || bytes[8..137] != binding.0
        {
            return Err("wallet retained pin context or encoding rejected".into());
        }
        let count = u16::from_le_bytes(bytes[137..139].try_into().expect("fixed count")) as usize;
        if count > MAX_RETAINED_PINS
            || bytes.len() != RETAINED_PREFIX_BYTES + count * RETAINED_ENTRY_BYTES
        {
            return Err("wallet retained pin length rejected".into());
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(count);
        for row in bytes[RETAINED_PREFIX_BYTES..]
            .as_chunks::<RETAINED_ENTRY_BYTES>()
            .0
        {
            let entry = Entry {
                height: u64::from_le_bytes(row[..8].try_into().expect("fixed height")),
                tip: row[8..40].try_into().expect("fixed tip"),
                digest: row[40..72].try_into().expect("fixed digest"),
                expires: u64::from_le_bytes(row[72..80].try_into().expect("fixed expiry")),
            };
            if entry.height > wire::MAX_HEIGHT
                || entry.expires == 0
                || entry.expires >= 1 << 53
                || entries
                    .iter()
                    .any(|e| (e.height, e.tip) == (entry.height, entry.tip))
            {
                return Err("wallet retained pin fields or duplicate rejected".into());
            }
            entries.push(entry);
        }
        Ok(Self { entries })
    }
    fn read(export: &PublicExport, binding: &Binding) -> Result<Self, String> {
        export
            .read_optional(RETAINED_INDEX_NAME, RETAINED_INDEX_BYTES)?
            .map(|b| Self::decode(binding, &b))
            .transpose()
            .map(|v| v.unwrap_or_default())
    }
    fn staged(
        &self,
        catalog: &Catalog,
        target: (u64, Hash),
        digest: Hash,
        now: u64,
        committed: Option<(u64, Hash)>,
    ) -> Result<Self, String> {
        let deadline = now
            .checked_add(RETAIN_SECONDS)
            .filter(|v| *v < 1 << 53)
            .ok_or("wallet retention clock overflow")?;
        if self
            .entries
            .iter()
            .any(|e| (e.height, e.tip) == target && e.digest != digest)
        {
            return Err("wallet retained pin digest conflict".into());
        }
        let mut next = self.clone();
        next.entries.retain(|e| now < e.expires);
        for old in &catalog.entries {
            if (old.height, old.tip) == target {
                if old.digest != digest {
                    return Err("wallet generation digest changed for exact head".into());
                }
                continue;
            }
            let mut entry = old.clone();
            if committed == Some((entry.height, entry.tip)) {
                entry.expires = deadline;
            } else if entry.expires == 0 {
                entry.expires = self
                    .entries
                    .iter()
                    .find(|e| (e.height, e.tip) == (entry.height, entry.tip))
                    .map_or(deadline, |e| e.expires);
            }
            if now >= entry.expires {
                continue;
            }
            if let Some(saved) = next
                .entries
                .iter_mut()
                .find(|e| (e.height, e.tip) == (entry.height, entry.tip))
            {
                if saved.digest != entry.digest {
                    return Err("wallet retained pin digest conflict".into());
                }
                saved.expires = saved.expires.max(entry.expires);
            } else {
                if next.entries.len() == MAX_RETAINED_PINS {
                    return Err("wallet retained pin index full".into());
                }
                next.entries.push(entry);
            }
        }
        Ok(next)
    }
}
impl Catalog {
    fn staged_advertisement(
        &self,
        retained: &RetainedIndex,
        height: u64,
        tip: Hash,
        digest: Hash,
        now: u64,
        committed: Option<(u64, Hash)>,
    ) -> Result<(Self, RetainedIndex), String> {
        let retained = retained.staged(self, (height, tip), digest, now, committed)?;
        let mut entries = Vec::with_capacity(RETAINED_HEADS);
        if let Some(previous) = committed.filter(|v| *v != (height, tip)) {
            entries.push(
                retained
                    .entries
                    .iter()
                    .find(|e| (e.height, e.tip) == previous)
                    .ok_or("wallet committed generation retention absent")?
                    .clone(),
            );
        }
        for row in retained.entries.iter().rev() {
            if (row.height, row.tip) == (height, tip) {
                continue;
            }
            if entries.len() == RETAINED_HEADS - 1 {
                break;
            }
            if !entries
                .iter()
                .any(|e| (e.height, e.tip) == (row.height, row.tip))
            {
                entries.push(row.clone());
            }
        }
        entries.push(Entry {
            height,
            tip,
            digest,
            expires: 0,
        });
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|v| *v < 1 << 53)
            .ok_or("wallet catalog sequence exhausted")?;
        Ok((Self { sequence, entries }, retained))
    }
}
impl PublicExport {
    /// Resolve an exact current or unexpired retained pin. The returned manifest
    /// supplies dependency digests, not native chain validity or current authority.
    /// Callers still authenticate every selected chunk and receipt independently.
    pub fn wallet_generation_manifest(
        &self,
        height: u64,
        tip: Hash,
        now: u64,
    ) -> Result<Manifest, String> {
        if height > wire::MAX_HEIGHT || now >= 1 << 53 {
            return Err("wallet generation lookup bounds rejected".into());
        }
        let binding = Binding::new(
            self.network,
            self.genesis,
            self.rules,
            crate::proofs::protocol_profile_fingerprint(),
        );
        let retained = RetainedIndex::read(self, &binding)?;
        let catalog = Catalog::decode(
            &binding,
            &self.read("wallet-generations.json", CATALOG_BYTES)?,
        )?;
        let head: Value = serde_json::from_slice(&self.read("wallet-head.json", 2048)?)
            .map_err(|_| "wallet committed head encoding rejected")?;
        if head.as_object().is_none_or(|o| o.len() != 9)
            || head["version"] != 2
            || context_json(&binding)
                .as_object()
                .expect("fixed context")
                .iter()
                .any(|(k, v)| head.get(k) != Some(v))
        {
            return Err("wallet committed head context rejected".into());
        }
        let current_height = head["height"]
            .as_u64()
            .filter(|v| *v <= wire::MAX_HEIGHT)
            .ok_or("wallet committed head height rejected")?;
        let current_tip = decode_hash(head["tip"].as_str().ok_or("wallet committed tip absent")?)?;
        head["published_unix_seconds"]
            .as_u64()
            .filter(|v| *v < 1 << 53)
            .ok_or("wallet committed publication time rejected")?;
        let current = (current_height, current_tip) == (height, tip);
        let entry = catalog
            .entries
            .iter()
            .find(|e| (e.height, e.tip) == (height, tip) && (current || now < e.expires))
            .or_else(|| {
                retained
                    .entries
                    .iter()
                    .find(|e| (e.height, e.tip) == (height, tip) && now < e.expires)
            })
            .ok_or("wallet generation pin absent or expired")?;
        let bytes = self.read(
            &format!("wallet-generation-{height}-{}.bin", crate::local::hex(&tip)),
            wire::MAX_MANIFEST_BYTES,
        )?;
        if wire::digest(&bytes) != entry.digest {
            return Err("wallet retained manifest digest differs".into());
        }
        let manifest = Manifest::decode(&binding, &bytes)?;
        if (manifest.height, manifest.tip) != (height, tip) {
            return Err("wallet retained manifest head differs".into());
        }
        Ok(manifest)
    }
}

struct RetainedHeaderPage {
    bytes: Vec<u8>,
    _reservation: p2p::Reservation,
}
impl AsRef<[u8]> for RetainedHeaderPage {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl PublicExport {
    /// Read a bounded header page through exact current or retained pin lookup.
    /// The encoded page preserves the requested head; it never substitutes the
    /// current head or grants work, chain selection or signing authority.
    pub fn wallet_generation_header_page(
        &self,
        head: (u64, Hash),
        from: u64,
        limit: usize,
        now: u64,
        budget: &p2p::Budget,
    ) -> Result<impl AsRef<[u8]> + use<>, String> {
        if from == 0 || from > head.0 || !(1..=wallet_history::MAX_HEADER_PAGE).contains(&limit) {
            return Err("wallet retained header page range rejected".into());
        }
        let count = limit.min(usize::try_from(head.0 - from + 1).unwrap_or(usize::MAX));
        let length =
            8 + wire::BINDING_BYTES + 8 + 32 + 8 + 2 + count * crate::eng2::header::HEADER_BYTES;
        let reservation = budget
            .reserve(
                3 * wire::MAX_MANIFEST_BYTES
                    + 3 * wire::MAX_CHUNK_BYTES
                    + 2 * length
                    + 3 * RETAINED_INDEX_BYTES
                    + CATALOG_BYTES
                    + 2048,
            )
            .map_err(|_| "wallet retained header page memory unavailable")?;
        let binding = Binding::new(
            self.network,
            self.genesis,
            self.rules,
            crate::proofs::protocol_profile_fingerprint(),
        );
        let manifest = self.wallet_generation_manifest(head.0, head.1, now)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(b"SWE2WHP1");
        bytes.extend_from_slice(&binding.0);
        bytes.extend_from_slice(&head.0.to_le_bytes());
        bytes.extend_from_slice(&head.1);
        bytes.extend_from_slice(&from.to_le_bytes());
        bytes.extend_from_slice(&(count as u16).to_le_bytes());
        let end = from + count as u64;
        let mut written = 0usize;
        let mut previous = None;
        for descriptor in &manifest.chunks {
            let stop = descriptor.from + u64::from(descriptor.count);
            if stop <= from || descriptor.from >= end {
                continue;
            }
            let raw = self.read(&descriptor.name(), wire::MAX_CHUNK_BYTES)?;
            let chunk = descriptor.decode_chunk(&binding, &raw)?;
            for height in from.max(descriptor.from)..end.min(stop) {
                let record = &chunk.records[(height - descriptor.from) as usize];
                let header = record.decoded(&binding)?;
                if header.height != height || previous.is_some_and(|tip| header.parent != tip) {
                    return Err("wallet retained header page continuity rejected".into());
                }
                bytes.extend_from_slice(&record.header);
                previous = Some(record.id);
                written += 1;
            }
        }
        if written != count
            || bytes.len() != length
            || end == head.0 + 1 && previous != Some(head.1)
        {
            return Err("wallet retained header page coverage rejected".into());
        }
        Ok(RetainedHeaderPage {
            bytes,
            _reservation: reservation,
        })
    }
}
