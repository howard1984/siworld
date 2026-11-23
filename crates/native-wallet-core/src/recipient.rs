//! Non-consensus recipient descriptors and content-addressed directory entries.
use bech32::{Hrp, segwit};
use libcrux_ml_kem::mlkem768::{self, MlKem768PublicKey};
use std::collections::BTreeMap;

const LEGACY_LEN: usize = 1250;
pub const V2_LEN: usize = 1266;
pub const MAX_DIRECTORY_ENTRIES: usize = 10_000;
pub const MAX_DIRECTORY_PAGE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
}

impl Network {
    fn hrp(self) -> Hrp {
        match self {
            Self::Mainnet => Hrp::parse("si").unwrap(),
            Self::Testnet => Hrp::parse("tsi").unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortAddress {
    pub network: Network,
    pub id: [u8; 32],
}

impl ShortAddress {
    pub fn encode(self) -> String {
        segwit::encode_v1(self.network.hrp(), &self.id).expect("fixed short address parameters")
    }

    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if !matches!(text.len(), 62 | 63) {
            return Err("Invalid short address length.");
        }
        let (hrp, version, bytes) =
            segwit::decode(text).map_err(|_| "Invalid short address encoding.")?;
        let network = match hrp.as_str().to_ascii_lowercase().as_str() {
            "si" => Network::Mainnet,
            "tsi" => Network::Testnet,
            _ => return Err("Unsupported address network."),
        };
        if version != segwit::VERSION_1 {
            return Err("Unsupported short address version.");
        }
        let id = bytes
            .try_into()
            .map_err(|_| "Invalid short address digest width.")?;
        Ok(Self { network, id })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    network: Network,
    bytes: Vec<u8>,
}

impl Descriptor {
    pub fn new_v2(
        network: Network,
        genesis: [u8; 32],
        recipient: &[u8; 1232],
    ) -> Result<Self, &'static str> {
        let mut bytes = Vec::with_capacity(V2_LEN);
        bytes.extend([2, network as u8]);
        bytes.extend(genesis);
        bytes.extend(recipient);
        Self::decode(&bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        match (bytes.first(), bytes.len()) {
            (Some(0), LEGACY_LEN) => {
                let owner = &bytes[34..66];
                let key: [u8; 1184] = bytes[66..].try_into().expect("legacy key width");
                if owner
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .any(|word| u32::from_le_bytes(*word) >= 2_130_706_433)
                    || !mlkem768::validate_public_key(&MlKem768PublicKey::from(&key))
                {
                    return Err("Invalid legacy recipient.");
                }
            }
            (Some(2), V2_LEN) => {
                crate::address::validate(bytes[34..].try_into().expect("v2 recipient width"))
                    .map_err(|_| "Invalid v2 recipient.")?;
            }
            _ => return Err("Invalid descriptor version or length."),
        }
        let network = match bytes[1] {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            _ => return Err("Invalid descriptor network."),
        };
        Ok(Self {
            network,
            bytes: bytes.to_vec(),
        })
    }

    pub fn encode(&self) -> &[u8] {
        &self.bytes
    }

    pub fn genesis(&self) -> [u8; 32] {
        self.bytes[2..34].try_into().expect("genesis width")
    }

    pub fn short_address(&self) -> ShortAddress {
        let context = if self.bytes[0] == 0 {
            "siworld recipient descriptor devnet v0"
        } else {
            "siworld recipient descriptor v2"
        };
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(&(self.bytes.len() as u64).to_le_bytes());
        hasher.update(&self.bytes);
        ShortAddress {
            network: self.network,
            id: *hasher.finalize().as_bytes(),
        }
    }

    pub fn native_recipient(&self) -> Result<&[u8; 1232], &'static str> {
        self.bytes[34..]
            .try_into()
            .map_err(|_| "Legacy descriptor cannot receive native payments.")
    }
}

pub struct Directory {
    network: Network,
    genesis: [u8; 32],
    records: BTreeMap<[u8; 32], Descriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: [u8; 32],
    pub count: usize,
}

pub struct Page<'a> {
    pub next: Option<usize>,
    pub entries: Vec<(ShortAddress, &'a [u8])>,
}

impl Directory {
    pub fn new(network: Network, genesis: [u8; 32]) -> Self {
        Self {
            network,
            genesis,
            records: BTreeMap::new(),
        }
    }

    pub fn insert_expected(
        &mut self,
        expected: ShortAddress,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        let descriptor = Descriptor::decode(bytes)?;
        if expected.network != self.network
            || descriptor.genesis() != self.genesis
            || descriptor.short_address() != expected
        {
            return Err("Descriptor does not match this destination or chain.");
        }
        if let Some(existing) = self.records.get(&expected.id) {
            return if existing == &descriptor {
                Ok(())
            } else {
                Err("Conflicting directory descriptor.")
            };
        }
        if self.records.len() >= MAX_DIRECTORY_ENTRIES {
            return Err("Recipient directory is full.");
        }
        self.records.insert(expected.id, descriptor);
        Ok(())
    }

    pub fn descriptor(&self, text: &str) -> Result<&Descriptor, &'static str> {
        let short = ShortAddress::parse(text)?;
        if short.network != self.network {
            return Err("Wrong address network.");
        }
        self.records
            .get(&short.id)
            .ok_or("Recipient address has not been published or is not available locally.")
    }

    pub fn resolve_native(&self, text: &str) -> Result<&[u8; 1232], &'static str> {
        self.descriptor(text)?.native_recipient()
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut hash = blake3::Hasher::new_derive_key("siworld recipient directory snapshot v1");
        hash.update(&[self.network as u8]);
        hash.update(&self.genesis);
        hash.update(&(self.records.len() as u64).to_le_bytes());
        for id in self.records.keys() {
            hash.update(id);
        }
        Snapshot {
            id: *hash.finalize().as_bytes(),
            count: self.records.len(),
        }
    }

    /// An offset is only valid for the exact snapshot it was issued for.
    pub fn page(
        &self,
        snapshot: Snapshot,
        offset: usize,
        limit: usize,
    ) -> Result<Page<'_>, &'static str> {
        if snapshot != self.snapshot() {
            return Err("Recipient directory snapshot changed.");
        }
        if offset > snapshot.count || !(1..=MAX_DIRECTORY_PAGE).contains(&limit) {
            return Err("Recipient directory page bounds rejected.");
        }
        let entries: Vec<_> = self
            .records
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(id, descriptor)| {
                (
                    ShortAddress {
                        network: self.network,
                        id: *id,
                    },
                    descriptor.encode(),
                )
            })
            .collect();
        let end = offset + entries.len();
        Ok(Page {
            next: (end < snapshot.count).then_some(end),
            entries,
        })
    }
}
