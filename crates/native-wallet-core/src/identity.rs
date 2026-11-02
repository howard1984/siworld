use crate::native_hash::{Digest, F, Hasher};
use libcrux_ml_kem::mlkem768;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use zeroize::{Zeroize, Zeroizing};

/// Secret fields deliberately have no Debug or serialization implementation.
pub struct Identity {
    spend: Zeroizing<[u8; 48]>,
    kem: Zeroizing<[u8; 64]>,
    change: Zeroizing<[u8; 32]>,
    scheduling: Zeroizing<[u8; 32]>,
    address: [u8; 1232],
}
impl Identity {
    pub fn derive(
        seed: &Zeroizing<[u8; 32]>,
        network: [u8; 32],
        account: u32,
    ) -> Result<Self, String> {
        if network == [0; 32] {
            return Err("A nonzero native network ID is required.".into());
        }
        let derive = |domain: &'static str| {
            let mut hash = Zeroizing::new(blake3::Hasher::new_derive_key(domain));
            hash.update(seed.as_ref());
            hash.update(&network);
            hash.update(&account.to_le_bytes());
            hash.finalize_xof()
        };
        let mut reader = derive("siworld native wallet spend key v1");
        let mut fields: Digest = [F::ZERO; 12];
        let mut count = 0;
        let mut buffer = Zeroizing::new([0u8; 64]);
        while count < fields.len() {
            reader.fill(buffer.as_mut());
            for bytes in buffer.as_chunks::<4>().0 {
                let value = u32::from_le_bytes(*bytes);
                if value < F::ORDER_U32 {
                    fields[count] = F::from_u32(value);
                    count += 1;
                    if count == fields.len() {
                        break;
                    }
                }
            }
        }
        let mut spend = Zeroizing::new([0u8; 48]);
        let mut address = [0u8; 1232];
        for (i, f) in fields.iter().enumerate() {
            spend[4 * i..4 * i + 4].copy_from_slice(&f.as_canonical_u32().to_le_bytes());
        }
        for (i, f) in Hasher::new().owner(&fields).iter().enumerate() {
            address[4 * i..4 * i + 4].copy_from_slice(&f.as_canonical_u32().to_le_bytes());
        }
        fields.fill(F::ZERO);
        let mut kem = Zeroizing::new([0u8; 64]);
        derive("siworld native wallet ML-KEM view key v1").fill(kem.as_mut());
        let (mut private, public) = mlkem768::generate_key_pair(*kem).into_parts();
        address[48..].copy_from_slice(public.as_slice());
        private[0..mlkem768::MlKem768PrivateKey::len()].zeroize();
        let mut change = Zeroizing::new([0u8; 32]);
        derive("siworld native wallet sender change key v1").fill(change.as_mut());
        let mut scheduling = Zeroizing::new([0u8; 32]);
        derive("siworld native wallet automatic note scheduling v1").fill(scheduling.as_mut());
        Ok(Self {
            spend,
            kem,
            change,
            scheduling,
            address,
        })
    }
    pub fn address(&self) -> &[u8; 1232] {
        &self.address
    }
    pub fn spend_key(&self) -> &[u8; 48] {
        &self.spend
    }
    pub fn kem_seed(&self) -> &[u8; 64] {
        &self.kem
    }
    pub fn change_key(&self) -> &[u8; 32] {
        &self.change
    }
    pub fn scheduling_key(&self) -> &[u8; 32] {
        &self.scheduling
    }
}
