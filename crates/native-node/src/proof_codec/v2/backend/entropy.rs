//! Independent private streams acquired once per proof attempt.
use rand::{SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    Unavailable,
}

pub(super) struct Streams {
    pub masks: StdRng,
    pub input_salts: StdRng,
    pub fri_salts: StdRng,
}
impl Streams {
    pub fn from_os() -> Result<Self, EntropyError> {
        Self::acquire(|bytes| getrandom::fill(bytes).map_err(|_| EntropyError::Unavailable))
    }
    fn acquire(
        fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
    ) -> Result<Self, EntropyError> {
        let mut entropy = Zeroizing::new([0u8; 96]);
        fill(entropy.as_mut())?;
        Ok(Self {
            masks: StdRng::from_seed(blake3::derive_key(
                "siworld native hiding v2 private polynomial masks",
                &entropy[..32],
            )),
            input_salts: StdRng::from_seed(blake3::derive_key(
                "siworld native hiding v2 private input leaf salts",
                &entropy[32..64],
            )),
            fri_salts: StdRng::from_seed(blake3::derive_key(
                "siworld native hiding v2 private FRI leaf salts",
                &entropy[64..],
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    #[test]
    fn entropy_failure_has_no_private_fallback() {
        assert!(matches!(
            Streams::acquire(|_| Err(EntropyError::Unavailable)),
            Err(EntropyError::Unavailable)
        ));
    }
    #[test]
    fn synthetic_equal_input_chunks_still_have_distinct_purpose_domains() {
        let mut streams = Streams::acquire(|bytes| {
            bytes.fill(7);
            Ok(())
        })
        .unwrap();
        let mut a = [0; 32];
        let mut b = [0; 32];
        let mut c = [0; 32];
        streams.masks.fill_bytes(&mut a);
        streams.input_salts.fill_bytes(&mut b);
        streams.fri_salts.fill_bytes(&mut c);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
