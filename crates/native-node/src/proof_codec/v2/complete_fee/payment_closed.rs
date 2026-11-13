//! Actual native payment format encryption relation; settlement linkage follows.
use super::{
    arx_closed,
    kem_arx_closed::{self, KemArxClosedAir},
    kem_closed,
    poly1305_closed::{self, Poly1305Air},
};
use ::native::{
    encryption::{EncryptionContext, PaymentAddress, PaymentCiphertext, PaymentEncryptionOpening},
    multi_asset::{Digest, F, Hasher, Note},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInOut, KeyInit},
};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

const HEIGHT: usize = 512;
const POLY_OFFSET: usize = kem_arx_closed::WIDTH;
pub(crate) const PLAIN_OFFSET: usize = POLY_OFFSET + poly1305_closed::WIDTH;
pub(crate) const WIDTH: usize = PLAIN_OFFSET + 32;
const POLY_PRE: usize = kem_arx_closed::PRE_WIDTH;
const LINK_PRE: usize = POLY_PRE + poly1305_closed::PRE_WIDTH;
pub(crate) const PRE_WIDTH: usize = LINK_PRE + 41;
#[derive(Clone)]
pub struct PaymentClosedAir {
    pub kem: KemArxClosedAir,
    pub poly: Poly1305Air,
    pub address: PaymentAddress,
    pub context: EncryptionContext,
    pub commitment: Digest,
    pub view_tag: u8,
}
pub fn aad(context: &EncryptionContext, commitment: &Digest) -> [u8; 117] {
    assert_eq!(context.version, 2);
    let mut bytes = Vec::from(&b"siworld multi-asset output aad v1\0"[..]);
    bytes.extend_from_slice(&context.version.to_le_bytes());
    bytes.extend_from_slice(&context.network);
    bytes.push(0);
    for field in commitment {
        use p3_field::PrimeField32;
        bytes.extend_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
    bytes.try_into().unwrap()
}
pub fn note_bytes(note: &Note) -> [u8; 208] {
    use p3_field::PrimeField32;
    let mut bytes = [0; 208];
    bytes[..8].copy_from_slice(&note.value.to_le_bytes());
    bytes[8..16].copy_from_slice(&note.unlock_height.to_le_bytes());
    for (i, field) in note.rho.iter().chain(&note.rseed).enumerate() {
        bytes[16 + i * 4..20 + i * 4].copy_from_slice(&field.as_canonical_u32().to_le_bytes());
    }
    bytes[112..144].copy_from_slice(&note.asset_id.0);
    bytes
}
impl PaymentClosedAir {
    pub fn ciphertext(&self) -> PaymentCiphertext {
        PaymentCiphertext {
            kem_ciphertext: self.kem.0.ciphertext,
            body: self.poly.body,
            tag: self.poly.tag,
            view_tag: self.view_tag,
        }
    }
}
impl BaseAir<F> for PaymentClosedAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        17
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        assert_eq!(self.address.encapsulation_key(), &self.kem.0.public_key);
        let kem = self.kem.preprocessed_trace().unwrap();
        let mut poly = self.poly.clone();
        poly.aad = aad(&self.context, &self.commitment);
        let poly = poly.preprocessed_trace().unwrap();
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for row in 0..HEIGHT {
            let off = row * PRE_WIDTH;
            values[off..off + POLY_PRE]
                .copy_from_slice(&kem.values[row * POLY_PRE..(row + 1) * POLY_PRE]);
            values[off + POLY_PRE..off + LINK_PRE].copy_from_slice(
                &poly.values
                    [row * poly1305_closed::PRE_WIDTH..(row + 1) * poly1305_closed::PRE_WIDTH],
            );
            for word in 0..8 {
                values[off + LINK_PRE + word] = F::from_bool(row == 16 + word);
            }
            if (32..84).contains(&row) {
                values[off + LINK_PRE + 8] = F::ONE;
                for bit in 0..32 {
                    values[off + LINK_PRE + 9 + bit] = F::from_bool(
                        self.poly.body[(row - 32) * 4 + bit / 8] >> (bit % 8) & 1 != 0,
                    );
                }
            }
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}
impl<AB> Air<AB> for PaymentClosedAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        self.kem.eval(b);
        poly1305_closed::eval_at(b, POLY_OFFSET, POLY_PRE);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = main.current_slice();
        let p = pre.current_slice();
        let stream = &l[kem_closed::WIDTH + arx_closed::POST_OFFSET + 64..];
        for word in 0..8 {
            for (bit, &stream_bit) in stream[..32].iter().enumerate() {
                let target = if word < 4 {
                    if poly1305_closed::clamped_bit(word * 32 + bit) {
                        continue;
                    }
                    POLY_OFFSET + poly1305_closed::R + word * 32 + bit
                } else {
                    POLY_OFFSET + poly1305_closed::S + (word - 4) * 32 + bit
                };
                b.assert_zero(
                    (AB::Expr::from(l[target]) - AB::Expr::from(stream_bit))
                        * AB::Expr::from(p[LINK_PRE + word]),
                );
            }
        }
        for bit in 0..32 {
            b.assert_bool(l[PLAIN_OFFSET + bit]);
            let plain = AB::Expr::from(l[PLAIN_OFFSET + bit]);
            let key = AB::Expr::from(stream[bit]);
            let expected = plain.clone() + key.clone() - plain * key * F::from_u32(2);
            b.assert_zero(
                (expected - AB::Expr::from(p[LINK_PRE + 9 + bit]))
                    * AB::Expr::from(p[LINK_PRE + 8]),
            );
        }
    }
}
pub fn generate(
    address: &PaymentAddress,
    coins: [u8; 32],
    note: &Note,
    context: &EncryptionContext,
) -> (PaymentClosedAir, RowMajorMatrix<F>) {
    generate_with_commitment(address, coins, note, context, Hasher::new().note_cm(note))
}
pub(crate) fn generate_with_commitment(
    address: &PaymentAddress,
    coins: [u8; 32],
    note: &Note,
    context: &EncryptionContext,
    commitment: Digest,
) -> (PaymentClosedAir, RowMajorMatrix<F>) {
    assert_eq!(address.owner(), note.owner);
    let (air, trace) =
        generate_with_plaintext(address, coins, note_bytes(note), context, commitment);
    if commitment == Hasher::new().note_cm(note) {
        let recovered = PaymentEncryptionOpening::from_encapsulation_coins(coins)
            .verify_payment(address, &commitment, &air.ciphertext(), context)
            .unwrap();
        assert_eq!(recovered.owner, note.owner);
        assert_eq!(note_bytes(&recovered), note_bytes(note));
    }
    (air, trace)
}
pub(crate) fn generate_with_plaintext(
    address: &PaymentAddress,
    coins: [u8; 32],
    plain: [u8; 208],
    context: &EncryptionContext,
    commitment: Digest,
) -> (PaymentClosedAir, RowMajorMatrix<F>) {
    let (kem, ktrace, view_tag) = kem_arx_closed::generate(address.encapsulation_key(), coins);
    let (_, secret) =
        super::kem_reference::encapsulate_reference(address.encapsulation_key(), coins);
    let (arx, _) = arx_closed::generate(secret);
    let stream = arx_closed::private_stream_bytes(&arx);
    let key = arx_closed::private_key_bytes(&arx);
    let associated = aad(context, &commitment);
    let mut body = plain;
    let tag = ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"))
        .encrypt_inout_detached(
            <&Nonce>::try_from([0u8; 12].as_slice()).expect("fixed nonce size"),
            &associated,
            body.as_mut_slice().into(),
        )
        .unwrap();
    let (poly, ptrace) =
        poly1305_closed::generate(stream[..32].try_into().unwrap(), associated, body);
    assert_eq!(poly.tag.as_slice(), &tag[..]);
    let air = PaymentClosedAir {
        kem,
        poly,
        address: address.clone(),
        context: *context,
        commitment,
        view_tag,
    };
    let mut independently_decrypted = body;
    ChaCha20Poly1305::new(<&Key>::try_from(key.as_slice()).expect("fixed key size"))
        .decrypt_inout_detached(
            <&Nonce>::try_from([0u8; 12].as_slice()).expect("fixed nonce size"),
            &associated,
            independently_decrypted.as_mut_slice().into(),
            &tag,
        )
        .unwrap();
    assert_eq!(independently_decrypted, plain);
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for row in 0..HEIGHT {
        values[row * WIDTH..row * WIDTH + POLY_OFFSET]
            .copy_from_slice(&ktrace.values[row * POLY_OFFSET..(row + 1) * POLY_OFFSET]);
        values[row * WIDTH + POLY_OFFSET..row * WIDTH + PLAIN_OFFSET].copy_from_slice(
            &ptrace.values[row * poly1305_closed::WIDTH..(row + 1) * poly1305_closed::WIDTH],
        );
        if (32..84).contains(&row) {
            for bit in 0..32 {
                values[row * WIDTH + PLAIN_OFFSET + bit] =
                    F::from_bool(plain[(row - 32) * 4 + bit / 8] >> (bit % 8) & 1 != 0);
            }
        }
    }
    (air, RowMajorMatrix::new(values, WIDTH))
}
