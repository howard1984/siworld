//! Private local encoding of one payment's retained encapsulation coins.
//! This is not a consensus format and is never included in public transactions.
use super::{ReservedPayment, UnlockedWallet};
use crate::wallet::WalletPayment;
use crate::wire::{Hash, Sidecar, Transaction};
use native::codec::{PublicTransaction, decode_digest, encode_digest};
use native::encryption::{EncryptionContext, PaymentAddress, PaymentEncryptionOpening};
use native::multi_asset::{F, Hasher, Note};
use p3_field::PrimeCharacteristicRing;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"SWNPO001";
const ENCODED_BYTES: usize = 8 + 32 + 32 + 48 + 1184 + 32;

/// Authenticated per-payment disclosure material, retained only inside the
/// encrypted journal. No formatting, serialization or public export is offered.
pub struct StoredPaymentOpening(Zeroizing<[u8; ENCODED_BYTES]>);
impl StoredPaymentOpening {
    /// Rebuild the KEM ciphertext and authenticate its decrypted commitment
    /// before creating the private local encoding.
    pub fn from_payment(
        network: Hash,
        transaction: &Transaction,
        recipient: &PaymentAddress,
        opening: &PaymentEncryptionOpening,
    ) -> Result<Self, String> {
        transaction.record.validate()?;
        check_opening(network, transaction, recipient, opening)?;
        let mut encoded = Zeroizing::new([0; ENCODED_BYTES]);
        encoded[..8].copy_from_slice(MAGIC);
        encoded[8..40].copy_from_slice(&network);
        encoded[40..72].copy_from_slice(&transaction.record.statement_id(&network));
        encoded[72..120].copy_from_slice(&encode_digest(&recipient.owner()));
        encoded[120..1304].copy_from_slice(recipient.encapsulation_key());
        encoded[1304..].copy_from_slice(opening.expose_encapsulation_coins());
        Ok(Self(encoded))
    }

    /// Validate a bounded decrypted journal payload against its exact retained
    /// transaction and expected network. This never changes the wire format.
    pub fn decode_and_check(
        bytes: &[u8],
        transaction: &Transaction,
        expected_network: Hash,
    ) -> Result<Self, String> {
        if bytes.len() != ENCODED_BYTES || &bytes[..8] != MAGIC {
            return Err("unsupported or malformed private payment opening".into());
        }
        transaction.record.validate()?;
        if bytes[8..40] != expected_network
            || bytes[40..72] != transaction.record.statement_id(&expected_network)
        {
            return Err("private opening network or transaction mismatch".into());
        }
        let owner = decode_digest(
            bytes[72..120]
                .try_into()
                .expect("fixed opening owner width"),
        )
        .map_err(|_| "invalid private opening owner")?;
        let recipient = PaymentAddress::new(
            owner,
            bytes[120..1304]
                .try_into()
                .expect("fixed opening KEM key width"),
        )
        .map_err(|_| "invalid private opening recipient key")?;
        let opening = PaymentEncryptionOpening::from_encapsulation_coins(
            bytes[1304..]
                .try_into()
                .expect("fixed encapsulation coins width"),
        );
        check_opening(expected_network, transaction, &recipient, &opening)?;
        Ok(Self(Zeroizing::new(
            bytes.try_into().expect("fixed local opening width"),
        )))
    }

    pub(super) fn private_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn check_opening(
    network: Hash,
    transaction: &Transaction,
    recipient: &PaymentAddress,
    opening: &PaymentEncryptionOpening,
) -> Result<(), String> {
    if network == [0; 32] {
        return Err("private payment opening requires a nonzero network".into());
    }
    let public = PublicTransaction::decode(&transaction.record.body)
        .map_err(|_| "invalid private opening transaction fields")?;
    let mut note = opening
        .verify_payment(
            recipient,
            &public.cm[0],
            &public.payment,
            &EncryptionContext::new(network),
        )
        .map_err(|_| "private payment opening does not authenticate this output")?;
    let valid = Hasher::new().note_cm(&note) == public.cm[0];
    erase_note(&mut note);
    if valid {
        Ok(())
    } else {
        Err("private payment opening commitment mismatch".into())
    }
}
fn erase_note(note: &mut Note) {
    note.owner.fill(F::ZERO);
    note.asset_id.0.zeroize();
    note.value.zeroize();
    note.unlock_height.zeroize();
    note.rho.fill(F::ZERO);
    note.rseed.fill(F::ZERO);
}

impl UnlockedWallet {
    /// Use only after the pre-proof reservation and independent native proof
    /// verification. The complete typed opening is checked and synchronized
    /// with the exact transaction and sidecar before submission is possible.
    pub fn store_wallet_payment(
        &mut self,
        reservation: &ReservedPayment,
        payment: &WalletPayment,
        recipient: &PaymentAddress,
    ) -> Result<(), String> {
        self.store_prepared_with_opening(
            reservation,
            &payment.transaction,
            &payment.sidecar,
            recipient,
            payment.payment_opening(),
        )
    }

    /// Native typed adapter; callers retain the independent proof-verification
    /// obligation. The generic bounded journal interface remains available.
    pub fn store_prepared_with_opening(
        &mut self,
        reservation: &ReservedPayment,
        transaction: &Transaction,
        sidecar: &Sidecar,
        recipient: &PaymentAddress,
        opening: &PaymentEncryptionOpening,
    ) -> Result<(), String> {
        let network = self.network();
        let stored = StoredPaymentOpening::from_payment(network, transaction, recipient, opening)?;
        self.store_prepared_payment(
            reservation,
            transaction,
            sidecar,
            Zeroizing::new(stored.private_bytes().to_vec()),
            |tx, bytes| StoredPaymentOpening::decode_and_check(bytes, tx, network).map(drop),
        )
    }

    /// Recheck the retained per-payment opening after restart, without
    /// disclosing its bytes or returning a plaintext note to telemetry.
    pub fn verified_payment_opening(&self, id: Hash) -> Result<StoredPaymentOpening, String> {
        let packet = self.payment_packet(id)?;
        StoredPaymentOpening::decode_and_check(
            packet.opening(),
            &packet.transaction()?,
            self.network(),
        )
    }
}
