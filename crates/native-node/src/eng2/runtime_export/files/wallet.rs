//! Explicit wallet artifacts using the existing descriptor-confined file export.
use super::*;
use crate::{eng2::wallet_history, p2p};

impl PublicExport {
    /// Keep the last complete generation readable while current publication is
    /// paused. This cursor is historical data, not canonical-state readiness.
    pub fn pause_wallet_head(&self) -> Result<(), String> {
        self.read_optional("wallet-head.json", 2048)?;
        Ok(())
    }
    /// Historical synthetic fixture helper. Production publication uses the
    /// complete generation publisher and commits the head last.
    #[cfg(test)]
    pub fn publish_wallet_head(
        &self,
        store: &Store,
        published: u64,
    ) -> Result<wallet_history::Head, String> {
        self.check_store(store)?;
        let head = wallet_history::Head::capture(store)?;
        self.write_once(
            "wallet-genesis.bin",
            &wallet_history::bootstrap(store, &head)?,
        )?;
        let bytes = serde_json::to_vec(&head.projection(published)?)
            .map_err(|_| "wallet head encoding failed")?;
        head.check_current(store)?;
        self.replace("wallet-head.json", &bytes)?;
        Ok(head)
    }
    /// Export only the durable floor. Readers still authenticate the
    /// certificate and its ancestry against their exact selected generation.
    #[cfg(feature = "eng2-runtime")]
    pub(in super::super) fn publish_wallet_checkpoint(&self, store: &Store) -> Result<(), String> {
        use super::super::super::certificate::CERTIFICATE_BYTES;
        const NAME: &str = "wallet-checkpoint-eng2.bin";
        self.check_store(store)?;
        let result = store.finalized_checkpoint().and_then(|certificate| {
            certificate
                .map(|value| {
                    value
                        .encode()
                        .map_err(|_| "wallet checkpoint encoding rejected".into())
                })
                .transpose()
        });
        let wanted = result
            .as_ref()
            .ok()
            .and_then(|value| value.as_ref())
            .map_or(&[][..], |value| value.as_slice());
        let current = self.read_optional(NAME, CERTIFICATE_BYTES);
        if !matches!(current, Ok(value) if value.as_deref().unwrap_or_default() == wanted) {
            // A broken export file can be replaced by the canonical artifact;
            // this never changes either the accepted floor or receipt export.
            self.replace(NAME, wanted)?;
        }
        result.map(|_| ())
    }
    /// Stage a receipt dependency without advertising a complete generation.
    pub fn publish_wallet_receipts(
        &self,
        store: &Store,
        head: &wallet_history::Head,
        height: u64,
        budget: &p2p::Budget,
    ) -> Result<String, String> {
        self.check_store(store)?;
        let export = wallet_history::receipts(store, head, height, budget)?;
        let name = format!("wallet-{}-{}.bin", height, crate::local::hex(&export.id()));
        self.write_once(&name, export.bytes())?;
        Ok(name)
    }
    pub fn publish_wallet_headers(
        &self,
        store: &Store,
        head: &wallet_history::Head,
        from: u64,
        limit: usize,
        budget: &p2p::Budget,
    ) -> Result<String, String> {
        self.check_store(store)?;
        let export = wallet_history::header_page(store, head, from, limit, budget)?;
        let name = format!(
            "wallet-headers-{}-{}-{}-{}.bin",
            head.height(),
            crate::local::hex(&head.tip()),
            from,
            limit
        );
        self.write_once(&name, export.bytes())?;
        Ok(name)
    }
}
