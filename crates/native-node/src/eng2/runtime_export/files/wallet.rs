//! Explicit wallet artifacts using the existing descriptor-confined file export.
use super::*;
use crate::{eng2::wallet_history, p2p};

impl PublicExport {
    /// Withdraw the mutable wallet cursor before canonical restoration. Immutable
    /// generations remain retained, but no incomplete prefix is advertised.
    pub fn pause_wallet_head(&self) -> Result<(), String> {
        if self.read_optional("wallet-head.json", 2048)?.is_some() {
            match unlinkat(&self.root, "wallet-head.json", AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => (),
                Err(_) => return Err("wallet cursor withdrawal failed".into()),
            }
            fsync(&self.root).map_err(|_| "wallet cursor withdrawal sync failed")?;
        }
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
