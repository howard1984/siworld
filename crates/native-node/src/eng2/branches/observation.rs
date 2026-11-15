//! Exact retained-branch inspection without opening a writable database.
use super::*;
use sha2::{Digest as _, Sha256};

pub struct Observation {
    pub entry: Entry,
    pub body_bytes: Option<usize>,
    pub body_sha256: Option<Hash>,
}

/// The caller holds the stopped node's service lease. This reads the durable
/// record, including Invalid, without admitting, repairing or updating it.
pub fn inspect(
    path: &Path,
    rules: &HeaderRules,
    id: Hash,
    policy: Policy,
) -> Result<Option<Observation>, String> {
    if path.canonicalize().ok().as_deref() != Some(path) {
        return Err("read-only retained branch requires a canonical regular database".into());
    }
    let maximum = usize::try_from(64_u64 * 1024 * 1024 * 1024).unwrap_or(usize::MAX);
    let checked = crate::local::regular_read(path, true, maximum)?;
    let before = checked
        .metadata()
        .map_err(|_| "retained branch file metadata unavailable")?;
    let database = redb::ReadOnlyDatabase::open(path)
        .map_err(|_| "read-only retained branch database unavailable")?;
    let after = std::fs::symlink_metadata(path).map_err(|_| "retained branch file changed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("retained branch file identity changed".into());
        }
    }
    if !after.file_type().is_file() || before.len() != after.len() {
        return Err("retained branch file changed while opening".into());
    }
    let transaction = database
        .begin_read()
        .map_err(|_| "read-only retained branch snapshot unavailable")?;
    let meta = transaction
        .open_table(META)
        .map_err(|_| "read-only retained branch metadata unavailable")?;
    if meta
        .get("rules")
        .map_err(|_| "read-only retained branch rules unavailable")?
        .ok_or("read-only retained branch rules missing")?
        .value()
        != rules_bytes(rules)
    {
        return Err("read-only retained branch rules differ".into());
    }
    let headers = transaction
        .open_table(HEADERS)
        .map_err(|_| "read-only retained branch headers unavailable")?;
    let Some(row) = headers
        .get(id.as_slice())
        .map_err(|_| "read-only retained branch lookup failed")?
    else {
        return Ok(None);
    };
    let entry = Entry::decode(row.value(), &rules.network)?;
    if entry.header.id().map_err(|_| "retained header encoding")? != id {
        return Err("read-only retained branch key differs from header".into());
    }
    let bodies = transaction
        .open_table(BODIES)
        .map_err(|_| "read-only retained branch bodies unavailable")?;
    let (body_bytes, body_sha256) = if let Some(row) = bodies
        .get(id.as_slice())
        .map_err(|_| "read-only retained branch body lookup failed")?
    {
        let bytes = row.value();
        if bytes.len() > policy.max_body_bytes {
            return Err("read-only retained branch body exceeds bound".into());
        }
        let body = Body::decode(bytes, rules.network, entry.header.height, policy)?;
        if body.commitment(policy)? != entry.header.body_commitment {
            return Err("read-only retained branch body commitment differs".into());
        }
        (Some(bytes.len()), Some(Sha256::digest(bytes).into()))
    } else {
        (None, None)
    };
    Ok(Some(Observation {
        entry,
        body_bytes,
        body_sha256,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_invalid_entry_inspection_preserves_database_and_checks_rules() {
        let fixture = super::super::tests::Fixture::new();
        let rules = HeaderRules {
            network: [17; 32],
            genesis: [2; 32],
            genesis_timestamp: 1,
            genesis_target: [255; 32],
            target_interval: 300,
            pow_iterations: 0,
            max_headers: 128,
        };
        let entry = Entry {
            header: Header {
                network: rules.network,
                height: 1,
                parent: rules.genesis,
                timestamp: 301,
                target: [255; 32],
                execution_commitment: [3; 32],
                body_commitment: [4; 32],
                nonce: 0,
            },
            cumulative_work: Work::one(),
            first_seen: 1,
            status: Status::Invalid,
        };
        let id = entry.header.id().unwrap();
        {
            let store = BranchStore::create(
                &fixture.path(),
                rules.clone(),
                Limits {
                    maximum_headers: 128,
                    maximum_body_bytes: 1024,
                },
            )
            .unwrap();
            let transaction = store.database.begin_write().unwrap();
            transaction
                .open_table(HEADERS)
                .unwrap()
                .insert(id.as_slice(), entry.encode().unwrap().as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let path = fixture.path().canonicalize().unwrap();
        let before = std::fs::read(fixture.path()).unwrap();
        let policy = Policy {
            profile: [7; 32],
            max_body_bytes: 1024,
            max_settlement_proof_bytes: 1024,
        };
        let observed = inspect(&path, &rules, id, policy).unwrap().unwrap();
        assert_eq!(observed.entry.status, Status::Invalid);
        assert_eq!(observed.entry.header.id().unwrap(), id);
        assert_eq!(observed.entry.cumulative_work, entry.cumulative_work);
        assert_eq!(observed.body_bytes, None);
        assert_eq!(observed.body_sha256, None);
        assert!(inspect(&path, &rules, [99; 32], policy).unwrap().is_none());
        let mut wrong_rules = rules.clone();
        wrong_rules.genesis = [8; 32];
        assert!(inspect(&path, &wrong_rules, id, policy).is_err());
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
        #[cfg(unix)]
        {
            let link = fixture.0.join("linked.redb");
            std::os::unix::fs::symlink(fixture.path(), &link).unwrap();
            assert!(inspect(&link, &rules, id, policy).is_err());
        }
    }
}
