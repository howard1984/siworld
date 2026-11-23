use serde::Serialize;
use sivault_core::standard::Safe;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeError {
    code: &'static str,
    message: String,
}

impl BridgeError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn core(error: impl std::fmt::Display) -> Self {
        Self::new("SAFE_OPERATION_FAILED", error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeInfo {
    pub id: String,
    pub name: String,
    pub session_id: String,
    pub read_only: bool,
}

#[derive(Debug, Serialize)]
pub struct EntryInfo {
    pub id: String,
    pub parent: Option<String>,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

impl From<&sivault_core::standard::Entry> for EntryInfo {
    fn from(entry: &sivault_core::standard::Entry) -> Self {
        Self {
            id: entry.id.clone(),
            parent: entry.parent.clone(),
            name: entry.name.clone(),
            is_dir: entry.is_dir,
            size: entry.size,
        }
    }
}

struct Record {
    path: PathBuf,
    name: String,
}
struct Session {
    info: SafeInfo,
    safe: Safe,
    path: PathBuf,
}

#[derive(Default)]
pub struct SafeAdapter {
    records: HashMap<String, Record>,
    active: Option<Session>,
}

impl SafeAdapter {
    pub fn create(&mut self, path: &Path, name: &str, password: &str) -> Result<SafeInfo> {
        let safe = Safe::create(path, password).map_err(BridgeError::core)?;
        Ok(self.activate(path, name, safe, false))
    }

    pub fn open(&mut self, path: &Path, password: &str, read_only: bool) -> Result<SafeInfo> {
        let safe = Safe::open(path, password, read_only).map_err(BridgeError::core)?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Standard safe");
        Ok(self.activate(path, name, safe, read_only))
    }

    pub fn unlock(&mut self, id: &str, password: &str, read_only: bool) -> Result<SafeInfo> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| BridgeError::new("SAFE_NOT_FOUND", "Choose the safe file again."))?;
        let path = record.path.clone();
        let name = record.name.clone();
        let safe = Safe::open(&path, password, read_only).map_err(BridgeError::core)?;
        Ok(self.activate(&path, &name, safe, read_only))
    }

    fn activate(&mut self, path: &Path, name: &str, safe: Safe, read_only: bool) -> SafeInfo {
        let id = self
            .records
            .iter()
            .find(|(_, record)| record.path == path)
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.records.insert(
            id.clone(),
            Record {
                path: path.to_owned(),
                name: name.to_owned(),
            },
        );
        let info = SafeInfo {
            id,
            name: name.to_owned(),
            session_id: Uuid::new_v4().to_string(),
            read_only,
        };
        self.active = Some(Session {
            info: info.clone(),
            safe,
            path: path.to_owned(),
        });
        info
    }

    fn session(&mut self, session_id: &str, writable: bool) -> Result<&mut Session> {
        let session = self
            .active
            .as_mut()
            .filter(|session| session.info.session_id == session_id)
            .ok_or_else(|| {
                BridgeError::new("SAFE_LOCKED", "This safe is locked. Open it again.")
            })?;
        if writable && session.info.read_only {
            return Err(BridgeError::new(
                "READ_ONLY",
                "This safe is open read-only.",
            ));
        }
        Ok(session)
    }

    pub fn list(&mut self, session_id: &str, parent: Option<&str>) -> Result<Vec<EntryInfo>> {
        let session = self.session(session_id, false)?;
        Ok(session
            .safe
            .entries()
            .iter()
            .filter(|entry| entry.parent.as_deref() == parent)
            .map(EntryInfo::from)
            .collect())
    }

    pub fn import(
        &mut self,
        session_id: &str,
        source: &Path,
        parent: Option<&str>,
    ) -> Result<EntryInfo> {
        let session = self.session(session_id, true)?;
        let entry = session
            .safe
            .import_file(source, parent)
            .map_err(BridgeError::core)?;
        Ok(EntryInfo::from(&entry))
    }

    pub fn export(&mut self, session_id: &str, entry_id: &str, destination: &Path) -> Result<()> {
        let session = self.session(session_id, false)?;
        let destination_parent = destination
            .parent()
            .and_then(|path| path.canonicalize().ok());
        let safe_path = session.path.canonicalize().map_err(BridgeError::core)?;
        if destination == session.path
            || destination
                .canonicalize()
                .is_ok_and(|path| path.starts_with(&safe_path))
            || destination_parent.is_some_and(|path| path.starts_with(&safe_path))
        {
            return Err(BridgeError::new(
                "INVALID_DESTINATION",
                "Choose a destination outside the safe folder.",
            ));
        }
        session
            .safe
            .export_file(entry_id, destination)
            .map_err(BridgeError::core)
    }

    pub fn export_name(&mut self, session_id: &str, entry_id: &str) -> Result<String> {
        self.session(session_id, false)?
            .safe
            .entries()
            .iter()
            .find(|entry| entry.id == entry_id && !entry.is_dir)
            .map(|entry| entry.name.clone())
            .ok_or_else(|| BridgeError::new("INVALID_ENTRY", "Select a file to export."))
    }

    pub fn check_writable(&mut self, session_id: &str) -> Result<()> {
        self.session(session_id, true).map(|_| ())
    }

    pub fn create_directory(
        &mut self,
        session_id: &str,
        name: &str,
        parent: Option<&str>,
    ) -> Result<EntryInfo> {
        let session = self.session(session_id, true)?;
        let entry = session
            .safe
            .create_directory(name, parent)
            .map_err(BridgeError::core)?;
        Ok(EntryInfo::from(&entry))
    }

    pub fn lock(&mut self, session_id: &str) -> Result<()> {
        self.session(session_id, false)?;
        self.active = None;
        Ok(())
    }
}

#[cfg(all(
    test,
    any(not(windows), all(debug_assertions, feature = "dev-windows-write"))
))]
mod tests {
    use super::*;

    #[test]
    fn offline_round_trip_and_session_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sivault");
        let source = dir.path().join("synthetic.txt");
        let output = dir.path().join("export.txt");
        let fixture = b"Synthetic desktop adapter integration fixture.\n";
        std::fs::write(&source, fixture).unwrap();
        let mut adapter = SafeAdapter::default();
        let created = adapter
            .create(&path, "Test archive", "synthetic test password")
            .unwrap();
        let folder = adapter
            .create_directory(&created.session_id, "Documents", None)
            .unwrap();
        let imported = adapter
            .import(&created.session_id, &source, Some(&folder.id))
            .unwrap();
        adapter.lock(&created.session_id).unwrap();
        assert!(adapter.list(&created.session_id, None).is_err());
        assert!(
            adapter
                .unlock(&created.id, "wrong password", false)
                .is_err()
        );
        let opened = adapter
            .unlock(&created.id, "synthetic test password", true)
            .unwrap();
        assert_ne!(created.session_id, opened.session_id);
        let files = adapter.list(&opened.session_id, Some(&folder.id)).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "synthetic.txt");
        assert!(adapter.import(&opened.session_id, &source, None).is_err());
        assert!(
            adapter
                .create_directory(&opened.session_id, "Blocked", None)
                .is_err()
        );
        assert!(
            adapter
                .export(&opened.session_id, &imported.id, &path)
                .is_err()
        );
        assert!(
            adapter
                .export(
                    &opened.session_id,
                    &imported.id,
                    &path.join("unexpected.txt")
                )
                .is_err()
        );
        adapter
            .export(&opened.session_id, &imported.id, &output)
            .unwrap();
        assert_eq!(std::fs::read(output).unwrap(), fixture);
        adapter.lock(&opened.session_id).unwrap();
        let reopened = adapter
            .open(&path, "synthetic test password", false)
            .unwrap();
        assert_eq!(adapter.list(&reopened.session_id, None).unwrap().len(), 1);
    }
}
