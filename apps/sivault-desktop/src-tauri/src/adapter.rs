use serde::Serialize;
use sivault_core::fixed::enrollment::{FixedEntry, FixedSafe};
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
    pub fixed: bool,
    pub can_manage_decoy: bool,
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
    safe: Payload,
    path: PathBuf,
}

enum Payload {
    Standard(Safe),
    Fixed(FixedSafe),
}

impl From<FixedEntry> for EntryInfo {
    fn from(entry: FixedEntry) -> Self {
        Self {
            id: Uuid::from_bytes(entry.id).to_string(),
            parent: (entry.parent != [0; 16]).then(|| Uuid::from_bytes(entry.parent).to_string()),
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
        }
    }
}

impl Payload {
    fn entries(&mut self) -> Result<Vec<EntryInfo>> {
        match self {
            Self::Standard(safe) => Ok(safe.entries().iter().map(EntryInfo::from).collect()),
            Self::Fixed(safe) => Ok(safe
                .entries()
                .map_err(BridgeError::core)?
                .into_iter()
                .map(EntryInfo::from)
                .collect()),
        }
    }
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

    pub fn create_fixed(
        &mut self,
        path: &Path,
        name: &str,
        password: &str,
        secondary: Option<&str>,
    ) -> Result<SafeInfo> {
        let safe = FixedSafe::create(path, password, secondary).map_err(BridgeError::core)?;
        Ok(self.activate_payload(path, name, Payload::Fixed(safe), false))
    }

    pub fn open(&mut self, path: &Path, password: &str, read_only: bool) -> Result<SafeInfo> {
        let safe = Self::open_payload(path, password, read_only)?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Standard safe");
        Ok(self.activate_payload(path, name, safe, read_only))
    }

    pub fn unlock(&mut self, id: &str, password: &str, read_only: bool) -> Result<SafeInfo> {
        let record = self
            .records
            .get(id)
            .ok_or_else(|| BridgeError::new("SAFE_NOT_FOUND", "Choose the safe file again."))?;
        let path = record.path.clone();
        let name = record.name.clone();
        let safe = Self::open_payload(&path, password, read_only)?;
        Ok(self.activate_payload(&path, &name, safe, read_only))
    }

    fn open_payload(path: &Path, password: &str, read_only: bool) -> Result<Payload> {
        if path.join("s-00000000").exists() {
            return FixedSafe::open(path, password, read_only)
                .map(Payload::Fixed)
                .map_err(BridgeError::core);
        }
        let safe = if Safe::has_controlled_registration(path).map_err(BridgeError::core)? {
            crate::controlled::open(path, password, read_only)
        } else {
            Safe::open(path, password, read_only).map_err(BridgeError::core)
        }?;
        Ok(Payload::Standard(safe))
    }

    pub(crate) fn activate(
        &mut self,
        path: &Path,
        name: &str,
        safe: Safe,
        read_only: bool,
    ) -> SafeInfo {
        self.activate_payload(path, name, Payload::Standard(safe), read_only)
    }

    fn activate_payload(
        &mut self,
        path: &Path,
        name: &str,
        safe: Payload,
        read_only: bool,
    ) -> SafeInfo {
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
        let fixed = matches!(safe, Payload::Fixed(_));
        let read_only = match &safe {
            Payload::Fixed(fixed) => fixed.read_only(),
            Payload::Standard(_) => read_only,
        };
        let info = SafeInfo {
            id,
            name: name.to_owned(),
            session_id: Uuid::new_v4().to_string(),
            read_only,
            fixed,
            can_manage_decoy: matches!(&safe, Payload::Fixed(safe) if safe.can_manage_decoy()),
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
            .entries()?
            .into_iter()
            .filter(|entry| entry.parent.as_deref() == parent)
            .collect())
    }

    pub fn import(
        &mut self,
        session_id: &str,
        source: &Path,
        parent: Option<&str>,
    ) -> Result<EntryInfo> {
        let session = self.session(session_id, true)?;
        match &mut session.safe {
            Payload::Standard(safe) => Ok(EntryInfo::from(
                &safe
                    .import_file(source, parent)
                    .map_err(BridgeError::core)?,
            )),
            Payload::Fixed(FixedSafe::Owner(owner)) if parent.is_none() => {
                let name = put_fixed_file(owner, source, false)?;
                session
                    .safe
                    .entries()?
                    .into_iter()
                    .find(|entry| entry.parent.is_none() && entry.name == name)
                    .ok_or_else(|| BridgeError::core("Imported file was not found."))
            }
            _ => Err(BridgeError::core("Choose the root folder.")),
        }
    }

    pub fn check_decoy_management(&mut self, session_id: &str) -> Result<()> {
        let session = self.session(session_id, true)?;
        if !session.info.can_manage_decoy {
            return Err(BridgeError::core("Open a writable fixed-size safe."));
        }
        Ok(())
    }

    pub fn update_decoy(&mut self, session_id: &str, source: &Path) -> Result<()> {
        self.check_decoy_management(session_id)?;
        let Payload::Fixed(FixedSafe::Owner(owner)) = &mut self.session(session_id, true)?.safe
        else {
            return Err(BridgeError::core("Open a writable fixed-size safe."));
        };
        put_fixed_file(owner, source, true).map(|_| ())
    }

    pub fn export(&mut self, session_id: &str, entry_id: &str, destination: &Path) -> Result<()> {
        let session = self.session(session_id, false)?;
        if let Payload::Fixed(safe) = &mut session.safe {
            let id = Uuid::parse_str(entry_id).map_err(BridgeError::core)?;
            return safe
                .export_file(*id.as_bytes(), &session.path, destination)
                .map_err(BridgeError::core);
        }
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
        match &session.safe {
            Payload::Standard(safe) => safe
                .export_file(entry_id, destination)
                .map_err(BridgeError::core),
            Payload::Fixed(_) => unreachable!(),
        }
    }

    pub fn export_name(&mut self, session_id: &str, entry_id: &str) -> Result<String> {
        self.session(session_id, false)?
            .safe
            .entries()?
            .into_iter()
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
        let Payload::Standard(safe) = &mut session.safe else {
            return Err(BridgeError::core(
                "Fixed-size safes support root files only.",
            ));
        };
        let entry = safe
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

fn put_fixed_file(
    owner: &mut sivault_core::fixed::enrollment::OwnerSafe,
    source: &Path,
    decoy: bool,
) -> Result<String> {
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BridgeError::core("Choose a file with a valid name."))?;
    if !source.metadata().map_err(BridgeError::core)?.is_file() {
        return Err(BridgeError::core("Choose a regular file."));
    }
    let input = std::fs::File::open(source).map_err(BridgeError::core)?;
    let metadata = input.metadata().map_err(BridgeError::core)?;
    if !metadata.is_file() {
        return Err(BridgeError::core("Choose a regular file."));
    }
    owner
        .put_file(decoy, name, metadata.len(), input)
        .map_err(BridgeError::core)?;
    Ok(name.to_owned())
}

#[cfg(all(
    test,
    any(not(windows), all(debug_assertions, feature = "dev-windows-write"))
))]
mod tests {
    use super::*;

    #[test]
    fn fixed_safe_desktop_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Archive.sivault");
        let real = "synthetic main password";
        let decoy = "synthetic alternate password";
        let source = dir.path().join("note.txt");
        let mut state = SafeAdapter::default();
        let owner = state
            .create_fixed(&path, "Archive", real, Some(decoy))
            .unwrap();
        assert!(owner.can_manage_decoy);
        std::fs::write(&source, b"main content").unwrap();
        state.import(&owner.session_id, &source, None).unwrap();
        std::fs::write(&source, b"old decoy").unwrap();
        state.update_decoy(&owner.session_id, &source).unwrap();
        std::fs::write(&source, b"updated decoy").unwrap();
        state.update_decoy(&owner.session_id, &source).unwrap();
        state.lock(&owner.session_id).unwrap();

        let segment = path.join("s-00000000");
        let before = segment.metadata().unwrap().modified().unwrap();
        let mut errors = Vec::new();
        for (i, (password, requested, content)) in [
            (real, true, b"main content".as_slice()),
            (decoy, false, b"updated decoy".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let view = state.unlock(&owner.id, password, requested).unwrap();
            assert!(view.read_only && !view.can_manage_decoy);
            errors.push(state.update_decoy(&view.session_id, &source).unwrap_err());
            let files = state.list(&view.session_id, None).unwrap();
            assert_eq!(files.len(), 1);
            let entry = &files[0];
            assert_eq!(entry.name, "note.txt");
            assert!(state.export(&view.session_id, &entry.id, &segment).is_err());
            assert!(
                state
                    .export(&view.session_id, &entry.id, &path.join("outside.txt"))
                    .is_err()
            );
            #[cfg(unix)]
            {
                let alias = dir.path().join("alias");
                std::os::unix::fs::symlink(&path, &alias).unwrap();
                assert!(
                    state
                        .export(&view.session_id, &entry.id, &alias.join("escaped.txt"))
                        .is_err()
                );
                std::fs::remove_file(alias).unwrap();
            }
            let output = dir.path().join(format!("export-{i}.txt"));
            state.export(&view.session_id, &entry.id, &output).unwrap();
            assert_eq!(std::fs::read(output).unwrap(), content);
            state.lock(&view.session_id).unwrap();
        }
        assert_eq!(errors[0].code, errors[1].code);
        assert_eq!(errors[0].message, errors[1].message);
        assert_eq!(segment.metadata().unwrap().modified().unwrap(), before);
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 1);
    }

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
