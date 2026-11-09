//! Handle-checked current-user storage. Native API calls are confined here.
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::SystemInformation::*;
use windows_sys::Win32::System::Threading::*;

const ERROR: &str = "Windows private storage ownership, ACL or file identity check failed";
static STOP: AtomicBool = AtomicBool::new(false);
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

fn wide(text: &OsStr) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = text.encode_wide().collect();
    if out.contains(&0) {
        return Err(ERROR.into());
    }
    out.push(0);
    Ok(out)
}

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: each allocation comes from a documented LocalAlloc API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn current_sid() -> Result<String, String> {
    // SAFETY: all output buffers are sized before the API writes to them.
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(ERROR.into());
        }
        let mut needed = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 || needed > 65_536 {
            CloseHandle(token);
            return Err(ERROR.into());
        }
        // A word-aligned buffer is required for TOKEN_USER.
        let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        let success = GetTokenInformation(
            token,
            TokenUser,
            data.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if success == 0 {
            return Err(ERROR.into());
        }
        let user = &*data.as_ptr().cast::<TOKEN_USER>();
        let mut string = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut string) == 0 {
            return Err(ERROR.into());
        }
        let allocation = Allocation(string.cast());
        let mut len = 0;
        while len < 256 && *string.add(len) != 0 {
            len += 1;
        }
        if len == 256 {
            return Err(ERROR.into());
        }
        let value =
            String::from_utf16(std::slice::from_raw_parts(string, len)).map_err(|_| ERROR)?;
        drop(allocation);
        Ok(value)
    }
}

struct Security(Allocation);
impl Security {
    fn new(directory: bool) -> Result<Self, String> {
        let sid = current_sid()?;
        let flags = if directory { "OICI" } else { "" };
        let descriptor = wide(OsStr::new(&format!("O:{sid}D:P(A;{flags};FA;;;{sid})")))?;
        let mut pointer = null_mut();
        // SAFETY: NUL-terminated input and valid output pointer; allocation is owned.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &mut pointer,
                null_mut(),
            )
        } == 0
        {
            return Err(ERROR.into());
        }
        Ok(Self(Allocation(pointer)))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}

fn info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    // SAFETY: the owned File keeps the handle valid; output is fully sized.
    unsafe {
        let mut data = zeroed();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut data) == 0 {
            return Err(ERROR.into());
        }
        Ok(data)
    }
}

pub fn file_identity(file: &File) -> Result<(u32, u64), String> {
    let data = info(file)?;
    Ok((
        data.dwVolumeSerialNumber,
        (u64::from(data.nFileIndexHigh) << 32) | u64::from(data.nFileIndexLow),
    ))
}

pub fn check_private(file: &File, directory: bool) -> Result<(), String> {
    let attributes = info(file)?;
    if attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && attributes.nNumberOfLinks != 1)
    {
        return Err(ERROR.into());
    }
    let expected = Security::new(directory)?;
    // SAFETY: GetSecurityInfo owns its returned allocation; GetAce pointers
    // remain valid until that allocation is dropped. ACE length is checked.
    unsafe {
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        if GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        ) != 0
        {
            return Err(ERROR.into());
        }
        let _allocation = Allocation(descriptor);
        if owner.is_null() || acl.is_null() {
            return Err(ERROR.into());
        }
        let mut expected_owner = null_mut();
        let mut defaulted = 0;
        if GetSecurityDescriptorOwner(expected.0.0, &mut expected_owner, &mut defaulted) == 0
            || EqualSid(owner, expected_owner) == 0
        {
            return Err(ERROR.into());
        }
        let mut control = 0;
        let mut revision = 0;
        if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || (directory && control & SE_DACL_PROTECTED == 0)
        {
            return Err(ERROR.into());
        }
        let mut summary: ACL_SIZE_INFORMATION = zeroed();
        if GetAclInformation(
            acl,
            (&mut summary as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
            || summary.AceCount != 1
        {
            return Err(ERROR.into());
        }
        let mut ace = null_mut();
        if GetAce(acl, 0, &mut ace) == 0 || ace.is_null() {
            return Err(ERROR.into());
        }
        let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Header.AceType != 0
            || usize::from(ace.Header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            || u32::from(ace.Header.AceFlags) & INHERIT_ONLY_ACE != 0
            || ace.Mask != FILE_ALL_ACCESS
            || EqualSid(
                (&ace.SidStart as *const u32).cast_mut().cast(),
                expected_owner,
            ) == 0
        {
            return Err(ERROR.into());
        }
    }
    Ok(())
}

fn open_raw(path: &Path, directory: bool, write: bool, create: bool) -> Result<File, String> {
    let path = wide(path.as_os_str())?;
    let security = Security::new(directory)?;
    let attrs = security.attributes();
    let access = if directory {
        // Attribute-only handles do not participate in all namespace sharing
        // checks. List access makes the no-delete-sharing anchor effective.
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL
    } else if write {
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL
    } else {
        GENERIC_READ | READ_CONTROL
    };
    // No delete sharing: an opened entry cannot be replaced while it is checked.
    // SAFETY: NUL-terminated path, valid security descriptor, owned new handle.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create { &attrs } else { null() },
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ERROR.into());
    }
    // SAFETY: CreateFileW returned a unique owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    let attributes = info(&file)?;
    if attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(ERROR.into());
    }
    Ok(file)
}

/// Anchors each ancestor without following junctions, symlinks or UNC paths.
/// Only the final directory must be private; system ancestors need not be.
pub struct Directory {
    path: PathBuf,
    anchors: Vec<File>,
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self, String> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir().map_err(|_| ERROR)?.join(path)
        };
        let mut current = PathBuf::new();
        let mut anchors = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(prefix)
                    if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
                {
                    current.push(prefix.as_os_str())
                }
                Component::RootDir => {
                    current.push(component.as_os_str());
                    anchors.push(open_raw(&current, true, false, false)?);
                }
                Component::Normal(name) => {
                    if name.to_string_lossy().contains(':') {
                        return Err(ERROR.into());
                    }
                    current.push(name);
                    anchors.push(open_raw(&current, true, false, false)?);
                }
                Component::CurDir => (),
                _ => return Err(ERROR.into()),
            }
        }
        check_private(anchors.last().ok_or(ERROR)?, true)?;
        Ok(Self {
            path: current,
            anchors,
        })
    }
    pub fn create(path: &Path) -> Result<Self, String> {
        // Caller supplies an existing parent. No data is written before the
        // final directory's protected DACL is created and checked.
        let security = Security::new(true)?;
        let attrs = security.attributes();
        let text = wide(path.as_os_str())?;
        // SAFETY: the descriptor outlives this synchronous creation call.
        if unsafe { CreateDirectoryW(text.as_ptr(), &attrs) } == 0 {
            return Err(ERROR.into());
        }
        Self::open(path)
    }
    fn child(&self, name: &OsStr) -> Result<PathBuf, String> {
        let p = Path::new(name);
        let mut components = p.components();
        if !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || name.to_string_lossy().contains(':')
        {
            return Err(ERROR.into());
        }
        self.check()?;
        Ok(self.path.join(name))
    }
    pub fn check(&self) -> Result<(), String> {
        check_private(self.anchors.last().ok_or(ERROR)?, true)
    }
    pub fn create_file(&self, name: &OsStr) -> Result<File, String> {
        let file = open_raw(&self.child(name)?, false, true, true)?;
        check_private(&file, false)?;
        Ok(file)
    }
    pub fn open_file(&self, name: &OsStr, write: bool) -> Result<File, String> {
        let file = open_raw(&self.child(name)?, false, write, false)?;
        check_private(&file, false)?;
        Ok(file)
    }
    pub fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>, String> {
        let file = self.open_file(OsStr::new(name), false)?;
        if file.metadata().map_err(|_| ERROR)?.len() > maximum as u64 {
            return Err(ERROR.into());
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ERROR)?;
        if bytes.len() > maximum {
            return Err(ERROR.into());
        }
        Ok(bytes)
    }
    pub fn write_once(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let mut file = self.create_file(OsStr::new(name))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ERROR)?;
        self.check()
    }
    pub fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.atomic_publish(name, bytes, true, || Ok(()))
    }
    pub fn publish(
        &self,
        name: &str,
        bytes: &[u8],
        before: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        self.atomic_publish(name, bytes, false, before)
    }
    fn atomic_publish(
        &self,
        name: &str,
        bytes: &[u8],
        replace: bool,
        before: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let destination = self.child(OsStr::new(name))?;
        if destination.try_exists().map_err(|_| ERROR)? {
            if !replace {
                return Err("Existing private file is preserved".into());
            }
            drop(self.open_file(OsStr::new(name), false)?);
        }
        let number = TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".miner-{}-{number}.tmp", std::process::id());
        let mut file = self.create_file(OsStr::new(&temporary))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ERROR)?;
        drop(file);
        if let Err(error) = before() {
            let _ = std::fs::remove_file(self.child(OsStr::new(&temporary))?);
            return Err(error);
        }
        let source = wide(self.child(OsStr::new(&temporary))?.as_os_str())?;
        let destination = wide(destination.as_os_str())?;
        // Readers deliberately deny delete sharing during ownership checks.
        // A bounded retry lets a status reader close its checked handle; other
        // errors preserve the temporary rather than weakening file sharing.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // SAFETY: same-directory checked paths; WRITE_THROUGH waits for move.
            if unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_WRITE_THROUGH
                        | if replace {
                            MOVEFILE_REPLACE_EXISTING
                        } else {
                            0
                        },
                )
            } != 0
            {
                break;
            }
            // SAFETY: immediately reads this thread's last native API error.
            let error = unsafe { GetLastError() };
            if !matches!(
                error,
                ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_ACCESS_DENIED
            ) || std::time::Instant::now() >= deadline
            {
                return Err(format!(
                    "Windows atomic replacement failed (error {error}); temporary evidence retained"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        self.check()
    }
}

pub fn create_private(path: &Path) -> Result<File, String> {
    Directory::open(path.parent().ok_or(ERROR)?)?.create_file(path.file_name().ok_or(ERROR)?)
}
pub fn read_private(path: &Path, write: bool) -> Result<File, String> {
    Directory::open(path.parent().ok_or(ERROR)?)?.open_file(path.file_name().ok_or(ERROR)?, write)
}
pub fn visible_memory() -> Result<u64, String> {
    // SAFETY: MEMORYSTATUSEX has the required size and stays writable.
    unsafe {
        let mut data: MEMORYSTATUSEX = zeroed();
        data.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut data) == 0 {
            return Err("Physical memory check unavailable".into());
        }
        Ok(data.ullTotalPhys)
    }
}
unsafe extern "system" fn console_stop(event: u32) -> i32 {
    if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        STOP.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}
pub fn install_stop_handler() -> Result<(), String> {
    // SAFETY: static callback only stores an atomic, never calls runtime APIs.
    if unsafe { SetConsoleCtrlHandler(Some(console_stop), 1) } == 0 {
        return Err("Console cancellation handler unavailable".into());
    }
    Ok(())
}
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temporary() -> PathBuf {
        std::env::temp_dir().join(format!(
            "siworld-win-acl-{}-{}",
            std::process::id(),
            TEMPORARY.fetch_add(1, Ordering::SeqCst)
        ))
    }
    #[test]
    fn owner_only_atomic_files_preserve_existing_evidence() {
        let root = temporary();
        {
            let d = Directory::create(&root).unwrap();
            d.write_once("config", b"first").unwrap();
            assert!(d.write_once("config", b"overwrite").is_err());
            assert_eq!(d.read("config", 5).unwrap(), b"first");
            assert!(d.read("config", 4).is_err());
            d.replace("config", b"second").unwrap();
            assert_eq!(d.read("config", 6).unwrap(), b"second");
            assert!(d.read("../config", 10).is_err());
            assert!(d.write_once("config:stream", b"x").is_err());
            assert!(d.write_once("sub/file", b"x").is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn atomic_status_replacement_waits_for_a_checked_reader() {
        let root = temporary();
        let d = Directory::create(&root).unwrap();
        d.write_once("status", b"first").unwrap();
        let reader = d.open_file(OsStr::new("status"), false).unwrap();
        let path = root.clone();
        let write = std::thread::spawn(move || {
            Directory::open(&path).unwrap().replace("status", b"second")
        });
        std::thread::sleep(std::time::Duration::from_millis(60));
        drop(reader);
        write.join().unwrap().unwrap();
        assert_eq!(d.read("status", 6).unwrap(), b"second");
        drop(d);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_shared_directory_is_not_accepted_as_private() {
        assert!(Directory::open(Path::new("C:\\Users\\Public")).is_err());
    }
}

/// Keeps a handle to the actual foreground process; PID reuse cannot revive it.
pub struct ProcessWatch(File);
impl ProcessWatch {
    pub fn open(pid: u32) -> Result<Self, String> {
        if pid == 0 || pid == std::process::id() {
            return Err("Invalid frontend process identity".into());
        }
        // SAFETY: no handle inheritance; the returned process handle is owned.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            return Err("Frontend process is unavailable".into());
        }
        // SAFETY: unique valid handle; File closes it with CloseHandle.
        Ok(Self(unsafe { File::from_raw_handle(handle) }))
    }
    pub fn is_running(&self) -> bool {
        // SAFETY: handle is kept alive; a zero timeout never blocks.
        unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) == WAIT_TIMEOUT }
    }
}

/// Clear the full console buffer, including its scrollback, on legacy CMD too.
pub fn clear_console() -> Result<(), String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONOUT$")
        .map_err(|_| "Private console unavailable")?;
    // SAFETY: the owned console handle remains live; all outputs are sized.
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = zeroed();
        if GetConsoleScreenBufferInfo(file.as_raw_handle(), &mut info) == 0 {
            return Err("Private console buffer unavailable".into());
        }
        let cells = u32::try_from(info.dwSize.X)
            .ok()
            .and_then(|x| {
                u32::try_from(info.dwSize.Y)
                    .ok()
                    .and_then(|y| x.checked_mul(y))
            })
            .filter(|n| *n <= 16_777_216)
            .ok_or("Console buffer exceeds clearing limit")?;
        let origin = COORD { X: 0, Y: 0 };
        let mut written = 0;
        if FillConsoleOutputCharacterW(file.as_raw_handle(), 32, cells, origin, &mut written) == 0
            || written != cells
            || FillConsoleOutputAttribute(
                file.as_raw_handle(),
                info.wAttributes,
                cells,
                origin,
                &mut written,
            ) == 0
            || written != cells
            || SetConsoleCursorPosition(file.as_raw_handle(), origin) == 0
        {
            return Err("Private console clearing failed".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use std::process::{Command, Stdio};
    fn temporary() -> PathBuf {
        std::env::temp_dir().join(format!(
            "siworld-win-boundary-{}-{}",
            std::process::id(),
            TEMPORARY.fetch_add(1, Ordering::SeqCst)
        ))
    }
    #[test]
    fn broadened_acl_and_hardlinks_fail_closed() {
        let root = temporary();
        {
            let d = Directory::create(&root).unwrap();
            d.write_once("fixture", b"synthetic data").unwrap();
            let alias = root.join("alias");
            std::fs::hard_link(root.join("fixture"), &alias).unwrap();
            assert!(d.read("fixture", 100).is_err());
            std::fs::remove_file(alias).unwrap();
            assert!(
                Command::new("icacls")
                    .arg(root.join("fixture"))
                    .args(["/grant", "*S-1-1-0:R"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(d.read("fixture", 100).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn junctions_and_live_directory_replacement_are_rejected() {
        let root = temporary();
        let alias = temporary();
        {
            let _d = Directory::create(&root).unwrap();
            assert!(
                Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(&alias)
                    .arg(&root)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(Directory::open(&alias).is_err());
            assert!(std::fs::rename(&root, temporary()).is_err());
            std::fs::remove_dir(alias).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
}

/// Unicode output goes directly to the console, independently of its code page
/// and redirected stdout/stderr. Intended for the interactive backup view.
pub struct Console(File);
impl Console {
    pub fn columns(&self) -> Option<usize> {
        // SAFETY: the owned console handle and fully sized output stay live.
        unsafe {
            let mut info: CONSOLE_SCREEN_BUFFER_INFO = zeroed();
            if GetConsoleScreenBufferInfo(self.0.as_raw_handle(), &mut info) == 0 {
                return None;
            }
            usize::try_from((info.srWindow.Right - info.srWindow.Left + 1).min(info.dwSize.X)).ok()
        }
    }

    pub fn open() -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONOUT$")
            .map_err(|_| "Trusted console unavailable")?;
        let mut mode = 0;
        // SAFETY: the owned console handle and output pointer remain valid.
        if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } == 0 {
            return Err("Trusted console mode unavailable".into());
        }
        Ok(Self(file))
    }
}
impl Write for Console {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let text = std::str::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Console output requires complete UTF-8",
            )
        })?;
        let wide = text.encode_utf16().collect::<Vec<_>>();
        let mut offset = 0;
        while offset < wide.len() {
            let count = (wide.len() - offset).min(16384) as u32;
            let mut written = 0;
            // SAFETY: the UTF-16 slice is initialized, bounded and live.
            if unsafe {
                WriteConsoleW(
                    self.0.as_raw_handle(),
                    wide.as_ptr().add(offset).cast(),
                    count,
                    &mut written,
                    null(),
                )
            } == 0
                || written == 0
                || written > count
            {
                return Err(std::io::Error::other("Console output failed"));
            }
            offset += written as usize;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
