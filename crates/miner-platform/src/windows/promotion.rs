//! Promote one already sealed private file without buffering or replacement.
use super::*;

/// Success retains a checked handle that denies replacement until the caller
/// reopens the admitted file. Any failure after a successful move is distinct
/// from a pre-admission error; callers must never retry by replacing the target.
pub enum Promotion {
    Durable(File),
    DurabilityUnconfirmed,
}
impl Directory {
    /// Both names belong to this anchored directory. Existing targets survive.
    /// The caller closes the sealed writer before invoking this method and must
    /// authenticate its own format again while retaining the returned handle.
    pub fn promote_existing(
        &self,
        source: &str,
        destination: &str,
        expected: (u32, u64),
    ) -> Result<Promotion, String> {
        let source_path = self.child(OsStr::new(source))?;
        let destination_path = self.child(OsStr::new(destination))?;
        if source_path == destination_path || source.eq_ignore_ascii_case(destination) {
            return Err("Private file promotion requires distinct names".into());
        }
        let file = self.open_file(OsStr::new(source), true)?;
        if file_identity(&file)? != expected {
            return Err("Private candidate file identity changed before admission".into());
        }
        file.sync_all()
            .map_err(|_| "Private candidate flush failed")?;
        // Checked file handles deny delete sharing. Recheck the exact identity
        // after the same-directory write-through move and retain that handle.
        drop(file);
        let source_path = wide(source_path.as_os_str())?;
        let destination_path = wide(destination_path.as_os_str())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            self.check()?;
            // SAFETY: anchored same-directory paths; replacement/copy flags are
            // absent, and WRITE_THROUGH completes the move before returning.
            if unsafe {
                MoveFileExW(
                    source_path.as_ptr(),
                    destination_path.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            } != 0
            {
                break;
            }
            // SAFETY: immediately reads this thread's native operation error.
            let error = unsafe { GetLastError() };
            if !matches!(
                error,
                ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_ACCESS_DENIED
            ) || std::time::Instant::now() >= deadline
            {
                return Err(format!(
                    "Private nonreplacing admission failed (error {error}); candidate retained"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let admitted = (|| {
            let file = self.open_file(OsStr::new(destination), true)?;
            if file_identity(&file)? != expected {
                return Err("Admitted private file identity differs".to_owned());
            }
            file.sync_all()
                .map_err(|_| "Admitted private file flush failed")?;
            self.check()?;
            Ok(file)
        })();
        Ok(match admitted {
            Ok(file) => Promotion::Durable(file),
            Err(_) => Promotion::DurabilityUnconfirmed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_file_promotion_pins_identity_and_preserves_an_existing_target() {
        let path = super::super::tests::temporary();
        let directory = Directory::create(&path).unwrap();
        directory
            .write_once("candidate", b"synthetic sealed database")
            .unwrap();
        let expected =
            file_identity(&directory.open_file(OsStr::new("candidate"), false).unwrap()).unwrap();
        assert!(
            directory
                .promote_existing("candidate", "canonical", (expected.0, expected.1 ^ 1))
                .is_err()
        );
        assert!(!path.join("canonical").exists());
        let Promotion::Durable(pin) = directory
            .promote_existing("candidate", "canonical", expected)
            .unwrap()
        else {
            panic!("synthetic admission uncertainty")
        };
        assert_eq!(file_identity(&pin).unwrap(), expected);
        assert_eq!(
            directory.read("canonical", 64).unwrap(),
            b"synthetic sealed database"
        );
        assert!(!path.join("candidate").exists());
        drop(pin);
        directory
            .write_once("candidate", b"second candidate")
            .unwrap();
        let second =
            file_identity(&directory.open_file(OsStr::new("candidate"), false).unwrap()).unwrap();
        assert!(
            directory
                .promote_existing("candidate", "canonical", second)
                .is_err()
        );
        assert_eq!(
            directory.read("canonical", 64).unwrap(),
            b"synthetic sealed database"
        );
        assert_eq!(
            directory.read("candidate", 64).unwrap(),
            b"second candidate"
        );
        assert!(
            directory
                .promote_existing("candidate", "candidate", second)
                .is_err()
        );
        drop(directory);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn linked_candidates_are_rejected_without_moving_or_removing_evidence() {
        let path = super::super::tests::temporary();
        let directory = Directory::create(&path).unwrap();
        directory
            .write_once("candidate", b"synthetic linked file")
            .unwrap();
        let expected =
            file_identity(&directory.open_file(OsStr::new("candidate"), false).unwrap()).unwrap();
        std::fs::hard_link(path.join("candidate"), path.join("alias")).unwrap();
        assert!(
            directory
                .promote_existing("candidate", "canonical", expected)
                .is_err()
        );
        assert!(!path.join("canonical").exists());
        assert!(path.join("candidate").exists() && path.join("alias").exists());
        drop(directory);
        std::fs::remove_dir_all(path).unwrap();
    }
}
