//! Atomic output publication: private temp file beside the target, identity
//! re-verified, fsync, rename.

use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct AtMetadata {
    mode: u32,
    owner: u32,
    identity: FileIdentity,
}

impl AtMetadata {
    fn is_file(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// A private temp file created beside a target path, published to that path
/// with an identity-verified `rename(2)` on `commit`. If never committed (or
/// if `commit` fails), the temp file is unlinked by `Drop`.
pub struct AtomicFile {
    directory: std::fs::File,
    temp_file: std::fs::File,
    temp_name: CString,
    final_name: CString,
    final_path: PathBuf,
    identity: FileIdentity,
    cleanup: bool,
}

impl AtomicFile {
    /// Opens the parent directory and creates `.p11scope.<pid>.<seq>.tmp`
    /// beside `path` with `openat(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o600)`,
    /// retrying seq 0..128 on collision.
    pub fn create(path: &Path) -> Result<AtomicFile, String> {
        let final_path = normalize_output_path(path.to_path_buf())?;
        let directory_path = final_path
            .parent()
            .ok_or_else(|| format!("output {} has no parent", final_path.display()))?;
        let directory = open_output_directory(directory_path)?;
        let final_name = final_path
            .file_name()
            .ok_or_else(|| format!("output {} has no file name", final_path.display()))?;
        let final_name = c_name(final_name, "output file name")?;
        for sequence in 0..128u32 {
            let temp_name =
                CString::new(format!(".p11scope.{}.{}.tmp", std::process::id(), sequence))
                    .expect("generated temporary output name has no NUL");
            match openat_profile(&directory, &temp_name) {
                Ok(temp_file) => {
                    let metadata = temp_file.metadata().map_err(|error| {
                        format!(
                            "checking temporary output beside {} failed: {error}",
                            final_path.display()
                        )
                    })?;
                    if !metadata.is_file() {
                        let _ = unlinkat(&directory, &temp_name);
                        return Err(format!(
                            "temporary output beside {} is not a regular file",
                            final_path.display()
                        ));
                    }
                    let identity = FileIdentity::from_metadata(&metadata);
                    return Ok(Self {
                        directory,
                        temp_file,
                        temp_name,
                        final_name,
                        final_path,
                        identity,
                        cleanup: true,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "creating temporary output beside {} failed: {error}",
                        final_path.display()
                    ));
                }
            }
        }
        Err(format!(
            "cannot allocate a unique temporary output beside {}",
            final_path.display()
        ))
    }

    pub fn file(&mut self) -> &mut std::fs::File {
        &mut self.temp_file
    }

    /// Re-verifies the temp identity (regular file, same dev/ino, owner ==
    /// euid, mode & 0o077 == 0), `sync_all`, then `renameat` over the final
    /// name. On any error the temp file is unlinked by `Drop`.
    pub fn commit(mut self) -> Result<(), String> {
        self.verify_temp_identity()?;
        self.temp_file.sync_all().map_err(|error| {
            format!(
                "syncing temporary output beside {} failed: {error}",
                self.final_path.display()
            )
        })?;
        renameat(
            &self.directory,
            &self.temp_name,
            &self.directory,
            &self.final_name,
        )
        .map_err(|error| {
            format!(
                "publishing output {} failed: {error}",
                self.final_path.display()
            )
        })?;
        self.directory.sync_all().map_err(|error| {
            format!(
                "syncing output directory for {} failed: {error}",
                self.final_path.display()
            )
        })?;
        self.cleanup = false;
        Ok(())
    }

    fn verify_temp_identity(&self) -> Result<(), String> {
        let metadata = metadata_at(&self.directory, &self.temp_name).map_err(|error| {
            format!(
                "temporary output identity check for {} failed: {error}",
                self.final_path.display()
            )
        })?;
        let current = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.identity != self.identity
            || metadata.owner != current
            || metadata.mode & 0o077 != 0
        {
            return Err(format!(
                "temporary output identity/owner/mode for {} does not match the retained private regular file",
                self.final_path.display()
            ));
        }
        let held = self.temp_file.metadata().map_err(|error| {
            format!(
                "checking retained temporary output for {} failed: {error}",
                self.final_path.display()
            )
        })?;
        if !held.is_file()
            || FileIdentity::from_metadata(&held) != self.identity
            || held.uid() != current
            || held.mode() & 0o077 != 0
        {
            return Err(format!(
                "retained temporary output identity/owner/mode for {} changed",
                self.final_path.display()
            ));
        }
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.cleanup
            && metadata_at(&self.directory, &self.temp_name).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.identity == self.identity
                    && metadata.owner == unsafe { libc::geteuid() }
                    && metadata.mode & 0o077 == 0
            })
        {
            let _ = unlinkat(&self.directory, &self.temp_name);
        }
    }
}

/// Opens (creating/truncating) a private regular file for an appended line
/// stream — trace `-o`, which streams lines as they arrive and so cannot be
/// published atomically like `AtomicFile`. O_NOFOLLOW on the final component
/// (a planted symlink at the target is refused, not followed), mode 0600, and
/// the opened descriptor must be a regular file (no FIFOs or devices).
pub fn create_private_stream(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("opening output {} failed: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("checking output {} failed: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("output {} is not a regular file", path.display()));
    }
    // A pre-existing target keeps its old mode through O_TRUNC; make it private too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("setting output {} private failed: {error}", path.display()))?;
    Ok(file)
}

fn normalize_output_path(path: PathBuf) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("resolving relative output failed: {error}"))?
            .join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::ParentDir => {
                return Err("output must not contain a .. parent component".into());
            }
            std::path::Component::Prefix(_) => {
                return Err("output uses an unsupported path prefix".into());
            }
        }
    }
    if normalized.file_name().is_none() {
        return Err(format!("output {} has no file name", normalized.display()));
    }
    Ok(normalized)
}

fn c_name(name: &OsStr, label: &str) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| format!("{label} contains a NUL byte"))
}

fn open_output_directory(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)
        .map_err(|error| {
            format!(
                "opening output directory {} failed: {error}",
                path.display()
            )
        })
}

fn openat_profile(directory: &std::fs::File, name: &CString) -> std::io::Result<std::fs::File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

fn metadata_at(directory: &std::fs::File, name: &CString) -> std::io::Result<AtMetadata> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(AtMetadata {
        mode: stat.st_mode,
        owner: stat.st_uid,
        identity: FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        },
    })
}

fn renameat(
    old_directory: &std::fs::File,
    old_name: &CString,
    new_directory: &std::fs::File,
    new_name: &CString,
) -> std::io::Result<()> {
    if unsafe {
        libc::renameat(
            old_directory.as_raw_fd(),
            old_name.as_ptr(),
            new_directory.as_raw_fd(),
            new_name.as_ptr(),
        )
    } == -1
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unlinkat(directory: &std::fs::File, name: &CString) -> std::io::Result<()> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn private_stream_refuses_a_symlinked_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.path().join("trace.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_private_stream(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn private_stream_creates_0600_and_truncates_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.log");
        let mut file = create_private_stream(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::io::Write::write_all(&mut file, b"first").unwrap();
        drop(file);
        // A pre-existing, world-readable target is truncated and made private.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(create_private_stream(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn commit_publishes_atomically_and_replaces_stale_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(&path, b"stale").unwrap();
        let mut a = AtomicFile::create(&path).unwrap();
        std::io::Write::write_all(a.file(), b"{\"ok\":true}").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"stale",
            "not visible before commit"
        );
        a.commit().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp left"
        );
    }

    #[test]
    fn temp_is_private_and_removed_when_not_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        {
            let mut a = AtomicFile::create(&path).unwrap();
            let temp = std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(temp.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            std::io::Write::write_all(a.file(), b"partial").unwrap();
        }
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn commit_fails_and_cleans_up_when_the_temp_was_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let mut a = AtomicFile::create(&path).unwrap();
        std::io::Write::write_all(a.file(), b"x").unwrap();
        let temp = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::remove_file(&temp).unwrap();
        std::fs::write(&temp, b"impostor").unwrap(); // different inode at the temp name
        assert!(a.commit().is_err());
        assert_eq!(
            std::fs::read(&temp).unwrap(),
            b"impostor",
            "Drop must not unlink a file it did not create"
        );
        assert!(!path.exists());
    }
}
