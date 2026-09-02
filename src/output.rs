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
        // The report is published at this point; a directory fsync that the
        // filesystem cannot honour must not turn a complete run into a failure.
        let _ = self.directory.sync_all();
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
/// published atomically like `AtomicFile`. The parent is retained without
/// following any path symlink, and O_NOFOLLOW protects the final component
/// too. O_NONBLOCK makes a planted FIFO fail instead of blocking, mode 0600.
/// An existing target is only truncated after it proved to be a regular file
/// owned by the caller; its mode is then made private too.
pub fn create_private_stream(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::PermissionsExt as _;
    if path.as_os_str().as_bytes().last() == Some(&b'/') {
        return Err(format!("output {} has no file name", path.display()));
    }
    let final_path = normalize_output_path(path.to_path_buf())?;
    let directory_path = final_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = open_output_directory(directory_path)?;
    let final_name = final_path
        .file_name()
        .ok_or_else(|| format!("output {} has no file name", final_path.display()))?;
    let final_name = c_name(final_name, "output file name")?;
    let file = openat_stream(&directory, &final_name)
        .map_err(|error| format!("opening output {} failed: {error}", final_path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("checking output {} failed: {error}", final_path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "output {} is not a regular file",
            final_path.display()
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!(
            "output {} exists and is owned by uid {}; refusing to overwrite it",
            final_path.display(),
            metadata.uid()
        ));
    }
    file.set_len(0)
        .map_err(|error| format!("truncating output {} failed: {error}", final_path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            format!(
                "setting output {} private failed: {error}",
                final_path.display()
            )
        })?;
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
    open_output_directory_with(path, openat2_directory)
}

fn open_output_directory_with<F>(path: &Path, openat2: F) -> Result<std::fs::File, String>
where
    F: FnOnce(&Path) -> std::io::Result<std::fs::File>,
{
    let display = path.display().to_string();
    match openat2(path) {
        Ok(opened) => {
            let walked = open_directory_nofollow_walk(path)
                .map_err(|error| format!("opening output directory {display} failed: {error}"))?;
            let opened_identity =
                FileIdentity::from_metadata(&opened.metadata().map_err(|error| {
                    format!("checking output directory {display} failed: {error}")
                })?);
            let walked_identity =
                FileIdentity::from_metadata(&walked.metadata().map_err(|error| {
                    format!("checking output directory {display} failed: {error}")
                })?);
            if opened_identity != walked_identity {
                return Err(format!(
                    "opening output directory {display} failed: retained directory identity changed"
                ));
            }
            Ok(opened)
        }
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == libc::ENOSYS || code == libc::EPERM) => {
            open_directory_nofollow_walk(path)
                .map_err(|error| format!("opening output directory {display} failed: {error}"))
        }
        Err(error) => Err(format!(
            "opening output directory {display} failed: {error}"
        )),
    }
}

fn openat2_directory(path: &Path) -> std::io::Result<std::fs::File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    // SAFETY: open_how is a plain kernel input struct; zero initializes all
    // fields not used by this call, including future non-exhaustive fields.
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd as _) })
    }
}

fn open_directory_nofollow_walk(path: &Path) -> std::io::Result<std::fs::File> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output directory walk requires an absolute path",
        ));
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let root = CString::new("/").expect("root has no NUL");
    let fd = unsafe { libc::open(root.as_ptr(), flags) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let mut directory = unsafe { std::fs::File::from_raw_fd(fd) };
    validate_trusted_directory(&directory, Path::new("/"))?;
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "output directory walk rejects parent or prefix components",
                    ));
                }
                std::path::Component::Normal(_) => unreachable!(),
            }
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path component contains a NUL byte",
            )
        })?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let next = unsafe { std::fs::File::from_raw_fd(fd) };
        current.push(OsStr::from_bytes(name.as_bytes()));
        validate_trusted_directory(&next, &current)?;
        directory = next;
    }
    Ok(directory)
}

fn validate_trusted_directory(directory: &std::fs::File, path: &Path) -> std::io::Result<()> {
    let metadata = directory.metadata()?;
    let mode = metadata.mode();
    if mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "output directory ancestor {} is untrusted: not a directory",
                path.display()
            ),
        ));
    }
    if mode & 0o022 != 0 && mode & libc::S_ISVTX == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "output directory ancestor {} is untrusted: writable",
                path.display()
            ),
        ));
    }
    let euid = unsafe { libc::geteuid() } as u32;
    let owner = metadata.uid();
    let owner_trusted = owner == euid || owner == 0 || (euid == 0 && sudo_uid() == Some(owner));
    if !owner_trusted {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "output directory ancestor {} is untrusted: owned by uid {}",
                path.display(),
                owner
            ),
        ));
    }
    Ok(())
}

fn sudo_uid() -> Option<u32> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let value = std::env::var_os("SUDO_UID")?;
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let uid = value.to_str()?.parse::<u32>().ok()?;
    if uid == 0 || uid == u32::MAX || !uid_has_account(uid) {
        return None;
    }
    Some(uid)
}

fn uid_has_account(uid: u32) -> bool {
    let mut account = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut account,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    status == 0 && !result.is_null()
}

fn openat_stream(directory: &std::fs::File, name: &CString) -> std::io::Result<std::fs::File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
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

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn private_stream_refuses_a_symlinked_target() {
        let dir = private_tempdir();
        let target = dir.path().join("target");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.path().join("trace.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_private_stream(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn private_stream_refuses_a_symlinked_parent() {
        let dir = private_tempdir();
        let target_dir = dir.path().join("target-dir");
        std::fs::create_dir(&target_dir).unwrap();
        let target = target_dir.join("trace.log");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.path().join("parent");
        std::os::unix::fs::symlink(&target_dir, &link).unwrap();

        assert!(create_private_stream(&link.join("trace.log")).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn private_stream_refuses_a_fifo_without_blocking() {
        let dir = private_tempdir();
        let fifo = dir.path().join("trace.log");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // No reader exists: a blocking open would hang here.
        assert!(create_private_stream(&fifo).is_err());
    }

    #[test]
    fn private_stream_creates_0600_and_truncates_an_existing_file() {
        let dir = private_tempdir();
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
        let dir = private_tempdir();
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
    fn atomic_file_refuses_a_symlinked_parent() {
        let dir = private_tempdir();
        let target_dir = dir.path().join("target-dir");
        std::fs::create_dir(&target_dir).unwrap();
        let target = target_dir.join("observed.json");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.path().join("parent");
        std::os::unix::fs::symlink(&target_dir, &link).unwrap();

        assert!(AtomicFile::create(&link.join("observed.json")).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn output_refuses_a_symlinked_intermediate_ancestor() {
        let dir = private_tempdir();
        let target_dir = dir.path().join("target-dir");
        let target = target_dir.join("nested/observed.json");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.path().join("ancestor");
        std::os::unix::fs::symlink(&target_dir, &link).unwrap();
        let path = link.join("nested/observed.json");

        assert!(AtomicFile::create(&path).is_err());
        assert!(create_private_stream(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn both_sinks_reject_parent_components_without_touching_target() {
        let dir = private_tempdir();
        let safe = dir.path().join("safe");
        let protected = dir.path().join("protected");
        std::fs::create_dir(&safe).unwrap();
        std::fs::create_dir(&protected).unwrap();
        let target = protected.join("trace.log");
        std::fs::write(&target, b"do not touch").unwrap();
        let path = safe.join("../protected/trace.log");

        assert!(AtomicFile::create(&path).is_err());
        assert!(create_private_stream(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }

    #[test]
    fn output_refuses_a_group_or_world_writable_ancestor() {
        let dir = private_tempdir();
        let ancestor = dir.path().join("ancestor");
        std::fs::create_dir(&ancestor).unwrap();
        let path = ancestor.join("observed.json");

        for mode in [0o775, 0o707] {
            std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = AtomicFile::create(&path)
                .err()
                .expect("writable ancestor must refuse");
            assert!(error.contains("ancestor"), "{error}");
            assert!(error.contains("untrusted"), "{error}");
            let error = create_private_stream(&path).unwrap_err();
            assert!(error.contains("ancestor"), "{error}");
            assert!(error.contains("untrusted"), "{error}");
        }

        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(AtomicFile::create(&path).unwrap());
        drop(create_private_stream(&ancestor.join("trace.log")).unwrap());

        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o1707)).unwrap();
        drop(AtomicFile::create(&ancestor.join("sticky.json")).unwrap());
        drop(create_private_stream(&ancestor.join("sticky.log")).unwrap());
    }

    #[test]
    fn root_owner_is_accepted_but_unrelated_owner_is_rejected() {
        let dir = private_tempdir();
        let root_owned = dir.path().join("root-owned");
        std::fs::create_dir(&root_owned).unwrap();
        std::fs::set_permissions(&root_owned, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root_owned.join("root.json");

        if unsafe { libc::geteuid() } == 0 {
            let root_path = std::ffi::CString::new(root_owned.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(root_path.as_ptr(), 0, u32::MAX) }, 0);
            drop(AtomicFile::create(&path).unwrap());

            std::fs::set_permissions(&root_owned, std::fs::Permissions::from_mode(0o775)).unwrap();
            let error = AtomicFile::create(&root_owned.join("mode.json"))
                .err()
                .expect("root ownership must not waive the mode rule");
            assert!(error.contains("untrusted"), "{error}");
            std::fs::set_permissions(&root_owned, std::fs::Permissions::from_mode(0o700)).unwrap();

            let foreign = dir.path().join("foreign-owned");
            std::fs::create_dir(&foreign).unwrap();
            std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o700)).unwrap();
            let sudo_uid = std::env::var_os("SUDO_UID")
                .and_then(|value| value.to_str().and_then(|value| value.parse::<u32>().ok()))
                .filter(|uid| *uid != 0 && *uid != u32::MAX);
            let foreign_uid = [1, 2, 3]
                .into_iter()
                .find(|uid| Some(*uid) != sudo_uid)
                .expect("a foreign fixture uid must be available");
            let foreign_path = std::ffi::CString::new(foreign.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(foreign_path.as_ptr(), foreign_uid, u32::MAX) },
                0
            );
            let error = AtomicFile::create(&foreign.join("foreign.json"))
                .err()
                .expect("unrelated ownership must refuse");
            assert!(error.contains("untrusted"), "{error}");

            if let Some(sudo_uid) = sudo_uid.filter(|uid| uid_has_account(*uid)) {
                let sudo_owned = dir.path().join("sudo-owned");
                std::fs::create_dir(&sudo_owned).unwrap();
                std::fs::set_permissions(&sudo_owned, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let sudo_path = std::ffi::CString::new(sudo_owned.as_os_str().as_bytes()).unwrap();
                assert_eq!(
                    unsafe { libc::chown(sudo_path.as_ptr(), sudo_uid, u32::MAX) },
                    0
                );
                assert!(
                    open_output_directory(&sudo_owned).is_ok(),
                    "validated SUDO_UID owner must be accepted"
                );
                drop(AtomicFile::create(&sudo_owned.join("sudo.json")).unwrap());
            }
        } else {
            drop(AtomicFile::create(&path).unwrap());
        }
    }

    #[test]
    fn the_nofollow_walk_fallback_matches_openat2_and_refuses_the_same_symlinks() {
        let dir = private_tempdir();
        let real = dir.path().join("real");
        let nested = real.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        let openat2 = open_output_directory(&nested).unwrap();
        let walk = open_directory_nofollow_walk(&nested).unwrap();
        assert_eq!(
            (
                openat2.metadata().unwrap().dev(),
                openat2.metadata().unwrap().ino()
            ),
            (
                walk.metadata().unwrap().dev(),
                walk.metadata().unwrap().ino()
            )
        );

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_directory_nofollow_walk(&link.join("nested")).is_err());
        assert!(open_directory_nofollow_walk(Path::new("/proc/self/fd/1")).is_err());

        for errno in [libc::EPERM, libc::ENOSYS] {
            let fallback = open_output_directory_with(&nested, |_| {
                Err(std::io::Error::from_raw_os_error(errno))
            })
            .unwrap();
            assert_eq!(
                (
                    fallback.metadata().unwrap().dev(),
                    fallback.metadata().unwrap().ino()
                ),
                (
                    walk.metadata().unwrap().dev(),
                    walk.metadata().unwrap().ino()
                )
            );
            assert!(
                open_output_directory_with(&link.join("nested"), |_| {
                    Err(std::io::Error::from_raw_os_error(errno))
                })
                .is_err()
            );
        }
    }

    #[test]
    fn temp_is_private_and_removed_when_not_committed() {
        let dir = private_tempdir();
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
        let dir = private_tempdir();
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
