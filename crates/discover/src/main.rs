//! SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope-discover — unprivileged short-lived discovery helper.
//! Design: v1 behavior when discovery fails is report-and-exit-nonzero;
//! never silently proceed (design spec, Architecture).

use std::fs::File;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::process::Command;

const USAGE: &str = "usage: p11scope-discover --module <provider.so> [-o manifest.json]\n       p11scope-discover --version";

#[derive(Clone, Copy)]
struct DropTarget {
    uid: libc::uid_t,
    gid: libc::gid_t,
    credential_transition: bool,
}

fn active_caps() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return u64::MAX;
    };
    let mut caps = 0u64;
    let mut seen = 0;
    for line in status.lines() {
        let value = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            .into_iter()
            .find_map(|prefix| line.strip_prefix(prefix));
        let Some(value) = value else { continue };
        let Ok(value) = u64::from_str_radix(value.trim(), 16) else {
            return u64::MAX;
        };
        caps |= value;
        seen += 1;
    }
    if seen == 4 { caps } else { u64::MAX }
}

fn target_id(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()?
        .parse()
        .ok()
        .filter(|value| *value != 0 && *value != u32::MAX)
}

fn current_ids() -> Result<([libc::uid_t; 3], [libc::gid_t; 3]), String> {
    let mut uids = [0; 3];
    let mut gids = [0; 3];
    if unsafe { libc::getresuid(&mut uids[0], &mut uids[1], &mut uids[2]) } != 0
        || unsafe { libc::getresgid(&mut gids[0], &mut gids[1], &mut gids[2]) } != 0
    {
        return Err(format!(
            "cannot read discovery credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((uids, gids))
}

fn prepare_drop() -> Result<DropTarget, String> {
    let (uids, gids) = current_ids()?;
    if uids[1] == 0 {
        return Ok(DropTarget {
            uid: target_id("SUDO_UID").unwrap_or(65_534),
            gid: target_id("SUDO_GID").unwrap_or(65_534),
            credential_transition: true,
        });
    }
    if uids != [uids[1]; 3] || gids != [gids[1]; 3] || gids[1] == 0 {
        return Err("refusing discovery with set-id credentials".into());
    }
    Ok(DropTarget {
        uid: uids[1],
        gid: gids[1],
        credential_transition: false,
    })
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_capabilities() -> Result<(), String> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(format!(
            "cannot clear discovery capabilities: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_dumpable_zero() -> Result<(), String> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot disable discovery dumpability: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("discovery process remained dumpable".into());
    }
    Ok(())
}

fn close_range_syscall() -> io::Result<()> {
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn close_fd(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn collect_proc_fd_snapshot(path: &std::path::Path) -> io::Result<(RawFd, Vec<RawFd>)> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in fd directory path"))?;
    let directory = unsafe { libc::opendir(path.as_ptr()) };
    if directory.is_null() {
        return Err(io::Error::last_os_error());
    }
    let collection = (|| -> io::Result<(RawFd, Vec<RawFd>)> {
        let enumeration_fd = unsafe { libc::dirfd(directory) };
        if enumeration_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fds = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error().is_some_and(|errno| errno != 0) {
                    return Err(error);
                }
                break;
            }
            let name =
                unsafe { std::ffi::CStr::from_ptr(std::ptr::addr_of!((*entry).d_name).cast()) };
            if !name.to_bytes().is_empty() && name.to_bytes().iter().all(u8::is_ascii_digit) {
                let fd = name.to_string_lossy().parse::<RawFd>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid numeric fd directory entry",
                    )
                })?;
                if fd > 2 {
                    fds.push(fd);
                }
            }
        }
        Ok((enumeration_fd, fds))
    })();
    let close = if unsafe { libc::closedir(directory) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    match (collection, close) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn close_inherited_descriptors_with<R, S, C>(
    close_range: R,
    snapshot: S,
    close: C,
) -> io::Result<()>
where
    R: FnOnce() -> io::Result<()>,
    S: FnOnce() -> io::Result<(RawFd, Vec<RawFd>)>,
    C: Fn(RawFd) -> io::Result<()>,
{
    match close_range() {
        Ok(()) => return Ok(()),
        Err(error) if !matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
            return Err(error);
        }
        Err(_) => {}
    }

    let (enumeration_fd, mut fds) = snapshot()?;
    if enumeration_fd <= 2 || !fds.contains(&enumeration_fd) {
        return Err(io::Error::other(
            "incomplete /proc/self/fd snapshot omitted its enumeration descriptor",
        ));
    }
    fds.sort_unstable();
    for fd in fds {
        if let Err(error) = close(fd) {
            if fd == enumeration_fd && error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
    }
    Ok(())
}

fn close_inherited_descriptors() -> io::Result<()> {
    close_inherited_descriptors_with(
        close_range_syscall,
        || collect_proc_fd_snapshot(std::path::Path::new("/proc/self/fd")),
        close_fd,
    )
}

const LOADER_SENSITIVE_ENV: &[&str] = &[
    "GCONV_PATH",
    "GETCONF_DIR",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LD_AUDIT",
    "LD_BIND_NOT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_LIBRARY_PATH",
    "LD_ORIGIN_PATH",
    "LD_PRELOAD",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_ARENA_MAX",
    "MALLOC_ARENA_TEST",
    "MALLOC_CHECK_",
    "MALLOC_MMAP_MAX_",
    "MALLOC_MMAP_THRESHOLD_",
    "MALLOC_PERTURB_",
    "MALLOC_TOP_PAD_",
    "MALLOC_TRACE",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TMPDIR",
    "TZDIR",
];

const SANITIZED_ENV_MARKER: &str = "P11SCOPE_LOADER_ENV_SANITIZED";

fn ensure_loader_env_sanitized() -> io::Result<()> {
    let present = LOADER_SENSITIVE_ENV
        .iter()
        .any(|name| std::env::var_os(name).is_some());
    let marked = std::env::var_os(SANITIZED_ENV_MARKER).is_some();
    if marked && present {
        return Err(io::Error::other(
            "sanitized marker with loader-sensitive environment",
        ));
    }
    if !present {
        return Ok(());
    }

    let mut command = Command::new("/proc/self/exe");
    command
        .args(std::env::args_os().skip(1))
        .env(SANITIZED_ENV_MARKER, "1");
    for name in LOADER_SENSITIVE_ENV {
        command.env_remove(name);
    }
    Err(std::os::unix::process::CommandExt::exec(&mut command))
}

/// Provider constructors and exports must never inherit observer authority.
fn drop_privileges_and_open_self_memory(target: DropTarget) -> Result<File, String> {
    close_inherited_descriptors()
        .map_err(|e| format!("inherited descriptor closure failed: {e}"))?;
    ensure_loader_env_sanitized()
        .map_err(|e| format!("loader environment sanitization failed: {e}"))?;
    if target.credential_transition {
        set_dumpable_zero()?;
    }
    // This is the post-exec address space. Root can open its nondumpable mem;
    // the already-unprivileged standalone lane must preopen before making
    // itself nondumpable and is never hostile-target authority.
    let self_memory =
        File::open("/proc/self/mem").map_err(|error| format!("/proc/self/mem: {error}"))?;
    if target.credential_transition && unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(format!(
            "cannot drop discovery privileges: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setresgid(target.gid, target.gid, target.gid) } != 0 {
        return Err(format!(
            "cannot drop discovery privileges: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setresuid(target.uid, target.uid, target.uid) } != 0 {
        return Err(format!(
            "cannot drop discovery privileges: {}",
            std::io::Error::last_os_error()
        ));
    }
    set_dumpable_zero()?;
    clear_capabilities()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err("discovery no_new_privs verification failed".into());
    }
    set_dumpable_zero()?;
    let (uids, gids) = current_ids()?;
    let fsuid = unsafe { libc::setfsuid(u32::MAX) };
    let fsgid = unsafe { libc::setfsgid(u32::MAX) };
    if uids != [target.uid; 3]
        || gids != [target.gid; 3]
        || fsuid as libc::uid_t != target.uid
        || fsgid as libc::gid_t != target.gid
        || target.uid == 0
        || target.gid == 0
        || active_caps() != 0
    {
        return Err(
            "discovery privilege drop did not remove every uid/gid and active capability".into(),
        );
    }
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if group_count == -1 {
        return Err(format!(
            "cannot verify discovery supplementary groups: {}",
            std::io::Error::last_os_error()
        ));
    }
    if target.credential_transition {
        if group_count != 0 {
            return Err("discovery privilege drop retained supplementary groups".into());
        }
    } else if group_count > 0 {
        let mut groups = vec![0; group_count as usize];
        if unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) } != group_count {
            return Err(format!(
                "cannot verify discovery supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
        if groups.contains(&0) {
            return Err("discovery process retained supplementary gid 0".into());
        }
    }
    Ok(self_memory)
}

/// Publishes `bytes` at `path` (F-56): a private (0600) temp file created
/// beside it with `O_CREAT|O_EXCL|O_NOFOLLOW`, fsynced, then renamed over
/// the name. A name that exists and is not a regular file — a symbolic
/// link (dangling or not), FIFO, socket, device or directory — is refused
/// and left as it was, never followed or replaced. The parent directory is
/// the operator's choice and is resolved normally; this process already
/// runs as the dropped, unprivileged identity.
fn write_private_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    write_private_atomically_with(path, bytes, || {})
}

/// `write_private_atomically` with a hook run once the temp file is
/// written, before the name is re-checked and replaced (test seam).
fn write_private_atomically_with(
    path: &std::path::Path,
    bytes: &[u8],
    before_publish: impl FnOnce(),
) -> Result<(), String> {
    use std::ffi::CString;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    let name = path
        .file_name()
        .ok_or_else(|| "the output names no file".to_string())?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    let c = |value: &std::ffi::OsStr| {
        CString::new(value.as_bytes())
            .map_err(|_| "the output path contains a NUL byte".to_string())
    };
    let directory_path = c(parent.as_os_str())?;
    let final_name = c(name)?;
    let fd = unsafe {
        libc::open(
            directory_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    // The directory that holds the file must not be world-writable unless
    // sticky, so no other user can rename or replace the published manifest
    // (review M2). Checked on the opened descriptor every later operation is
    // relative to. Unlike the observer, which runs privileged and also
    // refuses group-writable and symlinked parents, this helper runs as the
    // unprivileged operator: the parent path is theirs to choose, and a
    // group-writable directory (a user-private group under a 002 umask) is
    // accepted.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = directory
            .metadata()
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(format!(
                "directory {} is world-writable without the sticky bit (mode {:o}); \
                 choose a private directory or chmod o-w it",
                parent.display(),
                mode & 0o7777
            ));
        }
    }
    let check_final = || -> Result<(), String> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                final_name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error.to_string())
            };
        }
        let kind = match unsafe { stat.assume_init() }.st_mode & libc::S_IFMT {
            libc::S_IFREG => return Ok(()),
            libc::S_IFLNK => "a symbolic link",
            libc::S_IFDIR => "a directory",
            libc::S_IFIFO => "a FIFO",
            libc::S_IFSOCK => "a socket",
            libc::S_IFCHR | libc::S_IFBLK => "a device",
            _ => "not a regular file",
        };
        Err(format!("it exists and is {kind}; refusing to replace it"))
    };
    check_final()?;
    let (temp_name, mut temp) = (0..128u32)
        .find_map(|sequence| {
            let temp_name = CString::new(format!(
                ".p11scope-discover.{}.{sequence}.tmp",
                std::process::id()
            ))
            .expect("a generated name has no NUL");
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    temp_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd == -1 {
                let error = io::Error::last_os_error();
                return (error.raw_os_error() != Some(libc::EEXIST)).then_some(Err(error));
            }
            Some(Ok((temp_name, unsafe { File::from_raw_fd(fd) })))
        })
        .ok_or_else(|| "cannot allocate a temporary file beside it".to_string())?
        .map_err(|error| error.to_string())?;
    let published = temp
        .write_all(bytes)
        .and_then(|()| temp.sync_all())
        .map_err(|error| error.to_string())
        .and_then(|()| {
            before_publish();
            check_final()
        })
        .and_then(|()| {
            if unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temp_name.as_ptr(),
                    directory.as_raw_fd(),
                    final_name.as_ptr(),
                )
            } == -1
            {
                Err(io::Error::last_os_error().to_string())
            } else {
                Ok(())
            }
        });
    if published.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    published
}

fn main() {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1).peekable();
    // Like `p11scope --version`: the whole command line, answered before any
    // privilege handling or provider access.
    if matches!(args.peek().map(String::as_str), Some("--version" | "-V")) {
        args.next();
        if args.next().is_some() {
            eprintln!("--version takes no arguments\n{USAGE}");
            std::process::exit(2);
        }
        println!("p11scope-discover {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    while let Some(a) = args.next() {
        match a.as_str() {
            "--module" => match args.next() {
                Some(v) => module = Some(PathBuf::from(v)),
                None => {
                    eprintln!("--module requires a value\n{USAGE}");
                    std::process::exit(2);
                }
            },
            "-o" => match args.next() {
                Some(v) => out = Some(PathBuf::from(v)),
                None => {
                    eprintln!("-o requires a value\n{USAGE}");
                    std::process::exit(2);
                }
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let Some(module) = module else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    if !module.is_absolute() {
        eprintln!("--module must be an absolute path\n{USAGE}");
        std::process::exit(2);
    }
    let drop_target = match prepare_drop() {
        Ok(target) => target,
        Err(error) => {
            eprintln!("p11scope-discover: {error}");
            std::process::exit(1);
        }
    };
    let self_memory = match drop_privileges_and_open_self_memory(drop_target) {
        Ok(memory) => memory,
        Err(error) => {
            eprintln!("p11scope-discover: {error}");
            std::process::exit(1);
        }
    };
    match p11scope_discover::discover::discover_with_self_memory(&module, self_memory) {
        Err(e) => {
            eprintln!("p11scope-discover: {e}");
            std::process::exit(1);
        }
        Ok(m) => {
            let json = serde_json::to_string_pretty(&m).expect("manifest serializes");
            match out {
                None => println!("{json}"),
                Some(p) => {
                    if let Err(e) = write_private_atomically(&p, json.as_bytes()) {
                        eprintln!("p11scope-discover: write {}: {e}", p.display());
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        close_inherited_descriptors_with, collect_proc_fd_snapshot, write_private_atomically_with,
    };
    use std::io::{Error, ErrorKind};
    use std::os::fd::IntoRawFd as _;

    /// Review M2: the manifest is never published into a world-writable
    /// directory without the sticky bit, where any user could rename or
    /// replace it; a sticky shared directory (as `/tmp`) and a group-writable
    /// one (a user-private group under umask 002) are accepted.
    #[test]
    fn a_shared_writable_directory_without_the_sticky_bit_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory =
            std::env::temp_dir().join(format!("discover-shared-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let name = directory.join("manifest.json");
        for (mode, refused) in [
            (0o777, true),
            (0o773, true),
            (0o1777, false),
            (0o775, false),
        ] {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
            let _ = std::fs::remove_file(&name);
            let result = super::write_private_atomically(&name, b"{}");
            assert_eq!(result.is_err(), refused, "mode {mode:o}: {result:?}");
            if refused {
                assert!(
                    result.unwrap_err().contains("writable"),
                    "mode {mode:o} names the cause"
                );
                assert!(!name.exists(), "mode {mode:o}: nothing published");
            }
        }
        let left: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with('.'))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// F-56: a name that turns into a symbolic link while the manifest is
    /// written is re-checked before the rename: the link is left as it was,
    /// its target untouched, and the temp file is removed.
    #[test]
    fn a_symlink_planted_after_the_write_is_refused_and_the_temp_removed() {
        let directory =
            std::env::temp_dir().join(format!("discover-publish-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let name = directory.join("manifest.json");
        let target = directory.join("target");
        let error = write_private_atomically_with(&name, b"{}", || {
            std::os::unix::fs::symlink(&target, &name).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");
        assert!(
            std::fs::symlink_metadata(&name)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!target.exists());
        let mut left: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["manifest.json"], "the temp file was left behind");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn overflowing_fd_name_fails_snapshot() {
        let directory =
            std::env::temp_dir().join(format!("fd-snapshot-overflow-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let overflow = directory.join("999999999999999999999999999999999999");
        std::fs::write(&overflow, b"not an fd").unwrap();
        let error = collect_proc_fd_snapshot(&directory).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        let leaked = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .any(|target| target == directory);
        assert!(!leaked, "snapshot directory descriptor leaked");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn close_range_failure_uses_verified_proc_fallback() {
        let planted = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        let enumeration_fd = 1_000_000;
        let result = close_inherited_descriptors_with(
            || Err(Error::from_raw_os_error(libc::EPERM)),
            || Ok((enumeration_fd, vec![planted, enumeration_fd])),
            |fd| {
                if fd == enumeration_fd {
                    return Err(Error::from_raw_os_error(libc::EBADF));
                }
                if unsafe { libc::close(fd) } == 0 {
                    Ok(())
                } else {
                    Err(Error::last_os_error())
                }
            },
        );
        assert!(result.is_ok(), "verified fallback failed: {result:?}");
        assert_eq!(unsafe { libc::fcntl(planted, libc::F_GETFD) }, -1);
        assert_eq!(Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn unreadable_proc_fallback_fails_closed_without_closing_any_fd() {
        let close_calls = std::cell::Cell::new(0);
        let result = close_inherited_descriptors_with(
            || Err(Error::from_raw_os_error(libc::EPERM)),
            || {
                Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "injected /proc denial",
                ))
            },
            |_| {
                close_calls.set(close_calls.get() + 1);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(close_calls.get(), 0);
    }

    #[test]
    fn non_enumeration_ebadf_fails_closed() {
        let data_fd = 1_000_000;
        let enumeration_fd = 2_000_000;
        let result = close_inherited_descriptors_with(
            || Err(Error::from_raw_os_error(libc::EPERM)),
            || Ok((enumeration_fd, vec![data_fd, enumeration_fd])),
            |fd| {
                if fd == data_fd {
                    Err(Error::from_raw_os_error(libc::EBADF))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EBADF));
    }
}
