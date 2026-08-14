//! p11scope-discover — unprivileged short-lived discovery helper.
//! Design: v1 behavior when discovery fails is report-and-exit-nonzero;
//! never silently proceed (design spec, Architecture).

use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::PathBuf;

const USAGE: &str = "usage: p11scope-discover --module <provider.so> [-o manifest.json]";
const PREPARED: &[u8] = b"PREPARED";
const DROP: &[u8] = b"DROP";
const READY: &[u8] = b"READY";
const GO: &[u8] = b"GO";

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

fn validate_suid_dumpable(value: &[u8]) -> Result<(), String> {
    if value != b"0\n" {
        return Err(
            "refusing privileged discovery unless /proc/sys/fs/suid_dumpable is exactly 0".into(),
        );
    }
    Ok(())
}

fn prepare_drop() -> Result<DropTarget, String> {
    let (uids, gids) = current_ids()?;
    if uids[1] == 0 {
        let policy = std::fs::read("/proc/sys/fs/suid_dumpable")
            .map_err(|error| format!("cannot read /proc/sys/fs/suid_dumpable: {error}"))?;
        validate_suid_dumpable(&policy)?;
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

/// Provider constructors and exports must never inherit observer authority.
fn drop_privileges_and_open_self_memory(target: DropTarget) -> Result<File, String> {
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

fn socket_option(fd: RawFd, option: libc::c_int) -> Result<libc::c_int, String> {
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&value)
    {
        return Err(format!(
            "invalid discovery control socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(value)
}

fn inherited_control(value: &str) -> Result<OwnedFd, String> {
    let fd: RawFd = value
        .parse()
        .map_err(|_| "--control-fd requires an integer descriptor".to_string())?;
    if fd < 3 {
        return Err("--control-fd must not name stdin, stdout, or stderr".into());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(format!(
            "invalid discovery control descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    if socket_option(fd, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
    {
        return Err("discovery control descriptor is not an AF_UNIX SOCK_SEQPACKET".into());
    }
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut peer as *mut libc::sockaddr_storage).cast(),
            &mut peer_len,
        )
    } != 0
        || peer.ss_family as libc::c_int != libc::AF_UNIX
    {
        return Err("discovery control descriptor is not a connected AF_UNIX socket".into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(format!(
            "cannot protect discovery control descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_control(fd: &OwnedFd, packet: &[u8]) -> Result<(), String> {
    loop {
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if sent != packet.len() as isize {
            return Err(format!(
                "cannot send discovery control packet: {}",
                std::io::Error::last_os_error()
            ));
        }
        return Ok(());
    }
}

fn expect_control(fd: &OwnedFd, expected: &[u8]) -> Result<(), String> {
    let mut packet = [0u8; 16];
    loop {
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_TRUNC,
            )
        };
        if received == -1
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if received == 0 {
            return Err("discovery control channel closed before the expected packet".into());
        }
        if received != expected.len() as isize || &packet[..expected.len()] != expected {
            return Err("unexpected discovery control packet".into());
        }
        return Ok(());
    }
}

fn main() {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut control: Option<OwnedFd> = None;
    let mut args = std::env::args().skip(1);
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
            "--control-fd" => {
                if control.is_some() {
                    eprintln!("--control-fd may be specified only once\n{USAGE}");
                    std::process::exit(2);
                }
                let Some(value) = args.next() else {
                    eprintln!("--control-fd requires a value\n{USAGE}");
                    std::process::exit(2);
                };
                control = match inherited_control(&value) {
                    Ok(control) => Some(control),
                    Err(error) => {
                        eprintln!("p11scope-discover: {error}");
                        std::process::exit(2);
                    }
                };
            }
            "--help" | "-h" => {
                eprintln!("{USAGE}");
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
    if let Some(control) = control.as_ref()
        && let Err(error) =
            send_control(control, PREPARED).and_then(|()| expect_control(control, DROP))
    {
        eprintln!("p11scope-discover: {error}");
        std::process::exit(1);
    }
    let self_memory = match drop_privileges_and_open_self_memory(drop_target) {
        Ok(memory) => memory,
        Err(error) => {
            eprintln!("p11scope-discover: {error}");
            std::process::exit(1);
        }
    };
    if let Some(control) = control.as_ref()
        && let Err(error) = send_control(control, READY).and_then(|()| expect_control(control, GO))
    {
        eprintln!("p11scope-discover: {error}");
        std::process::exit(1);
    }
    drop(control);
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
                    if let Err(e) = std::fs::write(&p, json) {
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
    use super::*;

    #[test]
    fn credential_transition_requires_suid_dumpable_zero() {
        validate_suid_dumpable(b"0\n").unwrap();
        for value in [b"1\n".as_slice(), b"2\n", b"", b"garbage\n", b"0 1\n"] {
            assert!(validate_suid_dumpable(value).is_err(), "{value:?}");
        }
    }
}
