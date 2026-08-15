//! p11scope-discover — unprivileged short-lived discovery helper.
//! Design: v1 behavior when discovery fails is report-and-exit-nonzero;
//! never silently proceed (design spec, Architecture).

use std::fs::File;
use std::path::PathBuf;

const USAGE: &str = "usage: p11scope-discover --module <provider.so> [-o manifest.json]";

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

fn main() {
    let mut module: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
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
                    if let Err(e) = std::fs::write(&p, json) {
                        eprintln!("p11scope-discover: write {}: {e}", p.display());
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
