//! p11scope-discover — unprivileged short-lived discovery helper.
//! Design: v1 behavior when discovery fails is report-and-exit-nonzero;
//! never silently proceed (design spec, Architecture).

use std::path::PathBuf;

const USAGE: &str = "usage: p11scope-discover --module <provider.so> [-o manifest.json]";

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
        .filter(|value| *value != 0)
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

/// Provider constructors and exports must never inherit observer authority.
fn drop_privileges() -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };

    if euid == 0 {
        let target_uid = target_id("SUDO_UID").unwrap_or(65_534);
        let target_gid = target_id("SUDO_GID").unwrap_or(65_534);
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setresgid(target_gid, target_gid, target_gid) } != 0
            || unsafe { libc::setresuid(target_uid, target_uid, target_uid) } != 0
        {
            return Err(format!(
                "cannot drop discovery privileges: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else if uid != euid || gid != egid {
        return Err("refusing discovery with set-id credentials".into());
    }

    clear_capabilities()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }
    // setresuid clears dumpability. Restore it only so this unprivileged,
    // short-lived process can make bounded reads through /proc/self/mem.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot enable bounded self-memory reads: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::geteuid() } == 0 || active_caps() != 0 {
        return Err(
            "discovery privilege drop did not remove uid 0 and effective capabilities".into(),
        );
    }
    Ok(())
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
    if let Err(error) = drop_privileges() {
        eprintln!("p11scope-discover: {error}");
        std::process::exit(1);
    }
    match p11scope_discover::discover::discover(&module) {
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
