//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//!
//! First-mint coverage for per-mint stub-pool providers (p11-kit
//! proxy/client shape): every getter call mints a heap table with fresh
//! stub addresses from a shared pool, so a workload's first
//! `C_GetInterface` call uses pool mint 0. The manifest must record a v3
//! table from that first mint — otherwise the first-mint
//! `C_GetInterfaceList`/`C_GetInterface` stubs have no manifest row and
//! their calls are never attached.
use p11scope_discover::discover::discover;
use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);
static DISCOVER_LOCK: Mutex<()> = Mutex::new(());

struct RestoreEnv {
    previous: Option<std::ffi::OsString>,
}

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        // SAFETY: only the stub-pool fixture reads this variable, and
        // only under DISCOVER_LOCK below; restored on every exit path.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("P11SCOPE_STUB_POOL_LOG", value),
                None => std::env::remove_var("P11SCOPE_STUB_POOL_LOG"),
            }
        }
    }
}

fn build_fixture() -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "stub-pool-{}",
        FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/stub_pool_provider.c");
    let provider = dir.join("stub_pool_provider.so");
    let log = dir.join("mints.log");
    let ok = Command::new("gcc")
        .arg(format!("-m{}", usize::BITS))
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(&provider)
        .arg(&src)
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc stub_pool_provider.so failed");
    (provider, log)
}

struct Mint {
    kind: String,
    index: usize,
    slot0: u64,
    slot68: u64,
    slot69: u64,
}

fn parse_addr(text: &str) -> u64 {
    if text == "(nil)" {
        return 0;
    }
    let text = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(text.trim(), 16).unwrap()
}

fn parse_log(log: &Path) -> Vec<Mint> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("MINT "))
        .map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 6, "mint log line shape: {line:?}");
            Mint {
                kind: parts[1].to_string(),
                index: parts[2].parse().unwrap(),
                slot0: parse_addr(parts[3]),
                slot68: parse_addr(parts[4]),
                slot69: parse_addr(parts[5]),
            }
        })
        .collect()
}

/// File offset of a runtime address via this process's own maps. The
/// test holds the fixture dlopened, so its executable mapping is present.
fn file_offset(provider: &Path, addr: u64) -> u64 {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let want = provider.to_string_lossy().into_owned();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms), Some(offset)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !perms.starts_with("r-x") {
            continue;
        }
        let path = parts.last().unwrap_or("");
        if path != want {
            continue;
        }
        let (start, end) = range.split_once('-').unwrap();
        let (start, end) = (
            u64::from_str_radix(start, 16).unwrap(),
            u64::from_str_radix(end, 16).unwrap(),
        );
        if start <= addr && addr < end {
            return u64::from_str_radix(offset, 16).unwrap() + addr - start;
        }
    }
    panic!("address {addr:#x} not in an executable mapping of {want}");
}

fn resolution<'a>(s: &'a SurfaceRecord, name: &str) -> &'a Resolution {
    &s.functions.iter().find(|f| f.name == name).unwrap().resolution
}

fn resolved_offset(resolution: &Resolution) -> u64 {
    match *resolution {
        Resolution::Resolved { file_offset, .. } => file_offset,
        ref other => panic!("expected a resolved offset, got {other:?}"),
    }
}

#[test]
fn first_mint_v3_stubs_are_recorded() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let (provider, log) = build_fixture();
    // The target tmpdir persists across runs and the fixture appends:
    // drop a stale log so mint indices start at 0.
    let _ = std::fs::remove_file(&log);
    // Held for the whole test: the fixture mapping must stay readable
    // while logged mint addresses are converted to file offsets.
    let _held = unsafe { libloading::Library::new(provider.as_os_str()).unwrap() };
    let _restore = RestoreEnv {
        previous: std::env::var_os("P11SCOPE_STUB_POOL_LOG"),
    };
    // SAFETY: same confinement as the `Drop` above.
    unsafe {
        std::env::set_var("P11SCOPE_STUB_POOL_LOG", &log);
    }
    let m = discover(&provider).unwrap();
    drop(_restore);

    let mints = parse_log(&log);
    assert!(
        mints.len() >= 2,
        "expected at least a v3 and a legacy mint, got {}",
        mints.len()
    );
    // The v3 enumeration must mint before the legacy table: a workload's
    // first C_GetInterface call uses pool mint 0, and only a v3 table
    // records mint-0 slots 68/69.
    assert_eq!(mints[0].index, 0);
    assert_eq!(mints[1].index, 1);
    assert!(
        mints[0].kind == "list" || mints[0].kind == "iface",
        "first mint must be a v3 table, got {:?}",
        mints[0].kind
    );
    assert_eq!(mints[1].kind, "legacy");

    let mint0 = &mints[0];
    let mint1 = &mints[1];
    assert_eq!(mints.iter().position(|m| m.kind == "legacy"), Some(1));

    let legacy = &m.surfaces[0];
    assert_eq!(legacy.functions.len(), 68);
    assert_eq!(
        resolved_offset(resolution(legacy, "C_Initialize")),
        file_offset(&provider, mint1.slot0),
        "legacy surface records the post-v3 mint"
    );

    let v32 = m
        .surfaces
        .iter()
        .find(|s| s.version.as_ref().is_some_and(|v| v.major == 3 && v.minor == 2))
        .expect("a v3.2 surface");
    assert_eq!(
        resolved_offset(resolution(v32, "C_Initialize")),
        file_offset(&provider, mint0.slot0),
        "v3.2 surface records first-mint slot 0"
    );
    assert_eq!(
        resolved_offset(resolution(v32, "C_GetInterfaceList")),
        file_offset(&provider, mint0.slot68),
        "v3.2 surface records the first-mint C_GetInterfaceList stub"
    );
    assert_eq!(
        resolved_offset(resolution(v32, "C_GetInterface")),
        file_offset(&provider, mint0.slot69),
        "v3.2 surface records the first-mint C_GetInterface stub"
    );
}
