//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! BPF load feasibility measurements (parallel loading, resident service).
//!
//! Ignored privileged cells, run by hand as root under the privileged lock:
//! per-program load cost (wall time, verifier-reported processed
//! instructions where the kernel exposes them), parallel-load overlap, and
//! resident-service cost parts. Uses the embedded objects through the
//! existing `pub` statics only; never changes product code paths. Nothing
//! is attached, pinned, executed or retained: every load is dropped at the
//! end of its trial. The page-cache drop behind cache-cold trial 0 is
//! system-wide: it runs only with `P11SCOPE_FEASIBILITY_DROP_CACHES=1`
//! in an exclusive window; the default labels trial 0
//! fresh-process-first-trial without touching the cache.
//!
//! Rows go to stdout as JSONL and, when `P11SCOPE_FEASIBILITY_OUT` names a
//! directory, are appended to `<dir>/<cell>.jsonl` with a `run_id` per
//! process. `P11SCOPE_FEASIBILITY_TRIALS` overrides the trial counts
//! (default 10 for the per-program cell, 5 for the parallel cell); the
//! cleanup twin always runs once.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::fd::RawFd;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Objects measured, in product-load order: Detailed, then the counter
/// flavors, then the two Inventory flavors. The journal object is not a
/// production capture object and is out of scope for this lane.
fn measured_objects() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("detailed", p11scope::EBPF_OBJECT),
        ("counter-counts", p11scope::EBPF_COUNTER_COUNTS_OBJECT),
        (
            "counter-timestamps",
            p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT,
        ),
        ("counter-latency", p11scope::EBPF_COUNTER_LATENCY_OBJECT),
        ("inventory", p11scope::EBPF_INVENTORY_OBJECT),
        ("inventory-callers", p11scope::EBPF_INVENTORY_CALLERS_OBJECT),
    ]
}

fn require_root(cell: &str) {
    // SAFETY: geteuid only reads this process's effective user identity.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "{cell}: root owns the BPF load lane"
    );
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            })
        })
        .unwrap_or(0)
}

/// Sysctl exposing verifier-stats collection; cells toggle it 0→1→0.
const BPF_STATS_SYSCTL: &str = "/proc/sys/kernel/bpf_stats_enabled";

fn read_sysctl(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn write_sysctl(path: &str, value: &str) -> std::io::Result<()> {
    fs::write(path, value)?;
    Ok(())
}

fn bpf_stats_enabled() -> Option<String> {
    read_sysctl(BPF_STATS_SYSCTL)
}

/// RAII owner of the 0→1 stats toggle: enables at construction and
/// restores the prior value on drop — including on panic — so a
/// mid-cell failure cannot leak collection on for other lanes.
struct StatsGuard {
    path: String,
    restore: Option<String>,
}

impl StatsGuard {
    fn engage() -> Self {
        Self::engage_at(BPF_STATS_SYSCTL)
    }

    fn engage_at(path: &str) -> Self {
        let before = read_sysctl(path);
        if before.as_deref() == Some("0") {
            write_sysctl(path, "1").expect("enable bpf_stats for verified_insns");
            Self {
                path: path.to_string(),
                restore: before,
            }
        } else {
            Self {
                path: path.to_string(),
                restore: None,
            }
        }
    }
}

impl Drop for StatsGuard {
    fn drop(&mut self) {
        if let Some(prior) = self.restore.take() {
            let _ = write_sysctl(&self.path, &prior);
        }
    }
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Sysctl releasing page cache; the write is system-wide.
const DROP_CACHES_SYSCTL: &str = "/proc/sys/vm/drop_caches";

/// Opt-in for the system-wide page-cache drop; exclusive windows only.
const DROP_CACHES_ENV: &str = "P11SCOPE_FEASIBILITY_DROP_CACHES";

/// Attempt the cold-load precondition: drop page cache (including the
/// cached `/sys/kernel/btf/vmlinux` blob) so trial 0 is cache-cold —
/// but only with explicit opt-in, since the write is system-wide.
/// Returns the cold method label actually achieved.
fn drop_caches_for_cold() -> &'static str {
    drop_caches_for_cold_at(DROP_CACHES_SYSCTL)
}

fn drop_caches_for_cold_at(path: &str) -> &'static str {
    if std::env::var(DROP_CACHES_ENV).as_deref() != Ok("1") {
        return "fresh-process-first-trial";
    }
    match fs::write(path, "3") {
        Ok(()) => "drop_caches",
        Err(_) => "fresh-process-first-trial",
    }
}

fn trial_count(default: usize) -> usize {
    std::env::var("P11SCOPE_FEASIBILITY_TRIALS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(default)
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

struct Sink {
    file: Option<fs::File>,
}

impl Sink {
    fn open(cell: &str) -> Self {
        let file = std::env::var_os("P11SCOPE_FEASIBILITY_OUT").and_then(|dir| {
            let path = std::path::Path::new(&dir).join(format!("{cell}.jsonl"));
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        });
        Self { file }
    }

    fn row(&mut self, value: &serde_json::Value) {
        let line = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
        println!("{line}");
        if let Some(file) = self.file.as_mut() {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// Verifier stats for one loaded program, read through
/// `BPF_OBJ_GET_INFO_BY_FD` on the program fd. The kernel fills a prefix
/// of the info struct; `id` (offset 4), `load_time` (offset 40) and
/// `verified_insns` (offset 216, valid only with bpf_stats_enabled) are
/// stable early fields, so a zeroed oversized buffer is sufficient and
/// version-tolerant. Returns `(id, load_time_boot_ns, verified_insns)`.
fn prog_info_stats(fd: RawFd) -> Option<(u32, u64, Option<u32>)> {
    // BPF_OBJ_GET_INFO_BY_FD, linux/bpf.h enum bpf_cmd (15); this libc
    // does not export the constant.
    const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
    const INFO_LEN: usize = 4096;
    const OFF_ID: usize = 4;
    const OFF_LOAD_TIME: usize = 40;
    const OFF_VERIFIED_INSNS: usize = 216;
    #[repr(C)]
    struct InfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    let mut info = vec![0u8; INFO_LEN];
    let attr = InfoAttr {
        bpf_fd: fd as u32,
        info_len: INFO_LEN as u32,
        info: info.as_mut_ptr() as u64,
    };
    // SAFETY: bpf() with BPF_OBJ_GET_INFO_BY_FD reads the attr and writes
    // at most INFO_LEN bytes into the caller-owned buffer.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &attr as *const InfoAttr,
            std::mem::size_of::<InfoAttr>(),
        )
    };
    if ret != 0 {
        return None;
    }
    let id = u32::from_ne_bytes(info[OFF_ID..OFF_ID + 4].try_into().ok()?);
    let load_time = u64::from_ne_bytes(info[OFF_LOAD_TIME..OFF_LOAD_TIME + 8].try_into().ok()?);
    let verified = u32::from_ne_bytes(
        info[OFF_VERIFIED_INSNS..OFF_VERIFIED_INSNS + 4]
            .try_into()
            .ok()?,
    );
    let stats_on = bpf_stats_enabled().as_deref() != Some("0");
    Some((id, load_time, stats_on.then_some(verified)))
}

/// (program, section) pairs of one object, sorted by name. The section
/// drives the loader choice, mirroring the product's per-step loaders.
fn program_sections(bytes: &[u8]) -> Vec<(String, aya_obj::ProgramSection)> {
    let object = aya_obj::Object::parse(bytes).expect("embedded object must parse");
    let mut programs: Vec<(String, aya_obj::ProgramSection)> = object
        .programs
        .iter()
        .map(|(name, program)| (name.clone(), program.section.clone()))
        .collect();
    programs.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!programs.is_empty(), "embedded object must carry programs");
    programs
}

/// Attach targets for the non-uprobe programs, mirroring the product's
/// loaders: the instance hooks (`src/attach/instance.rs`
/// `INSTANCE_PROGRAMS`), the task iterators
/// (`src/attach/image_query.rs`, `src/attach/selected_detailed.rs`
/// `load_bootstrap`, `src/attach/selected_detailed/baseline.rs`, all
/// `load("task", btf)`), the BTF tracepoint (`src/attach.rs`
/// `LoadProgram`, `load("task_newtask", btf)`).
/// `p11_selected_cgroup_migrate` ships in the Detailed object but has no
/// load call in product code at this revision; the harness loads it as
/// fentry/cgroup_migrate so the object is priced whole, and labels it.
fn attach_target(name: &str) -> &'static str {
    match name {
        "p11_inst_vma_map" => "uprobe_mmap",
        "p11_inst_vma_unmap" => "uprobe_munmap",
        "p11_inst_vma_copy" => "copy_vma",
        "p11_image_exec_release" => "exec_mm_release",
        "p11_selected_cgroup_migrate" => "cgroup_migrate",
        "p11_image_query" | "p11_selected_bootstrap" | "p11_inventory_image_baseline" => "task",
        "task_newtask" => "task_newtask",
        other => panic!("no harness attach target for program {other}"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Single,
    Multi,
}

impl Variant {
    fn label(self) -> &'static str {
        match self {
            Variant::Single => "single",
            Variant::Multi => "multi",
        }
    }
}

struct LoadRow {
    name: String,
    wall: Duration,
    prog_id: u32,
    verified_insns: Option<u32>,
}

/// Load one program the way the product does, dispatched on its real
/// section: uprobes in the requested single/multi variant, raw
/// tracepoints, BTF tracepoints, fentry/fexit hooks and task iterators
/// with their product attach targets. Times the single `BPF_PROG_LOAD`
/// this issues; never attaches. An unknown section fails loud.
fn load_program_timed(
    ebpf: &mut aya::Ebpf,
    name: &str,
    section: &aya_obj::ProgramSection,
    variant: Variant,
    btf: &aya::Btf,
) -> LoadRow {
    use aya_obj::ProgramSection::*;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    let start = Instant::now();
    match section {
        UProbe { .. } | URetProbe { .. } => {
            let prog: &mut aya::programs::UProbe = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not a uprobe: {error}"));
            match variant {
                Variant::Single => prog
                    .load()
                    .unwrap_or_else(|error| panic!("loading {name} (single): {error}")),
                Variant::Multi => prog
                    .load_multi()
                    .unwrap_or_else(|error| panic!("loading {name} (multi): {error}")),
            }
        }
        RawTracePoint => {
            let prog: &mut aya::programs::RawTracePoint = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not a raw tracepoint: {error}"));
            prog.load()
                .unwrap_or_else(|error| panic!("loading raw {name}: {error}"));
        }
        BtfTracePoint => {
            let prog: &mut aya::programs::BtfTracePoint = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not a BTF tracepoint: {error}"));
            let target = attach_target(name);
            prog.load(target, btf)
                .unwrap_or_else(|error| panic!("loading BTF {name} on {target}: {error}"));
        }
        FEntry { .. } => {
            let prog: &mut aya::programs::FEntry = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not an fentry: {error}"));
            let target = attach_target(name);
            prog.load(target, btf)
                .unwrap_or_else(|error| panic!("loading fentry {name} on {target}: {error}"));
        }
        FExit { .. } => {
            let prog: &mut aya::programs::FExit = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not an fexit: {error}"));
            let target = attach_target(name);
            prog.load(target, btf)
                .unwrap_or_else(|error| panic!("loading fexit {name} on {target}: {error}"));
        }
        Iter { .. } => {
            let prog: &mut aya::programs::Iter = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("program {name} missing from object"))
                .try_into()
                .unwrap_or_else(|error| panic!("program {name} is not an iter: {error}"));
            let target = attach_target(name);
            prog.load(target, btf)
                .unwrap_or_else(|error| panic!("loading iter {name} on {target}: {error}"));
        }
        other => panic!("no harness loader for section {other:?} (program {name}"),
    }
    let wall = start.elapsed();
    let fd: RawFd = ebpf
        .program(name)
        .unwrap_or_else(|| panic!("just-loaded program {name} missing"))
        .fd()
        .unwrap_or_else(|error| panic!("loaded program {name} carries no fd: {error}"))
        .as_fd()
        .as_raw_fd();
    let (prog_id, _load_time, verified_insns) = prog_info_stats(fd).unwrap_or((0, 0, None));
    LoadRow {
        name: name.to_string(),
        wall,
        prog_id,
        verified_insns,
    }
}

/// Whether the single/multi variant distinction applies (uprobes only).
fn is_uprobe_section(section: &aya_obj::ProgramSection) -> bool {
    matches!(
        section,
        aya_obj::ProgramSection::UProbe { .. } | aya_obj::ProgramSection::URetProbe { .. }
    )
}

fn load_object_maps(bytes: &[u8], btf: &aya::Btf) -> (aya::Ebpf, Duration) {
    let start = Instant::now();
    let ebpf = aya::EbpfLoader::new()
        .btf(Some(btf))
        .allow_unsupported_maps()
        .load(bytes)
        .expect("maps/object load must succeed for measurement");
    (ebpf, start.elapsed())
}

/// Root runs the per-program load matrix: every production object,
/// program by program, in single and multi variants, 10 paired trials
/// (trial 0 cache-cold, the rest warm). Records wall time per
/// `BPF_PROG_LOAD` plus the verifier-reported processed instructions
/// where the kernel exposes them. Nothing is attached or retained.
#[test]
#[ignore = "privileged: per-program BPF load cost matrix; run as root with --ignored --test-threads=1"]
fn per_program_load_times() {
    const CELL: &str = "per_program_load_times";
    require_root(CELL);
    let trials = trial_count(10);
    let id = run_id();
    let kernel = kernel_release();
    let mut sink = Sink::open(CELL);
    let _stats = StatsGuard::engage();
    let stats_label = bpf_stats_enabled().unwrap_or_else(|| "?".to_string());

    let btf_start = Instant::now();
    let btf = aya::Btf::from_sys_fs().expect("host vmlinux BTF must load");
    let btf_wall = btf_start.elapsed();
    sink.row(&serde_json::json!({
        "cell": CELL, "run_id": id, "kernel": kernel,
        "bpf_stats_enabled": stats_label, "phase": "btf",
        "wall_ns": btf_wall.as_nanos() as u64,
    }));

    let mut totals: BTreeMap<(String, String), u128> = BTreeMap::new();
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (object_label, bytes) in measured_objects() {
        if bytes.is_empty() {
            sink.row(&serde_json::json!({
                "cell": CELL, "run_id": id, "kernel": kernel,
                "object": object_label, "skipped": "empty-embedded-object",
            }));
            println!("{CELL}: object {object_label}: SKIPPED (empty embedded object)");
            continue;
        }
        let programs = program_sections(bytes);
        println!("{CELL}: object {object_label}: {} programs", programs.len());
        for (name, section) in &programs {
            println!("{CELL}: object {object_label}: program {name} section {section:?}");
        }
        let cold_method = drop_caches_for_cold();
        for trial in 0..trials {
            let cold = trial == 0;
            // Alternate the variant order across trials so map/BTF warmth
            // cannot systematically favor one variant.
            let order = if trial % 2 == 0 {
                [Variant::Single, Variant::Multi]
            } else {
                [Variant::Multi, Variant::Single]
            };
            for variant in order {
                let (mut ebpf, maps_wall) = load_object_maps(bytes, &btf);
                sink.row(&serde_json::json!({
                    "cell": CELL, "run_id": id, "kernel": kernel,
                    "bpf_stats_enabled": stats_label, "object": object_label,
                    "trial": trial, "cold": cold, "cold_method": cold_method,
                    "variant": variant.label(), "phase": "maps",
                    "wall_ns": maps_wall.as_nanos() as u64,
                }));
                for (name, section) in &programs {
                    // Non-uprobe programs have no multi form; they load
                    // once per trial, on the single pass.
                    if !is_uprobe_section(section) && variant == Variant::Multi {
                        continue;
                    }
                    let row = load_program_timed(&mut ebpf, name, section, variant, &btf);
                    *totals
                        .entry((object_label.to_string(), name.clone()))
                        .or_default() += row.wall.as_nanos();
                    *counts
                        .entry((object_label.to_string(), name.clone()))
                        .or_default() += 1;
                    sink.row(&serde_json::json!({
                        "cell": CELL, "run_id": id, "kernel": kernel,
                        "bpf_stats_enabled": stats_label, "object": object_label,
                        "trial": trial, "cold": cold, "cold_method": cold_method,
                        "variant": variant.label(), "phase": "program",
                        "name": row.name, "section": format!("{section:?}"),
                        "wall_ns": row.wall.as_nanos() as u64,
                        "prog_id": row.prog_id, "verified_insns": row.verified_insns,
                    }));
                }
                // Programs and maps close here; nothing is attached.
            }
        }
    }
    println!("{CELL}: mean load wall per program over {trials} trials (both variants):");
    let mut means: Vec<(String, String, f64)> = totals
        .iter()
        .map(|((object, name), total)| {
            let count = counts
                .get(&(object.clone(), name.clone()))
                .copied()
                .unwrap_or(1)
                .max(1);
            (
                object.clone(),
                name.clone(),
                *total as f64 / count as f64 / 1_000_000.0,
            )
        })
        .collect();
    means.sort_by(|left, right| {
        right
            .2
            .partial_cmp(&left.2)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (object, name, mean_ms) in means {
        println!("{CELL}:   {object}/{name}: {mean_ms:.1} ms mean");
    }
}

/// Env var naming a `per_program_load_times.jsonl` whose warm means
/// deal the parallel partition on THIS host; unset keeps the
/// dev-host 7.0 const order with a loud warning.
const BASELINE_ENV: &str = "P11SCOPE_FEASIBILITY_BASELINE";

/// Warm per-program mean walls (ns) in the parallel configuration
/// plus the warm maps mean (ns), parsed from a baseline JSONL.
#[derive(Debug)]
struct BaselineCosts {
    programs: BTreeMap<String, f64>,
    maps_mean_ns: f64,
}

fn mean_ns(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len().max(1) as f64
}

/// Warm means for one object from a per-program JSONL: per-program
/// walls in the exact parallel configuration (multi variant where the
/// matrix measured one, else single) plus the maps mean. Cold trials
/// and other objects/cells are excluded; a malformed line or a
/// missing warm section fails loud.
fn baseline_program_costs(path: &str, object: &str) -> Result<BaselineCosts, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))?;
    let mut program_walls: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    let mut maps_walls: Vec<f64> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("{path} line {}: bad JSON: {error}", index + 1))?;
        let cell = row.get("cell").and_then(serde_json::Value::as_str);
        let row_object = row.get("object").and_then(serde_json::Value::as_str);
        if cell != Some("per_program_load_times") || row_object != Some(object) {
            continue;
        }
        if row.get("cold").and_then(serde_json::Value::as_bool) != Some(false) {
            continue;
        }
        let wall = row
            .get("wall_ns")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        match row.get("phase").and_then(serde_json::Value::as_str) {
            Some("maps") => maps_walls.push(wall),
            Some("program") => {
                let name = row
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| format!("{path} line {}: program row lacks name", index + 1))?;
                let variant = row
                    .get("variant")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        format!("{path} line {}: program row lacks variant", index + 1)
                    })?;
                program_walls
                    .entry((name.to_string(), variant.to_string()))
                    .or_default()
                    .push(wall);
            }
            _ => {}
        }
    }
    if maps_walls.is_empty() {
        return Err(format!("{path}: no warm maps rows for {object}"));
    }
    let mut names = BTreeSet::new();
    for (name, _) in program_walls.keys() {
        names.insert(name.clone());
    }
    let mut programs = BTreeMap::new();
    for name in names {
        let walls = program_walls
            .get(&(name.clone(), "multi".to_string()))
            .or_else(|| program_walls.get(&(name.clone(), "single".to_string())))
            .ok_or_else(|| format!("{path}: program {name} has no warm rows"))?;
        programs.insert(name, mean_ns(walls));
    }
    Ok(BaselineCosts {
        programs,
        maps_mean_ns: mean_ns(&maps_walls),
    })
}

/// Descending-cost deal order over exactly the embedded program set;
/// fails loud on drift either way (baseline missing a program, or
/// naming one the object no longer ships).
fn order_by_cost(
    costs: &BTreeMap<String, f64>,
    expected: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let mut missing: Vec<&str> = expected
        .iter()
        .filter(|name| !costs.contains_key(*name))
        .map(String::as_str)
        .collect();
    missing.sort_unstable();
    if !missing.is_empty() {
        return Err(format!("baseline lacks programs: {}", missing.join(", ")));
    }
    let mut unknown: Vec<&str> = costs
        .keys()
        .filter(|name| !expected.contains(*name))
        .map(String::as_str)
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Err(format!(
            "baseline has unknown programs: {}",
            unknown.join(", ")
        ));
    }
    let mut order: Vec<String> = expected.iter().cloned().collect();
    order.sort_by(|left, right| {
        costs[right]
            .partial_cmp(&costs[left])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(order)
}

/// Round-robin deal over descending cost (LPT): keeps worker sums
/// balanced without stacking the heavy programs on one worker.
fn deal_round_robin(order: &[String], workers: usize) -> Vec<Vec<String>> {
    let mut parts: Vec<Vec<String>> = vec![Vec::new(); workers];
    for (index, name) in order.iter().enumerate() {
        parts[index % workers].push(name.clone());
    }
    parts
}

impl BaselineCosts {
    /// Full serial load in the parallel configuration: program walls
    /// plus one maps/object creation (BTF excluded — workers parse it
    /// before the barrier, so the parallel wall never contains it).
    fn serial_reference_ns(&self) -> f64 {
        self.programs.values().sum::<f64>() + self.maps_mean_ns
    }
}

/// Honest speedup of one parallel trial: serial reference over
/// parallel wall — how much faster than today's serial load.
fn honest_speedup(serial_reference_ns: u64, parallel_wall: Duration) -> f64 {
    Duration::from_nanos(serial_reference_ns).as_secs_f64()
        / parallel_wall.as_secs_f64().max(f64::EPSILON)
}

/// Overlap ratio: contended per-program sum over parallel wall. The
/// per-program walls inflate under contention, so this measures
/// overlap-ignoring-inflation — NOT a speedup claim.
fn overlap_ratio(serial_sum: Duration, parallel_wall: Duration) -> f64 {
    serial_sum.as_secs_f64() / parallel_wall.as_secs_f64().max(f64::EPSILON)
}

/// Max/min worker program-cost-sum ratio; `None` when a worker sum is
/// zero (no numeric costs, or a degenerate empty worker).
fn worker_balance(parts: &[Vec<String>], costs: &BTreeMap<String, f64>) -> Option<f64> {
    let sums: Vec<f64> = parts
        .iter()
        .map(|part| {
            part.iter()
                .map(|name| costs.get(name).copied().unwrap_or(0.0))
                .sum()
        })
        .collect();
    let max = sums.iter().cloned().fold(0.0, f64::max);
    let min = sums.iter().cloned().fold(f64::INFINITY, f64::min);
    if min > 0.0 { Some(max / min) } else { None }
}

/// One worker's loaded program: name, section, variant, load wall,
// program id, verifier-reported processed insns.
type WorkerRow = (String, String, &'static str, Duration, u32, Option<u32>);

struct WorkerOutcome {
    rows: Vec<WorkerRow>,
    maps_wall: Duration,
    btf_wall: Duration,
    wall: Duration,
}

/// Root runs the parallel-load overlap probe: K worker threads each load
/// a disjoint program subset from its own Ebpf instance behind a start
/// barrier, reporting both the contended-sum overlap ratio and the
/// honest speedup against a serial reference (baseline means when
/// P11SCOPE_FEASIBILITY_BASELINE is set, else one in-process serial
/// pass). Reports the kernel-side serialization the design must live
/// with. Nothing is attached or retained.
#[test]
#[ignore = "privileged: parallel BPF load overlap probe; run as root with --ignored --test-threads=1"]
fn parallel_load_measures_kernel_overlap() {
    const CELL: &str = "parallel_load_measures_kernel_overlap";
    require_root(CELL);
    let trials = trial_count(5);
    let id = run_id();
    let kernel = kernel_release();
    let mut sink = Sink::open(CELL);
    let _stats = StatsGuard::engage();
    let stats_label = bpf_stats_enabled().unwrap_or_else(|| "?".to_string());

    let bytes = p11scope::EBPF_OBJECT;
    assert!(!bytes.is_empty(), "Detailed object must be embedded");
    let programs = program_sections(bytes);
    assert!(
        programs.len() >= 4,
        "need at least 4 programs to split across workers"
    );
    // Longest-processing-time order from the lane's own per-program means
    // (per_program_load_times, warm multi on the dev host, kernel 7.0):
    // dealing round-robin over descending cost balances worker sums.
    // Fallback when P11SCOPE_FEASIBILITY_BASELINE is unset; other
    // hosts/kernels must pass their own baseline JSONL.
    const COST_ORDER: [&str; 20] = [
        "p11_return",
        "interface_list_worker",
        "interface_return",
        "p11_entry",
        "sched_process_exec",
        "sched_process_exit",
        "function_list_return",
        "interface_list_return",
        "function_list_entry",
        "interface_list_entry",
        "interface_entry",
        "dl_debug_state",
        "p11_inst_vma_map",
        "p11_inst_vma_unmap",
        "p11_inst_vma_copy",
        "task_newtask",
        "p11_selected_bootstrap",
        "p11_image_query",
        "p11_image_exec_release",
        "p11_selected_cgroup_migrate",
    ];
    let mut by_name: BTreeMap<&str, aya_obj::ProgramSection> = BTreeMap::new();
    for (name, section) in &programs {
        by_name.insert(name.as_str(), section.clone());
    }
    // The set equality in both branches fails loud if the object
    // gains, loses, or renames a program.
    let expected: BTreeSet<String> = by_name.keys().map(|name| name.to_string()).collect();
    let (cost_order, cost_source, baseline) = match std::env::var_os(BASELINE_ENV) {
        Some(path) => {
            let path = path.to_string_lossy().into_owned();
            let baseline = baseline_program_costs(&path, "detailed")
                .unwrap_or_else(|error| panic!("{CELL}: baseline {path}: {error}"));
            let order = order_by_cost(&baseline.programs, &expected)
                .unwrap_or_else(|error| panic!("{CELL}: baseline {path}: {error}"));
            println!(
                "{CELL}: deal order from baseline {path} ({} programs)",
                order.len()
            );
            (order, format!("baseline:{path}"), Some(baseline))
        }
        None => {
            assert_eq!(
                by_name.len(),
                COST_ORDER.len(),
                "{CELL}: Detailed program set drifted; re-derive COST_ORDER"
            );
            for name in COST_ORDER {
                assert!(
                    by_name.contains_key(name),
                    "{CELL}: Detailed program {name} missing; re-derive COST_ORDER"
                );
            }
            println!(
                "{CELL}: WARNING: {BASELINE_ENV} unset; dealing by the dev-host 7.0 const order — pass this host's per_program JSONL on other kernels"
            );
            (
                COST_ORDER.iter().map(|name| name.to_string()).collect(),
                "const-fallback-7.0".to_string(),
                None,
            )
        }
    };
    let (serial_reference_ns, serial_reference_source) = match baseline.as_ref() {
        Some(costs) => (costs.serial_reference_ns() as u64, cost_source.clone()),
        None => {
            println!(
                "{CELL}: no baseline; measuring an in-process serial reference (one full load)"
            );
            let btf = aya::Btf::from_sys_fs().expect("reference BTF must load");
            let (mut ebpf, maps_wall) = load_object_maps(bytes, &btf);
            let mut program_sum = Duration::ZERO;
            for (name, section) in &programs {
                let variant = if is_uprobe_section(section) {
                    Variant::Multi
                } else {
                    Variant::Single
                };
                program_sum += load_program_timed(&mut ebpf, name, section, variant, &btf).wall;
            }
            drop(ebpf);
            let reference = maps_wall + program_sum;
            println!(
                "{CELL}: in-process serial reference: {:.3}s",
                reference.as_secs_f64()
            );
            (reference.as_nanos() as u64, "in-process".to_string())
        }
    };
    for workers in [2usize, 4usize] {
        // LPT partition: round-robin over descending cost keeps worker
        // sums balanced (name-sorted round-robin stacked p11_return and
        // interface_list_worker on one worker, capping speedup at 1.5x).
        let deal = deal_round_robin(&cost_order, workers);
        let balance = baseline
            .as_ref()
            .and_then(|costs| worker_balance(&deal, &costs.programs));
        match balance {
            Some(ratio) => {
                println!("{CELL}: workers={workers}: baseline cost balance max/min={ratio:.2}x");
                if ratio > 1.5 {
                    println!(
                        "{CELL}: WARNING: workers={workers}: imbalanced deal ({ratio:.2}x); speedup understates kernel overlap"
                    );
                }
            }
            None if baseline.is_some() => {
                println!("{CELL}: WARNING: workers={workers}: balance unknown (zero cost sum)")
            }
            None => {}
        }
        let mut parts: Vec<Vec<(String, aya_obj::ProgramSection)>> = vec![Vec::new(); workers];
        for (worker, subset) in deal.into_iter().enumerate() {
            for name in subset {
                let section = by_name.get(name.as_str()).expect("checked above").clone();
                parts[worker].push((name, section));
            }
        }
        for trial in 0..trials {
            let barrier = Arc::new(Barrier::new(workers + 1));
            let parts = parts.clone();
            let handles: Vec<_> = parts
                .into_iter()
                .map(|subset| {
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || -> WorkerOutcome {
                        let btf_start = Instant::now();
                        let btf = aya::Btf::from_sys_fs().expect("worker BTF must load");
                        let btf_wall = btf_start.elapsed();
                        barrier.wait();
                        let start = Instant::now();
                        let (mut ebpf, maps_wall) = load_object_maps(bytes, &btf);
                        let mut rows = Vec::new();
                        for (name, section) in &subset {
                            let variant = if is_uprobe_section(section) {
                                Variant::Multi
                            } else {
                                Variant::Single
                            };
                            let row = load_program_timed(&mut ebpf, name, section, variant, &btf);
                            rows.push((
                                row.name,
                                format!("{section:?}"),
                                variant.label(),
                                row.wall,
                                row.prog_id,
                                row.verified_insns,
                            ));
                        }
                        WorkerOutcome {
                            rows,
                            maps_wall,
                            btf_wall,
                            wall: start.elapsed(),
                        }
                    })
                })
                .collect();
            barrier.wait();
            let parallel_start = Instant::now();
            let mut outcomes = Vec::new();
            for (worker, handle) in handles.into_iter().enumerate() {
                let outcome: WorkerOutcome = handle.join().unwrap_or_else(|_| {
                    panic!("{CELL}: worker {worker} panicked (trial {trial}, workers {workers})")
                });
                outcomes.push(outcome);
            }
            let parallel_wall = parallel_start.elapsed();
            let mut serial_sum = Duration::ZERO;
            let mut loaded = 0usize;
            for (worker, outcome) in outcomes.iter().enumerate() {
                for (name, section, variant, wall, prog_id, verified_insns) in &outcome.rows {
                    serial_sum += *wall;
                    loaded += 1;
                    sink.row(&serde_json::json!({
                        "cell": CELL, "run_id": id, "kernel": kernel,
                        "bpf_stats_enabled": stats_label, "object": "detailed",
                        "workers": workers, "trial": trial, "worker": worker,
                        "variant": variant, "phase": "program",
                        "name": name, "section": section,
                        "wall_ns": wall.as_nanos() as u64,
                        "prog_id": prog_id, "verified_insns": verified_insns,
                        "worker_maps_wall_ns": outcome.maps_wall.as_nanos() as u64,
                        "worker_btf_wall_ns": outcome.btf_wall.as_nanos() as u64,
                        "worker_wall_ns": outcome.wall.as_nanos() as u64,
                    }));
                }
            }
            assert_eq!(
                loaded,
                programs.len(),
                "{CELL}: every program must load exactly once across workers"
            );
            let overlap = overlap_ratio(serial_sum, parallel_wall);
            let honest = honest_speedup(serial_reference_ns, parallel_wall);
            sink.row(&serde_json::json!({
                "cell": CELL, "run_id": id, "kernel": kernel,
                "object": "detailed", "workers": workers, "trial": trial,
                "phase": "summary", "parallel_wall_ns": parallel_wall.as_nanos() as u64,
                "serial_sum_ns": serial_sum.as_nanos() as u64,
                "overlap_ratio": overlap,
                "serial_reference_ns": serial_reference_ns,
                "serial_reference_source": serial_reference_source,
                "honest_speedup": honest,
                "cost_source": cost_source, "worker_balance": balance,
            }));
            println!(
                "{CELL}: workers={workers} trial={trial}: parallel={:.3}s serial-ref={:.3}s honest={honest:.2}x overlap={overlap:.2}x",
                parallel_wall.as_secs_f64(),
                serial_reference_ns as f64 / 1e9,
            );
        }
    }
}

/// Section-dispatched single load for the cleanup twin: the same
/// loader choice as `load_program_timed` (uprobes via multi), but
/// Result-returning so the injected failure surfaces instead of
/// panicking. Skips verifier-stats reads; the twin asserts cleanup.
fn twin_load_one(
    ebpf: &mut aya::Ebpf,
    name: &str,
    section: &aya_obj::ProgramSection,
    btf: &aya::Btf,
    worker: usize,
) -> Result<(), String> {
    use aya_obj::ProgramSection::*;
    let tag = format!("worker {worker}");
    match section {
        UProbe { .. } | URetProbe { .. } => {
            let prog: &mut aya::programs::UProbe = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            prog.load_multi()
                .map_err(|error| format!("{tag}: loading {name}: {error}"))?;
        }
        RawTracePoint => {
            let prog: &mut aya::programs::RawTracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            prog.load()
                .map_err(|error| format!("{tag}: loading raw {name}: {error}"))?;
        }
        BtfTracePoint => {
            let prog: &mut aya::programs::BtfTracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            let target = attach_target(name);
            prog.load(target, btf)
                .map_err(|error| format!("{tag}: loading BTF {name} on {target}: {error}"))?;
        }
        FEntry { .. } => {
            let prog: &mut aya::programs::FEntry = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            let target = attach_target(name);
            prog.load(target, btf)
                .map_err(|error| format!("{tag}: loading fentry {name} on {target}: {error}"))?;
        }
        FExit { .. } => {
            let prog: &mut aya::programs::FExit = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            let target = attach_target(name);
            prog.load(target, btf)
                .map_err(|error| format!("{tag}: loading fexit {name} on {target}: {error}"))?;
        }
        Iter { .. } => {
            let prog: &mut aya::programs::Iter = ebpf
                .program_mut(name)
                .ok_or_else(|| format!("{tag}: program {name} missing"))?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| format!("{tag}: {error}"))?;
            let target = attach_target(name);
            prog.load(target, btf)
                .map_err(|error| format!("{tag}: loading iter {name} on {target}: {error}"))?;
        }
        other => {
            return Err(format!(
                "{tag}: no harness loader for section {other:?} ({name})"
            ));
        }
    }
    Ok(())
}

/// Root runs the parallel-load cleanup twin: one worker is injected a
/// missing program name, so the parallel load fails partway. The failure
/// must surface with the missing name, and every worker's Ebpf stays the
/// single cleanup owner: dropping them must return the FD count to its
/// baseline (no leaked prog/map FDs) with nothing attached or retained.
#[test]
#[ignore = "privileged: parallel-load partial-failure cleanup twin; run as root with --ignored --test-threads=1"]
fn parallel_load_partial_failure_retains_cleanup_owner() {
    const CELL: &str = "parallel_load_partial_failure_retains_cleanup_owner";
    require_root(CELL);
    let bytes = p11scope::EBPF_OBJECT;
    assert!(!bytes.is_empty(), "Detailed object must be embedded");
    let programs = program_sections(bytes);
    assert!(
        programs.len() >= 4,
        "need at least 4 programs to split across workers"
    );
    const BOGUS: &str = "definitely_missing_program";
    assert!(
        !programs.iter().any(|(name, _)| name == BOGUS),
        "injected failure name must not collide with a real program"
    );
    let baseline_fds = fd_count();
    let workers = 4usize;
    let mut parts: Vec<Vec<(String, Option<aya_obj::ProgramSection>)>> = vec![Vec::new(); workers];
    for (index, (name, section)) in programs.iter().enumerate() {
        parts[index % workers].push((name.clone(), Some(section.clone())));
    }
    // Inject the failure into worker 1 after its real programs, so it
    // loads successfully first and then fails partway.
    parts[1].push((BOGUS.to_string(), None));
    let injected_real_share = parts[1].len() - 1;
    let barrier = Arc::new(Barrier::new(workers + 1));
    let handles: Vec<_> = parts
        .into_iter()
        .enumerate()
        .map(|(worker, subset)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || -> Result<usize, (usize, String)> {
                let btf = aya::Btf::from_sys_fs()
                    .map_err(|error| (0, format!("worker {worker} BTF: {error}")))?;
                barrier.wait();
                let (mut ebpf, _maps_wall) = load_object_maps(bytes, &btf);
                let mut loaded = 0usize;
                for (name, section) in &subset {
                    let Some(section) = section else {
                        return Err((
                            loaded,
                            format!("worker {worker}: program {name} missing from object"),
                        ));
                    };
                    if ebpf.program_mut(name).is_none() {
                        return Err((
                            loaded,
                            format!("worker {worker}: program {name} missing from object"),
                        ));
                    }
                    twin_load_one(&mut ebpf, name, section, &btf, worker)
                        .map_err(|error| (loaded, error))?;
                    loaded += 1;
                }
                Ok(loaded)
            })
        })
        .collect();
    barrier.wait();
    let mut failures = Vec::new();
    let mut total_loaded = 0usize;
    let mut injected_partial = 0usize;
    for (worker, handle) in handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ok(loaded)) => total_loaded += loaded,
            Ok(Err((partial, error))) => {
                total_loaded += partial;
                if worker == 1 {
                    injected_partial = partial;
                }
                failures.push((worker, error));
            }
            Err(_) => panic!("{CELL}: worker {worker} panicked"),
        }
    }
    // Every worker's Ebpf dropped at thread exit; FDs must be back.
    assert_eq!(
        failures.len(),
        1,
        "{CELL}: exactly the injected worker must fail, got {failures:?}"
    );
    assert_eq!(
        failures[0].0, 1,
        "{CELL}: the injected worker must be worker 1"
    );
    assert!(
        failures[0].1.contains(BOGUS),
        "{CELL}: the failure must name the missing program, got {:?}",
        failures[0].1
    );
    assert_eq!(
        injected_partial, injected_real_share,
        "{CELL}: the injected worker must load its real share before failing"
    );
    assert_eq!(
        total_loaded,
        programs.len(),
        "{CELL}: every real program must still load exactly once"
    );
    assert_eq!(
        fd_count(),
        baseline_fds,
        "{CELL}: dropping the workers must close every prog/map FD"
    );
    println!(
        "{CELL}: injected failure surfaced ({:?}); {} real programs loaded; FDs {} -> {} (no leak)",
        failures[0].1,
        total_loaded,
        baseline_fds,
        fd_count(),
    );
}

/// Splits one held object's idle RSS into the one-time shared BTF
/// share and the per-object maps/programs share. The daemon pays BTF
/// once (shared via `host_btf::shared`), so fleet projections must
/// scale only the second; saturates because RSS samples can dip.
fn split_hold_cost(baseline_rss_kb: u64, post_btf_rss_kb: u64, idle_rss_kb: u64) -> (u64, u64) {
    (
        post_btf_rss_kb.saturating_sub(baseline_rss_kb),
        idle_rss_kb.saturating_sub(post_btf_rss_kb),
    )
}

/// Root measures the resident-service cost parts on the Detailed object:
/// BTF parse, map/object creation without program loads, the serial
/// program-load sum, and the idle RSS/FD cost of one held fully-loaded
/// object (sampled, held, re-sampled, then dropped and re-sampled),
/// with the shared BTF share sampled separately so per-object
/// projections never scale it. Nothing is attached or retained.
#[test]
#[ignore = "privileged: resident-service cost parts; run as root with --ignored --test-threads=1"]
fn resident_service_cost_parts() {
    const CELL: &str = "resident_service_cost_parts";
    require_root(CELL);
    let id = run_id();
    let kernel = kernel_release();
    let mut sink = Sink::open(CELL);
    let _stats = StatsGuard::engage();
    let stats_label = bpf_stats_enabled().unwrap_or_else(|| "?".to_string());

    let bytes = p11scope::EBPF_OBJECT;
    assert!(!bytes.is_empty(), "Detailed object must be embedded");
    let programs = program_sections(bytes);
    let baseline_fds = fd_count();
    let baseline_rss = rss_kb();

    let btf_start = Instant::now();
    let btf = aya::Btf::from_sys_fs().expect("host vmlinux BTF must load");
    let btf_wall = btf_start.elapsed();
    // The daemon pays BTF once (shared), not per held object: sample
    // after BTF so the per-object delta excludes it.
    let post_btf_fds = fd_count();
    let post_btf_rss = rss_kb();

    // Per-capture floor: fresh maps/object without any program load.
    // Scoped so its map FDs close before the FD assertions below.
    let maps_only_wall = {
        let (_maps_only, maps_only_wall) = load_object_maps(bytes, &btf);
        maps_only_wall
    };

    // Full load: maps plus every program, serial, multi variant.
    let full_start = Instant::now();
    let (mut ebpf, maps_wall) = load_object_maps(bytes, &btf);
    let mut program_sum = Duration::ZERO;
    for (name, section) in &programs {
        let variant = if is_uprobe_section(section) {
            Variant::Multi
        } else {
            Variant::Single
        };
        let row = load_program_timed(&mut ebpf, name, section, variant, &btf);
        program_sum += row.wall;
    }
    let full_wall = full_start.elapsed();

    // Idle hold: the object stays loaded while RSS/FDs are sampled.
    let idle_fds = fd_count();
    let idle_rss = rss_kb();
    std::thread::sleep(Duration::from_secs(2));
    let idle_fds_late = fd_count();
    let idle_rss_late = rss_kb();
    assert_eq!(
        idle_fds, idle_fds_late,
        "{CELL}: held-object FDs must be stable across the idle hold"
    );
    drop(ebpf);
    let after_fds = fd_count();
    let after_rss = rss_kb();
    assert_eq!(
        after_fds, baseline_fds,
        "{CELL}: dropping the object must close every prog/map FD"
    );

    let (btf_rss_kb, object_rss_kb) = split_hold_cost(baseline_rss, post_btf_rss, idle_rss);
    let summary = serde_json::json!({
        "cell": CELL, "run_id": id, "kernel": kernel,
        "bpf_stats_enabled": stats_label, "object": "detailed",
        "programs": programs.len(), "phase": "summary",
        "btf_wall_ns": btf_wall.as_nanos() as u64,
        "maps_only_wall_ns": maps_only_wall.as_nanos() as u64,
        "full_wall_ns": full_wall.as_nanos() as u64,
        "maps_wall_ns": maps_wall.as_nanos() as u64,
        "program_sum_ns": program_sum.as_nanos() as u64,
        "baseline_fds": baseline_fds, "baseline_rss_kb": baseline_rss,
        "post_btf_fds": post_btf_fds, "post_btf_rss_kb": post_btf_rss,
        "btf_rss_kb": btf_rss_kb, "object_rss_kb": object_rss_kb,
        "object_fds": idle_fds.saturating_sub(post_btf_fds),
        "idle_fds": idle_fds, "idle_rss_kb": idle_rss,
        "idle_fds_late": idle_fds_late, "idle_rss_kb_late": idle_rss_late,
        "after_fds": after_fds, "after_rss_kb": after_rss,
    });
    sink.row(&summary);
    println!(
        "{CELL}: btf={:.3}s maps-only={:.3}s full={:.3}s (maps {:.3}s + programs {:.3}s); RSS {} -> {} (post-BTF) -> {} (held) -> {} kB; FDs {} -> {} -> {} -> {}",
        btf_wall.as_secs_f64(),
        maps_only_wall.as_secs_f64(),
        full_wall.as_secs_f64(),
        maps_wall.as_secs_f64(),
        program_sum.as_secs_f64(),
        baseline_rss,
        post_btf_rss,
        idle_rss,
        after_rss,
        baseline_fds,
        post_btf_fds,
        idle_fds,
        after_fds,
    );
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn fake_sysctl(initial: &str) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().expect("temp sysctl");
        file.write_all(initial.as_bytes()).expect("seed sysctl");
        file.flush().expect("flush sysctl");
        let path = file.path().to_str().expect("utf8 temp path").to_string();
        (file, path)
    }

    #[test]
    fn stats_guard_restores_zero_on_drop() {
        let (_file, path) = fake_sysctl("0\n");
        {
            let _guard = StatsGuard::engage_at(&path);
            assert_eq!(read_sysctl(&path).as_deref(), Some("1"));
        }
        assert_eq!(read_sysctl(&path).as_deref(), Some("0"));
    }

    #[test]
    fn stats_guard_restores_zero_on_panic() {
        let (_file, path) = fake_sysctl("0\n");
        let result = std::panic::catch_unwind(|| {
            let _guard = StatsGuard::engage_at(&path);
            assert_eq!(read_sysctl(&path).as_deref(), Some("1"));
            panic!("injected mid-cell panic");
        });
        assert!(result.is_err(), "the injected panic must propagate");
        assert_eq!(read_sysctl(&path).as_deref(), Some("0"));
    }

    #[test]
    fn stats_guard_leaves_nonzero_alone() {
        let (_file, path) = fake_sysctl("1\n");
        {
            let _guard = StatsGuard::engage_at(&path);
            assert_eq!(read_sysctl(&path).as_deref(), Some("1"));
        }
        assert_eq!(read_sysctl(&path).as_deref(), Some("1"));
    }

    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

    /// Serializes tests that mutate process env and restores the prior
    /// value on drop, so parallel tests never observe a half-set var.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn hold(key: &'static str, value: Option<&str>) -> Self {
            let lock = ENV_LOCK
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let prior = std::env::var_os(key);
            // SAFETY: the static mutex serializes every test that touches
            // process env, and no other thread in this binary reads this var.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            Self {
                _lock: lock,
                key,
                prior,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: same serialization as `hold`; restores the pre-test value.
            unsafe {
                match self.prior.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn drop_caches_defaults_to_fresh_process_label() {
        let _env = EnvGuard::hold(DROP_CACHES_ENV, None);
        let mut file = tempfile::NamedTempFile::new().expect("temp sysctl");
        file.write_all(b"seed").expect("seed sysctl");
        file.flush().expect("flush sysctl");
        let path = file.path().to_str().expect("utf8 temp path");
        assert_eq!(drop_caches_for_cold_at(path), "fresh-process-first-trial");
        assert_eq!(
            fs::read_to_string(path).expect("read back").as_str(),
            "seed",
            "default path must not write"
        );
    }

    #[test]
    fn drop_caches_writes_only_with_opt_in() {
        let file = tempfile::NamedTempFile::new().expect("temp sysctl");
        let path = file.path().to_str().expect("utf8 temp path").to_string();
        {
            let _env = EnvGuard::hold(DROP_CACHES_ENV, Some("1"));
            assert_eq!(drop_caches_for_cold_at(&path), "drop_caches");
            assert_eq!(fs::read_to_string(&path).expect("read back").as_str(), "3");
        }
        for value in ["0", "yes", ""] {
            let _env = EnvGuard::hold(DROP_CACHES_ENV, Some(value));
            fs::write(&path, "seed").expect("reseed");
            assert_eq!(
                drop_caches_for_cold_at(&path),
                "fresh-process-first-trial",
                "value {value:?} must not opt in"
            );
            assert_eq!(
                fs::read_to_string(&path).expect("read back").as_str(),
                "seed"
            );
        }
    }

    #[test]
    fn drop_caches_opt_in_failure_keeps_fresh_label() {
        let _env = EnvGuard::hold(DROP_CACHES_ENV, Some("1"));
        let missing = std::env::temp_dir().join("p11scope-feasibility-no-such-dir/sysctl");
        assert_eq!(
            drop_caches_for_cold_at(missing.to_str().expect("utf8")),
            "fresh-process-first-trial"
        );
    }

    fn program_row(name: &str, variant: &str, wall_ns: u64, cold: bool) -> String {
        format!(
            r#"{{"cell":"per_program_load_times","object":"detailed","cold":{cold},"phase":"program","name":"{name}","variant":"{variant}","wall_ns":{wall_ns}}}"#
        )
    }

    fn maps_row(wall_ns: u64, cold: bool) -> String {
        format!(
            r#"{{"cell":"per_program_load_times","object":"detailed","cold":{cold},"phase":"maps","wall_ns":{wall_ns}}}"#
        )
    }

    fn write_baseline(lines: &[String]) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().expect("temp baseline");
        for line in lines {
            file.write_all(line.as_bytes()).expect("write row");
            file.write_all(b"\n").expect("write newline");
        }
        file.flush().expect("flush baseline");
        let path = file.path().to_str().expect("utf8 temp path").to_string();
        (file, path)
    }

    #[test]
    fn baseline_prefers_multi_and_skips_cold() {
        let (_file, path) = write_baseline(&[
            program_row("prog-a", "multi", 100, false),
            program_row("prog-a", "multi", 200, false),
            program_row("prog-a", "single", 10, false),
            program_row("prog-a", "multi", 9999, true),
            program_row("prog-b", "single", 50, false),
            program_row("prog-b", "single", 70, false),
            maps_row(20, false),
            maps_row(30, false),
            maps_row(9999, true),
            r#"{"cell":"per_program_load_times","object":"counter-counts","cold":false,"phase":"program","name":"prog-a","variant":"multi","wall_ns":9999}"#.to_string(),
            r#"{"cell":"other_cell","object":"detailed","cold":false,"phase":"maps","wall_ns":9999}"#.to_string(),
            r#"{"cell":"per_program_load_times","object":"detailed","cold":false,"phase":"btf","wall_ns":9999}"#.to_string(),
        ]);
        let costs = baseline_program_costs(&path, "detailed").expect("parse baseline");
        assert_eq!(costs.programs.get("prog-a"), Some(&150.0));
        assert_eq!(costs.programs.get("prog-b"), Some(&60.0));
        assert_eq!(costs.maps_mean_ns, 25.0);
    }

    #[test]
    fn baseline_refuses_missing_file() {
        let error = baseline_program_costs("/nonexistent/baseline.jsonl", "detailed")
            .expect_err("missing file must fail loud");
        assert!(error.contains("read"), "unexpected: {error}");
    }

    #[test]
    fn baseline_refuses_without_warm_maps() {
        let (_file, path) = write_baseline(&[program_row("prog-a", "single", 10, false)]);
        let error = baseline_program_costs(&path, "detailed")
            .expect_err("maps-less baseline must fail loud");
        assert!(error.contains("no warm maps"), "unexpected: {error}");
    }

    #[test]
    fn baseline_refuses_bad_json() {
        let (_file, path) = write_baseline(&["{bad json".to_string()]);
        let error =
            baseline_program_costs(&path, "detailed").expect_err("corrupt line must fail loud");
        assert!(error.contains("bad JSON"), "unexpected: {error}");
    }

    #[test]
    fn order_by_cost_sorts_descending_and_checks_sets() {
        let costs = BTreeMap::from([
            ("a".to_string(), 1.0),
            ("b".to_string(), 3.0),
            ("c".to_string(), 2.0),
        ]);
        let expected = BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(
            order_by_cost(&costs, &expected).expect("exact set"),
            vec!["b".to_string(), "c".to_string(), "a".to_string()]
        );
        let wide = BTreeSet::from(["a".to_string(), "b".to_string(), "zzz".to_string()]);
        let error = order_by_cost(&costs, &wide).expect_err("missing must fail");
        assert!(error.contains("zzz"), "unexpected: {error}");
        let narrow = BTreeSet::from(["a".to_string()]);
        let error = order_by_cost(&costs, &narrow).expect_err("unknown must fail");
        assert!(error.contains("unknown"), "unexpected: {error}");
    }

    #[test]
    fn deal_round_robin_splits_descending() {
        let order: Vec<String> = (0..5).map(|index| format!("n{index}")).collect();
        assert_eq!(
            deal_round_robin(&order, 2),
            vec![
                vec!["n0".to_string(), "n2".to_string(), "n4".to_string()],
                vec!["n1".to_string(), "n3".to_string()],
            ]
        );
    }

    #[test]
    fn worker_balance_reports_ratio() {
        let costs = BTreeMap::from([("a".to_string(), 3.0), ("b".to_string(), 1.0)]);
        let parts = vec![vec!["a".to_string()], vec!["b".to_string()]];
        assert_eq!(worker_balance(&parts, &costs), Some(3.0));
        let empty: BTreeMap<String, f64> = BTreeMap::new();
        assert_eq!(worker_balance(&parts, &empty), None);
    }

    #[test]
    fn serial_reference_sums_programs_and_maps() {
        let costs = BaselineCosts {
            programs: BTreeMap::from([("a".to_string(), 1e9), ("b".to_string(), 2e9)]),
            maps_mean_ns: 0.5e9,
        };
        assert_eq!(costs.serial_reference_ns(), 3.5e9);
    }

    #[test]
    fn honest_and_overlap_ratios_differ() {
        // Contended per-program walls inflate the sum above the serial
        // reference; overlap must exceed honest on the same trial.
        let honest = honest_speedup(8_000_000_000, Duration::from_secs(4));
        let overlap = overlap_ratio(Duration::from_secs(10), Duration::from_secs(4));
        assert_eq!(honest, 2.0);
        assert_eq!(overlap, 2.5);
    }

    #[test]
    fn honest_speedup_guards_zero_wall() {
        let honest = honest_speedup(8_000_000_000, Duration::ZERO);
        assert!(honest.is_finite(), "zero wall must not yield NaN/inf");
    }

    #[test]
    fn split_hold_cost_isolates_shared_btf() {
        // Lane shape: 12.3MB process baseline, ~7MB BTF, ~12.5MB more
        // for the held maps/programs. Only the last scales per object.
        assert_eq!(split_hold_cost(12_256, 19_500, 31_792), (7_244, 12_292));
    }

    #[test]
    fn split_hold_cost_saturates_on_rss_dips() {
        assert_eq!(split_hold_cost(100, 90, 80), (0, 0));
        assert_eq!(split_hold_cost(100, 110, 105), (10, 0));
    }
}
