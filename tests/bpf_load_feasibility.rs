//! SPDX-License-Identifier: GPL-3.0-or-later
//! BPF load feasibility measurements (parallel loading, resident service).
//!
//! Ignored privileged cells, run by hand as root under the privileged lock:
//! per-program load cost (wall time, verifier-reported processed
//! instructions where the kernel exposes them), parallel-load overlap, and
//! resident-service cost parts. Uses the embedded objects through the
//! existing `pub` statics only; never changes product code paths. Nothing
//! is attached, pinned, executed or retained: every load is dropped at the
//! end of its trial.
//!
//! Rows go to stdout as JSONL and, when `P11SCOPE_FEASIBILITY_OUT` names a
//! directory, are appended to `<dir>/<cell>.jsonl` with a `run_id` per
//! process. `P11SCOPE_FEASIBILITY_TRIALS` overrides the trial counts
//! (default 10 for the per-program cell, 5 for the parallel cell); the
//! cleanup twin always runs once.

use std::collections::BTreeMap;
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

fn bpf_stats_enabled() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/bpf_stats_enabled")
        .ok()
        .map(|value| value.trim().to_string())
}

fn set_bpf_stats_enabled(value: &str) -> std::io::Result<()> {
    fs::write("/proc/sys/kernel/bpf_stats_enabled", value)?;
    Ok(())
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Attempt the cold-load precondition: drop page cache (including the
/// cached `/sys/kernel/btf/vmlinux` blob) so trial 0 is cache-cold.
/// Returns the cold method label actually achieved.
fn drop_caches_for_cold() -> &'static str {
    match fs::write("/proc/sys/vm/drop_caches", "3") {
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
    let stats_before = bpf_stats_enabled();
    if stats_before.as_deref() == Some("0") {
        set_bpf_stats_enabled("1").expect("enable bpf_stats for verified_insns");
    }
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
    if stats_before.as_deref() == Some("0") {
        let _ = set_bpf_stats_enabled("0");
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
/// barrier, measuring parallel wall against the serial sum. Reports the
/// kernel-side serialization the design must live with. Nothing is
/// attached or retained.
#[test]
#[ignore = "privileged: parallel BPF load overlap probe; run as root with --ignored --test-threads=1"]
fn parallel_load_measures_kernel_overlap() {
    const CELL: &str = "parallel_load_measures_kernel_overlap";
    require_root(CELL);
    let trials = trial_count(5);
    let id = run_id();
    let kernel = kernel_release();
    let mut sink = Sink::open(CELL);
    let stats_before = bpf_stats_enabled();
    if stats_before.as_deref() == Some("0") {
        set_bpf_stats_enabled("1").expect("enable bpf_stats for verified_insns");
    }
    let stats_label = bpf_stats_enabled().unwrap_or_else(|| "?".to_string());

    let bytes = p11scope::EBPF_OBJECT;
    assert!(!bytes.is_empty(), "Detailed object must be embedded");
    let programs = program_sections(bytes);
    assert!(
        programs.len() >= 4,
        "need at least 4 programs to split across workers"
    );
    // Longest-processing-time order from the lane's own per-program means
    // (per_program_load_times, warm multi): dealing round-robin over
    // descending cost balances worker sums. The set equality below fails
    // loud if the object gains, loses, or renames a program.
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
    for workers in [2usize, 4usize] {
        // LPT partition: round-robin over descending cost keeps worker
        // sums balanced (name-sorted round-robin stacked p11_return and
        // interface_list_worker on one worker, capping speedup at 1.5x).
        let mut parts: Vec<Vec<(String, aya_obj::ProgramSection)>> = vec![Vec::new(); workers];
        for (index, name) in COST_ORDER.iter().enumerate() {
            let section = by_name.get(name).expect("checked above").clone();
            parts[index % workers].push((name.to_string(), section));
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
            let speedup = serial_sum.as_secs_f64() / parallel_wall.as_secs_f64().max(f64::EPSILON);
            sink.row(&serde_json::json!({
                "cell": CELL, "run_id": id, "kernel": kernel,
                "object": "detailed", "workers": workers, "trial": trial,
                "phase": "summary", "parallel_wall_ns": parallel_wall.as_nanos() as u64,
                "serial_sum_ns": serial_sum.as_nanos() as u64, "speedup": speedup,
            }));
            println!(
                "{CELL}: workers={workers} trial={trial}: parallel={:.3}s serial-sum={:.3}s speedup={speedup:.2}x",
                parallel_wall.as_secs_f64(),
                serial_sum.as_secs_f64(),
            );
        }
    }
    if stats_before.as_deref() == Some("0") {
        let _ = set_bpf_stats_enabled("0");
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

/// Root measures the resident-service cost parts on the Detailed object:
/// BTF parse, map/object creation without program loads, the serial
/// program-load sum, and the idle RSS/FD cost of one held fully-loaded
/// object (sampled, held, re-sampled, then dropped and re-sampled).
/// Nothing is attached or retained.
#[test]
#[ignore = "privileged: resident-service cost parts; run as root with --ignored --test-threads=1"]
fn resident_service_cost_parts() {
    const CELL: &str = "resident_service_cost_parts";
    require_root(CELL);
    let id = run_id();
    let kernel = kernel_release();
    let mut sink = Sink::open(CELL);
    let stats_before = bpf_stats_enabled();
    if stats_before.as_deref() == Some("0") {
        set_bpf_stats_enabled("1").expect("enable bpf_stats for verified_insns");
    }
    let stats_label = bpf_stats_enabled().unwrap_or_else(|| "?".to_string());

    let bytes = p11scope::EBPF_OBJECT;
    assert!(!bytes.is_empty(), "Detailed object must be embedded");
    let programs = program_sections(bytes);
    let baseline_fds = fd_count();
    let baseline_rss = rss_kb();

    let btf_start = Instant::now();
    let btf = aya::Btf::from_sys_fs().expect("host vmlinux BTF must load");
    let btf_wall = btf_start.elapsed();

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
        "idle_fds": idle_fds, "idle_rss_kb": idle_rss,
        "idle_fds_late": idle_fds_late, "idle_rss_kb_late": idle_rss_late,
        "after_fds": after_fds, "after_rss_kb": after_rss,
    });
    sink.row(&summary);
    if stats_before.as_deref() == Some("0") {
        let _ = set_bpf_stats_enabled("0");
    }
    println!(
        "{CELL}: btf={:.3}s maps-only={:.3}s full={:.3}s (maps {:.3}s + programs {:.3}s); RSS {} -> {} -> {} kB; FDs {} -> {} -> {}",
        btf_wall.as_secs_f64(),
        maps_only_wall.as_secs_f64(),
        full_wall.as_secs_f64(),
        maps_wall.as_secs_f64(),
        program_sum.as_secs_f64(),
        baseline_rss,
        idle_rss,
        after_rss,
        baseline_fds,
        idle_fds,
        after_fds,
    );
}
