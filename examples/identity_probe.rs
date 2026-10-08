//! SPDX-License-Identifier: GPL-3.0-or-later
//! Stage 3 Wave D (W3-2): the kernel-identity probe CLI for privileged
//! host cells and vng guest cells (which cannot run cargo).
//!
//! Subcommands:
//! - `deny-check [--btf PATH]`: run the §6.1 items 2–4 BTF eligibility
//!   check and nothing else — this path issues zero `bpf()` syscalls, so
//!   a `DENY` verdict is structurally before-load. Prints `ELIGIBLE` or
//!   `DENY <reason>`; exits 0 or 3.
//! - `probe --dir DIR [--generation N]`: the §6.5 functional probe
//!   (fixture, executable-mapping child, anchor + target + stale runs).
//!   Prints the verdict lines plus `PROBE PASS` or `PROBE FAIL <stage>`;
//!   exits 0 or 4. Needs privileges (strict load + attach).
//! - `cost --population N --runs K [--per-pid-runs J]
//!   [--userspace-sample S]`: the D2c cost bench. Spawns `N` pause
//!   children, runs `K` whole-system target runs plus `J` per-pid runs
//!   over them, and times the userspace `map_files` proof over `S`
//!   sampled pids. Prints one JSON line per measurement plus a `SUMMARY`
//!   line with whole-system p50/p95/max, per-pid median, userspace
//!   per-pid median, and `S_MIN`. Every run must cover every child or
//!   the bench fails loudly. Needs privileges. Exits 0 or 4.
//!
//! Usage errors exit 2.

use p11scope::attach::identity_iter as ii;
use std::os::fd::AsFd as _;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: identity_probe deny-check [--btf PATH]");
    eprintln!("       identity_probe probe --dir DIR [--generation N]");
    eprintln!(
        "       identity_probe cost --population N --runs K [--per-pid-runs J] [--userspace-sample S]"
    );
    std::process::exit(2);
}

fn deny_check(btf_path: Option<PathBuf>) -> ! {
    let verdict = match btf_path {
        Some(path) => match std::fs::read(&path) {
            Ok(bytes) => ii::check_kernel_identity_btf(&bytes),
            Err(error) => Err(ii::KernelDeny::NoBtf(format!(
                "{}: {error}",
                path.display()
            ))),
        },
        None => ii::ensure_kernel_identity_btf().map(|_| ()),
    };
    match verdict {
        Ok(()) => {
            println!("ELIGIBLE");
            std::process::exit(0);
        }
        Err(deny) => {
            println!("DENY {}", deny.reason());
            std::process::exit(3);
        }
    }
}

fn probe(dir: PathBuf, generation: u64) -> ! {
    if let Err(deny) = ii::ensure_kernel_identity_btf() {
        println!("PROBE FAIL deny: {}", deny.reason());
        std::process::exit(4);
    }
    let btf = match aya::Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(error) => {
            println!("PROBE FAIL btf: {error}");
            std::process::exit(4);
        }
    };
    let mut loaded = match ii::load_identity_object_strict(&btf) {
        Ok(loaded) => loaded,
        Err(error) => {
            println!("PROBE FAIL load: {error:#}");
            if let Some(log) = ii::verifier_log_of(&error) {
                println!("--- verifier log ---\n{log}");
            }
            std::process::exit(4);
        }
    };
    match ii::run_functional_probe(&dir, &mut loaded, generation) {
        Ok(report) => {
            println!("child_pid={}", report.child_pid);
            println!("anchor_outcomes={:?}", report.anchor_outcomes);
            println!("hardlink={:?}", report.hardlink_verdict);
            println!("second={:?}", report.second_verdict);
            println!("copy={:?}", report.copy_verdict);
            println!(
                "records={} unmatched={}",
                report.child_record_count, report.child_unmatched_count
            );
            println!("pids_seen={:?}", report.pids_seen);
            println!("demoted={:?}", report.demoted_pids);
            println!("stale_unmatched={}", report.stale_unmatched);
            let pass = report.anchor_outcomes
                == vec![(0, ii::AnchorOutcome::Ok), (1, ii::AnchorOutcome::Ok)]
                && report.hardlink_verdict == ii::TargetVerdict::Slot(0)
                && report.second_verdict == ii::TargetVerdict::Slot(1)
                && report.copy_verdict == ii::TargetVerdict::Unmatched
                && report.pids_seen == vec![report.child_pid]
                && report.child_unmatched_count + 2 == report.child_record_count
                && report.demoted_pids.is_empty()
                && report.stale_unmatched;
            if pass {
                println!("PROBE PASS");
                std::process::exit(0);
            }
            println!("PROBE FAIL verdicts");
            std::process::exit(4);
        }
        Err(error) => {
            println!("PROBE FAIL {}: {}", error.stage, error.detail);
            std::process::exit(4);
        }
    }
}

fn percentile(sorted_ms: &[f64], pct: f64) -> f64 {
    assert!(!sorted_ms.is_empty());
    let rank = (pct / 100.0 * (sorted_ms.len() - 1) as f64).round() as usize;
    sorted_ms[rank.min(sorted_ms.len() - 1)]
}

/// Time the userspace proof primitive for one pid: open its `map_files`
/// dir, `fstatat` every executable file range from its maps, close.
/// Returns (ranges statted, milliseconds).
fn userspace_proof_cost(pid: u32) -> Result<(usize, f64), String> {
    let maps =
        std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| format!("maps: {e}"))?;
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let perms = fields.next().unwrap_or("");
        let tail: Vec<&str> = fields.collect();
        let Some(path) = tail.last() else { continue };
        if path.starts_with('[') || !perms.as_bytes().get(2).is_some_and(|b| *b == b'x') {
            continue;
        }
        ranges.push(range.to_owned());
    }
    let start = std::time::Instant::now();
    // SAFETY: `open`/`fstatat`/`close` on live paths; the dir fd is held
    // across the stats and closed after.
    unsafe {
        let dir_path = std::ffi::CString::new(format!("/proc/{pid}/map_files"))
            .map_err(|e| format!("cstr: {e}"))?;
        let dirfd = libc::open(dir_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if dirfd < 0 {
            return Err(format!(
                "map_files open: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut stat: libc::stat = std::mem::zeroed();
        for range in &ranges {
            let name = std::ffi::CString::new(range.as_str()).map_err(|e| format!("cstr: {e}"))?;
            if libc::fstatat(dirfd, name.as_ptr(), &mut stat, 0) != 0 {
                let error = std::io::Error::last_os_error();
                libc::close(dirfd);
                return Err(format!("fstatat {range}: {error}"));
            }
        }
        libc::close(dirfd);
    }
    Ok((ranges.len(), start.elapsed().as_secs_f64() * 1000.0))
}

fn ambient_tasks() -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
                count += 1;
            }
        }
    }
    count
}

#[allow(clippy::too_many_lines)]
fn cost(population: u32, runs: u32, per_pid_runs: u32, userspace_sample: u32) -> ! {
    if population == 0 || runs == 0 {
        usage();
    }
    if let Err(deny) = ii::ensure_kernel_identity_btf() {
        println!("COST FAIL deny: {}", deny.reason());
        std::process::exit(4);
    }
    let fail = |stage: &str, detail: String| -> ! {
        println!("COST FAIL {stage}: {detail}");
        std::process::exit(4);
    };
    let btf = aya::Btf::from_sys_fs().unwrap_or_else(|e| fail("btf", e.to_string()));
    let mut loaded =
        ii::load_identity_object_strict(&btf).unwrap_or_else(|e| fail("load", format!("{e:#}")));
    let spawn_start = std::time::Instant::now();
    let mut children =
        ii::spawn_pause_children(population).unwrap_or_else(|e| fail("spawn", e.to_string()));
    let spawn_ms = spawn_start.elapsed().as_secs_f64() * 1000.0;
    let pids: Vec<u32> = children.iter().map(ii::MappedChild::pid).collect();
    let ambient = ambient_tasks().saturating_sub(population as usize + 1);
    let observer = std::process::id();
    let arena = ii::AnchorArena::reserve(1).unwrap_or_else(|e| fail("arena", e.to_string()));
    let config = arena.config(11, 0, observer);
    if let Err(e) = ii::validate_arena_config(&config) {
        fail("arena-config", format!("{e:?}"));
    }
    if let Err(e) = ii::write_identity_config(&mut loaded.ebpf, &config) {
        fail("config", format!("{e}"));
    }
    if let Err(e) = ii::write_scope_bitmap(&mut loaded.ebpf, &pids) {
        fail("scope", format!("{e}"));
    }
    let scope: std::collections::BTreeSet<u32> = pids.iter().copied().collect();
    println!(
        "{{\"cell\":\"setup\",\"population\":{population},\"ambient_tasks\":{ambient},\"spawn_ms\":{spawn_ms:.3}}}"
    );
    // Whole-system runs.
    let mut whole_ms = Vec::with_capacity(runs as usize);
    for run in 0..runs {
        let start = std::time::Instant::now();
        let bytes = ii::attach_and_read_run(
            loaded.target_fd.as_fd(),
            None,
            start + std::time::Duration::from_secs(60),
            64 * 1024 * 1024,
        )
        .unwrap_or_else(|e| fail("run", format!("{e}")));
        let run_ms = start.elapsed().as_secs_f64() * 1000.0;
        let parse_start = std::time::Instant::now();
        let parsed = ii::parse(
            &bytes,
            &ii::Expect {
                generation: 11,
                slots: 0,
                scope: &scope,
                mode: ii::RunMode::WholeSystem,
                run: ii::RunKind::Target,
            },
        )
        .unwrap_or_else(|e| fail("parse", format!("{e:?}")));
        let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;
        if parsed.by_pid.len() != population as usize {
            fail(
                "coverage",
                format!(
                    "run {run}: {}/{} pids emitted",
                    parsed.by_pid.len(),
                    population
                ),
            );
        }
        if !parsed.demoted_pids.is_empty() {
            fail(
                "coverage",
                format!("run {run}: demotions {:?}", parsed.demoted_pids),
            );
        }
        let records: usize = parsed
            .by_pid
            .values()
            .map(std::collections::BTreeMap::len)
            .sum();
        whole_ms.push(run_ms);
        println!(
            "{{\"cell\":\"whole\",\"run\":{run},\"run_ms\":{run_ms:.3},\"parse_ms\":{parse_ms:.3},\"bytes\":{},\"records\":{records},\"pids\":{}}}",
            bytes.len(),
            parsed.by_pid.len()
        );
    }
    // Per-pid runs over the first child.
    let mut perpid_ms = Vec::with_capacity(per_pid_runs as usize);
    if per_pid_runs > 0 {
        let pidfd = ii::open_pidfd(pids[0]).unwrap_or_else(|e| fail("pidfd", e.to_string()));
        let single: std::collections::BTreeSet<u32> = [pids[0]].into_iter().collect();
        for run in 0..per_pid_runs {
            let start = std::time::Instant::now();
            let bytes = ii::attach_and_read_run(
                loaded.target_fd.as_fd(),
                Some(pidfd.as_fd()),
                start + std::time::Duration::from_secs(60),
                1024 * 1024,
            )
            .unwrap_or_else(|e| fail("perpid-run", format!("{e}")));
            let run_ms = start.elapsed().as_secs_f64() * 1000.0;
            let parsed = ii::parse(
                &bytes,
                &ii::Expect {
                    generation: 11,
                    slots: 0,
                    scope: &single,
                    mode: ii::RunMode::PerPid,
                    run: ii::RunKind::Target,
                },
            )
            .unwrap_or_else(|e| fail("perpid-parse", format!("{e:?}")));
            let records: usize = parsed
                .by_pid
                .values()
                .map(std::collections::BTreeMap::len)
                .sum();
            perpid_ms.push(run_ms);
            println!(
                "{{\"cell\":\"perpid\",\"run\":{run},\"run_ms\":{run_ms:.3},\"bytes\":{},\"records\":{records}}}",
                bytes.len()
            );
        }
    }
    // Userspace proof cost over a deterministic sample (every k-th pid).
    let mut user_ms = Vec::new();
    if userspace_sample > 0 {
        let step = (population / userspace_sample.max(1)).max(1) as usize;
        let sample: Vec<u32> = pids
            .iter()
            .copied()
            .step_by(step)
            .take(userspace_sample as usize)
            .collect();
        for pid in sample {
            match userspace_proof_cost(pid) {
                Ok((ranges, ms)) => {
                    user_ms.push(ms);
                    println!(
                        "{{\"cell\":\"userspace\",\"pid\":{pid},\"ranges\":{ranges},\"ms\":{ms:.3}}}"
                    );
                }
                Err(detail) => fail("userspace", detail),
            }
        }
    }
    for child in &mut children {
        child.reap();
    }
    whole_ms.sort_by(f64::total_cmp);
    let whole_p50 = percentile(&whole_ms, 50.0);
    let whole_p95 = percentile(&whole_ms, 95.0);
    let whole_max = whole_ms.last().copied().unwrap_or(0.0);
    perpid_ms.sort_by(f64::total_cmp);
    let perpid_med = if perpid_ms.is_empty() {
        0.0
    } else {
        percentile(&perpid_ms, 50.0)
    };
    user_ms.sort_by(f64::total_cmp);
    let user_med = if user_ms.is_empty() {
        0.0
    } else {
        percentile(&user_ms, 50.0)
    };
    let s_min = if user_med > 0.0 {
        (whole_p50 / user_med).ceil() as u64
    } else {
        0
    };
    println!(
        "SUMMARY population={population} runs={runs} ambient_tasks={ambient} spawn_ms={spawn_ms:.1} \
         whole_p50_ms={whole_p50:.3} whole_p95_ms={whole_p95:.3} whole_max_ms={whole_max:.3} \
         perpid_med_ms={perpid_med:.3} userspace_med_ms={user_med:.3} s_min={s_min}"
    );
    std::process::exit(0);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
    };
    match command.as_str() {
        "deny-check" => {
            let mut btf_path = None;
            let rest: Vec<String> = args.collect();
            let mut index = 0;
            while index < rest.len() {
                if rest[index] == "--btf" && index + 1 < rest.len() {
                    btf_path = Some(PathBuf::from(&rest[index + 1]));
                    index += 2;
                } else {
                    usage();
                }
            }
            deny_check(btf_path);
        }
        "probe" => {
            let rest: Vec<String> = args.collect();
            let mut dir = None;
            let mut generation = 1u64;
            let mut index = 0;
            while index < rest.len() {
                match rest[index].as_str() {
                    "--dir" if index + 1 < rest.len() => {
                        dir = Some(PathBuf::from(&rest[index + 1]));
                        index += 2;
                    }
                    "--generation" if index + 1 < rest.len() => {
                        generation = rest[index + 1].parse().unwrap_or_else(|_| usage());
                        index += 2;
                    }
                    _ => usage(),
                }
            }
            probe(dir.unwrap_or_else(|| usage()), generation);
        }
        "cost" => {
            let rest: Vec<String> = args.collect();
            let mut population = None;
            let mut runs = None;
            let mut per_pid_runs = 31u32;
            let mut userspace_sample = 128u32;
            let mut index = 0;
            while index < rest.len() {
                let number = |value: &str| value.parse().unwrap_or_else(|_| usage());
                match rest[index].as_str() {
                    "--population" if index + 1 < rest.len() => {
                        population = Some(number(&rest[index + 1]));
                        index += 2;
                    }
                    "--runs" if index + 1 < rest.len() => {
                        runs = Some(number(&rest[index + 1]));
                        index += 2;
                    }
                    "--per-pid-runs" if index + 1 < rest.len() => {
                        per_pid_runs = number(&rest[index + 1]);
                        index += 2;
                    }
                    "--userspace-sample" if index + 1 < rest.len() => {
                        userspace_sample = number(&rest[index + 1]);
                        index += 2;
                    }
                    _ => usage(),
                }
            }
            cost(
                population.unwrap_or_else(|| usage()),
                runs.unwrap_or_else(|| usage()),
                per_pid_runs,
                userspace_sample,
            );
        }
        _ => usage(),
    }
}
