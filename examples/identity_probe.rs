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
//!
//! Usage errors exit 2.

use p11scope::attach::identity_iter as ii;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: identity_probe deny-check [--btf PATH]");
    eprintln!("       identity_probe probe --dir DIR [--generation N]");
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
        _ => usage(),
    }
}
