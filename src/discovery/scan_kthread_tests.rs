//! SPDX-License-Identifier: GPL-3.0-or-later
//! Empty-maps classification: a kernel thread's `/proc/<pid>/maps` reads 0
//! bytes successfully (no user address space), which must scan as verified
//! absence — not as a refusal that forces every `--system` capture PARTIAL.
//! A zombie (empty maps, executable gone, no kernel-thread flag) follows the
//! exited path instead, and empty maps with a live executable keep the
//! refusal. Classification inputs ride the `ScanIo` seams, so every byte the
//! classifier sees here is scripted except in the one real-`/proc` test.

use super::*;
use crate::process::{PF_KTHREAD, start_time_from_stat, stat_flags_from_stat_text};
use std::io::{self, Cursor};

/// Scripted empty-maps fixture: maps bytes plus scripted `/proc` stat/exe
/// answers. The process view pins the test process itself, so generation
/// checks pass while every classified byte is scripted.
struct EmptyMapsFixture {
    maps: Vec<u8>,
    stat: Result<String, io::ErrorKind>,
    exe: Result<PathBuf, io::ErrorKind>,
}

struct DummyMem;

impl ScanMemory for DummyMem {
    fn read_memory_at(&self, _bytes: &mut [u8], _offset: u64) -> io::Result<usize> {
        Err(io::Error::other(
            "memory not scripted in empty-maps fixture",
        ))
    }
}

fn scripted<T: Clone>(value: &Result<T, io::ErrorKind>, what: &'static str) -> io::Result<T> {
    value.clone().map_err(|kind| io::Error::new(kind, what))
}

impl ScanIo for EmptyMapsFixture {
    type Memory = DummyMem;

    fn open_maps(&mut self, _: &ProcessView, _: &CaptureWorkBudget) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(Cursor::new(self.maps.clone())))
    }

    fn open_mem(&mut self, _: &ProcessView) -> io::Result<DummyMem> {
        Err(io::Error::other("mem not scripted in empty-maps fixture"))
    }

    fn final_generation(&mut self, view: &ProcessView) -> Result<(), String> {
        view.run_while_same(|| ())
    }

    fn stat_text(&mut self, _: &ProcessView) -> io::Result<String> {
        scripted(&self.stat, "scripted stat")
    }

    fn exe_target(&mut self, _: &ProcessView) -> io::Result<PathBuf> {
        scripted(&self.exe, "scripted exe")
    }
}

/// A `/proc/<pid>/stat` line with the given flags and start time. Field 9
/// holds the flags, field 22 the start time; the classifier binds both to
/// the view's pinned generation.
fn stat_line(pid: u32, comm: &str, flags: u32, start_time: u64) -> String {
    format!("{pid} ({comm}) S 0 0 0 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 {start_time} 0")
}

/// `PF_KTHREAD` flags fixture: kthreadd-shaped stat line (field 9 holds
/// `0x00200000`), bound to the view's own pinned start time.
fn kthread_stat(start_time: u64) -> String {
    stat_line(2, "kthreadd", PF_KTHREAD, start_time)
}

/// Non-kernel-thread flags fixture: `PF_RANDOMIZE` (`0x00400000`) shares no
/// bit with `PF_KTHREAD` (`0x00200000`), bound to the view's own pinned
/// start time.
fn user_stat(start_time: u64) -> String {
    stat_line(1234, "worker", 0x0040_0000, start_time)
}

fn self_view() -> ProcessView {
    ProcessView::open(ProcessViewId(501), std::process::id()).unwrap()
}

fn run_empty_maps(
    fixture: &mut EmptyMapsFixture,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    let view = self_view();
    let hooks = HookRegistry::builtin();
    scan_process_view_with_io(
        &ScanRequest {
            pid: view.pid(),
            hints: &[],
            hooks: &hooks,
        },
        &view,
        budget,
        fixture,
    )
}

fn pinned_start_time() -> u64 {
    self_view()
        .start_time()
        .expect("the test process pins a start time")
}

#[test]
fn scan_kernel_thread_empty_maps_is_verified_absence() {
    let mut fixture = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(kthread_stat(pinned_start_time())),
        // No executable, like a real kernel thread — but the stat flag, not
        // the missing exe, must drive the verdict.
        exe: Err(io::ErrorKind::NotFound),
    };
    let mut budget = CaptureWorkBudget::default();
    let outcome =
        run_empty_maps(&mut fixture, &mut budget).expect("kernel thread must scan, not error");
    assert!(
        outcome.unavailable_reason().is_none(),
        "kernel thread must complete the mapping bracket, got {outcome:?}"
    );
    assert_eq!(
        outcome.modules().len(),
        0,
        "kernel thread has no modules, got {outcome:?}"
    );
    assert!(
        outcome.skipped().is_empty(),
        "kernel thread must leave no skip, got {:?}",
        outcome.skipped()
    );
    assert_eq!(
        budget.kernel_thread_absences(),
        1,
        "one verified absence is counted once"
    );
}

#[test]
fn scan_empty_maps_zombie_is_not_absence() {
    let mut fixture = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(user_stat(pinned_start_time())),
        exe: Err(io::ErrorKind::NotFound),
    };
    let mut budget = CaptureWorkBudget::default();
    let error = run_empty_maps(&mut fixture, &mut budget)
        .expect_err("zombie/exiting empty maps must follow the exited path, never Ok");
    assert!(
        error.contains("exited before discovery"),
        "zombie must reuse the exited path, got {error:?}"
    );
    assert_eq!(
        budget.kernel_thread_absences(),
        0,
        "the exited path never counts as verified absence"
    );
}

#[test]
fn scan_empty_maps_live_exe_still_refuses() {
    let mut fixture = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(user_stat(pinned_start_time())),
        exe: Ok(PathBuf::from("/usr/bin/worker")),
    };
    let mut budget = CaptureWorkBudget::default();
    let outcome = run_empty_maps(&mut fixture, &mut budget)
        .expect("live exe must keep today's refusal outcome");
    assert!(
        outcome.skipped().iter().any(|skip| skip
            .reason
            .contains("empty or truncated /proc maps snapshot")),
        "live exe must keep today's refusal, got {:?}",
        outcome.skipped()
    );
    assert_eq!(
        budget.kernel_thread_absences(),
        0,
        "a refusal never counts as verified absence"
    );
}

#[test]
fn scan_empty_maps_malformed_stat_still_refuses() {
    for stat in [
        String::new(),
        "123 no-paren-here".to_string(),
        "123 (x) S 1".to_string(),
        "123 (x) S 1 2 3 4 -1 notanumber".to_string(),
    ] {
        let mut fixture = EmptyMapsFixture {
            maps: Vec::new(),
            stat: Ok(stat),
            exe: Err(io::ErrorKind::NotFound),
        };
        let mut budget = CaptureWorkBudget::default();
        let outcome = run_empty_maps(&mut fixture, &mut budget)
            .expect("malformed stat must keep the refusal");
        assert!(
            outcome.skipped().iter().any(|skip| skip
                .reason
                .contains("empty or truncated /proc maps snapshot")),
            "malformed stat must keep today's refusal, got {:?}",
            outcome.skipped()
        );
        assert_eq!(budget.kernel_thread_absences(), 0);
    }
}

#[test]
fn scan_empty_maps_recycled_generation_still_refuses() {
    // The stat line carries PF_KTHREAD but a start time that is not the
    // view's pinned generation: a pid recycled between the maps read and
    // the stat read. Positive flags on the wrong generation must refuse,
    // never count as verified absence.
    let recycled = pinned_start_time().wrapping_add(1_000_000_000);
    let mut fixture = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(kthread_stat(recycled)),
        exe: Err(io::ErrorKind::NotFound),
    };
    let mut budget = CaptureWorkBudget::default();
    let outcome =
        run_empty_maps(&mut fixture, &mut budget).expect("recycled pid must keep the refusal");
    assert!(
        outcome.skipped().iter().any(|skip| skip
            .reason
            .contains("empty or truncated /proc maps snapshot")),
        "recycled generation must keep today's refusal, got {:?}",
        outcome.skipped()
    );
    assert_eq!(
        budget.kernel_thread_absences(),
        0,
        "a recycled generation never counts as verified absence"
    );
}

#[test]
fn scan_empty_maps_exited_view_is_never_absence() {
    // A child pinned alive, then killed and reaped before the scan: the
    // pinned generation is provably gone, so even scripted kernel-thread
    // bytes bound to its old start time must not classify.
    // A held stdin pipe keeps `cat` waiting; a null stdin lets it exit
    // before the pin, which then fails on the dead mount namespace.
    let mut child = std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn a child that waits to be killed");
    let pid = child.id();
    let view = ProcessView::open(ProcessViewId(503), pid).expect("pin the live child");
    let start_time = view.start_time().unwrap_or(0);
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::default();
    let mut fixture = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(kthread_stat(start_time)),
        exe: Err(io::ErrorKind::NotFound),
    };
    let result = scan_process_view_with_io(
        &ScanRequest {
            pid,
            hints: &[],
            hooks: &hooks,
        },
        &view,
        &mut budget,
        &mut fixture,
    );
    match result {
        Err(error) => assert!(
            error.contains("exited before discovery") || error.contains("generation changed"),
            "an exited view fails closed, got {error:?}"
        ),
        Ok(outcome) => assert!(
            !outcome.skipped().is_empty(),
            "an exiting view keeps a refusal, never verified absence, got {outcome:?}"
        ),
    }
    assert_eq!(
        budget.kernel_thread_absences(),
        0,
        "an exited view never counts as verified absence"
    );
}

#[test]
fn kernel_thread_absence_count_is_conserved_across_scans() {
    // One pass, one budget: two kernel threads and one refusal count
    // exactly the two absences, no more and no less.
    let start_time = pinned_start_time();
    let mut budget = CaptureWorkBudget::default();
    for _ in 0..2 {
        let mut absence = EmptyMapsFixture {
            maps: Vec::new(),
            stat: Ok(kthread_stat(start_time)),
            exe: Err(io::ErrorKind::NotFound),
        };
        run_empty_maps(&mut absence, &mut budget).expect("absence scans");
    }
    let mut refusal = EmptyMapsFixture {
        maps: Vec::new(),
        stat: Ok(user_stat(start_time)),
        exe: Ok(PathBuf::from("/usr/bin/worker")),
    };
    run_empty_maps(&mut refusal, &mut budget).expect("refusal scans");
    assert_eq!(
        budget.kernel_thread_absences(),
        2,
        "two absences and one refusal count exactly two"
    );
}

#[test]
fn stat_flags_parse_comm_with_paren_and_space() {
    // Comm `a) b (c`: the flags parse must start after the LAST ')'.
    let stat = "123 (a) b (c) S 1 2 3 4 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 300 0";
    assert_eq!(stat_flags_from_stat_text(stat), Some(4194304));
    assert_eq!(start_time_from_stat(stat).unwrap(), 300);
    let stat = "2 (a) b (c) S 0 0 0 0 -1 2097152 0 0 0 0 0 0 0 0 20 0 1 0 3 0";
    assert_eq!(stat_flags_from_stat_text(stat), Some(2097152));
    assert_eq!(start_time_from_stat(stat).unwrap(), 3);
    assert_eq!(4194304 & PF_KTHREAD, 0);
    assert_ne!(2097152 & PF_KTHREAD, 0);
    // Malformed stat lines parse to None, which the classifier fails closed on.
    assert_eq!(stat_flags_from_stat_text(""), None);
    assert_eq!(stat_flags_from_stat_text("123 no-paren-here"), None);
    assert_eq!(stat_flags_from_stat_text("123 (x) S 1"), None);
    assert_eq!(
        stat_flags_from_stat_text("123 (x) S 1 2 3 4 -1 notanumber"),
        None
    );
}

#[test]
fn scan_real_kthreadd_is_verified_absence() {
    let comm = std::fs::read_to_string("/proc/2/comm").unwrap_or_default();
    if comm.trim() != "kthreadd" {
        eprintln!(
            "SKIP: /proc/2 is not kthreadd (comm={comm:?}); cannot positively test a real kernel thread"
        );
        return;
    }
    // The real stat line must carry PF_KTHREAD in field 9; this runs
    // everywhere /proc/2/stat is readable, with no pin needed.
    let stat = std::fs::read_to_string("/proc/2/stat").expect("read kthreadd stat");
    let flags = stat_flags_from_stat_text(&stat).expect("parse kthreadd stat flags");
    assert_ne!(
        flags & PF_KTHREAD,
        0,
        "kthreadd must carry PF_KTHREAD, got flags={flags}"
    );
    let view = match ProcessView::open(ProcessViewId(502), 2) {
        Ok(view) => view,
        Err(error) => {
            eprintln!(
                "SKIP: kthreadd is pinned only by a privileged observer ({error}); full-scan positive runs there"
            );
            return;
        }
    };
    let hooks = HookRegistry::builtin();
    let mut budget = CaptureWorkBudget::default();
    let outcome = scan_process_view(
        &ScanRequest {
            pid: 2,
            hints: &[],
            hooks: &hooks,
        },
        &view,
        &mut budget,
    )
    .expect("kthreadd must scan, not error");
    assert!(
        outcome.unavailable_reason().is_none(),
        "kthreadd must complete the mapping bracket, got {outcome:?}"
    );
    assert_eq!(
        outcome.modules().len(),
        0,
        "kthreadd has no modules, got {outcome:?}"
    );
    assert!(
        outcome.skipped().is_empty(),
        "kthreadd must leave no skip, got {:?}",
        outcome.skipped()
    );
    assert_eq!(
        budget.kernel_thread_absences(),
        1,
        "the real kernel thread is counted once"
    );
}
