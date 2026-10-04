//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates for the capture facade. Root BPF lane, run
//! serially through `scripts/run-privileged-lib-tests.sh`. Every caller is
//! an owned fixture process with an independent stdout ledger; every
//! endpoint comes through the real attach set (`absorb`) and the facade.

use super::super::activation::privileged_tests::{OwnedCaller, OwnedFixture};
use super::*;
use crate::discovery::inventory_attach_set::tests as fx;
use crate::plan::AdmissionPolicy;
use anyhow::ensure;
use std::time::Duration;

fn budget(n: u64) -> InventoryBudget {
    InventoryBudget::new(n, n * 8).unwrap()
}

const N: u64 = 128;

fn prepare(scope: CaptureScope) -> Result<InventoryCapture> {
    prepare_on(scope, AttachBackend::Singles)
}

fn prepare_on(scope: CaptureScope, backend: AttachBackend) -> Result<InventoryCapture> {
    InventoryCapture::prepare(scope, budget(N), caller_budget(budget(N), 64)?, backend)
}

fn read_window() -> ReadWindow {
    ReadWindow::new(4096, Instant::now() + Duration::from_secs(3)).unwrap()
}

fn extend_window() -> ExtendWindow {
    ExtendWindow::new(4096, Instant::now() + Duration::from_secs(30)).unwrap()
}

/// One attach-set pass over `fixtures`, each a module whose table targets
/// its own `owned_k` symbols: the real absorb path the coordinator runs.
fn absorb(set: &mut InventoryAttachSet, fixtures: &[&OwnedFixture]) -> TargetDelta {
    let files: Vec<(&std::path::Path, &str)> = fixtures
        .iter()
        .map(|fixture| (fixture.path.as_path(), fixture.expected_sha256.as_str()))
        .collect();
    let pins = fx::pass_pins(&files);
    let modules: Vec<_> = fixtures
        .iter()
        .map(|fixture| {
            let offsets: Vec<u64> = fixture
                .plan
                .slots
                .iter()
                .map(|slot| slot.file_offset)
                .collect();
            fx::module(&pins, &fixture.path, &offsets)
        })
        .collect();
    let plan = fx::lower_named(&modules, &pins, AdmissionPolicy::Inventory(set.budget()));
    set.absorb(&plan, &pins).delta
}

/// The endpoint the set holds for `fixture`'s `owned_k`.
fn endpoint_of(
    set: &InventoryAttachSet,
    fixture: &OwnedFixture,
    k: usize,
) -> Result<AttachEndpoint> {
    let offset = fixture.plan.slots[k].file_offset;
    let path = fixture.path.to_str().context("fixture path")?;
    set.endpoints()
        .find(|endpoint| {
            endpoint.file_offset == offset
                && set
                    .target(endpoint.object)
                    .is_some_and(|target| target.path() == path)
        })
        .copied()
        .context("fixture endpoint absent from the attach set")
}

/// Reads until one full CALLER_USE sweep completes. Asserts clean health
/// and no integrity row on the way.
fn read_sweep(
    read: &mut dyn FnMut(ReadWindow) -> WitnessBatch,
) -> Result<(Vec<WitnessRow>, WitnessBatch)> {
    let mut rows = Vec::new();
    for _ in 0..64 {
        let batch = read(read_window());
        ensure!(
            batch.integrity.is_empty(),
            "integrity rows: {:?}",
            batch.integrity
        );
        ensure!(batch.read_failures.is_empty(), "{:?}", batch.read_failures);
        ensure!(
            batch.phase == CapturePhase::Prepared || batch.health.failures.is_empty(),
            "{:?}",
            batch.health
        );
        rows.extend(batch.rows.iter().cloned());
        if batch.sweep_completed {
            return Ok((rows, batch));
        }
    }
    bail!("no CALLER_USE sweep completed in 64 quanta")
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

fn report_cost(cell: &str, receipt: &ExtendReceipt, fds_before: usize, fds_after: usize) {
    let attached = receipt.attached.len().max(1) as u64;
    eprintln!(
        "C3_COST cell={cell} attached={} failed={} attach_ns_total={} attach_ns_max={} \
         attach_ns_mean={} fds_before={fds_before} fds_after={fds_after}",
        receipt.attached.len(),
        receipt.failed.len(),
        receipt.attach_ns_total,
        receipt.attach_ns_max,
        receipt.attach_ns_total / attached,
    );
}

/// Bounded stop: service lifecycle records while retirement runs, then
/// take the retired capture.
fn stop(capture: InventoryCapture) -> Result<RetiredCapture> {
    let mut retiring = capture.begin_stop();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let service = retiring.service_discovery(read_window());
        ensure!(service.failure.is_none(), "{service:?}");
        if retiring.poll_completion(deadline)? {
            break;
        }
        ensure!(Instant::now() < deadline, "capture retirement deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("completed retirement did not transfer"))
}

fn rows_of(rows: &[WitnessRow], pid: u32) -> Vec<&WitnessRow> {
    rows.iter().filter(|row| row.host_tgid == pid).collect()
}

#[test]
#[ignore = "root-owned live BPF lane; a provider extended after activation is witnessed only after extend"]
fn privileged_inventory_capture_extend_late_provider_lp64() -> Result<()> {
    let a = OwnedFixture::build_n(false, 64)?;
    let b = OwnedFixture::build_n(false, 4)?;
    let mut set = InventoryAttachSet::new(budget(N));
    let first = absorb(&mut set, &[&a]);
    ensure!(first.endpoints.len() == 64, "{first:?}");
    let mut capture = prepare(CaptureScope::System)?;
    ensure!(capture.phase() == CapturePhase::Prepared);
    let fds_before = fd_count();
    let receipt = capture.extend(first, &set, extend_window());
    let fds_after = fd_count();
    report_cost("system-64", &receipt, fds_before, fds_after);
    ensure!(
        receipt.activated_roots
            && receipt.attached.len() == 64
            && receipt.failed.is_empty()
            && receipt.refused.is_none()
            && receipt.custody == Some(ScopeCustody::System),
        "{receipt:?}"
    );
    // One FD per entry plus two roots (and the activation's DISCOVERY
    // reader); retained objects are shared clones, never new FDs.
    ensure!(
        (66..=68).contains(&(fds_after - fds_before)),
        "activation FDs: {fds_before} -> {fds_after}"
    );

    let mut caller_a = a.spawn()?;
    let mut caller_b = b.spawn()?;
    caller_a.calls(1, 3)?;
    // B is not in the attach set yet: its call must leave no witness.
    caller_b.calls(0, 2)?;
    let (rows, batch) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(
        batch.health_regression.is_none(),
        "{:?}",
        batch.health_regression
    );
    let a1 = endpoint_of(&set, &a, 1)?;
    ensure!(
        rows.len() == 1
            && rows[0].host_tgid == caller_a.child.id()
            && rows[0].endpoint == a1.id
            && rows[0].object == a1.object
            && rows[0].domain == capture.domain(),
        "before extend: {rows:?}"
    );
    ensure!(rows_of(&rows, caller_b.child.id()).is_empty());
    eprintln!(
        "C3_LATE before_extend rows=1 a_pid={} b_pid={}",
        caller_a.child.id(),
        caller_b.child.id()
    );

    let second = absorb(&mut set, &[&a, &b]);
    ensure!(
        second.endpoints.iter().map(|e| e.id.0).collect::<Vec<_>>() == (64..68).collect::<Vec<_>>(),
        "only B's endpoints are new: {second:?}"
    );
    let fds_before = fd_count();
    let receipt = capture.extend(second, &set, extend_window());
    let fds_after = fd_count();
    report_cost("system-late-4", &receipt, fds_before, fds_after);
    ensure!(
        !receipt.activated_roots && receipt.attached.len() == 4 && receipt.failed.is_empty(),
        "{receipt:?}"
    );
    ensure!(fds_after - fds_before == 4, "{fds_before} -> {fds_after}");
    caller_b.calls(2, 1)?;
    let (rows, batch) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(
        batch.health_regression.is_none(),
        "{:?}",
        batch.health_regression
    );
    let b2 = endpoint_of(&set, &b, 2)?;
    ensure!(
        rows.len() == 1
            && rows[0].host_tgid == caller_b.child.id()
            && rows[0].endpoint == b2.id
            && rows[0].object == b2.object
            && b2.object != a1.object,
        "after extend, B's first witness is its post-extend call: {rows:?}"
    );
    ensure!(batch.seen_rows == 2, "{batch:?}");
    eprintln!(
        "C3_LATE after_extend rows=2 b_endpoint={} b_object={}",
        b2.id.0,
        b2.object.index()
    );
    caller_a.finish()?;
    caller_b.finish()?;
    // M8: B's provider modified in place after it was attached: the next
    // read's bounded pin recheck reports its object, once.
    {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&b.path)?
            .write_all(b"modified in place")?;
    }
    let changed = capture.read_witnesses(read_window());
    ensure!(
        changed.changed_objects == [b2.object],
        "pin recheck missed the in-place change: {:?}",
        changed.changed_objects
    );
    let again = capture.read_witnesses(read_window());
    ensure!(
        again.changed_objects.is_empty(),
        "{:?}",
        again.changed_objects
    );
    eprintln!("C3_PIN_RECHECK changed_object={}", b2.object.index());
    let retired = stop(capture)?;
    ensure!(
        retired.cleanup().closed == 70 && retired.cleanup().failures.is_empty(),
        "{:?}",
        retired.cleanup()
    );
    Ok(())
}

/// A process holding `pid`: the kernel's next PID is set through
/// `ns_last_pid` (the CRIU technique) and the spawn retried, since other
/// host processes may take the number first.
fn spawn_with_pid(fixture: &OwnedFixture, pid: u32) -> Result<OwnedCaller> {
    for attempt in 0..64 {
        std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", pid - 1))
            .context("writing ns_last_pid (needs CONFIG_CHECKPOINT_RESTORE and root)")?;
        let caller = fixture.spawn()?;
        if caller.child.id() == pid {
            eprintln!("C3_PID_REUSE pid={pid} attempt={attempt}");
            return Ok(caller);
        }
        drop(caller);
    }
    bail!("could not reuse pid {pid} in 64 attempts")
}

#[test]
#[ignore = "root-owned live BPF lane; PID scope excludes a foreign caller and a reused-PID process"]
fn privileged_inventory_capture_pid_scope_excludes_foreign_and_reused_pid_lp64() -> Result<()> {
    pid_scope_excludes_foreign_and_reused_pid(AttachBackend::Singles)
}

/// C5.11 security review: the same cell with the entries in one
/// uprobe-multi group named by the target's PID (the proven kernel pid
/// filter) plus the in-BPF PID_FILTER guard. A foreign process calling the
/// same provider meanwhile, and a later process that reuses the target's
/// PID, leave no row, no integrity row and no cookie.
#[test]
#[ignore = "root-owned live BPF lane; PID-scoped uprobe-multi excludes a foreign caller and a reused-PID process"]
fn privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64() -> Result<()>
{
    crate::attach::kernel_multi_pid_filter().map_err(anyhow::Error::msg)?;
    pid_scope_excludes_foreign_and_reused_pid(AttachBackend::Multi)
}

fn pid_scope_excludes_foreign_and_reused_pid(backend: AttachBackend) -> Result<()> {
    let a = OwnedFixture::build_n(false, 4)?;
    let mut set = InventoryAttachSet::new(budget(N));
    let delta = absorb(&mut set, &[&a]);
    let mut target = a.spawn()?;
    let mut foreign = a.spawn()?;
    let pid = target.child.id();
    let pin = PidPin::open(pid).map_err(anyhow::Error::msg)?;
    let mut capture = prepare_on(CaptureScope::Pid(pin), backend)?;
    ensure!(capture.backend() == backend);
    let fds_before = fd_count();
    let receipt = capture.extend(delta, &set, extend_window());
    report_cost("pid-4", &receipt, fds_before, fd_count());
    ensure!(
        receipt.attached.len() == 4 && receipt.custody == Some(ScopeCustody::PidHeld),
        "{receipt:?}"
    );
    ensure!(
        (backend == AttachBackend::Multi) == (receipt.groups.len() == 1),
        "{:?}",
        receipt.groups
    );
    // Interleaved: both processes stay live with the probes attached.
    foreign.calls(0, 2)?;
    target.calls(0, 2)?;
    foreign.calls(1, 2)?;
    foreign.calls(0, 2)?;
    let (rows, batch) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(
        batch.health_regression.is_none(),
        "{:?}",
        batch.health_regression
    );
    let a0 = endpoint_of(&set, &a, 0)?;
    ensure!(
        rows.len() == 1 && rows[0].host_tgid == pid && rows[0].endpoint == a0.id,
        "PID scope admitted a foreign caller: {rows:?}"
    );
    let CookieQuery::Cookie(cookie) =
        capture.query_cookie(target.pin.as_ref().context("target pin")?)
    else {
        bail!("the PID target holds no cookie after its witnessed call");
    };
    ensure!(cookie == rows[0].cookie() && cookie.domain() == capture.domain());
    ensure!(
        capture.query_cookie(foreign.pin.as_ref().context("foreign pin")?) == CookieQuery::NoCookie,
        "the foreign caller entered an instrumented endpoint"
    );
    ensure!(
        batch.integrity_total == 0,
        "integrity rows: {:?}",
        batch.integrity
    );
    eprintln!(
        "C3_PID_SCOPE backend={backend:?} target={pid} foreign={} rows=1",
        foreign.child.id()
    );

    target.finish()?;
    let mut reused = spawn_with_pid(&a, pid)?;
    reused.calls(2, 2)?;
    reused.calls(0, 1)?;
    let (rows, batch) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(
        rows.is_empty() && batch.integrity_total == 0,
        "a reused PID reached the PID-scoped capture: {rows:?}"
    );
    ensure!(
        capture.query_cookie(reused.pin.as_ref().context("reused pin")?) == CookieQuery::NoCookie,
        "the reused-PID process entered an instrumented endpoint"
    );
    // The original is gone: the capture refuses to extend and fails.
    let refused = capture.extend(TargetDelta::default(), &set, extend_window());
    ensure!(
        refused
            .refused
            .as_deref()
            .is_some_and(|reason| reason.contains("custody")),
        "{refused:?}"
    );
    ensure!(matches!(capture.custody(), ScopeCustody::PidLost { .. }));
    ensure!(capture.failure().is_some() && capture.phase() == CapturePhase::Retiring);
    eprintln!("C3_PID_REUSE_EXCLUDED backend={backend:?} pid={pid} rows=0 custody=lost");
    reused.finish()?;
    foreign.finish()?;
    let retired = stop(capture)?;
    ensure!(
        retired.cleanup().failures.is_empty(),
        "{:?}",
        retired.cleanup()
    );
    ensure!(
        retired
            .failure()
            .is_some_and(|reason| reason.contains("custody"))
    );
    Ok(())
}

#[test]
#[ignore = "root-owned live BPF lane; pidfd TASK_COOKIE answer equals the row and changes on nonleader exec"]
fn privileged_inventory_capture_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64()
-> Result<()> {
    let a = OwnedFixture::build_n(false, 4)?;
    let mut set = InventoryAttachSet::new(budget(N));
    let delta = absorb(&mut set, &[&a]);
    let mut capture = prepare(CaptureScope::System)?;
    let mut target = a.spawn()?;
    let pin_view = PidPin::open(target.child.id()).map_err(anyhow::Error::msg)?;
    ensure!(
        capture.query_cookie(&pin_view) == CookieQuery::NoCookie,
        "a cookie before any instrumented call"
    );
    let receipt = capture.extend(delta, &set, extend_window());
    ensure!(receipt.attached.len() == 4, "{receipt:?}");
    target.calls(0, 1)?;
    let (rows, _) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(rows.len() == 1, "{rows:?}");
    let first = rows[0].clone();
    ensure!(
        capture.query_cookie(&pin_view) == CookieQuery::Cookie(first.cookie()),
        "cookie query differs from the row"
    );
    // A nonleader worker execs: the pidfd now names the successor leader,
    // which holds no ticket in this domain.
    target.start_held_worker("NONLEADER_EXEC", 1)?;
    target.release_held_worker_exec()?;
    ensure!(
        !pin_view.original_exited().map_err(anyhow::Error::msg)?,
        "the process survives its nonleader exec"
    );
    ensure!(
        capture.query_cookie(&pin_view) == CookieQuery::NoCookie,
        "the old leader's cookie survived a nonleader exec"
    );
    target.calls(0, 1)?;
    let (rows, _) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(rows.len() == 1, "{rows:?}");
    let second = rows[0].clone();
    ensure!(
        second.host_tgid == first.host_tgid
            && second.cookie() != first.cookie()
            && second.exec_id() != first.exec_id(),
        "successor image did not get its own cookie: {first:?} {second:?}"
    );
    ensure!(capture.query_cookie(&pin_view) == CookieQuery::Cookie(second.cookie()));
    eprintln!(
        "C3_COOKIE pid={} first={:?} second={:?} exec {}->{}",
        first.host_tgid,
        first.cookie(),
        second.cookie(),
        first.exec_id(),
        second.exec_id()
    );
    target.finish()?;
    ensure!(capture.query_cookie(&pin_view) == CookieQuery::Exited);
    let retired = stop(capture)?;
    ensure!(
        retired.cleanup().failures.is_empty(),
        "{:?}",
        retired.cleanup()
    );
    Ok(())
}

#[test]
#[ignore = "root-owned live BPF lane; stop with a held call completes retirement and reports unsettled reads"]
fn privileged_inventory_capture_stop_with_held_call_reports_unsettled_lp64() -> Result<()> {
    let a = OwnedFixture::build_n(false, 4)?;
    let mut set = InventoryAttachSet::new(budget(N));
    let delta = absorb(&mut set, &[&a]);
    let mut capture = prepare(CaptureScope::System)?;
    let receipt = capture.extend(delta, &set, extend_window());
    ensure!(receipt.attached.len() == 4, "{receipt:?}");
    let mut target = a.spawn()?;
    target.hold_call_in_body(3, 1)?;
    let (rows, batch) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(!batch.unsettled && rows.len() == 1, "{rows:?}");

    let mut retiring = capture.begin_stop();
    let during = retiring.read_witnesses(read_window());
    ensure!(during.unsettled && during.phase == CapturePhase::Retiring);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !retiring.poll_completion(deadline)? {
        let _ = retiring.service_discovery(read_window());
        ensure!(
            Instant::now() < deadline,
            "retirement with a held call never completed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("completed retirement did not transfer"))?;
    ensure!(
        retired.cleanup().attempted == 6
            && retired.cleanup().closed == 6
            && retired.cleanup().failures.is_empty()
            && retired.cleanup().retained_links == 0,
        "{:?}",
        retired.cleanup()
    );
    let (rows, terminal) = read_sweep(&mut |window| retired.read_witnesses(window))?;
    ensure!(
        terminal.unsettled && terminal.phase == CapturePhase::Retired && rows.is_empty(),
        "terminal read claimed settlement or repeated a row: {terminal:?}"
    );
    ensure!(
        terminal.seen_rows == 1,
        "the held call's witness is retained"
    );
    // The held call is still in the body; release it after detach.
    target.resume_body(3)?;
    target.finish_calls(3, 1)?;
    target.finish()?;
    eprintln!("C3_STOP_HELD closed=6 unsettled=true rows_retained=1");
    Ok(())
}

/// An owned provider-and-caller whose leader thread can `pthread_exit`
/// while a worker keeps serving calls: `LEADER_EXIT` hands the command
/// loop to a new worker, which prints `WORKER <tid>`, then the leader
/// exits. `CALL k n` calls `owned_k` n times and prints the independent
/// ledger `DONE k n <calls>`.
struct LeaderExitFixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    sha256: String,
    offsets: Vec<u64>,
}

impl LeaderExitFixture {
    fn build() -> Result<Self> {
        use p11scope_manifest::elf::ElfSnapshot;
        use p11scope_manifest::identity::{inspect_file, open_object};
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("leader.c");
        let path = directory.path().join("leader-exit-provider");
        std::fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
__attribute__((noinline,used)) unsigned long owned_0(unsigned long x) { __asm__ volatile("" ::: "memory"); return x + 1; }
__attribute__((noinline,used)) unsigned long owned_1(unsigned long x) { __asm__ volatile("" ::: "memory"); return x + 1; }
__attribute__((noinline,used)) unsigned long owned_2(unsigned long x) { __asm__ volatile("" ::: "memory"); return x + 1; }
__attribute__((noinline,used)) unsigned long owned_3(unsigned long x) { __asm__ volatile("" ::: "memory"); return x + 1; }
static unsigned long (*const functions[4])(unsigned long) = {owned_0, owned_1, owned_2, owned_3};
static void *serve(void *worker) {
    char command[32]; unsigned id, n;
    if (worker) printf("WORKER %ld\n", (long)syscall(SYS_gettid));
    while (scanf("%31s", command) == 1) {
        if (!strcmp(command, "EXIT")) _exit(0);
        if (!strcmp(command, "LEADER_EXIT") && !worker) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, serve, (void *)1)) _exit(6);
            pthread_exit(NULL);
        }
        if (strcmp(command, "CALL") || scanf("%u %u", &id, &n) != 2 || id > 3) _exit(2);
        unsigned long calls = 0;
        for (unsigned i = 0; i < n; i++) calls += functions[id](i) - i;
        printf("DONE %u %u %lu\n", id, n, calls);
    }
    _exit(3);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("READY %ld\n", (long)getpid());
    serve(NULL);
    return 3;
}
"#,
        )?;
        let output = std::process::Command::new("cc")
            .args([
                "-O0",
                "-fno-inline",
                "-fno-pie",
                "-no-pie",
                "-rdynamic",
                "-pthread",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .output()?;
        ensure!(
            output.status.success(),
            "leader-exit fixture compiler failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let file = open_object(&path).map_err(anyhow::Error::msg)?;
        let elf = ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
        let mut offsets = Vec::new();
        for k in 0..4 {
            offsets.push(
                elf.defined_symbol(&format!("owned_{k}"))
                    .map_err(anyhow::Error::msg)?
                    .context("owned symbol")?
                    .file_offset,
            );
        }
        let sha256 = inspect_file(&file)
            .map_err(anyhow::Error::msg)?
            .identity
            .sha256
            .context("fixture digest")?;
        Ok(Self {
            _directory: directory,
            path,
            sha256,
            offsets,
        })
    }

    fn absorb(&self, set: &mut InventoryAttachSet) -> TargetDelta {
        let pins = fx::pass_pins(&[(self.path.as_path(), self.sha256.as_str())]);
        let module = fx::module(&pins, &self.path, &self.offsets);
        let plan = fx::lower_named(
            std::slice::from_ref(&module),
            &pins,
            AdmissionPolicy::Inventory(set.budget()),
        );
        set.absorb(&plan, &pins).delta
    }
}

struct LineChild {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::io::BufReader<std::process::ChildStdout>,
}

impl LineChild {
    fn spawn(path: &std::path::Path) -> Result<Self> {
        let mut child = std::process::Command::new(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().context("stdin")?;
        let output = std::io::BufReader::new(child.stdout.take().context("stdout")?);
        let mut this = Self {
            child,
            input,
            output,
        };
        let ready = this.line()?;
        ensure!(ready == format!("READY {}", this.child.id()), "{ready}");
        Ok(this)
    }

    fn line(&mut self) -> Result<String> {
        use std::io::BufRead as _;
        let mut line = String::new();
        ensure!(
            self.output.read_line(&mut line)? > 0,
            "fixture closed stdout"
        );
        Ok(line.trim_end().to_string())
    }

    fn send(&mut self, command: &str) -> Result<()> {
        use std::io::Write as _;
        writeln!(self.input, "{command}")?;
        Ok(self.input.flush()?)
    }

    fn calls(&mut self, id: u32, n: u32) -> Result<()> {
        self.send(&format!("CALL {id} {n}"))?;
        let ledger = self.line()?;
        ensure!(
            ledger == format!("DONE {id} {n} {n}"),
            "independent ledger: {ledger}"
        );
        Ok(())
    }
}

impl Drop for LineChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn leader_state(pid: u32) -> Result<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after = stat.rfind(')').context("stat comm")?;
    stat[after + 2..].chars().next().context("stat state")
}

fn usage_bit(capture: &InventoryCapture, endpoint: EndpointId) -> Result<u64> {
    let CaptureState::Active(active) = &capture.state else {
        bail!("capture is not active");
    };
    let map: aya::maps::Array<_, u64> =
        aya::maps::Array::try_from(active.state().ebpf().map("USAGE").context("USAGE")?)?;
    Ok(map.get(&endpoint.0, 0)?)
}

#[test]
#[ignore = "root-owned live BPF lane; probe: do OneProcess entries keep firing after the PID target's leader thread exits"]
fn privileged_inventory_capture_pid_scope_leader_exit_probe_lp64() -> Result<()> {
    let fixture = LeaderExitFixture::build()?;
    let mut set = InventoryAttachSet::new(budget(N));
    let delta = fixture.absorb(&mut set);
    ensure!(delta.endpoints.len() == 4, "{delta:?}");
    let mut target = LineChild::spawn(&fixture.path)?;
    let pid = target.child.id();
    let pin = PidPin::open(pid).map_err(anyhow::Error::msg)?;
    let mut capture = prepare(CaptureScope::Pid(pin))?;
    let receipt = capture.extend(delta.clone(), &set, extend_window());
    ensure!(receipt.attached.len() == 4, "{receipt:?}");
    // Control: the leader's own call fires.
    target.calls(0, 3)?;
    ensure!(
        usage_bit(&capture, delta.endpoints[0].id)? == 1,
        "control call did not fire"
    );
    let (rows, _) = read_sweep(&mut |window| capture.read_witnesses(window))?;
    ensure!(rows.len() == 1, "{rows:?}");
    // A worker call before the leader exits fires too (same mm).
    target.calls(1, 2)?;
    let before_exit = usage_bit(&capture, delta.endpoints[1].id)?;
    target.send("LEADER_EXIT")?;
    let worker = target.line()?;
    ensure!(worker.starts_with("WORKER "), "{worker}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while leader_state(pid)? != 'Z' {
        ensure!(Instant::now() < deadline, "leader did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
    let pin_view = PidPin::open(pid).map_err(anyhow::Error::msg)?;
    let pidfd_alive = !pin_view.original_exited().map_err(anyhow::Error::msg)?;
    // Fresh endpoints after the leader exit: their USAGE bit is the probe.
    target.calls(2, 5)?;
    target.calls(3, 5)?;
    let after = [
        usage_bit(&capture, delta.endpoints[2].id)?,
        usage_bit(&capture, delta.endpoints[3].id)?,
    ];
    let custody = capture.custody();
    let batch = capture.read_witnesses(ReadWindow::new(
        64,
        Instant::now() + Duration::from_secs(5),
    )?);
    eprintln!(
        "C3_LEADER_EXIT_PROBE pid={pid} before_exit_usage1={before_exit} leader_state=Z \
         pidfd_alive={pidfd_alive} after_exit_usage2_3={after:?} fired_after_exit={} custody={custody:?}",
        after.contains(&1)
    );
    ensure!(
        before_exit == 1,
        "a worker call before leader exit did not fire"
    );
    ensure!(
        pidfd_alive,
        "the pidfd reported the process exited while a worker runs"
    );
    // Observed on 7.0 (and the vng matrix): the entries stop firing. Either
    // way, custody after a leader exit is unproven, never held, so the
    // coordinator never reads its zero as no-use.
    ensure!(
        matches!(&custody, ScopeCustody::PidUnproven { reason, .. } if reason.contains("leader")),
        "custody after leader exit is not unproven: {custody:?}"
    );
    ensure!(batch.custody == custody, "{:?}", batch.custody);
    target.send("EXIT")?;
    let _ = target.child.wait();
    let _ = stop(capture)?;
    Ok(())
}

#[test]
#[ignore = "root-owned live BPF lane; a PID capture stopped before activation keeps its pin and re-polls custody"]
fn privileged_inventory_capture_stop_before_activation_repolls_custody_lp64() -> Result<()> {
    // C5.2 review fix 4: `begin_stop` from Prepared keeps the prepared PID
    // pin, so retiring and retired reads report custody as of their own
    // poll (held while the target lives, lost after it exits).
    let mut target = std::process::Command::new("sleep").arg("30").spawn()?;
    let pid = target.id();
    let pin = PidPin::open(pid).map_err(anyhow::Error::msg)?;
    let capture = prepare(CaptureScope::Pid(pin))?;
    let mut retiring = capture.begin_stop();
    let first = retiring.read_witnesses(read_window());
    let second = retiring.read_witnesses(read_window());
    ensure!(
        first.custody == ScopeCustody::PidHeld && second.custody == ScopeCustody::PidHeld,
        "{:?} {:?}",
        first.custody,
        second.custody
    );
    ensure!(
        second.custody_proven_ns > first.custody_proven_ns,
        "the retiring read did not re-poll: {:?} then {:?}",
        first.custody_proven_ns,
        second.custody_proven_ns
    );
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("an unactivated capture retires at once"))?;
    target.kill()?;
    target.wait()?;
    let terminal = retired.read_witnesses(read_window());
    ensure!(
        matches!(&terminal.custody, ScopeCustody::PidLost { reason, .. } if reason.contains("exited")),
        "{:?}",
        terminal.custody
    );
    eprintln!("C5_2_STOP_BEFORE_ACTIVATION custody=held,held,lost");
    Ok(())
}
