//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3 Stage A privileged gates: real fentry hooks, calibration, stamps
//! and routing against owned workloads with independent ledgers. Explicitly
//! selected ignored tests; they fail (never skip) on unavailable support.

use super::*;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::instances::{
    InstanceId, InstanceRouter, ObserveOutcome, Route, RouterLimits, UnknownReason,
};
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::{AttachPlan, Slot};
use crate::process::{PidPin, ProcessView, ProcessViewId};
use crate::semantic_capture::{
    InvalidationScope, SemanticCapture, TickLimits, TickOutcome, TickReport,
};
use anyhow::ensure;
use p11scope_ebpf_common::{
    EventRecord, ImageIdentity, InstanceRecord, JournalAdmissionControl, SlotSemantics, event_type,
    instance, journal_marker,
};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Write as _};
use std::ops::ControlFlow;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SOURCE: &str = include_str!("../../tests/fixtures/instance-continuity.c");
const SOFTHSM: &str = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
const TAG_MAIN: u64 = 0x7000_0000;
const TAG_SIBLING: u64 = 0x7100_0000;
const TAG_RACE: u64 = 0x7200_0000;

fn compile(directory: &Path, provider: bool) -> Result<PathBuf> {
    compile_for_abi(directory, provider, ElfAbi::Lp64)
}

fn compile_for_abi(directory: &Path, provider: bool, abi: ElfAbi) -> Result<PathBuf> {
    let source = directory.join("instance-continuity.c");
    std::fs::write(&source, SOURCE)?;
    let output = directory.join(if provider { "provider.so" } else { "driver" });
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
    if abi == ElfAbi::Ilp32 {
        cc.arg("-m32");
    }
    if provider {
        cc.args(["-fPIC", "-shared", "-DINSTANCE_PROVIDER"]);
    }
    cc.arg(&source).arg("-o").arg(&output);
    if !provider {
        cc.args(["-ldl", "-lpthread"]);
    }
    let result = cc.output()?;
    ensure!(
        result.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(output)
}

/// One owned workload process with a line-oriented ledger.
struct Target {
    child: Child,
    input: ChildStdin,
    lines: mpsc::Receiver<String>,
    pin: Arc<PidPin>,
    ledger: Vec<String>,
}

impl Target {
    fn spawn(program: &Path, args: &[&std::ffi::OsStr], env: &[(&str, &Path)]) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn()?;
        let input = child.stdin.take().context("fixture stdin")?;
        let output = child.stdout.take().context("fixture stdout")?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let pin = match PidPin::open(child.id()) {
            Ok(pin) => Arc::new(pin),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("pinning fixture: {error}");
            }
        };
        Ok(Self {
            child,
            input,
            lines,
            pin,
            ledger: Vec::new(),
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn line(&mut self, timeout: Duration) -> Result<String> {
        let line = self
            .lines
            .recv_timeout(timeout)
            .context("fixture ledger line")?;
        ensure!(!line.starts_with("FAIL"), "fixture failed: {line}");
        self.ledger.push(line.clone());
        Ok(line)
    }

    fn command(&mut self, command: u8) -> Result<String> {
        self.input.write_all(&[command])?;
        self.input.flush()?;
        self.line(Duration::from_secs(20))
    }

    fn send(&mut self, command: u8) -> Result<()> {
        self.input.write_all(&[command])?;
        self.input.flush()?;
        Ok(())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.input.write_all(b"x");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.pin.send_signal(libc::SIGKILL);
        let _ = self.child.wait();
    }
}

/// Pins the provider as the target maps it and plans one slot per function.
fn pin_and_plan(
    pid: u32,
    provider: &Path,
    functions: &[&str],
) -> Result<(ProcessView, PinnedObjects, AttachPlan, ObjectKey)> {
    pin_and_plan_for_abi(pid, provider, functions, ElfAbi::Lp64)
}

fn pin_and_plan_for_abi(
    pid: u32,
    provider: &Path,
    functions: &[&str],
    abi: ElfAbi,
) -> Result<(ProcessView, PinnedObjects, AttachPlan, ObjectKey)> {
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(anyhow::Error::msg)?;
    let file = open_object(provider).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
    ensure!(elf.abi() == abi);
    let key = ObjectKey {
        device: Device {
            major: mapping.device_major,
            minor: mapping.device_minor,
        },
        inode: mapping.inode,
    };
    let module = ScannedModule {
        mapped_identity: None,
        double_loaded: false,
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key,
        path: provider.display().to_string(),
        decoder_abi: None,
        exports: vec![],
        tables: vec![],
        interfaces: vec![],
    };
    let (pins, skipped) =
        pin_scanned_view_objects(&view, &[module], &mut CaptureWorkBudget::default())
            .map_err(anyhow::Error::msg)?;
    ensure!(skipped.is_empty(), "owned pin refused: {skipped:?}");
    let pinned = pins.pinned().next().context("owned provider pin")?;
    let mut slots = Vec::new();
    for (index, name) in functions.iter().enumerate() {
        let offset = elf
            .defined_symbol(name)
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("provider defines {name}"))?
            .file_offset;
        ensure!(elf.is_executable_offset(offset));
        let names = vec![name.to_string()];
        let (descriptor_index, ambiguous) = crate::kinds::descriptor_index(&names);
        ensure!(!ambiguous);
        slots.push(Slot {
            index: index as u32,
            descriptor_index,
            object: pinned.id,
            object_path: provider.display().to_string(),
            file_offset: offset,
            names,
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        });
    }
    let _ = SlotSemantics::COUNT_ONLY;
    Ok((view, pins, AttachPlan::from_slots(slots), key))
}

/// `BPF_ENABLE_STATS(BPF_STATS_RUN_TIME)`: per-program run counts and run
/// time while the returned fd is open, without touching the global sysctl.
fn enable_bpf_stats() -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    const BPF_ENABLE_STATS: libc::c_long = 32;
    let mut attr = [0u8; 128];
    // SAFETY: bpf(2) reads `enable_stats.type` (u32 0 = run time) from a
    // zeroed attr of the given size and returns a new fd or -1.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_ENABLE_STATS,
            attr.as_mut_ptr(),
            attr.len() as libc::c_uint,
        )
    };
    ensure!(
        fd >= 0,
        "BPF_ENABLE_STATS: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the kernel returned a fresh fd that this process owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

fn hook_runs(harness: &Harness, program: &str) -> Result<u64> {
    Ok(harness
        .session
        .instance_hook_stats()?
        .iter()
        .find(|(name, _)| *name == program)
        .with_context(|| format!("hook {program}"))?
        .1
        .run_cnt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Routed {
    slot: u32,
    tag: u64,
    route: Route,
}

#[derive(Default, Debug)]
struct ScanStats {
    scans: u64,
    pending_scans: u64,
    unstable: u64,
    total_ns: u128,
    max_ns: u128,
    outcomes: BTreeMap<String, u64>,
}

/// The observer half: one Session, one router, and the scan protocol.
struct Harness {
    session: Session,
    capture: SemanticCapture,
    file_slot: u32,
    offsets: BTreeMap<u32, u64>,

    routed: Vec<Routed>,
    images: Vec<ImageIdentity>,
    retired_images: Vec<p11scope_ebpf_common::ImageIdentity>,
    retired_instances: Vec<InstanceId>,
    retired_tasks: Vec<u64>,
    misses: u64,
    scan: ScanStats,
    events: u64,
}

impl Harness {
    fn start(plan: &AttachPlan, pid: u32, pins: &PinnedObjects) -> Result<Self> {
        Self::start_with_backend(plan, pid, pins, BackendSelection::Singles)
    }

    fn start_with_backend(
        plan: &AttachPlan,
        pid: u32,
        pins: &PinnedObjects,
        backend: BackendSelection,
    ) -> Result<Self> {
        Self::start_with_scope(plan, &Scope::Pid(pid), pins, backend)
    }

    /// Cgroup-scoped twin of [`Harness::start`]: the same Session start and
    /// the same checks, with the caller's cgroup scope instead of a PID.
    fn start_cgroup(plan: &AttachPlan, scope: &Scope, pins: &PinnedObjects) -> Result<Self> {
        ensure!(
            matches!(scope, Scope::Cgroup { .. }),
            "start_cgroup needs a cgroup scope"
        );
        Self::start_with_scope(plan, scope, pins, BackendSelection::Singles)
    }

    fn start_with_scope(
        plan: &AttachPlan,
        scope: &Scope,
        pins: &PinnedObjects,
        backend: BackendSelection,
    ) -> Result<Self> {
        let session = Session::start(
            plan,
            scope,
            pins,
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            backend,
        )?;
        ensure!(
            session.attach_failures().is_empty(),
            "attach failures: {:?}",
            session.attach_failures()
        );
        let tracking = session.instance_tracking();
        ensure!(
            tracking.refused().is_none(),
            "instance tracking refused: {:?}",
            tracking.refused()
        );
        let object = plan.slots[0].object;
        let watched = tracking
            .watched(object)
            .with_context(|| format!("not watched: {:?}", tracking.watch_refusal(object)))?
            .clone();
        let offsets = plan
            .slots
            .iter()
            .map(|slot| (slot.index, slot.file_offset))
            .collect();
        let capture = SemanticCapture::new(&session, TickLimits::default())?;
        Ok(Self {
            session,
            capture,
            file_slot: watched.file_slot,

            offsets,

            routed: Vec::new(),
            images: Vec::new(),
            retired_images: Vec::new(),
            retired_instances: Vec::new(),
            retired_tasks: Vec::new(),
            misses: 0,
            scan: ScanStats::default(),
            events: 0,
        })
    }

    fn record_report(
        &mut self,
        report: TickReport,
        elapsed: u128,
        pending: bool,
    ) -> Option<ObserveOutcome> {
        self.events += report.collected_calls as u64;
        self.scan.scans += report.scans as u64;
        if pending {
            self.scan.pending_scans += report.scans as u64;
        }
        self.scan.total_ns += elapsed;
        self.scan.max_ns = self.scan.max_ns.max(elapsed);
        for refusal in &report.scan_refusals {
            self.scan.unstable += 1;
            *self
                .scan
                .outcomes
                .entry(format!("{refusal:?}"))
                .or_default() += 1;
        }
        for observation in &report.observations {
            *self
                .scan
                .outcomes
                .entry(format!("{observation:?}"))
                .or_default() += 1;
        }
        let last = report.observations.last().cloned();
        for outcome in report.into_outcomes() {
            match outcome {
                TickOutcome::Call(call) => {
                    self.images.push(call.image());
                    self.routed.push(Routed {
                        slot: call.record().event.slot,
                        tag: call.record().event.slot_id,
                        route: call.route(),
                    });
                }
                TickOutcome::Invalidation(change) => match change.scope() {
                    InvalidationScope::ImageRetired(image) => self.retired_images.push(*image),
                    InvalidationScope::InstancesRetired { ids, .. } => {
                        self.retired_instances.extend(ids)
                    }
                    InvalidationScope::TaskRetired(cookie) => self.retired_tasks.push(*cookie),
                    _ => {}
                },
                TickOutcome::Other(_) => {}
            }
        }
        last
    }

    /// Explicit bounded refresh through the production full-image seal path.
    fn scan(&mut self, target: &Target, pending: bool) -> Result<Option<ObserveOutcome>> {
        let started = Instant::now();
        let report = self
            .capture
            .refresh(&mut self.session, target.pin.clone(), 0)?;
        Ok(self.record_report(report, started.elapsed().as_nanos(), pending))
    }

    /// The sole production collect/audit/route/scheduler owns EVENTS and all
    /// pending records. This harness records its opaque outputs only.
    fn pump(&mut self, target: &Target) -> Result<usize> {
        let started = Instant::now();
        let report = self
            .capture
            .tick(&mut self.session, std::slice::from_ref(&target.pin))?;
        let count = report.collected_calls;
        self.record_report(report, started.elapsed().as_nanos(), true);
        while self.session.discovery_dequeue()?.is_some() {}
        // Diagnostic only; the production tick already audited exact IDs and
        // each hook miss counter before granting any cached join.
        self.misses = self
            .session
            .instance_hook_stats()?
            .iter()
            .map(|(_, stats)| stats.recursion_misses)
            .sum();
        Ok(count)
    }

    fn joined_ids(&self) -> BTreeSet<InstanceId> {
        self.routed
            .iter()
            .filter_map(|routed| match routed.route {
                Route::Joined(id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Ground truth from the call's own tag: (handle family, generation).
    /// Returns the instance IDs that were joined with more than one truth.
    fn false_joins(&self) -> BTreeMap<InstanceId, BTreeSet<(u64, u64)>> {
        let mut truth: BTreeMap<InstanceId, BTreeSet<(u64, u64)>> = BTreeMap::new();
        for routed in &self.routed {
            if let Route::Joined(id) = routed.route {
                truth
                    .entry(id)
                    .or_default()
                    .insert((routed.tag & 0xff00_0000, routed.tag & 0x00ff_ffff));
            }
        }
        truth.retain(|_, truths| truths.len() > 1);
        truth
    }

    fn unknown_reasons(&self) -> BTreeMap<String, u64> {
        let mut reasons = BTreeMap::new();
        for routed in &self.routed {
            if let Route::Unknown(reason) = routed.route {
                *reasons.entry(format!("{reason:?}")).or_default() += 1;
            }
        }
        reasons
    }

    fn take_routed(&mut self) -> Vec<Routed> {
        std::mem::take(&mut self.routed)
    }

    /// The image identities of the drained calls, index-aligned with the
    /// [`Harness::take_routed`] vector taken at the same point: every Call
    /// outcome pushes exactly one of each, in order.
    fn take_images(&mut self) -> Vec<ImageIdentity> {
        std::mem::take(&mut self.images)
    }
}

fn single_join(routed: &[Routed]) -> Result<InstanceId> {
    let ids: BTreeSet<_> = routed
        .iter()
        .map(|routed| match routed.route {
            Route::Joined(id) => Ok(id),
            other => Err(anyhow!("call slot {} not joined: {other:?}", routed.slot)),
        })
        .collect::<Result<_>>()?;
    ensure!(ids.len() == 1, "expected one instance, got {ids:?}");
    Ok(*ids.iter().next().expect("one id"))
}

fn pump_until(harness: &mut Harness, target: &Target, calls: usize) -> Result<Vec<Routed>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while harness.routed.len() < calls {
        harness.pump(target)?;
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {calls} routed calls ({} so far)",
            harness.routed.len()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(harness.take_routed())
}

/// Bounded wait for routed outcomes without demanding joins: returns
/// whatever the router settled (joined or unknown) once `calls`
/// outcomes exist, or fails at the budget. For cells where the
/// expected outcome is an unjoined call that must arrive promptly.
fn pump_until_routed(
    harness: &mut Harness,
    target: &Target,
    calls: usize,
    budget: Duration,
) -> Result<Vec<Routed>> {
    let deadline = Instant::now() + budget;
    while harness.routed.len() < calls {
        harness.pump(target)?;
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {calls} routed calls ({} so far)",
            harness.routed.len()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(harness.take_routed())
}

/// A compiled provider+driver and a spawned `cmd` target answering READY.
/// The tempdir lives as long as the setup, so the target's files survive.
struct CmdSetup {
    _directory: tempfile::TempDir,
    provider: PathBuf,
    target: Target,
}

fn spawn_cmd_target() -> Result<CmdSetup> {
    let directory = tempfile::tempdir()?;
    let provider = compile(directory.path(), true)?;
    let driver = compile(directory.path(), false)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()], &[])?;
    let ready = target.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    Ok(CmdSetup {
        _directory: directory,
        provider,
        target,
    })
}

fn held_object_tid(target: &mut Target) -> Result<u32> {
    let held = target.command(b'o')?;
    let mut fields = held.split_whitespace();
    ensure!(
        fields.next() == Some("OHELD"),
        "object entry ledger: {held}"
    );
    let tid: u32 = fields.next().context("object call worker tid")?.parse()?;
    ensure!(tid != 0 && tid != target.pid() && fields.next().is_none());
    Ok(tid)
}

#[test]
fn instance_object_call_gate_reports_owned_tid_and_returns() -> Result<()> {
    let CmdSetup {
        _directory,
        provider: _,
        mut target,
    } = spawn_cmd_target()?;
    held_object_tid(&mut target)?;
    ensure!(target.command(b'u')? == "UNHELD 0 0");
    // Existing ordinary held-call commands keep their original protocol.
    ensure!(target.command(b'b')? == "HELD");
    ensure!(target.command(b'u')? == "UNHELD 0 3");
    Ok(())
}

fn object_call_evidence(session: &Session) -> Result<(u64, u64)> {
    use p11scope_ebpf_common::{EVIDENCE_RING_LOSS, EVIDENCE_UNMATCHED_RETURNS};
    let map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE")?)?;
    let total = |index| -> Result<u64> { Ok(map.get(&index, 0)?.iter().copied().sum()) };
    Ok((
        total(EVIDENCE_RING_LOSS)?,
        total(EVIDENCE_UNMATCHED_RETURNS)?,
    ))
}

/// Default FULL, real Multi/native hooks, with one exact owned continuity
/// entry removed while its object-arm call is held inside the provider.
/// Separate sessions keep the refused call's fault out of the healthy twin.
#[test]
#[ignore = "privileged: default FULL LP64, Multi and native instance hooks; exact held-call map injection"]
fn privileged_object_continuity_refusal_preserves_s1_base() -> Result<()> {
    use p11scope_ebpf_common::object_flow::continuity_joins;
    use p11scope_ebpf_common::{CallStart, InstanceEntry, InstanceStamp, StartKey};

    for missing_entry in [false, true] {
        let CmdSetup {
            _directory,
            provider,
            mut target,
        } = spawn_cmd_target()?;
        let pid = target.pid();
        let (_view, pins, plan, _) = pin_and_plan(pid, &provider, &["C_SignInit"])?;
        let mut harness = Harness::start_with_backend(&plan, pid, &pins, BackendSelection::Multi)?;
        ensure!(harness.session.static_multi_attached());
        ensure!(harness.session.backend_fallback().is_none());
        ensure!(!embedded_object_is_stubbed());
        let Some(Map::LruHashMap(starts)) = harness.session.ebpf.map("INSTANCE_START") else {
            bail!("expected native INSTANCE_START LRU map");
        };
        let info = starts.info()?;
        ensure!(info.key_size() == 16 && info.value_size() == 24 && info.max_entries() == 16_384);
        harness.pump(&target)?;
        ensure!(harness.events == 0 && harness.routed.is_empty());
        {
            let (drain, rows) = harness.session.event_drain_with_object_table()?;
            // Ordinary transport verifies the frozen rows independently;
            // it does not admit a semantic object tail without attestation.
            ensure!(rows.is_none(), "ordinary S1 has no attested semantic rows");
            ensure!(drain.malformed() == 0);
        }
        let before = crate::events::event_drain_positions(harness.session.event_drain()?);
        ensure!(
            before.capacity == 4 * 1024 * 1024,
            "requires the default FULL ring"
        );
        ensure!(
            before.consumer == before.producer,
            "startup ring must be empty"
        );
        let evidence_before = object_call_evidence(&harness.session)?;
        let fault_before = harness.session.instance_maps().fault()?;

        let tid = held_object_tid(&mut target)?;
        let key = StartKey {
            pid_tgid: (u64::from(pid) << 32) | u64::from(tid),
            slot: 0,
            _pad: 0,
        };
        {
            let starts: HashMap<_, StartKey, CallStart> =
                HashMap::try_from(harness.session.ebpf.map("START").context("START")?)?;
            ensure!(
                starts.get(&key, 0)?.object_required
                    == u64::from(plan.slots[0].descriptor_index) + 1
            );
        }
        let entry = {
            let mut starts: HashMap<_, StartKey, InstanceEntry> = HashMap::try_from(
                harness
                    .session
                    .ebpf
                    .map_mut("INSTANCE_START")
                    .context("INSTANCE_START")?,
            )?;
            let entry = starts.get(&key, 0)?;
            ensure!(entry.entry_ip != 0);
            ensure!(entry.entry_stamp.flags == instance::STAMP_VALID);
            ensure!(u32::from(entry.entry_stamp.file_slot_plus1) == harness.file_slot + 1);
            if missing_entry {
                starts.remove(&key)?;
                ensure!(matches!(starts.get(&key, 0), Err(MapError::KeyNotFound)));
            }
            entry
        }; // Release the map borrow before the call/session runs again.
        ensure!(target.command(b'u')? == "UNHELD 0 0");
        let after = crate::events::event_drain_positions(harness.session.event_drain()?);
        ensure!(
            after.consumer == before.consumer,
            "only H0 may advance this cursor"
        );
        // Actual producer positions include each eight-byte ring header.
        // Healthy:608. Refused: discarded608 plus one ordinary368. Combined
        // with the atomic decoder/outcome checks below this pins wire sizes
        // without adding a second ring consumer or a test emission flag.
        let expected_bytes = if missing_entry {
            608 + 8 + 368 + 8
        } else {
            608 + 8
        };
        ensure!(after.producer.checked_sub(before.producer) == Some(expected_bytes));
        let evidence_after = object_call_evidence(&harness.session)?;
        ensure!(
            evidence_after.0 == evidence_before.0,
            "no ring loss in either twin"
        );
        ensure!(evidence_after.1 - evidence_before.1 == u64::from(missing_entry));
        ensure!(
            harness.session.instance_maps().fault()? - fault_before == u64::from(missing_entry)
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut collected = 0;
        let mut shed = 0u64;
        let mut calls = Vec::new();
        loop {
            let report = harness
                .capture
                .tick(&mut harness.session, std::slice::from_ref(&target.pin))?;
            collected += report.collected_calls;
            let outcomes = report.into_outcomes();
            shed += crate::semantic_capture::unjoined_shed_counts(&outcomes)
                .values()
                .sum::<u64>();
            for outcome in outcomes {
                if let TickOutcome::Call(call) = outcome {
                    ensure!(call.joint_resource().is_none());
                    calls.push((*call.record(), call.route(), call.into_object_tail()));
                }
            }
            let positions = crate::events::event_drain_positions(harness.session.event_drain()?);
            if !calls.is_empty()
                && positions.consumer == positions.producer
                && harness.capture.router().pending_len() == 0
            {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "missing_entry={missing_entry}: collected={collected}, routed={}",
                calls.len()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        ensure!(
            collected == 1 && calls.len() == 1,
            "one actual call must conserve one collected/routed outcome"
        );
        ensure!(harness.session.event_drain()?.malformed() == 0);
        let (record, route, object) = calls.pop().unwrap();
        ensure!(record.event.event_type == event_type::CALL && record.event.slot == 0);
        ensure!(record.event.pid_tgid == key.pid_tgid && record.event.rv == 0);
        ensure!(record.continuity.return_stamp == entry.entry_stamp);
        ensure!(
            object.is_none(),
            "ordinary S1 grants no semantic object tail"
        );
        if missing_entry {
            ensure!(record.continuity.entry_ip == 0);
            ensure!(record.continuity.entry_stamp == InstanceStamp::default());
            ensure!(!continuity_joins(&record.continuity));
            ensure!(
                matches!(route, Route::Unknown(_)),
                "actual negative route: {route:?}"
            );
            ensure!(
                shed == 1,
                "count the routed call once, never a receipt repeat"
            );
        } else {
            ensure!(record.continuity.entry_ip == entry.entry_ip);
            ensure!(record.continuity.entry_stamp == entry.entry_stamp);
            ensure!(continuity_joins(&record.continuity));
            ensure!(
                matches!(route, Route::Joined(_)),
                "healthy route: {route:?}"
            );
            ensure!(shed == 0);
        }
        eprintln!(
            "S1 object twin missing_entry={missing_entry}: collected=1 route={route:?} shed={shed} wire_bytes={expected_bytes}"
        );
    }
    Ok(())
}

/// Two cmd targets sharing one provider file: the in-scope target and an
/// out-of-scope sibling whose calls hit the same probed offsets.
struct PairSetup {
    _directory: tempfile::TempDir,
    provider: PathBuf,
    inner: Target,
    outer: Target,
}

fn spawn_pair_targets() -> Result<PairSetup> {
    let directory = tempfile::tempdir()?;
    let provider = compile(directory.path(), true)?;
    let driver = compile(directory.path(), false)?;
    let args = ["cmd".as_ref(), provider.as_os_str()];
    let mut inner = Target::spawn(&driver, &args, &[])?;
    let ready = inner.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    let mut outer = Target::spawn(&driver, &args, &[])?;
    let ready = outer.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    ensure!(inner.pid() != outer.pid(), "sibling targets share a pid");
    Ok(PairSetup {
        _directory: directory,
        provider,
        inner,
        outer,
    })
}

/// The target leader's PROC_EPOCH row, if the kernel created one.
fn proc_record_of(harness: &Harness, target: &Target) -> Result<Option<InstanceRecord>> {
    harness.session.instance_maps().record(target.pin.pidfd()?)
}

/// The row's marker word, or 0 when no row exists. `InstanceRecord` has no
/// Debug impl, so cells format rows through this and [`marker_summary`].
fn marker_word_of(record: &Option<InstanceRecord>) -> u64 {
    record.map(|record| record.journal_bootstrap).unwrap_or(0)
}

fn marker_summary(record: &Option<InstanceRecord>) -> String {
    match record {
        None => "no row".to_string(),
        Some(record) => format!(
            "word {:#x} gen {}",
            record.journal_bootstrap, record.exec_attach_gen
        ),
    }
}

/// The session's marker admission row, read directly through the session's
/// instance maps.
fn admission_of(harness: &Harness) -> Result<JournalAdmissionControl> {
    harness.session.instance_maps().journal_admission_control()
}

/// The READY exec ID of a row that must already be published, or a loud
/// refusal naming the actual word.
fn ready_exec_of(record: &Option<InstanceRecord>, what: &str) -> Result<u64> {
    let word = marker_word_of(record);
    match journal_marker::read_word(word) {
        journal_marker::MarkerRead::Ready(exec) => Ok(exec),
        other => bail!(
            "{what} must publish READY, got {other:?} ({})",
            marker_summary(record),
        ),
    }
}

/// Pumps `rounds` ticks and returns whatever routed. For pins where the
/// expected outcome is silence (an out-of-scope return emits no call).
fn pump_rounds(harness: &mut Harness, target: &Target, rounds: u32) -> Result<Vec<Routed>> {
    for _ in 0..rounds {
        harness.pump(target)?;
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(harness.take_routed())
}

/// The process's current cgroup v2 directory: parses the `0::` line of
/// `/proc/<pid>/cgroup` under the v2 mount.
fn current_cgroup(pid: u32) -> Result<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    for line in text.lines() {
        if let Some(relative) = line.strip_prefix("0::") {
            return Ok(PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/')));
        }
    }
    bail!("no cgroup v2 entry for process {pid}: {text:?}")
}

/// Moves the whole process to `cgroup` and proves the move landed: a
/// misplaced process would flip every later scope assertion, so a silent
/// miss must fail here instead.
fn move_process_to(pid: u32, cgroup: &Path) -> Result<()> {
    std::fs::write(cgroup.join("cgroup.procs"), pid.to_string())
        .with_context(|| format!("moving {pid} to {}", cgroup.display()))?;
    let placed = current_cgroup(pid)?;
    ensure!(
        placed == cgroup,
        "process {pid} did not land in {} (in {})",
        cgroup.display(),
        placed.display()
    );
    Ok(())
}

/// One privately owned cgroup v2 child for the marker scope cells. The cell
/// moves its target back out and removes the directory explicitly; Drop
/// only best-effort retries the removal.
struct MarkerCgroup {
    path: PathBuf,
}

impl MarkerCgroup {
    fn create(tag: &str) -> Result<Self> {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/p11scope-marker-{}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(Self { path })
    }

    fn move_in(&self, pid: u32) -> Result<()> {
        move_process_to(pid, &self.path)
    }
}

impl Drop for MarkerCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Timeout-only reads of the owned fixture's actual capture path.
fn native_image_call_diagnostics(session: &Session, target: &Target) -> Result<String> {
    use p11scope_ebpf_common::{CallStart, EVIDENCE_CELLS, SlotStats, StartKey};

    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    let (entered, returned, errors) =
        stats
            .get(&0, 0)?
            .iter()
            .fold((0u64, 0u64, 0u64), |(entered, returned, errors), value| {
                (
                    entered.saturating_add(value.entered),
                    returned.saturating_add(value.returned),
                    errors.saturating_add(value.errors),
                )
            });
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE")?)?;
    let evidence = (0..EVIDENCE_CELLS)
        .map(|index| {
            Ok(evidence
                .get(&index, 0)?
                .iter()
                .copied()
                .fold(0u64, u64::saturating_add))
        })
        .collect::<Result<Vec<_>>>()?;
    let cookie: Array<_, ImageIdentityControl> =
        Array::try_from(session.ebpf.map("COOKIE_CTL").context("COOKIE_CTL")?)?;
    let owner: Array<_, ThreadOwnerControl> =
        Array::try_from(session.ebpf.map("OWNER_CTL").context("OWNER_CTL")?)?;
    let pid_filter: HashMap<_, u32, u64> =
        HashMap::try_from(session.ebpf.map("PID_FILTER").context("PID_FILTER")?)?;
    let start: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("START")?)?;
    let key = StartKey {
        pid_tgid: (u64::from(target.pid()) << 32) | u64::from(target.pid()),
        slot: 0,
        _pad: 0,
    };
    let start_present = match start.get(&key, 0) {
        Ok(_) => true,
        Err(MapError::KeyNotFound) => false,
        Err(error) => return Err(error).context("diagnostic START lookup"),
    };
    let array = |name: &str, index: u32| -> Result<u64> {
        let map: Array<_, u64> =
            Array::try_from(session.ebpf.map(name).with_context(|| name.to_string())?)?;
        Ok(map.get(&index, 0)?)
    };
    let maps = session.instance_maps();
    Ok(format!(
        "slot0 entered={entered} returned={returned} errors={errors} START={start_present}; \
         EVIDENCE[ring,start,unmatched,rv,cgroup,semantic,template,mechanism,abi]={evidence:?}; \
         cookie={:?}; owner={:?}; pid_filter={:?}; CONFIG={} STOP_GATE={}; fault={} sticky={}",
        cookie.get(&0, 0)?,
        owner.get(&0, 0)?,
        pid_filter.get(&target.pid(), 0),
        array("CONFIG", 0)?,
        array("STOP_GATE", 0)?,
        maps.fault()?,
        maps.sticky()?,
    ))
}

/// A real endpoint call and its private continuity record, collected without
/// the legacy cookie-only router harness.
fn native_image_call(session: &mut Session, target: &mut Target) -> Result<EventRecord> {
    let reply = target.command(b'c')?;
    ensure!(reply.starts_with("CALL "), "owned call ledger: {reply}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let drain = session.event_drain()?;
        let mut calls = Vec::new();
        let _ = drain.poll_records(Some(1 << 20), |record| {
            if record.event.event_type == event_type::CALL {
                calls.push(record);
            }
            ControlFlow::Continue(())
        });
        ensure!(drain.malformed() == 0, "malformed native call record");
        if !calls.is_empty() {
            ensure!(calls.len() == 1, "one owned call must produce one record");
            let record = calls.pop().unwrap();
            ensure!(record.event.slot_id == TAG_MAIN);
            ensure!(record.continuity.entry_stamp.flags == instance::STAMP_VALID);
            ensure!(record.continuity.return_stamp.flags == instance::STAMP_VALID);
            return Ok(record);
        }
        if Instant::now() >= deadline {
            let diagnostics = native_image_call_diagnostics(session, target)
                .unwrap_or_else(|error| format!("diagnostic read failed: {error:#}"));
            bail!("owned native call record timed out; {diagnostics}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn native_image_retained_kernel_ids(session: &Session) -> Result<BTreeMap<String, u32>> {
    let mut ids = BTreeMap::new();
    for (name, map) in session.ebpf.maps() {
        let data = match map {
            Map::Array(data)
            | Map::CgroupArray(data)
            | Map::HashMap(data)
            | Map::LruHashMap(data)
            | Map::PerCpuArray(data)
            | Map::PerCpuHashMap(data)
            | Map::ProgramArray(data)
            | Map::RingBuf(data)
            | Map::Unsupported(data) => data,
            _ => bail!("unexpected full-image fixture map {name}"),
        };
        let id = data.info()?.id();
        ensure!(id != 0);
        ids.insert(format!("map:{name}"), id);
    }
    for (name, program) in session.ebpf.programs() {
        match program.info() {
            Ok(info) => {
                ensure!(info.id() != 0);
                ids.insert(format!("program:{name}"), info.id());
            }
            Err(aya::programs::ProgramError::NotLoaded) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(ids)
}

/// Production tick integration, including explicit endpoint rebind after
/// de_thread. This qualifies routing within one retained proof domain; it
/// does not claim automatic recovery of fixed PID-scoped Multi links.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_semantic_capture_multi_reload_and_rebound_successor() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_with_backend(&plan, pid, &pins, BackendSelection::Multi)?;
    ensure!(
        harness.session.static_multi_attached() && harness.session.backend_fallback().is_none()
    );
    let domain = harness
        .session
        .native_domain()
        .context("retained native domain")?;
    let ids = native_image_retained_kernel_ids(&harness.session)?;
    let hooks = harness
        .session
        .instance_hook_stats()?
        .into_iter()
        .map(|(name, stats)| (name, stats.program_id))
        .collect::<BTreeMap<_, _>>();
    let window = || capture::ReadWindow::new(1, Instant::now() + Duration::from_secs(3));
    ensure!(matches!(
        harness.session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    target.command(b'c')?;
    let first = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(harness.retired_instances.is_empty() && harness.retired_images.is_empty());
    ensure!(harness.capture.router().ranges_retained() > 0);
    eprintln!("semantic tick: first nonempty join verified");
    let reload = target.command(b'r')?;
    let fields: Vec<_> = reload.split_whitespace().collect();
    ensure!(
        fields.len() == 4 && fields[2] == fields[3],
        "not same-address reload: {reload}"
    );
    target.command(b'c')?;
    let reloaded = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(reloaded != first && harness.retired_instances.contains(&first));
    target.command(b'e')?;
    ensure!(matches!(
        harness.session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    target.command(b'c')?;
    let leader = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(leader != reloaded && harness.retired_images.len() == 1);
    eprintln!("semantic tick: same-address reload and leader successor verified");
    target.command(b'E')?;
    ensure!(
        target.pid() == pid
            && matches!(
                harness.session.query_images(&[&target.pin], window()?),
                Err(image_query::ImageQueryRefusal::Unknown)
            )
    );
    harness.session.detach_slots(&plan.slots)?;
    ensure!(harness.session.detach_failures().is_empty() && !harness.session.has_slot_link(0));
    let (failed, completed) =
        harness
            .session
            .attach_targets(&plan.slots, &pins, &std::collections::BTreeSet::new())?;
    ensure!(failed.is_empty() && completed.len() == 1 && completed[0].0 == 0);
    let owned_sides = harness
        .session
        .links
        .iter()
        .filter(|link| link.slots().contains(&0))
        .map(|link| match link {
            RegisteredLink::MultiUProbe {
                program,
                slots,
                fds,
                ..
            } => {
                ensure!(slots == &[0] && fds.len() == 1);
                Ok(*program)
            }
            _ => bail!("successor endpoint is not owned Multi"),
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        owned_sides.len() == 2
            && BTreeSet::from_iter(owned_sides)
                == BTreeSet::from([
                    entry_program(
                        &plan.slots[0].semantics,
                        CapturePolicy::Allowlisted,
                        false,
                        ElfAbi::Lp64
                    ),
                    "p11_return"
                ])
    );
    ensure!(
        harness.session.native_domain() == Some(domain)
            && harness.session.backend_fallback().is_none()
    );
    ensure!(native_image_retained_kernel_ids(&harness.session)? == ids);
    ensure!(harness.session.instance_tracking().hook_link_count() == 4);
    ensure!(
        harness
            .session
            .instance_hook_stats()?
            .into_iter()
            .map(|(name, stats)| (name, stats.program_id))
            .collect::<BTreeMap<_, _>>()
            == hooks
    );
    ensure!(matches!(
        harness.session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    target.command(b'c')?;
    let successor = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        successor != leader
            && harness.retired_images.len() == 2
            && harness.retired_tasks.is_empty()
    );
    ensure!(
        harness.capture.router().ranges_retained() > 0
            && harness.capture.router().pending_len() == 0
    );
    eprintln!("semantic tick: rebound nonleader successor in same proof domain verified");
    // An actual ordinary fault rejects a collected old-era call; a genuine
    // later entry and fresh proof recover without restarting the owner.
    target.command(b'c')?;
    harness.session.instance_maps().raise_fault()?;
    let old = pump_until(&mut harness, &target, 1)?;
    ensure!(old.len() == 1 && old[0].route == Route::Unknown(UnknownReason::FaultEra));
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(harness.false_joins().is_empty());
    eprintln!("semantic tick: old-fault refusal and fresh-entry recovery verified");
    Ok(())
}

// Fixed PID-scoped Multi links retain the original leader task/mm and do not
// follow de_thread. Rebind only the endpoints for the successor positive;
// the same Session/domain/maps/four hooks stay retained throughout. Classic
// Singles' separate detachment/refusal gate remains unchanged.
fn native_full_image_multi_query_and_scan(abi: ElfAbi) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let provider = compile_for_abi(directory.path(), true, abi)?;
    let driver = compile_for_abi(directory.path(), false, abi)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()], &[])?;
    ensure!(target.line(Duration::from_secs(10))?.starts_with("READY"));
    let (_view, pins, plan, _key) =
        pin_and_plan_for_abi(target.pid(), &provider, &["C_GetSlotInfo"], abi)?;
    let mut session = Session::start(
        &plan,
        &Scope::Pid(target.pid()),
        &pins,
        CapturePolicy::Allowlisted,
        None,
        None,
        None,
        BackendSelection::Multi,
    )?;
    ensure!(
        session.static_multi_attached() && session.backend_fallback().is_none(),
        "full-image successor positive requires attached Multi with no fallback"
    );
    ensure!(session.attach_failures().is_empty());
    ensure!(
        session.instance_tracking().refused().is_none(),
        "full-image native startup refused: {:?}",
        session.instance_tracking().refused()
    );
    let window = || capture::ReadWindow::new(1, Instant::now() + Duration::from_secs(3));
    // Neither a fresh query nor process admission may manufacture Ready.
    ensure!(matches!(
        session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    eprintln!("full-image {abi:?}: native startup and initial Unknown query verified");
    let first = native_image_call(&mut session, &mut target).context("first owned native call")?;
    let domain = session.native_domain().context("retained native domain")?;
    let retained_ids = native_image_retained_kernel_ids(&session)?;
    let hook_ids = session
        .instance_hook_stats()?
        .into_iter()
        .map(|(name, stats)| (name, stats.program_id))
        .collect::<BTreeMap<_, _>>();
    ensure!(hook_ids.len() == 4 && session.instance_tracking().hook_link_count() == 4);
    let router = InstanceRouter::new(
        session.native_domain().context("native router domain")?,
        RouterLimits::default(),
    );
    let fence = router.fence();
    let scan = session
        .scan_image(&target.pin, plan.slots[0].object, window()?, fence, || {
            router.fence()
        })
        .map_err(|refusal| anyhow::anyhow!("full-image native scan refused: {refusal:?}"))?;
    ensure!(scan.domain() == domain && scan.image() == first.event.image);
    ensure!(
        !scan.ranges().is_empty(),
        "full-image positive must contain ranges"
    );
    ensure!(scan.file_slot() + 1 == u32::from(first.continuity.entry_stamp.file_slot_plus1));
    ensure!(scan.fence() == router.fence());
    eprintln!("full-image {abi:?}: first owned call and nonempty full-image scan verified");
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    // Poison is not repaired by a query. The real post-exec entry must renew.
    ensure!(matches!(
        session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    let renewed = native_image_call(&mut session, &mut target)
        .context("owned native call after leader exec")?;
    ensure!(renewed.event.image.task_cookie == first.event.image.task_cookie);
    ensure!(renewed.event.image.exec_id > first.event.image.exec_id);
    let scan = session
        .scan_image(&target.pin, plan.slots[0].object, window()?, fence, || {
            router.fence()
        })
        .map_err(|refusal| anyhow::anyhow!("renewed full-image scan refused: {refusal:?}"))?;
    ensure!(scan.domain() == domain && scan.image() == renewed.event.image);
    ensure!(!scan.ranges().is_empty());
    eprintln!("full-image {abi:?}: leader exec, renewed call and nonempty scan verified");
    let original_birth = target.pin.start_time();
    let original_pid = target.pid();
    let ready = target.command(b'E')?;
    ensure!(ready.starts_with("READY") && target.pid() == original_pid);
    // de_thread transfers leader birth time/PID custody. It must not be
    // mistaken for unchanged full image identity by the scan owner.
    ensure!(crate::process::process_start_time(original_pid).ok() == original_birth);
    ensure!(matches!(
        session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    eprintln!("full-image {abi:?}: nonleader exec custody and pre-entry Unknown verified");
    // The original fixed PID-Multi link cannot install a breakpoint in the
    // successor mm. This fixture rebinds endpoint links, without restarting
    // the proof owner or manufacturing continuity through a fresh Session.
    session
        .audit_image_continuity()
        .map_err(|refusal| anyhow::anyhow!("pre-rebind full-image audit refused: {refusal:?}"))?;
    session.detach_slots(&plan.slots)?;
    ensure!(session.detach_failures().is_empty() && !session.has_slot_link(plan.slots[0].index));
    let (failed, completed) =
        session.attach_targets(&plan.slots, &pins, &std::collections::BTreeSet::new())?;
    ensure!(failed.is_empty() && session.attach_failures().is_empty());
    ensure!(completed.len() == 1 && completed[0].0 == plan.slots[0].index);
    let owned_sides: Vec<_> = session
        .links
        .iter()
        .filter(|link| link.slots().contains(&plan.slots[0].index))
        .map(|link| match link {
            RegisteredLink::MultiUProbe {
                program,
                slots,
                fds,
                ..
            } => {
                ensure!(slots == &[plan.slots[0].index] && fds.len() == 1);
                Ok(*program)
            }
            _ => bail!("successor fixture endpoint is not owned Multi"),
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_entry = entry_program(
        &plan.slots[0].semantics,
        CapturePolicy::Allowlisted,
        false,
        abi,
    );
    ensure!(
        owned_sides.len() == 2
            && BTreeSet::from_iter(owned_sides) == BTreeSet::from([expected_entry, "p11_return"])
    );
    ensure!(session.backend_fallback().is_none() && session.native_domain() == Some(domain));
    ensure!(native_image_retained_kernel_ids(&session)? == retained_ids);
    ensure!(session.instance_tracking().hook_link_count() == 4);
    ensure!(
        session
            .instance_hook_stats()?
            .into_iter()
            .map(|(name, stats)| (name, stats.program_id))
            .collect::<BTreeMap<_, _>>()
            == hook_ids
    );
    session
        .audit_image_continuity()
        .map_err(|refusal| anyhow::anyhow!("post-rebind full-image audit refused: {refusal:?}"))?;
    ensure!(matches!(
        session.query_images(&[&target.pin], window()?),
        Err(image_query::ImageQueryRefusal::Unknown)
    ));
    eprintln!(
        "full-image {abi:?}: successor endpoints rebound; same domain/maps/programs/hooks and Unknown verified"
    );
    let successor = native_image_call(&mut session, &mut target)
        .context("owned native call after nonleader exec")?;
    ensure!(successor.event.image.task_cookie != renewed.event.image.task_cookie);
    let scan = session
        .scan_image(&target.pin, plan.slots[0].object, window()?, fence, || {
            router.fence()
        })
        .map_err(|refusal| {
            anyhow::anyhow!("nonleader successor full-image scan refused: {refusal:?}")
        })?;
    ensure!(scan.domain() == domain && scan.image() == successor.event.image);
    ensure!(!scan.ranges().is_empty());
    eprintln!("full-image {abi:?}: nonleader successor call and nonempty scan verified");
    session
        .audit_image_continuity()
        .map_err(|refusal| anyhow::anyhow!("final full-image audit refused: {refusal:?}"))?;
    let retired = target.pin.try_clone().map_err(anyhow::Error::msg)?;
    drop(target);
    // Real original-pin retirement control; numeric PID reuse is a separate
    // kernel fixture, not inferred from this newly exited original.
    ensure!(matches!(
        session.query_images(&[&retired], window()?),
        Err(image_query::ImageQueryRefusal::Custody)
    ));
    Ok(())
}

#[test]
#[ignore = "privileged: explicit Multi, same-object iterator and nonempty LP64 successor proof"]
fn privileged_full_image_native_multi_query_and_scan_lp64() -> Result<()> {
    native_full_image_multi_query_and_scan(ElfAbi::Lp64)
}

#[test]
#[ignore = "privileged: explicit Multi, same-object iterator and nonempty ia32 successor proof"]
fn privileged_full_image_native_multi_query_and_scan_ia32() -> Result<()> {
    native_full_image_multi_query_and_scan(ElfAbi::Ilp32)
}

/// Pins one `C_GetSlotInfo` slot per provider, in order; slot 0 is the
/// scanned and called file, so callers put their file first. Pins match
/// providers by maps key (distinct files, distinct inodes).
fn pin_and_plan_multi(
    pid: u32,
    providers: &[PathBuf],
) -> Result<(ProcessView, PinnedObjects, AttachPlan)> {
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(anyhow::Error::msg)?;
    let mut modules = Vec::new();
    let mut keyed = Vec::new();
    for provider in providers {
        let file = open_object(provider).map_err(anyhow::Error::msg)?;
        let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
        let elf = ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
        ensure!(elf.abi() == ElfAbi::Lp64);
        let key = ObjectKey {
            device: Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        keyed.push((key, elf));
        modules.push(ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key,
            path: provider.display().to_string(),
            decoder_abi: None,
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        });
    }
    let (pins, skipped) =
        pin_scanned_view_objects(&view, &modules, &mut CaptureWorkBudget::default())
            .map_err(anyhow::Error::msg)?;
    ensure!(skipped.is_empty(), "owned pins refused: {skipped:?}");
    let mut slots = Vec::new();
    for (index, ((key, elf), provider)) in keyed.iter().zip(providers).enumerate() {
        let pinned = pins
            .pinned()
            .find(|pinned| pinned.key == *key)
            .with_context(|| format!("no pin for {}", provider.display()))?;
        let offset = elf
            .defined_symbol("C_GetSlotInfo")
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("{} defines C_GetSlotInfo", provider.display()))?
            .file_offset;
        ensure!(elf.is_executable_offset(offset));
        let names = vec!["C_GetSlotInfo".to_string()];
        let (descriptor_index, ambiguous) = crate::kinds::descriptor_index(&names);
        ensure!(!ambiguous);
        slots.push(Slot {
            index: index as u32,
            descriptor_index,
            object: pinned.id,
            object_path: provider.display().to_string(),
            file_offset: offset,
            names,
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        });
    }
    Ok((view, pins, AttachPlan::from_slots(slots)))
}

/// Parses a `LOOPCOUNT n` / `LOOPED n` fixture reply.
fn loop_iterations(reply: &str) -> Result<u64> {
    reply
        .split_whitespace()
        .nth(1)
        .context("loop reply shape")?
        .parse()
        .context("loop iteration count")
}

/// Whether `dir` lives on btrfs (statfs magic), for the fs-gated cells.
fn dir_is_btrfs(dir: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes the whole struct on success.
    let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    ensure!(
        rc == 0,
        "statfs {}: {}",
        dir.display(),
        std::io::Error::last_os_error()
    );
    // SAFETY: success above initialized it.
    let stat = unsafe { stat.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_type as u64 == BTRFS_SUPER_MAGIC)
}

#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_system_identity_anchor_preserves_watched_instance() -> Result<()> {
    use crate::discovery::identity::ExaminedObject;
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelAnchorExclusions};
    use crate::discovery::sweep_attribution::{ReservationOwner, SegmentPolicy};

    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let object = plan.slots[0].object;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    target.command(b'c')?;
    let first = single_join(&pump_until(&mut harness, &target, 1)?)?;

    // A real external shared-mm mutation advances only the per-file
    // global epoch: the target's mapping and own epoch are unchanged, so
    // the instance continues. Establish this before the preservation
    // assertion, including on RED.
    let mutation_before = harness.session.instance_maps().counters()?;
    ensure!(target.command(b'v')? == "SHARER");
    let mutation_after = harness.session.instance_maps().counters()?;
    target.command(b'c')?;
    let after_mutation = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        mutation_after.global_bumps > mutation_before.global_bumps
            && mutation_after.shared > mutation_before.shared
            && mutation_after.local_bumps == mutation_before.local_bumps
            && after_mutation == first,
        "a foreign shared-mm mutation did not continue the watched instance: \
         {mutation_before:?} -> {mutation_after:?}"
    );

    // Renewing control: the target's own mapping changes still mint.
    // Later checks compare against the last own instance.
    target.command(b'p')?;
    target.command(b'c')?;
    let own = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(own != first, "the target's own mapping kept the instance");
    target.command(b'P')?;
    target.command(b'c')?;
    let own2 = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(own2 != own, "the target's own unmap kept the instance");

    // The unexcluded anchor path must also exercise the actual native
    // witness. Excluding selected files changes no BPF hook semantics.
    let unexcluded_before = harness.session.instance_maps().complete_epochs(
        target.pin.pidfd().map_err(anyhow::Error::msg)?,
        harness.file_slot,
    )?;
    let unexcluded_pins = pins.clone();
    crate::inventory_capture::collect_off_thread(
        move || {
            let custody = ExaminedCustody::new(
                ReservationOwner::for_examined(SegmentPolicy::from_headroom(128, 0, 0), 0),
                BTreeMap::new(),
            );
            drop(AnchorPass::prepare(
                &unexcluded_pins,
                [(key, object)],
                custody,
            ));
        },
        Duration::from_millis(20),
        &mut || {},
    );
    let unexcluded_after = harness.session.instance_maps().complete_epochs(
        target.pin.pidfd().map_err(anyhow::Error::msg)?,
        harness.file_slot,
    )?;
    target.command(b'c')?;
    let original = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        unexcluded_after.global > unexcluded_before.global
            && unexcluded_after.local == unexcluded_before.local
            && original == own2,
        "unexcluded System identity anchors did not continue the actual watched instance"
    );

    let retained = harness
        .session
        .instance_tracking()
        .watched(object)
        .context("the original provider is still watched")?
        .retained_target();
    let unrelated_path = _directory.path().join("unrelated-anchor");
    std::fs::write(&unrelated_path, [0u8; 4096])?;
    let unrelated_path = unrelated_path.canonicalize()?;
    let main_thread = std::thread::current().id();
    let mut preserved = true;
    for pass in 0..2 {
        let before_maps = std::fs::read(format!("/proc/{}/maps", target.pid()))?;
        let before = harness.session.instance_maps().complete_epochs(
            target.pin.pidfd().map_err(anyhow::Error::msg)?,
            harness.file_slot,
        )?;
        let counters_before = harness.session.instance_maps().counters()?;
        // Use the production exclusion snapshot of the actual watched
        // target. An unrelated examined anchor must still be mapped and
        // released, so the mixed pass cannot pass by disabling all anchors.
        let worker_pins = pins.clone();
        let worker_exclusions = KernelAnchorExclusions::from_targets([&retained]);
        let worker_unrelated = unrelated_path.clone();
        let worker = crate::inventory_capture::collect_off_thread(
            move || -> Result<_> {
                let file = std::fs::File::open(&worker_unrelated)?;
                let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
                let mapped = crate::discovery::identity::self_mapped_file(&file)
                    .map_err(anyhow::Error::msg)?;
                let examined = ExaminedObject {
                    key: ObjectKey {
                        device: Device {
                            major: mapping.device_major,
                            minor: mapping.device_minor,
                        },
                        inode: mapping.inode,
                    },
                    identity: mapped.identity,
                    key_is_identity: false,
                };
                let mut custody = ExaminedCustody::new(
                    ReservationOwner::for_examined(SegmentPolicy::from_headroom(128, 0, 0), 1),
                    BTreeMap::new(),
                );
                let scan = custody.begin_scan();
                ensure!(
                    custody.offer(scan, examined, file),
                    "unrelated custody refused"
                );
                let anchors = AnchorPass::prepare_excluding(
                    &worker_pins,
                    [(key, object)],
                    custody,
                    &worker_exclusions,
                );
                let has_unrelated_mapping = || -> Result<bool> {
                    Ok(std::fs::read_to_string("/proc/self/maps")?
                        .lines()
                        .any(|line| line.ends_with(worker_unrelated.to_str().unwrap())))
                };
                ensure!(
                    has_unrelated_mapping()?,
                    "unrelated identity anchor was not mapped"
                );
                drop(anchors);
                ensure!(
                    !has_unrelated_mapping()?,
                    "unrelated identity anchor was not released"
                );
                Ok(std::thread::current().id())
            },
            Duration::from_millis(20),
            &mut || {},
        )?;
        ensure!(
            worker != main_thread,
            "identity anchors did not use the worker"
        );
        let after = harness.session.instance_maps().complete_epochs(
            target.pin.pidfd().map_err(anyhow::Error::msg)?,
            harness.file_slot,
        )?;
        let counters_after = harness.session.instance_maps().counters()?;
        ensure!(
            before_maps == std::fs::read(format!("/proc/{}/maps", target.pid()))?
                && target.pin.still_the_same(),
            "the idle target changed during identity anchor preparation"
        );
        let observation = harness.scan(&target, false)?;
        target.command(b'c')?;
        let joined = single_join(&pump_until(&mut harness, &target, 1)?)?;
        let continued = observation == Some(ObserveOutcome::Continued) && joined == original;
        eprintln!(
            "H6_SYSTEM_IDENTITY_ANCHOR pass={pass} epochs_equal={} continued={continued} \
             local_delta={} global_delta={} fault_delta={} \
             counters_before={counters_before:?} counters_after={counters_after:?}",
            before == after,
            after.local.saturating_sub(before.local),
            after.global.saturating_sub(before.global),
            after.fault.saturating_sub(before.fault),
        );
        preserved &= before == after && continued;
    }
    ensure!(
        preserved,
        "System identity anchors changed the idle target's watched instance; \
         inspect actual H6_SYSTEM_IDENTITY_ANCHOR epoch/counter deltas"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_inventory_worker_scan_preserves_watched_instance() -> Result<()> {
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::identity::RetainedMappedIdentities;

    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let retained = pins
        .retain_inventory_target(pins.pinned().next().context("owned pin")?.id)
        .map_err(anyhow::Error::msg)?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    target.command(b'c')?;
    let first = single_join(&pump_until(&mut harness, &target, 1)?)?;

    // Establish the genuine global-mutation control before the regression
    // assertion, so RED still proves that the real hooks and router respond.
    // The existing fixture's short-lived CLONE_VM child is reaped by 'v'.
    // A foreign mutation moves only the global epoch, so it continues.
    let external_before = harness.session.instance_maps().counters()?;
    ensure!(target.command(b'v')? == "SHARER");
    let external_after = harness.session.instance_maps().counters()?;
    target.command(b'c')?;
    let after_external = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        external_after.global_bumps > external_before.global_bumps
            && external_after.shared > external_before.shared
            && external_after.local_bumps == external_before.local_bumps
            && after_external == first,
        "a real external shared-mm mutation did not continue the instance: \
         {external_before:?} -> {external_after:?}"
    );

    // Renewing control: the target's own mapping changes still mint.
    // Later checks compare against the last own instance.
    target.command(b'p')?;
    target.command(b'c')?;
    let own = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        own != after_external,
        "the target's own mapping kept the instance"
    );
    target.command(b'P')?;
    target.command(b'c')?;
    let original = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(original != own, "the target's own unmap kept the instance");
    let pid = target.pid();
    let pin = target.pin.clone();
    let cookie = harness
        .session
        .instance_maps()
        .cookie(pin.pidfd().map_err(anyhow::Error::msg)?)?
        .context("the real target call established its image cookie")?;
    let current_image = |harness: &mut Harness| -> Result<_> {
        harness
            .session
            .query_images(
                &[&pin],
                capture::ReadWindow::new(1, Instant::now() + Duration::from_secs(3))?,
            )
            .map_err(|reason| anyhow!("native current image query refused: {reason:?}"))?
            .image(cookie)
            .context("the original process still has its current image")
    };
    let image = current_image(&mut harness)?;
    let policy = crate::plan::AdmissionPolicy::inventory(
        crate::capacity::inventory_endpoint_budget(None).map_err(anyhow::Error::msg)?,
    );
    let main_thread = std::thread::current().id();
    let mut preserved = true;
    for pass in 0..2 {
        let before_maps = std::fs::read(format!("/proc/{}/maps", target.pid()))?;
        let before = harness.session.instance_maps().complete_epochs(
            target.pin.pidfd().map_err(anyhow::Error::msg)?,
            harness.file_slot,
        )?;
        let counters_before = harness.session.instance_maps().counters()?;
        // The same snapshot constructor used by the coordinator's collector:
        // the original target/file proof, calibrated before it was watched.
        let budget = CaptureWorkBudget::default()
            .with_retained_mapped_identities(RetainedMappedIdentities::from_targets([&retained]));
        // The same production scan/pinning path used by Inventory's collector,
        // on its real worker. No target command runs during this collection.
        let (worker, catalog) = crate::inventory_capture::collect_off_thread(
            || {
                (
                    std::thread::current().id(),
                    crate::inspect_system::collect_pid_with_budget(
                        pid,
                        std::slice::from_ref(&provider),
                        &HookRegistry::default(),
                        policy,
                        budget,
                    ),
                )
            },
            Duration::from_millis(20),
            &mut || {},
        );
        ensure!(
            worker != main_thread,
            "the production scan must run on its worker"
        );
        ensure!(
            catalog?.scanned == 1,
            "the owned target was not deep-scanned"
        );
        let after = harness.session.instance_maps().complete_epochs(
            target.pin.pidfd().map_err(anyhow::Error::msg)?,
            harness.file_slot,
        )?;
        let counters_after = harness.session.instance_maps().counters()?;
        ensure!(
            before_maps == std::fs::read(format!("/proc/{}/maps", target.pid()))?
                && current_image(&mut harness)? == image,
            "the idle target changed its mapping or image during the observer scan"
        );
        let observation = harness.scan(&target, false)?;
        target.command(b'c')?;
        let joined = single_join(&pump_until(&mut harness, &target, 1)?)?;
        let continued = observation == Some(ObserveOutcome::Continued) && joined == original;
        // Aggregate deltas come from the actual native maps. No epoch values
        // or image identities are fabricated or emitted as public evidence.
        eprintln!(
            "H6_OBSERVER_SCAN pass={pass} epochs_equal={} continued={continued} \
             local_delta={} global_delta={} fault_delta={} \
             counters_before={counters_before:?} counters_after={counters_after:?}",
            before == after,
            after.local.saturating_sub(before.local),
            after.global.saturating_sub(before.global),
            after.fault.saturating_sub(before.fault),
        );
        preserved &= before == after && continued;
    }
    ensure!(
        preserved,
        "Inventory's observer scan changed an idle target's watched instance; \
         inspect the actual H6_OBSERVER_SCAN epoch/counter deltas"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_routing_separates_reload_sibling_and_mutation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let provider = compile(directory.path(), true)?;
    let driver = compile(directory.path(), false)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()], &[])?;
    let ready = target.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let _stats = enable_bpf_stats()?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    // Matrix evidence: every loaded program's verifier work while this
    // session holds it (`verified_insns` exists from 5.16).
    if let Some(out) = std::env::var_os("P11SCOPE_T3A_PROG_SHOW") {
        let shown = Command::new("bpftool")
            .args(["prog", "show", "--json"])
            .output()?;
        ensure!(shown.status.success(), "bpftool prog show failed");
        std::fs::write(out, &shown.stdout)?;
    }
    let counters_before = harness.session.instance_maps().counters()?;
    ensure!(
        counters_before.calib_hits >= 1,
        "calibration hit: {counters_before:?}"
    );

    let mut steps = Vec::new();
    // Gen 0, three calls: one instance.
    for _ in 0..3 {
        target.command(b'c')?;
    }
    let a = single_join(&pump_until(&mut harness, &target, 3)?)?;
    steps.push(("gen0", a));
    // Unrelated file mapping churn: no bump, same instance.
    let local_before = harness.session.instance_maps().counters()?.local_bumps;
    target.command(b'm')?;
    target.command(b'c')?;
    let after_unrelated = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(after_unrelated == a, "unrelated churn changed the instance");
    ensure!(
        harness.session.instance_maps().counters()?.local_bumps == local_before,
        "unrelated mapping bumped a watched epoch"
    );
    // Same-address reload: a new instance, never the old one.
    let reload = target.command(b'r')?;
    let fields: Vec<_> = reload.split_whitespace().collect();
    ensure!(
        fields.len() == 4 && fields[2] == fields[3],
        "not same-address: {reload}"
    );
    target.command(b'c')?;
    target.command(b'c')?;
    let b = single_join(&pump_until(&mut harness, &target, 2)?)?;
    ensure!(b != a, "same-address reload revived instance {a:?}");
    steps.push(("gen1", b));
    // An extra provider mapping (direct mmap) is a watched mutation: the
    // conservative outcome is a new incarnation (named gap D2), never a join.
    target.command(b'p')?;
    target.command(b'c')?;
    let c = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(c != b, "extra provider mapping kept the instance");
    // mremap of a provider mapping reaches the copy_vma fexit hook.
    let copies = hook_runs(&harness, "p11_inst_vma_copy")?;
    target.command(b'M')?;
    let copied = hook_runs(&harness, "p11_inst_vma_copy")? - copies;
    ensure!(copied >= 1, "mremap did not reach the copy_vma hook");
    target.command(b'c')?;
    let moved = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(moved != c, "provider mremap kept the instance");
    target.command(b'P')?;
    target.command(b'c')?;
    let d = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(d != moved, "provider unmap kept the instance");
    // A CLONE_VM non-thread child mutating the provider in the shared mm:
    // marked at fork, its mutations go to the file's global epoch only.
    // The target's mapping and own epoch are unchanged, so it continues.
    let shared_before = harness.session.instance_maps().counters()?;
    target.command(b'v')?;
    let shared_after = harness.session.instance_maps().counters()?;
    ensure!(
        shared_after.shared >= shared_before.shared + 2
            && shared_after.global_bumps >= shared_before.global_bumps + 2
            && shared_after.local_bumps == shared_before.local_bumps,
        "CLONE_VM sharer was not globalized: {shared_before:?} -> {shared_after:?}"
    );
    target.command(b'c')?;
    let after_sharer = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        after_sharer == d,
        "a sharer's mutation did not continue the instance"
    );
    // dlmopen sibling: two loads of one file, two instances.
    target.command(b'd')?;
    target.command(b'c')?;
    target.command(b'C')?;
    let routed = pump_until(&mut harness, &target, 2)?;
    let main: Vec<_> = routed
        .iter()
        .copied()
        .filter(|r| r.tag & 0xff00_0000 == TAG_MAIN)
        .collect();
    let sibling: Vec<_> = routed
        .iter()
        .copied()
        .filter(|r| r.tag & 0xff00_0000 == TAG_SIBLING)
        .collect();
    let e = single_join(&main)?;
    let f = single_join(&sibling)?;
    ensure!(e != f, "dlmopen siblings joined one instance");
    let earlier = [a, b, c, moved, d, after_sharer];
    ensure!(!earlier.contains(&e) && !earlier.contains(&f));
    let counters = harness.session.instance_maps().counters()?;
    let hooks = harness.session.instance_hook_stats()?;
    eprintln!(
        "T3A_ROUTING steps={steps:?} sibling=({e:?},{f:?}) counters={counters:?} hooks={hooks:?} scans={:?} minted={}",
        harness.scan,
        harness.capture.router().instances_minted()
    );
    ensure!(counters.local_bumps > counters_before.local_bumps);
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c mapping controls that reach the provider file: each must
/// end the old incarnation (new ID) when witnessed, or keep it only when no
/// witness event fired and the mapping set is unchanged; no
/// control may produce a coverage fault (a range the hooks did not see).
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_mapping_controls_never_join_old_state() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let provider = compile(directory.path(), true)?;
    ensure!(
        std::fs::metadata(&provider)?.len() > 8192,
        "provider too small for the split control"
    );
    let driver = compile(directory.path(), false)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()], &[])?;
    let ready = target.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let call = |harness: &mut Harness, target: &mut Target| -> Result<InstanceId> {
        target.command(b'c')?;
        single_join(&pump_until(harness, target, 1)?)
    };
    let bumps = |harness: &Harness| -> Result<u64> {
        Ok(harness.session.instance_maps().counters()?.local_bumps)
    };

    let a = call(&mut harness, &mut target)?;
    target.command(b'p')?;
    let b = call(&mut harness, &mut target)?;
    ensure!(b != a, "extra provider mapping kept the instance");
    // MADV_DONTNEED changes no VMA, but the kernel's zap path calls
    // `uprobe_munmap` for file VMAs: a conservative spurious incarnation
    // (decision §3b), never a join to the old one.
    let before = bumps(&harness)?;
    target.command(b'D')?;
    let dontneed_bumps = bumps(&harness)? - before;
    let after_dontneed = call(&mut harness, &mut target)?;
    ensure!(
        (dontneed_bumps == 0) == (after_dontneed == b),
        "MADV_DONTNEED outcome inconsistent with its {dontneed_bumps} bumps"
    );
    // MAP_FIXED anonymous memory over the provider page.
    let before = bumps(&harness)?;
    target.command(b'F')?;
    ensure!(
        bumps(&harness)? > before,
        "MAP_FIXED replacement was not witnessed"
    );
    let after_fixed = call(&mut harness, &mut target)?;
    ensure!(after_fixed != b, "MAP_FIXED replacement kept the instance");
    // A split-inducing mprotect of a provider mapping.
    target.command(b'q')?;
    let paired = call(&mut harness, &mut target)?;
    ensure!(
        paired != after_fixed,
        "provider pair mapping kept the instance"
    );
    let before = bumps(&harness)?;
    target.command(b's')?;
    let split_bumps = bumps(&harness)? - before;
    let after_split = call(&mut harness, &mut target)?;
    ensure!(
        after_split != paired || split_bumps == 0,
        "inconsistent split outcome"
    );
    target.command(b'Q')?;
    let after_pair = call(&mut harness, &mut target)?;
    ensure!(
        after_pair != after_split,
        "provider pair unmap kept the instance"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_CONTROLS ids={:?} dontneed_bumps={dontneed_bumps} split_bumps={split_bumps} counters={counters:?} scans={:?}",
        [
            a,
            b,
            after_dontneed,
            after_fixed,
            paired,
            after_split,
            after_pair
        ],
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(
        harness.session.instance_maps().sticky()? == 0,
        "a control produced a coverage fault"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: same-address reload race against a second calling thread"]
fn privileged_instance_reload_race_has_zero_false_joins() -> Result<()> {
    let reloads: u64 = std::env::var("P11SCOPE_T3A_RELOADS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let directory = tempfile::tempdir()?;
    let provider = compile(directory.path(), true)?;
    let driver = compile(directory.path(), false)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()], &[])?;
    let ready = target.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    target.command(b'R')?;
    let mut same_address = 0u64;
    for _ in 0..reloads {
        for _ in 0..4 {
            harness.pump(&target)?;
            std::thread::sleep(Duration::from_millis(3));
        }
        let reload = target.command(b'r')?;
        let fields: Vec<_> = reload.split_whitespace().collect();
        if fields.len() == 4 && fields[2] == fields[3] {
            same_address += 1;
        }
        // Provider mutations without the call lock: epochs move while racing
        // calls are in flight, so some calls straddle and must be refused.
        target.command(b'p')?;
        harness.pump(&target)?;
        target.command(b'P')?;
    }
    let raced = target.command(b'S')?;
    for _ in 0..20 {
        harness.pump(&target)?;
        std::thread::sleep(Duration::from_millis(5));
    }
    let ledger: u64 = raced
        .split_whitespace()
        .skip(1)
        .filter_map(|pair| pair.split_once(':')?.1.parse::<u64>().ok())
        .sum();
    let raced_observed = harness
        .routed
        .iter()
        .filter(|r| r.tag & 0xff00_0000 == TAG_RACE)
        .count();
    let false_joins = harness.false_joins();
    let joined = harness
        .routed
        .iter()
        .filter(|r| matches!(r.route, Route::Joined(_)))
        .count();
    let unknown = harness.unknown_reasons();
    let ids = harness.joined_ids();
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_RELOAD_RACE reloads={reloads} same_address={same_address} ledger_calls={ledger} \
         observed={} raced_observed={raced_observed} joined={joined} unknown={unknown:?} ids={} false_joins={} pending={} \
         scans={:?} counters={counters:?} misses={}",
        harness.events,
        ids.len(),
        false_joins.len(),
        harness.capture.router().pending_len(),
        harness.scan,
        harness.misses
    );
    ensure!(false_joins.is_empty(), "false joins: {false_joins:?}");
    ensure!(
        harness.events == ledger,
        "observed {} calls, ledger {ledger}",
        harness.events
    );
    ensure!(
        harness.routed.len() as u64 == harness.events
            && harness.capture.router().pending_len() == 0,
        "every call must be joined or explicitly unknown"
    );
    ensure!(
        same_address == reloads,
        "only {same_address}/{reloads} same-address reloads"
    );
    ensure!(joined > 0, "no positive routing at all");
    Ok(())
}

/// The bounded continuity experiment (transfer plan Task 3): SoftHSM2 with a
/// long-lived key, `P11SCOPE_T3A_SECONDS` (default 60) under
/// `P11SCOPE_T3A_RATE` (default 0) unrelated mapping operations per second.
#[test]
#[ignore = "privileged: 60 s SoftHSM2 continuity experiment"]
fn privileged_instance_continuity_experiment_softhsm() -> Result<()> {
    let env_u64 = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let seconds = env_u64("P11SCOPE_T3A_SECONDS", 60);
    let rate = env_u64("P11SCOPE_T3A_RATE", 0);
    let directory = tempfile::tempdir()?;
    let driver = compile(directory.path(), false)?;
    let tokens = directory.path().join("tokens");
    std::fs::create_dir(&tokens)?;
    let conf = directory.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )?;
    let init = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf)
        .args([
            "--init-token",
            "--free",
            "--label",
            "t3a",
            "--so-pin",
            "5678",
            "--pin",
            "1234",
        ])
        .output()?;
    ensure!(
        init.status.success(),
        "token init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let unrelated_file = directory.path().join("unrelated.dat");
    std::fs::write(&unrelated_file, vec![0x5au8; 8192])?;
    let unrelated_so = directory.path().join("unrelated.so");
    let so_source = directory.path().join("unrelated.c");
    std::fs::write(&so_source, "int unrelated_marker(void) { return 7; }\n")?;
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&unrelated_so)
        .arg(&so_source)
        .output()?;
    ensure!(built.status.success());
    let seconds_arg = seconds.to_string();
    let rate_arg = rate.to_string();
    let mut target = Target::spawn(
        &driver,
        &[
            "churn".as_ref(),
            SOFTHSM.as_ref(),
            unrelated_file.as_os_str(),
            unrelated_so.as_os_str(),
            seconds_arg.as_ref(),
            rate_arg.as_ref(),
        ],
        &[("SOFTHSM2_CONF", &conf)],
    )?;
    let ready = target.line(Duration::from_secs(30))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    let key_line = target.line(Duration::from_secs(10))?;
    let (_view, pins, plan, _key) = pin_and_plan(
        target.pid(),
        Path::new(SOFTHSM),
        &["C_GetSlotInfo", "C_EncryptInit", "C_Encrypt"],
    )?;
    let _stats = enable_bpf_stats()?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let maps = harness.session.instance_maps();
    let counters_start = maps.counters()?;
    let global_start = maps.global(harness.file_slot)?;
    let hooks_start = harness.session.instance_hook_stats()?;
    let started = Instant::now();
    target.send(b'g')?;
    let mut ledger = None;
    let mut ops = None;
    let mut last_periodic = Instant::now();
    let mut first_local = None;
    while ops.is_none() {
        harness.pump(&target)?;
        if last_periodic.elapsed() >= Duration::from_secs(1) {
            last_periodic = Instant::now();
            harness.scan(&target, false)?;
            if first_local.is_none() {
                first_local = harness
                    .session
                    .instance_maps()
                    .record(target.pin.pidfd()?)?
                    .map(|record| (record.slot_plus1, record.epoch));
            }
        }
        while let Ok(line) = target.lines.try_recv() {
            ensure!(!line.starts_with("FAIL"), "{line}");
            if line.starts_with("LEDGER") {
                ledger = Some(line.clone());
            } else if line.starts_with("OPS") {
                ops = Some(line.clone());
            }
            target.ledger.push(line);
        }
        ensure!(
            started.elapsed() < Duration::from_secs(seconds + 60),
            "experiment overran"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let elapsed = started.elapsed();
    for _ in 0..20 {
        harness.pump(&target)?;
        std::thread::sleep(Duration::from_millis(5));
    }
    harness.scan(&target, false)?;
    let maps = harness.session.instance_maps();
    let counters_end = maps.counters()?;
    let global_end = maps.global(harness.file_slot)?;
    let last_local = maps
        .record(target.pin.pidfd()?)?
        .map(|record| (record.slot_plus1, record.epoch));
    let hooks_end = harness.session.instance_hook_stats()?;
    let ledger = ledger.context("ledger line")?;
    let ledger_calls: u64 = ledger
        .split_whitespace()
        .find_map(|field| field.strip_prefix("calls=")?.parse().ok())
        .context("ledger calls")?;
    let observed_tags = harness
        .routed
        .iter()
        .filter(|r| r.slot == 0 && r.tag == TAG_MAIN)
        .count() as u64;
    let ids = harness.joined_ids();
    let joined = harness
        .routed
        .iter()
        .filter(|r| matches!(r.route, Route::Joined(_)))
        .count();
    let unknown = harness.unknown_reasons();
    let hook_delta: Vec<_> = hooks_start
        .iter()
        .zip(&hooks_end)
        .map(|((name, start), (_, end))| {
            (
                *name,
                end.run_cnt - start.run_cnt,
                end.run_time_ns - start.run_time_ns,
                end.recursion_misses - start.recursion_misses,
            )
        })
        .collect();
    let hook_ns: u64 = hook_delta.iter().map(|(_, _, ns, _)| ns).sum();
    let hook_calls: u64 = hook_delta.iter().map(|(_, calls, _, _)| calls).sum();
    eprintln!(
        "T3A_EXPERIMENT rate={rate} seconds={seconds} elapsed_ms={} {key_line} {ledger} {} \
         observed_calls={} observed_tagged={observed_tags} joined={joined} unknown={unknown:?} \
         ids={ids:?} first_record={first_local:?} last_record={last_local:?} \
         global=({global_start},{global_end}) counters_delta=(watched {} local {} global {} \
         remote {} shared {} null {} overflow {} teardown {} faults {}) hook_calls={hook_calls} \
         hook_ns={hook_ns} hook_cpu_pct={:.4} hooks={hook_delta:?} scans={:?} router=(minted {} \
         ranges {} pending {}) misses={}",
        elapsed.as_millis(),
        ops.as_deref().unwrap_or(""),
        harness.events,
        counters_end.watched_hits - counters_start.watched_hits,
        counters_end.local_bumps - counters_start.local_bumps,
        counters_end.global_bumps - counters_start.global_bumps,
        counters_end.remote - counters_start.remote,
        counters_end.shared - counters_start.shared,
        counters_end.storage_null - counters_start.storage_null,
        counters_end.overflow - counters_start.overflow,
        counters_end.teardown_skips - counters_start.teardown_skips,
        counters_end.faults - counters_start.faults,
        hook_ns as f64 / elapsed.as_nanos() as f64 * 100.0,
        harness.scan,
        harness.capture.router().instances_minted(),
        harness.capture.router().ranges_retained(),
        harness.capture.router().pending_len(),
        harness.misses,
    );
    target.send(b'x')?;
    ensure!(ids.len() == 1, "instance IDs not stable: {ids:?}");
    ensure!(unknown.is_empty(), "unknown routing: {unknown:?}");
    ensure!(
        observed_tags == ledger_calls,
        "observed {observed_tags} tagged calls, ledger {ledger_calls}"
    );
    ensure!(
        first_local == last_local,
        "watched epoch moved under unrelated churn"
    );
    ensure!(
        global_start == global_end,
        "global epoch moved under unrelated churn"
    );
    ensure!(
        counters_end.watched_hits == counters_start.watched_hits,
        "provider file was mutated during the run"
    );
    ensure!(harness.misses == 0);
    Ok(())
}

/// Decision §3c: a pure `MREMAP_DONTUNMAP` keeps the old VMA (no munmap
/// hook) while the new VMA reaches the copy_vma fexit hook. Both mappings
/// stay live (the fixture mincore-checks them); the move renews the
/// incarnation, and unmapping the pair renews it again. Zero false joins.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_mremap_dontunmap_keeps_both_and_renews() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let _stats = enable_bpf_stats()?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let call = |harness: &mut Harness, target: &mut Target| -> Result<InstanceId> {
        target.command(b'c')?;
        single_join(&pump_until(harness, target, 1)?)
    };
    let a = call(&mut harness, &mut target)?;
    target.command(b'p')?;
    let b = call(&mut harness, &mut target)?;
    ensure!(b != a, "extra provider mapping kept the instance");
    let copies = hook_runs(&harness, "p11_inst_vma_copy")?;
    let moved = target.command(b'U')?;
    ensure!(moved == "PUREMOVE", "DONTUNMAP dropped a mapping: {moved}");
    let copied = hook_runs(&harness, "p11_inst_vma_copy")? - copies;
    ensure!(
        copied >= 1,
        "DONTUNMAP move did not reach the copy_vma hook"
    );
    let after_move = call(&mut harness, &mut target)?;
    ensure!(after_move != b, "DONTUNMAP move kept the instance");
    target.command(b'P')?;
    let after_unmap = call(&mut harness, &mut target)?;
    ensure!(
        after_unmap != after_move,
        "DONTUNMAP pair unmap kept the instance"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_DONTUNMAP copied={copied} counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c: a true vfork child (parent suspended) unmapping the
/// shared provider page. The child is marked at fork, so the unmap goes
/// to the file's global epoch and renews the parent's incarnation.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_vfork_unmap_globalizes() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let call = |harness: &mut Harness, target: &mut Target| -> Result<InstanceId> {
        target.command(b'c')?;
        single_join(&pump_until(harness, target, 1)?)
    };
    let a = call(&mut harness, &mut target)?;
    target.command(b'p')?;
    let b = call(&mut harness, &mut target)?;
    ensure!(b != a, "extra provider mapping kept the instance");
    let before = harness.session.instance_maps().counters()?;
    let unmapped = target.command(b'V')?;
    ensure!(unmapped == "VUNMAP", "{unmapped}");
    let after = harness.session.instance_maps().counters()?;
    ensure!(
        after.shared > before.shared && after.global_bumps > before.global_bumps,
        "vfork unmap was not globalized: {before:?} -> {after:?}"
    );
    let c = call(&mut harness, &mut target)?;
    ensure!(c != b, "vfork unmap kept the instance");
    eprintln!("T3A_VFORK counters={after:?} scans={:?}", harness.scan);
    ensure!(harness.false_joins().is_empty());
    ensure!(after.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Best-effort killer for a fixture sharer pid: the leak regressions must
/// not leave a blocked child behind when they fail (RED) or flake.
struct SharerGuard {
    pid: u32,
}

impl Drop for SharerGuard {
    fn drop(&mut self) {
        // SAFETY: signaling a possibly-dead pid by number; ESRCH is fine.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn hold_sharer(target: &mut Target) -> u32 {
    let held = target.command(b'w').unwrap();
    assert!(held.starts_with("SHARER_HELD"), "{held}");
    let pid: u32 = held.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(process_alive(pid), "the fixture held no live sharer");
    pid
}

/// Sol B2 (`w` -> `x`): graceful shutdown wakes (EOF) and reaps the held
/// sharer — the driver exits promptly and no child is left behind.
#[test]
fn held_sharer_is_reaped_on_graceful_exit() {
    let mut setup = spawn_cmd_target().unwrap();
    let sharer = hold_sharer(&mut setup.target);
    let _guard = SharerGuard { pid: sharer };
    let start = Instant::now();
    setup.target.send(b'x').unwrap();
    let mut exited = false;
    for _ in 0..1000 {
        if setup.target.child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(exited, "the driver did not exit after w -> x");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "graceful shutdown took too long"
    );
    assert!(
        !process_alive(sharer),
        "held sharer {sharer} leaked after w -> x"
    );
}

/// Sol B2 (failure before `W`): when the parent dies without cleanup (as
/// on a Rust setup failure), the held sharer must see EOF and exit on its
/// own instead of blocking forever on its inherited write end.
#[test]
fn held_sharer_exits_when_parent_dies_before_wake() {
    let mut setup = spawn_cmd_target().unwrap();
    let sharer = hold_sharer(&mut setup.target);
    let _guard = SharerGuard { pid: sharer };
    // SIGKILL: no handlers, no cleanup — the leak shape under test.
    setup.target.child.kill().unwrap();
    setup.target.child.wait().unwrap();
    let mut gone = false;
    for _ in 0..500 {
        if !process_alive(sharer) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        gone,
        "held sharer {sharer} leaked after its parent died before W"
    );
}

/// P2-2: a CLONE_VM non-thread sharer that predates the attach carries no
/// SHARED_MM mark (marking happens on forks observed after attachment);
/// its watched mutations still globalize — the mm has users beyond the
/// thread group — but the target's mapping and own epoch are unchanged,
/// so this process's incarnation continues.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_pre_attachment_sharer_globalizes() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    // The sharer predates the attach: held here, mutating after.
    let held = target.command(b'w')?;
    ensure!(held.starts_with("SHARER_HELD"), "{held}");
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let call = |harness: &mut Harness, target: &mut Target| -> Result<InstanceId> {
        target.command(b'c')?;
        single_join(&pump_until(harness, target, 1)?)
    };
    let a = call(&mut harness, &mut target)?;
    let before = harness.session.instance_maps().counters()?;
    let woke = target.command(b'W')?;
    ensure!(woke == "SHARER_WOKE", "{woke}");
    let after = harness.session.instance_maps().counters()?;
    ensure!(
        after.shared >= before.shared + 2
            && after.global_bumps >= before.global_bumps + 2
            && after.local_bumps == before.local_bumps,
        "pre-attachment sharer was not globalized: {before:?} -> {after:?}"
    );
    let b = call(&mut harness, &mut target)?;
    ensure!(
        b == a,
        "a pre-attachment sharer's mutation did not continue the instance"
    );
    eprintln!("T3A_PRESHARER counters={after:?} scans={:?}", harness.scan);
    ensure!(harness.false_joins().is_empty());
    ensure!(after.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// F3 soundness: a zombie group leader still counted in `nr_threads` plus
/// one live external CLONE_VM sharer — mm_users 2 against nr_threads 2
/// under the old equality — still globalizes, since the zombie holds
/// no mm reference, but the target's mapping and own epoch are unchanged,
/// so its incarnation continues. The window predates the attach (no fork
/// marks); the fixture self-validates it (leader State Z, Threads 2,
/// sharer alive) and fails loudly when it is not live.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_zombie_leader_sharer_globalizes() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    // The zombie window plus the sharer predate the attach.
    let held = target.command(b'z')?;
    ensure!(held.starts_with("ZOMBIE_HELD"), "{held}");
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let call = |harness: &mut Harness, target: &mut Target| -> Result<InstanceId> {
        target.command(b'c')?;
        single_join(&pump_until(harness, target, 1)?)
    };
    let a = call(&mut harness, &mut target)?;
    let before = harness.session.instance_maps().counters()?;
    let woke = target.command(b'Z')?;
    ensure!(woke == "ZOMBIE_WOKE", "{woke}");
    let after = harness.session.instance_maps().counters()?;
    ensure!(
        after.shared >= before.shared + 2
            && after.global_bumps >= before.global_bumps + 2
            && after.local_bumps == before.local_bumps
            && after.storage_null == before.storage_null,
        "zombie-leader sharer was not globalized: {before:?} -> {after:?}"
    );
    let b = call(&mut harness, &mut target)?;
    ensure!(
        b == a,
        "a zombie-leader sharer's mutation did not continue the instance"
    );
    eprintln!("T3A_ZOMBIE counters={after:?} scans={:?}", harness.scan);
    ensure!(harness.false_joins().is_empty());
    ensure!(after.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c: a punch-hole on the provider file from another process,
/// settled as correct fail-closed behavior (R-39). The hole
/// changes the file on disk, so the watched provider's `(ino, size,
/// ctime)` identity pin no longer proves the instance it calibrated:
/// `LiveImageScan::audit` refuses every later scan with Custody, and
/// the post-hole call stays unjoined (`Unknown`, never a join to the
/// old instance or a new one) instead of attributing calls to an
/// instance that can no longer be proven. The loaded image keeps
/// executing from untouched text while the header page's VMAs are
/// zapped through `unmap_mapping_range`, which must still reach the
/// munmap hook — a miss there stays a hook-completeness finding, not
/// a soft control. Static skip: needs punch-hole support under TMPDIR
/// (btrfs/ext4/xfs; tmpfs refuses); run by hand as root with a suitable
/// TMPDIR.
#[test]
#[ignore = "privileged: loads BPF; needs punch-hole-capable TMPDIR, run by hand"]
fn privileged_instance_cross_process_punch_hole_renews() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let object = plan.slots[0].object;
    let call = |harness: &mut Harness, target: &mut Target, which: &str| -> Result<InstanceId> {
        target
            .command(b'c')
            .with_context(|| format!("punch-hole call {which}: fixture did not answer"))?;
        let routed = pump_until(&mut *harness, target, 1)?;
        single_join(&routed).with_context(|| {
            let counters = harness.session.instance_maps().counters();
            format!(
                "punch-hole call {which} did not join \
                 (routed={routed:?} counters={counters:?} scans={:?})",
                harness.scan
            )
        })
    };
    let epochs_of = |harness: &Harness, target: &Target| -> Result<(u64, u64, u64, u64, u64)> {
        let reading = harness.session.instance_maps().complete_epochs(
            target.pin.pidfd().map_err(anyhow::Error::msg)?,
            harness.file_slot,
        )?;
        Ok((
            reading.local,
            reading.global,
            reading.fault,
            reading.sticky,
            reading.record_flags,
        ))
    };
    // The cause proof: the watched provider's fail-closed state plus
    // the file's own (ctime, length). Read-only while unchanged.
    let watched_state = |harness: &Harness| -> Result<(bool, (i64, i64, u64))> {
        let tracking = harness.session.instance_tracking();
        let watched = tracking.watched(object).with_context(|| {
            format!(
                "not watched after attach: {:?}",
                tracking.watch_refusal(object)
            )
        })?;
        let unchanged = watched.check_unchanged().map_err(anyhow::Error::msg)?;
        let metadata = std::fs::metadata(&provider)?;
        let stamp = (
            std::os::unix::fs::MetadataExt::ctime(&metadata),
            std::os::unix::fs::MetadataExt::ctime_nsec(&metadata),
            metadata.len(),
        );
        Ok((unchanged, stamp))
    };
    let a = call(&mut harness, &mut target, "a (before the hole)")?;
    let (unchanged_before, stamp_before) = watched_state(&harness)?;
    ensure!(
        unchanged_before,
        "watched provider already reports changed before the hole (stamp {stamp_before:?})"
    );
    let before = harness.session.instance_maps().counters()?;
    let epochs_before = epochs_of(&harness, &target)?;
    let scans_before = harness.scan.outcomes.clone();
    let holed = target.command(b'h')?;
    ensure!(holed == "PHOLE", "{holed}");
    let (unchanged_after, stamp_after) = watched_state(&harness)?;
    ensure!(
        stamp_after != stamp_before,
        "punch-hole left the provider file unchanged on disk: {stamp_before:?} vs {stamp_after:?}"
    );
    ensure!(
        !unchanged_after,
        "watched provider still reports unchanged after the hole \
         (stamp {stamp_before:?} -> {stamp_after:?})"
    );
    let after_hole = harness.session.instance_maps().counters()?;
    let epochs_after = epochs_of(&harness, &target)?;
    let hole_bumps = after_hole.local_bumps - before.local_bumps;
    eprintln!(
        "T3A_PHOLE_DIAG counters_before={before:?} counters_after={after_hole:?} \
         target_local={}->{} target_global={}->{} fault={}->{} sticky={}->{} flags={}->{} \
         unchanged={unchanged_before}->{unchanged_after} stamp={stamp_before:?}->{stamp_after:?} \
         scans={:?}",
        epochs_before.0,
        epochs_after.0,
        epochs_before.1,
        epochs_after.1,
        epochs_before.2,
        epochs_after.2,
        epochs_before.3,
        epochs_after.3,
        epochs_before.4,
        epochs_after.4,
        harness.scan
    );
    ensure!(
        hole_bumps >= 1,
        "punch-hole did not reach uprobe_munmap (hook gap?)"
    );
    // Call b is collected but never joined: the changed provider
    // refuses every scan, so the call expires unjoined instead of
    // attributing to an unprovable instance. Bounded: the unjoined
    // outcome must arrive promptly, not after an unbounded wait.
    target
        .command(b'c')
        .with_context(|| "punch-hole call b (after the hole): fixture did not answer")?;
    let routed = pump_until_routed(&mut harness, &target, 1, Duration::from_secs(10))?;
    ensure!(
        routed.len() == 1,
        "punch-hole call b: expected one routed outcome, got {routed:?}"
    );
    ensure!(
        matches!(routed[0].route, Route::Unknown(_)),
        "punch-hole call b joined after the provider changed (fail-open): \
         {:?} (a={a:?} scans={:?})",
        routed[0].route,
        harness.scan
    );
    // Every scan after the hole refused Custody (at least one ran),
    // and no New/Continued observation was sealed after the hole:
    // every other ledger entry is frozen at its pre-hole count.
    let custody_before = scans_before.get("Custody").copied().unwrap_or(0);
    let custody_after = harness.scan.outcomes.get("Custody").copied().unwrap_or(0);
    ensure!(
        custody_after > custody_before,
        "no Custody scan refusal after the hole: {scans_before:?} -> {:?}",
        harness.scan.outcomes
    );
    for (outcome, after) in &harness.scan.outcomes {
        if outcome == "Custody" {
            continue;
        }
        let before_count = scans_before.get(outcome).copied().unwrap_or(0);
        ensure!(
            *after == before_count,
            "post-hole scan ledger entry {outcome:?} moved {before_count}->{after}; \
             only Custody refusals are allowed after a provider change"
        );
    }
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_PHOLE hole_bumps={hole_bumps} counters={counters:?} \
         target_local={}->{} target_global={}->{} custody={custody_before}->{custody_after} \
         b_route={:?} scans={:?}",
        epochs_before.0,
        epochs_after.0,
        epochs_before.1,
        epochs_after.1,
        routed[0].route,
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c: exec renews the instance. The leader's record survives
/// (same task), but the post-exec provider reload bumps past every
/// pre-exec epoch, so post-exec calls join a new instance, never the old.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_exec_renews_the_instance() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, pid, &pins)?;
    target.command(b'c')?;
    let a = single_join(&pump_until(&mut harness, &target, 1)?)?;
    let ready = target.command(b'e')?;
    let fields: Vec<_> = ready.split_whitespace().collect();
    ensure!(
        fields.len() >= 2 && fields[0] == "READY" && fields[1] == pid.to_string(),
        "not the same process after exec: {ready}"
    );
    target.command(b'c')?;
    let b = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(b != a, "exec kept the instance");
    let counters = harness.session.instance_maps().counters()?;
    eprintln!("T3A_EXEC counters={counters:?} scans={:?}", harness.scan);
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Reads one byte of the target's memory (own child, as root).
fn probe_byte(pid: u32, address: u64) -> Result<(isize, u8)> {
    let mut byte = [0u8; 1];
    let local = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: two live one-byte iovecs.
    let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    Ok((n, byte[0]))
}

/// Decision §3c: a non-leader thread execs. BOUND-documented outcome: the
/// old leader dies, which silently detaches the classic (Singles) uprobe
/// attachments — the new image's endpoint carries the original text byte,
/// not `int3`, so post-exec calls execute untraced. No events means zero
/// false joins (fail closed and visible); reattach on leader death is a
/// product attach-layer gap (DR-T3A-6, Stage 5 non-leader-exec handoff),
/// not witness misrouting. The gate pins the bound: no post-exec events
/// with the detached-breakpoint mechanism shown, and no scan either (no
/// traced call ever identifies the new leader, so it has no cookie).
/// Nothing is routable, and nothing routes.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_nonleader_exec_detaches_without_misrouting() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, pid, &pins)?;
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let events_before = harness.events;
    let ready = target.command(b'E')?;
    let fields: Vec<_> = ready.split_whitespace().collect();
    ensure!(
        fields.len() >= 3 && fields[0] == "READY" && fields[1] == pid.to_string(),
        "not the same process after nonleader exec: {ready}"
    );
    target.command(b'c')?;
    for _ in 0..20 {
        harness.pump(&target)?;
        std::thread::sleep(Duration::from_millis(50));
    }
    ensure!(
        harness.events == events_before,
        "post-exec calls unexpectedly traced"
    );
    // The mechanism: no breakpoint in the new mapping (original text byte,
    // not int3). If a backend fix reattaches here, this fails and the gate
    // must be upgraded to expect routing.
    let base = u64::from_str_radix(fields[2], 16)?;
    let offset = *harness.offsets.get(&0).context("slot 0 offset")?;
    let (n, byte) = probe_byte(pid, base + offset)?;
    ensure!(n == 1, "could not read the endpoint byte");
    ensure!(
        byte != 0xcc,
        "breakpoint present after nonleader exec: reattach landed, upgrade this gate"
    );
    // No scan either: without a traced call the new leader has no cookie,
    // so the scan protocol refuses (rather than scanning an unidentified
    // process).
    let outcome = harness.scan(&target, false)?;
    ensure!(
        outcome.is_none(),
        "post-exec scan unexpectedly worked: {outcome:?}"
    );
    ensure!(
        harness.scan.outcomes.contains_key("Unknown"),
        "post-exec full-image query must remain Unknown: {:?}",
        harness.scan.outcomes
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_NONLEADER_EXEC_DETACHED byte={byte:02x} counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c: fork without exec. Whether `dup_mmap` reaches the hooks
/// is kernel behavior; the gate pins consistency (a new instance exactly
/// when the fork bumped) and zero false joins either way.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_fork_without_exec_stays_consistent() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    target.command(b'c')?;
    let a = single_join(&pump_until(&mut harness, &target, 1)?)?;
    let before = harness.session.instance_maps().counters()?;
    let forked = target.command(b'f')?;
    ensure!(forked == "FORKED", "{forked}");
    let after = harness.session.instance_maps().counters()?;
    let bumps =
        (after.local_bumps - before.local_bumps) + (after.global_bumps - before.global_bumps);
    target.command(b'c')?;
    let b = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        (bumps == 0) == (b == a),
        "fork outcome inconsistent with its {bumps} bumps"
    );
    eprintln!(
        "T3A_FORK bumps={bumps} counters={after:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(after.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Birth marker: an exec before closure publishes nothing; the first exec
/// after the mint publishes READY with the minted generation and one
/// admission, and the next call carries the same exec ID.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_exec_after_closure_publishes_ready() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, pid, &pins)?;
    ensure!(
        harness.session.instance_maps().attach_cell()? == 0,
        "a fresh session must not have minted a closure"
    );
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let before = harness.take_images();
    ensure!(before.len() == 1, "one call, one image");
    // Pre-closure twin: an exec with no minted generation publishes
    // nothing and spends nothing.
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let pre = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&pre) == 0,
        "a pre-closure exec must leave word 0 or no row: {}",
        marker_summary(&pre)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 0 && control.failed == 0,
        "a pre-closure exec must spend nothing: {control:?}"
    );
    // Closure, then the exec under test.
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    ensure!(
        harness.session.instance_maps().attach_cell()? == minted,
        "the mint must land in the attach cell"
    );
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "a post-closure exec")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "READY must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "one exec, one admission: {control:?}"
    );
    // The first call after the exec carries the published exec ID.
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let images = harness.take_images();
    ensure!(images.len() == 1, "one call, one image");
    ensure!(
        images[0].exec_id == exec,
        "the post-exec call must carry the published exec id: call {} marker {exec}",
        images[0].exec_id
    );
    ensure!(
        exec > before[0].exec_id,
        "the exec must advance the exec id: {exec} <= {}",
        before[0].exec_id
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_EXEC exec={exec} minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Birth marker: a non-leader exec gives the fresh leader its own READY
/// row with one admission and no latch. Post-exec calls stay untraced
/// (the neighbor detachment gate pins that bound), so this cell reads the
/// row, never events.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_nonleader_exec_creates_fresh_ready_row() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let harness = Harness::start(&plan, pid, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 0 && control.failed == 0,
        "the mint spends nothing: {control:?}"
    );
    let ready = target.command(b'E')?;
    let fields: Vec<_> = ready.split_whitespace().collect();
    ensure!(
        fields.len() >= 2 && fields[0] == "READY" && fields[1] == pid.to_string(),
        "not the same process after nonleader exec: {ready}"
    );
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "the fresh leader")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "the fresh row must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "one fresh leader, one admission: {control:?}"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_NONLEADER_EXEC exec={exec} minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Birth marker DIRTY-first twin under Scope::Cgroup: after an exec, a
/// cgroup gap, and re-entry, a non-leader exec gives the fresh leader its
/// own READY row with a second admission. The old leader's task_struct,
/// and its DIRTY row, is discarded; in effect the process recovers by
/// re-execing from a thread. Reads the row after the exec, never events.
/// The private cgroup is removed at the end.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_dirty_nonleader_exec_publishes_fresh_ready() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let home = current_cgroup(pid)?;
    let group = MarkerCgroup::create("dirty-exec")?;
    group.move_in(pid)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_cgroup(&plan, &scope, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let row = proc_record_of(&harness, &target)?;
    let old = ready_exec_of(&row, "the in-scope exec")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "READY must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    // One call outside the cgroup dirties without charging: the row is READY.
    move_process_to(pid, &home)?;
    target.command(b'c')?;
    let dirtied = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&dirtied) == journal_marker::MARKER_DIRTY,
        "an out-of-cgroup call must dirty: {}",
        marker_summary(&dirtied)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "dirtying READY charges nothing: {control:?}"
    );
    // Back inside: a call still joins (S1 continues) and keeps DIRTY.
    group.move_in(pid)?;
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let reentered = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&reentered) == journal_marker::MARKER_DIRTY,
        "re-entry must not clear DIRTY: {}",
        marker_summary(&reentered)
    );
    // The non-leader exec under test: a fresh READY row, one more admission.
    let ready = target.command(b'E')?;
    let fields: Vec<_> = ready.split_whitespace().collect();
    ensure!(
        fields.len() >= 2 && fields[0] == "READY" && fields[1] == pid.to_string(),
        "not the same process after nonleader exec: {ready}"
    );
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "the fresh leader")?;
    ensure!(
        exec != old,
        "the fresh row must name a new exec: {exec} == {old}"
    );
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "the fresh row must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 2 && control.failed == 0,
        "two admissions, one per leader: {control:?}"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_DIRTY_NONLEADER_EXEC old={old} exec={exec} minted={minted} \
         control={control:?} counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    // Teardown before rmdir: the retired session must not hold the cgroup.
    drop(harness);
    move_process_to(pid, &home)?;
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

/// Birth marker: a fork without exec publishes nothing. The reaped child
/// keeps no row (task storage dies with the task), every marker write
/// charges first, and the parent's row is untouched.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_fork_without_exec_has_no_ready() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let harness = Harness::start(&plan, target.pid(), &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    ensure!(
        harness.session.instance_maps().attach_cell()? == minted,
        "the mint must land in the attach cell"
    );
    let parent_before = proc_record_of(&harness, &target)?;
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 0 && control.failed == 0,
        "the mint spends nothing: {control:?}"
    );
    let forked = target.command(b'f')?;
    ensure!(forked == "FORKED", "{forked}");
    let parent_after = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&parent_after) == marker_word_of(&parent_before)
            && parent_after.map(|row| row.exec_attach_gen)
                == parent_before.map(|row| row.exec_attach_gen),
        "a fork must not touch the parent row: {} -> {}",
        marker_summary(&parent_before),
        marker_summary(&parent_after)
    );
    ensure!(
        marker_word_of(&parent_after) == 0,
        "the parent must have no READY without an exec: {}",
        marker_summary(&parent_after)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 0 && control.failed == 0,
        "a fork must charge nothing: {control:?}"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_FORK control={control:?} counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Birth marker under Scope::Cgroup: an outsider that never enters the
/// private cgroup dirties its own absent row once no matter how often it
/// calls, and a later out-of-scope exec keeps DIRTY. The outsider is
/// spawned before attach, so it has no Stage A row: this is the only live
/// cell for the gap's reserve-then-create path, and it fails if that path
/// stops creating (no row), stops charging once (spent moves), or faults.
/// The in-scope twin joins clean. The private cgroup is removed at the end.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_cgroup_outsider_call_creates_dirty_row() -> Result<()> {
    let PairSetup {
        _directory,
        provider,
        mut inner,
        mut outer,
    } = spawn_pair_targets()?;
    let pid = inner.pid();
    let home = current_cgroup(pid)?;
    let group = MarkerCgroup::create("outsider")?;
    group.move_in(pid)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_cgroup(&plan, &scope, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    ensure!(
        harness.session.instance_maps().attach_cell()? == minted,
        "the mint must land in the attach cell"
    );
    ensure!(
        current_cgroup(outer.pid())? == home,
        "the outsider must never enter the private cgroup"
    );
    // Twin: the in-scope target joins, spending nothing and dirtying nothing.
    inner.command(b'c')?;
    single_join(&pump_until(&mut harness, &inner, 1)?)?;
    ensure!(
        marker_word_of(&proc_record_of(&harness, &inner)?) == 0,
        "in-scope calls never dirty"
    );
    ensure!(
        proc_record_of(&harness, &outer)?.is_none(),
        "the outsider must start rowless so the first call drives reserve-then-create"
    );
    // Two out-of-scope calls on the absent row: one DIRTY, one admission.
    outer.command(b'c')?;
    outer.command(b'c')?;
    let dirtied = proc_record_of(&harness, &outer)?;
    ensure!(
        marker_word_of(&dirtied) == journal_marker::MARKER_DIRTY,
        "out-of-scope calls must dirty the outsider row: {}",
        marker_summary(&dirtied)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "two calls, one admission: {control:?}"
    );
    // A later out-of-scope exec by the same leader keeps DIRTY and spends
    // nothing: it never reaches the birth path.
    let ready = outer.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let kept = proc_record_of(&harness, &outer)?;
    ensure!(
        marker_word_of(&kept) == journal_marker::MARKER_DIRTY,
        "an out-of-scope exec must not clear DIRTY: {}",
        marker_summary(&kept)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "a DIRTY exec spends nothing: {control:?}"
    );
    // The in-scope target still joins with a clean row.
    inner.command(b'c')?;
    single_join(&pump_until(&mut harness, &inner, 1)?)?;
    ensure!(
        marker_word_of(&proc_record_of(&harness, &inner)?) == 0,
        "in-scope calls never dirty"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_CGROUP_OUTSIDER minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    // Teardown before rmdir: the retired session must not hold the cgroup.
    drop(harness);
    move_process_to(pid, &home)?;
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

/// Birth marker under Scope::Pid: an outsider sibling is never observed,
/// so it has no row, spends nothing and routes no call. Perf links bind to
/// the target and the kernel pid filter drops the rest, on every backend;
/// no outsider call ever reaches BPF. The in-scope target joins clean.
/// (No vfork child runs here, so the CLONE_VM-sharer exception is out of
/// scope for this cell.)
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_pid_outsider_stays_unobserved() -> Result<()> {
    let PairSetup {
        _directory,
        provider,
        mut inner,
        mut outer,
    } = spawn_pair_targets()?;
    let (_view, pins, plan, _key) = pin_and_plan(inner.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, inner.pid(), &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    ensure!(
        harness.session.instance_maps().attach_cell()? == minted,
        "the mint must land in the attach cell"
    );
    // Twin: the in-scope target joins, spending nothing and dirtying nothing.
    inner.command(b'c')?;
    single_join(&pump_until(&mut harness, &inner, 1)?)?;
    ensure!(
        marker_word_of(&proc_record_of(&harness, &inner)?) == 0,
        "in-scope calls never dirty"
    );
    // Two outsider calls: no row, no admission, no routed call.
    outer.command(b'c')?;
    outer.command(b'c')?;
    let absent = proc_record_of(&harness, &outer)?;
    ensure!(
        absent.is_none(),
        "an unobserved outsider must have no row: {}",
        marker_summary(&absent)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 0 && control.failed == 0,
        "unobserved calls spend nothing: {control:?}"
    );
    let stray = pump_rounds(&mut harness, &inner, 10)?;
    ensure!(stray.is_empty(), "the outsider must route no call");
    // The in-scope target still joins with a clean row.
    inner.command(b'c')?;
    single_join(&pump_until(&mut harness, &inner, 1)?)?;
    ensure!(
        marker_word_of(&proc_record_of(&harness, &inner)?) == 0,
        "in-scope calls never dirty"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_PID_OUTSIDER minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Birth marker under Scope::Cgroup: READY after closure, then a move out
/// and one call stick DIRTY across the move back, another call, and a
/// later in-scope exec. The private cgroup is removed at the end.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_cgroup_gap_sticks_across_reentry_and_exec() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let home = current_cgroup(pid)?;
    let group = MarkerCgroup::create("gap")?;
    group.move_in(pid)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_cgroup(&plan, &scope, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "the in-scope exec")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "READY must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    // One call outside the cgroup dirties without charging: the row is READY.
    move_process_to(pid, &home)?;
    target.command(b'c')?;
    let dirtied = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&dirtied) == journal_marker::MARKER_DIRTY,
        "an out-of-cgroup call must dirty: {}",
        marker_summary(&dirtied)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "dirtying READY charges nothing: {control:?}"
    );
    // Back inside: a call still joins (S1 continues) and keeps DIRTY.
    group.move_in(pid)?;
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let reentered = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&reentered) == journal_marker::MARKER_DIRTY,
        "re-entry must not clear DIRTY: {}",
        marker_summary(&reentered)
    );
    // A later in-scope exec keeps DIRTY and spends nothing.
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let kept = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&kept) == journal_marker::MARKER_DIRTY,
        "an in-scope exec must not clear DIRTY: {}",
        marker_summary(&kept)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "sticky DIRTY spends nothing more: {control:?}"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_CGROUP_GAP exec={exec} minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    // Teardown before rmdir: the retired session must not hold the cgroup.
    drop(harness);
    move_process_to(pid, &home)?;
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

/// Birth marker return-side twin: one provider call held inside the
/// provider while the process leaves the cgroup dirties on return, with no
/// other call in between. The same held call released in scope leaves READY.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_return_outside_scope_dirties() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let home = current_cgroup(pid)?;
    let group = MarkerCgroup::create("return")?;
    group.move_in(pid)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_cgroup(&plan, &scope, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "the in-scope exec")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "READY must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    let published = journal_marker::ready_word(exec);
    // Healthy twin: hold and release inside the scope; the word never moves.
    let held = target.command(b'b')?;
    ensure!(held == "HELD", "{held}");
    ensure!(
        marker_word_of(&proc_record_of(&harness, &target)?) == published,
        "an in-scope entry must not mark"
    );
    let unheld = target.command(b'u')?;
    ensure!(unheld.starts_with("UNHELD"), "{unheld}");
    ensure!(
        marker_word_of(&proc_record_of(&harness, &target)?) == published,
        "an in-scope return must not mark"
    );
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    let images = harness.take_images();
    ensure!(
        images.len() == 1 && images[0].exec_id == exec,
        "the released call must carry the published exec id"
    );
    // The return under test: hold in scope, release outside it.
    let held = target.command(b'b')?;
    ensure!(held == "HELD", "{held}");
    move_process_to(pid, &home)?;
    let unheld = target.command(b'u')?;
    ensure!(unheld.starts_with("UNHELD"), "{unheld}");
    let marked = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&marked) == journal_marker::MARKER_DIRTY,
        "an out-of-scope return must dirty: {}",
        marker_summary(&marked)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "the return charged nothing: {control:?}"
    );
    // The discarded return emitted no call, and the ledger shows the held
    // call as the only one between the hold and the release: only the
    // return path can have marked it.
    let stray = pump_rounds(&mut harness, &target, 10)?;
    ensure!(
        stray.is_empty(),
        "the out-of-scope return must emit no call"
    );
    let ledger = &target.ledger;
    ensure!(
        ledger.len() >= 2
            && ledger[ledger.len() - 2] == "HELD"
            && ledger[ledger.len() - 1].starts_with("UNHELD"),
        "no other call ran between the hold and the release"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_RETURN_OUTSIDE_SCOPE exec={exec} minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    // Teardown before rmdir: the retired session must not hold the cgroup.
    drop(harness);
    move_process_to(pid, &home)?;
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

/// Birth marker abandoned-call twin: a provider call held inside the
/// provider while its thread is cancelled dirties at thread exit, with no
/// other call in between. The same held call released normally leaves
/// READY. The process keeps running throughout; the private cgroup is
/// removed at the end.
#[test]
#[ignore = "R52 deferred to 0.6.0: requires a marker-enabled BPF build"]
fn privileged_journal_marker_abandoned_call_at_thread_exit_dirties() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let pid = target.pid();
    let home = current_cgroup(pid)?;
    let group = MarkerCgroup::create("abandoned")?;
    group.move_in(pid)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let (_view, pins, plan, _key) = pin_and_plan(pid, &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start_cgroup(&plan, &scope, &pins)?;
    let minted = harness.session.instance_maps().mint_attach_generation()?;
    let ready = target.command(b'e')?;
    ensure!(ready.starts_with("READY"), "owned exec ledger: {ready}");
    let row = proc_record_of(&harness, &target)?;
    let exec = ready_exec_of(&row, "the in-scope exec")?;
    ensure!(
        row.map(|row| row.exec_attach_gen) == Some(minted),
        "READY must name the minted closure: {} minted {minted}",
        marker_summary(&row)
    );
    let published = journal_marker::ready_word(exec);
    // Healthy twin: hold and release in scope; the word never moves.
    let held = target.command(b'b')?;
    ensure!(held == "HELD", "{held}");
    let unheld = target.command(b'u')?;
    ensure!(unheld.starts_with("UNHELD"), "{unheld}");
    ensure!(
        marker_word_of(&proc_record_of(&harness, &target)?) == published,
        "a returned call must not mark"
    );
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    // The call under test: hold in scope, then cancel the holding thread.
    // The process keeps running; thread exit reclaims the live START.
    let held = target.command(b'b')?;
    ensure!(held == "HELD", "{held}");
    let cancelled = target.command(b'K')?;
    ensure!(cancelled.starts_with("CANCELLED"), "{cancelled}");
    let marked = proc_record_of(&harness, &target)?;
    ensure!(
        marker_word_of(&marked) == journal_marker::MARKER_DIRTY,
        "a call abandoned at thread exit must dirty: {}",
        marker_summary(&marked)
    );
    let control = admission_of(&harness)?;
    ensure!(
        control.spent == 1 && control.failed == 0,
        "the abandoned call charged nothing: {control:?}"
    );
    // The abandoned call emitted no completion, and the ledger shows the
    // held call as the only one between the hold and the cancel: only the
    // thread-exit path can have marked it.
    let stray = pump_rounds(&mut harness, &target, 10)?;
    ensure!(stray.is_empty(), "the abandoned call must emit no call");
    let ledger = &target.ledger;
    ensure!(
        ledger.len() >= 2
            && ledger[ledger.len() - 2] == "HELD"
            && ledger[ledger.len() - 1].starts_with("CANCELLED"),
        "no other call ran between the hold and the cancel"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "MARKER_ABANDONED_CALL exec={exec} minted={minted} control={control:?} \
         counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    // Teardown before rmdir: the retired session must not hold the cgroup.
    drop(harness);
    move_process_to(pid, &home)?;
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

/// Task 1d overhead gate: the mapping hooks attach for profile sessions
/// but stay down for metrics (aggregate-only) sessions, whose attach still
/// succeeds with every slot unmapped (`NO_FILE`: no stamp can ever route).
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_hooks_attach_for_profile_but_not_metrics() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let object = plan.slots[0].object;
    let metrics = Session::start(
        &plan,
        &Scope::Pid(target.pid()),
        &pins,
        CapturePolicy::AggregateOnly,
        None,
        None,
        None,
        BackendSelection::Singles,
    )?;
    ensure!(
        metrics.attach_failures().is_empty(),
        "metrics attach failures: {:?}",
        metrics.attach_failures()
    );
    let refused = metrics
        .instance_tracking()
        .refused()
        .context("a metrics session attached the instance hooks")?;
    ensure!(
        refused.contains("aggregate-only (metrics)"),
        "metrics refusal names the policy: {refused}"
    );
    ensure!(
        metrics.instance_tracking().watched(object).is_none(),
        "a metrics session watched a provider file"
    );
    drop(metrics);
    let profile = Session::start(
        &plan,
        &Scope::Pid(target.pid()),
        &pins,
        CapturePolicy::Allowlisted,
        None,
        None,
        None,
        BackendSelection::Singles,
    )?;
    ensure!(
        profile.attach_failures().is_empty(),
        "profile attach failures: {:?}",
        profile.attach_failures()
    );
    ensure!(
        profile.instance_tracking().refused().is_none(),
        "profile refused: {:?}",
        profile.instance_tracking().refused()
    );
    ensure!(
        profile.instance_tracking().watched(object).is_some(),
        "a profile session watched nothing"
    );
    Ok(())
}

/// Decision §3c fault injection: `OVERFLOW` at the 9th watched file in one
/// process. Nine provider files load before attach (unwatched, unclaimed);
/// post-attach reloads claim the eight record cells in order, and the
/// ninth file's reload overflows: its mutations go to its global epoch,
/// its calls stamp `OVERFLOW` and never join, and no other file's global
/// moves. The record flag is process-wide, so every later call from this
/// process is unknown — fail closed.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_overflow_at_ninth_file_is_unknown() -> Result<()> {
    let directory = tempfile::tempdir()?;
    // Nine distinct files (distinct inodes) with identical bytes.
    let first = compile(directory.path(), true)?;
    let mut copies = vec![first];
    for n in 1..9 {
        let copy = directory.path().join(format!("provider{n}.so"));
        std::fs::copy(&copies[0], &copy)?;
        copies.push(copy);
    }
    let driver = compile(directory.path(), false)?;
    let mut args: Vec<&std::ffi::OsStr> = vec!["ovf".as_ref()];
    args.extend(copies.iter().map(|path| path.as_os_str()));
    let mut target = Target::spawn(&driver, &args, &[])?;
    let ready = target.line(Duration::from_secs(10))?;
    ensure!(ready.starts_with("READY"), "{ready}");
    // Slot 0 is the scanned and called file (file 8); the rest follow.
    let mut ordered = vec![copies[8].clone()];
    ordered.extend(copies[..8].iter().cloned());
    let (_view, pins, plan) = pin_and_plan_multi(target.pid(), &ordered)?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let file_slots: Vec<u32> = plan
        .slots
        .iter()
        .map(|slot| {
            harness
                .session
                .instance_tracking()
                .watched(slot.object)
                .map(|watched| watched.file_slot)
                .with_context(|| format!("slot {} not watched", slot.index))
        })
        .collect::<Result<_>>()?;
    for n in 0..8u8 {
        let reopened = target.command(b'0' + n)?;
        ensure!(reopened == format!("REOPENED {n}"), "{reopened}");
    }
    let maps = harness.session.instance_maps();
    ensure!(
        maps.counters()?.overflow == 0,
        "eight files must fit the record"
    );
    let reopened = target.command(b'8')?;
    ensure!(reopened == "REOPENED 8", "{reopened}");
    let maps = harness.session.instance_maps();
    ensure!(
        maps.counters()?.overflow >= 1,
        "the ninth file did not overflow the record"
    );
    let pidfd = target.pin.pidfd()?;
    let record = maps
        .record(pidfd)?
        .context("the target must own a record after nine reloads")?;
    ensure!(
        record.flags & instance::RECORD_OVERFLOW != 0,
        "record flags {:x} lack OVERFLOW",
        record.flags
    );
    ensure!(
        maps.global(file_slots[0])? >= 1,
        "the ninth file's mutations must go global"
    );
    for (slot, file) in file_slots[1..].iter().enumerate() {
        ensure!(
            maps.global(*file)? == 0,
            "file {slot}'s mutations must stay local"
        );
    }
    target.command(b'c')?;
    let routed = pump_until(&mut harness, &target, 1)?;
    ensure!(
        routed
            == vec![Routed {
                slot: 0,
                tag: TAG_MAIN,
                route: Route::Unknown(UnknownReason::Overflow),
            }],
        "the ninth file's call must be Overflow-unknown: {routed:?}"
    );
    ensure!(
        harness.joined_ids().is_empty(),
        "nothing may join past OVERFLOW"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_OVERFLOW counters={counters:?} scans={:?}",
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// Decision §3c fault injection: the registration race — attach while a
/// second thread loops dlmopen/dlclose. The loop-iteration counts around
/// attach prove churn overlapped it; afterwards calls join one instance
/// with zero false joins.
#[test]
#[ignore = "privileged: loads BPF, attaches fentry hooks and uprobes"]
fn privileged_instance_attach_during_reload_loop_has_zero_false_joins() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let looping = target.command(b'L')?;
    ensure!(looping == "LOOPING", "{looping}");
    let before = loop_iterations(&target.command(b'n')?)?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    let during = loop_iterations(&target.command(b'n')?)?;
    ensure!(
        during > before,
        "no reload churn overlapped attach ({before} -> {during})"
    );
    let looped = target.command(b'l')?;
    ensure!(looped.starts_with("LOOPED"), "{looped}");
    for _ in 0..3 {
        target.command(b'c')?;
    }
    let routed = pump_until(&mut harness, &target, 3)?;
    single_join(&routed)?;
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_RACE churned_during_attach={} counters={counters:?} scans={:?}",
        during - before,
        harness.scan
    );
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// F5 LRU-eviction injection: under a small-state build (one-entry
/// `INSTANCE_START`) two hammer threads' overlapping in-flight calls evict
/// each other, so evicted calls surface `Unstamped` and never join — while
/// sequential calls still join. Static skip: needs a
/// `P11SCOPE_SMALL_STATE_MAPS=1` build; run by hand as root with that
/// variable set.
#[test]
#[ignore = "privileged: needs a small-state build, run by hand"]
fn privileged_instance_small_state_lru_eviction_never_joins() -> Result<()> {
    ensure!(
        std::env::var("P11SCOPE_SMALL_STATE_MAPS").as_deref() == Ok("1"),
        "run by hand under a small-state build: P11SCOPE_SMALL_STATE_MAPS=1 <libtest> --exact {} --ignored",
        "attach::instance_tests::privileged_instance_small_state_lru_eviction_never_joins",
    );
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    // A sequential baseline joins even at LRU=1 (no overlap, no eviction).
    target.command(b'c')?;
    single_join(&pump_until(&mut harness, &target, 1)?)?;
    target.send(b'H')?;
    let started = target.line(Duration::from_secs(20))?;
    ensure!(started == "HAMMERING", "{started}");
    // Pump while the hammers run; ring loss is tolerated (no ledger
    // equality here), but the drain must stay non-vacuous.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut hammered = None;
    while hammered.is_none() {
        harness.pump(&target)?;
        while let Ok(line) = target.lines.try_recv() {
            ensure!(!line.starts_with("FAIL"), "fixture failed: {line}");
            target.ledger.push(line.clone());
            if line.starts_with("HAMMERED") {
                hammered = Some(line);
            }
        }
        ensure!(Instant::now() < deadline, "timed out waiting for HAMMERED");
        std::thread::sleep(Duration::from_millis(5));
    }
    let hammered = hammered.expect("loop exits only on HAMMERED");
    ensure!(hammered == "HAMMERED 100000", "{hammered}");
    for _ in 0..20 {
        harness.pump(&target)?;
        std::thread::sleep(Duration::from_millis(5));
    }
    let unstamped = harness
        .routed
        .iter()
        .filter(|routed| routed.route == Route::Unknown(UnknownReason::Unstamped))
        .count();
    let joined = harness
        .routed
        .iter()
        .filter(|routed| matches!(routed.route, Route::Joined(_)))
        .count();
    let counters = harness.session.instance_maps().counters()?;
    eprintln!(
        "T3A_EVICT observed={} joined={joined} unstamped={unstamped} unknown={:?} counters={counters:?} scans={:?}",
        harness.events,
        harness.unknown_reasons(),
        harness.scan
    );
    ensure!(
        unstamped >= 1,
        "no eviction observed — is this a small-state build?"
    );
    ensure!(joined >= 1, "no positive routing at all");
    ensure!(harness.events >= 100, "drain went vacuous");
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}

/// F5 stale-key control on a live btrfs filesystem: the provider's
/// kernel-observed `s_dev`/`i_ino` (anonymous btrfs device numbers) flows
/// through calibration into hook keys and map_files-confirmed scans, and
/// same-address reload still separates. Static skip: needs TMPDIR on
/// btrfs; run by hand as root with a suitable TMPDIR.
#[test]
#[ignore = "privileged: needs TMPDIR on btrfs, run by hand"]
fn privileged_instance_routing_on_btrfs_tmpdir() -> Result<()> {
    let CmdSetup {
        _directory,
        provider,
        mut target,
    } = spawn_cmd_target()?;
    ensure!(
        dir_is_btrfs(_directory.path())?,
        "needs TMPDIR on btrfs, run by hand: TMPDIR=<btrfs dir> <binary> --exact {} --ignored",
        "attach::instance_tests::privileged_instance_routing_on_btrfs_tmpdir",
    );
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, &["C_GetSlotInfo"])?;
    let mut harness = Harness::start(&plan, target.pid(), &pins)?;
    target.command(b'c')?;
    let a = single_join(&pump_until(&mut harness, &target, 1)?)?;
    let reload = target.command(b'r')?;
    let fields: Vec<_> = reload.split_whitespace().collect();
    ensure!(
        fields.len() == 4 && fields[2] == fields[3],
        "not same-address: {reload}"
    );
    target.command(b'c')?;
    let b = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(
        b != a,
        "same-address reload on btrfs revived instance {a:?}"
    );
    let counters = harness.session.instance_maps().counters()?;
    eprintln!("T3A_BTRFS counters={counters:?} scans={:?}", harness.scan);
    ensure!(harness.false_joins().is_empty());
    ensure!(counters.faults == 0 && harness.misses == 0);
    ensure!(harness.session.instance_maps().sticky()? == 0);
    Ok(())
}
