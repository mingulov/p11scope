//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3 Stage A privileged gates: real fentry hooks, calibration, stamps
//! and routing against owned workloads with independent ledgers. Explicitly
//! selected ignored tests; they fail (never skip) on unavailable support.

use super::*;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::instances::{
    CallFacts, EntryIp, InstanceId, InstanceRouter, ObserveOutcome, Route, RouterLimits,
    stable_scan,
};
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::{AttachPlan, Slot};
use crate::process::{PidPin, ProcessView, ProcessViewId};
use anyhow::ensure;
use p11scope_ebpf_common::{EventRecord, SlotSemantics, event_type};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Write as _};
use std::ops::ControlFlow;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SOURCE: &str = include_str!("../../tests/fixtures/instance-continuity.c");
const SOFTHSM: &str = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
const TAG_MAIN: u64 = 0x7000_0000;
const TAG_SIBLING: u64 = 0x7100_0000;
const TAG_RACE: u64 = 0x7200_0000;

fn compile(directory: &Path, provider: bool) -> Result<PathBuf> {
    let source = directory.join("instance-continuity.c");
    std::fs::write(&source, SOURCE)?;
    let output = directory.join(if provider { "provider.so" } else { "driver" });
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
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
    pin: PidPin,
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
            Ok(pin) => pin,
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
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(anyhow::Error::msg)?;
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

#[derive(Clone, Copy, Debug)]
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
    router: InstanceRouter,
    file_slot: u32,
    maps_keys: Vec<ObjectKey>,
    identity: crate::discovery::instances::MappedFileIdentity,
    offsets: BTreeMap<u32, u64>,
    next_token: u64,
    awaiting: BTreeMap<u64, (u32, u64)>,
    routed: Vec<Routed>,
    misses: u64,
    scan: ScanStats,
    events: u64,
}

impl Harness {
    fn start(plan: &AttachPlan, pid: u32, pins: &PinnedObjects) -> Result<Self> {
        let session = Session::start(
            plan,
            &Scope::Pid(pid),
            pins,
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            BackendSelection::Singles,
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
        Ok(Self {
            session,
            router: InstanceRouter::new(RouterLimits::default()),
            file_slot: watched.file_slot,
            maps_keys: watched.maps_keys,
            identity: watched.identity,
            offsets,
            next_token: 0,
            awaiting: BTreeMap::new(),
            routed: Vec::new(),
            misses: 0,
            scan: ScanStats::default(),
            events: 0,
        })
    }

    fn record(&mut self, token: u64, route: Route) {
        if let Some((slot, tag)) = self.awaiting.remove(&token) {
            self.routed.push(Routed { slot, tag, route });
        }
    }

    /// One stable scan of (pid, provider), observed by the router.
    fn scan(&mut self, target: &Target, pending: bool) -> Result<Option<ObserveOutcome>> {
        let started = Instant::now();
        let observation = {
            let pidfd = target.pin.pidfd()?;
            let mut reader = LiveScan {
                maps: self.session.instance_maps(),
                pidfd,
                pid: target.pid(),
                file_slot: self.file_slot,
                maps_keys: &self.maps_keys,
                identity: self.identity,
            };
            stable_scan(&mut reader, self.file_slot, 8)
        };
        let elapsed = started.elapsed().as_nanos();
        self.scan.scans += 1;
        self.scan.pending_scans += u64::from(pending);
        self.scan.total_ns += elapsed;
        self.scan.max_ns = self.scan.max_ns.max(elapsed);
        let observation = match observation {
            Ok(observation) => observation,
            Err(refusal) => {
                self.scan.unstable += 1;
                *self
                    .scan
                    .outcomes
                    .entry(format!("{refusal:?}"))
                    .or_default() += 1;
                return Ok(None);
            }
        };
        let (outcome, resolved) = self.router.observe(observation);
        *self
            .scan
            .outcomes
            .entry(format!("{outcome:?}"))
            .or_default() += 1;
        for (token, route) in resolved {
            self.record(token, route);
        }
        Ok(Some(outcome))
    }

    /// Drains EVENTS, audits faults/misses, routes every call, and scans
    /// while any call waits for a stable observation.
    fn pump(&mut self, target: &Target) -> Result<usize> {
        let mut batch: Vec<EventRecord> = Vec::new();
        let drain = self.session.event_drain()?;
        let _ = drain.poll_records(Some(1 << 20), |record| {
            batch.push(record);
            ControlFlow::Continue(())
        });
        ensure!(drain.malformed() == 0, "malformed EVENTS records");
        while self.session.discovery_dequeue()?.is_some() {}
        // Batch audit before routing: hook-program misses raise the fault
        // generation, so no call stamped before them can join afterwards.
        let misses: u64 = self
            .session
            .instance_hook_stats()?
            .iter()
            .map(|(_, stats)| stats.recursion_misses)
            .sum();
        if misses != self.misses {
            self.misses = misses;
            self.session.instance_maps().raise_fault()?;
        }
        let maps = self.session.instance_maps();
        let (fault, sticky) = (maps.fault()?, maps.sticky()?);
        for (token, route) in self.router.audit(fault, sticky) {
            self.record(token, route);
        }
        let mut count = 0;
        for record in batch {
            let (event, continuity) = (record.event, record.continuity);
            if event.event_type != event_type::CALL {
                continue;
            }
            count += 1;
            self.events += 1;
            let token = self.next_token;
            self.next_token += 1;
            self.awaiting.insert(token, (event.slot, event.slot_id));
            let route = self.router.route(CallFacts {
                token,
                cookie: event.image.task_cookie,
                entry: continuity.entry_stamp,
                ret: continuity.return_stamp,
                ip: EntryIp::new(continuity.entry_ip),
                attached_offset: self.offsets.get(&event.slot).copied(),
            });
            if route != Route::Pending {
                self.record(token, route);
            }
        }
        for _ in 0..4 {
            if self.router.pending_len() == 0 {
                break;
            }
            self.scan(target, true)?;
        }
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
    // marked at fork, its mutations go to the file's global epoch, which
    // ends this process's incarnation too.
    let shared_before = harness.session.instance_maps().counters()?;
    target.command(b'v')?;
    let shared_after = harness.session.instance_maps().counters()?;
    ensure!(
        shared_after.shared >= shared_before.shared + 2
            && shared_after.global_bumps >= shared_before.global_bumps + 2,
        "CLONE_VM sharer was not globalized: {shared_before:?} -> {shared_after:?}"
    );
    target.command(b'c')?;
    let after_sharer = single_join(&pump_until(&mut harness, &target, 1)?)?;
    ensure!(after_sharer != d, "a sharer's mutation kept the instance");
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
        harness.router.instances_minted()
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
        harness.router.pending_len(),
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
        harness.routed.len() as u64 == harness.events && harness.router.pending_len() == 0,
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
        harness.router.instances_minted(),
        harness.router.ranges_retained(),
        harness.router.pending_len(),
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
