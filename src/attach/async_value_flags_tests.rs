//! SPDX-License-Identifier: GPL-3.0-or-later
//! Privileged live gates for the async control value flags: an OK
//! `C_AsyncGetID` with a NULL output pointer must set
//! `ASYNC_VALUE_UNREADABLE`, while a GetID/Join with a readable id must
//! carry the id with no bit set. Root BPF lane, run serially through
//! `scripts/run-privileged-lib-tests.sh`. Every cell drives the owned
//! `tests/fixtures/async-32/` stub provider (real 3.2 signatures at
//! ordinals 99-101) through its line-oriented driver, attaches a real
//! `Session` to the driver PID, and asserts on the drained `CALL`
//! events. The unprivileged ledger test below pins the fixture's own
//! determinism without loading BPF; a second unprivileged test pins the
//! Join id-read-failure arm in BPF source, which no live call can trigger.

use super::*;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::{AttachPlan, Slot};
use crate::process::{PidPin, ProcessView, ProcessViewId};
use anyhow::ensure;
use p11scope_ebpf_common::{capture, event_type};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::io::{BufRead as _, BufReader, Write as _};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROVIDER_SOURCE: &str = include_str!("../../tests/fixtures/async-32/async-provider.c");
const DRIVER_SOURCE: &str = include_str!("../../tests/fixtures/async-32/async-driver.c");
const HEADER_SOURCE: &str = include_str!("../../tests/fixtures/async-32/async-32.h");

/// One owned driver process with a line-oriented ledger.
struct Target {
    child: Child,
    input: ChildStdin,
    lines: mpsc::Receiver<String>,
    pin: Arc<PidPin>,
    ledger: Vec<String>,
}

impl Target {
    fn spawn(program: &Path, args: &[&std::ffi::OsStr]) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
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
        self.ledger.push(line.clone());
        Ok(line)
    }

    fn command(&mut self, command: u8) -> Result<String> {
        self.input.write_all(&[command])?;
        self.input.flush()?;
        self.line(Duration::from_secs(20))
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

fn strict_cc(abi: ElfAbi) -> Command {
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
    if abi == ElfAbi::Ilp32 {
        cc.arg("-m32");
    }
    cc
}

/// Compile the provider and driver for `abi` into `directory`.
fn compile(directory: &Path, abi: ElfAbi) -> Result<(PathBuf, PathBuf)> {
    std::fs::write(directory.join("async-32.h"), HEADER_SOURCE)?;
    let provider_source = directory.join("async-provider.c");
    let driver_source = directory.join("async-driver.c");
    std::fs::write(&provider_source, PROVIDER_SOURCE)?;
    std::fs::write(&driver_source, DRIVER_SOURCE)?;
    let provider = directory.join("async-provider.so");
    let driver = directory.join("async-driver");
    let result = strict_cc(abi)
        .args(["-fPIC", "-shared", "-fvisibility=hidden"])
        .arg(&provider_source)
        .arg("-o")
        .arg(&provider)
        .output()?;
    ensure!(
        result.status.success(),
        "provider compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = strict_cc(abi)
        .arg(&driver_source)
        .arg("-o")
        .arg(&driver)
        .arg("-ldl")
        .output()?;
    ensure!(
        result.status.success(),
        "driver compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok((provider, driver))
}

/// Pins the provider as the target maps it and plans one slot per function.
fn pin_and_plan(
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
        module_hint: None,
        mapped_identity: None,
        double_loaded: false,
        same_file_loads: 1,
        pre_copy_up: None,
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key,
        path: provider.display().to_string(),
        tables_scan_finished: false,
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
    Ok((view, pins, AttachPlan::from_slots(slots), key))
}

/// Drain until `want` CALL events arrive or the deadline passes.
fn drain_calls(
    session: &mut Session,
    want: usize,
    timeout: Duration,
) -> Result<Vec<p11scope_ebpf_common::Event>> {
    let deadline = Instant::now() + timeout;
    let mut calls = Vec::new();
    loop {
        {
            let drain = session.event_drain()?;
            drain.poll(Some(1 << 20), |event| {
                if event.event_type == event_type::CALL {
                    calls.push(event);
                }
                ControlFlow::Continue(())
            });
            ensure!(drain.malformed() == 0, "malformed owned call record");
        }
        if calls.len() >= want {
            return Ok(calls);
        }
        ensure!(
            Instant::now() < deadline,
            "owned async call records timed out after {} of {want}",
            calls.len()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn sign_target() -> u32 {
    crate::kinds::function_id("C_Sign").expect("catalog holds C_Sign")
}

/// Read the semantic-capture-failure evidence cell (index 5), following
/// the `object_call_evidence` precedent in `instance_tests`.
fn semantic_capture_failures(session: &Session) -> Result<u64> {
    use p11scope_ebpf_common::EVIDENCE_SEMANTIC_CAPTURE_FAILURES;
    let map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE")?)?;
    Ok(map
        .get(&EVIDENCE_SEMANTIC_CAPTURE_FAILURES, 0)?
        .iter()
        .copied()
        .sum())
}

/// Compile, spawn, attach `functions`, and run `script` (after READY),
/// returning the ledger lines, the drained CALL events, and the
/// semantic-capture-failure evidence delta across the script.
fn run_script(
    abi: ElfAbi,
    functions: &[&str],
    script: &[u8],
    want: usize,
) -> Result<(Vec<String>, Vec<p11scope_ebpf_common::Event>, u64)> {
    let directory = tempfile::tempdir()?;
    let (provider, driver) = compile(directory.path(), abi)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()])?;
    ensure!(
        target.line(Duration::from_secs(10))?.starts_with("READY "),
        "owned driver ready"
    );
    let (_view, pins, plan, _key) = pin_and_plan(target.pid(), &provider, functions, abi)?;
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
        session.attach_failures().is_empty(),
        "attach failures: {:?}",
        session.attach_failures()
    );
    ensure!(session.backend_fallback().is_none());
    for (index, _name) in functions.iter().enumerate() {
        ensure!(session.has_slot_link(index as u32), "slot {index} linked");
    }
    let evidence_before = semantic_capture_failures(&session)?;
    let mut ledger = Vec::new();
    for command in script {
        ledger.push(target.command(*command)?);
    }
    let calls = drain_calls(&mut session, want, Duration::from_secs(10))?;
    let evidence_after = semantic_capture_failures(&session)?;
    Ok((ledger, calls, evidence_after - evidence_before))
}

fn events_for(
    calls: &[p11scope_ebpf_common::Event],
    slot: u32,
) -> Vec<&p11scope_ebpf_common::Event> {
    calls.iter().filter(|event| event.slot == slot).collect()
}

#[test]
fn async32_fixture_ledger_runs_the_full_flow() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (provider, driver) = compile(directory.path(), ElfAbi::Lp64)?;
    let mut target = Target::spawn(&driver, &["cmd".as_ref(), provider.as_os_str()])?;
    ensure!(
        target.line(Duration::from_secs(10))?.starts_with("READY "),
        "owned driver ready"
    );
    for (command, expected) in [
        (b'i', "INIT 0"),
        (b'o', "SESSION 1 1 0"),
        (b'o', "SESSION 2 2 0"),
        (b't', "SIGNINIT 0"),
        (b'n', "SIGN 516"),
        (b'g', "GETID 0 1"),
        (b'G', "GETID_NULL 0"),
        (b'j', "JOIN 0"),
        (b'c', "COMPLETE 0"),
    ] {
        let line = target.command(command)?;
        ensure!(line == expected, "ledger {command}: {line}");
    }
    Ok(())
}

/// Structural pin for the Join id-read-failure arm: no live call can
/// trigger it (LP64 register reads are infallible and the ia32 stack
/// word is always mapped at probe entry), so this unprivileged test
/// pins the `else` arm in BPF source instead of a live RED cell.
#[test]
fn join_entry_marks_value_unreadable_when_id_read_fails() {
    const BPF_MAIN: &str = include_str!("../../crates/ebpf/src/main.rs");
    let join_anchor = "lifecycle::ASYNC_JOIN => {";
    let getid_anchor = "lifecycle::ASYNC_GET_ID => {";
    let join_start = BPF_MAIN
        .find(join_anchor)
        .expect("Join entry anchor in BPF main");
    let after_join = &BPF_MAIN[join_start + join_anchor.len()..];
    let getid_offset = after_join
        .find(getid_anchor)
        .expect("GetID entry anchor follows the Join block");
    let join_block = &after_join[..getid_offset];
    assert!(
        join_block.contains("} else {"),
        "Join entry keeps its id-read-failure else arm"
    );
    assert!(
        join_block.contains("start.capture |= capture::ASYNC_VALUE_UNREADABLE"),
        "Join entry else arm sets ASYNC_VALUE_UNREADABLE"
    );
}

#[test]
#[ignore = "privileged: OK C_AsyncGetID with NULL output sets ASYNC_VALUE_UNREADABLE"]
fn privileged_async_getid_null_output_sets_value_unreadable_lp64() -> Result<()> {
    let (ledger, calls, evidence) = run_script(ElfAbi::Lp64, &["C_AsyncGetID"], b"iotnG", 1)?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID_NULL 0"
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 1, "one owned GetID call: {}", calls.len());
    let event = &calls[0];
    ensure!(event.slot == 0, "GetID slot: {}", event.slot);
    ensure!(event.rv == 0, "GetID rv: {}", event.rv);
    ensure!(
        event.target_function == sign_target(),
        "GetID target: {}",
        event.target_function
    );
    ensure!(
        event.capture & capture::ASYNC_VALUE_UNREADABLE != 0,
        "OK GetID with NULL output must set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        event.capture
    );
    ensure!(event.async_value == 0, "no id without output");
    ensure!(
        evidence == 1,
        "OK GetID with NULL output must bump the semantic evidence counter exactly once: {evidence}"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: OK C_AsyncGetID with NULL output sets ASYNC_VALUE_UNREADABLE"]
fn privileged_async_getid_null_output_sets_value_unreadable_ia32() -> Result<()> {
    let (ledger, calls, evidence) = run_script(ElfAbi::Ilp32, &["C_AsyncGetID"], b"iotnG", 1)?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID_NULL 0"
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 1, "one owned GetID call: {}", calls.len());
    let event = &calls[0];
    ensure!(event.slot == 0, "GetID slot: {}", event.slot);
    ensure!(event.rv == 0, "GetID rv: {}", event.rv);
    ensure!(
        event.target_function == sign_target(),
        "GetID target: {}",
        event.target_function
    );
    ensure!(
        event.capture & capture::ASYNC_VALUE_UNREADABLE != 0,
        "OK GetID with NULL output must set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        event.capture
    );
    ensure!(event.async_value == 0, "no id without output");
    ensure!(
        evidence == 1,
        "OK GetID with NULL output must bump the semantic evidence counter exactly once: {evidence}"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: OK C_AsyncGetID with a valid output reads the id with no flag"]
fn privileged_async_getid_valid_output_reads_id_lp64() -> Result<()> {
    let (ledger, calls, evidence) = run_script(ElfAbi::Lp64, &["C_AsyncGetID"], b"iotng", 1)?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID 0 1"
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 1, "one owned GetID call: {}", calls.len());
    let event = &calls[0];
    ensure!(event.slot == 0, "GetID slot: {}", event.slot);
    ensure!(event.rv == 0, "GetID rv: {}", event.rv);
    ensure!(
        event.target_function == sign_target(),
        "GetID target: {}",
        event.target_function
    );
    ensure!(
        event.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "readable GetID id must not set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        event.capture
    );
    ensure!(event.async_value == 1, "GetID id: {}", event.async_value);
    ensure!(
        evidence == 0,
        "readable GetID id must not bump the semantic evidence counter: {evidence}"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: OK C_AsyncGetID with a valid output reads the id with no flag"]
fn privileged_async_getid_valid_output_reads_id_ia32() -> Result<()> {
    let (ledger, calls, evidence) = run_script(ElfAbi::Ilp32, &["C_AsyncGetID"], b"iotng", 1)?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID 0 1"
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 1, "one owned GetID call: {}", calls.len());
    let event = &calls[0];
    ensure!(event.slot == 0, "GetID slot: {}", event.slot);
    ensure!(event.rv == 0, "GetID rv: {}", event.rv);
    ensure!(
        event.target_function == sign_target(),
        "GetID target: {}",
        event.target_function
    );
    ensure!(
        event.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "readable GetID id must not set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        event.capture
    );
    ensure!(event.async_value == 1, "GetID id: {}", event.async_value);
    ensure!(
        evidence == 0,
        "readable GetID id must not bump the semantic evidence counter: {evidence}"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: C_AsyncJoin carries the detached id with no flag and the op completes"]
fn privileged_async_join_reads_id_and_completes_lp64() -> Result<()> {
    let (ledger, calls, evidence) = run_script(
        ElfAbi::Lp64,
        &["C_AsyncGetID", "C_AsyncJoin", "C_AsyncComplete"],
        b"iootngjc",
        3,
    )?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SESSION 2 2 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID 0 1",
                "JOIN 0",
                "COMPLETE 0",
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 3, "three owned calls: {}", calls.len());
    let getids = events_for(&calls, 0);
    let joins = events_for(&calls, 1);
    let completes = events_for(&calls, 2);
    ensure!(
        getids.len() == 1 && joins.len() == 1 && completes.len() == 1,
        "one call per slot"
    );
    let getid = getids[0];
    ensure!(getid.rv == 0, "GetID rv: {}", getid.rv);
    ensure!(
        getid.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "GetID capture: {:#x}",
        getid.capture
    );
    ensure!(getid.async_value == 1, "GetID id: {}", getid.async_value);
    ensure!(
        getid.target_function == sign_target(),
        "GetID target: {}",
        getid.target_function
    );
    let join = joins[0];
    ensure!(join.rv == 0, "Join rv: {}", join.rv);
    ensure!(
        join.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "readable Join id must not set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        join.capture
    );
    ensure!(
        join.async_value == getid.async_value,
        "Join id follows GetID: {}",
        join.async_value
    );
    ensure!(
        join.target_function == sign_target(),
        "Join target: {}",
        join.target_function
    );
    let complete = completes[0];
    ensure!(complete.rv == 0, "Complete rv: {}", complete.rv);
    ensure!(
        complete.target_function == sign_target(),
        "Complete target: {}",
        complete.target_function
    );
    ensure!(
        evidence == 0,
        "readable GetID/Join flow must not bump the semantic evidence counter: {evidence}"
    );
    Ok(())
}

#[test]
#[ignore = "privileged: C_AsyncJoin carries the detached id with no flag and the op completes"]
fn privileged_async_join_reads_id_and_completes_ia32() -> Result<()> {
    let (ledger, calls, evidence) = run_script(
        ElfAbi::Ilp32,
        &["C_AsyncGetID", "C_AsyncJoin", "C_AsyncComplete"],
        b"iootngjc",
        3,
    )?;
    ensure!(
        ledger
            == [
                "INIT 0",
                "SESSION 1 1 0",
                "SESSION 2 2 0",
                "SIGNINIT 0",
                "SIGN 516",
                "GETID 0 1",
                "JOIN 0",
                "COMPLETE 0",
            ],
        "owned ledger: {ledger:?}"
    );
    ensure!(calls.len() == 3, "three owned calls: {}", calls.len());
    let getids = events_for(&calls, 0);
    let joins = events_for(&calls, 1);
    let completes = events_for(&calls, 2);
    ensure!(
        getids.len() == 1 && joins.len() == 1 && completes.len() == 1,
        "one call per slot"
    );
    let getid = getids[0];
    ensure!(getid.rv == 0, "GetID rv: {}", getid.rv);
    ensure!(
        getid.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "GetID capture: {:#x}",
        getid.capture
    );
    ensure!(getid.async_value == 1, "GetID id: {}", getid.async_value);
    ensure!(
        getid.target_function == sign_target(),
        "GetID target: {}",
        getid.target_function
    );
    let join = joins[0];
    ensure!(join.rv == 0, "Join rv: {}", join.rv);
    ensure!(
        join.capture & capture::ASYNC_VALUE_UNREADABLE == 0,
        "readable Join id must not set ASYNC_VALUE_UNREADABLE: capture={:#x}",
        join.capture
    );
    ensure!(
        join.async_value == getid.async_value,
        "Join id follows GetID: {}",
        join.async_value
    );
    ensure!(
        join.target_function == sign_target(),
        "Join target: {}",
        join.target_function
    );
    let complete = completes[0];
    ensure!(complete.rv == 0, "Complete rv: {}", complete.rv);
    ensure!(
        complete.target_function == sign_target(),
        "Complete target: {}",
        complete.target_function
    );
    ensure!(
        evidence == 0,
        "readable GetID/Join flow must not bump the semantic evidence counter: {evidence}"
    );
    Ok(())
}
