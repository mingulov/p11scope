//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned Detailed lifecycle gates and their unprivileged fixture protocols.
//! Explicitly selected ignored gates fail on unavailable kernel support.

mod exec_tests;

use super::*;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::process::{PidPin, ProcessView, ProcessViewId};
use anyhow::ensure;
use aya::maps::{MapData, PerCpuHashMap};
use aya::programs::ProgramError;
use aya_obj::generated::{bpf_cmd, bpf_link_info};
use p11scope_ebpf_common::{
    CallStart, EVIDENCE_CELLS, Event, ImageIdentity, RvKey, SlotStats, StartKey, event_type,
};
use p11scope_manifest::elf::ElfSnapshot;
use p11scope_manifest::identity::{mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use std::ops::ControlFlow;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    _directory: tempfile::TempDir,
    provider: PathBuf,
    driver: PathBuf,
    sibling: bool,
}

impl Fixture {
    fn build() -> Result<Self> {
        Self::build_variant(false)
    }

    fn build_sibling() -> Result<Self> {
        Self::build_variant(true)
    }

    fn build_variant(sibling: bool) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("thread-exit.c");
        std::fs::write(
            &source,
            include_str!("../../tests/fixtures/detailed-thread-exit.c"),
        )?;
        let provider = directory.path().join("provider.so");
        let driver = directory.path().join("driver");
        for is_provider in [true, false] {
            let mut compiler = Command::new("cc");
            compiler.args([
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-omit-frame-pointer",
            ]);
            if sibling {
                compiler.arg("-DDETAILED_SIBLING_EXIT");
            }
            if is_provider {
                compiler.args(["-fPIC", "-shared", "-DDETAILED_THREAD_EXIT_PROVIDER"]);
            }
            compiler.arg(&source);
            if !is_provider {
                compiler.arg("-ldl");
            }
            let output = compiler
                .arg("-o")
                .arg(if is_provider { &provider } else { &driver })
                .output()?;
            ensure!(
                output.status.success(),
                "owned fixture compilation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(Self {
            _directory: directory,
            provider,
            driver,
            sibling,
        })
    }

    fn spawn(&self) -> Result<Caller> {
        let child = Command::new(&self.driver)
            .arg(&self.provider)
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        // Acquire cleanup custody before any fallible pin/pipe/receipt operation.
        let mut custody = ChildCustody {
            child,
            pin: None,
            reaped: false,
        };
        let pin = PidPin::open(custody.child.id()).map_err(anyhow::Error::msg)?;
        pin.pidfd()
            .context("fixture requires the original leader pidfd")?;
        custody.pin = Some(pin);
        let input = custody.child.stdin.take().context("fixture input pipe")?;
        let output = custody.child.stdout.take().context("fixture output pipe")?;
        let birth = task_birth(custody.child.id(), custody.child.id())?;
        let mut caller = Caller {
            custody,
            input,
            output,
            birth,
            last_ns: 0,
            lines: 0,
            max_lines: if self.sibling { 7 } else { 6 },
        };
        let fields = caller.record("READY", 4)?;
        let metadata = std::fs::metadata(&self.provider)?;
        ensure!(
            fields
                == [
                    u64::from(caller.pid()),
                    u64::from(caller.pid()),
                    metadata.dev(),
                    metadata.ino()
                ]
        );
        eprintln!("LIFECYCLE_GENERATION leader={} birth={birth}", caller.pid());
        Ok(caller)
    }

    fn pin(&self, caller: &Caller) -> Result<(ProcessView, PinnedObjects, AttachPlan)> {
        let view = ProcessView::open(ProcessViewId(0), caller.pid()).map_err(anyhow::Error::msg)?;
        let file = open_object(&self.provider).map_err(anyhow::Error::msg)?;
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
            path: self.provider.display().to_string(),
            decoder_abi: None,
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        };
        let (pins, skipped) =
            pin_scanned_view_objects(&view, &[module], &mut CaptureWorkBudget::default())
                .map_err(anyhow::Error::msg)?;
        ensure!(
            skipped.is_empty(),
            "owned physical pin refused: {skipped:?}"
        );
        let pinned = pins.pinned().next().context("owned provider pin")?;
        ensure!(pinned.key == key);
        let offset = elf
            .defined_symbol("C_Initialize")
            .map_err(anyhow::Error::msg)?
            .context("owned provider function")?
            .file_offset;
        ensure!(elf.is_executable_offset(offset));
        eprintln!(
            "LIFECYCLE_PHYSICAL key={key:?} sha256={} offset={offset} path={}",
            pinned.sha256,
            self.provider.display()
        );
        let plan = AttachPlan::from_slots(vec![Slot {
            index: 0,
            descriptor_index: 0,
            object: pinned.id,
            object_path: self.provider.display().to_string(),
            file_offset: offset,
            names: vec!["C_Initialize".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }]);
        Ok((view, pins, plan))
    }
}

struct ChildCustody {
    child: Child,
    pin: Option<PidPin>,
    reaped: bool,
}

impl Drop for ChildCustody {
    fn drop(&mut self) {
        if !self.reaped {
            eprintln!("LIFECYCLE_RESCUE pid={}", self.child.id());
            let signalled = self
                .pin
                .as_ref()
                .is_some_and(|pin| pin.send_signal(libc::SIGKILL).is_ok());
            if !signalled {
                // The direct unreaped Child still prevents reuse of this PID.
                let _ = self.child.kill();
            }
            // Last-resort custody cleanup may block. The live runner must retain
            // its outer process/pidfd watchdog; this is never a bounded success.
            match self.child.wait() {
                Ok(status) => {
                    eprintln!("LIFECYCLE_RESCUED pid={} status={status}", self.child.id())
                }
                Err(error) => {
                    eprintln!("LIFECYCLE_UNSETTLED pid={} error={error}", self.child.id())
                }
            }
        }
    }
}

struct Caller {
    custody: ChildCustody,
    input: ChildStdin,
    output: ChildStdout,
    birth: u64,
    last_ns: u64,
    lines: usize,
    max_lines: usize,
}

#[derive(Clone, Copy)]
struct Worker {
    tid: u32,
    birth: u64,
}

fn task_birth(tgid: u32, tid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{tgid}/task/{tid}/stat"))?;
    let (prefix, tail) = stat.rsplit_once(')').context("owned stat framing")?;
    let (number, _) = prefix.split_once('(').context("owned stat PID")?;
    ensure!(number.trim().parse::<u32>()? == tid);
    tail.split_ascii_whitespace()
        .nth(19)
        .context("owned stat birth")?
        .parse()
        .map_err(Into::into)
}

impl Caller {
    fn pid(&self) -> u32 {
        self.custody.child.id()
    }
    fn pin(&self) -> &PidPin {
        self.custody.pin.as_ref().expect("retained original pin")
    }
    fn same_leader(&self) -> Result<()> {
        ensure!(self.pin().still_the_same());
        ensure!(!self.pin().original_exited().map_err(anyhow::Error::msg)?);
        ensure!(task_birth(self.pid(), self.pid())? == self.birth);
        Ok(())
    }
    fn send(&mut self, command: u8) -> Result<()> {
        self.input.write_all(&[command])?;
        self.input.flush()?;
        Ok(())
    }
    fn record(&mut self, phase: &str, fields: usize) -> Result<Vec<u64>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut bytes = Vec::with_capacity(128);
        loop {
            ensure!(bytes.len() < 256, "oversized fixture receipt");
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "fixture receipt deadline for {phase}");
            let mut fd = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll borrows one retained pipe, with an absolute caller deadline.
            let ready = unsafe {
                libc::poll(
                    &mut fd,
                    1,
                    remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
                )
            };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                continue;
            }
            let mut byte = [0];
            ensure!(
                self.output.read(&mut byte)? == 1,
                "fixture EOF before {phase}"
            );
            if byte[0] == b'\n' {
                break;
            }
            bytes.push(byte[0]);
        }
        let text = String::from_utf8(bytes)?;
        eprintln!("LIFECYCLE_FIXTURE {text}");
        self.lines += 1;
        ensure!(
            self.lines <= self.max_lines,
            "unexpected extra fixture receipt"
        );
        let mut parts = text.split_ascii_whitespace();
        ensure!(
            parts.next() == Some(phase),
            "expected fixture {phase}: {text}"
        );
        let mut numbers = parts
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            numbers.len() == fields + 1,
            "malformed fixture {phase}: {text}"
        );
        let time = numbers.pop().unwrap();
        ensure!(time > 0 && time >= self.last_ns, "regressing fixture clock");
        self.last_ns = time;
        Ok(numbers)
    }
    fn start_worker(&mut self) -> Result<Worker> {
        self.same_leader()?;
        self.send(b'G')?;
        let started = self.record("THREAD", 3)?;
        let tid = u32::try_from(started[1])?;
        ensure!(tid != 0 && tid != self.pid());
        ensure!(started == [u64::from(self.pid()), u64::from(tid), u64::from(tid)]);
        let worker = Worker {
            tid,
            birth: task_birth(self.pid(), tid)?,
        };
        eprintln!("LIFECYCLE_GENERATION worker={tid} birth={}", worker.birth);
        ensure!(
            self.record("WORKER_DONE", 5)? == [u64::from(self.pid()), u64::from(tid), 11, 6, 5]
        );
        ensure!(self.record("BODY", 2)? == [u64::from(self.pid()), u64::from(tid)]);
        Ok(worker)
    }
    fn assert_worker_body_held(&self, worker: Worker) -> Result<()> {
        self.same_leader()?;
        ensure!(task_birth(self.pid(), worker.tid)? == worker.birth);
        let mut fd = libc::pollfd {
            fd: self.output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // No delay: the body must not report an exit before its command.
        ensure!(
            unsafe { libc::poll(&mut fd, 1, 0) } == 0,
            "worker escaped its body barrier"
        );
        Ok(())
    }
    fn await_sibling_bodies(&mut self, worker: Worker) -> Result<()> {
        ensure!(self.record("LEADER_BODY", 2)? == [u64::from(self.pid()), u64::from(self.pid())]);
        self.assert_worker_body_held(worker)
    }
    fn assert_leader_body_held(&self) -> Result<()> {
        self.same_leader()?;
        let mut fd = libc::pollfd {
            fd: self.output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // No delay or duration inference: the explicit L command is withheld.
        ensure!(
            unsafe { libc::poll(&mut fd, 1, 0) } == 0,
            "leader completed before its explicit return release"
        );
        Ok(())
    }
    fn release_worker(&mut self, worker: Worker) -> Result<()> {
        self.send(b'X')?;
        ensure!(self.record("EXITED", 3)? == [u64::from(self.pid()), u64::from(worker.tid), 0]);
        // Primary evidence is the kernel-cleared child_tid/futex handshake.
        // Also wait for this owned thread's proc entry to retire; no thread is
        // created again in this group, and absence alone is not the exit proof.
        let deadline = Instant::now() + Duration::from_secs(3);
        let path = PathBuf::from(format!("/proc/{}/task/{}", self.pid(), worker.tid));
        while path.try_exists()? {
            ensure!(
                Instant::now() < deadline,
                "owned worker proc retirement deadline"
            );
            std::thread::yield_now();
        }
        self.same_leader()
    }
    fn continue_leader(&mut self) -> Result<()> {
        self.same_leader()?;
        self.send(b'L')?;
        ensure!(
            self.record("LEADER_DONE", 5)?
                == [u64::from(self.pid()), u64::from(self.pid()), 17, 9, 8]
        );
        self.same_leader()
    }
    fn finish(&mut self) -> Result<()> {
        self.send(b'F')?;
        ensure!(
            self.pin().wait_ready(Some(Duration::from_secs(3)))?,
            "leader exit deadline"
        );
        let status = self.custody.child.wait()?;
        self.custody.reaped = true;
        ensure!(status.success(), "fixture failed: {status}");
        ensure!(self.pin().original_exited().map_err(anyhow::Error::msg)?);
        eprintln!("LIFECYCLE_REAPED pid={} birth={}", self.pid(), self.birth);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Expected {
    entered: u64,
    returned: u64,
    errors: u64,
    starts: usize,
    outstanding: u64,
    abandoned: u64,
    rv_zero: u64,
    rv_five: u64,
}

fn assert_maps(
    session: &Session,
    phase: &str,
    expected: Expected,
) -> Result<Vec<(StartKey, CallStart)>> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    let mut totals = SlotStats::ZERO;
    for cpu in stats.get(&0, 0)?.iter() {
        totals.entered += cpu.entered;
        totals.returned += cpu.returned;
        totals.errors += cpu.errors;
    }
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("START")?)?;
    let rows = starts.iter().collect::<std::result::Result<Vec<_>, _>>()?;
    let owner: Array<_, ThreadOwnerControl> =
        Array::try_from(session.ebpf.map("OWNER_CTL").context("OWNER_CTL")?)?;
    let control = owner.get(&0, 0)?;
    let rv_map: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let mut rvs = BTreeMap::new();
    for entry in rv_map.iter() {
        let (key, counts) = entry?;
        ensure!(key.slot == 0 && key._pad == 0);
        ensure!(rvs.insert(key.rv, counts.iter().sum::<u64>()).is_none());
    }
    eprintln!(
        "LIFECYCLE_MAPS phase={phase} entered={} returned={} errors={} starts={} owner={control:?} rvs={rvs:?}",
        totals.entered,
        totals.returned,
        totals.errors,
        rows.len()
    );
    ensure!(
        (totals.entered, totals.returned, totals.errors)
            == (expected.entered, expected.returned, expected.errors),
        "{phase}: actual aggregates disagree with independent completed/abandoned ledger"
    );
    ensure!(
        rows.len() == expected.starts,
        "{phase}: unresolved START keys"
    );
    ensure!(
        owner_control_fields(control)
            == [
                THREAD_OWNER_LIMIT,
                expected.outstanding,
                0,
                0,
                0,
                expected.abandoned,
                0
            ],
        "{phase}: owner debt, poison or unexplained failure"
    );
    let expected_rvs: BTreeMap<_, _> = [(0, expected.rv_zero), (5, expected.rv_five)]
        .into_iter()
        .filter(|(_, count)| *count != 0)
        .collect();
    ensure!(
        rvs == expected_rvs,
        "{phase}: real return-code map disagrees with fixture ledger"
    );
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE")?)?;
    for index in 0..EVIDENCE_CELLS {
        let count = evidence.get(&index, 0)?.iter().sum::<u64>();
        ensure!(count == 0, "{phase}: EVIDENCE[{index}]={count}");
    }
    ensure!(
        session.counter_snapshot()? == CounterSnapshot::default(),
        "{phase}: discovery/ABI health changed"
    );
    Ok(rows)
}

fn drain_owned(
    session: &mut Session,
    caller: &Caller,
    worker: Worker,
    events: &mut Vec<Event>,
) -> Result<()> {
    let mut overflow = false;
    let drain = session.event_drain()?;
    let more = drain.poll(Some(64), |event| {
        if events.len() >= 28 {
            overflow = true;
            return ControlFlow::Break(());
        }
        events.push(event);
        ControlFlow::Continue(())
    });
    ensure!(
        !more && !overflow && drain.malformed() == 0,
        "unexpected event backlog/overflow/malformed records"
    );
    for event in events.iter() {
        ensure!(event.event_type == event_type::CALL && event.slot == 0);
        ensure!((event.pid_tgid >> 32) as u32 == caller.pid());
        ensure!([caller.pid(), worker.tid].contains(&(event.pid_tgid as u32)));
        ensure!(event.image.task_cookie != 0);
    }
    // This fixture creates no exec or process child while capture is active.
    // A nonleader LEADER_EXIT would drive incorrect process/provider retirement.
    match session.discovery_dequeue()? {
        Some(events::DiscoveryItem::Record(record)) => bail!(
            "unexpected lifecycle discovery for nonleader exit: kind={} pid_tgid={} hook_ts_ns={}",
            record.kind,
            record.pid_tgid,
            record.hook_ts_ns
        ),
        Some(events::DiscoveryItem::Malformed) => bail!("malformed lifecycle discovery record"),
        None => {}
    }
    Ok(())
}

#[derive(Default, Debug)]
struct OwnedIds {
    maps: BTreeSet<u32>,
    programs: BTreeSet<u32>,
    links: BTreeSet<u32>,
}

fn id_exists(command: bpf_cmd, id: u32) -> Result<bool> {
    let mut attr = [id.checked_sub(1).context("nonzero owned BPF ID")?, 0, 0];
    // Non-owning registry query. Never reopen a retiring object with GET_FD_BY_ID.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command as u32,
            &mut attr,
            std::mem::size_of::<[u32; 3]>(),
        )
    };
    if result == 0 {
        ensure!(attr[1] > attr[0]);
        return Ok(attr[1] == id);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error.into())
    }
}

fn map_data(map: &Map) -> Result<&MapData> {
    match map {
        Map::Array(data)
        | Map::CgroupArray(data)
        | Map::HashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::ProgramArray(data)
        | Map::RingBuf(data)
        | Map::Unsupported(data) => Ok(data),
        _ => bail!("unexpected Detailed map variant in owned gate"),
    }
}

impl OwnedIds {
    fn observe(session: &Session) -> Result<Self> {
        let mut ids = Self::default();
        for (_, map) in session.ebpf.maps() {
            let id = map_data(map)?.info()?.id();
            ensure!(id_exists(bpf_cmd::BPF_MAP_GET_NEXT_ID, id)?);
            ids.maps.insert(id);
        }
        for (_, program) in session.ebpf.programs() {
            match program.info() {
                Ok(info) => {
                    ensure!(id_exists(bpf_cmd::BPF_PROG_GET_NEXT_ID, info.id())?);
                    ids.programs.insert(info.id());
                }
                Err(ProgramError::NotLoaded) => {}
                Err(error) => return Err(error.into()),
            }
        }
        // One descriptor enumeration while Session retains every link. Query
        // borrowed descriptors and validate the ID/program pair before use.
        for entry in std::fs::read_dir("/proc/self/fdinfo")? {
            let entry = entry?;
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let field = |key| {
                text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    (name == key)
                        .then(|| value.trim().parse::<u32>().ok())
                        .flatten()
                })
            };
            let (Some(program), Some(id)) = (field("prog_id"), field("link_id")) else {
                continue;
            };
            if !ids.programs.contains(&program) {
                continue;
            }
            let fd: u32 = entry.file_name().to_string_lossy().parse()?;
            // SAFETY: zeroed kernel output POD, used only after successful ioctl.
            let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
            #[repr(C)]
            struct InfoAttr {
                fd: u32,
                len: u32,
                info: u64,
            }
            let attr = InfoAttr {
                fd,
                len: std::mem::size_of_val(&info) as u32,
                info: (&mut info as *mut bpf_link_info) as u64,
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32,
                    &attr,
                    std::mem::size_of_val(&attr),
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error().into());
            }
            ensure!(info.id == id && info.prog_id == program);
            ensure!(id_exists(bpf_cmd::BPF_LINK_GET_NEXT_ID, id)?);
            ensure!(ids.links.insert(id), "duplicate owned link FD");
        }
        ensure!(!ids.maps.is_empty() && !ids.programs.is_empty());
        ensure!(
            ids.links.len() == session.links.len(),
            "not every retained Detailed link has an owned descriptor receipt"
        );
        eprintln!("LIFECYCLE_IDS {ids:?}");
        Ok(ids)
    }
    fn released(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut present = false;
            for (command, ids) in [
                (bpf_cmd::BPF_MAP_GET_NEXT_ID, &self.maps),
                (bpf_cmd::BPF_PROG_GET_NEXT_ID, &self.programs),
                (bpf_cmd::BPF_LINK_GET_NEXT_ID, &self.links),
            ] {
                for id in ids {
                    present |= id_exists(command, *id)?;
                }
            }
            if !present {
                eprintln!("LIFECYCLE_RELEASED {self:?}");
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "owned BPF registry cleanup deadline: {self:?}"
            );
            std::thread::yield_now();
        }
    }
}

fn detailed_nonleader_exit_gate() -> Result<()> {
    let fixture = Fixture::build()?;
    let mut child = fixture.spawn()?;
    let (view, pins, plan) = fixture.pin(&child)?;
    let object_hash: String = Sha256::digest(crate::EBPF_OBJECT)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!("LIFECYCLE_OBJECT sha256={object_hash}");
    let mut session = Session::start(
        &plan,
        &Scope::Pid(child.pid()),
        &pins,
        CapturePolicy::Allowlisted,
        None,
        None,
        None,
        BackendSelection::Singles,
    )?;
    ensure!(session.attach_failures().is_empty() && session.attached_probes() == 2);
    ensure!(session.lifecycle_tracking_unavailable().is_none());
    ensure!(session.process_creation_tracking_unavailable().is_none());
    let ids = OwnedIds::observe(&session)?;
    let result = (|| -> Result<()> {
        assert_maps(
            &session,
            "baseline",
            Expected {
                entered: 0,
                returned: 0,
                errors: 0,
                starts: 0,
                outstanding: 0,
                abandoned: 0,
                rv_zero: 0,
                rv_five: 0,
            },
        )?;
        let worker = child.start_worker()?;
        child.assert_worker_body_held(worker)?;
        let rows = assert_maps(
            &session,
            "body",
            Expected {
                entered: 12,
                returned: 11,
                errors: 5,
                starts: 1,
                outstanding: 1,
                abandoned: 0,
                rv_zero: 6,
                rv_five: 5,
            },
        )?;
        ensure!(rows[0].0.pid_tgid == (u64::from(child.pid()) << 32 | u64::from(worker.tid)));
        ensure!(rows[0].0.slot == 0 && rows[0].0._pad == 0);
        let image: ImageIdentity = rows[0].1.image;
        ensure!(image.task_cookie != 0);
        let mut events = Vec::with_capacity(28);
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(
            events.len() == 11
                && events
                    .iter()
                    .all(|event| event.pid_tgid as u32 == worker.tid)
        );
        child.release_worker(worker)?;
        assert_maps(
            &session,
            "worker_exited",
            Expected {
                entered: 12,
                returned: 11,
                errors: 5,
                starts: 0,
                outstanding: 0,
                abandoned: 1,
                rv_zero: 6,
                rv_five: 5,
            },
        )?;
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(events.len() == 11);
        ensure!(view.still_the_same() && session.has_slot_link(0));
        ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
        child.continue_leader()?;
        // entered-returned intentionally remains one for the abandoned call.
        // Zero debt means no START rows or outstanding owner reservations; no
        // synthetic return is invented to make aggregate subtraction zero.
        assert_maps(
            &session,
            "leader_done",
            Expected {
                entered: 29,
                returned: 28,
                errors: 13,
                starts: 0,
                outstanding: 0,
                abandoned: 1,
                rv_zero: 15,
                rv_five: 13,
            },
        )?;
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(events.len() == 28 && events.iter().all(|event| event.image == image));
        let worker_rvs: Vec<_> = events
            .iter()
            .filter(|event| event.pid_tgid as u32 == worker.tid)
            .map(|event| event.rv)
            .collect();
        let leader_rvs: Vec<_> = events
            .iter()
            .filter(|event| event.pid_tgid as u32 == child.pid())
            .map(|event| event.rv)
            .collect();
        ensure!(worker_rvs == [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]);
        ensure!(leader_rvs == [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]);
        ensure!(view.still_the_same() && session.has_slot_link(0));
        ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
        child.same_leader()?;
        eprintln!(
            "LIFECYCLE_ACCOUNTED worker_completed=11 leader_completed=17 abandoned=1 image={image:?}"
        );
        Ok(())
    })();
    if let Err(error) = &result {
        eprintln!("LIFECYCLE_FAILURE {error:#}");
    }
    let detach = session.detach_producers();
    let detached_cleanly = session.detach_failures().is_empty();
    drop(session);
    let released = ids.released();
    // Success leaves the leader at its explicit final barrier until links are
    // gone. Failure retains ChildCustody for kill/reap instead of sending a
    // command into an unknown fixture phase.
    if result.is_ok() {
        child.finish()?;
    }
    result?;
    detach?;
    ensure!(detached_cleanly);
    released?;
    Ok(())
}

#[test]
fn detailed_thread_exit_fixture_requires_kernel_exit_before_leader_continuation()
-> anyhow::Result<()> {
    let fixture = Fixture::build()?;
    let mut child = fixture.spawn()?;
    let worker = child.start_worker()?;
    child.assert_worker_body_held(worker)?;
    child.release_worker(worker)?;
    child.continue_leader()?;
    child.finish()?;
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; real Detailed Singles, raw nonleader exit and surviving leader"]
fn privileged_detailed_nonleader_exit_reclaims_start_and_preserves_leader() -> anyhow::Result<()> {
    detailed_nonleader_exit_gate()
}

// Read the actual kernel value as bytes. This covers every field and padding
// without observing Rust struct padding or synthesizing an expected value.
fn start_bytes(session: &Session, key: &StartKey) -> Result<[u8; size_of::<CallStart>()]> {
    let starts: HashMap<_, StartKey, [u8; size_of::<CallStart>()]> =
        HashMap::try_from(session.ebpf.map("START").context("START bytes")?)?;
    Ok(starts.get(key, 0)?)
}

fn detailed_sibling_exit_gate() -> Result<()> {
    let fixture = Fixture::build_sibling()?;
    let mut child = fixture.spawn()?;
    let (view, pins, plan) = fixture.pin(&child)?;
    let object_hash: String = Sha256::digest(crate::EBPF_OBJECT)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!("LIFECYCLE_OBJECT sha256={object_hash}");
    let mut session = Session::start(
        &plan,
        &Scope::Pid(child.pid()),
        &pins,
        CapturePolicy::Allowlisted,
        None,
        None,
        None,
        BackendSelection::Singles,
    )?;
    ensure!(session.attach_failures().is_empty() && session.attached_probes() == 2);
    ensure!(session.lifecycle_tracking_unavailable().is_none());
    ensure!(session.process_creation_tracking_unavailable().is_none());
    let ids = OwnedIds::observe(&session)?;
    let result = (|| -> Result<()> {
        assert_maps(
            &session,
            "baseline",
            Expected {
                entered: 0,
                returned: 0,
                errors: 0,
                starts: 0,
                outstanding: 0,
                abandoned: 0,
                rv_zero: 0,
                rv_five: 0,
            },
        )?;
        let worker = child.start_worker()?;
        child.await_sibling_bodies(worker)?;
        let rows = assert_maps(
            &session,
            "sibling_bodies",
            Expected {
                entered: 13,
                returned: 11,
                errors: 5,
                starts: 2,
                outstanding: 2,
                abandoned: 0,
                rv_zero: 6,
                rv_five: 5,
            },
        )?;
        let worker_id = u64::from(child.pid()) << 32 | u64::from(worker.tid);
        let leader_id = u64::from(child.pid()) << 32 | u64::from(child.pid());
        ensure!(rows.iter().all(|(key, _)| key.slot == 0 && key._pad == 0));
        let (_, worker_start) = rows
            .iter()
            .find(|(key, _)| key.pid_tgid == worker_id)
            .context("exact held worker START")?;
        let (leader_key, leader_start) = rows
            .iter()
            .find(|(key, _)| key.pid_tgid == leader_id)
            .context("exact same-slot held leader START")?;
        let image = worker_start.image;
        ensure!(image.task_cookie != 0 && leader_start.image == image);
        ensure!(worker_start.ts_ns > 0 && leader_start.ts_ns >= worker_start.ts_ns);
        let saved_leader = start_bytes(&session, leader_key)?;
        let leader_hash: String = Sha256::digest(saved_leader)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        eprintln!(
            "LIFECYCLE_SIBLING_START phase=both_held worker_pid_tgid={worker_id} leader_pid_tgid={leader_id} slot=0 bytes={} leader_sha256={leader_hash}",
            saved_leader.len()
        );
        let mut events = Vec::with_capacity(28);
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(events.len() == 11 && events.iter().all(|event| event.pid_tgid == worker_id));

        // X is read inside the leader's still-probed frame. Its EXITED receipt
        // follows the kernel's child_tid clear, before L can allow its return.
        child.release_worker(worker)?;
        child.assert_leader_body_held()?;
        let survivor = assert_maps(
            &session,
            "worker_exited_sibling_held",
            Expected {
                entered: 13,
                returned: 11,
                errors: 5,
                starts: 1,
                outstanding: 1,
                abandoned: 1,
                rv_zero: 6,
                rv_five: 5,
            },
        )?;
        ensure!(
            survivor[0].0.pid_tgid == leader_id
                && survivor[0].0.slot == 0
                && survivor[0].0._pad == 0,
            "worker cleanup did not preserve the exact sibling key"
        );
        ensure!(
            start_bytes(&session, leader_key)? == saved_leader,
            "worker cleanup changed the surviving sibling's START value"
        );
        eprintln!(
            "LIFECYCLE_SIBLING_START phase=worker_exited worker_absent=true leader_pid_tgid={leader_id} slot=0 preserved=true leader_sha256={leader_hash}"
        );
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(
            events.len() == 11,
            "a held/abandoned call produced a false completion"
        );
        ensure!(view.still_the_same() && session.has_slot_link(0));
        ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
        child.continue_leader()?;
        assert_maps(
            &session,
            "leader_done",
            Expected {
                entered: 29,
                returned: 28,
                errors: 13,
                starts: 0,
                outstanding: 0,
                abandoned: 1,
                rv_zero: 15,
                rv_five: 13,
            },
        )?;
        drain_owned(&mut session, &child, worker, &mut events)?;
        ensure!(events.len() == 28 && events.iter().all(|event| event.image == image));
        let worker_rvs: Vec<_> = events
            .iter()
            .filter(|event| event.pid_tgid == worker_id)
            .map(|event| event.rv)
            .collect();
        let leader_rvs: Vec<_> = events
            .iter()
            .filter(|event| event.pid_tgid == leader_id)
            .map(|event| event.rv)
            .collect();
        ensure!(worker_rvs == [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]);
        ensure!(leader_rvs == [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]);
        ensure!(view.still_the_same() && session.has_slot_link(0));
        ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
        child.same_leader()?;
        eprintln!(
            "LIFECYCLE_ACCOUNTED sibling_preserved=true worker_completed=11 leader_completed=17 abandoned=1 image={image:?}"
        );
        Ok(())
    })();
    if let Err(error) = &result {
        eprintln!("LIFECYCLE_FAILURE {error:#}");
    }
    let detach = session.detach_producers();
    let detached_cleanly = session.detach_failures().is_empty();
    drop(session);
    let released = ids.released();
    if result.is_ok() {
        child.finish()?;
    }
    result?;
    detach?;
    ensure!(detached_cleanly);
    released?;
    Ok(())
}

#[test]
fn detailed_sibling_exit_fixture_holds_leader_through_kernel_worker_exit() -> anyhow::Result<()> {
    let fixture = Fixture::build_sibling()?;
    let mut child = fixture.spawn()?;
    let worker = child.start_worker()?;
    child.await_sibling_bodies(worker)?;
    child.release_worker(worker)?;
    child.assert_leader_body_held()?;
    child.continue_leader()?;
    child.finish()?;
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; real Detailed Singles, two held STARTs and selective thread cleanup"]
fn privileged_detailed_nonleader_exit_preserves_same_slot_sibling_start() -> anyhow::Result<()> {
    detailed_sibling_exit_gate()
}
