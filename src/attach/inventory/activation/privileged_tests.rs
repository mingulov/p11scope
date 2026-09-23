//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates. The parent runs these serially with its BPF lane.
use super::*;
use crate::capacity::CallerBudget;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::Slot;
use crate::process::{PidPin, ProcessView, ProcessViewId};
use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray, PerCpuHashMap};
use aya::programs::ProgramError;
use aya_obj::generated::{bpf_cmd, bpf_link_info, bpf_link_type, bpf_perf_event_type};
use p11scope_ebpf_common::inventory_callers::{CallerObjectKey, CallerObjectUse, EndpointObject};
use p11scope_ebpf_common::{
    CallStart, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT, EVIDENCE_CELLS, Event,
    ImageIdentity, RvKey, SlotSemantics, SlotStats, StartKey, THREAD_OWNER_LIMIT,
    ThreadOwnerControl, event_type,
};
use p11scope_manifest::elf::ElfSnapshot;
use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use std::ops::ControlFlow;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

fn budget() -> InventoryBudget {
    InventoryBudget::new(576, 4608).unwrap()
}
fn caller_budget(pairs: u64) -> CallerBudget {
    CallerBudget::new(budget(), pairs, 4608 + 56 * pairs).unwrap()
}
fn window() -> InventoryReadWindow {
    InventoryReadWindow::new(576, Instant::now() + Duration::from_secs(3)).unwrap()
}

struct OwnedFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    pins: PinnedObjects,
    plan: AttachPlan,
    expected_key: ObjectKey,
    expected_sha256: String,
    expected_abi: ElfAbi,
}

impl OwnedFixture {
    fn build(ia32: bool) -> Result<Self> {
        Self::build_n(ia32, 576)
    }

    fn build_n(ia32: bool, endpoints: u32) -> Result<Self> {
        ensure!(
            (1..=2_113).contains(&endpoints),
            "unsupported owned fixture size"
        );
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("owned.c");
        let path = directory.path().join("owned-provider");
        let mut c = String::from(
            r#"#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
static unsigned hold_id = UINT_MAX;
static unsigned hold_action = 0;
static char **exec_argv;
static void hold_in_body(unsigned id) {
    if (hold_id != id) return;
    hold_id = UINT_MAX;
    printf("BODY %u\n", id);
    char resume[16];
    if (scanf("%15s", resume) != 1) _exit(4);
    if (hold_action == 1 && !strcmp(resume, "THREAD_EXIT")) pthread_exit(NULL);
    if (hold_action == 2 && !strcmp(resume, "EXEC_THREAD")) { execv(exec_argv[0], exec_argv); _exit(5); }
    if (strcmp(resume, "RESUME")) _exit(4);
    printf("RESUMED %u\n", id);
}
"#,
        );
        for id in 0..endpoints {
            c.push_str(&format!("__attribute__((noinline,used)) unsigned long owned_{id}(unsigned long x) {{ __asm__ volatile(\"\" ::: \"memory\"); hold_in_body({id}); return x + {id}; }}\n"));
        }
        c.push_str(&format!(
            "typedef unsigned long (*fn)(unsigned long);\nstatic fn const functions[{endpoints}] = {{\n",
        ));
        for id in 0..endpoints {
            c.push_str(&format!("owned_{id},\n"));
        }
        c.push_str(
            &r#"};
struct thread_work { unsigned id, calls; unsigned long sum; unsigned tid, action; };
static void *thread_call(void *data) {
    struct thread_work *work = data;
    work->tid = (unsigned)syscall(SYS_gettid);
    if (work->action) printf("WORKER %u %u\n", work->id, work->tid);
    for (unsigned n = 0; n < work->calls; n++) work->sum += functions[work->id](n);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc < 1 || argc > 2 || (argc == 2 && strcmp(argv[1], "GO_REQUIRED"))) return 2;
    int go = argc == 1;
    exec_argv = argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("READY %ld\n", (long)getpid());
    char command[16]; unsigned id, calls;
    while (scanf("%15s", command) == 1) {
        if (!strcmp(command, "GO")) {
            if (go) return 2;
            go = 1; printf("GO %ld\n", (long)getpid()); continue;
        }
        if (!go && strcmp(command, "EXIT")) return 8;
        if (!strcmp(command, "EXIT")) return 0;
        if (!strcmp(command, "EXEC")) { execv(argv[0], argv); return 5; }
        if (!strcmp(command, "RETURN")) {
            unsigned long input;
            if (scanf("%u %lu", &id, &input) != 2 || id >= 576) return 2;
            unsigned long rv = functions[id](input);
            printf("RETURNED %u %lu %lu\n", id, input, rv); continue;
        }
        if (!strcmp(command, "ARM")) {
            if (scanf("%u", &id) != 1 || id >= 576) return 2;
            hold_id = id; printf("ARMED %u\n", id); continue;
        }
        if (!strcmp(command, "ABANDON") || !strcmp(command, "NONLEADER_EXEC")) {
            if (scanf("%u", &id) != 1 || id >= 576) return 2;
            int abandon = !strcmp(command, "ABANDON");
            hold_id = id; hold_action = abandon ? 1 : 2;
            struct thread_work work = {id, 1, 0, 0, hold_action}; pthread_t worker;
            printf("THREAD_START %u 1\n", id);
            if (pthread_create(&worker, NULL, thread_call, &work)) return 6;
            if (pthread_join(worker, NULL)) return 7;
            if (abandon) { hold_action = 0; printf("ABANDONED %u %u\n", id, work.tid); continue; }
            return 9;
        }
        int thread = !strcmp(command, "THREAD");
        if (!thread && strcmp(command, "CALL")) return 2;
        if (scanf("%u %u", &id, &calls) != 2 || id >= 576 || calls > 1000000) return 2;
        if (thread) {
            struct thread_work work = {id, calls, 0, 0, 0}; pthread_t worker;
            printf("THREAD_START %u %u\n", id, calls);
            if (pthread_create(&worker, NULL, thread_call, &work)) return 6;
            if (pthread_join(worker, NULL)) return 7;
            printf("THREAD_DONE %u %u %lu %u\n", id, calls, work.sum, work.tid);
        } else {
            printf("START %u %u\n", id, calls);
            unsigned long sum = 0;
            for (unsigned n = 0; n < calls; n++) sum += functions[id](n);
            printf("DONE %u %u %lu\n", id, calls, sum);
        }
    }

    return 3;
}
"#
            .replace("576", &endpoints.to_string()),
        );
        std::fs::write(&source, c)?;
        let mut compiler = Command::new("cc");
        compiler.args([
            "-O0",
            "-fno-inline",
            "-fno-pie",
            "-no-pie",
            "-rdynamic",
            "-pthread",
        ]);
        if ia32 {
            compiler.arg("-m32");
        }
        let output = compiler.arg(&source).arg("-o").arg(&path).output()?;
        ensure!(
            output.status.success(),
            "owned fixture compiler failed (ia32={ia32}): {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let file = open_object(&path).map_err(anyhow::Error::msg)?;
        let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
        let elf = ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
        ensure!(elf.abi() == if ia32 { ElfAbi::Ilp32 } else { ElfAbi::Lp64 });
        let view =
            ProcessView::open(ProcessViewId(0), std::process::id()).map_err(anyhow::Error::msg)?;
        let module = ScannedModule {
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key: ObjectKey {
                device: Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            path: path.display().to_string(),
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
            "owned physical pin was skipped: {skipped:?}"
        );
        let summary = pins.pinned().next().context("owned physical pin")?;
        let object = summary.id;
        let expected_key = summary.key;
        let expected_sha256 = summary.sha256.to_string();
        eprintln!(
            "OWNED_PHYSICAL abi={:?} key={:?} sha256={} path={}",
            elf.abi(),
            summary.key,
            summary.sha256,
            path.display()
        );
        let mut slots = vec![];
        let mut offsets = BTreeSet::new();
        for id in 0..endpoints {
            let name = format!("owned_{id}");
            let offset = elf
                .defined_symbol(&name)
                .map_err(anyhow::Error::msg)?
                .context("owned symbol")?
                .file_offset;
            ensure!(elf.is_executable_offset(offset));
            ensure!(
                offsets.insert(offset),
                "owned fixture aliased physical offset {offset:#x}"
            );
            slots.push(Slot {
                index: id,
                descriptor_index: 0,
                object,
                object_path: path.display().to_string(),
                file_offset: offset,
                names: vec![name],
                aliased: false,
                semantics: SlotSemantics::COUNT_ONLY,
                semantic_authorized: false,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![],
            });
        }
        let inventory_budget = InventoryBudget::new(u64::from(endpoints), 8 * u64::from(endpoints))
            .map_err(anyhow::Error::msg)?;
        let plan =
            AttachPlan::from_slots_with_policy(slots, AdmissionPolicy::Inventory(inventory_budget))
                .map_err(anyhow::Error::msg)?;
        Ok(Self {
            _directory: directory,
            path,
            pins,
            plan,
            expected_key,
            expected_sha256,
            expected_abi: elf.abi(),
        })
    }

    fn targets(&self) -> Result<InventoryTargets> {
        InventoryTargets::from_plan(&self.plan, &self.pins)
    }
    fn spawn(&self) -> Result<OwnedCaller> {
        self.spawn_inner(false)
    }

    fn spawn_gated(&self) -> Result<OwnedCaller> {
        self.spawn_inner(true)
    }

    fn spawn_inner(&self, gated: bool) -> Result<OwnedCaller> {
        let caller = OwnedCaller::spawn_inner(&self.path, gated)?;
        self.assert_caller_identity(&caller)?;
        Ok(caller)
    }

    fn assert_caller_identity(&self, caller: &OwnedCaller) -> Result<()> {
        let executable = open_object(&PathBuf::from(format!("/proc/{}/exe", caller.child.id())))
            .map_err(anyhow::Error::msg)?;
        let mapping = mapping_file_key(&executable).map_err(anyhow::Error::msg)?;
        let key = ObjectKey {
            device: Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        let inspected = inspect_file(&executable).map_err(anyhow::Error::msg)?;
        ensure!(
            key == self.expected_key,
            "owned caller executes a different physical object"
        );
        ensure!(
            inspected.identity.sha256.as_deref() == Some(self.expected_sha256.as_str()),
            "owned caller digest differs from pinned target"
        );
        ensure!(
            inspected.abi == self.expected_abi,
            "owned caller ABI differs from pinned target"
        );
        eprintln!(
            "OWNED_CALLER pid={} key={key:?} sha256={} abi={:?}",
            caller.child.id(),
            self.expected_sha256,
            inspected.abi
        );
        Ok(())
    }
}

struct OwnedCaller {
    child: Child,
    pin: Option<PidPin>,
    input: ChildStdin,
    output: ChildStdout,
    observed: Vec<String>,
}
impl OwnedCaller {
    fn spawn(path: &Path) -> Result<Self> {
        Self::spawn_inner(path, false)
    }

    fn spawn_inner(path: &Path, gated: bool) -> Result<Self> {
        let mut command = Command::new(path);
        if gated {
            command.arg("GO_REQUIRED");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().context("owned input")?;
        let output = child.stdout.take().context("owned output")?;
        let mut caller = Self {
            child,
            pin: None,
            input,
            output,
            observed: Vec::new(),
        };
        let pin = PidPin::open(caller.child.id()).map_err(anyhow::Error::msg)?;
        pin.pidfd()
            .context("owned fixture requires exact child pidfd custody")?;
        caller.pin = Some(pin);
        let expected = format!("READY {}", caller.child.id());
        ensure!(
            caller.line()? == expected,
            "owned caller did not reach readiness"
        );
        Ok(caller)
    }

    fn line(&mut self) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut line = vec![];
        while line.len() < 256 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "owned caller deadline");
            let mut poll = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll borrows one valid owned stdout descriptor.
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(1000) as i32) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            let mut byte = [0];
            ensure!(
                self.output.read(&mut byte)? == 1,
                "owned caller closed stdout early"
            );
            if byte[0] == b'\n' {
                let reply = String::from_utf8(line)?;
                self.observed.push(reply.clone());
                return Ok(reply);
            }
            line.push(byte[0]);
        }
        bail!("owned caller line exceeded bound")
    }

    fn go(&mut self) -> Result<()> {
        writeln!(self.input, "GO")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("GO {}", self.child.id()));
        Ok(())
    }

    fn call_exact(&mut self, id: u32, rv: u64) -> Result<()> {
        let input = rv.wrapping_sub(u64::from(id));
        writeln!(self.input, "RETURN {id} {input}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("RETURNED {id} {input} {rv}"));
        Ok(())
    }

    fn start_held_worker(&mut self, command: &str, id: u32) -> Result<u32> {
        ensure!(["ABANDON", "NONLEADER_EXEC"].contains(&command));
        writeln!(self.input, "{command} {id}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("THREAD_START {id} 1"));
        let worker = self.line()?;
        let tid: u32 = worker
            .strip_prefix(&format!("WORKER {id} "))
            .context("held worker TID receipt")?
            .parse()?;
        ensure!(
            tid != 0 && tid != self.child.id(),
            "held worker is not a nonleader"
        );
        ensure!(self.line()? == format!("BODY {id}"));
        self.assert_body_held()?;
        Ok(tid)
    }

    fn release_held_worker_exit(&mut self, id: u32, tid: u32) -> Result<()> {
        writeln!(self.input, "THREAD_EXIT")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("ABANDONED {id} {tid}"));
        ensure!(
            !PathBuf::from(format!("/proc/{}/task/{tid}", self.child.id())).exists(),
            "abandoned worker TID still exists"
        );
        Ok(())
    }

    fn release_held_worker_exec(&mut self) -> Result<()> {
        writeln!(self.input, "EXEC_THREAD")?;
        self.input.flush()?;
        ensure!(
            self.line()? == format!("READY {}", self.child.id()),
            "nonleader exec did not produce successor readiness"
        );
        Ok(())
    }

    fn calls(&mut self, id: u32, calls: u32) -> Result<()> {
        self.start_calls(id, calls)?;
        self.finish_calls(id, calls)
    }

    fn thread_calls(&mut self, id: u32, calls: u32) -> Result<u32> {
        writeln!(self.input, "THREAD {id} {calls}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("THREAD_START {id} {calls}"));
        let sum = u64::from(calls) * u64::from(id)
            + u64::from(calls) * u64::from(calls.saturating_sub(1)) / 2;
        let receipt = self.line()?;
        let prefix = format!("THREAD_DONE {id} {calls} {sum} ");
        let tid: u32 = receipt
            .strip_prefix(&prefix)
            .context("owned thread receipt mismatch")?
            .parse()?;
        ensure!(
            tid != 0 && tid != self.child.id(),
            "owned worker was not a physical nonleader thread"
        );
        eprintln!("OWNED_THREAD pid={} tid={tid} {receipt}", self.child.id());
        Ok(tid)
    }

    fn exec_self(&mut self) -> Result<()> {
        writeln!(self.input, "EXEC")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("READY {}", self.child.id()));
        eprintln!("OWNED_EXEC pid={}", self.child.id());
        Ok(())
    }

    fn start_calls(&mut self, id: u32, calls: u32) -> Result<()> {
        writeln!(self.input, "CALL {id} {calls}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("START {id} {calls}"));
        Ok(())
    }

    fn hold_call_in_body(&mut self, id: u32, calls: u32) -> Result<()> {
        ensure!(calls != 0);
        writeln!(self.input, "ARM {id}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("ARMED {id}"));
        self.start_calls(id, calls)?;
        let receipt = self.line()?;
        ensure!(receipt == format!("BODY {id}"));
        eprintln!("OWNED_BODY pid={} {receipt}", self.child.id());
        self.assert_body_held()
    }

    fn assert_body_held(&mut self) -> Result<()> {
        let mut poll = libc::pollfd {
            fd: self.output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one valid owned stdout descriptor.
        ensure!(
            unsafe { libc::poll(&mut poll, 1, 50) } == 0,
            "owned body advanced before explicit resume"
        );
        ensure!(self.child.try_wait()?.is_none(), "held child exited");
        Ok(())
    }

    fn resume_body(&mut self, id: u32) -> Result<()> {
        writeln!(self.input, "RESUME")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("RESUMED {id}"));
        Ok(())
    }

    fn finish_calls(&mut self, id: u32, calls: u32) -> Result<()> {
        let sum = u64::from(calls) * u64::from(id)
            + u64::from(calls) * u64::from(calls.saturating_sub(1)) / 2;
        let ledger = self.line()?;
        ensure!(
            ledger == format!("DONE {id} {calls} {sum}"),
            "independent owned ledger differs: {ledger}"
        );
        eprintln!("OWNED_LEDGER pid={} {ledger}", self.child.id());
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        writeln!(self.input, "EXIT")?;
        self.input.flush()?;
        ensure!(
            self.pin
                .as_ref()
                .context("owned pidfd")?
                .wait_ready(Some(Duration::from_secs(3)))?,
            "owned fixture pidfd exit deadline"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(status.success());
                ensure!(
                    self.pin
                        .as_ref()
                        .context("owned pidfd")?
                        .original_exited()
                        .map_err(anyhow::Error::msg)?,
                    "owned fixture original generation did not exit"
                );
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "owned exit deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedCaller {
    fn drop(&mut self) {
        let signalled = self
            .pin
            .as_ref()
            .is_some_and(|pin| pin.send_signal(libc::SIGKILL).is_ok());
        if !signalled {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[derive(Default, Debug)]
struct OwnedIds {
    maps: BTreeSet<u32>,
    programs: BTreeSet<u32>,
    links: BTreeSet<u32>,
}
fn id_exists(command: bpf_cmd, id: u32) -> Result<bool> {
    let mut attr = [id.checked_sub(1).context("nonzero owned ID")?, 0, 0];
    // GET_NEXT_ID reads the registry without acquiring any object reference.
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
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error.into())
    }
}
impl OwnedIds {
    fn detailed(session: &crate::attach::Session) -> Result<Self> {
        let mut ids = Self::default();
        for (_, map) in session.ebpf.maps() {
            let id = detailed_map_data(map)?.info()?.id();
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
        for (id, info) in owned_link_info_snapshot(&ids.programs)? {
            ensure!(id_exists(bpf_cmd::BPF_LINK_GET_NEXT_ID, id)?);
            ensure!(info.id == id && ids.programs.contains(&info.prog_id));
            ids.links.insert(id);
        }
        ensure!(
            ids.links.len() == session.links.len(),
            "Detailed link IDs differ from retained links"
        );
        Ok(ids)
    }

    fn prepared(prepared: &PreparedInventory) -> Result<Self> {
        let mut ids = Self::default();
        for (name, map) in prepared.ebpf.maps() {
            let id = super::super::inventory_map_data(name, map)?.1.info()?.id();
            ensure!(id_exists(bpf_cmd::BPF_MAP_GET_NEXT_ID, id)?);
            ids.maps.insert(id);
        }
        for (_, program) in prepared.ebpf.programs() {
            let id = program.info()?.id();
            ensure!(id_exists(bpf_cmd::BPF_PROG_GET_NEXT_ID, id)?);
            ids.programs.insert(id);
        }
        let expected_maps = if matches!(prepared.flavor, InventoryFlavor::Callers(_)) {
            18
        } else {
            13
        };
        ensure!(ids.maps.len() == expected_maps && ids.programs.len() == 12);
        Ok(ids)
    }

    fn observe_open_owned_links(&mut self) -> Result<()> {
        for (id, info) in owned_link_info_snapshot(&self.programs)? {
            ensure!(id_exists(bpf_cmd::BPF_LINK_GET_NEXT_ID, id)?);
            ensure!(info.id == id && self.programs.contains(&info.prog_id));
            self.links.insert(id);
        }
        Ok(())
    }

    fn inspect_links(&mut self, state: &InventoryState, expected_entries: usize) -> Result<()> {
        ensure!(state.links.len() == expected_entries + 2);
        // FdLink's public API exposes summary info but not its borrowed raw FD
        // or full perf metadata. Resolve all retained descriptors once while
        // this borrow keeps every real link alive; never reopen them by ID.
        let raw_infos = owned_link_info_snapshot(&self.programs)?;
        for link in &state.links {
            let KernelInventoryLink::Fds(fds) = &link.handle else {
                bail!("quarantined live link");
            };
            ensure!(fds.len() == 1);
            let info = fds[0].info()?;
            ensure!(id_exists(bpf_cmd::BPF_LINK_GET_NEXT_ID, info.id())?);
            self.links.insert(info.id());
            let raw = raw_infos
                .get(&info.id())
                .context("owned link has no retained descriptor in inspection snapshot")?;
            ensure!(raw.id == info.id() && raw.prog_id == info.program_id());
            let name = match link.target {
                InventoryLinkIdentity::Lifecycle(name) => {
                    ensure!(raw.type_ == bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32);
                    name
                }
                InventoryLinkIdentity::Entry(id) => {
                    ensure!(raw.type_ == bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32);
                    // SAFETY: type_ identifies the perf-event union member.
                    let perf = unsafe { raw.__bindgen_anon_1.perf_event };
                    ensure!(
                        perf.type_ == bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u32,
                        "ordinary return link installed"
                    );
                    // SAFETY: the exact perf type above identifies an ordinary uprobe.
                    let point = unsafe { perf.__bindgen_anon_1.uprobe };
                    let entry = &state.targets.entries[id as usize];
                    ensure!(u64::from(point.offset) == entry.file_offset);
                    ensure!(point.cookie == (0x5055_5347_0000_0000 | u64::from(id)));
                    match entry.abi {
                        ElfAbi::Lp64 => "p11_usage_entry_lp64",
                        ElfAbi::Ilp32 => "p11_usage_entry_ia32",
                    }
                }
            };
            ensure!(
                state
                    .prepared
                    .ebpf
                    .program(name)
                    .context(name)?
                    .info()?
                    .id()
                    == info.program_id()
            );
        }
        eprintln!("OWNED_IDS {self:?}");
        Ok(())
    }

    fn released(&self) -> Result<()> {
        self.released_with_budget(Duration::from_secs(3))
    }

    fn released_with_budget(&self, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            let mut present = false;
            for (command, ids) in [
                (bpf_cmd::BPF_LINK_GET_NEXT_ID, &self.links),
                (bpf_cmd::BPF_PROG_GET_NEXT_ID, &self.programs),
                (bpf_cmd::BPF_MAP_GET_NEXT_ID, &self.maps),
            ] {
                for id in ids {
                    present |= id_exists(command, *id)?;
                }
            }
            if !present {
                eprintln!("OWNED_RELEASED {self:?}");
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "owned registry cleanup deadline: {self:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn detailed_map_data(map: &Map) -> Result<&MapData> {
    match map {
        Map::Array(data)
        | Map::CgroupArray(data)
        | Map::HashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::ProgramArray(data)
        | Map::RingBuf(data)
        | Map::Unsupported(data) => Ok(data),
        _ => bail!("unexpected Detailed map variant in Task 4 gate"),
    }
}

fn task4_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn task4_digest_hex(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const TASK4_FILE_LIMIT: usize = 16 * 1024 * 1024;
const TASK4_ROW_LIMIT: usize = 20_000;

struct Task4Rows {
    path: PathBuf,
    file: std::fs::File,
    rows: usize,
    bytes: usize,
}

impl Task4Rows {
    fn create(directory: &Path, index: usize, name: &str, suffix: &str) -> Result<Self> {
        let path = directory.join(format!("case-{index:02}-{name}.{suffix}"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            path,
            file,
            rows: 0,
            bytes: 0,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.bytes
                .checked_add(bytes.len())
                .is_some_and(|n| n <= TASK4_FILE_LIMIT),
            "Task 4 evidence file exceeded 16 MiB: {}",
            self.path.display()
        );
        ensure!(
            self.rows < TASK4_ROW_LIMIT,
            "Task 4 evidence row limit exceeded"
        );
        self.file.write_all(bytes)?;
        self.bytes += bytes.len();
        self.rows += 1;
        Ok(())
    }

    fn json(&mut self, row: serde_json::Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(&row)?;
        bytes.push(b'\n');
        self.write(&bytes)
    }

    fn contents(&mut self) -> Result<Vec<u8>> {
        self.file.flush()?;
        let bytes = std::fs::read(&self.path)?;
        ensure!(bytes.len() == self.bytes && bytes.len() <= TASK4_FILE_LIMIT);
        Ok(bytes)
    }
}

struct Task4Evidence {
    directory: PathBuf,
    index: usize,
    case: &'static str,
    profile: &'static str,
    fixture_sha256: String,
    offsets_sha256: String,
    object_sha256: String,
    ledger: Task4Rows,
    raw: Task4Rows,
    rendered: Task4Rows,
    resources: Vec<serde_json::Value>,
    ledger_calls: usize,
    raw_calls: usize,
}

impl Task4Evidence {
    fn new(
        case: &'static str,
        profile: &'static str,
        fixture: &OwnedFixture,
        object: &[u8],
    ) -> Result<Self> {
        let directory = PathBuf::from(
            std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR").context("Task 4 evidence dir")?,
        );
        let index: usize = std::env::var("P11SCOPE_TASK4_CASE_INDEX")?.parse()?;
        ensure!(index < 100);
        let offsets = std::fs::read(directory.join(format!("offsets-{index:02}.json")))?;
        Ok(Self {
            ledger: Task4Rows::create(&directory, index, "ledger", "jsonl")?,
            raw: Task4Rows::create(&directory, index, "raw", "jsonl")?,
            rendered: Task4Rows::create(&directory, index, "rendered", "txt")?,
            directory,
            index,
            case,
            profile,
            fixture_sha256: fixture.expected_sha256.clone(),
            offsets_sha256: task4_hash(&offsets),
            object_sha256: task4_hash(object),
            resources: Vec::new(),
            ledger_calls: 0,
            raw_calls: 0,
        })
    }

    fn caller(&mut self, caller: &mut OwnedCaller, phase: &str) -> Result<()> {
        for reply in caller.observed.drain(..) {
            let words: Vec<_> = reply.split_whitespace().collect();
            if words.first() == Some(&"RETURNED") {
                ensure!(words.len() == 4, "malformed observed RETURNED row");
                let slot: u32 = words[1].parse()?;
                let input: u64 = words[2].parse()?;
                let rv: u64 = words[3].parse()?;
                ensure!(input.wrapping_add(u64::from(slot)) == rv);
                self.ledger.json(serde_json::json!({
                    "kind":"call", "phase":phase, "position":self.ledger_calls,
                    "slot":slot, "input":input, "rv":rv, "reply":reply
                }))?;
                self.ledger_calls += 1;
            } else {
                self.ledger.json(serde_json::json!({
                    "kind":"barrier", "phase":phase, "reply":reply
                }))?;
            }
        }
        Ok(())
    }

    fn raw_row(&mut self, row: serde_json::Value) -> Result<()> {
        self.raw.json(row)
    }

    fn inventory_snapshot(&mut self, phase: &str, snapshot: &InventoryUsageSnapshot) -> Result<()> {
        self.raw.json(serde_json::json!({
            "kind":"usage_phase","phase":phase,
            "cells_read":snapshot.usage.cells_read,
            "positive_count":snapshot.usage.positive_count,
            "newly_positive":snapshot.usage.newly_positive,
            "usage_integrity_failures":snapshot.usage_integrity_failures,
            "usage_read_failures":snapshot.usage_read_failures,
            "provider_changed":snapshot.provider_changed,
            "malformed_discovery":snapshot.malformed_discovery,
            "terminal_unsettled":snapshot.terminal_unsettled,
            "health":format!("{:?}",snapshot.health)
        }))
    }

    fn event(&mut self, event: &Event, fixture: &OwnedFixture, phase: &str) -> Result<()> {
        let slot = usize::try_from(event.slot)?;
        let physical = fixture
            .plan
            .slots
            .get(slot)
            .context("raw CALL slot lacks physical target")?;
        let metadata = std::fs::metadata(&fixture.path)?;
        self.raw.json(serde_json::json!({
            "kind":"call", "phase":phase, "position":self.raw_calls,
            "slot":event.slot, "rv":event.rv, "event_type":event.event_type,
            "pid_tgid":event.pid_tgid,
            "image":{"task_cookie":event.image.task_cookie,"exec_id":event.image.exec_id},
            "dev":metadata.dev(), "ino":metadata.ino(), "offset":physical.file_offset,
            "ts_ns":event.ts_ns, "duration_ns":event.duration_ns
        }))?;
        self.raw_calls += 1;
        Ok(())
    }

    fn render(&mut self, line: &str) -> Result<()> {
        self.rendered.write(format!("{line}\n").as_bytes())
    }

    fn fd_sample(&mut self, phase: &str) -> Result<()> {
        // The enumerator's own descriptor is included. This is a sampled
        // process occupancy, never the unobserved attach-time peak.
        let count = std::fs::read_dir("/proc/self/fd")?
            .collect::<std::io::Result<Vec<_>>>()?
            .len();
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: getrlimit writes a complete rlimit value to valid storage.
        ensure!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0);
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let row = serde_json::json!({
            "phase":phase,"fd_count":count,"timestamp_ns":timestamp_ns.to_string(),
            "soft":limit.rlim_cur,"hard":limit.rlim_max
        });
        eprintln!(
            "TASK4_FD_SAMPLE phase={phase} fd_count={count} soft={} hard={} enumerator_included=true",
            limit.rlim_cur, limit.rlim_max
        );
        self.resources.push(row);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let ledger = self.ledger.contents()?;
        let raw = self.raw.contents()?;
        let rendered = self.rendered.contents()?;
        let offsets = std::fs::read(
            self.directory
                .join(format!("offsets-{:02}.json", self.index)),
        )?;
        ensure!(task4_hash(&offsets) == self.offsets_sha256);
        let replay = task4_replay_files(self.case, &ledger, &raw, &rendered, &offsets)?;
        ensure!(replay.0 == self.ledger_calls && replay.1 == self.raw_calls);
        task4_validate_resource_samples(self.case, &self.resources)?;
        let resources = serde_json::json!({
            "schema":1,"case_index":self.index,"profile":self.profile,
            "count_semantics":"/proc/self/fd enumeration includes its own fd; sampled occupancy, not attach peak",
            "max_sampled_fd":self.resources.iter().filter_map(|row| row["fd_count"].as_u64()).max(),
            "samples":self.resources
        });
        let resources_bytes = serde_json::to_vec(&resources)?;
        ensure!(resources_bytes.len() <= TASK4_FILE_LIMIT);
        let resources_name = format!("case-{:02}-resources.json", self.index);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(&resources_name))?
            .write_all(&resources_bytes)?;
        let file = |name: &str, bytes: &[u8], rows: usize| {
            serde_json::json!({
                "name":format!("case-{:02}-{name}",self.index),"sha256":task4_hash(bytes),
                "bytes":bytes.len(),"rows":rows
            })
        };
        let manifest = serde_json::json!({
            "schema":1,"case_index":self.index,"case":self.case,"profile":self.profile,
            "fixture_sha256":self.fixture_sha256,"offsets_sha256":self.offsets_sha256,
            "object_sha256":self.object_sha256,
            "files":{
                "ledger":file("ledger.jsonl",&ledger,self.ledger.rows),
                "raw":file("raw.jsonl",&raw,self.raw.rows),
                "rendered":file("rendered.txt",&rendered,self.rendered.rows),
                "resources":file("resources.json",&resources_bytes,self.resources.len())
            },
            "replay":{"ok":true,"completed_calls":replay.0,"raw_calls":replay.1}
        });
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_name = format!("case-{:02}-evidence.json", self.index);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(&manifest_name))?
            .write_all(&manifest_bytes)?;
        eprintln!(
            "TASK4_ARTIFACTS case={:02} evidence_sha256={} ledger_sha256={} raw_sha256={} rendered_sha256={} resources_sha256={}",
            self.index,
            task4_hash(&manifest_bytes),
            task4_hash(&ledger),
            task4_hash(&raw),
            task4_hash(&rendered),
            task4_hash(&resources_bytes)
        );
        Ok(())
    }
}

fn task4_validate_resource_samples(case: &str, samples: &[serde_json::Value]) -> Result<()> {
    let phases: &[&str] = if case == "highslot-exec" {
        &["baseline", "post_attach", "post_rebind", "pre_detach"]
    } else {
        &["baseline", "post_attach", "pre_detach"]
    };
    ensure!(
        samples.len() == phases.len(),
        "Task 4 FD phases missing or duplicated"
    );
    let mut limit = None;
    let mut previous_time = 0_u128;
    for (sample, &phase) in samples.iter().zip(phases) {
        ensure!(
            sample["phase"].as_str() == Some(phase),
            "Task 4 FD phase order changed"
        );
        let count = sample["fd_count"].as_u64().context("FD count")?;
        let soft = sample["soft"].as_u64().context("RLIMIT_NOFILE soft")?;
        let hard = sample["hard"].as_u64().context("RLIMIT_NOFILE hard")?;
        let time: u128 = sample["timestamp_ns"]
            .as_str()
            .context("FD sample timestamp")?
            .parse()?;
        ensure!(
            count > 0 && count <= soft && soft <= hard && time >= previous_time,
            "invalid Task 4 FD occupancy/limit sample"
        );
        if let Some(original) = limit {
            ensure!(
                original == (soft, hard),
                "Task 4 FD limit changed during case"
            );
        } else {
            limit = Some((soft, hard));
        }
        previous_time = time;
    }
    Ok(())
}

fn task4_synthetic_terminal(calls: u64) -> serde_json::Value {
    serde_json::json!({
        "kind":"terminal","phase":"terminal","ring_loss":0,
        "raw_calls":calls,"rendered":calls,"pending":0,"orphan_ops":0,"unmatched_closes":0,
        "kernel":{
            "ring_loss":0,"start_insert_failures":0,"unmatched_returns":0,
            "rv_update_failures":0,"cgroup_scope_failures":0,"semantic_capture_failures":0,
            "template_tail_failures":0,"unregistered_mechanisms":0,"abi_refusals":0
        },
        "discovery":{
            "ring_loss":0,"export_state_failures":0,"export_bounded_read_failures":0,
            "loader_hits":0,"loader_state_read_failures":0,"abi_refusals":0
        }
    })
}

#[test]
fn task4_file_replay_rejects_swapped_physical_calls_and_changed_rendering() -> Result<()> {
    let offsets = serde_json::to_vec(&serde_json::json!([
        {"dev":1,"ino":2,"offset":64}, {"dev":1,"ino":2,"offset":80}
    ]))?;
    let mut ledger = Vec::new();
    ledger.push(serde_json::json!({"kind":"barrier","phase":"pre_go","reply":"GO 77"}));
    let mut raw = Vec::new();
    let mut rendered = Vec::new();
    for position in 0..4 {
        let slot = position / 2;
        let rv = if position % 2 == 0 { 0_u64 } else { 5 };
        let input = rv.wrapping_sub(slot as u64);
        ledger.push(
            serde_json::json!({"kind":"call","phase":"after_go", "position":position,
            "slot":slot,"input":input,"rv":rv,
            "reply":format!("RETURNED {slot} {input} {rv}")}),
        );
        raw.push(
            serde_json::json!({"kind":"call","phase":"after_go", "position":position,
            "slot":slot,"rv":rv,"pid_tgid":(77_u64<<32)|77,
            "event_type":event_type::CALL,"image":{"task_cookie":1,"exec_id":0},
            "dev":1,"ino":2,"offset":if slot == 0 {64} else {80},
            "ts_ns":position+1,"duration_ns":1}),
        );
        let rv_label = pkcs11_types::CkRv(rv).to_string();
        let rv_label = rv_label.split(" (").next().unwrap_or(&rv_label);
        rendered.extend_from_slice(
            format!("owned_{slot} [semantics unverified] → {rv_label} \n").as_bytes(),
        );
    }
    for slot in 0..2 {
        raw.push(
            serde_json::json!({"kind":"stats","phase":"after_go","slot":slot,
            "entered":2,"returned":2,"errors":1,"in_flight":0}),
        );
        for rv in [0, 5] {
            raw.push(
                serde_json::json!({"kind":"rv","phase":"after_go","slot":slot,
                "rv":rv,"count":1}),
            );
        }
    }
    let lines = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    let ledger_bytes = lines(&ledger)?;
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&raw)?,
            &rendered,
            &offsets
        )
        .is_err(),
        "replay accepted per-ID rows without terminal reducer/loss observation"
    );
    raw.push(task4_synthetic_terminal(4));
    let raw_bytes = lines(&raw)?;
    ensure!(
        task4_replay_files("detailed", &ledger_bytes, &raw_bytes, &rendered, &offsets)? == (4, 4)
    );
    raw.swap(0, 2);
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&raw)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    raw.swap(0, 2);
    let mut missing = raw.clone();
    missing.pop();
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&missing)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut bad_stats = raw.clone();
    bad_stats
        .iter_mut()
        .find(|row| row["kind"] == "stats")
        .context("STATS row")?["entered"] = serde_json::json!(3);
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&bad_stats)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut bad_rv = raw.clone();
    bad_rv
        .iter_mut()
        .find(|row| row["kind"] == "rv")
        .context("RV row")?["count"] = serde_json::json!(2);
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&bad_rv)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut bad_physical = raw.clone();
    bad_physical[0]["offset"] = serde_json::json!(80);
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&bad_physical)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut changed = rendered;
    changed[6] = b'9';
    assert!(task4_replay_files("detailed", &ledger_bytes, &raw_bytes, &changed, &offsets).is_err());
    Ok(())
}

#[test]
fn task4_inventory_replay_requires_observed_repeat_snapshot() -> Result<()> {
    let offsets = serde_json::to_vec(&serde_json::json!([
        {"dev":1,"ino":2,"offset":64},{"dev":1,"ino":2,"offset":80}
    ]))?;
    let mut ledger = vec![serde_json::json!({"kind":"barrier","phase":"after_go","reply":"GO 77"})];
    for (position, slot) in [0_u64, 1, 511, 512, 999, 2047, 2048, 2111]
        .into_iter()
        .enumerate()
    {
        let input = 0_u64.wrapping_sub(slot);
        ledger.push(serde_json::json!({"kind":"call","phase":if position < 2 {"after_go"} else {"after_repeat"},
            "position":position,"slot":slot,"input":input,"rv":0,
            "reply":format!("RETURNED {slot} {input} 0")}));
    }
    let mut raw = Vec::new();
    for (phase, value) in [
        ("pre_go", 0),
        ("after_go", 1),
        ("after_repeat", 1),
        ("terminal", 1),
    ] {
        for slot in 0..2 {
            raw.push(serde_json::json!({"kind":"usage","phase":phase,"slot":slot,"value":value}));
        }
    }
    let lines = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    let ledger_bytes = lines(&ledger)?;
    assert!(
        task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets).is_err(),
        "replay accepted map cells without independent repeat snapshot metadata"
    );
    for (phase, positive, newly) in [
        ("pre_go", 0, vec![]),
        ("after_go", 2, vec![0, 1]),
        ("after_repeat", 2, vec![]),
        ("terminal", 2, vec![]),
    ] {
        raw.push(
            serde_json::json!({"kind":"usage_phase","phase":phase,"cells_read":2,
            "positive_count":positive,"newly_positive":newly}),
        );
    }
    raw.push(serde_json::json!({"kind":"terminal","phase":"terminal",
        "usage_positive":2,"terminal_unsettled":true,
        "usage_integrity_failures":0,"usage_read_failures":0}));
    ensure!(
        task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets)? == (8, 0)
    );
    raw.iter_mut()
        .find(|row| row["kind"] == "usage_phase" && row["phase"] == "after_repeat")
        .context("repeat phase")?["newly_positive"] = serde_json::json!([511]);
    assert!(task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets).is_err());
    Ok(())
}

#[test]
fn task4_resource_samples_require_all_phases_and_stable_limit() -> Result<()> {
    let sample = |phase: &str, count: u64, soft: u64| {
        serde_json::json!({
            "phase":phase,"fd_count":count,"soft":soft,"hard":8192,"timestamp_ns":"100"
        })
    };
    let complete = vec![
        sample("baseline", 10, 8192),
        sample("post_attach", 4230, 8192),
        sample("pre_detach", 4230, 8192),
    ];
    task4_validate_resource_samples("detailed", &complete)?;
    assert!(task4_validate_resource_samples("detailed", &complete[..2]).is_err());
    let mut changed = complete;
    changed[2]["soft"] = serde_json::json!(4096);
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    Ok(())
}

#[test]
fn task4_highslot_replay_requires_old_worker_start_and_new_image() -> Result<()> {
    let offsets = serde_json::to_vec(
        &(0..2_049)
            .map(|slot| {
                serde_json::json!({
                    "dev":1,"ino":2,"offset":slot*8
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let lines = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    for (case, rv) in [("highslot-exit", 0_u64), ("highslot-exec", 5)] {
        let input = rv.wrapping_sub(2048);
        let ledger = lines(&[
            serde_json::json!({"kind":"barrier","phase":"pre_go","reply":"READY 77"}),
            serde_json::json!({"kind":"barrier","phase":"after_go","reply":"GO 77"}),
            serde_json::json!({"kind":"barrier","phase":"old_held","reply":"WORKER 2048 78"}),
            serde_json::json!({"kind":"call","phase":"successor_completed","position":0,
                "slot":2048,"input":input,"rv":rv,"reply":format!("RETURNED 2048 {input} {rv}")}),
        ])?;
        let image = serde_json::json!({"task_cookie":1,"exec_id":if rv==5 {1} else {0}});
        let mut raw = vec![serde_json::json!({
            "kind":"call","phase":"successor_completed","position":0,"slot":2048,"rv":rv,
            "event_type":event_type::CALL,"pid_tgid":(77_u64<<32)|77,"image":image,
            "dev":1,"ino":2,"offset":2048*8,"ts_ns":10,"duration_ns":1
        })];
        for (phase, entered, returned, starts, outstanding, abandoned, has_rv) in [
            ("before_go", 0_u64, 0_u64, 0_u64, 0_u64, 0_u64, false),
            ("old_held", 1, 0, 1, 1, 0, false),
            ("old_cleaned_before_rebind", 1, 0, 0, 0, 1, false),
            ("successor_completed", 2, 1, 0, 0, 1, true),
            ("terminal", 2, 1, 0, 0, 1, true),
        ] {
            let held = if phase == "old_held" {
                serde_json::json!({
                    "slot":2048,"pid_tgid":(77_u64<<32)|78,"ts_ns":5,
                    "image":{"task_cookie":1,"exec_id":0}
                })
            } else {
                serde_json::Value::Null
            };
            raw.push(
                serde_json::json!({"kind":"state","phase":phase,"starts":starts,
                "owner_outstanding":outstanding,"abandoned":abandoned,
                "rv_rows":u64::from(has_rv),"held_start":held}),
            );
            for slot in 0..2_049 {
                let selected = slot == 2_048;
                raw.push(serde_json::json!({"kind":"stats","phase":phase,"slot":slot,
                    "entered":if selected {entered} else {0},
                    "returned":if selected {returned} else {0},
                    "errors":if selected && has_rv && rv==5 {1} else {0},
                    "unreturned":if selected {entered-returned} else {0},
                    "in_flight":if selected {starts} else {0}}));
            }
            if has_rv {
                raw.push(
                    serde_json::json!({"kind":"rv","phase":phase,"slot":2048,"rv":rv,"count":1}),
                );
            }
        }
        raw.push(task4_synthetic_terminal(1));
        let rv_label = pkcs11_types::CkRv(rv).to_string();
        let rv_label = rv_label.split(" (").next().unwrap_or(&rv_label);
        let rendered = format!("owned_2048 [semantics unverified] → {rv_label} \n");
        ensure!(
            task4_replay_files(case, &ledger, &lines(&raw)?, rendered.as_bytes(), &offsets)?
                == (1, 1)
        );
        raw.iter_mut()
            .find(|row| row["kind"] == "state" && row["phase"] == "old_cleaned_before_rebind")
            .context("cleaned state")?["held_start"] = serde_json::json!({"slot":2048});
        assert!(
            task4_replay_files(case, &ledger, &lines(&raw)?, rendered.as_bytes(), &offsets)
                .is_err()
        );
    }
    Ok(())
}

fn task4_jsonl(bytes: &[u8]) -> Result<Vec<serde_json::Value>> {
    ensure!(bytes.len() <= TASK4_FILE_LIMIT && bytes.last() == Some(&b'\n'));
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(anyhow::Error::from))
        .collect()
}

fn task4_replay_files(
    case: &str,
    ledger_bytes: &[u8],
    raw_bytes: &[u8],
    rendered_bytes: &[u8],
    offsets_bytes: &[u8],
) -> Result<(usize, usize)> {
    let ledger = task4_jsonl(ledger_bytes)?;
    let raw = task4_jsonl(raw_bytes)?;
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    ensure!(!offsets.is_empty());
    let calls: Vec<_> = ledger.iter().filter(|row| row["kind"] == "call").collect();
    let events: Vec<_> = raw.iter().filter(|row| row["kind"] == "call").collect();
    let expected_calls = match case {
        "inventory" => offsets.len() + 6,
        "detailed" => offsets.len() * 2,
        "highslot-exit" | "highslot-exec" => 1,
        _ => bail!("unknown Task 4 evidence case {case}"),
    };
    let expected_raw_rows = match case {
        "inventory" => 4 * (offsets.len() + 1) + 1,
        "detailed" => 5 * offsets.len() + 1,
        "highslot-exit" | "highslot-exec" => 5 * (offsets.len() + 1) + 4,
        _ => unreachable!(),
    };
    ensure!(
        raw.len() == expected_raw_rows,
        "replay raw row count changed"
    );
    let terminal: Vec<_> = raw
        .iter()
        .filter(|row| row["kind"] == "terminal" && row["phase"] == "terminal")
        .collect();
    ensure!(terminal.len() == 1, "replay lacks one terminal observation");
    let terminal = terminal[0];
    if case == "inventory" {
        ensure!(
            terminal["usage_positive"].as_u64() == Some(offsets.len() as u64)
                && terminal["terminal_unsettled"].as_bool() == Some(true)
                && terminal["usage_integrity_failures"].as_u64() == Some(0)
                && terminal["usage_read_failures"].as_u64() == Some(0),
            "replay Inventory terminal state changed"
        );
    } else {
        ensure!(
            terminal["ring_loss"].as_u64() == Some(0)
                && terminal["raw_calls"].as_u64() == Some(expected_calls as u64)
                && terminal["rendered"].as_u64() == Some(expected_calls as u64)
                && terminal["pending"].as_u64() == Some(0)
                && terminal["orphan_ops"].as_u64() == Some(0)
                && terminal["unmatched_closes"].as_u64() == Some(0),
            "replay Detailed terminal loss/reducer state changed"
        );
        for key in [
            "ring_loss",
            "start_insert_failures",
            "unmatched_returns",
            "rv_update_failures",
            "cgroup_scope_failures",
            "semantic_capture_failures",
            "template_tail_failures",
            "unregistered_mechanisms",
            "abi_refusals",
        ] {
            ensure!(
                terminal["kernel"][key].as_u64() == Some(0),
                "replay terminal kernel evidence {key} changed"
            );
        }
        for key in [
            "ring_loss",
            "export_state_failures",
            "export_bounded_read_failures",
            "loader_hits",
            "loader_state_read_failures",
            "abi_refusals",
        ] {
            ensure!(
                terminal["discovery"][key].as_u64() == Some(0),
                "replay terminal discovery counter {key} changed"
            );
        }
    }
    ensure!(
        calls.len() == expected_calls,
        "replay missing owned child reply"
    );
    for (position, row) in calls.iter().enumerate() {
        let slot = row["slot"].as_u64().context("ledger slot")?;
        let input = row["input"].as_u64().context("ledger input")?;
        let rv = row["rv"].as_u64().context("ledger RV")?;
        ensure!(row["position"].as_u64() == Some(position as u64));
        ensure!(
            row["reply"].as_str() == Some(&format!("RETURNED {slot} {input} {rv}"))
                && input.wrapping_add(slot) == rv,
            "replay owned reply differs from call command"
        );
        let expected = match case {
            "inventory" if position < offsets.len() => (position as u64, 0),
            "inventory" => (
                [511, 512, 999, 2047, 2048, 2111][position - offsets.len()],
                0,
            ),
            "detailed" => ((position / 2) as u64, if position % 2 == 0 { 0 } else { 5 }),
            "highslot-exit" => (2048, 0),
            "highslot-exec" => (2048, 5),
            _ => unreachable!(),
        };
        ensure!(
            (slot, rv) == expected,
            "replay child call order changed at {position}"
        );
    }
    ensure!(
        ledger
            .iter()
            .any(|row| row["reply"].as_str().is_some_and(|s| s.starts_with("GO "))),
        "replay lacks observed post-attach GO barrier"
    );
    if case == "inventory" {
        ensure!(events.is_empty() && rendered_bytes.is_empty());
        for (phase, value) in [
            ("pre_go", 0),
            ("after_go", 1),
            ("after_repeat", 1),
            ("terminal", 1),
        ] {
            let rows: Vec<_> = raw
                .iter()
                .filter(|row| row["kind"] == "usage" && row["phase"] == phase)
                .collect();
            ensure!(
                rows.len() == offsets.len(),
                "replay Inventory {phase} missing per-ID rows"
            );
            for (slot, row) in rows.iter().enumerate() {
                ensure!(
                    row["slot"].as_u64() == Some(slot as u64)
                        && row["value"].as_u64() == Some(value),
                    "replay Inventory {phase} slot {slot} changed"
                );
            }
            let phases: Vec<_> = raw
                .iter()
                .filter(|row| row["kind"] == "usage_phase" && row["phase"] == phase)
                .collect();
            ensure!(
                phases.len() == 1,
                "replay Inventory {phase} lacks one observed snapshot"
            );
            let snapshot = phases[0];
            let expected_new: Vec<usize> = if phase == "after_go" {
                (0..offsets.len()).collect()
            } else {
                Vec::new()
            };
            ensure!(
                snapshot["cells_read"].as_u64() == Some(offsets.len() as u64)
                    && snapshot["positive_count"].as_u64()
                        == Some(if phase == "pre_go" {
                            0
                        } else {
                            offsets.len() as u64
                        })
                    && snapshot["newly_positive"] == serde_json::json!(expected_new),
                "replay Inventory {phase} observed snapshot changed"
            );
        }
    } else {
        ensure!(
            events.len() == calls.len(),
            "replay CALL count differs from child replies"
        );
        let rendered = std::str::from_utf8(rendered_bytes)?;
        ensure!(rendered.ends_with('\n'));
        let rendered_lines: Vec<_> = rendered.lines().collect();
        ensure!(
            rendered_lines.len() == events.len(),
            "replay rendered line count differs"
        );
        let mut pid_tgid = None;
        for (position, row) in events.iter().enumerate() {
            let slot = usize::try_from(row["slot"].as_u64().context("raw CALL slot")?)?;
            let physical = offsets
                .get(slot)
                .context("raw CALL outside physical offsets")?;
            let rv = row["rv"].as_u64().context("raw CALL RV")?;
            ensure!(
                row["position"].as_u64() == Some(position as u64)
                    && calls[position]["slot"] == row["slot"]
                    && calls[position]["rv"] == row["rv"]
                    && row["event_type"].as_u64() == Some(u64::from(event_type::CALL))
                    && row["dev"] == physical["dev"]
                    && row["ino"] == physical["ino"]
                    && row["offset"] == physical["offset"],
                "replay physical CALL/ledger join changed at {position}"
            );
            let pid = row["pid_tgid"].as_u64().context("raw CALL pid_tgid")?;
            ensure!((pid >> 32) == (pid as u32 as u64) && pid != 0);
            if case == "detailed" {
                ensure!(
                    pid_tgid.get_or_insert(pid) == &pid,
                    "replay Detailed foreign process"
                );
            }
            ensure!(
                row["image"]["task_cookie"]
                    .as_u64()
                    .is_some_and(|cookie| cookie != 0)
            );
            let rv_label = pkcs11_types::CkRv(rv).to_string();
            let rv_label = rv_label.split(" (").next().unwrap_or(&rv_label);
            ensure!(
                rendered_lines[position].contains(&format!(
                    "owned_{slot} [semantics unverified] → {rv_label} "
                )),
                "replay rendered slot/RV differs at {position}"
            );
        }
        if case == "detailed" {
            let stats: Vec<_> = raw
                .iter()
                .filter(|row| row["kind"] == "stats" && row["phase"] == "after_go")
                .collect();
            let rvs: Vec<_> = raw
                .iter()
                .filter(|row| row["kind"] == "rv" && row["phase"] == "after_go")
                .collect();
            ensure!(stats.len() == offsets.len() && rvs.len() == offsets.len() * 2);
            for (slot, row) in stats.iter().enumerate() {
                ensure!(
                    row["slot"].as_u64() == Some(slot as u64)
                        && row["entered"].as_u64() == Some(2)
                        && row["returned"].as_u64() == Some(2)
                        && row["errors"].as_u64() == Some(1)
                        && row["in_flight"].as_u64() == Some(0),
                    "replay Detailed STATS[{slot}] changed"
                );
            }
            for (position, row) in rvs.iter().enumerate() {
                ensure!(
                    row["slot"].as_u64() == Some((position / 2) as u64)
                        && row["rv"].as_u64() == Some(if position % 2 == 0 { 0 } else { 5 })
                        && row["count"].as_u64() == Some(1),
                    "replay Detailed RV row {position} changed"
                );
            }
        } else {
            let phases = [
                ("before_go", 0, 0, 0, 0, 0, false),
                ("old_held", 1, 0, 1, 1, 0, false),
                ("old_cleaned_before_rebind", 1, 0, 0, 0, 1, false),
                ("successor_completed", 2, 1, 0, 0, 1, true),
                ("terminal", 2, 1, 0, 0, 1, true),
            ];
            let worker = ledger
                .iter()
                .filter_map(|row| row["reply"].as_str())
                .find_map(|reply| reply.strip_prefix("WORKER 2048 "))
                .context("replay high-slot worker receipt")?
                .parse::<u32>()?;
            let mut old_image = None;
            for (phase, entered, returned, starts, outstanding, abandoned, has_rv) in phases {
                let states: Vec<_> = raw
                    .iter()
                    .filter(|row| row["kind"] == "state" && row["phase"] == phase)
                    .collect();
                ensure!(
                    states.len() == 1,
                    "replay high-slot {phase} state cardinality"
                );
                let state = states[0];
                ensure!(
                    state["starts"].as_u64() == Some(starts)
                        && state["owner_outstanding"].as_u64() == Some(outstanding)
                        && state["abandoned"].as_u64() == Some(abandoned)
                        && state["rv_rows"].as_u64() == Some(u64::from(has_rv)),
                    "replay high-slot {phase} owner/START/RV state changed"
                );
                if phase == "old_held" {
                    let held = &state["held_start"];
                    ensure!(
                        held["slot"].as_u64() == Some(2048)
                            && held["pid_tgid"].as_u64()
                                == Some(
                                    (events[0]["pid_tgid"].as_u64().context("successor PID")?
                                        & !0xffff_ffff)
                                        | u64::from(worker)
                                )
                            && held["image"]["task_cookie"]
                                .as_u64()
                                .is_some_and(|n| n != 0),
                        "replay old held START is not owned worker frame"
                    );
                    old_image = Some(held["image"].clone());
                } else {
                    ensure!(
                        state["held_start"].is_null(),
                        "replay high-slot stale START at {phase}"
                    );
                }
                let stats: Vec<_> = raw
                    .iter()
                    .filter(|row| row["kind"] == "stats" && row["phase"] == phase)
                    .collect();
                ensure!(
                    stats.len() == offsets.len(),
                    "replay high-slot {phase} missing per-ID STATS"
                );
                for (slot, row) in stats.iter().enumerate() {
                    let expected = if slot == 2048 {
                        (
                            entered,
                            returned,
                            if has_rv && case == "highslot-exec" {
                                1
                            } else {
                                0
                            },
                        )
                    } else {
                        (0, 0, 0)
                    };
                    ensure!(
                        row["slot"].as_u64() == Some(slot as u64)
                            && row["entered"].as_u64() == Some(expected.0)
                            && row["returned"].as_u64() == Some(expected.1)
                            && row["errors"].as_u64() == Some(expected.2)
                            && row["unreturned"].as_u64() == Some(expected.0 - expected.1)
                            && row["in_flight"].as_u64()
                                == Some(if slot == 2048 { starts } else { 0 }),
                        "replay high-slot {phase} STATS[{slot}] changed"
                    );
                }
                let rvs: Vec<_> = raw
                    .iter()
                    .filter(|row| row["kind"] == "rv" && row["phase"] == phase)
                    .collect();
                ensure!(
                    rvs.len() == usize::from(has_rv),
                    "replay high-slot {phase} RV rows changed"
                );
                if has_rv {
                    ensure!(
                        rvs[0]["slot"].as_u64() == Some(2048)
                            && rvs[0]["rv"].as_u64()
                                == Some(if case == "highslot-exec" { 5 } else { 0 })
                            && rvs[0]["count"].as_u64() == Some(1)
                    );
                }
            }
            let old = old_image.context("missing held START image")?;
            let new = &events[0]["image"];
            if case == "highslot-exec" {
                ensure!(
                    new != &old
                        && new["exec_id"].as_u64()
                            == old["exec_id"].as_u64().and_then(|n| n.checked_add(1)),
                    "replay nonleader exec image did not advance"
                );
            } else {
                ensure!(new == &old, "replay worker-exit image changed");
            }
        }
    }
    Ok((calls.len(), events.len()))
}

#[test]
fn task4_rendered_digest_is_sha256_of_exact_lines() {
    let mut digest = Sha256::new();
    digest.update(b"alpha\n");
    assert_eq!(
        task4_digest_hex(digest.finalize()),
        "b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060"
    );
}

fn task4_fixture_receipt(fixture: &OwnedFixture) -> Result<()> {
    let directory = PathBuf::from(
        std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR")
            .context("P11SCOPE_TASK4_EVIDENCE_DIR is required for a live Task 4 gate")?,
    );
    let index: usize = std::env::var("P11SCOPE_TASK4_CASE_INDEX")
        .context("P11SCOPE_TASK4_CASE_INDEX is required")?
        .parse()?;
    ensure!(
        index < 100,
        "Task 4 case index exceeds evidence naming bound"
    );
    let metadata = std::fs::metadata(&fixture.path)?;
    let elf = std::fs::read(&fixture.path)?;
    ensure!(
        task4_hash(&elf) == fixture.expected_sha256,
        "fixture ELF changed after pinning"
    );
    verify_task4_physical_slots(&fixture.plan.slots, fixture.plan.slots.len())?;
    let offsets: Vec<_> = fixture
        .plan
        .slots
        .iter()
        .map(|slot| {
            serde_json::json!({
                "dev": metadata.dev(), "ino": metadata.ino(), "offset": slot.file_offset,
            })
        })
        .collect();
    let keys: BTreeSet<_> = fixture
        .plan
        .slots
        .iter()
        .map(|slot| slot.file_offset)
        .collect();
    ensure!(
        keys.len() == offsets.len(),
        "fixture offset alias before evidence copy"
    );
    let offsets_bytes = serde_json::to_vec(&offsets)?;
    std::fs::write(directory.join(format!("fixture-{index:02}.elf")), &elf)?;
    std::fs::write(
        directory.join(format!("offsets-{index:02}.json")),
        &offsets_bytes,
    )?;
    eprintln!(
        "TASK4_FIXTURE elf_sha256={} offsets_sha256={}",
        task4_hash(&elf),
        task4_hash(&offsets_bytes)
    );
    eprintln!(
        "TASK4_PHYSICAL endpoints={} unique_offsets=true",
        offsets.len()
    );
    Ok(())
}

fn task4_inventory_usage(
    evidence: &mut Task4Evidence,
    ebpf: &aya::Ebpf,
    phase: &str,
    n: u32,
) -> Result<()> {
    let usage: Array<_, u64> = Array::try_from(ebpf.map("USAGE").context("USAGE evidence map")?)?;
    for slot in 0..n {
        let value = usage.get(&slot, 0)?;
        evidence.raw_row(serde_json::json!({
            "kind":"usage","phase":phase,"slot":slot,"value":value
        }))?;
    }
    Ok(())
}

fn verify_task4_physical_slots(slots: &[Slot], expected: usize) -> Result<()> {
    ensure!(
        slots.len() == expected,
        "owned fixture is missing a physical tail endpoint"
    );
    let mut physical = BTreeSet::new();
    for (id, slot) in slots.iter().enumerate() {
        ensure!(
            slot.index as usize == id,
            "owned fixture has a missing or duplicated slot index"
        );
        ensure!(
            physical.insert((slot.object, slot.file_offset)),
            "owned fixture aliases two physical offsets"
        );
    }
    ensure!(physical.len() == expected);
    Ok(())
}

#[test]
fn task4_physical_slot_oracle_rejects_alias_and_missing_tail() -> Result<()> {
    let fixture = OwnedFixture::build_n(false, 2_049)?;
    let mut slots = fixture.plan.slots.clone();
    verify_task4_physical_slots(&slots, 2_049)?;
    slots[2_048].file_offset = slots[2_047].file_offset;
    assert!(verify_task4_physical_slots(&slots, 2_049).is_err());
    slots[2_048].file_offset = fixture.plan.slots[2_048].file_offset;
    slots.pop();
    assert!(verify_task4_physical_slots(&slots, 2_049).is_err());
    Ok(())
}

fn task4_ids_receipt(ids: &OwnedIds) {
    let csv = task4_ids_csv;
    eprintln!(
        "TASK4_OWNED_IDS maps={} programs={} links={}",
        csv(&ids.maps),
        csv(&ids.programs),
        csv(&ids.links)
    );
}

fn task4_ids_csv(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn task4_ids_phase(phase: &str, ids: &OwnedIds) {
    eprintln!(
        "TASK4_IDS_PHASE phase={phase} maps={} programs={} links={}",
        task4_ids_csv(&ids.maps),
        task4_ids_csv(&ids.programs),
        task4_ids_csv(&ids.links)
    );
}

fn wide_inventory_gate() -> Result<()> {
    const N: u32 = 2_112;
    let origin = Instant::now();
    eprintln!(
        "TASK4_PROFILE name={} detailed_slots={} rv_keys={} inventory_budget=2112",
        if cfg!(feature = "wide-detailed-2112") {
            "wide-detailed-2112"
        } else {
            "default"
        },
        p11scope_ebpf_common::MAX_SLOTS,
        p11scope_ebpf_common::RV_ENTRIES
    );
    let mut fixture = OwnedFixture::build_n(false, N)?;
    verify_task4_physical_slots(&fixture.plan.slots, N as usize)?;
    task4_fixture_receipt(&fixture)?;
    let profile = if cfg!(feature = "wide-detailed-2112") {
        "wide-detailed-2112"
    } else {
        "default"
    };
    let mut evidence =
        Task4Evidence::new("inventory", profile, &fixture, crate::EBPF_INVENTORY_OBJECT)?;
    evidence.fd_sample("baseline")?;
    let targets = fixture.targets()?;
    let budget =
        InventoryBudget::new(u64::from(N), 8 * u64::from(N)).map_err(anyhow::Error::msg)?;
    let prepare_start = Instant::now();
    let prepared = PreparedInventory::prepare(Scope::System, budget, AttachBackend::Singles)?;
    let prepare_ms = prepare_start.elapsed().as_millis();
    let usage_data =
        super::super::inventory_map_data("USAGE", prepared.ebpf.map("USAGE").context("USAGE")?)?.1;
    let usage_meta = super::super::super::read_map_metadata("USAGE", usage_data)?;
    ensure!(
        usage_meta.max_entries == N && usage_meta.value_size == 8,
        "wrong loaded USAGE map"
    );
    for absent in ["START", "RV_COUNTS", "EVENTS"] {
        ensure!(
            prepared.ebpf.map(absent).is_none(),
            "Inventory loaded {absent}"
        );
    }
    eprintln!(
        "TASK4_LOADED_OBJECT kind=inventory-global.elf sha256={}",
        task4_hash(crate::EBPF_INVENTORY_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS USAGE=2112 START=absent RV_COUNTS=absent EVENTS=absent");
    let registry_start = Instant::now();
    let mut ids = OwnedIds::prepared(&prepared)?;
    let registry_ms = registry_start.elapsed().as_millis();
    let attach_start = Instant::now();
    let mut active = prepared
        .activate(targets)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let attach_ms = attach_start.elapsed().as_millis();
    ids.inspect_links(&active.state, N as usize)?;
    ensure!(
        ids.links.len() == N as usize + 2,
        "incomplete Inventory link set"
    );
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_attach")?;
    eprintln!(
        "TASK4_PHASE prepare_ms={prepare_ms} attach_ms={attach_ms} registry_ms={registry_ms} probes=2112"
    );
    fixture.pins = PinnedObjects::empty();
    let window =
        || InventoryReadWindow::new(N as usize, Instant::now() + Duration::from_secs(60)).unwrap();
    let zero = active.usage_snapshot(window());
    assert_health(&zero)?;
    ensure!(
        zero.usage.cells_read == N as usize && zero.usage.positive_count == 0,
        "Inventory was positive before GO or missed initial cells"
    );
    evidence.inventory_snapshot("pre_go", &zero)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "pre_go", N)?;
    let mut caller = fixture.spawn_gated()?;
    evidence.caller(&mut caller, "pre_go")?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_EXEC)?;
    caller.go()?;
    evidence.caller(&mut caller, "after_go")?;
    for id in 0..N {
        caller.call_exact(id, 0)?;
        if id % 64 == 63 {
            evidence.caller(&mut caller, "after_go")?;
        }
    }
    evidence.caller(&mut caller, "after_go")?;
    eprintln!("TASK4_LEDGER phase=after_go physical_ids={N} completed_calls={N} first=0 tail=2111");
    let positive = active.usage_snapshot(window());
    assert_health(&positive)?;
    ensure!(
        positive.usage.cells_read == N as usize && positive.usage.positive_count == N as usize,
        "Inventory did not read every cell positive"
    );
    ensure!(
        positive.usage.newly_positive == (0..N).collect::<Vec<_>>(),
        "Inventory per-ID set differs from owned workload ledger"
    );
    evidence.inventory_snapshot("after_go", &positive)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "after_go", N)?;
    eprintln!("TASK4_RAW_MAPS phase=after_go usage_positive={N} exact_ids=0..2111");
    for id in [511, 512, 999, 2_047, 2_048, 2_111] {
        caller.call_exact(id, 0)?;
        evidence.caller(&mut caller, "after_repeat")?;
    }
    let repeated = active.usage_snapshot(window());
    assert_health(&repeated)?;
    ensure!(
        repeated.usage.cells_read == N as usize
            && repeated.usage.positive_count == N as usize
            && repeated.usage.newly_positive.is_empty(),
        "Inventory repeated calls changed the latched all-ID set"
    );
    evidence.inventory_snapshot("after_repeat", &repeated)?;
    task4_inventory_usage(
        &mut evidence,
        &active.state.prepared.ebpf,
        "after_repeat",
        N,
    )?;
    eprintln!("TASK4_REPEAT ids=511,512,999,2047,2048,2111 completed_calls=6 newly_positive=0");
    caller.finish()?;
    evidence.caller(&mut caller, "after_repeat")?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    evidence.fd_sample("pre_detach")?;
    let stop_start = Instant::now();
    let mut retiring = active.begin_stop();
    finish_owned_retirement_inner(&mut retiring, true, Duration::from_secs(420))?;
    let stop_ms = stop_start.elapsed().as_millis();
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("wide retirement did not finish"))?;
    ensure!(
        retired.cleanup.closed == N as usize + 2 && retired.cleanup.failures.is_empty(),
        "Inventory retirement omitted owned links"
    );
    let terminal = retired.usage_snapshot(window());
    assert_health(&terminal)?;
    ensure!(
        terminal.usage.cells_read == N as usize
            && terminal.usage.positive_count == N as usize
            && terminal.usage.newly_positive.is_empty(),
        "terminal Inventory map/health differs from all-ID positive ledger"
    );
    evidence.inventory_snapshot("terminal", &terminal)?;
    task4_inventory_usage(&mut evidence, &retired.state.prepared.ebpf, "terminal", N)?;
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal",
        "usage_positive":terminal.usage.positive_count,
        "terminal_unsettled":terminal.terminal_unsettled,
        "usage_integrity_failures":terminal.usage_integrity_failures,
        "usage_read_failures":terminal.usage_read_failures,
        "health":format!("{:?}",terminal.health)
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal inventory_positive=2112 exact_physical_ids=true ordinary_return_maps=absent"
    );
    drop(retired);
    let release_start = Instant::now();
    ids.released_with_budget(Duration::from_secs(60))?;
    let release_ms = release_start.elapsed().as_millis();
    eprintln!("TASK4_LOSS ring=0 usage=0 owner=0");
    evidence.finish()?;
    eprintln!(
        "TASK4_TIMING links={} prepare_ms={prepare_ms} attach_ms={attach_ms} stop_ms={stop_ms} registry_ms={registry_ms} release_ms={release_ms} elapsed_ms={}",
        N + 2,
        origin.elapsed().as_millis()
    );
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; 2112 distinct physical Inventory entry probes and exact all-ID ledger"]
fn privileged_task4_inventory_2112_lp64() -> Result<()> {
    wide_inventory_gate()
}

fn drain_task4_detailed(
    session: &mut crate::attach::Session,
    events: &mut Vec<Event>,
) -> Result<()> {
    let drain = session.event_drain()?;
    for _ in 0..64 {
        let more = drain.poll(Some(256), |event| {
            events.push(event);
            ControlFlow::Continue(())
        });
        ensure!(
            events.len() <= 4_224,
            "unexpected extra Detailed CALL record"
        );
        if !more {
            ensure!(drain.malformed() == 0, "malformed Detailed event");
            return Ok(());
        }
    }
    bail!("Detailed ring did not empty within bounded drain")
}

fn verify_task4_call_sequence(rows: &[(u32, u64)]) -> Result<()> {
    ensure!(
        rows.len() == 4_224,
        "Detailed CALL sequence length differs from owned ledger"
    );
    for (position, &(slot, rv)) in rows.iter().enumerate() {
        let expected = (position / 2) as u32;
        let expected_rv = if position % 2 == 0 { 0 } else { 5 };
        ensure!(
            (slot, rv) == (expected, expected_rv),
            "Detailed completed CALL at position {position} disagrees with independent command/return ledger: slot={slot} rv={rv}, expected slot={expected} rv={expected_rv}"
        );
    }
    Ok(())
}

fn verify_task4_event_identity(
    event: &Event,
    pid: u32,
    image: Option<ImageIdentity>,
) -> Result<ImageIdentity> {
    ensure!(
        event.event_type == event_type::CALL,
        "non-CALL event in owned trace"
    );
    ensure!(
        event.pid_tgid == (u64::from(pid) << 32 | u64::from(pid)),
        "foreign process or worker event in owned trace"
    );
    ensure!(
        event.image.task_cookie != 0,
        "owned event lacks image provenance"
    );
    if let Some(expected) = image {
        ensure!(
            event.image == expected,
            "owned event has stale or changed image identity"
        );
    }
    Ok(event.image)
}

#[test]
fn task4_event_identity_rejects_foreign_traffic_and_stale_image() {
    let mut event = Event {
        event_type: event_type::CALL,
        pid_tgid: (77u64 << 32) | 77,
        image: ImageIdentity {
            task_cookie: 1,
            ..ImageIdentity::default()
        },
        ..Event::default()
    };
    assert!(verify_task4_event_identity(&event, 77, None).is_ok());
    assert!(verify_task4_event_identity(&event, 78, None).is_err());
    event.pid_tgid = (77u64 << 32) | 78;
    assert!(verify_task4_event_identity(&event, 77, None).is_err());
    event.pid_tgid = (77u64 << 32) | 77;
    let old_image = event.image;
    event.image.task_cookie = 2;
    assert!(verify_task4_event_identity(&event, 77, Some(old_image)).is_err());
    event.image.task_cookie = 0;
    assert!(verify_task4_event_identity(&event, 77, None).is_err());
}

#[test]
fn task4_call_sequence_rejects_swapped_physical_cookie_even_with_equal_aggregate_rvs() {
    let mut rows: Vec<_> = (0..2_112).flat_map(|slot| [(slot, 0), (slot, 5)]).collect();
    assert!(verify_task4_call_sequence(&rows).is_ok());
    rows.swap(0, 2);
    rows.swap(1, 3);
    assert!(verify_task4_call_sequence(&rows).is_err());
    let mut rows: Vec<_> = (0..2_112).flat_map(|slot| [(slot, 0), (slot, 5)]).collect();
    rows.pop();
    assert!(verify_task4_call_sequence(&rows).is_err());
    rows.push((2_110, 5));
    assert!(verify_task4_call_sequence(&rows).is_err());
    rows[0] = (2_111, 0);
    assert!(verify_task4_call_sequence(&rows).is_err());
    rows[0] = (0, 5);
    assert!(verify_task4_call_sequence(&rows).is_err());
}

fn assert_task4_detailed_maps(session: &crate::attach::Session, completed: bool) -> Result<()> {
    let expected = if completed { 2 } else { 0 };
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    for id in 0..2_112 {
        let mut total = SlotStats::ZERO;
        for cpu in stats.get(&id, 0)?.iter() {
            total.entered += cpu.entered;
            total.returned += cpu.returned;
            total.errors += cpu.errors;
        }
        ensure!(
            (total.entered, total.returned, total.errors) == (expected, expected, expected / 2),
            "slot {id} raw STATS mismatch: entered={} returned={} errors={}",
            total.entered,
            total.returned,
            total.errors
        );
    }
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("START")?)?;
    ensure!(
        starts.iter().next().is_none(),
        "Detailed START debt remains"
    );
    let owner: Array<_, ThreadOwnerControl> =
        Array::try_from(session.ebpf.map("OWNER_CTL").context("OWNER_CTL")?)?;
    let control = owner.get(&0, 0)?;
    ensure!(
        crate::attach::owner_control_fields(control) == [THREAD_OWNER_LIMIT, 0, 0, 0, 0, 0, 0],
        "Detailed owner debt or failure: {control:?}"
    );
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let mut seen = BTreeMap::new();
    for entry in rvs.iter() {
        let (key, counts) = entry?;
        ensure!(
            key.slot < 2_112 && key._pad == 0 && [0, 5].contains(&key.rv),
            "foreign or malformed Detailed RV key: slot={} rv={} pad={}",
            key.slot,
            key.rv,
            key._pad
        );
        ensure!(
            seen.insert((key.slot, key.rv), counts.iter().sum::<u64>())
                .is_none(),
            "duplicate Detailed RV key"
        );
    }
    ensure!(
        seen.len() == if completed { 4_224 } else { 0 },
        "Detailed RV key cardinality"
    );
    for id in 0..2_112 {
        for rv in [0, 5] {
            ensure!(
                seen.get(&(id, rv)).copied().unwrap_or(0) == u64::from(completed),
                "missing or doubled raw RV row for slot {id} rv {rv}"
            );
        }
    }
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE")?)?;
    for index in 0..EVIDENCE_CELLS {
        ensure!(
            evidence.get(&index, 0)?.iter().sum::<u64>() == 0,
            "Detailed EVIDENCE[{index}] was nonzero"
        );
    }
    ensure!(
        session.counter_snapshot()? == crate::attach::CounterSnapshot::default(),
        "Detailed discovery or identity loss"
    );
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
fn task4_detailed_rows(
    session: &crate::attach::Session,
    evidence: &mut Task4Evidence,
) -> Result<()> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    for slot in 0..2_112 {
        let mut entered = 0_u64;
        let mut returned = 0_u64;
        let mut errors = 0_u64;
        for cpu in stats.get(&slot, 0)?.iter() {
            entered += cpu.entered;
            returned += cpu.returned;
            errors += cpu.errors;
        }
        evidence.raw_row(serde_json::json!({
            "kind":"stats","phase":"after_go","slot":slot,
            "entered":entered,"returned":returned,"errors":errors,
            "in_flight":entered.saturating_sub(returned)
        }))?;
    }
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let mut rows = BTreeMap::new();
    for entry in rvs.iter() {
        let (key, values) = entry?;
        ensure!(
            rows.insert((key.slot, key.rv), values.iter().sum::<u64>())
                .is_none()
        );
    }
    for ((slot, rv), count) in rows {
        evidence.raw_row(serde_json::json!({
            "kind":"rv","phase":"after_go","slot":slot,"rv":rv,"count":count
        }))?;
    }
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
fn wide_detailed_gate() -> Result<()> {
    let origin = Instant::now();
    eprintln!(
        "TASK4_PROFILE name=wide-detailed-2112 detailed_slots=2112 rv_keys=8192 inventory_budget=2112"
    );
    let fixture = OwnedFixture::build_n(false, 2_112)?;
    verify_task4_physical_slots(&fixture.plan.slots, 2_112)?;
    task4_fixture_receipt(&fixture)?;
    let mut evidence = Task4Evidence::new(
        "detailed",
        "wide-detailed-2112",
        &fixture,
        crate::EBPF_OBJECT,
    )?;
    evidence.fd_sample("baseline")?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    let attach_start = Instant::now();
    let mut session = crate::attach::Session::start(
        &plan,
        &Scope::Pid(caller.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::Allowlisted,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )?;
    let attach_ms = attach_start.elapsed().as_millis();
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 4_224,
        "wide Detailed did not retain every paired static probe"
    );
    ensure!(
        session.lifecycle_tracking_unavailable().is_none()
            && session.process_creation_tracking_unavailable().is_none()
    );
    let map_max = |name| -> Result<u32> {
        let map = session
            .ebpf
            .map(name)
            .with_context(|| format!("{name} map"))?;
        Ok(crate::attach::read_map_metadata(name, detailed_map_data(map)?)?.max_entries)
    };
    ensure!(
        map_max("STATS")? == 2_112 && map_max("RV_COUNTS")? == 8_192 && map_max("START")? == 16_384,
        "wrong loaded wide Detailed map bounds"
    );
    let events_capacity = map_max("EVENTS")?;
    ensure!(events_capacity >= 4_096, "Detailed EVENTS ring too small");
    eprintln!(
        "TASK4_LOADED_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS STATS=2112 RV_COUNTS=8192 START=16384 EVENTS={events_capacity}");
    let registry_start = Instant::now();
    let ids = OwnedIds::detailed(&session)?;
    let registry_ms = registry_start.elapsed().as_millis();
    ensure!(
        ids.links.len() >= 4_224,
        "Detailed retained fewer links than paired probes"
    );
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_attach")?;
    eprintln!("TASK4_PHASE attach_ms={attach_ms} registry_ms={registry_ms} probes=4224");
    assert_task4_detailed_maps(&session, false)?;
    let mut events = Vec::with_capacity(4_224);
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    evidence.caller(&mut caller, "after_go")?;
    for id in 0..2_112 {
        caller.call_exact(id, 0)?;
        caller.call_exact(id, 5)?;
        if id % 32 == 31 {
            evidence.caller(&mut caller, "after_go")?;
            drain_task4_detailed(&mut session, &mut events)?;
        }
    }
    evidence.caller(&mut caller, "after_go")?;
    drain_task4_detailed(&mut session, &mut events)?;
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids=2112 completed_calls=4224 rv0=2112 rv5=2112 first=0 tail=2111"
    );
    assert_task4_detailed_maps(&session, true)?;
    task4_detailed_rows(&session, &mut evidence)?;
    ensure!(
        events.len() == 4_224,
        "Detailed trace event count differs from fixture ledger"
    );
    let mut event_keys = BTreeMap::new();
    let mut sequence = Vec::with_capacity(4_224);
    let mut image = None;
    let mut tracer = crate::trace::Tracer::new(&plan);
    let mut state =
        crate::semantics::State::with_policy(&plan, crate::attach::CapturePolicy::Allowlisted);
    let mut rendered_hash = Sha256::new();
    let mut rendered_count = 0u64;
    for event in &events {
        ensure!(
            event.slot < 2_112 && [0, 5].contains(&event.rv),
            "foreign Detailed event"
        );
        image = Some(verify_task4_event_identity(
            event,
            caller.child.id(),
            image,
        )?);
        *event_keys.entry((event.slot, event.rv)).or_insert(0u32) += 1;
        sequence.push((event.slot, event.rv));
        evidence.event(event, &fixture, "after_go")?;
        tracer.count_raw_call(event);
        let rendered = tracer.on_event(event, &mut state);
        let rv_label = pkcs11_types::CkRv(event.rv).to_string();
        let rv_label = rv_label.split(" (").next().unwrap_or(&rv_label);
        ensure!(
            rendered.contains(&format!(
                "owned_{} [semantics unverified] → {rv_label} ",
                event.slot
            )),
            "Tracer failed to render exact fixture slot and RV without authority: {rendered}"
        );
        rendered_hash.update(rendered.as_bytes());
        rendered_hash.update(b"\n");
        evidence.render(&rendered)?;
        rendered_count += 1;
    }
    verify_task4_call_sequence(&sequence)?;
    ensure!(
        tracer.raw_calls() == 4_224 && rendered_count == 4_224 && event_keys.len() == 4_224,
        "Tracer raw count or distinct event keys differ"
    );
    ensure!(
        state.semantic_evidence() == crate::semantics::SemanticEvidence::default()
            && state.pending_at_end() == 0
            && state.orphan_ops() == 0
            && state.unmatched_closes() == 0,
        "count-only Detailed fixture left reducer debt or semantic loss"
    );
    eprintln!(
        "TASK4_REDUCER raw_calls=4224 rendered=4224 pending=0 semantic_evidence=zero orphan_ops=0 unmatched_closes=0"
    );
    for id in 0..2_112 {
        for rv in [0, 5] {
            ensure!(
                event_keys.get(&(id, rv)) == Some(&1),
                "missing or doubled completed CALL slot {id} rv {rv}"
            );
        }
    }
    eprintln!(
        "TASK4_RAW_MAPS phase=after_go stats_entered=4224 stats_returned=4224 stats_errors=2112 rv_keys=4224 start=0 owner_outstanding=0"
    );
    let rendered_digest = task4_digest_hex(rendered_hash.finalize());
    ensure!(
        task4_hash(&evidence.rendered.contents()?) == rendered_digest,
        "rendered stream and retained bytes differ"
    );
    eprintln!(
        "TASK4_TRACE phase=after_go calls=4224 rendered=4224 distinct_slot_rv=4224 ordered_ledger=true ring_malformed=0 rendered_sha256={rendered_digest}"
    );
    evidence.fd_sample("pre_detach")?;
    let stop_start = Instant::now();
    let detached = session.detach_producers();
    let stop_ms = stop_start.elapsed().as_millis();
    let clean_detach = session.detach_failures().is_empty();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 4_224,
        "terminal drain found unaccounted Detailed events"
    );
    assert_task4_detailed_maps(&session, true)?;
    let terminal_evidence = crate::metrics::kernel_evidence(&session)?;
    ensure!(
        terminal_evidence == crate::metrics::KernelEvidence::default(),
        "terminal Detailed kernel evidence changed: {terminal_evidence:?}"
    );
    let terminal_counters = session.counter_snapshot()?;
    ensure!(
        terminal_counters == crate::attach::CounterSnapshot::default(),
        "terminal Detailed discovery loss changed"
    );
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","ring_loss":terminal_evidence.ring_loss,
        "raw_calls":tracer.raw_calls(),"rendered":rendered_count,
        "pending":state.pending_at_end(),"orphan_ops":state.orphan_ops(),
        "unmatched_closes":state.unmatched_closes(),
        "kernel":{
            "ring_loss":terminal_evidence.ring_loss,
            "start_insert_failures":terminal_evidence.start_insert_failures,
            "unmatched_returns":terminal_evidence.unmatched_returns,
            "rv_update_failures":terminal_evidence.rv_update_failures,
            "cgroup_scope_failures":terminal_evidence.cgroup_scope_failures,
            "semantic_capture_failures":terminal_evidence.semantic_capture_failures,
            "template_tail_failures":terminal_evidence.template_tail_failures,
            "unregistered_mechanisms":terminal_evidence.unregistered_mechanisms,
            "abi_refusals":terminal_evidence.abi_refusals
        },
        "discovery":{
            "ring_loss":terminal_counters.ring_loss,
            "export_state_failures":terminal_counters.export_state_failures,
            "export_bounded_read_failures":terminal_counters.export_bounded_read_failures,
            "loader_hits":terminal_counters.loader_hits,
            "loader_state_read_failures":terminal_counters.loader_state_read_failures,
            "abi_refusals":terminal_counters.abi_refusals
        }
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal stats_entered=4224 stats_returned=4224 rv_keys=4224 raw_calls=4224 rendered=4224 ordered_ledger=true"
    );
    drop(session);
    let release_start = Instant::now();
    ids.released_with_budget(Duration::from_secs(60))?;
    let release_ms = release_start.elapsed().as_millis();
    caller.finish()?;
    evidence.caller(&mut caller, "terminal")?;
    detached?;
    ensure!(clean_detach, "Detailed detach retained failures");
    eprintln!(
        "TASK4_LOSS ring={} discovery=0 owner=0 output_rendered={rendered_count}",
        terminal_evidence.ring_loss
    );
    evidence.finish()?;
    eprintln!(
        "TASK4_TIMING links={} attach_ms={attach_ms} stop_ms={stop_ms} registry_ms={registry_ms} release_ms={release_ms} elapsed_ms={}",
        ids.links.len(),
        origin.elapsed().as_millis()
    );
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
#[test]
#[ignore = "root-owned BPF lane; 2112 distinct physical Detailed slots, 4224 CALL events and exact raw RV rows"]
fn privileged_task4_detailed_2112_lp64() -> Result<()> {
    wide_detailed_gate()
}

#[test]
fn task4_high_slot_fixture_worker_exit_and_nonleader_exec_have_separate_barriers() -> Result<()> {
    let fixture = OwnedFixture::build_n(false, 2_049)?;
    verify_task4_physical_slots(&fixture.plan.slots, 2_049)?;
    let mut caller = fixture.spawn_gated()?;
    caller.go()?;
    let tid = caller.start_held_worker("ABANDON", 2_048)?;
    caller.release_held_worker_exit(2_048, tid)?;
    caller.call_exact(2_048, 0)?;
    let tid = caller.start_held_worker("NONLEADER_EXEC", 2_048)?;
    caller.release_held_worker_exec()?;
    ensure!(tid != caller.child.id());
    caller.go()?;
    caller.call_exact(2_048, 5)?;
    caller.finish()
}

#[cfg(feature = "wide-detailed-2112")]
struct Task4HighslotExpected {
    phase: &'static str,
    entered: u64,
    returned: u64,
    starts: usize,
    outstanding: u64,
    abandoned: u64,
    rv: Option<u64>,
}

#[cfg(feature = "wide-detailed-2112")]
fn assert_task4_highslot_maps(
    session: &crate::attach::Session,
    expected: Task4HighslotExpected,
    evidence: &mut Task4Evidence,
) -> Result<Option<CallStart>> {
    let Task4HighslotExpected {
        phase,
        entered,
        returned,
        starts,
        outstanding,
        abandoned,
        rv,
    } = expected;
    let start_map: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("START")?)?;
    let rows = start_map
        .iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == starts, "{phase}: wrong START cardinality");
    let observed_starts = rows.len();
    let held_start = rows.first().map(|(key, value)| {
        serde_json::json!({
            "slot":key.slot,"pid_tgid":key.pid_tgid,"ts_ns":value.ts_ns,
            "image":{"task_cookie":value.image.task_cookie,"exec_id":value.image.exec_id}
        })
    });
    let old_start = rows
        .first()
        .map(|(key, value)| {
            ensure!(
                key.slot == 2_048 && key._pad == 0 && value.image.task_cookie != 0,
                "{phase}: START is not the physical high slot"
            );
            Ok(*value)
        })
        .transpose()?;
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    for id in 0..2_049 {
        let mut actual = SlotStats::ZERO;
        for cpu in stats.get(&id, 0)?.iter() {
            actual.entered += cpu.entered;
            actual.returned += cpu.returned;
            actual.errors += cpu.errors;
        }
        let expected = if id == 2_048 {
            (entered, returned, u64::from(rv == Some(5)))
        } else {
            (0, 0, 0)
        };
        ensure!(
            (actual.entered, actual.returned, actual.errors) == expected,
            "{phase}: high-slot STATS[{id}] entered={} returned={} errors={} expected={expected:?}",
            actual.entered,
            actual.returned,
            actual.errors
        );
        evidence.raw_row(serde_json::json!({
            "kind":"stats","phase":phase,"slot":id,
            "entered":actual.entered,"returned":actual.returned,"errors":actual.errors,
            "unreturned":actual.entered.saturating_sub(actual.returned),
            "in_flight":if id == 2_048 {observed_starts} else {0}
        }))?;
    }
    let owner: Array<_, ThreadOwnerControl> =
        Array::try_from(session.ebpf.map("OWNER_CTL").context("OWNER_CTL")?)?;
    let actual_owner = crate::attach::owner_control_fields(owner.get(&0, 0)?);
    ensure!(
        actual_owner == [THREAD_OWNER_LIMIT, outstanding, 0, 0, 0, abandoned, 0],
        "{phase}: high-slot owner debt or poison {actual_owner:?}"
    );
    let rv_map: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let rows = rv_map.iter().collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() == usize::from(rv.is_some()),
        "{phase}: wrong high-slot RV cardinality"
    );
    if let Some(expected) = rv {
        let (key, values) = &rows[0];
        ensure!(
            key.slot == 2_048
                && key.rv == expected
                && key._pad == 0
                && values.iter().sum::<u64>() == 1,
            "{phase}: wrong high-slot RV row"
        );
        evidence.raw_row(serde_json::json!({
            "kind":"rv","phase":phase,"slot":key.slot,"rv":key.rv,
            "count":values.iter().sum::<u64>()
        }))?;
    }
    evidence.raw_row(serde_json::json!({
        "kind":"state","phase":phase,"starts":observed_starts,
        "owner_outstanding":actual_owner[1],"abandoned":actual_owner[5],
        "rv_rows":usize::from(rv.is_some()),"held_start":held_start
    }))?;
    let evidence = crate::metrics::kernel_evidence(session)?;
    ensure!(
        evidence == crate::metrics::KernelEvidence::default(),
        "{phase}: high-slot kernel evidence {evidence:?}"
    );
    eprintln!(
        "TASK4_RAW_MAPS phase={phase} slot=2048 entered={entered} returned={returned} starts={starts} owner_outstanding={outstanding} abandoned={abandoned} rv={rv:?}"
    );
    Ok(old_start)
}

#[cfg(feature = "wide-detailed-2112")]
fn assert_task4_highslot_lifecycle(
    session: &mut crate::attach::Session,
    exec: bool,
    pid: u32,
) -> Result<()> {
    let mut kinds = Vec::new();
    while let Some(item) = session.discovery_dequeue()? {
        let crate::events::DiscoveryItem::Record(record) = item else {
            bail!("malformed high-slot lifecycle discovery record");
        };
        ensure!(kinds.len() < 2, "extra high-slot lifecycle discovery");
        ensure!(
            record.pid_tgid == (u64::from(pid) << 32 | u64::from(pid)),
            "foreign high-slot lifecycle record"
        );
        kinds.push(record.kind);
    }
    let expected = if exec {
        vec![DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_EXEC]
    } else {
        Vec::new()
    };
    ensure!(
        kinds == expected,
        "high-slot lifecycle order differs: {kinds:?}"
    );
    eprintln!("TASK4_LIFECYCLE exec={exec} kinds={kinds:?} pid={pid}");
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
fn wide_highslot_gate(exec: bool) -> Result<()> {
    let origin = Instant::now();
    eprintln!(
        "TASK4_PROFILE name=wide-detailed-2112 detailed_slots=2112 rv_keys=8192 inventory_budget=2049"
    );
    let fixture = OwnedFixture::build_n(false, 2_049)?;
    verify_task4_physical_slots(&fixture.plan.slots, 2_049)?;
    task4_fixture_receipt(&fixture)?;
    let case = if exec {
        "highslot-exec"
    } else {
        "highslot-exit"
    };
    let mut evidence =
        Task4Evidence::new(case, "wide-detailed-2112", &fixture, crate::EBPF_OBJECT)?;
    evidence.fd_sample("baseline")?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    let attach_start = Instant::now();
    let mut session = crate::attach::Session::start(
        &plan,
        &Scope::Pid(caller.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::Allowlisted,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )?;
    let attach_ms = attach_start.elapsed().as_millis();
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 4_098,
        "high-slot test did not retain all 2049 physical probe pairs"
    );
    ensure!(
        session.lifecycle_tracking_unavailable().is_none()
            && session.process_creation_tracking_unavailable().is_none()
    );
    let stats_meta = crate::attach::read_map_metadata(
        "STATS",
        detailed_map_data(session.ebpf.map("STATS").context("STATS")?)?,
    )?;
    let rv_meta = crate::attach::read_map_metadata(
        "RV_COUNTS",
        detailed_map_data(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?,
    )?;
    let start_meta = crate::attach::read_map_metadata(
        "START",
        detailed_map_data(session.ebpf.map("START").context("START")?)?,
    )?;
    let events_meta = crate::attach::read_map_metadata(
        "EVENTS",
        detailed_map_data(session.ebpf.map("EVENTS").context("EVENTS")?)?,
    )?;
    ensure!(
        (
            stats_meta.max_entries,
            rv_meta.max_entries,
            start_meta.max_entries
        ) == (2_112, 8_192, 16_384),
        "high-slot loaded wrong Detailed map bounds"
    );
    eprintln!(
        "TASK4_LOADED_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    eprintln!(
        "TASK4_LOADED_MAPS STATS=2112 RV_COUNTS=8192 START=16384 EVENTS={}",
        events_meta.max_entries
    );
    let registry_start = Instant::now();
    let mut ids = OwnedIds::detailed(&session)?;
    let initial_links = ids.links.len();
    let registry_ms = registry_start.elapsed().as_millis();
    ensure!(
        ids.links.len() >= 4_098,
        "high-slot retained fewer links than paired probes"
    );
    task4_ids_phase("initial", &ids);
    evidence.fd_sample("post_attach")?;
    eprintln!("TASK4_PHASE attach_ms={attach_ms} registry_ms={registry_ms} probes=4098");
    assert_task4_highslot_maps(
        &session,
        Task4HighslotExpected {
            phase: "before_go",
            entered: 0,
            returned: 0,
            starts: 0,
            outstanding: 0,
            abandoned: 0,
            rv: None,
        },
        &mut evidence,
    )?;
    evidence.caller(&mut caller, "pre_go")?;
    caller.go()?;
    evidence.caller(&mut caller, "after_go")?;
    let command = if exec { "NONLEADER_EXEC" } else { "ABANDON" };
    let worker = caller.start_held_worker(command, 2_048)?;
    evidence.caller(&mut caller, "old_held")?;
    let old_start = assert_task4_highslot_maps(
        &session,
        Task4HighslotExpected {
            phase: "old_held",
            entered: 1,
            returned: 0,
            starts: 1,
            outstanding: 1,
            abandoned: 0,
            rv: None,
        },
        &mut evidence,
    )?
    .context("high-slot old START missing")?;
    let start_map: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("held START")?)?;
    let (old_key, _) = start_map.iter().next().context("held worker START key")??;
    ensure!(
        old_key.pid_tgid == (u64::from(caller.child.id()) << 32 | u64::from(worker)),
        "high-slot START was not owned by the actual worker TID"
    );
    let mut events = Vec::new();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.is_empty(),
        "held high-slot entry emitted a completed CALL"
    );
    if exec {
        caller.release_held_worker_exec()?;
        fixture.assert_caller_identity(&caller)?;
    } else {
        caller.release_held_worker_exit(2_048, worker)?;
    }
    evidence.caller(&mut caller, "old_cleaned_before_rebind")?;
    // This checkpoint precedes any explicit target detach, rebind, or
    // successor call. A lingering START or owner reservation is a failure.
    assert_task4_highslot_maps(
        &session,
        Task4HighslotExpected {
            phase: "old_cleaned_before_rebind",
            entered: 1,
            returned: 0,
            starts: 0,
            outstanding: 0,
            abandoned: 1,
            rv: None,
        },
        &mut evidence,
    )?;
    assert_task4_highslot_lifecycle(&mut session, exec, caller.child.id())?;
    if exec {
        let detached = session.detach_slots(&[plan.slots[2_048].clone()])?;
        ensure!(detached == crate::attach::DetachOutcome::default());
        let removed = OwnedIds::detailed(&session)?;
        ensure!(
            removed.links.len() + 2 == ids.links.len(),
            "old high-slot pair was not removed"
        );
        ensure!(
            removed.links.is_subset(&ids.links),
            "unowned links appeared during high-slot detach"
        );
        let old_pair: BTreeSet<_> = ids.links.difference(&removed.links).copied().collect();
        ensure!(
            old_pair.len() == 2,
            "old high-slot pair lacks two unique IDs"
        );
        let attachment = session.attach_targets(&[plan.slots[2_048].clone()], &fixture.pins);
        let rebound = OwnedIds::detailed(&session)?;
        task4_ids_phase("post_rebind_attempt", &rebound);
        ids.links.extend(rebound.links.iter().copied());
        let (failures, completed) = attachment?;
        ensure!(
            failures.is_empty() && completed.len() == 1 && completed[0].0 == 2_048,
            "high-slot explicit same-Session rebind failed"
        );
        ensure!(
            rebound.links.len() == initial_links
                && removed.links.is_subset(&rebound.links)
                && rebound.links.is_disjoint(&old_pair)
                && rebound.maps == ids.maps
                && rebound.programs == ids.programs,
            "rebound object/link cardinality or old-ID retirement changed"
        );
        ensure!(
            ids.links.len() == initial_links + 2,
            "final owned-ID union omitted or reused a high-slot link ID"
        );
        evidence.fd_sample("post_rebind")?;
        caller.go()?;
        caller.call_exact(2_048, 5)?;
    } else {
        caller.call_exact(2_048, 0)?;
    }
    let rv = if exec { 5 } else { 0 };
    evidence.caller(&mut caller, "successor_completed")?;
    assert_task4_highslot_maps(
        &session,
        Task4HighslotExpected {
            phase: "successor_completed",
            entered: 2,
            returned: 1,
            starts: 0,
            outstanding: 0,
            abandoned: 1,
            rv: Some(rv),
        },
        &mut evidence,
    )?;
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 1
            && events[0].event_type == event_type::CALL
            && events[0].slot == 2_048
            && events[0].rv == rv
            && events[0].pid_tgid
                == (u64::from(caller.child.id()) << 32 | u64::from(caller.child.id())),
        "high-slot successor CALL differs from owned ledger"
    );
    ensure!(events[0].image.task_cookie != 0);
    if exec {
        ensure!(
            events[0].image != old_start.image
                && events[0].image.exec_id == old_start.image.exec_id + 1,
            "nonleader exec successor did not advance image generation"
        );
    } else {
        ensure!(
            events[0].image == old_start.image,
            "worker-exit successor changed image generation"
        );
    }
    let mut tracer = crate::trace::Tracer::new(&plan);
    let mut state =
        crate::semantics::State::with_policy(&plan, crate::attach::CapturePolicy::Allowlisted);
    tracer.count_raw_call(&events[0]);
    let rendered = tracer.on_event(&events[0], &mut state);
    evidence.event(&events[0], &fixture, "successor_completed")?;
    evidence.render(&rendered)?;
    ensure!(
        tracer.raw_calls() == 1 && rendered.contains("owned_2048 [semantics unverified]"),
        "high-slot successor was not rendered by real Tracer"
    );
    ensure!(
        state.semantic_evidence() == crate::semantics::SemanticEvidence::default()
            && state.pending_at_end() == 0
            && state.orphan_ops() == 0
            && state.unmatched_closes() == 0,
        "high-slot count-only reducer retained debt or semantic loss"
    );
    eprintln!(
        "TASK4_REDUCER raw_calls=1 rendered=1 pending=0 semantic_evidence=zero orphan_ops=0 unmatched_closes=0"
    );
    eprintln!("TASK4_WORKER selected_id=2048 tid={worker} nonleader=true");
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids=2049 selected_id=2048 entered=2 completed_calls=1 abandoned=1 rv={rv}"
    );
    let rendered_digest = task4_hash(&evidence.rendered.contents()?);
    eprintln!(
        "TASK4_TRACE phase=after_go calls=1 rendered=1 selected_id=2048 rv={rv} old_image={:?} new_image={:?} rendered_sha256={rendered_digest}",
        old_start.image, events[0].image
    );
    task4_ids_receipt(&ids);
    evidence.fd_sample("pre_detach")?;
    let stop_start = Instant::now();
    let detach = session.detach_producers();
    let stop_ms = stop_start.elapsed().as_millis();
    let clean_detach = session.detach_failures().is_empty();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 1,
        "terminal high-slot ring has an unowned CALL"
    );
    assert_task4_highslot_maps(
        &session,
        Task4HighslotExpected {
            phase: "terminal",
            entered: 2,
            returned: 1,
            starts: 0,
            outstanding: 0,
            abandoned: 1,
            rv: Some(rv),
        },
        &mut evidence,
    )?;
    let terminal_counters = session.counter_snapshot()?;
    ensure!(
        terminal_counters == crate::attach::CounterSnapshot::default(),
        "terminal high-slot discovery loss"
    );
    let terminal_kernel = crate::metrics::kernel_evidence(&session)?;
    ensure!(
        terminal_kernel == crate::metrics::KernelEvidence::default(),
        "terminal high-slot kernel loss changed"
    );
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","ring_loss":terminal_kernel.ring_loss,
        "raw_calls":tracer.raw_calls(),"rendered":1,
        "pending":state.pending_at_end(),"orphan_ops":state.orphan_ops(),
        "unmatched_closes":state.unmatched_closes(),
        "kernel":{
            "ring_loss":terminal_kernel.ring_loss,
            "start_insert_failures":terminal_kernel.start_insert_failures,
            "unmatched_returns":terminal_kernel.unmatched_returns,
            "rv_update_failures":terminal_kernel.rv_update_failures,
            "cgroup_scope_failures":terminal_kernel.cgroup_scope_failures,
            "semantic_capture_failures":terminal_kernel.semantic_capture_failures,
            "template_tail_failures":terminal_kernel.template_tail_failures,
            "unregistered_mechanisms":terminal_kernel.unregistered_mechanisms,
            "abi_refusals":terminal_kernel.abi_refusals
        },
        "discovery":{
            "ring_loss":terminal_counters.ring_loss,
            "export_state_failures":terminal_counters.export_state_failures,
            "export_bounded_read_failures":terminal_counters.export_bounded_read_failures,
            "loader_hits":terminal_counters.loader_hits,
            "loader_state_read_failures":terminal_counters.loader_state_read_failures,
            "abi_refusals":terminal_counters.abi_refusals
        }
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal selected_id=2048 entered=2 returned=1 abandoned=1 raw_calls=1 rendered=1 old_start_absent=true owner_debt=0 rv={rv}"
    );
    drop(session);
    let release_start = Instant::now();
    ids.released_with_budget(Duration::from_secs(60))?;
    let release_ms = release_start.elapsed().as_millis();
    caller.finish()?;
    evidence.caller(&mut caller, "terminal")?;
    detach?;
    ensure!(clean_detach, "high-slot detach retained errors");
    eprintln!("TASK4_LOSS ring=0 discovery=0 owner=0");
    evidence.finish()?;
    eprintln!(
        "TASK4_TIMING links={} attach_ms={attach_ms} stop_ms={stop_ms} registry_ms={registry_ms} release_ms={release_ms} elapsed_ms={}",
        ids.links.len(),
        origin.elapsed().as_millis()
    );
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
#[test]
#[ignore = "root-owned BPF lane; 2049 physical endpoints and slot 2048 worker-exit START cleanup"]
fn privileged_task4_highslot_2048_worker_exit() -> Result<()> {
    wide_highslot_gate(false)
}

#[cfg(feature = "wide-detailed-2112")]
#[test]
#[ignore = "root-owned BPF lane; 2049 physical endpoints and slot 2048 nonleader-exec START cleanup"]
fn privileged_task4_highslot_2048_nonleader_exec() -> Result<()> {
    wide_highslot_gate(true)
}

#[derive(Clone)]
struct OwnedLinkDescriptor {
    fd: u32,
    program: u32,
    id: u32,
}

fn read_link_descriptors() -> Result<Vec<OwnedLinkDescriptor>> {
    let mut descriptors = vec![];
    for file in std::fs::read_dir("/proc/self/fdinfo")? {
        let file = file?;
        let Ok(text) = std::fs::read_to_string(file.path()) else {
            continue;
        };
        let field = |key: &str| {
            text.lines().find_map(|line| {
                let (found, value) = line.split_once(':')?;
                (found == key)
                    .then(|| value.trim().parse::<u32>().ok())
                    .flatten()
            })
        };
        if let (Some(program), Some(id)) = (field("prog_id"), field("link_id")) {
            descriptors.push(OwnedLinkDescriptor {
                fd: file.file_name().to_string_lossy().parse()?,
                program,
                id,
            });
        }
    }
    Ok(descriptors)
}

fn raw_link_info_by_borrowed_fd(fd: u32) -> Result<bpf_link_info> {
    // Borrow only; never duplicate or reopen a link by kernel ID.
    // SAFETY: initialized output POD, read only after successful kernel call.
    let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
    #[repr(C)]
    struct Attr {
        fd: u32,
        len: u32,
        info: u64,
    }
    let mut attr = Attr {
        fd,
        len: std::mem::size_of_val(&info) as u32,
        info: (&mut info as *mut bpf_link_info) as u64,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32,
            &mut attr,
            std::mem::size_of::<Attr>(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info)
}

fn owned_link_info_snapshot_with(
    programs: &BTreeSet<u32>,
    mut scan: impl FnMut() -> Result<Vec<OwnedLinkDescriptor>>,
    mut query: impl FnMut(u32) -> Result<bpf_link_info>,
) -> Result<BTreeMap<u32, bpf_link_info>> {
    let mut infos = BTreeMap::new();
    for descriptor in scan()? {
        if programs.contains(&descriptor.program) {
            let info = query(descriptor.fd).with_context(|| {
                format!(
                    "querying retained fd {} for link {}",
                    descriptor.fd, descriptor.id
                )
            })?;
            ensure!(
                info.prog_id == descriptor.program && info.id == descriptor.id,
                "retained descriptor changed ID/program pairing"
            );
            ensure!(
                infos.insert(info.id, info).is_none(),
                "duplicate owned link descriptor"
            );
        }
    }
    Ok(infos)
}

fn owned_link_info_snapshot(programs: &BTreeSet<u32>) -> Result<BTreeMap<u32, bpf_link_info>> {
    owned_link_info_snapshot_with(
        programs,
        read_link_descriptors,
        raw_link_info_by_borrowed_fd,
    )
}

#[test]
fn owned_link_inspection_enumerates_descriptors_once_above_512() -> Result<()> {
    let rows: Vec<_> = (1..=578)
        .map(|id| OwnedLinkDescriptor {
            fd: id + 1000,
            program: 42,
            id,
        })
        .collect();
    let mut enumerations = 0;
    let mut queried = BTreeSet::new();
    let infos = owned_link_info_snapshot_with(
        &BTreeSet::from([42]),
        || {
            enumerations += 1;
            Ok(rows.clone())
        },
        |fd| {
            ensure!(queried.insert(fd), "descriptor queried more than once");
            // SAFETY: fixture POD has no pointer-bearing active union member.
            let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
            info.id = fd - 1000;
            info.prog_id = 42;
            Ok(info)
        },
    )?;
    ensure!(infos.len() == 578 && queried.len() == 578);
    assert_eq!(
        enumerations, 1,
        "inspection rescanned the descriptor directory per owned link"
    );
    Ok(())
}

#[test]
fn owned_link_inspection_borrows_descriptors_and_refuses_changed_identity() -> Result<()> {
    use std::io::{Seek as _, SeekFrom};
    for mutation in ["none", "id", "program", "query", "duplicate"] {
        let mut file = tempfile::tempfile()?;
        file.write_all(b"owned descriptor remains retained")?;
        file.seek(SeekFrom::Start(7))?;
        let fd = u32::try_from(file.as_raw_fd())?;
        let mut queries = 0;
        let mut scans = 0;
        let result = owned_link_info_snapshot_with(
            &BTreeSet::from([42]),
            || {
                scans += 1;
                let owned = OwnedLinkDescriptor {
                    fd,
                    program: 42,
                    id: 575,
                };
                let mut rows = vec![
                    owned.clone(),
                    OwnedLinkDescriptor {
                        fd: u32::MAX,
                        program: 99,
                        id: 900,
                    },
                ];
                if mutation == "duplicate" {
                    rows.push(owned);
                }
                Ok(rows)
            },
            |queried_fd| {
                queries += 1;
                ensure!(queried_fd == fd, "foreign descriptor queried");
                // Actual owned OS descriptor remains open. Replace only the
                // privileged metadata syscall with independently supplied POD.
                ensure!(unsafe { libc::fcntl(queried_fd as i32, libc::F_GETFD) } >= 0);
                if mutation == "query" {
                    bail!("owned metadata syscall failure");
                }
                let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
                info.id = if mutation == "id" { 574 } else { 575 };
                info.prog_id = if mutation == "program" { 41 } else { 42 };
                Ok(info)
            },
        );
        ensure!(scans == 1);
        ensure!(queries == if mutation == "duplicate" { 2 } else { 1 });
        if mutation == "none" {
            let infos = result?;
            ensure!(infos.len() == 1 && infos[&575].id == 575 && infos[&575].prog_id == 42);
        } else {
            let error = match result {
                Ok(_) => bail!("invalid retained metadata accepted: {mutation}"),
                Err(error) => error,
            };
            let expected = match mutation {
                "query" => "owned metadata syscall failure",
                "duplicate" => "duplicate owned link descriptor",
                _ => "changed ID/program pairing",
            };
            ensure!(format!("{error:#}").contains(expected));
        }
        // No ownership transfer, close, seek, or read of the inspected FD.
        ensure!(file.metadata()?.len() == 33 && file.stream_position()? == 7);
        let mut tail = String::new();
        file.read_to_string(&mut tail)?;
        ensure!(tail == "escriptor remains retained");
    }
    Ok(())
}

fn assert_health(snapshot: &InventoryUsageSnapshot) -> Result<()> {
    assert_non_loss_health(snapshot)?;
    ensure!(
        snapshot.health.discovery_counters == Some([0; 5]),
        "{snapshot:?}"
    );
    Ok(())
}

fn assert_non_loss_health(snapshot: &InventoryUsageSnapshot) -> Result<()> {
    ensure!(snapshot.health.failures.is_empty(), "{snapshot:?}");
    ensure!(
        snapshot.health.usage_evidence == Some([0; 3]),
        "{snapshot:?}"
    );
    ensure!(snapshot.health.evidence == Some([0; 9]), "{snapshot:?}");
    let owner = snapshot.health.owner.context("owned health absent")?;
    ensure!(
        owner.limit == 64
            && owner.outstanding == 0
            && owner.poison == 0
            && owner.admission_failures == 0
            && owner.reclamation_failures == 0,
        "{owner:?}"
    );
    ensure!(
        snapshot.usage_integrity_failures == 0
            && snapshot.usage_read_failures == 0
            && snapshot.pin_check_failures == 0
            && snapshot.malformed_discovery == 0
            && snapshot.health_read_failures == 0
    );
    ensure!(
        !snapshot.retirement_fallback.abandoned
            && snapshot.retirement_fallback.records == 0
            && snapshot.retirement_fallback.malformed == 0
            && snapshot.retirement_fallback.worker_failures == 0,
        "{snapshot:?}"
    );
    ensure!(!snapshot.provider_changed && snapshot.pin_error.is_none());
    Ok(())
}

fn caller_rows(
    ebpf: &Ebpf,
    expected_object: PinnedObjectId,
) -> Result<Vec<(CallerObjectKey, CallerObjectUse)>> {
    let map: HashMap<_, CallerObjectKey, CallerObjectUse> =
        HashMap::try_from(ebpf.map("CALLER_USE").context("CALLER_USE map")?)?;
    let endpoints: Array<_, EndpointObject> =
        Array::try_from(ebpf.map("ENDPOINT_OBJECT").context("ENDPOINT_OBJECT map")?)?;
    let rows = map.iter().collect::<Result<Vec<_>, _>>()?;
    for (key, value) in &rows {
        ensure!(
            key.is_valid() && key.object_id == expected_object.0,
            "foreign or malformed caller key {key:?}"
        );
        ensure!(value.is_valid(576), "malformed caller witness {value:?}");
        let binding = endpoints.get(&value.witness_endpoint, 0)?;
        ensure!(
            binding.committed_object_id() == Some(key.object_id),
            "witness lacks physical binding"
        );
    }
    Ok(rows)
}

fn caller_pair_set(
    ebpf: &Ebpf,
    expected_object: PinnedObjectId,
) -> Result<Vec<(CallerObjectKey, CallerObjectUse)>> {
    let mut rows = caller_rows(ebpf, expected_object)?;
    rows.sort_by_key(|(key, _)| {
        (
            key.image.task_cookie,
            key.image.exec_id,
            key.object_id,
            key.reserved,
        )
    });
    Ok(rows)
}

fn caller_usage(ebpf: &Ebpf, endpoint: u32) -> Result<u64> {
    let map: Array<_, u64> = Array::try_from(ebpf.map("USAGE").context("USAGE map")?)?;
    Ok(map.get(&endpoint, 0)?)
}

fn assert_retained_pin(targets: &InventoryTargets, object: PinnedObjectId) -> Result<()> {
    let target = targets
        .pins
        .get(&object)
        .context("retained physical target")?;
    ensure!(target.check_unchanged().map_err(anyhow::Error::msg)?);
    ensure!(
        std::fs::metadata(target.attach_path()).is_ok(),
        "retained physical target descriptor closed"
    );
    Ok(())
}

fn assert_caller_health(snapshot: &InventoryUsageSnapshot, evidence: [u64; 4]) -> Result<()> {
    assert_non_loss_health(snapshot)?;
    ensure!(
        snapshot.health.caller_evidence == Some(evidence),
        "caller evidence {snapshot:?}"
    );
    let control = snapshot
        .health
        .caller_control
        .context("caller native control is unknown")?;
    ensure!(
        control.limit == 16_384 && control.next_ticket > 0,
        "caller native control {control:?}"
    );
    Ok(())
}

fn await_lifecycle(active: &mut ActiveInventory, pid: u32, kind: u8) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    for _ in 0..4096 {
        ensure!(
            Instant::now() < deadline,
            "owned lifecycle deadline kind={kind} pid={pid}"
        );
        if let Some(record) = active.discovery_dequeue()? {
            if (record.pid_tgid >> 32) as u32 == pid && record.kind == kind {
                return Ok(());
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    bail!("owned lifecycle dequeue limit")
}

fn finish_owned_retirement(mut retiring: RetiringInventory) -> Result<RetiredInventory> {
    finish_owned_retirement_inner(&mut retiring, false, Duration::from_secs(100))?;
    retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("completed retirement did not retain its result"))
}

fn finish_owned_retirement_inner(
    retiring: &mut RetiringInventory,
    receipts: bool,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    let mut execs = 0u64;
    let mut exits = 0u64;
    loop {
        // The fixture consumer accounts for each typed lifecycle record in
        // constant space. Product callers supply their own actual dispatcher.
        let service = retiring
            .service_discovery(256, deadline, |record| {
                if receipts {
                    lifecycle_receipt(&record);
                }
                match record.kind {
                    DISCOVERY_KIND_EXEC => execs += 1,
                    DISCOVERY_KIND_LEADER_EXIT => exits += 1,
                    other => bail!("unexpected Inventory lifecycle kind {other}"),
                }
                Ok(())
            })
            .map_err(|failure| anyhow::anyhow!("retirement dispatch: {failure:?}"))?;
        if retiring.poll_completion(deadline)? {
            // A bounded final quantum, still without a quiescence claim.
            retiring
                .service_discovery(256, Instant::now() + Duration::from_secs(1), |record| {
                    if receipts {
                        lifecycle_receipt(&record);
                    }
                    match record.kind {
                        DISCOVERY_KIND_EXEC => execs += 1,
                        DISCOVERY_KIND_LEADER_EXIT => exits += 1,
                        other => bail!("unexpected terminal lifecycle kind {other}"),
                    }
                    Ok(())
                })
                .map_err(|failure| anyhow::anyhow!("terminal dispatch: {failure:?}"))?;
            eprintln!("OWNED_RETIREMENT_DISPATCH execs={execs} exits={exits}");
            return Ok(());
        }
        // The root's outer pidfd deadline still bounds a failed fixture. An
        // abandoned capability may perform blocking fallback reclamation.
        ensure!(Instant::now() < deadline, "owned retirement wait deadline");
        if !service.record_bound_reached {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn system_gate(ia32: bool) -> Result<()> {
    let origin = Instant::now();
    let phase = |name: &str, start: Instant| {
        eprintln!(
            "I3A_PHASE name={name} start_us={} elapsed_us={} total_us={}",
            start.duration_since(origin).as_micros(),
            start.elapsed().as_micros(),
            origin.elapsed().as_micros()
        );
    };
    let started = Instant::now();
    let mut fixture = OwnedFixture::build(ia32)?;
    phase("fixture", started);
    let started = Instant::now();
    let targets = fixture.targets()?;
    let retained = fixture
        .pins
        .attach_path_for(fixture.plan.slots[0].object)
        .map_err(anyhow::Error::msg)?;
    phase("targets", started);
    let started = Instant::now();
    let prepared = PreparedInventory::prepare(Scope::System, budget(), AttachBackend::Singles)?;
    phase("prepare", started);
    let started = Instant::now();
    let mut ids = OwnedIds::prepared(&prepared)?;
    phase("prepared_ids", started);
    let started = Instant::now();
    let mut active = prepared
        .activate(targets)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    phase("activate", started);
    eprintln!(
        "I3A_HEALTH phase=after_activate {:?}",
        read_inventory_health(
            &active.state.prepared.ebpf,
            Instant::now() + Duration::from_secs(3)
        )
    );
    let started = Instant::now();
    ids.inspect_links(&active.state, 576)?;
    phase("inspect_links", started);
    ensure!(
        active.state.discovery.as_ref().unwrap().domain_id()
            == active.state.prepared.discovery_domain.id()
    );
    fixture.pins = PinnedObjects::empty();
    ensure!(
        std::fs::metadata(retained).is_ok(),
        "activation lost the physical pin"
    );
    let started = Instant::now();
    let zero = active.usage_snapshot(window());
    phase("zero_snapshot", started);
    assert_health(&zero)?;
    ensure!(zero.usage.positive_count == 0);
    let started = Instant::now();
    let mut caller = fixture.spawn()?;
    phase("caller_spawn", started);
    let started = Instant::now();
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_EXEC)?;
    phase("await_exec", started);
    let started = Instant::now();
    caller.calls(575, 11)?;
    phase("calls_11", started);
    let started = Instant::now();
    let first = active.usage_snapshot(window());
    phase("first_snapshot", started);
    assert_health(&first)?;
    ensure!(first.usage.newly_positive == [575] && first.usage.positive_count == 1);
    let started = Instant::now();
    caller.calls(575, 17)?;
    phase("calls_17", started);
    let started = Instant::now();
    let repeated = active.usage_snapshot(window());
    phase("repeated_snapshot", started);
    assert_health(&repeated)?;
    ensure!(repeated.usage.newly_positive.is_empty() && repeated.usage.positive_count == 1);
    let started = Instant::now();
    caller.finish()?;
    phase("caller_finish", started);
    let started = Instant::now();
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    phase("await_exit", started);
    let started = Instant::now();
    let before_stop = active.usage_snapshot(window());
    phase("before_stop_snapshot", started);
    eprintln!("I3A_HEALTH phase=before_stop {before_stop:?}");
    let started = Instant::now();
    let mut retired = finish_owned_retirement(active.begin_stop())?;
    phase("stop", started);
    ensure!(retired.cleanup.closed == 578 && retired.cleanup.failures.is_empty());
    ensure!(!retired.cleanup.callback_quiescence_proven);
    let started = Instant::now();
    let last = retired.usage_snapshot(window());
    phase("after_stop_snapshot", started);
    eprintln!("I3A_HEALTH phase=after_stop {last:?}");
    assert_health(&last)?;
    ensure!(last.usage.positive_count == 1 && last.terminal_unsettled);
    drop(retired);
    ids.released()
}

#[test]
fn owned_inventory_fixture_has_physical_targets_and_independent_call_ledger() -> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let targets = fixture.targets()?;
    ensure!(targets.entries.len() == 576 && targets.entries[575].id == 575);
    let mut caller = fixture.spawn()?;
    caller.calls(575, 11)?;
    caller.calls(0, 23)?;
    caller.finish()
}

#[test]
fn owned_fixture_2112_has_distinct_physical_offsets_and_callable_999() -> Result<()> {
    let fixture = OwnedFixture::build_n(false, 2_112)?;
    ensure!(
        fixture.plan.slots.len() == 2_112,
        "fixture truncated its physical targets"
    );
    let offsets: BTreeSet<_> = fixture
        .plan
        .slots
        .iter()
        .map(|slot| slot.file_offset)
        .collect();
    ensure!(
        offsets.len() == 2_112,
        "fixture aliased at least one physical offset"
    );
    let mut caller = fixture.spawn()?;
    caller.calls(999, 1)?;
    caller.calls(2_111, 1)?;
    caller.finish()
}

#[test]
fn owned_fixture_go_barrier_and_exact_return_receipts() -> Result<()> {
    let fixture = OwnedFixture::build_n(false, 2_112)?;
    let mut caller = fixture.spawn_gated()?;
    caller.go()?;
    for id in [0_u32, 511, 512, 999, 2_047, 2_048, 2_111] {
        for rv in [0_u64, 5] {
            caller.call_exact(id, rv)?;
        }
    }
    caller.finish()
}

#[test]
fn owned_inventory_fixture_holds_entered_call_until_resume_and_reaps_held_child() -> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let mut caller = fixture.spawn()?;
    caller.hold_call_in_body(575, 23)?;
    caller.assert_body_held()?;
    caller.resume_body(575)?;
    caller.finish_calls(575, 23)?;
    caller.finish()?;

    let mut abandoned = fixture.spawn()?;
    abandoned.hold_call_in_body(575, 23)?;
    let pid = abandoned.child.id() as libc::pid_t;
    let started = Instant::now();
    drop(abandoned);
    ensure!(started.elapsed() < Duration::from_secs(3));
    let mut status = 0;
    // SAFETY: this probes only the previously owned child and does not block.
    ensure!(unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == -1);
    ensure!(std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD));
    Ok(())
}

#[test]
fn owned_inventory_fixture_text_protocol_threads_and_same_pid_exec_have_bounded_receipts()
-> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let mut caller = fixture.spawn()?;
    let pid = caller.child.id();
    caller.calls(0, 2)?;
    let first_tid = caller.thread_calls(575, 3)?;
    let second_tid = caller.thread_calls(575, 2)?;
    ensure!(
        first_tid != 0
            && second_tid != 0
            && first_tid != second_tid
            && first_tid != pid
            && second_tid != pid,
        "fixture did not prove two distinct nonleader physical threads"
    );
    caller.exec_self()?;
    ensure!(caller.child.id() == pid, "exec changed owned PID");
    caller.calls(575, 5)?;
    caller.finish()
}

#[test]
fn owned_inventory_fixture_ia32_thread_and_exec_receipts_are_physical() -> Result<()> {
    let fixture = OwnedFixture::build(true)?;
    let mut caller = fixture.spawn()?;
    let pid = caller.child.id();
    let tid = caller.thread_calls(575, 1)?;
    ensure!(tid != pid, "ia32 thread receipt named the leader");
    caller.exec_self()?;
    ensure!(caller.child.id() == pid, "ia32 exec changed owned PID");
    caller.calls(575, 2)?;
    caller.finish()
}

#[test]
#[ignore = "parent-owned privileged BPF lane; actual links, physical owned GO ledger and cleanup"]
fn privileged_inventory_activation_system_lp64() -> Result<()> {
    system_gate(false)
}

#[test]
#[ignore = "parent-owned privileged BPF lane plus cc -m32; actual IA32 entry links and workload"]
fn privileged_inventory_activation_system_ia32() -> Result<()> {
    system_gate(true)
}

fn caller_system_gate(ia32: bool) -> Result<()> {
    let mut fixture = OwnedFixture::build(ia32)?;
    let object = fixture.plan.slots[0].object;
    let prepared = PreparedInventory::prepare_callers(
        Scope::System,
        budget(),
        caller_budget(3),
        AttachBackend::Singles,
    )?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ids.inspect_links(&active.state, 576)?;
    fixture.pins = PinnedObjects::empty();
    assert_retained_pin(&active.state.targets, object)?;
    ensure!(caller_pair_set(&active.state.prepared.ebpf, object)?.is_empty());
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 0);
    eprintln!(
        "I2C_CALLER_READY abi={:?} maps={} programs={} links={}",
        fixture.expected_abi,
        ids.maps.len(),
        ids.programs.len(),
        ids.links.len()
    );

    let mut a = fixture.spawn()?;
    await_lifecycle(&mut active, a.child.id(), DISCOVERY_KIND_EXEC)?;
    a.calls(575, 1)?;
    let first = caller_pair_set(&active.state.prepared.ebpf, object)?;
    ensure!(
        first.len() == 1
            && first[0].0.object_id == object.0
            && first[0].1.host_tgid == a.child.id()
            && first[0].1.witness_endpoint == 575,
        "A first leader call did not create exact endpoint-575 pair: {first:?}"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    assert_caller_health(&active.usage_snapshot(window()), [0; 4])?;
    eprintln!(
        "I2C_CALLER_A_FIRST abi={:?} pid={} rows=1 witness=575 usage575=1",
        fixture.expected_abi,
        a.child.id()
    );
    a.calls(575, 2)?;
    ensure!(caller_pair_set(&active.state.prepared.ebpf, object)? == first);
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    eprintln!(
        "I2C_CALLER_A_REPEAT abi={:?} rows=1 witness=575",
        fixture.expected_abi
    );
    let thread_1 = a.thread_calls(575, 1)?;
    ensure!(thread_1 != a.child.id(), "first A worker was the leader");
    ensure!(caller_pair_set(&active.state.prepared.ebpf, object)? == first);
    eprintln!(
        "I2C_CALLER_A_THREAD abi={:?} ordinal=1 tid={thread_1} rows=1",
        fixture.expected_abi
    );
    let thread_2 = a.thread_calls(575, 2)?;
    ensure!(
        thread_1 != thread_2 && thread_1 != a.child.id() && thread_2 != a.child.id(),
        "two A physical thread identities were not proven"
    );
    ensure!(caller_pair_set(&active.state.prepared.ebpf, object)? == first);
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    eprintln!(
        "I2C_CALLER_A_THREAD abi={:?} ordinal=2 tid={thread_2} rows=1",
        fixture.expected_abi
    );
    assert_caller_health(&active.usage_snapshot(window()), [0; 4])?;

    let mut b = fixture.spawn()?;
    await_lifecycle(&mut active, b.child.id(), DISCOVERY_KIND_EXEC)?;
    b.calls(575, 3)?;
    b.finish()?;
    await_lifecycle(&mut active, b.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    let after_b = caller_pair_set(&active.state.prepared.ebpf, object)?;
    ensure!(
        after_b.len() == 2
            && after_b.contains(&first[0])
            && after_b.iter().any(|(key, value)| {
                value.host_tgid == b.child.id()
                    && value.witness_endpoint == 575
                    && key.image.task_cookie != first[0].0.image.task_cookie
                    && key.object_id == object.0
            }),
        "B after USAGE=1 or exit history absent: {after_b:?}"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    assert_caller_health(&active.usage_snapshot(window()), [0; 4])?;
    eprintln!(
        "I2C_CALLER_B_AFTER_GLOBAL abi={:?} pid={} rows=2",
        fixture.expected_abi,
        b.child.id()
    );

    a.exec_self()?;
    await_lifecycle(&mut active, a.child.id(), DISCOVERY_KIND_EXEC)?;
    a.calls(575, 4)?;
    let after_exec = caller_pair_set(&active.state.prepared.ebpf, object)?;
    ensure!(
        after_exec.len() == 3
            && after_b.iter().all(|row| after_exec.contains(row))
            && after_exec.iter().any(|(key, value)| {
                value.host_tgid == a.child.id()
                    && value.witness_endpoint == 575
                    && key.object_id == object.0
                    && key.image.task_cookie == first[0].0.image.task_cookie
                    && key.image.exec_id != first[0].0.image.exec_id
            }),
        "same-PID exec did not retain old pairs and create new image pair: {after_exec:?}"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    assert_caller_health(&active.usage_snapshot(window()), [0; 4])?;
    eprintln!(
        "I2C_CALLER_EXEC abi={:?} pid={} rows=3",
        fixture.expected_abi,
        a.child.id()
    );

    let mut c = fixture.spawn()?;
    let before_c = active.usage_snapshot(window());
    assert_caller_health(&before_c, [0; 4])?;
    c.calls(575, 5)?;
    c.finish()?;
    let exhausted = active.usage_snapshot(window());
    let evidence = exhausted
        .health
        .caller_evidence
        .context("caller evidence after P exhaustion")?;
    ensure!(
        evidence[2] > 0 && evidence[0] == 0 && evidence[1] == 0 && evidence[3] == 0,
        "P exhaustion evidence {evidence:?}"
    );
    let prior_evidence = before_c
        .health
        .caller_evidence
        .context("pre-C caller evidence")?;
    ensure!(
        evidence[2] > prior_evidence[2]
            && evidence[0] == prior_evidence[0]
            && evidence[1] == prior_evidence[1]
            && evidence[3] == prior_evidence[3],
        "C did not raise only pair-insert failure: before={prior_evidence:?} after={evidence:?}"
    );
    ensure!(
        caller_pair_set(&active.state.prepared.ebpf, object)? == after_exec,
        "P exhaustion replaced an existing pair"
    );
    ensure!(
        !after_exec
            .iter()
            .any(|(_, value)| value.host_tgid == c.child.id()),
        "C acquired a positive pair at capacity"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    ensure!(
        exhausted.usage.positive_count == 1,
        "global use lost after P exhaustion"
    );
    eprintln!(
        "I2C_CALLER_P_EXHAUST abi={:?} rows=3 evidence={evidence:?}",
        fixture.expected_abi
    );
    a.calls(575, 6)?;
    ensure!(caller_pair_set(&active.state.prepared.ebpf, object)? == after_exec);
    let after_repeat = active.usage_snapshot(window());
    assert_caller_health(&after_repeat, evidence)?;
    a.finish()?;
    let retiring = active.begin_stop();
    assert_retained_pin(
        &retiring.state.as_ref().context("retiring state")?.targets,
        object,
    )?;
    let mut retired = finish_owned_retirement(retiring)?;
    ensure!(retired.cleanup.closed == 578 && retired.cleanup.failures.is_empty());
    let last = retired.usage_snapshot(window());
    ensure!(last.terminal_unsettled && last.health.caller_evidence == Some(evidence));
    ensure!(caller_pair_set(&retired.state.prepared.ebpf, object)? == after_exec);
    assert_retained_pin(&retired.state.targets, object)?;
    eprintln!(
        "I2C_CALLER_RETAINED abi={:?} rows=3 maps={}",
        fixture.expected_abi,
        ids.maps.len()
    );
    drop(retired);
    ids.released()?;
    eprintln!("I2C_CALLER_RELEASED abi={:?}", fixture.expected_abi);
    Ok(())
}

#[test]
#[ignore = "root-owned live BPF lane; exact LP64 caller images, pair exhaustion and release"]
fn privileged_inventory_caller_system_lp64() -> Result<()> {
    caller_system_gate(false)
}

#[test]
#[ignore = "root-owned live BPF lane; exact IA32 caller images, pair exhaustion and release"]
fn privileged_inventory_caller_system_ia32() -> Result<()> {
    caller_system_gate(true)
}

#[test]
#[ignore = "root-owned live BPF/cgroup lane; included/excluded image pairs and release"]
fn privileged_inventory_caller_cgroup_lp64() -> Result<()> {
    let mut fixture = OwnedFixture::build(false)?;
    let object = fixture.plan.slots[0].object;
    let group = OwnedCgroup::create()?;
    let mut inside = fixture.spawn()?;
    let mut outside = fixture.spawn()?;
    group.move_in(&inside)?;
    let scope = crate::scope::cgroup(&group.path)?;
    let prepared = PreparedInventory::prepare_callers(
        scope,
        budget(),
        caller_budget(2),
        AttachBackend::Singles,
    )?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ids.inspect_links(&active.state, 576)?;
    fixture.pins = PinnedObjects::empty();
    assert_retained_pin(&active.state.targets, object)?;
    outside.calls(575, 1)?;
    ensure!(
        caller_pair_set(&active.state.prepared.ebpf, object)?.is_empty(),
        "excluded caller acquired pair"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 0);
    let excluded = active.usage_snapshot(window());
    assert_non_loss_health(&excluded)?;
    ensure!(excluded.health.caller_evidence == Some([0; 4]));
    let excluded_control = excluded
        .health
        .caller_control
        .context("caller native control after excluded call is unknown")?;
    ensure!(
        excluded_control.limit == 16_384
            && excluded_control.next_ticket == 0
            && excluded_control.unavailable == 0
            && excluded_control.create_failures == 0
            && excluded_control.retry_exhausted == 0,
        "excluded caller changed native control: {excluded_control:?}"
    );
    ensure!(
        excluded.usage.positive_count == 0 && excluded.usage.newly_positive.is_empty(),
        "excluded caller set global usage: {excluded:?}"
    );
    eprintln!(
        "I2C_CALLER_CGROUP_EXCLUDED pid={} rows=0 usage575=0 evidence=[0,0,0,0]",
        outside.child.id()
    );
    inside.calls(575, 2)?;
    let rows = caller_pair_set(&active.state.prepared.ebpf, object)?;
    ensure!(
        rows.len() == 1
            && rows[0].1.host_tgid == inside.child.id()
            && rows[0].1.witness_endpoint == 575
            && rows[0].0.object_id == object.0,
        "cgroup physical caller rows {rows:?}"
    );
    ensure!(caller_usage(&active.state.prepared.ebpf, 575)? == 1);
    let snapshot = active.usage_snapshot(window());
    assert_caller_health(&snapshot, [0; 4])?;
    ensure!(snapshot.usage.newly_positive == [575] && snapshot.usage.positive_count == 1);
    eprintln!(
        "I2C_CALLER_CGROUP path={} included={} excluded={} rows=1",
        group.path.display(),
        inside.child.id(),
        outside.child.id()
    );
    inside.finish()?;
    outside.finish()?;
    let retiring = active.begin_stop();
    assert_retained_pin(
        &retiring.state.as_ref().context("retiring state")?.targets,
        object,
    )?;
    let retired = finish_owned_retirement(retiring)?;
    ensure!(retired.cleanup.failures.is_empty());
    assert_retained_pin(&retired.state.targets, object)?;
    ensure!(caller_pair_set(&retired.state.prepared.ebpf, object)? == rows);
    drop(retired);
    ids.released()?;
    drop(inside);
    drop(outside);
    std::fs::remove_dir(&group.path).context("caller cgroup cleanup")?;
    Ok(())
}

#[test]
#[ignore = "root-owned live BPF lane; partial caller activation retains binding, pair, IDs and pin"]
fn privileged_inventory_caller_partial_activation_lp64() -> Result<()> {
    let mut fixture = OwnedFixture::build(false)?;
    let object = fixture.plan.slots[0].object;
    let mut caller = fixture.spawn()?;
    let targets = fixture.targets()?;
    assert_retained_pin(&targets, object)?;
    let retained = targets
        .pins
        .get(&object)
        .context("retained target")?
        .attach_path();
    fixture.pins = PinnedObjects::empty();
    ensure!(std::fs::metadata(&retained).is_ok());
    let prepared = PreparedInventory::prepare_callers(
        Scope::System,
        budget(),
        caller_budget(2),
        AttachBackend::Singles,
    )?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut ordinal = 0;
    let result = prepared.activate_inner(targets, |_| {
        let current = ordinal;
        ordinal += 1;
        if current == 3 {
            ids.observe_open_owned_links()?;
            ensure!(
                ids.links.len() == 3,
                "partial caller activation lost link custody"
            );
            eprintln!("I2C_CALLER_PARTIAL_IDS phase=held ids={ids:?}");
            ensure!(
                std::fs::metadata(&retained).is_ok(),
                "retained pin closed before fault"
            );
            caller.calls(0, 2)?;
            bail!("owned caller second-entry attachment failure");
        }
        Ok(())
    });
    let failure = match result {
        Ok(_) => bail!("caller partial activation fault skipped"),
        Err(failure) => failure,
    };
    ensure!(
        format!("{:#}", failure.error).contains("owned caller second-entry attachment failure")
    );
    assert_retained_pin(
        &failure
            .retiring
            .state
            .as_ref()
            .context("retiring state")?
            .targets,
        object,
    )?;
    let mut retired = finish_owned_retirement(*failure.retiring)?;
    ensure!(retired.cleanup.closed == 3 && retired.cleanup.failures.is_empty());
    let rows = caller_pair_set(&retired.state.prepared.ebpf, object)?;
    ensure!(
        rows.len() == 1
            && rows[0].1.host_tgid == caller.child.id()
            && rows[0].1.witness_endpoint == 0,
        "partial caller positive pair lost {rows:?}"
    );
    let snapshot = retired.usage_snapshot(window());
    assert_caller_health(&snapshot, [0; 4])?;
    ensure!(snapshot.usage.positive_count == 1 && snapshot.terminal_unsettled);
    ensure!(retired.state.targets.allocated.len() == 576);
    assert_retained_pin(&retired.state.targets, object)?;
    eprintln!(
        "I2C_CALLER_PARTIAL pid={} rows=1 allocated={} maps={} links={}",
        caller.child.id(),
        retired.state.targets.allocated.len(),
        ids.maps.len(),
        ids.links.len()
    );
    caller.finish()?;
    drop(retired);
    ids.released()
}

fn monotonic_ns() -> Result<u64> {
    // SAFETY: initialized writable timespec; CLOCK_MONOTONIC shares the BPF
    // hook timestamp's clock domain. This is private test evidence only.
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0);
    Ok(u64::try_from(time.tv_sec)? * 1_000_000_000 + u64::try_from(time.tv_nsec)?)
}

fn lifecycle_receipt(record: &DiscoveryRecord) {
    eprintln!(
        "I3A_LIFECYCLE kind={} pid_tgid={} hook_ts_ns={}",
        record.kind, record.pid_tgid, record.hook_ts_ns
    );
}

/// Root-owned test control only; no environment branch exists in product code.
struct RetirementBarrier {
    directory: PathBuf,
    nonce: String,
}

impl RetirementBarrier {
    fn new(directory: PathBuf, nonce: String) -> Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let info = std::fs::symlink_metadata(&directory)?;
        ensure!(directory.is_absolute() && info.is_dir());
        // SAFETY: geteuid has no arguments or memory side effects.
        ensure!(info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o077 == 0);
        ensure!(
            !nonce.is_empty()
                && nonce.len() <= 128
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
            "invalid retirement control nonce"
        );
        for marker in ["entered", "release"] {
            match std::fs::symlink_metadata(directory.join(marker)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => bail!("retirement control marker already exists: {marker}"),
            }
        }
        Ok(Self { directory, nonce })
    }

    fn wait(&self, timeout: Duration) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let entered = monotonic_ns()?;
        let mut marker = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join("entered"))?;
        write!(marker, "nonce={}\nmonotonic_ns={entered}\n", self.nonce)?;
        marker.flush()?;
        eprintln!(
            "I3A_BARRIER phase=entered nonce={} monotonic_ns={entered}",
            self.nonce
        );
        let deadline = Instant::now() + timeout;
        loop {
            ensure!(
                Instant::now() < deadline,
                "owned retirement barrier deadline"
            );
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.directory.join("release"))
            {
                Ok(file) => {
                    ensure!(file.metadata()?.is_file(), "release must be a regular file");
                    let mut content = String::new();
                    file.take(130).read_to_string(&mut content)?;
                    ensure!(
                        content == format!("{}\n", self.nonce),
                        "retirement release nonce mismatch"
                    );
                    eprintln!(
                        "I3A_BARRIER phase=released nonce={} monotonic_ns={}",
                        self.nonce,
                        monotonic_ns()?
                    );
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn owned_retirement_barrier_checks_nonce_and_bounds_unreleased_wait() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    for expected in ["success", "wrong_nonce", "deadline"] {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let barrier = RetirementBarrier::new(directory.path().to_owned(), "owned_nonce".into())?;
        let path = directory.path().to_owned();
        let timeout = if expected == "deadline" {
            Duration::from_millis(20)
        } else {
            Duration::from_secs(2)
        };
        let worker = std::thread::spawn(move || barrier.wait(timeout));
        let deadline = Instant::now() + Duration::from_secs(2);
        let entered = loop {
            if let Ok(entered) = std::fs::read_to_string(path.join("entered")) {
                if entered.lines().count() == 2 {
                    break entered;
                }
            }
            ensure!(Instant::now() < deadline, "fixture barrier not entered");
            std::thread::sleep(Duration::from_millis(1));
        };
        ensure!(entered.starts_with("nonce=owned_nonce\nmonotonic_ns="));
        if expected != "deadline" {
            std::fs::write(
                path.join("publish"),
                if expected == "success" {
                    "owned_nonce\n"
                } else {
                    "different_nonce\n"
                },
            )?;
            std::fs::rename(path.join("publish"), path.join("release"))?;
        }
        let result = worker
            .join()
            .map_err(|_| anyhow::anyhow!("barrier worker panicked"))?;
        match expected {
            "success" => result?,
            "wrong_nonce" => ensure!(result.unwrap_err().to_string().contains("nonce mismatch")),
            "deadline" => ensure!(result.unwrap_err().to_string().contains("barrier deadline")),
            _ => unreachable!(),
        }
    }
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane and external lifecycle ledger; explicit controlled worker/synchronous comparison"]
fn privileged_inventory_retirement_controlled_churn() -> Result<()> {
    let mode = std::env::var("P11SCOPE_I3A_RETIREMENT_MODE")?;
    ensure!(
        mode == "worker" || mode == "synchronous",
        "invalid retirement mode"
    );
    let barrier = RetirementBarrier::new(
        std::env::var("P11SCOPE_I3A_RETIREMENT_CONTROL_DIR")?.into(),
        std::env::var("P11SCOPE_I3A_RETIREMENT_NONCE")?,
    )?;
    let fixture = OwnedFixture::build(false)?;
    let prepared = PreparedInventory::prepare(Scope::System, budget(), AttachBackend::Singles)?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    eprintln!(
        "I3A_HEALTH phase=after_activate {:?}",
        read_inventory_health(
            &active.state.prepared.ebpf,
            Instant::now() + Duration::from_secs(3)
        )
    );
    ids.inspect_links(&active.state, 576)?;
    let mut caller = fixture.spawn()?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_EXEC)?;
    caller.calls(575, 11)?;
    caller.finish()?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    let before = active.usage_snapshot(window());
    assert_health(&before)?;
    ensure!(before.usage.positive_count == 1);
    eprintln!(
        "I3A_CONTROLLED_BEFORE mode={mode} counters={:?}",
        before.health.discovery_counters
    );
    // The immutable static order establishes that the first real successful
    // close is entry575; both roots remain in the work while the barrier waits.
    ensure!(active.state.links.last().unwrap().target == InventoryLinkIdentity::Entry(575));
    let mut first = true;
    let mut close = move |fds: &mut Vec<FdLink>| {
        close_inventory_fds(fds)?;
        if first {
            first = false;
            barrier.wait(Duration::from_secs(30))?;
        }
        Ok(())
    };
    let mut retiring = if mode == "worker" {
        RetiringInventory::begin_with_close(active.state, close)
    } else {
        // Permanent actual-kernel negative control: the same closes/barrier,
        // but the sole reader cannot run while synchronous cleanup is blocked.
        let mut state = active.state;
        let mut work = state.take_retirement_work();
        work.run(&mut close);
        let cleanup = state.collect_retirement_work(work);
        RetiringInventory {
            state: Some(state),
            job: None,
            unstarted: None,
            empty_worker: None,
            cleanup: Some(cleanup),
            control_error: None,
        }
    };
    finish_owned_retirement_inner(&mut retiring, true, Duration::from_secs(100))?;
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("controlled retirement remains pending"))?;
    let after = retired.usage_snapshot(window());
    let counters = after
        .health
        .discovery_counters
        .context("controlled discovery counters unavailable")?;
    eprintln!(
        "I3A_CONTROLLED_RESULT mode={mode} counters={counters:?} closed={} failures={} terminal_unsettled={}",
        retired.cleanup.closed,
        retired.cleanup.failures.len(),
        after.terminal_unsettled
    );
    let qualified = (|| -> Result<()> {
        ensure!(retired.cleanup.closed == 578 && retired.cleanup.failures.is_empty());
        ensure!(!retired.cleanup.callback_quiescence_proven && after.terminal_unsettled);
        ensure!(after.usage.positive_count == 1);
        if mode == "worker" {
            assert_health(&after)?;
        } else {
            assert_non_loss_health(&after)?;
            ensure!(
                counters[0] > 0 && counters[1..] == [0; 4],
                "negative control did not show isolated ring loss: {counters:?}"
            );
        }
        Ok(())
    })();
    drop(retired);
    ids.released()?;
    qualified
}

#[test]
#[ignore = "parent-owned BPF lane; bounded owned calls overlap producer stop, no quiescence claim"]
fn privileged_inventory_activation_stop_with_owned_calls_in_progress() -> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let prepared = PreparedInventory::prepare(Scope::System, budget(), AttachBackend::Singles)?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ids.inspect_links(&active.state, 576)?;
    let mut caller = fixture.spawn()?;
    // BODY is emitted from inside owned_575, which cannot return until resume.
    // This proves a userspace call overlaps stop, not that a BPF callback does.
    caller.hold_call_in_body(575, 23)?;
    ensure!(active.usage_snapshot(window()).usage.newly_positive == [575]);
    let mut retired = finish_owned_retirement(active.begin_stop())?;
    caller.assert_body_held()?;
    caller.resume_body(575)?;
    caller.finish_calls(575, 23)?;
    ensure!(retired.cleanup.closed == 578 && retired.cleanup.failures.is_empty());
    let snapshot = retired.usage_snapshot(window());
    assert_health(&snapshot)?;
    ensure!(snapshot.usage.positive_count == 1 && snapshot.terminal_unsettled);
    ensure!(!retired.cleanup.callback_quiescence_proven);
    caller.finish()?;
    drop(retired);
    ids.released()
}

struct OwnedCgroup {
    path: PathBuf,
}
impl OwnedCgroup {
    fn create() -> Result<Self> {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/p11scope-i3a-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).context("creating exclusively owned I3a cgroup")?;
        Ok(Self { path })
    }
    fn move_in(&self, caller: &OwnedCaller) -> Result<()> {
        std::fs::write(
            self.path.join("cgroup.procs"),
            caller.child.id().to_string(),
        )?;
        Ok(())
    }
}
impl Drop for OwnedCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[test]
#[ignore = "parent-owned BPF/cgroup lane; owned in/out callers and retained cgroup descriptor"]
fn privileged_inventory_activation_cgroup_separates_owned_callers() -> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let group = OwnedCgroup::create()?;
    let mut inside = fixture.spawn()?;
    let mut outside = fixture.spawn()?;
    group.move_in(&inside)?;
    let mut scope = crate::scope::cgroup(&group.path)?;
    if let Scope::Cgroup { path, .. } = &mut scope {
        path.push("must-not-reopen");
    }
    let prepared = PreparedInventory::prepare(scope, budget(), AttachBackend::Singles)?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ids.inspect_links(&active.state, 576)?;
    outside.calls(575, 13)?;
    let excluded = active.usage_snapshot(window());
    assert_health(&excluded)?;
    ensure!(
        excluded.usage.positive_count == 0,
        "out-of-cgroup owned call set a usage cell"
    );
    inside.calls(575, 19)?;
    let included = active.usage_snapshot(window());
    assert_health(&included)?;
    ensure!(included.usage.newly_positive == [575] && included.usage.positive_count == 1);
    inside.finish()?;
    outside.finish()?;
    let retired = finish_owned_retirement(active.begin_stop())?;
    ensure!(retired.cleanup.failures.is_empty());
    drop(retired);
    ids.released()?;
    drop(inside);
    drop(outside);
    std::fs::remove_dir(&group.path).context("owned cgroup cleanup")?;
    Ok(())
}

#[test]
#[ignore = "parent-owned BPF lane; real partial activation and preserved positive failure evidence"]
fn privileged_inventory_activation_failure_preserves_usage_and_releases_resources() -> Result<()> {
    let fixture = OwnedFixture::build(false)?;
    let mut caller = fixture.spawn()?;
    let prepared = PreparedInventory::prepare(Scope::System, budget(), AttachBackend::Singles)?;
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut ordinal = 0;
    let result = prepared.activate_inner(fixture.targets()?, |_| {
        let current = ordinal;
        ordinal += 1;
        if current == 3 {
            ids.observe_open_owned_links()?;
            ensure!(
                ids.links.len() == 3,
                "partial activation must own two roots and one entry"
            );
            caller.calls(0, 23)?;
            bail!("owned injected second-entry failure");
        }
        Ok(())
    });
    let failure = match result {
        Ok(_) => bail!("fault injection did not fail activation"),
        Err(failure) => failure,
    };
    ensure!(format!("{:#}", failure.error).contains("owned injected second-entry failure"));
    let mut retired = finish_owned_retirement(*failure.retiring)?;
    ensure!(retired.cleanup.closed == 3 && retired.cleanup.failures.is_empty());
    eprintln!("OWNED_FAILED_ACTIVATION {ids:?}");
    let snapshot = retired.usage_snapshot(window());
    assert_health(&snapshot)?;
    ensure!(
        snapshot.usage.newly_positive == [0]
            && snapshot.usage.positive_count == 1
            && snapshot.terminal_unsettled
    );
    caller.finish()?;
    drop(retired);
    ids.released()
}
