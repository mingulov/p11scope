//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates. The parent runs these serially with its BPF lane.
use super::*;
use crate::capacity::CallerBudget;
use crate::discovery::identity::pin_scanned_view_objects;
use crate::discovery::scan::{CaptureWorkBudget, ScannedModule};
use crate::plan::Slot;
use crate::process::{ProcessView, ProcessViewId};
use aya::maps::HashMap;
use aya_obj::generated::{bpf_cmd, bpf_link_info, bpf_link_type, bpf_perf_event_type};
use p11scope_ebpf_common::inventory_callers::{CallerObjectKey, CallerObjectUse, EndpointObject};
use p11scope_ebpf_common::{DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT, SlotSemantics};
use p11scope_manifest::elf::ElfSnapshot;
use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
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
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("owned.c");
        let path = directory.path().join("owned-provider");
        let mut c = String::from(
            r#"#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>
static unsigned hold_id = 999;
static void hold_in_body(unsigned id) { if (hold_id != id) return; hold_id = 999; printf("BODY %u\n", id); char resume[16]; if (scanf("%15s", resume) != 1 || strcmp(resume, "RESUME")) _exit(4); printf("RESUMED %u\n", id); }
"#,
        );
        for id in 0..576 {
            c.push_str(&format!("__attribute__((noinline,used)) unsigned long owned_{id}(unsigned long x) {{ __asm__ volatile(\"\" ::: \"memory\"); hold_in_body({id}); return x + {id}; }}\n"));
        }
        c.push_str(
            "typedef unsigned long (*fn)(unsigned long);\nstatic fn const functions[576] = {\n",
        );
        for id in 0..576 {
            c.push_str(&format!("owned_{id},\n"));
        }
        c.push_str(
            r#"};
struct thread_work { unsigned id, calls; unsigned long sum; unsigned tid; };
static void *thread_call(void *data) {
    struct thread_work *work = data;
    work->tid = (unsigned)syscall(SYS_gettid);
    for (unsigned n = 0; n < work->calls; n++) work->sum += functions[work->id](n);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 1) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("READY %ld\n", (long)getpid());
    char command[16]; unsigned id, calls;
    while (scanf("%15s", command) == 1) {
        if (!strcmp(command, "EXIT")) return 0;
        if (!strcmp(command, "EXEC")) { execv(argv[0], argv); return 5; }
        if (!strcmp(command, "ARM")) {
            if (scanf("%u", &id) != 1 || id >= 576) return 2;
            hold_id = id; printf("ARMED %u\n", id); continue;
        }
        int thread = !strcmp(command, "THREAD");
        if (!thread && strcmp(command, "CALL")) return 2;
        if (scanf("%u %u", &id, &calls) != 2 || id >= 576 || calls > 1000000) return 2;
        if (thread) {
            struct thread_work work = {id, calls, 0, 0}; pthread_t worker;
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
"#,
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
        for id in 0..576 {
            let name = format!("owned_{id}");
            let offset = elf
                .defined_symbol(&name)
                .map_err(anyhow::Error::msg)?
                .context("owned symbol")?
                .file_offset;
            ensure!(elf.is_executable_offset(offset));
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
        let plan = AttachPlan::from_slots_with_policy(slots, AdmissionPolicy::Inventory(budget()))
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
        let caller = OwnedCaller::spawn(&self.path)?;
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
        Ok(caller)
    }
}

struct OwnedCaller {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}
impl OwnedCaller {
    fn spawn(path: &Path) -> Result<Self> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().context("owned input")?;
        let output = child.stdout.take().context("owned output")?;
        let mut caller = Self {
            child,
            input,
            output,
        };
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
                return Ok(String::from_utf8(line)?);
            }
            line.push(byte[0]);
        }
        bail!("owned caller line exceeded bound")
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
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(status.success());
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "owned exit deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedCaller {
    fn drop(&mut self) {
        let _ = self.child.kill();
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
        let deadline = Instant::now() + Duration::from_secs(3);
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
    finish_owned_retirement_inner(&mut retiring, false)?;
    retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("completed retirement did not retain its result"))
}

fn finish_owned_retirement_inner(retiring: &mut RetiringInventory, receipts: bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(100);
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
    finish_owned_retirement_inner(&mut retiring, true)?;
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
