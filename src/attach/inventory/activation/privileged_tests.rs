//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates. The parent runs these serially with its BPF lane.
use super::*;
use crate::capacity::CallerBudget;
use crate::discovery::identity::{bind_scanned_modules, pin_scanned_view_objects};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedModule, scan_process_view,
};
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

/// Largest owned-fixture endpoint count: the biggest controller-owned live
/// selector N (L-T7-5 boundary at 8192; covers L-T7-3 4097 and L-T7-4 6530).
/// The Inventory path is parametric in N (budget to u32 capacity to
/// `map_max_entries`), so this fixture bound — not a map or plan limit — is
/// what admits those cells. Anything larger is unowned and stays refused.
const OWNED_FIXTURE_MAX_ENDPOINTS: u32 = 8_192;

impl OwnedFixture {
    fn build(ia32: bool) -> Result<Self> {
        Self::build_n(ia32, 576)
    }

    fn build_n(ia32: bool, endpoints: u32) -> Result<Self> {
        Self::build_n_with_alias(ia32, endpoints, false)
    }

    fn build_n_with_alias(ia32: bool, endpoints: u32, alias_zero: bool) -> Result<Self> {
        let (directory, path) = Self::compile_n(ia32, endpoints, alias_zero)?;
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

    fn compile_n(
        ia32: bool,
        endpoints: u32,
        alias_zero: bool,
    ) -> Result<(tempfile::TempDir, PathBuf)> {
        ensure!(
            (1..=OWNED_FIXTURE_MAX_ENDPOINTS).contains(&endpoints),
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
        c.push_str(if alias_zero {
            "#define IDENTITY_ALIAS 1\n"
        } else {
            "#define IDENTITY_ALIAS 0\n"
        });
        for id in 0..endpoints {
            c.push_str(&format!("__attribute__((noinline,used)) unsigned long owned_{id}(unsigned long x) {{ __asm__ volatile(\"\" ::: \"memory\"); hold_in_body({id}); return x + {id}; }}\n"));
        }
        if alias_zero {
            c.push_str(
                "extern __typeof__(owned_0) owned_alias_0 __attribute__((alias(\"owned_0\")));\n",
            );
            c.push_str(
                r#"typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_FLAGS;
typedef struct { unsigned char major, minor; } CK_VERSION;
typedef struct { CK_VERSION version; void *funcs[68]; } CK_FUNCTION_LIST;
typedef struct { char *pInterfaceName; void *pFunctionList; CK_FLAGS flags; } CK_INTERFACE;
__attribute__((used)) static CK_FUNCTION_LIST identity_table = {
    {2, 40}, {(void *)owned_0, (void *)owned_0}
};
__attribute__((used)) static CK_INTERFACE identity_interface = {
    "PKCS 11", &identity_table, 0
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST **list) {
    if (!list) return 7;
    *list = &identity_table;
    return 0;
}
CK_RV C_GetInterfaceList(CK_INTERFACE *list, CK_ULONG *count) {
    if (!count) return 7;
    if (!list) { *count = 1; return 0; }
    if (*count < 1) { *count = 1; return 0x150; }
    list[0] = identity_interface;
    *count = 1;
    return 0;
}
"#,
            );
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
static void *hammer_call(void *data) {
    struct thread_work *work = data;
    for (unsigned n = 0; n < work->calls; n++) work->sum += functions[work->id](0);
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
#if IDENTITY_ALIAS
            if (id != 0) return 2;
            unsigned long rv = ((unsigned long (*)(unsigned long))identity_table.funcs[0])(input);
#else
            unsigned long rv = functions[id](input);
#endif
            printf("RETURNED %u %lu %lu\n", id, input, rv); continue;
        }
        if (!strcmp(command, "RETURN_ALIAS")) {
#if IDENTITY_ALIAS
            unsigned long input;
            if (scanf("%u %lu", &id, &input) != 2 || id != 0) return 2;
            unsigned long rv = ((unsigned long (*)(unsigned long))identity_table.funcs[1])(input);
            printf("RETURNED_ALIAS %u %lu %lu\n", id, input, rv); continue;
#else
            return 2;
#endif
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
        if (!strcmp(command, "HAMMER")) {
            unsigned threads, percalls;
            if (scanf("%u %u", &threads, &percalls) != 2 || threads < 1 || threads > 64 || percalls < 1 || percalls > 10000000) return 2;
            printf("HAMMER_START %u %u\n", threads, percalls);
            struct thread_work works[64]; pthread_t workers[64];
            for (unsigned t = 0; t < threads; t++) {
                works[t].id = t; works[t].calls = percalls; works[t].sum = 0; works[t].tid = 0; works[t].action = 0;
                if (pthread_create(&workers[t], NULL, hammer_call, &works[t])) return 6;
            }
            unsigned long total = 0;
            for (unsigned t = 0; t < threads; t++) {
                if (pthread_join(workers[t], NULL)) return 7;
                total += works[t].sum;
            }
            printf("HAMMER_DONE %u %u %lu\n", threads, percalls, total);
            continue;
        }
        if (!strcmp(command, "FANOUT")) {
            unsigned threads, percalls;
            if (scanf("%u %u", &threads, &percalls) != 2 || threads < 1 || threads > 64 || threads > 576 || percalls < 1 || percalls > 1000000) return 2;
            printf("FANOUT_START %u %u\n", threads, percalls);
            struct thread_work works[64]; pthread_t workers[64];
            for (unsigned t = 0; t < threads; t++) {
                works[t].id = t; works[t].calls = percalls; works[t].sum = 0; works[t].tid = 0; works[t].action = 0;
                if (pthread_create(&workers[t], NULL, thread_call, &works[t])) return 6;
            }
            unsigned long total = 0;
            for (unsigned t = 0; t < threads; t++) {
                if (pthread_join(workers[t], NULL)) return 7;
                total += works[t].sum;
            }
            printf("FANOUT_DONE %u %u %lu\n", threads, percalls, total);
            continue;
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
        Ok((directory, path))
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

struct Task4IdentityFixture {
    fixture: OwnedFixture,
    copy_path: PathBuf,
    original_slot: u32,
    copy_slot: u32,
    original_caller: Option<OwnedCaller>,
    copy_caller: Option<OwnedCaller>,
    views: [ProcessView; 2],
    retained_checks: std::cell::RefCell<[[bool; 3]; 2]>,
}

impl Task4IdentityFixture {
    fn build(policy: AdmissionPolicy) -> Result<Self> {
        let (directory, path) = OwnedFixture::compile_n(false, 1, true)?;
        let original_elf = open_object(&path).map_err(anyhow::Error::msg)?;
        let snapshot = ElfSnapshot::read(&original_elf).map_err(anyhow::Error::msg)?;
        let original_offset = snapshot
            .defined_symbol("owned_0")
            .map_err(anyhow::Error::msg)?
            .context("owned_0")?
            .file_offset;
        let alias_offset = snapshot
            .defined_symbol("owned_alias_0")
            .map_err(anyhow::Error::msg)?
            .context("owned_alias_0")?
            .file_offset;
        ensure!(original_offset == alias_offset && snapshot.is_executable_offset(original_offset));
        let copy_path = directory.path().join("owned-provider-copy");
        std::fs::copy(&path, &copy_path)?;
        let copy_elf = open_object(&copy_path).map_err(anyhow::Error::msg)?;
        let copy_snapshot = ElfSnapshot::read(&copy_elf).map_err(anyhow::Error::msg)?;
        let copy_offset = copy_snapshot
            .defined_symbol("owned_0")
            .map_err(anyhow::Error::msg)?
            .context("copy owned_0")?
            .file_offset;
        ensure!(copy_offset == original_offset);
        let original_bytes = std::fs::read(&path)?;
        let copy_bytes = std::fs::read(&copy_path)?;
        let expected_sha256 = task4_hash(&original_bytes);
        ensure!(
            original_bytes == copy_bytes && task4_hash(&copy_bytes) == expected_sha256,
            "same-byte identity control changed ELF bytes"
        );
        let original_meta = std::fs::metadata(&path)?;
        let copy_meta = std::fs::metadata(&copy_path)?;
        ensure!(
            (original_meta.dev(), original_meta.ino()) != (copy_meta.dev(), copy_meta.ino()),
            "same-byte identity copy reused live inode"
        );
        let original_caller = OwnedCaller::spawn_inner(&path, true)?;
        let copy_caller = OwnedCaller::spawn_inner(&copy_path, true)?;
        let views = [
            ProcessView::open(ProcessViewId(1), original_caller.child.id())
                .map_err(anyhow::Error::msg)?,
            ProcessView::open(ProcessViewId(2), copy_caller.child.id())
                .map_err(anyhow::Error::msg)?,
        ];
        let hooks = crate::discovery::hooks::HookRegistry::builtin();
        let mut work = CaptureWorkBudget::default();
        let mut pins = PinnedObjects::empty();
        let mut modules = Vec::with_capacity(2);
        for (caller, view, hint, offset) in [
            (&original_caller, &views[0], &path, original_offset),
            (&copy_caller, &views[1], &copy_path, copy_offset),
        ] {
            ensure!(caller.child.id() == view.pid() && view.still_the_same());
            let hints = [hint.clone()];
            let scan = scan_process_view(
                &ScanRequest {
                    pid: view.pid(),
                    hints: &hints,
                    hooks: &hooks,
                },
                view,
                &mut work,
            )
            .map_err(anyhow::Error::msg)?;
            let ScanOutcome::Scanned {
                modules: scanned,
                skipped,
                ..
            } = scan
            else {
                bail!("identity production scan was unavailable");
            };
            ensure!(skipped.is_empty(), "identity scan skipped: {skipped:?}");
            ensure!(scanned.len() == 1 && scanned[0].path == hint.display().to_string());
            let module = &scanned[0];
            ensure!(module.view == view.id() && module.decoder_abi == Some(ElfAbi::Lp64));
            ensure!(module.tables.len() == 1 && module.tables[0].version == (2, 40));
            ensure!(module.tables[0].null_entries.len() == 66);
            let entries = &module.tables[0].entries;
            ensure!(
                entries.len() == 2
                    && entries[0].name == "C_Initialize"
                    && entries[1].name == "C_Finalize"
                    && entries.iter().all(|entry| entry.file_offset == offset)
            );
            ensure!(module.interfaces.iter().any(|interface| {
                interface.name_class == "exact_standard" && interface.table == Some(0)
            }));
            let (local, skipped) =
                pin_scanned_view_objects(view, &scanned, &mut work).map_err(anyhow::Error::msg)?;
            ensure!(skipped.is_empty(), "identity pins skipped: {skipped:?}");
            ensure!(
                pins.absorb(local).is_empty(),
                "identity pin absorption ambiguous"
            );
            modules.extend(scanned);
        }
        let (reconciled, skipped) = bind_scanned_modules(&modules, &mut pins);
        ensure!(
            skipped.is_empty() && reconciled.len() == 2,
            "identity bind incomplete: {skipped:?}"
        );
        ensure!(
            views.iter().all(ProcessView::still_the_same),
            "identity child changed after production scans"
        );
        let plan = crate::plan::build_from_sources_for_policy(&reconciled, &[], &pins, policy);
        ensure!(
            plan.slots.len() == 2,
            "identity planner collapsed distinct inodes"
        );
        let original_id = reconciled[0].object;
        let copy_id = reconciled[1].object;
        ensure!(original_id != copy_id);
        let original_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == original_id)
            .context("original physical target omitted")?;
        let copy_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == copy_id)
            .context("same-byte distinct-inode physical target omitted")?;
        ensure!(
            original_slot.file_offset == original_offset
                && original_slot.aliased
                && original_slot.names == ["C_Finalize", "C_Initialize"]
                && copy_slot.file_offset == copy_offset
                && copy_slot.aliased
                && copy_slot.names == ["C_Finalize", "C_Initialize"],
            "identity plan lost alias or distinct-inode facts"
        );
        let (original_slot, copy_slot) = (original_slot.index, copy_slot.index);
        ensure!((original_slot, copy_slot) == (0, 1));
        let original_pin = pins.summary(original_id).context("original live pin")?;
        let copy_pin = pins.summary(copy_id).context("copy live pin")?;
        ensure!(
            original_pin.key != copy_pin.key
                && original_pin.sha256 == expected_sha256
                && copy_pin.sha256 == expected_sha256
        );
        let expected_key = original_pin.key;
        let fixture = OwnedFixture {
            _directory: directory,
            path,
            pins,
            plan,
            expected_key,
            expected_sha256,
            expected_abi: ElfAbi::Lp64,
        };
        Ok(Self {
            fixture,
            copy_path,
            original_slot,
            copy_slot,
            original_caller: Some(original_caller),
            copy_caller: Some(copy_caller),
            views,
            retained_checks: std::cell::RefCell::new([[true, false, false]; 2]),
        })
    }

    fn take_callers(&mut self) -> Result<(OwnedCaller, OwnedCaller)> {
        Ok((
            self.original_caller
                .take()
                .context("original identity caller already taken")?,
            self.copy_caller
                .take()
                .context("copy identity caller already taken")?,
        ))
    }

    fn check_views(&self, point: usize, callers: &[&OwnedCaller; 2]) -> Result<()> {
        ensure!(point < 3);
        for (index, (view, caller)) in self.views.iter().zip(callers).enumerate() {
            ensure!(
                view.id() == ProcessViewId(index as u32 + 1)
                    && view.pid() == caller.child.id()
                    && view.still_the_same(),
                "identity process view changed before checkpoint"
            );
            self.retained_checks.borrow_mut()[index][point] = true;
        }
        Ok(())
    }

    fn assert_copy_caller(&self, caller: &OwnedCaller) -> Result<()> {
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
        let slot = &self.fixture.plan.slots[self.copy_slot as usize];
        let pinned = self
            .fixture
            .pins
            .summary(slot.object)
            .context("copy caller pin")?;
        let inspected = inspect_file(&executable).map_err(anyhow::Error::msg)?;
        ensure!(
            key == pinned.key
                && inspected.identity.sha256.as_deref()
                    == Some(self.fixture.expected_sha256.as_str())
                && inspected.abi == ElfAbi::Lp64,
            "copy caller executable differs from live pinned physical target"
        );
        eprintln!(
            "OWNED_CALLER pid={} key={key:?} sha256={} abi={:?}",
            caller.child.id(),
            self.fixture.expected_sha256,
            inspected.abi
        );
        Ok(())
    }
}

#[test]
fn task4_physical_identity_real_alias_and_same_bytes_distinct_inode() -> Result<()> {
    let inventory = InventoryBudget::new(2, 16).map_err(anyhow::Error::msg)?;
    let fixture = Task4IdentityFixture::build(AdmissionPolicy::Inventory(inventory))?;
    ensure!(fixture.original_slot != fixture.copy_slot);
    ensure!(fixture.fixture.targets()?.entries.len() == 2);
    let mut original = fixture.fixture.spawn_gated()?;
    let mut copy = OwnedCaller::spawn_inner(&fixture.copy_path, true)?;
    fixture.assert_copy_caller(&copy)?;
    let hooks = crate::discovery::hooks::HookRegistry::builtin();
    let mut work = CaptureWorkBudget::default();
    for (ordinal, (caller, path)) in [
        (&original, &fixture.fixture.path),
        (&copy, &fixture.copy_path),
    ]
    .into_iter()
    .enumerate()
    {
        let view = ProcessView::open(ProcessViewId(ordinal as u32 + 1), caller.child.id())
            .map_err(anyhow::Error::msg)?;
        let hint = [path.clone()];
        let scan = crate::discovery::scan::scan_process_view(
            &crate::discovery::scan::ScanRequest {
                pid: caller.child.id(),
                hints: &hint,
                hooks: &hooks,
            },
            &view,
            &mut work,
        )
        .map_err(anyhow::Error::msg)?;
        let crate::discovery::scan::ScanOutcome::Scanned {
            modules, skipped, ..
        } = scan
        else {
            bail!("owned identity scan unavailable");
        };
        ensure!(
            skipped.is_empty(),
            "owned identity scan skipped: {skipped:?}"
        );
        let own = modules
            .iter()
            .find(|module| module.path == path.display().to_string())
            .context("owned executable missing from production scan")?;
        ensure!(own.decoder_abi == Some(ElfAbi::Lp64));
        ensure!(
            own.tables.len() == 1,
            "owned executable lacks one real table"
        );
        ensure!(own.interfaces.iter().any(|interface| {
            interface.name_class == "exact_standard" && interface.table == Some(0)
        }));
        let entries: Vec<_> = own.tables[0]
            .entries
            .iter()
            .map(|entry| (entry.name, entry.file_offset))
            .collect();
        ensure!(
            entries.len() == 2
                && entries[0].0 == "C_Initialize"
                && entries[1].0 == "C_Finalize"
                && entries[0].1 == entries[1].1,
            "both canonical table fields must resolve to the same executable offset"
        );
    }
    original.finish()?;
    copy.finish()?;
    let detailed = Task4IdentityFixture::build(AdmissionPolicy::Detailed)?;
    ensure!(detailed.original_slot != detailed.copy_slot);
    Ok(())
}

#[test]
fn task4_identity_alias_command_uses_second_table_field_after_go() -> Result<()> {
    let budget = InventoryBudget::new(2, 16).map_err(anyhow::Error::msg)?;
    let mut identity = Task4IdentityFixture::build(AdmissionPolicy::Inventory(budget))?;
    let (mut caller, mut before_go) = identity.take_callers()?;
    writeln!(before_go.input, "RETURN_ALIAS 0 0")?;
    before_go.input.flush()?;
    ensure!(
        before_go
            .pin
            .as_ref()
            .context("owned alias child pin")?
            .wait_ready(Some(Duration::from_secs(3)))?,
        "alias request before GO did not terminate the gated child"
    );
    ensure!(before_go.child.try_wait()?.is_some());
    caller.go()?;
    writeln!(caller.input, "RETURN_ALIAS 0 0")?;
    caller.input.flush()?;
    ensure!(caller.line()? == "RETURNED_ALIAS 0 0 0");
    caller.finish()?;
    Ok(())
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

    fn call_alias_exact(&mut self, rv: u64) -> Result<()> {
        writeln!(self.input, "RETURN_ALIAS 0 {rv}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("RETURNED_ALIAS 0 {rv} {rv}"));
        Ok(())
    }

    fn hold_exact_return_in_body(&mut self, id: u32, rv: u64) -> Result<()> {
        let input = rv.wrapping_sub(u64::from(id));
        writeln!(self.input, "ARM {id}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("ARMED {id}"));
        writeln!(self.input, "RETURN {id} {input}")?;
        self.input.flush()?;
        ensure!(self.line()? == format!("BODY {id}"));
        self.assert_body_held()
    }

    fn resume_exact_return(&mut self, id: u32, rv: u64) -> Result<()> {
        self.resume_body(id)?;
        let input = rv.wrapping_sub(u64::from(id));
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
        await_task_released(self.child.id(), tid, Duration::from_secs(5))
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

    /// Every thread hammers its own endpoint with a constant input: the
    /// independent ledger is sum(t * percalls).
    fn hammer_calls(&mut self, threads: u32, percalls: u32) -> Result<()> {
        writeln!(self.input, "HAMMER {threads} {percalls}")?;
        self.input.flush()?;
        ensure!(
            self.line()? == format!("HAMMER_START {threads} {percalls}"),
            "hammer start receipt differs"
        );
        let total: u64 = (0..u64::from(threads)).sum::<u64>() * u64::from(percalls);
        let ledger = self.line()?;
        ensure!(
            ledger == format!("HAMMER_DONE {threads} {percalls} {total}"),
            "independent hammer ledger differs: {ledger}"
        );
        eprintln!("OWNED_HAMMER pid={} {ledger}", self.child.id());
        Ok(())
    }

    fn fanout_calls(&mut self, threads: u32, percalls: u32) -> Result<()> {
        self.start_fanout(threads, percalls)?;
        self.finish_fanout(threads, percalls)
    }

    fn start_fanout(&mut self, threads: u32, percalls: u32) -> Result<()> {
        writeln!(self.input, "FANOUT {threads} {percalls}")?;
        self.input.flush()?;
        ensure!(
            self.line()? == format!("FANOUT_START {threads} {percalls}"),
            "fanout start receipt differs"
        );
        Ok(())
    }

    fn finish_fanout(&mut self, threads: u32, percalls: u32) -> Result<()> {
        let mut total = 0u64;
        for t in 0..threads {
            total += u64::from(percalls) * u64::from(t)
                + u64::from(percalls) * u64::from(percalls.saturating_sub(1)) / 2;
        }
        let ledger = self.line()?;
        ensure!(
            ledger == format!("FANOUT_DONE {threads} {percalls} {total}"),
            "independent fanout ledger differs: {ledger}"
        );
        eprintln!("OWNED_FANOUT pid={} {ledger}", self.child.id());
        Ok(())
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
    fn union(&self, other: &Self) -> Self {
        Self {
            maps: self.maps.union(&other.maps).copied().collect(),
            programs: self.programs.union(&other.programs).copied().collect(),
            links: self.links.union(&other.links).copied().collect(),
        }
    }

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
            ensure!(info.raw.id == id && ids.programs.contains(&info.raw.prog_id));
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
            ensure!(info.raw.id == id && self.programs.contains(&info.raw.prog_id));
            self.links.insert(id);
        }
        Ok(())
    }

    fn inspect_links(
        &mut self,
        state: &InventoryState,
        expected_entries: usize,
    ) -> Result<Vec<serde_json::Value>> {
        ensure!(state.links.len() == expected_entries + 2);
        // FdLink's public API exposes summary info but not its borrowed raw FD
        // or full perf metadata. Resolve all retained descriptors once while
        // this borrow keeps every real link alive; never reopen them by ID.
        let raw_infos = owned_link_info_snapshot(&self.programs)?;
        ensure!(raw_infos.len() == state.links.len());
        let mut rows = Vec::with_capacity(state.links.len());
        let mut entry_capability = None;
        for (position, link) in state.links.iter().enumerate() {
            let KernelInventoryLink::Fds(fds) = &link.handle else {
                bail!("quarantined live link");
            };
            ensure!(fds.len() == 1);
            let info = fds[0].info()?;
            ensure!(id_exists(bpf_cmd::BPF_LINK_GET_NEXT_ID, info.id())?);
            self.links.insert(info.id());
            let observed = raw_infos
                .get(&info.id())
                .context("owned link has no retained descriptor in inspection snapshot")?;
            let raw = &observed.raw;
            ensure!(raw.id == info.id() && raw.prog_id == info.program_id());
            let kernel_common = serde_json::json!({
                "link_id":raw.id,"program_id":raw.prog_id,"type":raw.type_,
                "info_len":observed.returned_len
            });
            let (name, row) = match link.target {
                InventoryLinkIdentity::Lifecycle(name) => {
                    ensure!(raw.type_ == bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32);
                    (
                        name,
                        serde_json::json!({
                            "position":position,"role":"lifecycle","kernel_common":kernel_common,
                            "userspace_requested":{
                                "source":"retained_inventory_attach_request",
                                "program":name,"tracepoint":name
                            }
                        }),
                    )
                }
                InventoryLinkIdentity::Entry(id) => {
                    let entry = &state.targets.entries[id as usize];
                    ensure!(entry.id == id && position == id as usize + 2);
                    state.targets.check_pin(entry.object)?;
                    let pin = state
                        .targets
                        .pins
                        .get(&entry.object)
                        .context("missing retained Inventory target pin")?;
                    let metadata = std::fs::metadata(pin.attach_path())?;
                    let cookie = 0x5055_5347_0000_0000 | u64::from(id);
                    let detail = task4_classify_perf_info(
                        raw,
                        observed.returned_len,
                        entry.file_offset,
                        cookie,
                    )
                    .map_err(|error| {
                        // These are raw union bytes, explicitly unvalidated
                        // when a distro kernel reports an unknown ABI shape.
                        let perf = unsafe { raw.__bindgen_anon_1.perf_event };
                        let point = unsafe { perf.__bindgen_anon_1.uprobe };
                        eprintln!(
                            "TASK4_LINK_UNCLASSIFIED slot={id} info_len={} base_type={} link_id={} program_id={} raw_perf_type={} raw_offset={} raw_cookie={} validity=unvalidated error={error:#}",
                            observed.returned_len, raw.type_, raw.id, raw.prog_id,
                            perf.type_, point.offset, point.cookie
                        );
                        error
                    })?;
                    let (capability, kernel_perf_detail) = match detail {
                        Task4PerfDetail::BaseOnly515 => (
                            "base_only_5_15",
                            serde_json::json!({"capability":"base_only_5_15"}),
                        ),
                        Task4PerfDetail::Partial { type_, offset } => (
                            "partial_type_offset",
                            serde_json::json!({
                                "capability":"partial_type_offset","type":type_,"offset":offset
                            }),
                        ),
                        Task4PerfDetail::Full {
                            type_,
                            offset,
                            cookie,
                        } => (
                            "full_type_offset_cookie",
                            serde_json::json!({
                                "capability":"full_type_offset_cookie",
                                "type":type_,"offset":offset,"cookie":cookie
                            }),
                        ),
                    };
                    if let Some(prior) = entry_capability {
                        ensure!(
                            prior == capability,
                            "Inventory entry link metadata mixed capabilities"
                        );
                    } else {
                        entry_capability = Some(capability);
                    }
                    let (program, abi) = match entry.abi {
                        ElfAbi::Lp64 => ("p11_usage_entry_lp64", "Lp64"),
                        ElfAbi::Ilp32 => ("p11_usage_entry_ia32", "Ilp32"),
                    };
                    (
                        program,
                        serde_json::json!({
                            "position":position,"role":"entry","slot":id,
                            "kernel_common":kernel_common,
                            "kernel_perf_detail":kernel_perf_detail,
                            "userspace_requested":{
                                "source":"retained_inventory_attach_request",
                                "program":program,"object_id":entry.object.0,
                                "dev":metadata.dev(),"ino":metadata.ino(),
                                "offset":entry.file_offset,"cookie":cookie,"abi":abi,
                                "pin_unchanged":true
                            }
                        }),
                    )
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
            rows.push(row);
        }
        ensure!(rows.len() == expected_entries + 2);
        task4_emit_link_capability(
            expected_entries,
            entry_capability.context("Inventory entry link capability missing")?,
        )?;
        eprintln!("OWNED_IDS {self:?}");
        Ok(rows)
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

fn task4_emit_link_capability(expected_entries: usize, capability: &str) -> Result<()> {
    ensure!(
        expected_entries > 0
            && matches!(
                capability,
                "base_only_5_15" | "partial_type_offset" | "full_type_offset_cookie"
            )
    );
    eprintln!("TASK4_LINK_CAPABILITY entries={expected_entries} capability={capability}");
    Ok(())
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
const TASK4_LEGACY_ROW_LIMIT: usize = 20_000;

fn task4_row_limit(case: &str, name: &str, endpoints: usize) -> Result<usize> {
    if case != "inventory" {
        return Ok(TASK4_LEGACY_ROW_LIMIT);
    }
    // A sweep emits four N-cell USAGE dumps, N per-call transitions and
    // five phase/terminal rows: 5N + 5 raw rows. Keep bounded headroom for
    // diagnostics without letting a loop produce ten times the owned work.
    // Ledger: N calls plus repeats/barriers. Links: N entries + two owners.
    // Rendered output is currently empty; allow one line per endpoint.
    let (per_endpoint, fixed) = match name {
        "raw" => (8usize, 64),
        "ledger" => (2, 64),
        "links" => (2, 8),
        "rendered" => (1, 64),
        _ => bail!("unrecognized Inventory evidence file: {name}"),
    };
    endpoints
        .checked_mul(per_endpoint)
        .and_then(|rows| rows.checked_add(fixed))
        .context("Task 4 evidence row budget overflow")
}

struct Task4Rows {
    path: PathBuf,
    file: std::fs::File,
    rows: usize,
    bytes: usize,
    row_limit: usize,
}

impl Task4Rows {
    fn create(
        directory: &Path,
        index: usize,
        name: &str,
        suffix: &str,
        case: &str,
        endpoints: usize,
    ) -> Result<Self> {
        let row_limit = task4_row_limit(case, name, endpoints)?;
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
            row_limit,
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
            self.rows < self.row_limit,
            "Task 4 evidence row limit exceeded ({}): {}",
            self.row_limit,
            self.path.display()
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
    control: Option<(&'static str, &'static str, &'static str, &'static str)>,
    profile: &'static str,
    fixture_sha256: String,
    offsets_sha256: String,
    object_sha256: String,
    ledger: Task4Rows,
    raw: Task4Rows,
    links: Option<Task4Rows>,
    registration: Option<Task4Rows>,
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
        Self::new_control(case, profile, fixture, object, None)
    }

    fn new_control(
        case: &'static str,
        profile: &'static str,
        fixture: &OwnedFixture,
        object: &[u8],
        control: Option<(&'static str, &'static str, &'static str, &'static str)>,
    ) -> Result<Self> {
        let directory = PathBuf::from(
            std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR").context("Task 4 evidence dir")?,
        );
        let index: usize = std::env::var("P11SCOPE_TASK4_CASE_INDEX")?.parse()?;
        Self::new_control_at(case, profile, fixture, object, control, directory, index)
    }

    fn new_control_at(
        case: &'static str,
        profile: &'static str,
        fixture: &OwnedFixture,
        object: &[u8],
        control: Option<(&'static str, &'static str, &'static str, &'static str)>,
        directory: PathBuf,
        index: usize,
    ) -> Result<Self> {
        ensure!(index < 100);
        let offsets = std::fs::read(directory.join(format!("offsets-{index:02}.json")))?;
        let rows = |name, suffix| {
            Task4Rows::create(
                &directory,
                index,
                name,
                suffix,
                case,
                fixture.plan.slots.len(),
            )
        };
        Ok(Self {
            ledger: rows("ledger", "jsonl")?,
            raw: rows("raw", "jsonl")?,
            links: matches!(case, "inventory" | "inventory-identity")
                .then(|| rows("links", "jsonl"))
                .transpose()?,
            registration: (control.is_some() && matches!(case, "detailed" | "detailed-identity"))
                .then(|| rows("registration", "jsonl"))
                .transpose()?,
            rendered: rows("rendered", "txt")?,
            directory,
            index,
            case,
            control,
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

    fn identity_caller(
        &mut self,
        caller: &mut OwnedCaller,
        phase: &str,
        slot: u32,
        object: u32,
    ) -> Result<()> {
        for reply in caller.observed.drain(..) {
            let words: Vec<_> = reply.split_whitespace().collect();
            if matches!(words.first(), Some(&"RETURNED" | &"RETURNED_ALIAS")) {
                ensure!(words.len() == 4 && words[1] == "0");
                let alias = words[0] == "RETURNED_ALIAS";
                ensure!(
                    !alias || slot == 0,
                    "copy child cannot claim original alias command"
                );
                let input: u64 = words[2].parse()?;
                let rv: u64 = words[3].parse()?;
                ensure!(input == rv);
                self.ledger.json(serde_json::json!({
                    "kind":"call","phase":phase,"position":self.ledger_calls,
                    "slot":slot,"object":object,"local_id":0,"pid":caller.child.id(),
                    "input":input,"rv":rv,"reply":reply,
                    "invoked_table_name":if alias {"C_Finalize"} else {"C_Initialize"}
                }))?;
                self.ledger_calls += 1;
            } else {
                self.ledger.json(serde_json::json!({
                    "kind":"barrier","phase":phase,"slot":slot,"object":object,
                    "pid":caller.child.id(),"reply":reply
                }))?;
            }
        }
        Ok(())
    }

    fn raw_row(&mut self, row: serde_json::Value) -> Result<()> {
        self.raw.json(row)
    }

    fn link_row(&mut self, row: serde_json::Value) -> Result<()> {
        self.links
            .as_mut()
            .context("Task 4 Inventory links file missing")?
            .json(row)
    }

    fn registration_row(&mut self, row: serde_json::Value) -> Result<()> {
        self.registration
            .as_mut()
            .context("Task 4 Detailed registration file missing")?
            .json(row)
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
        let metadata = std::fs::metadata(&physical.object_path)?;
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

    fn identity_event(
        &mut self,
        event: &Event,
        fixture: &OwnedFixture,
        witness: Task4SessionWitness,
        view_role: &str,
    ) -> Result<()> {
        let slot = fixture
            .plan
            .slots
            .get(event.slot as usize)
            .context("identity CALL slot outside full plan")?;
        let file = fixture
            .pins
            .file_for(slot.object)
            .context("identity CALL pin")?;
        let metadata = file.metadata()?;
        self.raw.json(serde_json::json!({
            "kind":"call","phase":"after_go","position":self.raw_calls,
            "slot":event.slot,"rv":event.rv,"event_type":event.event_type,
            "pid_tgid":event.pid_tgid,
            "image":{"task_cookie":event.image.task_cookie,"exec_id":event.image.exec_id},
            "dev":metadata.dev(),"ino":metadata.ino(),"offset":slot.file_offset,
            "ts_ns":event.ts_ns,"duration_ns":event.duration_ns,
            "session_generation":witness.session_generation,
            "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
            "view_role":view_role
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
        let links = self.links.as_mut().map(Task4Rows::contents).transpose()?;
        let registration = self
            .registration
            .as_mut()
            .map(Task4Rows::contents)
            .transpose()?;
        let rendered = self.rendered.contents()?;
        let offsets = std::fs::read(
            self.directory
                .join(format!("offsets-{:02}.json", self.index)),
        )?;
        ensure!(task4_hash(&offsets) == self.offsets_sha256);
        let replay = if matches!(self.case, "inventory-identity" | "detailed-identity") {
            task4_replay_identity_files(self.case, &ledger, &raw, &rendered, &offsets)?
        } else {
            task4_replay_files(self.case, &ledger, &raw, &rendered, &offsets)?
        };
        ensure!(replay.0 == self.ledger_calls && replay.1 == self.raw_calls);
        if self.case == "inventory" {
            task4_replay_links(
                links.as_deref().context("Inventory links bytes missing")?,
                &offsets,
            )?;
            if self.control.is_some() {
                task4_replay_link_availability(
                    links.as_deref().context("Inventory links bytes missing")?,
                )?;
            }
        } else if self.case == "inventory-identity" {
            task4_replay_identity_links(
                links
                    .as_deref()
                    .context("Inventory identity links bytes missing")?,
                &offsets,
            )?;
        } else {
            ensure!(links.is_none(), "non-Inventory links file appeared");
        }
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
        let mut files = serde_json::Map::new();
        files.insert(
            "ledger".into(),
            file("ledger.jsonl", &ledger, self.ledger.rows),
        );
        files.insert("raw".into(), file("raw.jsonl", &raw, self.raw.rows));
        files.insert(
            "rendered".into(),
            file("rendered.txt", &rendered, self.rendered.rows),
        );
        files.insert(
            "resources".into(),
            file("resources.json", &resources_bytes, self.resources.len()),
        );
        if let Some(bytes) = &links {
            let rows = self
                .links
                .as_ref()
                .context("Inventory links row count missing")?
                .rows;
            files.insert("links".into(), file("links.jsonl", bytes, rows));
            eprintln!("TASK4_LINKS sha256={} rows={}", task4_hash(bytes), rows);
        }
        if let Some(bytes) = &registration {
            task4_replay_registration(
                bytes,
                &offsets,
                if self.case == "detailed-identity" {
                    "second_attached"
                } else {
                    "attached"
                },
            )?;
            let rows = self
                .registration
                .as_ref()
                .context("registration row count")?
                .rows;
            files.insert(
                "registration".into(),
                file("registration.jsonl", bytes, rows),
            );
            eprintln!(
                "TASK4_REGISTRATION sha256={} rows={rows}",
                task4_hash(bytes)
            );
        }
        if matches!(self.case, "inventory-identity" | "detailed-identity") {
            let copy = std::fs::read(
                self.directory
                    .join(format!("fixture-{:02}-copy.elf", self.index)),
            )?;
            let identity = std::fs::read(
                self.directory
                    .join(format!("case-{:02}-identity.json", self.index)),
            )?;
            let original = std::fs::read(
                self.directory
                    .join(format!("fixture-{:02}.elf", self.index)),
            )?;
            task4_replay_identity_receipt(&identity, &offsets, &original, &copy)?;
            ensure!(task4_hash(&copy) == self.fixture_sha256);
            files.insert(
                "fixture_copy".into(),
                serde_json::json!({
                    "name":format!("fixture-{:02}-copy.elf", self.index),
                    "sha256":task4_hash(&copy),"bytes":copy.len(),"rows":1
                }),
            );
            files.insert("identity".into(), file("identity.json", &identity, 1));
        }
        let mut manifest = serde_json::json!({
            "schema":2,"case_index":self.index,"case":self.case,"profile":self.profile,
            "fixture_sha256":self.fixture_sha256,"offsets_sha256":self.offsets_sha256,
            "object_sha256":self.object_sha256,
            "files":files,
            "replay":{"ok":true,"completed_calls":replay.0,"raw_calls":replay.1}
        });
        if let Some((cell, outcome, fixture_mode, loaded_object_kind)) = self.control {
            manifest["cell"] = cell.into();
            manifest["outcome"] = outcome.into();
            manifest["fixture_mode"] = fixture_mode.into();
            manifest["loaded_object_kind"] = loaded_object_kind.into();
        }
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
    let phases: &[&str] = if case == "detailed-identity" {
        &[
            "baseline",
            "post_first_attach",
            "post_second_attach",
            "pre_detach",
        ]
    } else if case == "highslot-exec" {
        &["baseline", "post_attach", "post_rebind", "pre_detach"]
    } else {
        &["baseline", "post_attach", "pre_detach"]
    };
    ensure!(
        samples.len() == phases.len(),
        "Task 4 FD phases missing or duplicated"
    );
    let mut baseline = None;
    let mut attached_soft = None;
    let mut previous_time = 0_u128;
    for (index, (sample, &phase)) in samples.iter().zip(phases).enumerate() {
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
        if let Some((baseline_soft, baseline_hard)) = baseline {
            ensure!(
                hard == baseline_hard,
                "Task 4 FD hard limit changed during case"
            );
            if index == 1 {
                // Session::start may raise soft to hard before the first link.
                // Its best-effort setrlimit also permits the original soft.
                let session = matches!(
                    case,
                    "detailed" | "detailed-identity" | "highslot-exit" | "highslot-exec"
                );
                ensure!(
                    soft == baseline_soft || (session && soft == baseline_hard),
                    "Task 4 FD attach limit transition changed"
                );
                attached_soft = Some(soft);
            } else {
                ensure!(
                    attached_soft == Some(soft),
                    "Task 4 FD limit changed after attach"
                );
            }
        } else {
            baseline = Some((soft, hard));
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
            "ts_ns":position+11,"duration_ns":1}),
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
    assert!(
        task4_replay_files("detailed", &ledger_bytes, &raw_bytes, &rendered, &offsets).is_err(),
        "replay accepted coherent CALL images without an independent held START witness"
    );
    raw.insert(
        0,
        serde_json::json!({
            "kind":"image_witness","phase":"held_first_call","position":0,"slot":0,
            "pid_tgid":(77_u64<<32)|77,"ts_ns":10,
            "image":{"task_cookie":1,"exec_id":0}
        }),
    );
    let raw_bytes = lines(&raw)?;
    ensure!(
        task4_replay_files("detailed", &ledger_bytes, &raw_bytes, &rendered, &offsets)? == (4, 4)
    );
    raw.swap(1, 3);
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
    raw.swap(1, 3);
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
    bad_physical[1]["offset"] = serde_json::json!(80);
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
    let mut changed = rendered.clone();
    changed[6] = b'9';
    assert!(task4_replay_files("detailed", &ledger_bytes, &raw_bytes, &changed, &offsets).is_err());
    let mut changed_image = raw.clone();
    for row in &mut changed_image {
        if row["kind"] == "call" {
            row["image"]["task_cookie"] = serde_json::json!(2);
        }
    }
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&changed_image)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut changed_timestamp = raw;
    changed_timestamp[1]["ts_ns"] = serde_json::json!(12);
    assert!(
        task4_replay_files(
            "detailed",
            &ledger_bytes,
            &lines(&changed_timestamp)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn task4_inventory_replay_requires_observed_repeat_snapshot() -> Result<()> {
    let offsets = serde_json::to_vec(&serde_json::json!([
        {"dev":1,"ino":2,"offset":64},{"dev":1,"ino":2,"offset":80}
    ]))?;
    let mut ledger = vec![serde_json::json!({"kind":"barrier","phase":"after_go","reply":"GO 77"})];
    for (position, slot) in [0_u64, 1, 0, 1].into_iter().enumerate() {
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
    assert!(
        task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets).is_err(),
        "replay accepted final all-positive cells without serial first-call usage observations"
    );
    let mut ordered = Vec::new();
    let mut first_step = None;
    for phase in ["pre_go", "after_go", "after_repeat", "terminal"] {
        ordered.push(
            raw.iter()
                .find(|row| row["kind"] == "usage_phase" && row["phase"] == phase)
                .context("fixture phase")?
                .clone(),
        );
        ordered.extend(
            raw.iter()
                .filter(|row| row["kind"] == "usage" && row["phase"] == phase)
                .cloned(),
        );
        if phase == "pre_go" {
            first_step = Some(ordered.len());
            for slot in 0..2 {
                ordered.push(serde_json::json!({
                    "kind":"usage_step","phase":"after_go","position":slot,
                    "slot":slot,"before":0,"after":1
                }));
            }
        }
    }
    ordered.push(
        raw.iter()
            .find(|row| row["kind"] == "terminal")
            .context("fixture terminal")?
            .clone(),
    );
    raw = ordered;
    let first_step = first_step.context("fixture first step")?;
    ensure!(
        task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets)? == (4, 0)
    );
    let mut swapped_steps = raw.clone();
    swapped_steps.swap(first_step, first_step + 1);
    assert!(
        task4_replay_files(
            "inventory",
            &ledger_bytes,
            &lines(&swapped_steps)?,
            b"",
            &offsets
        )
        .is_err()
    );
    let mut steps_after_snapshot = raw.clone();
    let after_go = steps_after_snapshot
        .iter()
        .position(|row| row["kind"] == "usage_phase" && row["phase"] == "after_go")
        .context("after-GO fixture phase")?;
    steps_after_snapshot.swap(first_step, after_go);
    assert!(
        task4_replay_files(
            "inventory",
            &ledger_bytes,
            &lines(&steps_after_snapshot)?,
            b"",
            &offsets
        )
        .is_err()
    );
    let mut wrong_step = raw.clone();
    wrong_step[first_step]["after"] = serde_json::json!(0);
    assert!(
        task4_replay_files(
            "inventory",
            &ledger_bytes,
            &lines(&wrong_step)?,
            b"",
            &offsets
        )
        .is_err()
    );
    raw.iter_mut()
        .find(|row| row["kind"] == "usage_phase" && row["phase"] == "after_repeat")
        .context("repeat phase")?["newly_positive"] = serde_json::json!([511]);
    assert!(task4_replay_files("inventory", &ledger_bytes, &lines(&raw)?, b"", &offsets).is_err());
    Ok(())
}

#[test]
fn task4_inventory_replay_accepts_exact_n511_boundary_repeats() -> Result<()> {
    const N: usize = 511;
    let offsets = serde_json::to_vec(
        &(0..N)
            .map(|slot| {
                serde_json::json!({
                    "dev":1,"ino":2,"offset":64+16*slot
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let mut ledger = vec![serde_json::json!({
        "kind":"barrier","phase":"after_go","reply":"GO 77"
    })];
    for (position, slot) in (0..N).chain([0, N - 1]).enumerate() {
        let input = 0_u64.wrapping_sub(slot as u64);
        ledger.push(serde_json::json!({
            "kind":"call","phase":if position < N {"after_go"} else {"after_repeat"},
            "position":position,"slot":slot,"input":input,"rv":0,
            "reply":format!("RETURNED {slot} {input} 0")
        }));
    }
    let mut raw = Vec::new();
    for (phase, value, positive, newly) in [
        ("pre_go", 0, 0, Vec::new()),
        ("after_go", 1, N, (0..N).collect()),
        ("after_repeat", 1, N, Vec::new()),
        ("terminal", 1, N, Vec::new()),
    ] {
        if phase == "after_go" {
            for slot in 0..N {
                raw.push(serde_json::json!({
                    "kind":"usage_step","phase":"after_go","position":slot,
                    "slot":slot,"before":0,"after":1
                }));
            }
        }
        raw.push(serde_json::json!({
            "kind":"usage_phase","phase":phase,"cells_read":N,
            "positive_count":positive,"newly_positive":newly
        }));
        for slot in 0..N {
            raw.push(serde_json::json!({
                "kind":"usage","phase":phase,"slot":slot,"value":value
            }));
        }
    }
    raw.push(serde_json::json!({
        "kind":"terminal","phase":"terminal","usage_positive":N,
        "terminal_unsettled":true,"usage_integrity_failures":0,"usage_read_failures":0
    }));
    let jsonl = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    ensure!(
        task4_replay_files("inventory", &jsonl(&ledger)?, &jsonl(&raw)?, b"", &offsets)?
            == (N + 2, 0)
    );
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
fn task4_resource_samples_allow_only_documented_attach_raise() -> Result<()> {
    let sample = |phase: &str, count: u64, soft: u64, hard: u64, time: u64| {
        serde_json::json!({
            "phase":phase,"fd_count":count,"soft":soft,"hard":hard,
            "timestamp_ns":time.to_string()
        })
    };
    let raised = vec![
        sample("baseline", 10, 8192, 524_288, 1),
        sample("post_attach", 4230, 524_288, 524_288, 2),
        sample("pre_detach", 4230, 524_288, 524_288, 3),
    ];
    task4_validate_resource_samples("detailed", &raised)?;
    task4_validate_resource_samples("highslot-exit", &raised)?;
    let mut exec = raised.clone();
    exec.insert(2, sample("post_rebind", 4230, 524_288, 524_288, 3));
    exec[3]["timestamp_ns"] = serde_json::json!("4");
    task4_validate_resource_samples("highslot-exec", &exec)?;

    let mut unchanged = raised.clone();
    unchanged[1]["soft"] = serde_json::json!(8192);
    unchanged[2]["soft"] = serde_json::json!(8192);
    task4_validate_resource_samples("detailed", &unchanged)?;
    task4_validate_resource_samples("inventory", &unchanged)?;
    assert!(task4_validate_resource_samples("inventory", &raised).is_err());

    let mut changed = raised.clone();
    changed[1]["soft"] = serde_json::json!(16_384);
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    changed = raised.clone();
    changed[1]["hard"] = serde_json::json!(600_000);
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    changed = raised.clone();
    changed[2]["soft"] = serde_json::json!(8192);
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    changed = exec.clone();
    changed[2]["soft"] = serde_json::json!(8192);
    assert!(task4_validate_resource_samples("highslot-exec", &changed).is_err());
    changed = raised.clone();
    changed[1]["fd_count"] = serde_json::json!(524_289);
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    changed = raised.clone();
    changed[2]["timestamp_ns"] = serde_json::json!("1");
    assert!(task4_validate_resource_samples("detailed", &changed).is_err());
    assert!(task4_validate_resource_samples("detailed", &raised[..2]).is_err());
    changed = raised;
    changed.swap(1, 2);
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

fn task4_inventory_repeats(endpoints: usize) -> Vec<u32> {
    if endpoints == 2_112 {
        return vec![511, 512, 999, 2_047, 2_048, 2_111];
    }
    let mut ids = Vec::new();
    for id in [
        0,
        endpoints.saturating_sub(1),
        511,
        512,
        999,
        2_047,
        2_048,
        2_111,
    ] {
        if id < endpoints && !ids.contains(&(id as u32)) {
            ids.push(id as u32);
        }
    }
    ids
}

fn task4_replay_links(bytes: &[u8], offsets_bytes: &[u8]) -> Result<()> {
    let links = task4_jsonl(bytes)?;
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    ensure!(
        links.len() == offsets.len() + 2,
        "Inventory link receipt cardinality changed"
    );
    let mut link_ids = BTreeSet::new();
    let mut role_programs = BTreeMap::new();
    let mut entry_capability = None;
    for (position, row) in links.iter().enumerate() {
        ensure!(row["position"].as_u64() == Some(position as u64));
        let common = &row["kernel_common"];
        let link_id = u32::try_from(common["link_id"].as_u64().context("link ID")?)?;
        let program_id = u32::try_from(common["program_id"].as_u64().context("program ID")?)?;
        let info_len = u32::try_from(common["info_len"].as_u64().context("link info length")?)?;
        ensure!(link_id != 0 && program_id != 0 && link_ids.insert(link_id));
        ensure!((12..=64).contains(&info_len));
        let request = &row["userspace_requested"];
        ensure!(request["source"] == "retained_inventory_attach_request");
        if position < 2 {
            let name = if position == 0 {
                "sched_process_exec"
            } else {
                "sched_process_exit"
            };
            ensure!(
                row["role"] == "lifecycle"
                    && row.get("kernel_perf_detail").is_none()
                    && common["type"].as_u64()
                        == Some(bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u64)
                    && request["program"] == name
                    && request["tracepoint"] == name
            );
            role_programs.insert(name, program_id);
        } else {
            let slot = position - 2;
            let physical = &offsets[slot];
            let cookie = 0x5055_5347_0000_0000_u64 | slot as u64;
            ensure!(
                row["role"] == "entry"
                    && row["slot"].as_u64() == Some(slot as u64)
                    && common["type"].as_u64()
                        == Some(bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u64)
                    && request["program"] == "p11_usage_entry_lp64"
                    && request["object_id"].as_u64() == Some(0)
                    && request["dev"] == physical["dev"]
                    && request["ino"] == physical["ino"]
                    && request["offset"] == physical["offset"]
                    && request["cookie"].as_u64() == Some(cookie)
                    && request["abi"] == "Lp64"
                    && request["pin_unchanged"] == true,
                "Inventory userspace request differs from physical fixture slot {slot}"
            );
            if let Some(previous) = role_programs.insert("entry", program_id) {
                ensure!(previous == program_id, "Inventory entry program ID changed");
            }
            let detail = &row["kernel_perf_detail"];
            let capability = detail["capability"]
                .as_str()
                .context("perf detail capability")?;
            if let Some(previous) = entry_capability {
                ensure!(
                    previous == capability,
                    "Inventory link capability changed within case"
                );
            } else {
                entry_capability = Some(capability);
            }
            let expected_len = match capability {
                "base_only_5_15" => {
                    ensure!(detail.as_object().is_some_and(|object| object.len() == 1));
                    32
                }
                "partial_type_offset" => {
                    ensure!(
                        detail.as_object().is_some_and(|object| object.len() == 3)
                            && detail["type"].as_u64()
                                == Some(bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u64)
                            && detail["offset"] == physical["offset"]
                    );
                    48
                }
                "full_type_offset_cookie" => {
                    ensure!(
                        detail.as_object().is_some_and(|object| object.len() == 4)
                            && detail["type"].as_u64()
                                == Some(bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u64)
                            && detail["offset"] == physical["offset"]
                            && detail["cookie"].as_u64() == Some(cookie)
                    );
                    64
                }
                other => bail!("unknown Inventory perf detail capability {other}"),
            };
            ensure!(info_len == expected_len);
        }
    }
    ensure!(role_programs.len() == 3 && entry_capability.is_some());
    let unique_programs: BTreeSet<_> = role_programs.values().copied().collect();
    ensure!(
        unique_programs.len() == 3,
        "Inventory role program IDs overlap"
    );
    Ok(())
}

fn task4_perf_availability(detail: &serde_json::Value) -> Result<serde_json::Value> {
    Ok(
        match detail["capability"].as_str().context("perf capability")? {
            "base_only_5_15" => serde_json::json!({
                "type":null,"offset":null,"cookie":null,"reason":"base_only_info_len_32"
            }),
            "partial_type_offset" => serde_json::json!({
                "type":detail["type"],"offset":detail["offset"],
                "cookie":null,"reason":"cookie_not_returned_len_48"
            }),
            "full_type_offset_cookie" => serde_json::json!({
                "type":detail["type"],"offset":detail["offset"],
                "cookie":detail["cookie"],"reason":null
            }),
            other => bail!("unknown perf capability {other}"),
        },
    )
}

fn task4_replay_link_availability(bytes: &[u8]) -> Result<()> {
    for (position, row) in task4_jsonl(bytes)?.iter().enumerate() {
        if position < 2 {
            ensure!(row.get("kernel_perf_availability").is_none());
        } else {
            ensure!(
                row["kernel_perf_availability"]
                    == task4_perf_availability(&row["kernel_perf_detail"])?,
                "Inventory optional perf availability differs from observed capability"
            );
        }
    }
    Ok(())
}

fn task4_replay_identity_links(bytes: &[u8], offsets_bytes: &[u8]) -> Result<()> {
    let rows = task4_jsonl(bytes)?;
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    ensure!(rows.len() == 4 && offsets.len() == 2);
    let mut ids = BTreeSet::new();
    let mut roles = BTreeMap::new();
    for (position, row) in rows.iter().enumerate() {
        let common = &row["kernel_common"];
        let link_id = common["link_id"].as_u64().context("identity link ID")?;
        let program_id = common["program_id"]
            .as_u64()
            .context("identity program ID")?;
        ensure!(
            row["position"].as_u64() == Some(position as u64)
                && link_id > 0
                && program_id > 0
                && ids.insert(link_id),
            "identity link ordering or uniqueness changed"
        );
        let requested = &row["userspace_requested"];
        ensure!(requested["source"] == "retained_inventory_attach_request");
        if position < 2 {
            let name = if position == 0 {
                "sched_process_exec"
            } else {
                "sched_process_exit"
            };
            ensure!(
                row["role"] == "lifecycle"
                    && common["type"].as_u64()
                        == Some(bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u64)
                    && requested["program"] == name
                    && requested["tracepoint"] == name
                    && row.get("kernel_perf_detail").is_none()
                    && row.get("kernel_perf_availability").is_none()
            );
            roles.insert(name, program_id);
        } else {
            let slot = position - 2;
            let physical = &offsets[slot];
            let cookie = 0x5055_5347_0000_0000_u64 | slot as u64;
            ensure!(
                row["role"] == "entry"
                    && row["slot"].as_u64() == Some(slot as u64)
                    && common["type"].as_u64()
                        == Some(bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u64)
                    && requested["program"] == "p11_usage_entry_lp64"
                    && requested["object_id"] == physical["object"]
                    && requested["dev"] == physical["dev"]
                    && requested["ino"] == physical["ino"]
                    && requested["offset"] == physical["offset"]
                    && requested["cookie"].as_u64() == Some(cookie)
                    && requested["pin_unchanged"] == true
                    && row["kernel_perf_availability"]
                        == task4_perf_availability(&row["kernel_perf_detail"])?,
                "identity Inventory link differs from physical pin"
            );
            if let Some(prior) = roles.insert("entry", program_id) {
                ensure!(prior == program_id);
            }
        }
    }
    ensure!(roles.len() == 3 && roles.values().copied().collect::<BTreeSet<_>>().len() == 3);
    Ok(())
}

fn task4_replay_identity_receipt(
    receipt_bytes: &[u8],
    offsets_bytes: &[u8],
    original: &[u8],
    copy: &[u8],
) -> Result<()> {
    ensure!(
        original == copy && !original.is_empty(),
        "identity fixture bytes differ"
    );
    let receipt: serde_json::Value = serde_json::from_slice(receipt_bytes)?;
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    ensure!(
        offsets.len() == 2
            && receipt["schema"].as_u64() == Some(2)
            && receipt["mode"] == "alias_equal_bytes_distinct_inode"
            && receipt["alias_pair"] == serde_json::json!(["owned_0", "owned_alias_0"])
            && receipt["alias_pair_source"] == "elf_defined_symbols"
            && receipt["equal_bytes"] == true
            && receipt["distinct_inode"] == true
    );
    let a = &receipt["original"];
    let b = &receipt["copy"];
    let digest = task4_hash(original);
    for (role, object) in [("original", a), ("copy", b)] {
        let slot = object["slot"].as_u64().context("identity slot")? as usize;
        let physical = offsets.get(slot).context("identity slot outside offsets")?;
        ensure!(
            object["object"] == physical["object"]
                && object["dev"] == physical["dev"]
                && object["ino"] == physical["ino"]
                && object["offset"] == physical["offset"]
                && object["names"] == physical["names"]
                && object["sha256"] == digest
                && object["abi"] == "Lp64"
                && object["pin_key"]["inode"] == object["ino"]
                && object["pin_key"]["device_major"].as_u64().is_some()
                && object["pin_key"]["device_minor"].as_u64().is_some(),
            "identity archive receipt does not join live pin/offset facts"
        );
        ensure!(
            object["names"] == serde_json::json!(["C_Finalize", "C_Initialize"])
                && object["table"]["version"] == serde_json::json!([2, 40])
                && object["table"]["linkage"] == "interface"
                && object["table"]["ordinal_names"]
                    == serde_json::json!(["C_Initialize", "C_Finalize"])
                && object["table"]["ordinal_offsets"]
                    == serde_json::json!([object["offset"], object["offset"]])
                && object["process_view"]["role"] == role
                && object["process_view"]["pid"]
                    .as_u64()
                    .is_some_and(|pid| pid > 0)
                && object["process_view"]["admitted_ns"]
                    .as_u64()
                    .is_some_and(|ns| ns > 0)
                && object["process_view"]["mount_namespace"]["device"]
                    .as_u64()
                    .is_some()
                && object["process_view"]["mount_namespace"]["inode"]
                    .as_u64()
                    .is_some()
                && object["process_view"]["retained_checks"]
                    == serde_json::json!({"post_scan":true,"pre_go":true,"after_calls":true}),
            "identity table or retained process view receipt missing"
        );
    }
    ensure!(
        a["slot"] != b["slot"]
            && a["object"] != b["object"]
            && a["process_view"]["pid"] != b["process_view"]["pid"]
            && (a["dev"] != b["dev"] || a["ino"] != b["ino"])
            && a["offset"] == b["offset"]
            && a["names"] == b["names"],
        "identity alias or distinct-inode claim is false"
    );
    Ok(())
}

#[test]
fn task4_identity_receipt_rejects_false_alias_and_inode_collapse() -> Result<()> {
    let bytes = b"identical ELF bytes";
    let offsets = serde_json::to_vec(&vec![
        serde_json::json!({"slot":0,"object":0,"dev":1,"ino":10,"offset":99,
            "names":["C_Finalize","C_Initialize"]}),
        serde_json::json!({"slot":1,"object":1,"dev":1,"ino":11,"offset":99,
            "names":["C_Finalize","C_Initialize"]}),
    ])?;
    let digest = task4_hash(bytes);
    let object = |slot: u32, ino: u64, role: &str, pid: u32| {
        serde_json::json!({
            "slot":slot,"object":slot,"dev":1,"ino":ino,"offset":99,
            "names":["C_Finalize","C_Initialize"],"sha256":digest,"abi":"Lp64",
            "pin_key":{"device_major":0,"device_minor":1,"inode":ino},
            "table":{"version":[2,40],"linkage":"interface",
                "ordinal_names":["C_Initialize","C_Finalize"],"ordinal_offsets":[99,99]},
            "process_view":{"role":role,"pid":pid,"mount_namespace":{"device":4,"inode":5},
                "admitted_ns":100,"retained_checks":{
                    "post_scan":true,"pre_go":true,"after_calls":true}}
        })
    };
    let mut receipt = serde_json::json!({
        "schema":2,"mode":"alias_equal_bytes_distinct_inode",
        "alias_pair":["owned_0","owned_alias_0"],
        "alias_pair_source":"elf_defined_symbols",
        "equal_bytes":true,"distinct_inode":true,
        "original":object(0,10,"original",101),
        "copy":object(1,11,"copy",102)
    });
    task4_replay_identity_receipt(&serde_json::to_vec(&receipt)?, &offsets, bytes, bytes)?;
    receipt["original"]["names"] = serde_json::json!(["C_Initialize"]);
    assert!(
        task4_replay_identity_receipt(&serde_json::to_vec(&receipt)?, &offsets, bytes, bytes)
            .is_err()
    );
    receipt["original"]["names"] = serde_json::json!(["C_Finalize", "C_Initialize"]);
    receipt["copy"]["ino"] = serde_json::json!(10);
    assert!(
        task4_replay_identity_receipt(&serde_json::to_vec(&receipt)?, &offsets, bytes, bytes)
            .is_err()
    );
    Ok(())
}

#[test]
fn task4_identity_inventory_replay_rejects_wrong_physical_join() -> Result<()> {
    let offsets = serde_json::to_vec(&vec![
        serde_json::json!({"slot":0,"object":0,"dev":1,"ino":10,"offset":99,
            "names":["C_Finalize","C_Initialize"]}),
        serde_json::json!({"slot":1,"object":1,"dev":1,"ino":11,"offset":99,
            "names":["C_Finalize","C_Initialize"]}),
    ])?;
    let mut ledger = Vec::new();
    for (slot, pid) in [(0, 100), (1, 101)] {
        ledger.push(serde_json::json!({"kind":"barrier","phase":"pre_go",
            "slot":slot,"object":slot,"pid":pid,"reply":format!("READY {pid}")}));
    }
    for (slot, pid) in [(0, 100), (1, 101)] {
        ledger.push(serde_json::json!({"kind":"barrier","phase":"after_go",
            "slot":slot,"object":slot,"pid":pid,"reply":format!("GO {pid}")}));
    }
    for (position, slot, pid, name, command) in [
        (0, 0, 100, "C_Initialize", "RETURNED"),
        (1, 0, 100, "C_Finalize", "RETURNED_ALIAS"),
        (2, 1, 101, "C_Initialize", "RETURNED"),
    ] {
        ledger.push(serde_json::json!({
            "kind":"call","phase":"after_go","position":position,"slot":slot,
            "object":slot,"local_id":0,"pid":pid,"input":0,"rv":0,
            "reply":format!("{command} 0 0 0"),"invoked_table_name":name
        }));
    }
    let mut raw = Vec::new();
    for (phase, positive, newly) in [
        ("pre_go", 0, vec![]),
        ("after_go", 2, vec![0, 1]),
        ("terminal", 2, vec![]),
    ] {
        if phase == "after_go" {
            for (position, slot, before, after) in [(0, 0, 0, 1), (1, 0, 1, 1), (2, 1, 0, 1)] {
                raw.push(serde_json::json!({"kind":"usage_step","phase":"after_go",
                    "position":position,"slot":slot,"before":before,"after":after}));
            }
        }
        raw.push(serde_json::json!({"kind":"usage_phase","phase":phase,
            "cells_read":2,"positive_count":positive,"newly_positive":newly,
            "health":"synthetic"}));
        for slot in 0..2 {
            raw.push(serde_json::json!({"kind":"usage","phase":phase,
                "slot":slot,"value":u64::from(positive != 0)}));
        }
    }
    raw.push(serde_json::json!({"kind":"terminal","phase":"terminal",
        "usage_positive":2,"terminal_unsettled":true,
        "usage_integrity_failures":0,"usage_read_failures":0,"health":"synthetic"}));
    let encode = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    task4_replay_identity_files(
        "inventory-identity",
        &encode(&ledger)?,
        &encode(&raw)?,
        b"",
        &offsets,
    )?;
    let mut wrong = ledger.clone();
    wrong[6]["object"] = serde_json::json!(0);
    assert!(
        task4_replay_identity_files(
            "inventory-identity",
            &encode(&wrong)?,
            &encode(&raw)?,
            b"",
            &offsets
        )
        .is_err()
    );
    let mut wrong: Vec<serde_json::Value> = serde_json::from_slice(&offsets)?;
    wrong[1]["ino"] = serde_json::json!(10);
    assert!(
        task4_replay_identity_files(
            "inventory-identity",
            &encode(&ledger)?,
            &encode(&raw)?,
            b"",
            &serde_json::to_vec(&wrong)?
        )
        .is_err()
    );
    Ok(())
}

fn task4_synthetic_inventory_snapshot(
    phase: &str,
    positive: usize,
    newly: Vec<u32>,
) -> InventoryUsageSnapshot {
    InventoryUsageSnapshot {
        usage: InventoryUsageRead {
            newly_positive: newly,
            cells_read: 2,
            positive_count: positive,
            ..InventoryUsageRead::default()
        },
        health: InventoryHealthSnapshot {
            discovery_counters: Some([0; 5]),
            evidence: Some([0; 9]),
            usage_evidence: Some([0; 3]),
            owner: Some(ThreadOwnerControl {
                limit: p11scope_ebpf_common::INVENTORY_OWNER_LIMIT,
                ..ThreadOwnerControl::default()
            }),
            ..InventoryHealthSnapshot::default()
        },
        pin_error: None,
        provider_changed: false,
        malformed_discovery: 0,
        usage_integrity_failures: 0,
        usage_read_failures: 0,
        health_read_failures: 0,
        pin_check_failures: 0,
        retirement_fallback: retirement::RetirementFallbackSnapshot {
            abandoned: false,
            records: 0,
            malformed: 0,
            worker_failures: 0,
        },
        terminal_unsettled: phase == "terminal",
    }
}

#[test]
fn task4_identity_source_serialization_synthetic_bundle() -> Result<()> {
    let inventory = InventoryBudget::new(2, 16).map_err(anyhow::Error::msg)?;
    let mut identity = Task4IdentityFixture::build(AdmissionPolicy::Inventory(inventory))?;
    let scratch = tempfile::tempdir()?;
    let directory = std::env::var_os("P11SCOPE_TASK4_SYNTHETIC_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| scratch.path().to_path_buf());
    std::fs::create_dir_all(&directory)?;
    std::fs::OpenOptions::new().write(true).create_new(true)
        .open(directory.join("SYNTHETIC.txt"))?
        .write_all(b"Task4a schema fixture only: owned caller replies and live pin facts are real; BPF link IDs, USAGE and terminal counters are fabricated. Not a live qualification.\n")?;
    eprintln!(
        "TASK4_SYNTHETIC_BUNDLE path={} qualification=false",
        directory.display()
    );
    task4_identity_fixture_receipt_at(&identity, &directory, 0)?;
    let (original, copy) = identity.take_callers()?;
    let fixture = &identity.fixture;
    let mut evidence = Task4Evidence::new_control_at(
        "inventory-identity",
        "default",
        fixture,
        crate::EBPF_INVENTORY_OBJECT,
        Some((
            "inventory-physical-identity",
            "complete-identity",
            "alias_equal_bytes_distinct_inode",
            "inventory-global.elf",
        )),
        directory.clone(),
        0,
    )?;
    evidence.fd_sample("baseline")?;
    eprintln!("TASK4_PROFILE name=default detailed_slots=512 rv_keys=4096 inventory_budget=2");
    eprintln!(
        "TASK4_LOADED_OBJECT kind=inventory-global.elf sha256={}",
        task4_hash(crate::EBPF_INVENTORY_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS USAGE=2 START=absent RV_COUNTS=absent EVENTS=absent");
    for (position, name) in ["sched_process_exec", "sched_process_exit"]
        .into_iter()
        .enumerate()
    {
        evidence.link_row(serde_json::json!({
            "position":position,"role":"lifecycle",
            "kernel_common":{"link_id":100+position,"program_id":10+position,
                "type":bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32,"info_len":32},
            "userspace_requested":{"source":"retained_inventory_attach_request",
                "program":name,"tracepoint":name}
        }))?;
    }
    for slot in &fixture.plan.slots {
        let meta = std::fs::metadata(&slot.object_path)?;
        evidence.link_row(serde_json::json!({
            "position":slot.index+2,"role":"entry","slot":slot.index,
            "kernel_common":{"link_id":102+slot.index,"program_id":12,
                "type":bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,"info_len":32},
            "kernel_perf_detail":{"capability":"base_only_5_15"},
            "kernel_perf_availability":{"type":null,"offset":null,"cookie":null,
                "reason":"base_only_info_len_32"},
            "userspace_requested":{"source":"retained_inventory_attach_request",
                "program":"p11_usage_entry_lp64","object_id":slot.object.0,
                "dev":meta.dev(),"ino":meta.ino(),"offset":slot.file_offset,
                "cookie":0x5055_5347_0000_0000_u64|u64::from(slot.index),
                "abi":"Lp64","pin_unchanged":true}
        }))?;
    }
    task4_emit_link_capability(2, "base_only_5_15")?;
    let synthetic_ids = OwnedIds {
        maps: (1..=13).collect(),
        programs: (10..=21).collect(),
        links: (100..=103).collect(),
    };
    task4_ids_phase("attached", &synthetic_ids);
    task4_ids_receipt(&synthetic_ids);
    evidence.fd_sample("post_attach")?;
    evidence.inventory_snapshot(
        "pre_go",
        &task4_synthetic_inventory_snapshot("pre_go", 0, vec![]),
    )?;
    for slot in 0..2 {
        evidence.raw_row(serde_json::json!({
            "kind":"usage","phase":"pre_go","slot":slot,"value":0
        }))?;
    }
    fixture.assert_caller_identity(&original)?;
    identity.assert_copy_caller(&copy)?;
    let mut callers = vec![
        (identity.original_slot, original),
        (identity.copy_slot, copy),
    ];
    callers.sort_by_key(|(slot, _)| *slot);
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        evidence.identity_caller(caller, "pre_go", *slot, object)?;
    }
    identity.check_views(1, &[&callers[0].1, &callers[1].1])?;
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        caller.go()?;
        evidence.identity_caller(caller, "after_go", *slot, object)?;
    }
    let mut step_position = 0;
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        caller.call_exact(0, 0)?;
        evidence.identity_caller(caller, "after_go", *slot, object)?;
        evidence.raw_row(serde_json::json!({
            "kind":"usage_step","phase":"after_go","position":step_position,
            "slot":slot,"before":0,"after":1
        }))?;
        step_position += 1;
        if *slot == identity.original_slot {
            caller.call_alias_exact(0)?;
            evidence.identity_caller(caller, "after_go", *slot, object)?;
            evidence.raw_row(serde_json::json!({
                "kind":"usage_step","phase":"after_go","position":step_position,
                "slot":slot,"before":1,"after":1
            }))?;
            step_position += 1;
        }
    }
    eprintln!("TASK4_LEDGER phase=after_go physical_ids=2 completed_calls=3 first=0 tail=1");
    for (phase, positive, newly) in [
        ("after_go", 2, vec![0, 1]),
        ("terminal", 2, Vec::<u32>::new()),
    ] {
        evidence.inventory_snapshot(
            phase,
            &task4_synthetic_inventory_snapshot(phase, positive, newly),
        )?;
        for slot in 0..2 {
            evidence.raw_row(serde_json::json!({
                "kind":"usage","phase":phase,"slot":slot,
                "value":u64::from(positive != 0)
            }))?;
        }
    }
    identity.check_views(2, &[&callers[0].1, &callers[1].1])?;
    task4_identity_seal_receipt_at(&identity, &directory, 0)?;
    for (slot, caller) in &mut callers {
        caller.finish()?;
        let object = fixture.plan.slots[*slot as usize].object.0;
        evidence.identity_caller(caller, "terminal", *slot, object)?;
    }
    evidence.fd_sample("pre_detach")?;
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","usage_positive":2,
        "terminal_unsettled":true,"usage_integrity_failures":0,
        "usage_read_failures":0,
        "health":format!("{:?}",task4_synthetic_inventory_snapshot("terminal", 2, vec![]).health)
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal inventory_positive=2 exact_physical_ids=true ordinary_return_maps=absent"
    );
    eprintln!("TASK4_LOSS ring=0 usage=0 owner=0");
    evidence.finish()?;
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    eprintln!("TASK4_SYNTHETIC_BUNDLE path={}", directory.display());
    Ok(())
}

#[test]
fn task4_detailed_identity_source_serialization_synthetic_bundle() -> Result<()> {
    let mut identity = Task4IdentityFixture::build(AdmissionPolicy::Detailed)?;
    let scratch = tempfile::tempdir()?;
    let directory = std::env::var_os("P11SCOPE_TASK4_SYNTHETIC_DETAILED_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| scratch.path().to_path_buf());
    std::fs::create_dir_all(&directory)?;
    std::fs::OpenOptions::new().write(true).create_new(true)
        .open(directory.join("SYNTHETIC.txt"))?
        .write_all(b"Task4a schema fixture only: owned child replies and live pin/scan facts are real; BPF registration/IDs, START/STATS/RV/CALL, maps, loss and terminal counters are fabricated. Equal numeric images are intentional across separately anchored Sessions. Not live qualification.\n")?;
    eprintln!(
        "TASK4_SYNTHETIC_BUNDLE path={} qualification=false",
        directory.display()
    );
    task4_identity_fixture_receipt_at(&identity, &directory, 0)?;
    let (mut original, mut copy) = identity.take_callers()?;
    let fixture = &identity.fixture;
    fixture.assert_caller_identity(&original)?;
    identity.assert_copy_caller(&copy)?;
    let mut evidence = Task4Evidence::new_control_at(
        "detailed-identity",
        "default",
        fixture,
        crate::EBPF_OBJECT,
        Some((
            "detailed-physical-identity",
            "complete-identity",
            "alias_equal_bytes_distinct_inode",
            "detailed.elf",
        )),
        directory.clone(),
        0,
    )?;
    evidence.fd_sample("baseline")?;
    eprintln!("TASK4_PROFILE name=default detailed_slots=512 rv_keys=4096 inventory_budget=2112");
    let first_ids = OwnedIds {
        maps: (1..=22).collect(),
        programs: (100..=112).collect(),
        links: (1000..=1006).collect(),
    };
    let second_ids = OwnedIds {
        maps: (23..=44).collect(),
        programs: (200..=212).collect(),
        links: (2000..=2006).collect(),
    };
    let witnesses = [
        Task4SessionWitness {
            session_generation: 1,
            stats_map_id: 1,
            scope_pid: original.child.id(),
            pid_filter_token: 1,
        },
        Task4SessionWitness {
            session_generation: 2,
            stats_map_id: 23,
            scope_pid: copy.child.id(),
            pid_filter_token: 1,
        },
    ];
    for (generation, ids) in [(0, &first_ids), (1, &second_ids)] {
        let witness = witnesses[generation];
        let phase = if generation == 0 {
            "first_attached"
        } else {
            "second_attached"
        };
        let return_program = if generation == 0 { 100 } else { 200 };
        let entry_program = return_program + 1;
        for slot in &fixture.plan.slots {
            let file = fixture
                .pins
                .file_for(slot.object)
                .context("synthetic borrowed pin")?;
            let meta = file.metadata()?;
            let summary = fixture.pins.summary(slot.object).context("synthetic pin")?;
            let fresh = task4_fresh_pinned_hash(file)?;
            ensure!(summary.sha256.to_string() == fresh);
            for (side, role, program, program_id) in [
                (0, "return", "p11_return", return_program),
                (1, "entry", "p11_entry", entry_program),
            ] {
                evidence.registration_row(serde_json::json!({
                    "kind":"static","phase":phase,"position":2*slot.index+side,
                    "slot":slot.index,"role":role,"program":program,
                    "program_id":program_id,"object":slot.object.0,
                    "dev":meta.dev(),"ino":meta.ino(),"offset":slot.file_offset,
                    "pin_unchanged":true,
                    "session_generation":witness.session_generation,
                    "stats_map_id":witness.stats_map_id,
                    "scope_pid":witness.scope_pid,
                    "pid_filter_token":witness.pid_filter_token,
                    "descriptor_index":slot.descriptor_index,
                    "requested_attach_cookie":p11scope_ebpf_common::attach_cookie(
                        slot.index, slot.descriptor_index),
                    "cookie_provenance":"userspace_requested",
                    "pin_id":slot.object.0,
                    "pin_key":{"device_major":summary.key.device.major,
                        "device_minor":summary.key.device.minor,
                        "inode":summary.key.inode},
                    "pin_sha256":summary.sha256.to_string(),
                    "fresh_pin_sha256":fresh,"abi":"Lp64"
                }))?;
            }
        }
        for (position, (program_id, role, program, kind)) in [
            (
                return_program,
                "return",
                "p11_return",
                bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,
            ),
            (
                return_program,
                "return",
                "p11_return",
                bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,
            ),
            (
                entry_program,
                "entry",
                "p11_entry",
                bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,
            ),
            (
                entry_program,
                "entry",
                "p11_entry",
                bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,
            ),
            (
                return_program + 2,
                "other",
                "sched_process_exec",
                bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32,
            ),
            (
                return_program + 3,
                "other",
                "sched_process_exit",
                bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32,
            ),
            (
                return_program + 4,
                "other",
                "task_newtask",
                bpf_link_type::BPF_LINK_TYPE_TRACING as u32,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            evidence.registration_row(serde_json::json!({
                "kind":"kernel_link","phase":phase,"position":position,
                "link_id":if generation == 0 { 1000+position } else { 2000+position },
                "program_id":program_id,"type":kind,"info_len":32,
                "role":role,"program":program,
                "session_generation":witness.session_generation,
                "stats_map_id":witness.stats_map_id,
                "scope_pid":witness.scope_pid,
                "pid_filter_token":witness.pid_filter_token
            }))?;
        }
        task4_ids_phase(
            phase,
            &if generation == 0 {
                first_ids.union(&OwnedIds::default())
            } else {
                first_ids.union(&second_ids)
            },
        );
        task4_session_ids(phase, witness, ids);
        evidence.fd_sample(if generation == 0 {
            "post_first_attach"
        } else {
            "post_second_attach"
        })?;
    }
    let all_ids = first_ids.union(&second_ids);
    task4_ids_receipt(&all_ids);
    eprintln!(
        "TASK4_LOADED_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS STATS=512 RV_COUNTS=4096 START=16384 EVENTS=4096");
    evidence.identity_caller(&mut original, "pre_go", 0, fixture.plan.slots[0].object.0)?;
    evidence.identity_caller(&mut copy, "pre_go", 1, fixture.plan.slots[1].object.0)?;
    identity.check_views(1, &[&original, &copy])?;
    original.go()?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    copy.go()?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;

    let image = ImageIdentity {
        task_cookie: 1,
        exec_id: 1,
    };
    let zero_stats = |slot: u32| {
        serde_json::json!({
            "slot":slot,"entered":0,"returned":0,"errors":0,"in_flight":0
        })
    };
    let full_stats = |slot: u32| {
        serde_json::json!({
            "slot":slot,"entered":2,"returned":2,"errors":1,"in_flight":0
        })
    };
    let snapshot = |generation: usize, own: bool| {
        let witness = witnesses[generation];
        let role = if generation == 0 { "original" } else { "copy" };
        serde_json::json!({
            "session_generation":witness.session_generation,
            "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
            "view_role":role,"start_rows":0,"owner_outstanding":0,
            "ring_malformed":0,"ring_loss":0,"calls_seen":if own {2} else {0},
            "stats":[
                if own && generation == 0 { full_stats(0) } else { zero_stats(0) },
                if own && generation == 1 { full_stats(1) } else { zero_stats(1) }
            ],
            "rv":if own { serde_json::json!([
                {"slot":generation,"rv":0,"count":1},
                {"slot":generation,"rv":5,"count":1}
            ]) } else { serde_json::json!([]) }
        })
    };
    let first_done = snapshot(0, true);
    let second_zero = snapshot(1, false);
    let second_done = snapshot(1, true);

    original.hold_exact_return_in_body(0, 0)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    evidence.raw_row(serde_json::json!({
        "kind":"image_witness","phase":"held_first_call","position":0,
        "slot":0,"pid_tgid":u64::from(original.child.id()) << 32 | u64::from(original.child.id()),
        "ts_ns":1000,"image":{"task_cookie":image.task_cookie,"exec_id":image.exec_id},
        "session_generation":1,"stats_map_id":1,"scope_pid":original.child.id(),
        "view_role":"original","foreign_at_hold":task4_identity_foreign_at_hold(&second_zero)
    }))?;
    original.resume_exact_return(0, 0)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    original.call_alias_exact(5)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    evidence.raw_row(serde_json::json!({
        "kind":"cross_session_snapshot","phase":"after_original",
        "sessions":[first_done,second_zero]
    }))?;

    copy.hold_exact_return_in_body(0, 0)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    evidence.raw_row(serde_json::json!({
        "kind":"image_witness","phase":"held_first_call","position":1,
        "slot":1,"pid_tgid":u64::from(copy.child.id()) << 32 | u64::from(copy.child.id()),
        "ts_ns":2000,"image":{"task_cookie":image.task_cookie,"exec_id":image.exec_id},
        "session_generation":2,"stats_map_id":23,"scope_pid":copy.child.id(),
        "view_role":"copy","foreign_at_hold":task4_identity_foreign_at_hold(&first_done)
    }))?;
    copy.resume_exact_return(0, 0)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    copy.call_exact(0, 5)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    evidence.raw_row(serde_json::json!({
        "kind":"cross_session_snapshot","phase":"after_copy",
        "sessions":[first_done,second_done]
    }))?;
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids=2 completed_calls=4 rv0=2 rv5=2 first=0 tail=1"
    );

    for (generation, source) in [(0, &first_done), (1, &second_done)] {
        let witness = witnesses[generation];
        let role = if generation == 0 { "original" } else { "copy" };
        for stats in source["stats"].as_array().context("synthetic STATS")? {
            evidence.raw_row(serde_json::json!({
                "kind":"stats","phase":"after_go","slot":stats["slot"],
                "entered":stats["entered"],"returned":stats["returned"],
                "errors":stats["errors"],"in_flight":stats["in_flight"],
                "session_generation":witness.session_generation,
                "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
                "view_role":role
            }))?;
        }
    }
    for (generation, source) in [(0, &first_done), (1, &second_done)] {
        let witness = witnesses[generation];
        let role = if generation == 0 { "original" } else { "copy" };
        for rv in source["rv"].as_array().context("synthetic RV")? {
            evidence.raw_row(serde_json::json!({
                "kind":"rv","phase":"after_go","slot":rv["slot"],
                "rv":rv["rv"],"count":rv["count"],
                "session_generation":witness.session_generation,
                "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
                "view_role":role
            }))?;
        }
    }
    let mut tracer = crate::trace::Tracer::new(&fixture.plan);
    let mut state = crate::semantics::State::with_policy(
        &fixture.plan,
        crate::attach::CapturePolicy::Allowlisted,
    );
    for (slot, pid, witness, role, start_ts) in [
        (0, original.child.id(), witnesses[0], "original", 1000),
        (1, copy.child.id(), witnesses[1], "copy", 2000),
    ] {
        for rv in [0, 5] {
            let event = Event {
                event_type: event_type::CALL,
                slot,
                rv,
                pid_tgid: u64::from(pid) << 32 | u64::from(pid),
                image,
                ts_ns: start_ts + 50 + rv,
                duration_ns: if rv == 0 { 50 } else { 40 },
                ..Event::default()
            };
            evidence.identity_event(&event, fixture, witness, role)?;
            tracer.count_raw_call(&event);
            evidence.render(&tracer.on_event(&event, &mut state))?;
        }
    }
    ensure!(tracer.raw_calls() == 4 && state.pending_at_end() == 0);
    identity.check_views(2, &[&original, &copy])?;
    task4_identity_seal_receipt_at(&identity, &directory, 0)?;
    original.finish()?;
    evidence.identity_caller(&mut original, "terminal", 0, fixture.plan.slots[0].object.0)?;
    copy.finish()?;
    evidence.identity_caller(&mut copy, "terminal", 1, fixture.plan.slots[1].object.0)?;
    evidence.fd_sample("pre_detach")?;
    let kernel = serde_json::json!({
        "ring_loss":0,"start_insert_failures":0,"unmatched_returns":0,
        "rv_update_failures":0,"cgroup_scope_failures":0,
        "semantic_capture_failures":0,"template_tail_failures":0,
        "unregistered_mechanisms":0,"abi_refusals":0
    });
    let discovery = serde_json::json!({
        "ring_loss":0,"export_state_failures":0,
        "export_bounded_read_failures":0,"loader_hits":0,
        "loader_state_read_failures":0,"abi_refusals":0
    });
    let terminal_session = |generation: usize| {
        let witness = witnesses[generation];
        serde_json::json!({
            "session_generation":witness.session_generation,
            "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
            "view_role":if generation == 0 { "original" } else { "copy" },
            "start_rows":0,"raw_calls":2,"ring_malformed":0,
            "owner":{"limit":THREAD_OWNER_LIMIT,"outstanding":0,"poison":0,
                "admission_failures":0,"reclamation_failures":0,
                "abandoned_start":0,"abandoned_discovery":0},
            "kernel":kernel,"discovery":discovery
        })
    };
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","ring_loss":0,
        "raw_calls":4,"rendered":4,"pending":0,"orphan_ops":0,
        "unmatched_closes":0,"kernel":kernel,"discovery":discovery,
        "sessions":[terminal_session(0),terminal_session(1)]
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal stats_entered=4 stats_returned=4 rv_keys=4 raw_calls=4 rendered=4 ordered_ledger=true"
    );
    eprintln!("TASK4_LOSS ring=0 discovery=0 owner=0 output_rendered=4");
    evidence.finish()?;
    let ledger = std::fs::read(directory.join("case-00-ledger.jsonl"))?;
    let offsets = std::fs::read(directory.join("offsets-00.json"))?;
    let rendered = std::fs::read(directory.join("case-00-rendered.txt"))?;
    let raw = task4_jsonl(&std::fs::read(directory.join("case-00-raw.jsonl"))?)?;
    let registration = task4_jsonl(&std::fs::read(
        directory.join("case-00-registration.jsonl"),
    )?)?;
    let lines = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    assert_eq!(
        task4_replay_identity_files(
            "detailed-identity",
            &ledger,
            &lines(&raw)?,
            &rendered,
            &offsets
        )?,
        (4, 4)
    );
    for count in [0, 1, 3] {
        let mut changed = raw.clone();
        let mut sessions = raw[16]["sessions"]
            .as_array()
            .context("valid Detailed terminal Sessions")?
            .clone();
        if count == 3 {
            sessions.push(sessions[0].clone());
        } else {
            sessions.truncate(count);
        }
        changed[16]["sessions"] = serde_json::Value::Array(sessions);
        assert!(
            task4_replay_identity_files(
                "detailed-identity",
                &ledger,
                &lines(&changed)?,
                &rendered,
                &offsets
            )
            .is_err(),
            "Detailed terminal with {count} Sessions was accepted"
        );
    }
    let mut changed = raw.clone();
    changed[1]["sessions"][1]["stats"][0]["entered"] = serde_json::json!(1);
    assert!(
        task4_replay_identity_files(
            "detailed-identity",
            &ledger,
            &lines(&changed)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut changed = raw.clone();
    changed[0]["stats_map_id"] = serde_json::json!(23);
    assert!(
        task4_replay_identity_files(
            "detailed-identity",
            &ledger,
            &lines(&changed)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut changed = raw.clone();
    changed[2]["image"]["task_cookie"] = serde_json::json!(2);
    assert!(
        task4_replay_identity_files(
            "detailed-identity",
            &ledger,
            &lines(&changed)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    let mut changed = raw.clone();
    changed[12]["pid_tgid"] = raw[14]["pid_tgid"].clone();
    assert!(
        task4_replay_identity_files(
            "detailed-identity",
            &ledger,
            &lines(&changed)?,
            &rendered,
            &offsets
        )
        .is_err()
    );
    assert!(
        task4_replay_registration(&lines(&registration[..11])?, &offsets, "second_attached")
            .is_err()
    );
    let mut changed = registration.clone();
    for row in &mut changed[11..] {
        row["stats_map_id"] = serde_json::json!(1);
    }
    assert!(task4_replay_registration(&lines(&changed)?, &offsets, "second_attached").is_err());
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    eprintln!("TASK4_SYNTHETIC_BUNDLE path={}", directory.display());
    Ok(())
}

fn task4_replay_identity_files(
    case: &str,
    ledger_bytes: &[u8],
    raw_bytes: &[u8],
    rendered_bytes: &[u8],
    offsets_bytes: &[u8],
) -> Result<(usize, usize)> {
    ensure!(matches!(case, "inventory-identity" | "detailed-identity"));
    let detailed = case == "detailed-identity";
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    ensure!(offsets.len() == 2);
    for (slot, row) in offsets.iter().enumerate() {
        ensure!(
            row["slot"].as_u64() == Some(slot as u64)
                && row["names"] == serde_json::json!(["C_Finalize", "C_Initialize"])
        );
    }
    ensure!(
        offsets[0]["object"] != offsets[1]["object"]
            && (offsets[0]["dev"] != offsets[1]["dev"] || offsets[0]["ino"] != offsets[1]["ino"])
            && offsets[0]["offset"] == offsets[1]["offset"]
    );
    let ledger = task4_jsonl(ledger_bytes)?;
    let raw = task4_jsonl(raw_bytes)?;
    ensure!(ledger.len() == if detailed { 14 } else { 7 });
    let mut pids = [0_u64; 2];
    for slot in 0..2 {
        let row = &ledger[slot];
        let pid = row["pid"].as_u64().context("identity READY PID")?;
        ensure!(
            pid > 0
                && row["kind"] == "barrier"
                && row["phase"] == "pre_go"
                && row["slot"] == slot
                && row["object"] == offsets[slot]["object"]
                && row["reply"] == format!("READY {pid}")
        );
        pids[slot] = pid;
    }
    ensure!(pids[0] != pids[1]);
    for slot in 0..2 {
        let row = &ledger[slot + 2];
        ensure!(
            row["kind"] == "barrier"
                && row["phase"] == "after_go"
                && row["slot"] == slot
                && row["pid"] == pids[slot]
                && row["object"] == offsets[slot]["object"]
                && row["reply"] == format!("GO {}", pids[slot])
        );
    }
    let call_rows: Vec<_> = ledger.iter().filter(|row| row["kind"] == "call").collect();
    let slots: &[usize] = if detailed { &[0, 0, 1, 1] } else { &[0, 0, 1] };
    ensure!(call_rows.len() == slots.len());
    for (position, (&slot, call)) in slots.iter().zip(&call_rows).enumerate() {
        let rv = if detailed && position % 2 == 1 { 5 } else { 0 };
        let alias = position == 1;
        let command = if alias { "RETURNED_ALIAS" } else { "RETURNED" };
        let input = call["input"].as_u64().context("identity input")?;
        ensure!(
            call["kind"] == "call"
                && call["phase"] == "after_go"
                && call["position"] == position
                && call["slot"] == slot
                && call["object"] == offsets[slot]["object"]
                && call["local_id"] == 0
                && call["pid"] == pids[slot]
                && call["rv"] == rv
                && input == rv
                && call["reply"] == format!("{command} 0 {input} {rv}")
                && call["invoked_table_name"] == if alias { "C_Finalize" } else { "C_Initialize" },
            "identity child reply or table-field provenance changed"
        );
    }
    if detailed {
        for (at, slot, reply) in [
            (4, 0, "ARMED 0"),
            (5, 0, "BODY 0"),
            (6, 0, "RESUMED 0"),
            (9, 1, "ARMED 0"),
            (10, 1, "BODY 0"),
            (11, 1, "RESUMED 0"),
        ] {
            let row = &ledger[at];
            ensure!(
                row["kind"] == "barrier"
                    && row["phase"] == "after_go"
                    && row["slot"] == slot
                    && row["pid"] == pids[slot]
                    && row["object"] == offsets[slot]["object"]
                    && row["reply"] == reply
            );
        }
        for (at, position) in [(7, 0), (8, 1), (12, 2), (13, 3)] {
            ensure!(
                ledger[at] == *call_rows[position],
                "identity held-call order changed"
            );
        }
        ensure!(raw.len() == 17 && rendered_bytes.ends_with(b"\n"));
        let rendered: Vec<_> = rendered_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        ensure!(rendered.len() == 4);
        let witness_a = &raw[0];
        let snapshot_a = &raw[1];
        let witness_b = &raw[2];
        let snapshot_b = &raw[3];
        ensure!(
            snapshot_a["kind"] == "cross_session_snapshot"
                && snapshot_a["phase"] == "after_original"
                && snapshot_b["kind"] == "cross_session_snapshot"
                && snapshot_b["phase"] == "after_copy"
        );
        let first = &snapshot_a["sessions"][0];
        let second_before = &snapshot_a["sessions"][1];
        let first_after = &snapshot_b["sessions"][0];
        let second = &snapshot_b["sessions"][1];
        task4_identity_assert_snapshot(first, Some(0))?;
        task4_identity_assert_snapshot(second_before, None)?;
        task4_identity_assert_snapshot(second, Some(1))?;
        ensure!(first_after == first);
        for (slot, witness, snapshot) in [(0, witness_a, first), (1, witness_b, second)] {
            let generation = slot + 1;
            ensure!(
                witness["kind"] == "image_witness"
                    && witness["phase"] == "held_first_call"
                    && witness["position"] == slot
                    && witness["slot"] == slot
                    && witness["pid_tgid"] == (pids[slot] << 32 | pids[slot])
                    && witness["ts_ns"].as_u64().is_some_and(|ts| ts > 0)
                    && witness["image"]["task_cookie"]
                        .as_u64()
                        .is_some_and(|cookie| cookie > 0)
                    && witness["session_generation"] == generation
                    && witness["stats_map_id"] == snapshot["stats_map_id"]
                    && witness["scope_pid"] == pids[slot]
                    && snapshot["session_generation"] == generation
                    && snapshot["scope_pid"] == pids[slot]
                    && snapshot["view_role"] == if slot == 0 { "original" } else { "copy" }
            );
        }
        ensure!(first["stats_map_id"] != second["stats_map_id"]);
        ensure!(witness_a["foreign_at_hold"] == task4_identity_foreign_at_hold(second_before));
        ensure!(witness_b["foreign_at_hold"] == task4_identity_foreign_at_hold(first));
        for (index, row) in raw[4..8].iter().enumerate() {
            let generation = index / 2;
            let slot = index % 2;
            let source = if generation == 0 { first } else { second };
            ensure!(
                row["kind"] == "stats"
                    && row["phase"] == "after_go"
                    && row["slot"] == slot
                    && row["session_generation"] == generation + 1
                    && row["stats_map_id"] == source["stats_map_id"]
                    && row["scope_pid"] == pids[generation]
                    && row["view_role"] == if generation == 0 { "original" } else { "copy" }
            );
            for key in ["entered", "returned", "errors", "in_flight"] {
                ensure!(row[key] == source["stats"][slot][key]);
            }
        }
        for (index, row) in raw[8..12].iter().enumerate() {
            let generation = index / 2;
            let source = if generation == 0 { first } else { second };
            ensure!(
                row["kind"] == "rv"
                    && row["phase"] == "after_go"
                    && row["session_generation"] == generation + 1
                    && row["stats_map_id"] == source["stats_map_id"]
                    && row["scope_pid"] == pids[generation]
                    && row["slot"] == generation
                    && row["rv"] == if index % 2 == 0 { 0 } else { 5 }
                    && row["count"] == 1
            );
        }
        for (position, row) in raw[12..16].iter().enumerate() {
            let slot = position / 2;
            let witness = if slot == 0 { witness_a } else { witness_b };
            let source = if slot == 0 { first } else { second };
            let rv = if position % 2 == 0 { 0 } else { 5 };
            let ts = row["ts_ns"].as_u64().context("identity CALL time")?;
            let duration = row["duration_ns"]
                .as_u64()
                .context("identity CALL duration")?;
            ensure!(
                row["kind"] == "call"
                    && row["phase"] == "after_go"
                    && row["position"] == position
                    && row["slot"] == slot
                    && row["rv"] == rv
                    && row["event_type"] == u64::from(event_type::CALL)
                    && row["pid_tgid"] == (pids[slot] << 32 | pids[slot])
                    && row["image"] == witness["image"]
                    && row["dev"] == offsets[slot]["dev"]
                    && row["ino"] == offsets[slot]["ino"]
                    && row["offset"] == offsets[slot]["offset"]
                    && row["session_generation"] == slot + 1
                    && row["stats_map_id"] == source["stats_map_id"]
                    && row["scope_pid"] == pids[slot]
                    && row["view_role"] == if slot == 0 { "original" } else { "copy" }
                    && (position % 2 != 0 || ts.checked_sub(duration) == witness["ts_ns"].as_u64())
            );
            let line = std::str::from_utf8(rendered[position])?;
            ensure!(
                line.contains("C_Finalize")
                    && line.contains("C_Initialize")
                    && line.contains("[semantics unverified]")
            );
        }
        let terminal = &raw[16];
        ensure!(
            terminal["kind"] == "terminal"
                && terminal["phase"] == "terminal"
                && terminal["ring_loss"] == 0
                && terminal["raw_calls"] == 4
                && terminal["rendered"] == 4
                && terminal["pending"] == 0
                && terminal["orphan_ops"] == 0
                && terminal["unmatched_closes"] == 0
        );
        let sessions = terminal["sessions"]
            .as_array()
            .context("terminal Sessions")?;
        ensure!(
            sessions.len() == 2,
            "Detailed terminal requires two Sessions"
        );
        for (slot, row) in sessions.iter().enumerate() {
            let source = if slot == 0 { first } else { second };
            ensure!(
                row["session_generation"] == slot + 1
                    && row["stats_map_id"] == source["stats_map_id"]
                    && row["scope_pid"] == pids[slot]
                    && row["view_role"] == if slot == 0 { "original" } else { "copy" }
                    && row["start_rows"] == 0
                    && row["raw_calls"] == 2
                    && row["ring_malformed"] == 0
                    && row["owner"]["limit"] == THREAD_OWNER_LIMIT
            );
            for key in [
                "outstanding",
                "poison",
                "admission_failures",
                "reclamation_failures",
                "abandoned_start",
                "abandoned_discovery",
            ] {
                ensure!(row["owner"][key] == 0);
            }
            for map in ["kernel", "discovery"] {
                for (_, value) in row[map].as_object().context("terminal counters")? {
                    ensure!(*value == 0);
                }
                ensure!(row[map] == terminal[map]);
            }
        }
        Ok((4, 4))
    } else {
        for (at, position) in [(4, 0), (5, 1), (6, 2)] {
            ensure!(ledger[at] == *call_rows[position]);
        }
        ensure!(raw.len() == 13 && rendered_bytes.is_empty());
        for (index, (slot, before, after)) in
            [(0, 0, 1), (0, 1, 1), (1, 0, 1)].into_iter().enumerate()
        {
            let row = &raw[index + 3];
            ensure!(
                row["kind"] == "usage_step"
                    && row["phase"] == "after_go"
                    && row["position"] == index
                    && row["slot"] == slot
                    && row["before"] == before
                    && row["after"] == after
            );
        }
        for (at, phase, positive) in [(0, "pre_go", 0), (6, "after_go", 2), (9, "terminal", 2)] {
            let row = &raw[at];
            ensure!(
                row["kind"] == "usage_phase"
                    && row["phase"] == phase
                    && row["cells_read"] == 2
                    && row["positive_count"] == positive
                    && row["newly_positive"]
                        == if positive == 0 || phase == "terminal" {
                            serde_json::json!([])
                        } else {
                            serde_json::json!([0, 1])
                        }
            );
            for slot in 0..2 {
                let usage = &raw[at + 1 + slot];
                ensure!(
                    usage["kind"] == "usage"
                        && usage["phase"] == phase
                        && usage["slot"] == slot
                        && usage["value"] == if positive == 0 { 0 } else { 1 }
                );
            }
        }
        ensure!(
            raw[12]["kind"] == "terminal"
                && raw[12]["phase"] == "terminal"
                && raw[12]["usage_positive"] == 2
                && raw[12]["terminal_unsettled"] == true
                && raw[12]["usage_integrity_failures"] == 0
                && raw[12]["usage_read_failures"] == 0
                && raw[12]["health"] == raw[9]["health"]
        );
        Ok((3, 0))
    }
}

#[derive(Clone, Copy)]
struct Task4SessionWitness {
    session_generation: u64,
    stats_map_id: u32,
    scope_pid: u32,
    pid_filter_token: u64,
}

fn task4_session_witness(
    session: &crate::attach::Session,
    ids: &OwnedIds,
    session_generation: u64,
    scope_pid: u32,
) -> Result<Task4SessionWitness> {
    ensure!(session_generation > 0 && scope_pid > 0);
    let stats_map_id = detailed_map_data(session.ebpf.map("STATS").context("STATS map")?)?
        .info()?
        .id();
    ensure!(stats_map_id > 0 && ids.maps.contains(&stats_map_id));
    let pid_filter: HashMap<_, u32, u64> =
        HashMap::try_from(session.ebpf.map("PID_FILTER").context("PID_FILTER map")?)?;
    let entries = pid_filter
        .iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        entries.len() == 1 && entries[0].0 == scope_pid && entries[0].1 == 1,
        "Detailed PID_FILTER is not the exact owned PID entry"
    );
    Ok(Task4SessionWitness {
        session_generation,
        stats_map_id,
        scope_pid,
        pid_filter_token: entries[0].1,
    })
}

fn task4_session_ids(phase: &str, witness: Task4SessionWitness, ids: &OwnedIds) {
    eprintln!(
        "TASK4_SESSION_IDS phase={phase} session_generation={} stats_map_id={} scope_pid={} pid_filter_token={} maps={} programs={} links={}",
        witness.session_generation,
        witness.stats_map_id,
        witness.scope_pid,
        witness.pid_filter_token,
        task4_ids_csv(&ids.maps),
        task4_ids_csv(&ids.programs),
        task4_ids_csv(&ids.links)
    );
}

fn task4_fresh_pinned_hash(file: &std::fs::File) -> Result<String> {
    use std::os::unix::fs::FileExt as _;
    let len = file.metadata()?.len();
    ensure!(
        len <= TASK4_FILE_LIMIT as u64,
        "owned pinned ELF exceeds evidence limit"
    );
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    while offset < len {
        let count = usize::try_from((len - offset).min(chunk.len() as u64))?;
        let read = file.read_at(&mut chunk[..count], offset)?;
        ensure!(read > 0, "borrowed pinned ELF ended before metadata size");
        digest.update(&chunk[..read]);
        offset += read as u64;
    }
    Ok(task4_digest_hex(digest.finalize()))
}

fn task4_record_registration(
    session: &crate::attach::Session,
    ids: &OwnedIds,
    slots: &[Slot],
    pins: &PinnedObjects,
    witness: Task4SessionWitness,
    evidence: &mut Task4Evidence,
    phase: &str,
) -> Result<()> {
    use crate::attach::{ProbeSide, RegisteredLink};
    let n = slots.len();
    let expected: BTreeSet<_> = slots
        .iter()
        .flat_map(|slot| {
            [
                (slot.index, ProbeSide::Return),
                (slot.index, ProbeSide::Entry),
            ]
        })
        .collect();
    ensure!(
        session.successful_static == expected,
        "Detailed static registration tuple missing"
    );
    let retained: BTreeSet<_> = session
        .links
        .iter()
        .filter_map(|link| match link {
            RegisteredLink::UProbe { program, slot, .. } if *program == "p11_return" => {
                Some((*slot, ProbeSide::Return))
            }
            RegisteredLink::UProbe { program, slot, .. } if *program == "p11_entry" => {
                Some((*slot, ProbeSide::Entry))
            }
            _ => None,
        })
        .collect();
    ensure!(retained == expected && session.retained_static.len() == n);
    ensure!(
        pins.check_unchanged().map_err(anyhow::Error::msg)?,
        "Detailed registration pin changed"
    );
    let return_program = session
        .ebpf
        .program("p11_return")
        .context("return program")?
        .info()?
        .id();
    let entry_program = session
        .ebpf
        .program("p11_entry")
        .context("entry program")?
        .info()?
        .id();
    ensure!(return_program != entry_program);
    let lifecycle: BTreeMap<_, _> = ["sched_process_exec", "sched_process_exit", "task_newtask"]
        .into_iter()
        .map(|name| -> Result<_> {
            Ok((session.ebpf.program(name).context(name)?.info()?.id(), name))
        })
        .collect::<Result<_>>()?;
    ensure!(
        lifecycle.len() == 3
            && !lifecycle.contains_key(&return_program)
            && !lifecycle.contains_key(&entry_program)
    );
    let mut pin_facts = BTreeMap::new();
    for target in slots {
        if pin_facts.contains_key(&target.object) {
            continue;
        }
        let file = pins
            .file_for(target.object)
            .context("borrowed Detailed pin")?;
        let summary = pins
            .summary(target.object)
            .context("Detailed pin summary")?;
        let mapping = mapping_file_key(file).map_err(anyhow::Error::msg)?;
        let metadata = file.metadata()?;
        let fresh = task4_fresh_pinned_hash(file)?;
        ensure!(
            mapping.device_major == summary.key.device.major
                && mapping.device_minor == summary.key.device.minor
                && mapping.inode == summary.key.inode
                && metadata.ino() == summary.key.inode
                && summary.sha256 == fresh
                && pins.abi_for(target.object) == Some(ElfAbi::Lp64)
        );
        pin_facts.insert(
            target.object,
            (metadata.dev(), metadata.ino(), summary.key, fresh),
        );
    }
    for (position, (slot, side)) in expected.iter().enumerate() {
        let target = &slots[*slot as usize];
        let retained = session
            .retained_static
            .get(slot)
            .context("retained static target")?;
        ensure!(
            retained.slot.file_offset == target.file_offset
                && retained.slot.object == target.object
                && retained.slot.descriptor_index == target.descriptor_index
                && retained.path
                    == pins
                        .attach_path_for(target.object)
                        .map_err(anyhow::Error::msg)?
                && retained.abi == ElfAbi::Lp64
        );
        let (dev, ino, pin_key, fresh_sha256) = pin_facts
            .get(&target.object)
            .context("Detailed pin facts")?;
        let summary = pins.summary(target.object).context("Detailed pin digest")?;
        ensure!(retained.abi == pins.abi_for(target.object).context("Detailed pin ABI")?);
        let (role, program, program_id) = match side {
            ProbeSide::Return => ("return", "p11_return", return_program),
            ProbeSide::Entry => ("entry", "p11_entry", entry_program),
        };
        evidence.registration_row(serde_json::json!({
            "kind":"static","phase":phase,"position":position,"slot":slot,
            "role":role,"program":program,"program_id":program_id,
            "object":target.object.0,"dev":dev,"ino":ino,
            "offset":target.file_offset,"pin_unchanged":true,
            "session_generation":witness.session_generation,
            "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
            "pid_filter_token":witness.pid_filter_token,
            "descriptor_index":target.descriptor_index,
            "requested_attach_cookie":p11scope_ebpf_common::attach_cookie(
                target.index, target.descriptor_index),
            "cookie_provenance":"userspace_requested","pin_id":target.object.0,
            "pin_key":{"device_major":pin_key.device.major,
                "device_minor":pin_key.device.minor,"inode":pin_key.inode},
            "pin_sha256":summary.sha256.to_string(),
            "fresh_pin_sha256":fresh_sha256,"abi":"Lp64"
        }))?;
    }
    let infos = owned_link_info_snapshot(&ids.programs)?;
    ensure!(infos.len() == ids.links.len());
    let mut role_counts = [0usize; 2];
    for (position, (id, info)) in infos.iter().enumerate() {
        ensure!(ids.links.contains(id) && info.raw.id == *id);
        let (role, program) = if info.raw.prog_id == return_program {
            role_counts[0] += 1;
            ("return", "p11_return")
        } else if info.raw.prog_id == entry_program {
            role_counts[1] += 1;
            ("entry", "p11_entry")
        } else {
            (
                "other",
                *lifecycle
                    .get(&info.raw.prog_id)
                    .context("unexpected non-static program in Detailed link census")?,
            )
        };
        if role != "other" {
            ensure!(info.raw.type_ == bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32);
        } else {
            let expected = if program == "task_newtask" {
                bpf_link_type::BPF_LINK_TYPE_TRACING as u32
            } else {
                bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32
            };
            ensure!(
                info.raw.type_ == expected,
                "Detailed lifecycle link type differs from retained attach role"
            );
        }
        evidence.registration_row(serde_json::json!({
            "kind":"kernel_link","phase":phase,"position":position,
            "link_id":id,"program_id":info.raw.prog_id,
            "type":info.raw.type_,"info_len":info.returned_len,"role":role,
            "program":program,
            "session_generation":witness.session_generation,
            "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
            "pid_filter_token":witness.pid_filter_token
        }))?;
    }
    ensure!(
        role_counts == [n, n] && infos.len() == 2 * n + 3,
        "Detailed kernel per-program link census omitted a side or lifecycle role"
    );
    Ok(())
}

fn task4_replay_registration(bytes: &[u8], offsets_bytes: &[u8], phase: &str) -> Result<()> {
    let rows = task4_jsonl(bytes)?;
    let offsets: Vec<serde_json::Value> = serde_json::from_slice(offsets_bytes)?;
    let n = offsets.len();
    ensure!(n > 0);
    let identity = phase == "second_attached";
    ensure!(rows.len() == if identity { 22 } else { 4 * n + 3 });
    let groups: Vec<_> = if identity {
        ensure!(n == 2);
        vec![
            (&rows[..11], "first_attached", 1_u64),
            (&rows[11..], "second_attached", 2_u64),
        ]
    } else {
        vec![(&rows[..], phase, 1_u64)]
    };
    let mut anchors = BTreeSet::new();
    let mut scopes = BTreeSet::new();
    let mut all_programs = BTreeSet::new();
    let mut all_links = BTreeSet::new();
    for (group, expected_phase, generation) in groups {
        ensure!(group.len() == 4 * n + 3);
        let static_rows = &group[..2 * n];
        let kernel_rows = &group[2 * n..];
        let anchor = group[0]["stats_map_id"].as_u64().context("STATS map ID")?;
        let scope = group[0]["scope_pid"].as_u64().context("PID scope")?;
        ensure!(
            anchor > 0
                && anchor <= u32::MAX as u64
                && scope > 0
                && scope <= u32::MAX as u64
                && anchors.insert(anchor)
                && scopes.insert(scope)
        );
        let mut program_ids = BTreeMap::new();
        for (position, row) in static_rows.iter().enumerate() {
            let slot = position / 2;
            let (role, program) = if position % 2 == 0 {
                ("return", "p11_return")
            } else {
                ("entry", "p11_entry")
            };
            let program_id = row["program_id"]
                .as_u64()
                .context("registered program ID")?;
            let digest = row["pin_sha256"].as_str().context("pinned SHA-256")?;
            let fresh = row["fresh_pin_sha256"]
                .as_str()
                .context("fresh borrowed SHA-256")?;
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                    && digest == fresh
            );
            ensure!(
                row["kind"] == "static"
                    && row["phase"] == expected_phase
                    && row["position"] == position
                    && row["slot"] == slot
                    && row["role"] == role
                    && row["program"] == program
                    && row["dev"] == offsets[slot]["dev"]
                    && row["ino"] == offsets[slot]["ino"]
                    && row["offset"] == offsets[slot]["offset"]
                    && row["object"] == offsets[slot]["object"]
                    && row["pin_unchanged"] == true
                    && row["session_generation"] == generation
                    && row["stats_map_id"] == anchor
                    && row["scope_pid"] == scope
                    && row["pid_filter_token"] == 1
                    && row["descriptor_index"] == 0
                    && row["requested_attach_cookie"]
                        == p11scope_ebpf_common::attach_cookie(slot as u32, 0)
                    && row["cookie_provenance"] == "userspace_requested"
                    && row["pin_id"] == row["object"]
                    && row["pin_key"]["device_major"].as_u64().is_some()
                    && row["pin_key"]["device_minor"].as_u64().is_some()
                    && row["pin_key"]["inode"] == row["ino"]
                    && row["abi"] == "Lp64"
                    && program_id > 0,
                "Detailed retained static tuple or pin provenance differs from endpoint"
            );
            if let Some(prior) = program_ids.insert(role, program_id) {
                ensure!(prior == program_id);
            }
        }
        ensure!(program_ids.len() == 2 && program_ids["return"] != program_ids["entry"]);
        let mut link_ids = BTreeSet::new();
        let mut role_counts = [0usize; 2];
        let mut lifecycle = BTreeMap::new();
        for (position, row) in kernel_rows.iter().enumerate() {
            let id = row["link_id"].as_u64().context("kernel link ID")?;
            let program_id = row["program_id"].as_u64().context("kernel program ID")?;
            let (role, program) = if program_id == program_ids["return"] {
                role_counts[0] += 1;
                ("return", "p11_return")
            } else if program_id == program_ids["entry"] {
                role_counts[1] += 1;
                ("entry", "p11_entry")
            } else {
                let name = row["program"].as_str().context("lifecycle program")?;
                ensure!(lifecycle.insert(name, program_id).is_none());
                ("other", name)
            };
            let kind = match role {
                "return" | "entry" => bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u64,
                "other" if program == "task_newtask" => bpf_link_type::BPF_LINK_TYPE_TRACING as u64,
                "other" => bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u64,
                _ => unreachable!(),
            };
            ensure!(
                row["kind"] == "kernel_link"
                    && row["phase"] == expected_phase
                    && row["position"] == position
                    && id > 0
                    && link_ids.insert(id)
                    && row["role"] == role
                    && row["program"] == program
                    && row["type"] == kind
                    && row["info_len"]
                        .as_u64()
                        .is_some_and(|len| (12..=64).contains(&len))
                    && row["session_generation"] == generation
                    && row["stats_map_id"] == anchor
                    && row["scope_pid"] == scope
                    && row["pid_filter_token"] == 1,
                "Detailed borrowed-FD kernel link census changed"
            );
        }
        ensure!(
            role_counts == [n, n]
                && lifecycle.keys().copied().collect::<BTreeSet<_>>()
                    == BTreeSet::from(["sched_process_exec", "sched_process_exit", "task_newtask"])
        );
        let group_programs: BTreeSet<_> = program_ids
            .values()
            .copied()
            .chain(lifecycle.values().copied())
            .collect();
        ensure!(
            group_programs.len() == 5
                && all_programs.is_disjoint(&group_programs)
                && all_links.is_disjoint(&link_ids)
        );
        all_programs.extend(group_programs);
        all_links.extend(link_ids);
    }
    Ok(())
}

#[test]
fn task4_detailed_registration_rejects_missing_tail_entry_and_kernel_link() -> Result<()> {
    let offsets = serde_json::to_vec(&vec![
        serde_json::json!({"object":0,"dev":1,"ino":2,"offset":100}),
        serde_json::json!({"object":0,"dev":1,"ino":2,"offset":200}),
    ])?;
    let mut rows = Vec::new();
    for slot in 0..2_u64 {
        for (role, program, program_id) in
            [("return", "p11_return", 10), ("entry", "p11_entry", 11)]
        {
            rows.push(serde_json::json!({
                "kind":"static","phase":"attached","position":rows.len(),
                "slot":slot,"role":role,"program":program,"program_id":program_id,
                "object":0,"dev":1,"ino":2,"offset":100+100*slot,"pin_unchanged":true,
                "session_generation":1,"stats_map_id":21,"scope_pid":77,
                "pid_filter_token":1,"descriptor_index":0,
                "requested_attach_cookie":slot,"cookie_provenance":"userspace_requested",
                "pin_id":0,"pin_key":{"device_major":0,"device_minor":1,"inode":2},
                "pin_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "fresh_pin_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "abi":"Lp64"
            }));
        }
    }
    for (position, program_id) in [10, 10, 11, 11].into_iter().enumerate() {
        rows.push(serde_json::json!({
            "kind":"kernel_link","phase":"attached","position":position,
            "link_id":position+100,"program_id":program_id,
            "type":bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,"info_len":32,
            "role":if program_id == 10 {"return"} else {"entry"},
            "program":if program_id == 10 {"p11_return"} else {"p11_entry"},
            "session_generation":1,"stats_map_id":21,"scope_pid":77,
            "pid_filter_token":1
        }));
    }
    for (index, program) in ["sched_process_exec", "sched_process_exit", "task_newtask"]
        .into_iter()
        .enumerate()
    {
        rows.push(serde_json::json!({
            "kind":"kernel_link","phase":"attached","position":index+4,
            "link_id":index+104,"program_id":index+20,
            "type":if program=="task_newtask" {
                bpf_link_type::BPF_LINK_TYPE_TRACING as u32
            } else {bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32},
            "info_len":32,
            "role":"other","program":program,
            "session_generation":1,"stats_map_id":21,"scope_pid":77,
            "pid_filter_token":1
        }));
    }
    let encode = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    task4_replay_registration(&encode(&rows)?, &offsets, "attached")?;
    let mut missing = rows.clone();
    missing.remove(3);
    assert!(task4_replay_registration(&encode(&missing)?, &offsets, "attached").is_err());
    let mut missing = rows.clone();
    missing.remove(7);
    assert!(task4_replay_registration(&encode(&missing)?, &offsets, "attached").is_err());
    for (key, replacement) in [
        ("requested_attach_cookie", serde_json::json!(2)),
        (
            "pin_sha256",
            serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ),
        ("abi", serde_json::json!("Ilp32")),
        ("session_generation", serde_json::json!(2)),
        ("stats_map_id", serde_json::json!(22)),
    ] {
        let mut changed = rows.clone();
        changed[0][key] = replacement;
        assert!(
            task4_replay_registration(&encode(&changed)?, &offsets, "attached").is_err(),
            "registration accepted a changed {key}"
        );
    }
    Ok(())
}

#[test]
fn task4_optional_perf_availability_rejects_unobserved_cookie() -> Result<()> {
    let mut rows = vec![
        serde_json::json!({"role":"lifecycle"}),
        serde_json::json!({"role":"lifecycle"}),
        serde_json::json!({
            "role":"entry",
            "kernel_perf_detail":{"capability":"base_only_5_15"},
            "kernel_perf_availability":{
                "type":null,"offset":null,"cookie":null,"reason":"base_only_info_len_32"
            }
        }),
    ];
    let encode = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    task4_replay_link_availability(&encode(&rows)?)?;
    rows[2]["kernel_perf_availability"]["cookie"] = serde_json::json!(17);
    assert!(task4_replay_link_availability(&encode(&rows)?).is_err());
    rows[2]["kernel_perf_availability"]["cookie"] = serde_json::Value::Null;
    rows[2]["kernel_perf_availability"]["reason"] = serde_json::json!("kernel_layout_5_15");
    assert!(task4_replay_link_availability(&encode(&rows)?).is_err());
    Ok(())
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
    let repeats = task4_inventory_repeats(offsets.len());
    let expected_calls = match case {
        "inventory" => offsets.len() + repeats.len(),
        "detailed" => offsets.len() * 2,
        "highslot-exit" | "highslot-exec" => 1,
        _ => bail!("unknown Task 4 evidence case {case}"),
    };
    let expected_raw_rows = match case {
        "inventory" => 4 * (offsets.len() + 1) + 1 + offsets.len(),
        "detailed" => 5 * offsets.len() + 2,
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
            "inventory" => (u64::from(repeats[position - offsets.len()]), 0),
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
        let steps: Vec<_> = raw
            .iter()
            .filter(|row| row["kind"] == "usage_step")
            .collect();
        ensure!(
            steps.len() == offsets.len(),
            "replay lacks serial Inventory usage steps"
        );
        for (position, row) in steps.iter().enumerate() {
            ensure!(
                row["phase"] == "after_go"
                    && row["position"].as_u64() == Some(position as u64)
                    && row["slot"].as_u64() == Some(position as u64)
                    && row["before"].as_u64() == Some(0)
                    && row["after"].as_u64() == Some(1)
                    && row["slot"] == calls[position]["slot"],
                "replay Inventory first-call usage transition changed at {position}"
            );
        }
        let pre_go = raw
            .iter()
            .position(|row| row["kind"] == "usage_phase" && row["phase"] == "pre_go")
            .context("Inventory pre-GO phase row")?;
        let after_go = raw
            .iter()
            .position(|row| row["kind"] == "usage_phase" && row["phase"] == "after_go")
            .context("Inventory after-GO phase row")?;
        let first_step = raw
            .iter()
            .position(|row| row["kind"] == "usage_step")
            .context("Inventory first usage step")?;
        let last_step = raw
            .iter()
            .rposition(|row| row["kind"] == "usage_step")
            .context("Inventory last usage step")?;
        let first_after_go_usage = raw
            .iter()
            .position(|row| row["kind"] == "usage" && row["phase"] == "after_go")
            .context("Inventory first after-GO usage row")?;
        ensure!(pre_go < first_step && last_step < after_go && after_go < first_after_go_usage);
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
        let witness = if case == "detailed" {
            let rows: Vec<_> = raw
                .iter()
                .filter(|row| row["kind"] == "image_witness")
                .collect();
            ensure!(
                rows.len() == 1,
                "replay Detailed held START witness missing"
            );
            let row = rows[0];
            ensure!(
                row["phase"] == "held_first_call"
                    && row["position"].as_u64() == Some(0)
                    && row["slot"].as_u64() == Some(0)
                    && row["pid_tgid"].as_u64().is_some_and(|pid| pid != 0)
                    && row["ts_ns"].as_u64().is_some_and(|ts| ts != 0)
                    && row["image"]["task_cookie"]
                        .as_u64()
                        .is_some_and(|cookie| cookie != 0)
                    && row["image"]["exec_id"].as_u64().is_some(),
                "replay Detailed held START witness malformed"
            );
            ensure!(
                raw.iter()
                    .position(|candidate| candidate["kind"] == "image_witness")
                    < raw.iter().position(|candidate| candidate["kind"] == "call"),
                "replay Detailed witness followed completed CALL"
            );
            Some(row)
        } else {
            None
        };
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
                let held = witness.context("Detailed witness missing")?;
                ensure!(
                    row["pid_tgid"] == held["pid_tgid"] && row["image"] == held["image"],
                    "replay Detailed CALL differs from held START image or owner"
                );
                if position == 0 {
                    let ts = row["ts_ns"].as_u64().context("first CALL timestamp")?;
                    let duration = row["duration_ns"].as_u64().context("first CALL duration")?;
                    ensure!(
                        ts.checked_sub(duration) == held["ts_ns"].as_u64(),
                        "replay first Detailed CALL is not the held START frame"
                    );
                }
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

#[cfg(not(feature = "wide-detailed-2112"))]
fn task4_identity_fixture_receipt(identity: &Task4IdentityFixture) -> Result<()> {
    let directory = PathBuf::from(
        std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR")
            .context("P11SCOPE_TASK4_EVIDENCE_DIR required")?,
    );
    let index: usize = std::env::var("P11SCOPE_TASK4_CASE_INDEX")?.parse()?;
    task4_identity_fixture_receipt_at(identity, &directory, index)
}

fn task4_identity_fixture_receipt_at(
    identity: &Task4IdentityFixture,
    directory: &Path,
    index: usize,
) -> Result<()> {
    ensure!(index < 100);
    let fixture = &identity.fixture;
    let original = std::fs::read(&fixture.path)?;
    let copy = std::fs::read(&identity.copy_path)?;
    ensure!(
        original == copy && task4_hash(&original) == fixture.expected_sha256,
        "identity fixture bytes changed after pinning"
    );
    let offsets: Vec<_> = fixture
        .plan
        .slots
        .iter()
        .map(|slot| -> Result<_> {
            let meta = std::fs::metadata(&slot.object_path)?;
            Ok(serde_json::json!({
                "slot":slot.index,"object":slot.object.0,"dev":meta.dev(),"ino":meta.ino(),
                "offset":slot.file_offset,"names":slot.names
            }))
        })
        .collect::<Result<_>>()?;
    ensure!(offsets.len() == 2);
    let offsets_bytes = serde_json::to_vec(&offsets)?;
    std::fs::write(directory.join(format!("fixture-{index:02}.elf")), &original)?;
    std::fs::write(
        directory.join(format!("fixture-{index:02}-copy.elf")),
        &copy,
    )?;
    std::fs::write(
        directory.join(format!("offsets-{index:02}.json")),
        &offsets_bytes,
    )?;
    eprintln!(
        "TASK4_FIXTURE elf_sha256={} offsets_sha256={}",
        task4_hash(&original),
        task4_hash(&offsets_bytes)
    );
    eprintln!(
        "TASK4_PHYSICAL endpoints=2 unique_keys=true alias_names=2 equal_bytes=true distinct_inode=true"
    );
    Ok(())
}

fn task4_identity_seal_receipt_at(
    identity: &Task4IdentityFixture,
    directory: &Path,
    index: usize,
) -> Result<()> {
    let checks = *identity.retained_checks.borrow();
    ensure!(index < 100 && checks == [[true; 3]; 2]);
    let fixture = &identity.fixture;
    ensure!(fixture.pins.check_unchanged().map_err(anyhow::Error::msg)?);
    let make = |role: &str, slot_index: u32, view: &ProcessView, checks: [bool; 3]| -> Result<_> {
        let slot = &fixture.plan.slots[slot_index as usize];
        let summary = fixture
            .pins
            .summary(slot.object)
            .context("identity live pin")?;
        let file = fixture
            .pins
            .file_for(slot.object)
            .context("identity borrowed pin")?;
        let meta = file.metadata()?;
        let namespace = view.mount_namespace();
        ensure!(view.still_the_same() && meta.ino() == summary.key.inode);
        Ok(serde_json::json!({
            "slot":slot_index,"object":slot.object.0,"dev":meta.dev(),"ino":meta.ino(),
            "pin_key":{"device_major":summary.key.device.major,
                "device_minor":summary.key.device.minor,"inode":summary.key.inode},
            "sha256":summary.sha256.to_string(),"abi":"Lp64",
            "names":slot.names,"offset":slot.file_offset,
            "table":{"version":[2,40],"linkage":"interface",
                "ordinal_names":["C_Initialize","C_Finalize"],
                "ordinal_offsets":[slot.file_offset,slot.file_offset]},
            "process_view":{"role":role,"pid":view.pid(),
                "mount_namespace":{"device":namespace.device,"inode":namespace.inode},
                "admitted_ns":view.admitted_ns(),
                "retained_checks":{"post_scan":checks[0],"pre_go":checks[1],
                    "after_calls":checks[2]}}
        }))
    };
    let original = make(
        "original",
        identity.original_slot,
        &identity.views[0],
        checks[0],
    )?;
    let copy = make("copy", identity.copy_slot, &identity.views[1], checks[1])?;
    ensure!(original["pin_key"] != copy["pin_key"] && original["sha256"] == copy["sha256"]);
    let row = serde_json::json!({
        "schema":2,"mode":"alias_equal_bytes_distinct_inode",
        "original":original,"copy":copy,
        "alias_pair":["owned_0","owned_alias_0"],
        "alias_pair_source":"elf_defined_symbols",
        "equal_bytes":true,"distinct_inode":true
    });
    let bytes = serde_json::to_vec(&row)?;
    ensure!(bytes.len() <= TASK4_FILE_LIMIT);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(format!("case-{index:02}-identity.json")))?
        .write_all(&bytes)?;
    Ok(())
}

fn task4_identity_seal_receipt(identity: &Task4IdentityFixture) -> Result<()> {
    let directory = PathBuf::from(
        std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR")
            .context("P11SCOPE_TASK4_EVIDENCE_DIR required")?,
    );
    let index: usize = std::env::var("P11SCOPE_TASK4_CASE_INDEX")?.parse()?;
    task4_identity_seal_receipt_at(identity, &directory, index)
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
    inventory_sweep_gate(2_112, None)
}

fn inventory_sweep_gate(n: u32, cell: Option<&'static str>) -> Result<()> {
    let repeats = task4_inventory_repeats(n as usize);
    let origin = Instant::now();
    eprintln!(
        "TASK4_PROFILE name={} detailed_slots={} rv_keys={} inventory_budget={n}",
        if cfg!(feature = "wide-detailed-2112") {
            "wide-detailed-2112"
        } else {
            "default"
        },
        p11scope_ebpf_common::MAX_SLOTS,
        p11scope_ebpf_common::RV_ENTRIES
    );
    let mut fixture = OwnedFixture::build_n(false, n)?;
    verify_task4_physical_slots(&fixture.plan.slots, n as usize)?;
    task4_fixture_receipt(&fixture)?;
    let profile = if cfg!(feature = "wide-detailed-2112") {
        "wide-detailed-2112"
    } else {
        "default"
    };
    let mut evidence = Task4Evidence::new_control(
        "inventory",
        profile,
        &fixture,
        crate::EBPF_INVENTORY_OBJECT,
        cell.map(|name| {
            (
                name,
                "complete",
                "single_unique_offsets",
                "inventory-global.elf",
            )
        }),
    )?;
    evidence.fd_sample("baseline")?;
    let targets = fixture.targets()?;
    let budget =
        InventoryBudget::new(u64::from(n), 8 * u64::from(n)).map_err(anyhow::Error::msg)?;
    let prepare_start = Instant::now();
    let prepared = PreparedInventory::prepare(Scope::System, budget, AttachBackend::Singles)?;
    let prepare_ms = prepare_start.elapsed().as_millis();
    let usage_data =
        super::super::inventory_map_data("USAGE", prepared.ebpf.map("USAGE").context("USAGE")?)?.1;
    let usage_meta = super::super::super::read_map_metadata("USAGE", usage_data)?;
    ensure!(
        usage_meta.max_entries == n && usage_meta.value_size == 8,
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
    eprintln!("TASK4_LOADED_MAPS USAGE={n} START=absent RV_COUNTS=absent EVENTS=absent");
    let registry_start = Instant::now();
    let mut ids = OwnedIds::prepared(&prepared)?;
    let registry_ms = registry_start.elapsed().as_millis();
    let attach_start = Instant::now();
    let mut active = prepared
        .activate(targets)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let attach_ms = attach_start.elapsed().as_millis();
    for mut row in ids.inspect_links(&active.state, n as usize)? {
        if cell.is_some() && row["role"] == "entry" {
            row["kernel_perf_availability"] = task4_perf_availability(&row["kernel_perf_detail"])?;
        }
        evidence.link_row(row)?;
    }
    ensure!(
        ids.links.len() == n as usize + 2,
        "incomplete Inventory link set"
    );
    if cell.is_some() {
        task4_ids_phase("attached", &ids);
    }
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_attach")?;
    eprintln!(
        "TASK4_PHASE prepare_ms={prepare_ms} attach_ms={attach_ms} registry_ms={registry_ms} probes={n}"
    );
    fixture.pins = PinnedObjects::empty();
    let window =
        || InventoryReadWindow::new(n as usize, Instant::now() + Duration::from_secs(60)).unwrap();
    let zero = active.usage_snapshot(window());
    assert_health(&zero)?;
    ensure!(
        zero.usage.cells_read == n as usize && zero.usage.positive_count == 0,
        "Inventory was positive before GO or missed initial cells"
    );
    evidence.inventory_snapshot("pre_go", &zero)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "pre_go", n)?;
    let mut caller = fixture.spawn_gated()?;
    evidence.caller(&mut caller, "pre_go")?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_EXEC)?;
    caller.go()?;
    evidence.caller(&mut caller, "after_go")?;
    let usage: Array<_, u64> = Array::try_from(
        active
            .state
            .prepared
            .ebpf
            .map("USAGE")
            .context("serial Inventory USAGE evidence map")?,
    )?;
    for id in 0..n {
        let before = usage.get(&id, 0)?;
        ensure!(
            before == 0,
            "Inventory USAGE[{id}] positive before its first call"
        );
        caller.call_exact(id, 0)?;
        let after = usage.get(&id, 0)?;
        ensure!(
            after == 1,
            "Inventory USAGE[{id}] did not latch its first call"
        );
        evidence.raw_row(serde_json::json!({
            "kind":"usage_step","phase":"after_go","position":id,
            "slot":id,"before":before,"after":after
        }))?;
        if id % 64 == 63 {
            evidence.caller(&mut caller, "after_go")?;
        }
    }
    evidence.caller(&mut caller, "after_go")?;
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids={n} completed_calls={n} first=0 tail={}",
        n - 1
    );
    let positive = active.usage_snapshot(window());
    assert_health(&positive)?;
    ensure!(
        positive.usage.cells_read == n as usize && positive.usage.positive_count == n as usize,
        "Inventory did not read every cell positive"
    );
    ensure!(
        positive.usage.newly_positive == (0..n).collect::<Vec<_>>(),
        "Inventory per-ID set differs from owned workload ledger"
    );
    evidence.inventory_snapshot("after_go", &positive)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "after_go", n)?;
    eprintln!(
        "TASK4_RAW_MAPS phase=after_go usage_positive={n} exact_ids=0..{}",
        n - 1
    );
    for &id in &repeats {
        caller.call_exact(id, 0)?;
        evidence.caller(&mut caller, "after_repeat")?;
    }
    let repeated = active.usage_snapshot(window());
    assert_health(&repeated)?;
    ensure!(
        repeated.usage.cells_read == n as usize
            && repeated.usage.positive_count == n as usize
            && repeated.usage.newly_positive.is_empty(),
        "Inventory repeated calls changed the latched all-ID set"
    );
    evidence.inventory_snapshot("after_repeat", &repeated)?;
    task4_inventory_usage(
        &mut evidence,
        &active.state.prepared.ebpf,
        "after_repeat",
        n,
    )?;
    eprintln!(
        "TASK4_REPEAT ids={} completed_calls={} newly_positive=0",
        repeats
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
        repeats.len()
    );
    caller.finish()?;
    evidence.caller(&mut caller, "after_repeat")?;
    await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    evidence.fd_sample("pre_detach")?;
    let stop_start = Instant::now();
    let mut retiring = active.begin_stop();
    // r2 measured 39.236 s / 578 links and 72.265 s / 1026 links.
    // Serial detach therefore projects beyond the old 420 s budget at
    // N=6530. Budget bounded owned work at >2x the measured per-link cost;
    // this is a harness deadline, not a product stop-latency acceptance.
    let stop_budget = Duration::from_millis((u64::from(n) + 2) * 150).max(Duration::from_secs(420));
    eprintln!(
        "TASK4_RETIRE_BUDGET links={} budget_ms={}",
        n + 2,
        stop_budget.as_millis()
    );
    finish_owned_retirement_inner(&mut retiring, true, stop_budget)?;
    let stop_ms = stop_start.elapsed().as_millis();
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("wide retirement did not finish"))?;
    ensure!(
        retired.cleanup.closed == n as usize + 2 && retired.cleanup.failures.is_empty(),
        "Inventory retirement omitted owned links"
    );
    let terminal = retired.usage_snapshot(window());
    assert_health(&terminal)?;
    ensure!(
        terminal.usage.cells_read == n as usize
            && terminal.usage.positive_count == n as usize
            && terminal.usage.newly_positive.is_empty(),
        "terminal Inventory map/health differs from all-ID positive ledger"
    );
    evidence.inventory_snapshot("terminal", &terminal)?;
    task4_inventory_usage(&mut evidence, &retired.state.prepared.ebpf, "terminal", n)?;
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal",
        "usage_positive":terminal.usage.positive_count,
        "terminal_unsettled":terminal.terminal_unsettled,
        "usage_integrity_failures":terminal.usage_integrity_failures,
        "usage_read_failures":terminal.usage_read_failures,
        "health":format!("{:?}",terminal.health)
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal inventory_positive={n} exact_physical_ids=true ordinary_return_maps=absent"
    );
    drop(retired);
    let release_start = Instant::now();
    ids.released_with_budget(Duration::from_secs(60))?;
    let release_ms = release_start.elapsed().as_millis();
    eprintln!("TASK4_LOSS ring=0 usage=0 owner=0");
    evidence.finish()?;
    eprintln!(
        "TASK4_TIMING links={} prepare_ms={prepare_ms} attach_ms={attach_ms} stop_ms={stop_ms} registry_ms={registry_ms} release_ms={release_ms} elapsed_ms={}",
        n + 2,
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

#[cfg(not(feature = "wide-detailed-2112"))]
macro_rules! inventory_sweep_test {
    ($name:ident, $n:literal, $cell:literal) => {
        #[test]
        #[ignore = "root-owned BPF lane; bounded physical Inventory sweep"]
        fn $name() -> Result<()> {
            inventory_sweep_gate($n, Some($cell))
        }
    };
}
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_task4_inventory_n511_lp64,
    511,
    "inventory-default-n511"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_task4_inventory_n512_lp64,
    512,
    "inventory-default-n512"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_task4_inventory_n513_lp64,
    513,
    "inventory-default-n513"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_task4_inventory_n2048_lp64,
    2048,
    "inventory-default-n2048"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_task4_inventory_n2049_lp64,
    2049,
    "inventory-default-n2049"
);
// T7 (finish plan box 6): controller-owned live coverage at 576/1024/4097,
// the 6530 motivating union, and the 8192 within-budget boundary. Inventory
// N is profile-independent, so these run on the default profile only. Each
// cell calls every admitted ID and requires the exact all-ID positive set;
// the controller checks the FD/link preflight (ordinary T7 math test) first.
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(privileged_t7_inventory_n576_lp64, 576, "inventory-t7-n576");
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_t7_inventory_n1024_lp64,
    1024,
    "inventory-t7-n1024"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_t7_inventory_n4097_lp64,
    4097,
    "inventory-t7-n4097"
);
#[cfg(not(feature = "wide-detailed-2112"))]
inventory_sweep_test!(
    privileged_t7_inventory_n6530_lp64,
    6530,
    "inventory-t7-n6530"
);
/// T7 L-T7-5 boundary cell: the sweep plus an explicit out-of-envelope
/// refusal branch. The preflight gate samples live FD occupancy against
/// `RLIMIT_NOFILE` before attaching; the post-failure classifier converts an
/// FD-exhaustion failure into the same refusal verdict. Both emit
/// `T7_ENVELOPE_REFUSAL` and return `Ok` as a separate result — never a
/// coverage pass, never an ambiguous failure. Any other error still fails.
#[cfg(not(feature = "wide-detailed-2112"))]
fn t7_boundary_cell_gate(n: u32, cell: &'static str) -> Result<()> {
    let open_fds = std::fs::read_dir("/proc/self/fd")?
        .collect::<std::io::Result<Vec<_>>>()?
        .len() as u64;
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: getrlimit writes a complete rlimit value to valid storage.
    ensure!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0);
    if let Err(verdict) =
        crate::capacity::t7_boundary_preflight(u64::from(n), limit.rlim_cur, open_fds)
    {
        eprintln!("T7_ENVELOPE_REFUSAL cell={cell} n={n} phase=preflight verdict=\"{verdict}\"");
        return Ok(());
    }
    match inventory_sweep_gate(n, Some(cell)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let message = format!("{error:?}");
            if crate::capacity::t7_is_envelope_exhaustion(&message) {
                eprintln!(
                    "T7_ENVELOPE_REFUSAL cell={cell} n={n} phase=post_failure_classification verdict=\"{message}\""
                );
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(not(feature = "wide-detailed-2112"))]
#[test]
#[ignore = "root-owned BPF lane; bounded physical Inventory sweep with envelope refusal branch"]
fn privileged_t7_inventory_n8192_boundary_lp64() -> Result<()> {
    t7_boundary_cell_gate(8192, "inventory-t7-n8192-boundary")
}

#[cfg(not(feature = "wide-detailed-2112"))]
#[cfg(not(feature = "wide-detailed-2112"))]
#[test]
#[ignore = "root-owned BPF lane; real aliased symbol and same-byte distinct-inode Inventory targets"]
fn privileged_task4_inventory_physical_identity_controls() -> Result<()> {
    let budget = InventoryBudget::new(2, 16).map_err(anyhow::Error::msg)?;
    let mut identity = Task4IdentityFixture::build(AdmissionPolicy::Inventory(budget))?;
    task4_identity_fixture_receipt(&identity)?;
    let (original, copy) = identity.take_callers()?;
    let fixture = &identity.fixture;
    let mut evidence = Task4Evidence::new_control(
        "inventory-identity",
        "default",
        fixture,
        crate::EBPF_INVENTORY_OBJECT,
        Some((
            "inventory-physical-identity",
            "complete-identity",
            "alias_equal_bytes_distinct_inode",
            "inventory-global.elf",
        )),
    )?;
    evidence.fd_sample("baseline")?;
    eprintln!("TASK4_PROFILE name=default detailed_slots=512 rv_keys=4096 inventory_budget=2");
    let prepared = PreparedInventory::prepare(Scope::System, budget, AttachBackend::Singles)?;
    let usage_meta = super::super::super::read_map_metadata(
        "USAGE",
        super::super::inventory_map_data("USAGE", prepared.ebpf.map("USAGE").context("USAGE")?)?.1,
    )?;
    ensure!(usage_meta.max_entries == 2 && usage_meta.value_size == 8);
    for absent in ["START", "RV_COUNTS", "EVENTS"] {
        ensure!(prepared.ebpf.map(absent).is_none());
    }
    eprintln!(
        "TASK4_LOADED_OBJECT kind=inventory-global.elf sha256={}",
        task4_hash(crate::EBPF_INVENTORY_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS USAGE=2 START=absent RV_COUNTS=absent EVENTS=absent");
    let mut ids = OwnedIds::prepared(&prepared)?;
    let mut active = prepared
        .activate(fixture.targets()?)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    for mut row in ids.inspect_links(&active.state, 2)? {
        if row["role"] == "entry" {
            row["kernel_perf_availability"] = task4_perf_availability(&row["kernel_perf_detail"])?;
        }
        evidence.link_row(row)?;
    }
    ensure!(ids.links.len() == 4);
    task4_ids_phase("attached", &ids);
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_attach")?;
    let window = || InventoryReadWindow::new(2, Instant::now() + Duration::from_secs(30)).unwrap();
    let zero = active.usage_snapshot(window());
    assert_health(&zero)?;
    ensure!(zero.usage.cells_read == 2 && zero.usage.positive_count == 0);
    evidence.inventory_snapshot("pre_go", &zero)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "pre_go", 2)?;
    fixture.assert_caller_identity(&original)?;
    identity.assert_copy_caller(&copy)?;
    let mut callers = vec![
        (identity.original_slot, original),
        (identity.copy_slot, copy),
    ];
    callers.sort_by_key(|(slot, _)| *slot);
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        evidence.identity_caller(caller, "pre_go", *slot, object)?;
        await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_EXEC)?;
    }
    identity.check_views(1, &[&callers[0].1, &callers[1].1])?;
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        caller.go()?;
        evidence.identity_caller(caller, "after_go", *slot, object)?;
    }
    let usage: Array<_, u64> = Array::try_from(
        active
            .state
            .prepared
            .ebpf
            .map("USAGE")
            .context("identity USAGE")?,
    )?;
    let mut step_position = 0;
    for (slot, caller) in &mut callers {
        let object = fixture.plan.slots[*slot as usize].object.0;
        let before = usage.get(slot, 0)?;
        ensure!(before == 0);
        caller.call_exact(0, 0)?;
        evidence.identity_caller(caller, "after_go", *slot, object)?;
        let after = usage.get(slot, 0)?;
        ensure!(after == 1);
        evidence.raw_row(serde_json::json!({
            "kind":"usage_step","phase":"after_go","position":step_position,
            "slot":slot,"before":before,"after":after
        }))?;
        step_position += 1;
        if *slot == identity.original_slot {
            caller.call_alias_exact(0)?;
            evidence.identity_caller(caller, "after_go", *slot, object)?;
            let repeat = usage.get(slot, 0)?;
            ensure!(repeat == 1);
            evidence.raw_row(serde_json::json!({
                "kind":"usage_step","phase":"after_go","position":step_position,
                "slot":slot,"before":after,"after":repeat
            }))?;
            step_position += 1;
        }
    }
    ensure!(step_position == 3);
    eprintln!("TASK4_LEDGER phase=after_go physical_ids=2 completed_calls=3 first=0 tail=1");
    let positive = active.usage_snapshot(window());
    assert_health(&positive)?;
    ensure!(
        positive.usage.cells_read == 2
            && positive.usage.positive_count == 2
            && positive.usage.newly_positive == vec![0, 1]
    );
    evidence.inventory_snapshot("after_go", &positive)?;
    task4_inventory_usage(&mut evidence, &active.state.prepared.ebpf, "after_go", 2)?;
    identity.check_views(2, &[&callers[0].1, &callers[1].1])?;
    task4_identity_seal_receipt(&identity)?;
    for (slot, caller) in &mut callers {
        caller.finish()?;
        let object = fixture.plan.slots[*slot as usize].object.0;
        evidence.identity_caller(caller, "terminal", *slot, object)?;
        await_lifecycle(&mut active, caller.child.id(), DISCOVERY_KIND_LEADER_EXIT)?;
    }
    evidence.fd_sample("pre_detach")?;
    let mut retiring = active.begin_stop();
    finish_owned_retirement_inner(&mut retiring, true, Duration::from_secs(60))?;
    let mut retired = retiring
        .try_finish()
        .map_err(|_| anyhow::anyhow!("identity retirement unfinished"))?;
    ensure!(retired.cleanup.closed == 4 && retired.cleanup.failures.is_empty());
    let terminal = retired.usage_snapshot(window());
    assert_health(&terminal)?;
    ensure!(terminal.usage.positive_count == 2 && terminal.usage.newly_positive.is_empty());
    evidence.inventory_snapshot("terminal", &terminal)?;
    task4_inventory_usage(&mut evidence, &retired.state.prepared.ebpf, "terminal", 2)?;
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","usage_positive":2,
        "terminal_unsettled":terminal.terminal_unsettled,
        "usage_integrity_failures":terminal.usage_integrity_failures,
        "usage_read_failures":terminal.usage_read_failures,
        "health":format!("{:?}",terminal.health)
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal inventory_positive=2 exact_physical_ids=true ordinary_return_maps=absent"
    );
    drop(retired);
    ids.released_with_budget(Duration::from_secs(60))?;
    eprintln!("TASK4_LOSS ring=0 usage=0 owner=0");
    evidence.finish()?;
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    Ok(())
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
    verify_task4_call_sequence_n(rows, 2_112)
}

fn verify_task4_call_sequence_n(rows: &[(u32, u64)], endpoints: usize) -> Result<()> {
    ensure!(
        rows.len() == endpoints * 2,
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

#[test]
fn task4_detailed_n512_sequence_is_exact() {
    let mut rows: Vec<_> = (0..512).flat_map(|slot| [(slot, 0), (slot, 5)]).collect();
    assert!(verify_task4_call_sequence_n(&rows, 512).is_ok());
    rows.swap(0, 2);
    rows.swap(1, 3);
    assert!(verify_task4_call_sequence_n(&rows, 512).is_err());
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

fn assert_task4_detailed_maps(
    session: &crate::attach::Session,
    completed: bool,
    endpoints: u32,
) -> Result<()> {
    let expected = if completed { 2 } else { 0 };
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    for id in 0..endpoints {
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
            key.slot < endpoints && key._pad == 0 && [0, 5].contains(&key.rv),
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
        seen.len() == if completed { 2 * endpoints as usize } else { 0 },
        "Detailed RV key cardinality"
    );
    for id in 0..endpoints {
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

fn task4_detailed_rows(
    session: &crate::attach::Session,
    evidence: &mut Task4Evidence,
    endpoints: u32,
) -> Result<()> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    for slot in 0..endpoints {
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

fn task4_identity_session_snapshot(
    session: &mut crate::attach::Session,
    witness: Task4SessionWitness,
    view_role: &str,
    calls_seen: usize,
) -> Result<serde_json::Value> {
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("identity START")?)?;
    let start_rows = starts
        .iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .len();
    let owner: Array<_, ThreadOwnerControl> = Array::try_from(
        session
            .ebpf
            .map("OWNER_CTL")
            .context("identity OWNER_CTL")?,
    )?;
    let control = owner.get(&0, 0)?;
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("identity STATS")?)?;
    let mut stats_rows = Vec::with_capacity(2);
    for slot in 0..2 {
        let mut total = SlotStats::ZERO;
        for cpu in stats.get(&slot, 0)?.iter() {
            total.entered += cpu.entered;
            total.returned += cpu.returned;
            total.errors += cpu.errors;
        }
        stats_rows.push(serde_json::json!({
            "slot":slot,"entered":total.entered,"returned":total.returned,
            "errors":total.errors,
            "in_flight":total.entered.saturating_sub(total.returned)
        }));
    }
    let rv_map: PerCpuHashMap<_, RvKey, u64> = PerCpuHashMap::try_from(
        session
            .ebpf
            .map("RV_COUNTS")
            .context("identity RV_COUNTS")?,
    )?;
    let mut rv_rows = BTreeMap::new();
    for entry in rv_map.iter() {
        let (key, values) = entry?;
        ensure!(key.slot < 2 && key._pad == 0 && [0, 5].contains(&key.rv));
        ensure!(
            rv_rows
                .insert((key.slot, key.rv), values.iter().sum::<u64>())
                .is_none()
        );
    }
    let rv_rows: Vec<_> = rv_rows
        .into_iter()
        .map(|((slot, rv), count)| serde_json::json!({"slot":slot,"rv":rv,"count":count}))
        .collect();
    let kernel = crate::metrics::kernel_evidence(session)?;
    Ok(serde_json::json!({
        "session_generation":witness.session_generation,
        "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
        "view_role":view_role,"start_rows":start_rows,
        "owner_outstanding":control.outstanding,
        "ring_malformed":session.event_drain()?.malformed(),
        "ring_loss":kernel.ring_loss,"calls_seen":calls_seen,
        "stats":stats_rows,"rv":rv_rows
    }))
}

fn task4_identity_held_start(
    session: &crate::attach::Session,
    slot: u32,
    pid: u32,
) -> Result<(ImageIdentity, u64)> {
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("held identity START")?)?;
    let held = starts.iter().collect::<std::result::Result<Vec<_>, _>>()?;
    let pid_tgid = u64::from(pid) << 32 | u64::from(pid);
    ensure!(
        held.len() == 1
            && held[0].0.slot == slot
            && held[0].0.pid_tgid == pid_tgid
            && held[0].1.ts_ns != 0
            && held[0].1.image.task_cookie != 0
    );
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("held identity STATS")?)?;
    let mut entered = 0;
    let mut returned = 0;
    for cpu in stats.get(&slot, 0)?.iter() {
        entered += cpu.entered;
        returned += cpu.returned;
    }
    ensure!((entered, returned) == (1, 0));
    Ok((held[0].1.image, held[0].1.ts_ns))
}

fn task4_identity_assert_snapshot(row: &serde_json::Value, own_slot: Option<u32>) -> Result<()> {
    ensure!(
        row["start_rows"] == 0
            && row["owner_outstanding"] == 0
            && row["ring_malformed"] == 0
            && row["ring_loss"] == 0
    );
    let expected_calls = if own_slot.is_some() { 2 } else { 0 };
    ensure!(row["calls_seen"] == expected_calls);
    for slot in 0..2_u32 {
        let stats = &row["stats"][slot as usize];
        let own = own_slot == Some(slot);
        ensure!(
            stats
                == &serde_json::json!({
                    "slot":slot,"entered":if own {2} else {0},
                    "returned":if own {2} else {0},
                    "errors":if own {1} else {0},"in_flight":0
                }),
            "identity Session STATS contains foreign traffic"
        );
    }
    let rv = if let Some(slot) = own_slot {
        serde_json::json!([
            {"slot":slot,"rv":0,"count":1},
            {"slot":slot,"rv":5,"count":1}
        ])
    } else {
        serde_json::json!([])
    };
    ensure!(
        row["rv"] == rv,
        "identity Session RV contains foreign traffic"
    );
    Ok(())
}

fn task4_identity_foreign_at_hold(row: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "session_generation":row["session_generation"],
        "stats_map_id":row["stats_map_id"],
        "start_rows":row["start_rows"],"calls_seen":row["calls_seen"],
        "stats":row["stats"],"rv":row["rv"]
    })
}

fn task4_identity_terminal_session(
    session: &mut crate::attach::Session,
    witness: Task4SessionWitness,
    view_role: &str,
    raw_calls: usize,
) -> Result<serde_json::Value> {
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("terminal START")?)?;
    let start_rows = starts
        .iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .len();
    let owner: Array<_, ThreadOwnerControl> = Array::try_from(
        session
            .ebpf
            .map("OWNER_CTL")
            .context("terminal OWNER_CTL")?,
    )?;
    let control = owner.get(&0, 0)?;
    let kernel = crate::metrics::kernel_evidence(session)?;
    let discovery = session.counter_snapshot()?;
    let malformed = session.event_drain()?.malformed();
    ensure!(start_rows == 0 && malformed == 0 && raw_calls == 2);
    ensure!(crate::attach::owner_control_fields(control) == [THREAD_OWNER_LIMIT, 0, 0, 0, 0, 0, 0]);
    ensure!(
        kernel == crate::metrics::KernelEvidence::default()
            && discovery == crate::attach::CounterSnapshot::default()
    );
    Ok(serde_json::json!({
        "session_generation":witness.session_generation,
        "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
        "view_role":view_role,"start_rows":start_rows,"raw_calls":raw_calls,
        "ring_malformed":malformed,
        "owner":{"limit":control.limit,"outstanding":control.outstanding,
            "poison":control.poison,"admission_failures":control.admission_failures,
            "reclamation_failures":control.reclamation_failures,
            "abandoned_start":control.abandoned_start,
            "abandoned_discovery":control.abandoned_discovery},
        "kernel":{"ring_loss":kernel.ring_loss,
            "start_insert_failures":kernel.start_insert_failures,
            "unmatched_returns":kernel.unmatched_returns,
            "rv_update_failures":kernel.rv_update_failures,
            "cgroup_scope_failures":kernel.cgroup_scope_failures,
            "semantic_capture_failures":kernel.semantic_capture_failures,
            "template_tail_failures":kernel.template_tail_failures,
            "unregistered_mechanisms":kernel.unregistered_mechanisms,
            "abi_refusals":kernel.abi_refusals},
        "discovery":{"ring_loss":discovery.ring_loss,
            "export_state_failures":discovery.export_state_failures,
            "export_bounded_read_failures":discovery.export_bounded_read_failures,
            "loader_hits":discovery.loader_hits,
            "loader_state_read_failures":discovery.loader_state_read_failures,
            "abi_refusals":discovery.abi_refusals}
    }))
}

#[cfg(feature = "wide-detailed-2112")]
fn wide_detailed_gate() -> Result<()> {
    detailed_sweep_gate(2_112, None)
}

fn detailed_sweep_gate(n: u32, cell: Option<&'static str>) -> Result<()> {
    ensure!(
        n <= p11scope_ebpf_common::MAX_SLOTS,
        "Detailed sweep exceeds profile cap"
    );
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
    let fixture = OwnedFixture::build_n(false, n)?;
    verify_task4_physical_slots(&fixture.plan.slots, n as usize)?;
    task4_fixture_receipt(&fixture)?;
    let profile = if cfg!(feature = "wide-detailed-2112") {
        "wide-detailed-2112"
    } else {
        "default"
    };
    let mut evidence = Task4Evidence::new_control(
        "detailed",
        profile,
        &fixture,
        crate::EBPF_OBJECT,
        cell.map(|name| (name, "complete", "single_unique_offsets", "detailed.elf")),
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
        session.attach_failures().is_empty() && session.attached_probes() == 2 * n as usize,
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
        map_max("STATS")? == p11scope_ebpf_common::MAX_SLOTS
            && map_max("RV_COUNTS")? == p11scope_ebpf_common::RV_ENTRIES
            && map_max("START")? == 16_384,
        "wrong loaded Detailed map bounds"
    );
    let events_capacity = map_max("EVENTS")?;
    ensure!(events_capacity >= 4_096, "Detailed EVENTS ring too small");
    eprintln!(
        "TASK4_LOADED_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    eprintln!(
        "TASK4_LOADED_MAPS STATS={} RV_COUNTS={} START=16384 EVENTS={events_capacity}",
        p11scope_ebpf_common::MAX_SLOTS,
        p11scope_ebpf_common::RV_ENTRIES
    );
    let registry_start = Instant::now();
    let ids = OwnedIds::detailed(&session)?;
    let registry_ms = registry_start.elapsed().as_millis();
    ensure!(
        ids.links.len() >= 2 * n as usize,
        "Detailed retained fewer links than paired probes"
    );
    if cell.is_some() {
        let witness = task4_session_witness(&session, &ids, 1, caller.child.id())?;
        task4_record_registration(
            &session,
            &ids,
            &fixture.plan.slots,
            &fixture.pins,
            witness,
            &mut evidence,
            "attached",
        )?;
        task4_ids_phase("attached", &ids);
    }
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_attach")?;
    eprintln!(
        "TASK4_PHASE attach_ms={attach_ms} registry_ms={registry_ms} probes={}",
        2 * n
    );
    assert_task4_detailed_maps(&session, false, n)?;
    let mut events = Vec::with_capacity(2 * n as usize);
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    evidence.caller(&mut caller, "after_go")?;
    caller.hold_exact_return_in_body(0, 0)?;
    evidence.caller(&mut caller, "after_go")?;
    let starts: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("held first START")?)?;
    let held = starts.iter().collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(held.len() == 1, "Detailed held first call lacks sole START");
    let (start_key, start) = held[0];
    let leader = u64::from(caller.child.id()) << 32 | u64::from(caller.child.id());
    ensure!(
        start_key.slot == 0
            && start_key._pad == 0
            && start_key.pid_tgid == leader
            && start.ts_ns != 0
            && start.image.task_cookie != 0,
        "Detailed held START is not the owned first call"
    );
    let witness_image = start.image;
    let witness_ts_ns = start.ts_ns;
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("held first STATS")?)?;
    let mut held_stats = SlotStats::ZERO;
    for cpu in stats.get(&0, 0)?.iter() {
        held_stats.entered += cpu.entered;
        held_stats.returned += cpu.returned;
    }
    ensure!(
        (held_stats.entered, held_stats.returned) == (1, 0),
        "Detailed first call was not held before return"
    );
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.is_empty(),
        "held Detailed entry emitted completed CALL"
    );
    evidence.raw_row(serde_json::json!({
        "kind":"image_witness","phase":"held_first_call","position":0,"slot":0,
        "pid_tgid":start_key.pid_tgid,"ts_ns":witness_ts_ns,
        "image":{"task_cookie":witness_image.task_cookie,"exec_id":witness_image.exec_id}
    }))?;
    caller.resume_exact_return(0, 0)?;
    evidence.caller(&mut caller, "after_go")?;
    for id in 0..n {
        if id != 0 {
            caller.call_exact(id, 0)?;
        }
        caller.call_exact(id, 5)?;
        if id % 32 == 31 {
            evidence.caller(&mut caller, "after_go")?;
            drain_task4_detailed(&mut session, &mut events)?;
        }
    }
    evidence.caller(&mut caller, "after_go")?;
    drain_task4_detailed(&mut session, &mut events)?;
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids={n} completed_calls={} rv0={n} rv5={n} first=0 tail={}",
        2 * n,
        n - 1
    );
    assert_task4_detailed_maps(&session, true, n)?;
    task4_detailed_rows(&session, &mut evidence, n)?;
    ensure!(
        events.len() == 2 * n as usize,
        "Detailed trace event count differs from fixture ledger"
    );
    let mut event_keys = BTreeMap::new();
    let mut sequence = Vec::with_capacity(2 * n as usize);
    let mut tracer = crate::trace::Tracer::new(&plan);
    let mut state =
        crate::semantics::State::with_policy(&plan, crate::attach::CapturePolicy::Allowlisted);
    let mut rendered_hash = Sha256::new();
    let mut rendered_count = 0u64;
    for (position, event) in events.iter().enumerate() {
        ensure!(
            event.slot < n && [0, 5].contains(&event.rv),
            "foreign Detailed event"
        );
        verify_task4_event_identity(event, caller.child.id(), Some(witness_image))?;
        if position == 0 {
            ensure!(
                event.ts_ns.checked_sub(event.duration_ns) == Some(witness_ts_ns),
                "first Detailed CALL is not the held START frame"
            );
        }
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
    verify_task4_call_sequence_n(&sequence, n as usize)?;
    ensure!(
        tracer.raw_calls() == u64::from(2 * n)
            && rendered_count == u64::from(2 * n)
            && event_keys.len() == 2 * n as usize,
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
        "TASK4_REDUCER raw_calls={} rendered={} pending=0 semantic_evidence=zero orphan_ops=0 unmatched_closes=0",
        2 * n,
        2 * n
    );
    for id in 0..n {
        for rv in [0, 5] {
            ensure!(
                event_keys.get(&(id, rv)) == Some(&1),
                "missing or doubled completed CALL slot {id} rv {rv}"
            );
        }
    }
    eprintln!(
        "TASK4_RAW_MAPS phase=after_go stats_entered={} stats_returned={} stats_errors={n} rv_keys={} start=0 owner_outstanding=0",
        2 * n,
        2 * n,
        2 * n
    );
    let rendered_digest = task4_digest_hex(rendered_hash.finalize());
    ensure!(
        task4_hash(&evidence.rendered.contents()?) == rendered_digest,
        "rendered stream and retained bytes differ"
    );
    eprintln!(
        "TASK4_TRACE phase=after_go calls={} rendered={} distinct_slot_rv={} ordered_ledger=true ring_malformed=0 rendered_sha256={rendered_digest}",
        2 * n,
        2 * n,
        2 * n
    );
    evidence.fd_sample("pre_detach")?;
    let stop_start = Instant::now();
    let detached = session.detach_producers();
    let stop_ms = stop_start.elapsed().as_millis();
    let clean_detach = session.detach_failures().is_empty();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 2 * n as usize,
        "terminal drain found unaccounted Detailed events"
    );
    assert_task4_detailed_maps(&session, true, n)?;
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
        "TASK4_RAW_SUMMARY phase=terminal stats_entered={} stats_returned={} rv_keys={} raw_calls={} rendered={} ordered_ledger=true",
        2 * n,
        2 * n,
        2 * n,
        2 * n,
        2 * n
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

#[test]
#[ignore = "root-owned BPF lane; Detailed per-call overhead bench, timed 1-thread CALL and 8-thread FANOUT batches"]
fn privileged_bench_overhead_detailed_calls() -> Result<()> {
    const ENDPOINTS: u32 = 8;
    const BATCH_1T: u32 = 4000;
    const WORKERS_8T: u32 = 8;
    const PERCALLS_8T: u32 = 500;
    const BATCH_8T: u32 = WORKERS_8T * PERCALLS_8T;
    const REPS: u32 = 25;
    const WARMUP: u32 = 2;
    const SLOT_1T: u32 = 0;

    let fixture = OwnedFixture::build_n(false, ENDPOINTS)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
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
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * ENDPOINTS as usize,
        "bench Detailed did not retain every paired static probe"
    );
    let ids = OwnedIds::detailed(&session)?;
    eprintln!(
        "BENCH_OVERHEAD_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    caller.go()?;
    for _ in 0..WARMUP {
        caller.calls(SLOT_1T, BATCH_1T)?;
        let mut warmed = Vec::new();
        drain_task4_detailed(&mut session, &mut warmed)?;
        ensure!(
            warmed.len() == BATCH_1T as usize,
            "warmup 1-thread event count differs from ledger"
        );
        caller.fanout_calls(WORKERS_8T, PERCALLS_8T)?;
        let mut warmed8 = Vec::new();
        drain_task4_detailed(&mut session, &mut warmed8)?;
        ensure!(
            warmed8.len() == BATCH_8T as usize,
            "warmup 8-thread event count differs from ledger"
        );
    }
    let mut wall_1t = Duration::new(0, 0);
    for _ in 0..REPS {
        caller.start_calls(SLOT_1T, BATCH_1T)?;
        let start = Instant::now();
        caller.finish_calls(SLOT_1T, BATCH_1T)?;
        wall_1t += start.elapsed();
        let mut events = Vec::new();
        drain_task4_detailed(&mut session, &mut events)?;
        ensure!(
            events.len() == BATCH_1T as usize,
            "timed 1-thread event count differs from ledger"
        );
    }
    let mut wall_8t = Duration::new(0, 0);
    for _ in 0..REPS {
        caller.start_fanout(WORKERS_8T, PERCALLS_8T)?;
        let start = Instant::now();
        caller.finish_fanout(WORKERS_8T, PERCALLS_8T)?;
        wall_8t += start.elapsed();
        let mut events = Vec::new();
        drain_task4_detailed(&mut session, &mut events)?;
        ensure!(
            events.len() == BATCH_8T as usize,
            "timed 8-thread event count differs from ledger"
        );
    }
    let calls_1t = u64::from(BATCH_1T) * u64::from(REPS);
    let calls_8t = u64::from(BATCH_8T) * u64::from(REPS);
    let wall_1t_ns = wall_1t.as_nanos();
    let wall_8t_ns = wall_8t.as_nanos();
    eprintln!(
        "BENCH_OVERHEAD threads=1 reps={REPS} batch={BATCH_1T} calls={calls_1t} wall_ns={wall_1t_ns} calls_per_s={:.0} ns_per_call={:.1}",
        calls_1t as f64 / wall_1t.as_secs_f64(),
        wall_1t_ns as f64 / calls_1t as f64
    );
    eprintln!(
        "BENCH_OVERHEAD threads=8 reps={REPS} workers={WORKERS_8T} percalls={PERCALLS_8T} calls={calls_8t} wall_ns={wall_8t_ns} calls_per_s={:.0} ns_per_call={:.1}",
        calls_8t as f64 / wall_8t.as_secs_f64(),
        wall_8t_ns as f64 / calls_8t as f64
    );
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    let mut terminal = Vec::new();
    drain_task4_detailed(&mut session, &mut terminal)?;
    ensure!(
        terminal.is_empty(),
        "terminal drain found unaccounted Detailed events"
    );
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "bench Detailed detach retained failures");
    Ok(())
}

/// D1/D5 regression (live repro: 12 SoftHSM threads froze capture within
/// ~10 ms). Every call reserves and refunds the one shared native owner
/// count; many threads on many CPUs must never poison it, never refuse an
/// admission, and every counter must be exact: STATS calls, RV_COUNTS rows
/// and errors equal the fixture's independent ledger, nothing in flight.
#[test]
#[ignore = "root-owned BPF lane; multi-thread owner accounting never poisons and counts exactly"]
fn privileged_detailed_multithread_owner_accounting_exact() -> Result<()> {
    let threads = std::thread::available_parallelism()
        .map(|cpus| u32::try_from(cpus.get()).unwrap_or(64))
        .unwrap_or(4)
        .clamp(4, 32);
    const PERCALLS: u32 = 200_000;
    let fixture = OwnedFixture::build_n(false, threads)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    // Aggregate policy still pairs every call through the native owner
    // (reserve at entry, refund at return) but emits no events, so ring
    // capacity cannot mask or excuse a counting defect.
    let session = crate::attach::Session::start(
        &plan,
        &Scope::Pid(caller.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::AggregateOnly,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )?;
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * threads as usize,
        "multithread Detailed did not retain every paired static probe"
    );
    let ids = OwnedIds::detailed(&session)?;
    caller.go()?;
    caller.hammer_calls(threads, PERCALLS)?;
    let reports = crate::metrics::read(&session, &plan)?;
    let kernel = crate::metrics::kernel_evidence(&session)?;
    let calls: u64 = reports.iter().map(|report| report.calls).sum();
    let in_flight: u64 = reports.iter().map(|report| report.in_flight).sum();
    let rv_total: u64 = reports
        .iter()
        .flat_map(|report| report.rv_counts.values())
        .sum();
    eprintln!(
        "MULTITHREAD_OWNER threads={threads} percalls={PERCALLS} expected={} calls={calls} \
         in_flight={in_flight} rv_total={rv_total} control={:?} kernel={kernel:?}",
        u64::from(threads) * u64::from(PERCALLS),
        kernel.control.evidence()
    );
    ensure!(
        kernel.control == crate::metrics::KernelControl::default(),
        "native owner poisoned or refused under multi-thread load: {:?}",
        kernel.control.evidence()
    );
    ensure!(
        kernel == crate::metrics::KernelEvidence::default(),
        "kernel evidence reports loss under multi-thread load: {kernel:?}"
    );
    ensure!(
        calls == u64::from(threads) * u64::from(PERCALLS) && in_flight == 0,
        "captured calls differ from the independent ledger"
    );
    ensure!(
        rv_total == calls,
        "RV_COUNTS rows disagree with STATS calls"
    );
    ensure!(
        reports.len() == plan.slots.len(),
        "one report per planned slot"
    );
    for (slot, report) in plan.slots.iter().zip(&reports) {
        // Thread t calls endpoint t with input 0, and endpoint t returns t.
        let rv = u64::from(slot.index);
        ensure!(
            report.calls == u64::from(PERCALLS)
                && report.rv_counts == BTreeMap::from([(rv, u64::from(PERCALLS))])
                && report.errors
                    == if rv == 0 || rv == 0x204 {
                        0
                    } else {
                        u64::from(PERCALLS)
                    },
            "per-slot counts differ from the ledger: {:?}",
            (
                report.names.clone(),
                report.calls,
                &report.rv_counts,
                report.errors
            )
        );
    }
    let mut session = session;
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(
        clean_detach,
        "multithread Detailed detach retained failures"
    );
    Ok(())
}

/// D1 disclosure end to end: a poisoned native owner (seeded before freeze)
/// halts every probe at its scope gate, userspace reads OWNER_CTL, and the
/// published evidence names the halt and is a concrete-gap PARTIAL, instead
/// of a quiet zero-call capture.
#[test]
#[ignore = "root-owned BPF lane; a poisoned native owner halts capture and is disclosed"]
fn privileged_detailed_owner_poison_is_disclosed() -> Result<()> {
    const CALLS: u32 = 1_000;
    let fixture = OwnedFixture::build_n(false, 1)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    crate::attach::TEST_OWNER_POISON
        .with(|seed| seed.set(p11scope_ebpf_common::OWNER_CLASSIFIER_FAILED));
    let started = crate::attach::Session::start(
        &plan,
        &Scope::Pid(caller.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::AggregateOnly,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    );
    crate::attach::TEST_OWNER_POISON.with(|seed| seed.set(0));
    let mut session = started?;
    let ids = OwnedIds::detailed(&session)?;
    caller.go()?;
    caller.calls(0, CALLS)?;
    let reports = crate::metrics::read(&session, &plan)?;
    let kernel = crate::metrics::kernel_evidence(&session)?;
    let calls: u64 = reports.iter().map(|report| report.calls).sum();
    let mut evidence = crate::render::tests::evidence();
    evidence.kernel_control = kernel.control.evidence();
    evidence.verdict();
    eprintln!(
        "OWNER_POISON_DISCLOSURE calls={calls} control={:?} verdict={}/{}",
        evidence.kernel_control, evidence.completeness, evidence.verdict_detail
    );
    ensure!(
        kernel.control.owner_poison == p11scope_ebpf_common::OWNER_CLASSIFIER_FAILED,
        "userspace did not read the sticky owner poison"
    );
    ensure!(calls == 0, "a halted owner still counted calls");
    ensure!(
        evidence.kernel_control.capture_halted
            && evidence.kernel_control.owner_poison == ["classifier_failed"]
            && evidence.completeness == "PARTIAL"
            && evidence.verdict_detail == crate::render::VERDICT_CONCRETE_GAP,
        "a halted capture was not disclosed as a named concrete gap"
    );
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "poisoned Detailed detach retained failures");
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
#[test]
#[ignore = "root-owned BPF lane; 2112 distinct physical Detailed slots, 4224 CALL events and exact raw RV rows"]
fn privileged_task4_detailed_2112_lp64() -> Result<()> {
    wide_detailed_gate()
}

macro_rules! detailed_sweep_test {
    ($name:ident, $n:literal, $cell:literal) => {
        #[test]
        #[ignore = "root-owned BPF lane; bounded physical Detailed sweep"]
        fn $name() -> Result<()> {
            detailed_sweep_gate($n, Some($cell))
        }
    };
}
#[cfg(feature = "wide-detailed-2112")]
detailed_sweep_test!(
    privileged_task4_detailed_n511_lp64,
    511,
    "detailed-wide-n511"
);
#[cfg(feature = "wide-detailed-2112")]
detailed_sweep_test!(
    privileged_task4_detailed_n512_lp64,
    512,
    "detailed-wide-n512"
);
#[cfg(feature = "wide-detailed-2112")]
detailed_sweep_test!(
    privileged_task4_detailed_n513_lp64,
    513,
    "detailed-wide-n513"
);
#[cfg(feature = "wide-detailed-2112")]
detailed_sweep_test!(
    privileged_task4_detailed_n2048_lp64,
    2048,
    "detailed-wide-n2048"
);
#[cfg(feature = "wide-detailed-2112")]
detailed_sweep_test!(
    privileged_task4_detailed_n2049_lp64,
    2049,
    "detailed-wide-n2049"
);
#[cfg(not(feature = "wide-detailed-2112"))]
detailed_sweep_test!(
    privileged_task4_detailed_n512_lp64,
    512,
    "detailed-default-n512"
);

// T7 (finish plan box 6): controller-owned live probe for a new RV key on an
// already-hot endpoint. Slot 0 heats with RVs {0,5} while old slots 1..8
// each take one call, then slot 0 takes a third RV. Profile-independent:
// the exact key/STAT/event assertions hold under both RV map sizes.
#[test]
#[ignore = "root-owned BPF lane; third RV key on a hot Detailed slot with exact per-plane rows"]
fn privileged_t7_detailed_hot_slot_third_rv_lp64() -> Result<()> {
    const N: u32 = 8;
    const HOT: u32 = 0;
    eprintln!(
        "TASK4_PROFILE name={} detailed_slots={} rv_keys={} hot_slot={HOT}",
        if cfg!(feature = "wide-detailed-2112") {
            "wide-detailed-2112"
        } else {
            "default"
        },
        p11scope_ebpf_common::MAX_SLOTS,
        p11scope_ebpf_common::RV_ENTRIES
    );
    let fixture = OwnedFixture::build_n(false, N)?;
    verify_task4_physical_slots(&fixture.plan.slots, N as usize)?;
    task4_fixture_receipt(&fixture)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
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
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * N as usize,
        "hot-RV Detailed did not retain every paired static probe"
    );
    let map_max = |name| -> Result<u32> {
        let map = session
            .ebpf
            .map(name)
            .with_context(|| format!("{name} map"))?;
        Ok(crate::attach::read_map_metadata(name, detailed_map_data(map)?)?.max_entries)
    };
    ensure!(
        map_max("STATS")? == p11scope_ebpf_common::MAX_SLOTS
            && map_max("RV_COUNTS")? == p11scope_ebpf_common::RV_ENTRIES
            && map_max("START")? == 16_384,
        "wrong loaded Detailed map bounds"
    );
    let ids = OwnedIds::detailed(&session)?;
    let mut events = Vec::new();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    caller.call_exact(HOT, 0)?;
    caller.call_exact(HOT, 5)?;
    for id in 1..N {
        caller.call_exact(id, 0)?;
    }
    caller.call_exact(HOT, 7)?;
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == (N + 2) as usize,
        "hot-RV event count differs from the owned ledger"
    );
    let mut event_keys = BTreeMap::new();
    for event in &events {
        ensure!(event.slot < N, "foreign Detailed event");
        *event_keys.entry((event.slot, event.rv)).or_insert(0u32) += 1;
    }
    for rv in [0u64, 5, 7] {
        ensure!(
            event_keys.get(&(HOT, rv)) == Some(&1),
            "missing or doubled hot CALL slot {HOT} rv {rv}"
        );
    }
    for id in 1..N {
        ensure!(
            event_keys.get(&(id, 0)) == Some(&1),
            "missing or doubled old-cell CALL slot {id}"
        );
    }
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    let slot_total = |id: u32| -> Result<(u64, u64, u64)> {
        let mut total = (0, 0, 0);
        for cpu in stats.get(&id, 0)?.iter() {
            total.0 += cpu.entered;
            total.1 += cpu.returned;
            total.2 += cpu.errors;
        }
        Ok(total)
    };
    ensure!(
        slot_total(HOT)? == (3, 3, 2),
        "hot slot raw STATS mismatch: {:?}",
        slot_total(HOT)?
    );
    for id in 1..N {
        ensure!(
            slot_total(id)? == (1, 1, 0),
            "old-cell slot {id} raw STATS mismatch: {:?}",
            slot_total(id)?
        );
    }
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let mut seen = BTreeMap::new();
    for entry in rvs.iter() {
        let (key, counts) = entry?;
        ensure!(
            key.slot < N && key._pad == 0,
            "foreign or malformed Detailed RV key"
        );
        ensure!(
            seen.insert((key.slot, key.rv), counts.iter().sum::<u64>())
                .is_none(),
            "duplicate Detailed RV key"
        );
    }
    ensure!(
        seen.len() == (N + 2) as usize,
        "hot-RV key cardinality differs: {}",
        seen.len()
    );
    for rv in [0u64, 5, 7] {
        ensure!(
            seen.get(&(HOT, rv)) == Some(&1),
            "hot slot RV key (0,{rv}) is not exactly once"
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
    ensure!(
        crate::attach::owner_control_fields(owner.get(&0, 0)?)
            == [THREAD_OWNER_LIMIT, 0, 0, 0, 0, 0, 0],
        "Detailed owner debt or failure"
    );
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
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "Detailed detach retained failures");
    eprintln!("T7_HOT_RV hot_slot={HOT} rvs=0,5,7 old_cells=1..{N} exact=true");
    Ok(())
}

fn task4_writer_evidence(endpoints: u32) -> Result<(tempfile::TempDir, Task4Evidence)> {
    let directory = tempfile::tempdir()?;
    let fixture = OwnedFixture::build_n(false, endpoints)?;
    let offsets: Vec<_> = fixture
        .plan
        .slots
        .iter()
        .map(|slot| slot.file_offset)
        .collect();
    std::fs::write(
        directory.path().join("offsets-00.json"),
        serde_json::to_vec(&offsets)?,
    )?;
    let evidence = Task4Evidence::new_control_at(
        "inventory",
        if cfg!(feature = "wide-detailed-2112") {
            "wide-detailed-2112"
        } else {
            "default"
        },
        &fixture,
        crate::EBPF_INVENTORY_OBJECT,
        None,
        directory.path().to_owned(),
        0,
    )?;
    Ok((directory, evidence))
}

fn task4_assert_complete_writer_sweep(
    endpoints: u32,
    raw_rows: usize,
    ledger_rows: usize,
    link_rows: usize,
) -> Result<()> {
    let (_directory, mut evidence) = task4_writer_evidence(endpoints)?;
    for (writer, rows) in [
        (&mut evidence.raw, raw_rows),
        (&mut evidence.ledger, ledger_rows),
        (evidence.links.as_mut().context("links writer")?, link_rows),
    ] {
        for position in 0..rows {
            writer.json(serde_json::json!({
                "kind": if position + 1 == rows { "terminal" } else { "sample" },
                "position": position,
            }))?;
        }
        let bytes = writer.contents()?;
        let lines: Vec<_> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .collect();
        ensure!(lines.len() == rows, "writer omitted an evidence row");
        let terminal: serde_json::Value = serde_json::from_slice(lines[rows - 1])?;
        ensure!(terminal["kind"] == "terminal" && terminal["position"] == rows - 1);
        ensure!(
            bytes.last() == Some(&b'\n'),
            "writer lost the final delimiter"
        );
    }
    Ok(())
}

// Counts are hand-derived from the live sweep's four map snapshots, per-entry
// transition rows and phase/terminal records, not from the writer's budget.
// This catches a fixed cap that truncates a valid sweep before its terminal row.
#[test]
fn task4_evidence_preserves_n4097_sweep() -> Result<()> {
    task4_assert_complete_writer_sweep(4_097, 20_490, 4_107, 4_099)
}

#[test]
fn task4_evidence_preserves_n6530_sweep() -> Result<()> {
    task4_assert_complete_writer_sweep(6_530, 32_655, 6_540, 6_532)
}

#[test]
fn task4_evidence_preserves_n8192_sweep() -> Result<()> {
    task4_assert_complete_writer_sweep(8_192, 40_965, 8_202, 8_194)
}

#[test]
fn task4_evidence_refuses_runaway_rows_without_writing() -> Result<()> {
    let (_directory, mut evidence) = task4_writer_evidence(8_192)?;
    for (writer, runaway_rows) in [
        (&mut evidence.raw, 409_650),
        (&mut evidence.ledger, 82_020),
        (evidence.links.as_mut().context("links writer")?, 81_940),
    ] {
        let mut refused = false;
        for written in 0..runaway_rows {
            if let Err(error) = writer.write(b"{}\n") {
                ensure!(
                    format!("{error:#}").contains("row limit"),
                    "wrong refusal: {error:#}"
                );
                let before = writer.contents()?;
                ensure!(before.len() == written * 3, "failed row was partly written");
                ensure!(writer.write(b"unexpected\n").is_err());
                ensure!(
                    writer.contents()? == before,
                    "refusal changed existing evidence"
                );
                refused = true;
                break;
            }
        }
        ensure!(refused, "writer admitted a tenfold runaway");
    }
    Ok(())
}

#[test]
fn task4_evidence_byte_limit_preserves_existing_bytes() -> Result<()> {
    let (_directory, mut evidence) = task4_writer_evidence(1)?;
    let at_limit = vec![b'x'; 16 * 1024 * 1024];
    evidence.raw.write(&at_limit)?;
    let error = evidence
        .raw
        .write(b"x")
        .expect_err("oversize file admitted");
    ensure!(format!("{error:#}").contains("16 MiB"));
    ensure!(
        evidence.raw.contents()? == at_limit,
        "failed write changed evidence"
    );
    Ok(())
}

// T7 fix round 2: the owned fixture must admit every owned live selector N
// (L-T7-3 4097, L-T7-4 6530, L-T7-5 8192 boundary). Live L-T7-3/4 failed
// instantly with `unsupported owned fixture size`; this gate proves the
// fixture (compile + ELF + distinct physical offsets + Inventory plan)
// builds at each selector size without BPF. Anything larger stays refused.
#[test]
fn task4_owned_fixture_admits_t7_live_selector_sizes() -> Result<()> {
    for endpoints in [4_097u32, 6_530, 8_192] {
        let fixture = OwnedFixture::build_n(false, endpoints)?;
        verify_task4_physical_slots(&fixture.plan.slots, endpoints as usize)?;
    }
    let error = match OwnedFixture::build_n(false, 8_193) {
        Ok(_) => bail!("fixture admitted past 8192"),
        Err(error) => error,
    };
    ensure!(
        format!("{error:?}").contains("unsupported owned fixture size"),
        "wrong oversize fixture refusal: {error:?}"
    );
    Ok(())
}

#[test]
fn task4_detailed_physical_capacity_refusal() -> Result<()> {
    for endpoints in [p11scope_ebpf_common::MAX_SLOTS + 1, 2_113] {
        let fixture = OwnedFixture::build_n(false, endpoints)?;
        verify_task4_physical_slots(&fixture.plan.slots, endpoints as usize)?;
        let error = AttachPlan::from_slots_with_policy(
            fixture.plan.slots.clone(),
            AdmissionPolicy::Detailed,
        )
        .expect_err("Detailed plan admitted physical capacity overflow");
        ensure!(
            error.contains(&format!("requires {endpoints}"))
                && error.contains(&format!("only {}", p11scope_ebpf_common::MAX_SLOTS)),
            "wrong physical capacity refusal: {error}"
        );
    }
    Ok(())
}

#[cfg(not(feature = "wide-detailed-2112"))]
#[test]
#[ignore = "root-owned BPF lane; real aliased symbol and same-byte distinct-inode Detailed targets"]
fn privileged_task4_detailed_physical_identity_controls() -> Result<()> {
    let mut identity = Task4IdentityFixture::build(AdmissionPolicy::Detailed)?;
    task4_identity_fixture_receipt(&identity)?;
    let (mut original, mut copy) = identity.take_callers()?;
    let fixture = &identity.fixture;
    fixture.assert_caller_identity(&original)?;
    identity.assert_copy_caller(&copy)?;
    let mut evidence = Task4Evidence::new_control(
        "detailed-identity",
        "default",
        fixture,
        crate::EBPF_OBJECT,
        Some((
            "detailed-physical-identity",
            "complete-identity",
            "alias_equal_bytes_distinct_inode",
            "detailed.elf",
        )),
    )?;
    evidence.fd_sample("baseline")?;
    eprintln!("TASK4_PROFILE name=default detailed_slots=512 rv_keys=4096 inventory_budget=2112");
    let mut first = crate::attach::Session::start(
        &fixture.plan,
        &Scope::Pid(original.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::Allowlisted,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )?;
    ensure!(first.attach_failures().is_empty() && first.attached_probes() == 4);
    let first_ids = OwnedIds::detailed(&first)?;
    ensure!(
        (
            first_ids.maps.len(),
            first_ids.programs.len(),
            first_ids.links.len()
        ) == (23, 13, 7)
    );
    let first_witness = task4_session_witness(&first, &first_ids, 1, original.child.id())?;
    task4_record_registration(
        &first,
        &first_ids,
        &fixture.plan.slots,
        &fixture.pins,
        first_witness,
        &mut evidence,
        "first_attached",
    )?;
    task4_ids_phase("first_attached", &first_ids);
    task4_session_ids("first_attached", first_witness, &first_ids);
    evidence.fd_sample("post_first_attach")?;

    let mut second = crate::attach::Session::start(
        &fixture.plan,
        &Scope::Pid(copy.child.id()),
        &fixture.pins,
        crate::attach::CapturePolicy::Allowlisted,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )?;
    ensure!(second.attach_failures().is_empty() && second.attached_probes() == 4);
    let second_ids = OwnedIds::detailed(&second)?;
    ensure!(
        (
            second_ids.maps.len(),
            second_ids.programs.len(),
            second_ids.links.len()
        ) == (23, 13, 7)
    );
    let second_witness = task4_session_witness(&second, &second_ids, 2, copy.child.id())?;
    ensure!(
        first_witness.stats_map_id != second_witness.stats_map_id
            && first_ids.maps.is_disjoint(&second_ids.maps)
            && first_ids.programs.is_disjoint(&second_ids.programs)
            && first_ids.links.is_disjoint(&second_ids.links)
    );
    task4_record_registration(
        &second,
        &second_ids,
        &fixture.plan.slots,
        &fixture.pins,
        second_witness,
        &mut evidence,
        "second_attached",
    )?;
    let ids = first_ids.union(&second_ids);
    ensure!((ids.maps.len(), ids.programs.len(), ids.links.len()) == (46, 26, 14));
    task4_ids_phase("second_attached", &ids);
    task4_session_ids("second_attached", second_witness, &second_ids);
    task4_ids_receipt(&ids);
    evidence.fd_sample("post_second_attach")?;

    for session in [&first, &second] {
        let map_max = |name| -> Result<u32> {
            let map = session
                .ebpf
                .map(name)
                .with_context(|| format!("{name} map"))?;
            Ok(crate::attach::read_map_metadata(name, detailed_map_data(map)?)?.max_entries)
        };
        ensure!(
            map_max("STATS")? == 512
                && map_max("RV_COUNTS")? == 4_096
                && map_max("START")? == 16_384
                && map_max("EVENTS")? >= 4_096
        );
    }
    let events_capacity = crate::attach::read_map_metadata(
        "EVENTS",
        detailed_map_data(first.ebpf.map("EVENTS").context("EVENTS")?)?,
    )?
    .max_entries;
    eprintln!(
        "TASK4_LOADED_OBJECT kind=detailed.elf sha256={}",
        task4_hash(crate::EBPF_OBJECT)
    );
    eprintln!("TASK4_LOADED_MAPS STATS=512 RV_COUNTS=4096 START=16384 EVENTS={events_capacity}");
    let mut first_events = Vec::new();
    let mut second_events = Vec::new();
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.is_empty() && second_events.is_empty());
    let before_first = task4_identity_session_snapshot(&mut first, first_witness, "original", 0)?;
    let before_second = task4_identity_session_snapshot(&mut second, second_witness, "copy", 0)?;
    task4_identity_assert_snapshot(&before_first, None)?;
    task4_identity_assert_snapshot(&before_second, None)?;

    evidence.identity_caller(&mut original, "pre_go", 0, fixture.plan.slots[0].object.0)?;
    evidence.identity_caller(&mut copy, "pre_go", 1, fixture.plan.slots[1].object.0)?;
    identity.check_views(1, &[&original, &copy])?;
    original.go()?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    copy.go()?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;

    original.hold_exact_return_in_body(0, 0)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    let (first_image, first_ts) = task4_identity_held_start(&first, 0, original.child.id())?;
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.is_empty() && second_events.is_empty());
    let foreign_at_first_hold =
        task4_identity_session_snapshot(&mut second, second_witness, "copy", 0)?;
    task4_identity_assert_snapshot(&foreign_at_first_hold, None)?;
    evidence.raw_row(serde_json::json!({
        "kind":"image_witness","phase":"held_first_call","position":0,
        "slot":0,"pid_tgid":u64::from(original.child.id()) << 32 | u64::from(original.child.id()),
        "ts_ns":first_ts,
        "image":{"task_cookie":first_image.task_cookie,"exec_id":first_image.exec_id},
        "session_generation":first_witness.session_generation,
        "stats_map_id":first_witness.stats_map_id,"scope_pid":first_witness.scope_pid,
        "view_role":"original",
        "foreign_at_hold":task4_identity_foreign_at_hold(&foreign_at_first_hold)
    }))?;
    original.resume_exact_return(0, 0)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    original.call_alias_exact(5)?;
    evidence.identity_caller(&mut original, "after_go", 0, fixture.plan.slots[0].object.0)?;
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.len() == 2 && second_events.is_empty());
    let after_original_first =
        task4_identity_session_snapshot(&mut first, first_witness, "original", first_events.len())?;
    let after_original_second =
        task4_identity_session_snapshot(&mut second, second_witness, "copy", second_events.len())?;
    task4_identity_assert_snapshot(&after_original_first, Some(0))?;
    task4_identity_assert_snapshot(&after_original_second, None)?;
    evidence.raw_row(serde_json::json!({
        "kind":"cross_session_snapshot","phase":"after_original",
        "sessions":[after_original_first,after_original_second]
    }))?;

    copy.hold_exact_return_in_body(0, 0)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    let (second_image, second_ts) = task4_identity_held_start(&second, 1, copy.child.id())?;
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.len() == 2 && second_events.is_empty());
    let foreign_at_second_hold =
        task4_identity_session_snapshot(&mut first, first_witness, "original", first_events.len())?;
    ensure!(foreign_at_second_hold == after_original_first);
    evidence.raw_row(serde_json::json!({
        "kind":"image_witness","phase":"held_first_call","position":1,
        "slot":1,"pid_tgid":u64::from(copy.child.id()) << 32 | u64::from(copy.child.id()),
        "ts_ns":second_ts,
        "image":{"task_cookie":second_image.task_cookie,"exec_id":second_image.exec_id},
        "session_generation":second_witness.session_generation,
        "stats_map_id":second_witness.stats_map_id,"scope_pid":second_witness.scope_pid,
        "view_role":"copy",
        "foreign_at_hold":task4_identity_foreign_at_hold(&foreign_at_second_hold)
    }))?;
    copy.resume_exact_return(0, 0)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    copy.call_exact(0, 5)?;
    evidence.identity_caller(&mut copy, "after_go", 1, fixture.plan.slots[1].object.0)?;
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.len() == 2 && second_events.len() == 2);
    let after_copy_first =
        task4_identity_session_snapshot(&mut first, first_witness, "original", first_events.len())?;
    let after_copy_second =
        task4_identity_session_snapshot(&mut second, second_witness, "copy", second_events.len())?;
    ensure!(after_copy_first == after_original_first);
    task4_identity_assert_snapshot(&after_copy_second, Some(1))?;
    evidence.raw_row(serde_json::json!({
        "kind":"cross_session_snapshot","phase":"after_copy",
        "sessions":[after_copy_first,after_copy_second]
    }))?;
    eprintln!(
        "TASK4_LEDGER phase=after_go physical_ids=2 completed_calls=4 rv0=2 rv5=2 first=0 tail=1"
    );

    for (witness, role, snapshot) in [
        (first_witness, "original", &after_copy_first),
        (second_witness, "copy", &after_copy_second),
    ] {
        for stats in snapshot["stats"]
            .as_array()
            .context("identity slot stats")?
        {
            evidence.raw_row(serde_json::json!({
                "kind":"stats","phase":"after_go","slot":stats["slot"],
                "entered":stats["entered"],"returned":stats["returned"],
                "errors":stats["errors"],"in_flight":stats["in_flight"],
                "session_generation":witness.session_generation,
                "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
                "view_role":role
            }))?;
        }
    }
    for (witness, role, snapshot) in [
        (first_witness, "original", &after_copy_first),
        (second_witness, "copy", &after_copy_second),
    ] {
        for rv in snapshot["rv"].as_array().context("identity RV rows")? {
            evidence.raw_row(serde_json::json!({
                "kind":"rv","phase":"after_go","slot":rv["slot"],
                "rv":rv["rv"],"count":rv["count"],
                "session_generation":witness.session_generation,
                "stats_map_id":witness.stats_map_id,"scope_pid":witness.scope_pid,
                "view_role":role
            }))?;
        }
    }
    let mut tracer = crate::trace::Tracer::new(&fixture.plan);
    let mut state = crate::semantics::State::with_policy(
        &fixture.plan,
        crate::attach::CapturePolicy::Allowlisted,
    );
    for (slot, events, image, ts, pid, witness, role) in [
        (
            0,
            &first_events,
            first_image,
            first_ts,
            original.child.id(),
            first_witness,
            "original",
        ),
        (
            1,
            &second_events,
            second_image,
            second_ts,
            copy.child.id(),
            second_witness,
            "copy",
        ),
    ] {
        for (position, event) in events.iter().enumerate() {
            ensure!(event.slot == slot && event.rv == if position == 0 { 0 } else { 5 });
            verify_task4_event_identity(event, pid, Some(image))?;
            if position == 0 {
                ensure!(event.ts_ns.checked_sub(event.duration_ns) == Some(ts));
            }
            evidence.identity_event(event, fixture, witness, role)?;
            tracer.count_raw_call(event);
            let rendered = tracer.on_event(event, &mut state);
            let rv_label = pkcs11_types::CkRv(event.rv).to_string();
            let rv_label = rv_label.split(" (").next().unwrap_or(&rv_label);
            ensure!(
                rendered.contains("C_Finalize")
                    && rendered.contains("C_Initialize")
                    && rendered.contains(&format!("[semantics unverified] → {rv_label} "))
            );
            evidence.render(&rendered)?;
        }
    }
    ensure!(
        tracer.raw_calls() == 4
            && state.pending_at_end() == 0
            && state.semantic_evidence() == crate::semantics::SemanticEvidence::default()
    );
    eprintln!(
        "TASK4_TRACE phase=after_go calls=4 rendered=4 distinct_slot_rv=4 ordered_ledger=true ring_malformed=0 rendered_sha256={}",
        task4_hash(&evidence.rendered.contents()?)
    );
    identity.check_views(2, &[&original, &copy])?;
    task4_identity_seal_receipt(&identity)?;
    original.finish()?;
    evidence.identity_caller(&mut original, "terminal", 0, fixture.plan.slots[0].object.0)?;
    copy.finish()?;
    evidence.identity_caller(&mut copy, "terminal", 1, fixture.plan.slots[1].object.0)?;
    evidence.fd_sample("pre_detach")?;
    let detached_first = first.detach_producers();
    let detached_second = second.detach_producers();
    drain_task4_detailed(&mut first, &mut first_events)?;
    drain_task4_detailed(&mut second, &mut second_events)?;
    ensure!(first_events.len() == 2 && second_events.len() == 2);
    let terminal_first = task4_identity_terminal_session(&mut first, first_witness, "original", 2)?;
    let terminal_second = task4_identity_terminal_session(&mut second, second_witness, "copy", 2)?;
    ensure!(
        terminal_first["kernel"] == terminal_second["kernel"]
            && terminal_first["discovery"] == terminal_second["discovery"]
    );
    evidence.raw_row(serde_json::json!({
        "kind":"terminal","phase":"terminal","ring_loss":0,
        "raw_calls":4,"rendered":4,"pending":state.pending_at_end(),
        "orphan_ops":state.orphan_ops(),"unmatched_closes":state.unmatched_closes(),
        "kernel":terminal_first["kernel"],"discovery":terminal_first["discovery"],
        "sessions":[terminal_first,terminal_second]
    }))?;
    eprintln!(
        "TASK4_RAW_SUMMARY phase=terminal stats_entered=4 stats_returned=4 rv_keys=4 raw_calls=4 rendered=4 ordered_ledger=true"
    );
    drop(first);
    drop(second);
    ids.released_with_budget(Duration::from_secs(60))?;
    detached_first?;
    detached_second?;
    eprintln!("TASK4_LOSS ring=0 discovery=0 owner=0 output_rendered=4");
    evidence.finish()?;
    eprintln!("TASK4_CLEANUP owned_ids_released=true terminal_unsettled=true");
    Ok(())
}

/// Waits until `/proc/<pid>/task/<tid>` is gone. `pthread_join` returns at the
/// kernel's clear-child-TID futex wake, which precedes `release_task()` unhashing
/// the TID from /proc, so a single sample right after a join can still see it.
fn await_task_released(pid: u32, tid: u32, limit: Duration) -> Result<()> {
    let task = PathBuf::from(format!("/proc/{pid}/task/{tid}"));
    let deadline = Instant::now() + limit;
    while task.try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "abandoned worker TID still exists"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn awaited_task_release_follows_join_and_refuses_a_live_thread() -> Result<()> {
    // Regression for the post-join /proc window: a single immediate absence
    // check fails a few percent of joins, so 200 joins catch a revert.
    let pid = std::process::id();
    for _ in 0..200 {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            // SAFETY: gettid has no arguments and cannot fail.
            let _ = sender.send(unsafe { libc::syscall(libc::SYS_gettid) } as u32);
        });
        let tid = receiver.recv()?;
        worker.join().expect("worker thread");
        await_task_released(pid, tid, Duration::from_secs(5))?;
        ensure!(!PathBuf::from(format!("/proc/{pid}/task/{tid}")).try_exists()?);
    }
    // A live thread is never reported as released, only as timing out.
    let (sender, receiver) = std::sync::mpsc::channel();
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: gettid has no arguments and cannot fail.
        let _ = sender.send(unsafe { libc::syscall(libc::SYS_gettid) } as u32);
        let _ = hold.recv();
    });
    let tid = receiver.recv()?;
    let refused = await_task_released(pid, tid, Duration::from_millis(50));
    release.send(())?;
    worker.join().expect("held worker thread");
    let error = refused.expect_err("a live thread must not be reported as released");
    ensure!(error.to_string().contains("still exists"), "{error:#}");
    Ok(())
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

#[derive(Clone, Copy)]
struct Task4LinkInfo {
    raw: bpf_link_info,
    returned_len: u32,
}

#[derive(Clone, Copy, Debug)]
enum Task4PerfDetail {
    BaseOnly515,
    Partial {
        type_: u32,
        offset: u32,
    },
    Full {
        type_: u32,
        offset: u32,
        cookie: u64,
    },
}

fn task4_classify_perf_info(
    raw: &bpf_link_info,
    returned_len: u32,
    expected_offset: u64,
    expected_cookie: u64,
) -> Result<Task4PerfDetail> {
    ensure!(raw.type_ == bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32);
    ensure!(
        expected_offset <= u64::from(u32::MAX),
        "Inventory uprobe offset exceeds metadata width"
    );
    // SAFETY: type_ identifies the perf-event union member.
    let perf = unsafe { raw.__bindgen_anon_1.perf_event };
    let point = unsafe { perf.__bindgen_anon_1.uprobe };
    match returned_len {
        // Compiled directly against the upstream Linux v5.15 UAPI:
        // sizeof(bpf_link_info)=32, common fields at 0/4/8, union at 16.
        32 => {
            let other = unsafe { perf.__bindgen_anon_1.kprobe };
            ensure!(
                perf.type_ == 0
                    && perf._bitfield_1.get(0, 32) == 0
                    && other.func_name == 0
                    && other.name_len == 0
                    && other.offset == 0
                    && other.addr == 0
                    && other.missed == 0
                    && other.cookie == 0,
                "legacy Inventory perf detail is not entirely zero"
            );
            Ok(Task4PerfDetail::BaseOnly515)
        }
        48 | 64 => {
            ensure!(
                perf.type_ == bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u32,
                "ordinary return link installed"
            );
            ensure!(
                u64::from(point.offset) == expected_offset,
                "Inventory kernel uprobe offset differs from requested offset"
            );
            if returned_len == 48 {
                ensure!(
                    point.cookie == 0,
                    "partial Inventory perf detail carries unexpected cookie"
                );
                Ok(Task4PerfDetail::Partial {
                    type_: perf.type_,
                    offset: point.offset,
                })
            } else {
                ensure!(
                    point.cookie == expected_cookie,
                    "Inventory kernel uprobe cookie differs from requested cookie"
                );
                Ok(Task4PerfDetail::Full {
                    type_: perf.type_,
                    offset: point.offset,
                    cookie: point.cookie,
                })
            }
        }
        other => bail!("ambiguous Inventory perf link info length {other}"),
    }
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

fn raw_link_info_by_borrowed_fd(fd: u32) -> Result<Task4LinkInfo> {
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
    ensure!(
        (12..=std::mem::size_of::<bpf_link_info>() as u32).contains(&attr.len),
        "retained link info lacks common identity or exceeds requested buffer"
    );
    Ok(Task4LinkInfo {
        raw: info,
        returned_len: attr.len,
    })
}

fn owned_link_info_snapshot_with(
    programs: &BTreeSet<u32>,
    mut scan: impl FnMut() -> Result<Vec<OwnedLinkDescriptor>>,
    mut query: impl FnMut(u32) -> Result<Task4LinkInfo>,
) -> Result<BTreeMap<u32, Task4LinkInfo>> {
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
                info.raw.prog_id == descriptor.program && info.raw.id == descriptor.id,
                "retained descriptor changed ID/program pairing"
            );
            ensure!(
                infos.insert(info.raw.id, info).is_none(),
                "duplicate owned link descriptor"
            );
        }
    }
    Ok(infos)
}

fn owned_link_info_snapshot(programs: &BTreeSet<u32>) -> Result<BTreeMap<u32, Task4LinkInfo>> {
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
            Ok(Task4LinkInfo {
                raw: info,
                returned_len: 32,
            })
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
fn task4_link_metadata_accepts_only_explicit_legacy_or_exact_detail() -> Result<()> {
    assert_eq!(std::mem::size_of::<bpf_link_info>(), 64);
    // SAFETY: a zeroed UAPI POD is the kernel's v5.15 base-only representation.
    let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
    info.type_ = bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32;
    info.id = 12;
    info.prog_id = 34;
    let cookie = 0x5055_5347_0000_0000_u64;
    ensure!(matches!(
        task4_classify_perf_info(&info, 32, 64, cookie)?,
        Task4PerfDetail::BaseOnly515
    ));
    let mut malformed = info;
    // SAFETY: the synthetic perf union member is writable as test input.
    let mut perf = unsafe { malformed.__bindgen_anon_1.perf_event };
    perf.type_ = bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u32;
    malformed.__bindgen_anon_1.perf_event = perf;
    assert!(task4_classify_perf_info(&malformed, 32, 64, cookie).is_err());

    let mut full = info;
    let mut perf = unsafe { full.__bindgen_anon_1.perf_event };
    perf.type_ = bpf_perf_event_type::BPF_PERF_EVENT_UPROBE as u32;
    let mut point = unsafe { perf.__bindgen_anon_1.uprobe };
    point.offset = 64;
    point.cookie = cookie;
    perf.__bindgen_anon_1.uprobe = point;
    full.__bindgen_anon_1.perf_event = perf;
    let full_len = u32::try_from(std::mem::size_of::<bpf_link_info>())?;
    ensure!(matches!(
        task4_classify_perf_info(&full, full_len, 64, cookie)?,
        Task4PerfDetail::Full { .. }
    ));
    let mut wrong = full;
    let mut perf = unsafe { wrong.__bindgen_anon_1.perf_event };
    let mut point = unsafe { perf.__bindgen_anon_1.uprobe };
    point.offset = 80;
    perf.__bindgen_anon_1.uprobe = point;
    wrong.__bindgen_anon_1.perf_event = perf;
    assert!(task4_classify_perf_info(&wrong, full_len, 64, cookie).is_err());
    let mut wrong = full;
    let mut perf = unsafe { wrong.__bindgen_anon_1.perf_event };
    let mut point = unsafe { perf.__bindgen_anon_1.uprobe };
    point.cookie ^= 1;
    perf.__bindgen_anon_1.uprobe = point;
    wrong.__bindgen_anon_1.perf_event = perf;
    assert!(task4_classify_perf_info(&wrong, full_len, 64, cookie).is_err());
    let mut wrong = full;
    let mut perf = unsafe { wrong.__bindgen_anon_1.perf_event };
    perf.type_ = bpf_perf_event_type::BPF_PERF_EVENT_URETPROBE as u32;
    wrong.__bindgen_anon_1.perf_event = perf;
    assert!(task4_classify_perf_info(&wrong, full_len, 64, cookie).is_err());
    wrong = info;
    wrong.type_ = bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32;
    assert!(task4_classify_perf_info(&wrong, 32, 64, cookie).is_err());
    Ok(())
}

#[test]
fn task4_link_receipt_replay_rejects_swapped_request_and_mixed_capability() -> Result<()> {
    let offsets = serde_json::to_vec(&serde_json::json!([
        {"dev":1,"ino":2,"offset":64}, {"dev":1,"ino":2,"offset":80}
    ]))?;
    let mut rows = Vec::new();
    for (position, name) in ["sched_process_exec", "sched_process_exit"]
        .into_iter()
        .enumerate()
    {
        rows.push(serde_json::json!({
            "position":position,"role":"lifecycle",
            "kernel_common":{"link_id":100+position,"program_id":10+position,
                "type":bpf_link_type::BPF_LINK_TYPE_RAW_TRACEPOINT as u32,"info_len":32},
            "userspace_requested":{"source":"retained_inventory_attach_request",
                "program":name,"tracepoint":name}
        }));
    }
    for slot in 0..2 {
        rows.push(serde_json::json!({
            "position":slot+2,"role":"entry","slot":slot,
            "kernel_common":{"link_id":slot+102,"program_id":12,
                "type":bpf_link_type::BPF_LINK_TYPE_PERF_EVENT as u32,"info_len":32},
            "kernel_perf_detail":{"capability":"base_only_5_15"},
            "userspace_requested":{"source":"retained_inventory_attach_request",
                "program":"p11_usage_entry_lp64","object_id":0,"dev":1,"ino":2,
                "offset":64+slot*16,"cookie":0x5055_5347_0000_0000_u64 | slot as u64,
                "abi":"Lp64","pin_unchanged":true}
        }));
    }
    let encode = |rows: &[serde_json::Value]| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, row)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    };
    task4_replay_links(&encode(&rows)?, &offsets)?;
    let mut wrong = rows.clone();
    wrong[2]["userspace_requested"]["offset"] = serde_json::json!(80);
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
    wrong = rows.clone();
    wrong[3]["kernel_common"]["link_id"] = serde_json::json!(102);
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
    wrong = rows.clone();
    wrong[2]["kernel_perf_detail"]["type"] = serde_json::json!(1);
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
    let mut full = rows.clone();
    for (slot, row) in full[2..].iter_mut().enumerate() {
        row["kernel_common"]["info_len"] = serde_json::json!(64);
        row["kernel_perf_detail"] = serde_json::json!({
            "capability":"full_type_offset_cookie","type":1,
            "offset":64+slot*16,"cookie":0x5055_5347_0000_0000_u64 | slot as u64
        });
    }
    task4_replay_links(&encode(&full)?, &offsets)?;
    wrong = full.clone();
    wrong[2]["kernel_perf_detail"]["cookie"] = serde_json::json!(0);
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
    wrong = full.clone();
    wrong[3] = rows[3].clone();
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
    let mut partial = rows;
    for (slot, row) in partial[2..].iter_mut().enumerate() {
        row["kernel_common"]["info_len"] = serde_json::json!(48);
        row["kernel_perf_detail"] = serde_json::json!({
            "capability":"partial_type_offset","type":1,"offset":64+slot*16
        });
    }
    task4_replay_links(&encode(&partial)?, &offsets)?;
    wrong = partial;
    wrong[2]["kernel_perf_detail"]["type"] = serde_json::json!(2);
    assert!(task4_replay_links(&encode(&wrong)?, &offsets).is_err());
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
                Ok(Task4LinkInfo {
                    raw: info,
                    returned_len: 32,
                })
            },
        );
        ensure!(scans == 1);
        ensure!(queries == if mutation == "duplicate" { 2 } else { 1 });
        if mutation == "none" {
            let infos = result?;
            ensure!(infos.len() == 1 && infos[&575].raw.id == 575 && infos[&575].raw.prog_id == 42);
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
    caller.hold_exact_return_in_body(0, 0)?;
    caller.resume_exact_return(0, 0)?;
    for id in [0_u32, 511, 512, 999, 2_047, 2_048, 2_111] {
        for rv in [0_u64, 5] {
            if id == 0 && rv == 0 {
                continue;
            }
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

// Task 6 (stop gate) Step 1: privileged live selectors. The controller owns
// Steps 2-3 (privileged runs + overhead); these only compile here.

/// Byte-level capture-state snapshot for the stop-gate freeze assertions:
/// per-CPU STATS rows, per-CPU RV_COUNTS rows, full START rows, and both
/// ring producer positions.
/// One per-CPU STATS row: entered, returned, errors, total_ns, max_ns,
/// and the latency buckets.
type StopGateStatsRow = (u64, u64, u64, u64, u64, Vec<u64>);

#[derive(Debug, PartialEq, Eq)]
struct StopGateCaptureState {
    stats: Vec<Vec<StopGateStatsRow>>,
    rvs: BTreeMap<(u32, u64), Vec<u64>>,
    starts: BTreeMap<(u64, u32), StopGateStartRow>,
    events_producer: usize,
    discovery_producer: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct StopGateStartRow {
    ts_ns: u64,
    session: u64,
    slot_id: u64,
    mechanism: u64,
    mechanism_ptr: u64,
    flags: u64,
    out_ptr: u64,
    user_type: u32,
    shape: u32,
    p0: u64,
    p1: u64,
    p2: u64,
    async_value: u64,
    attr_types: Vec<u64>,
    attr_count: u32,
    attr_total: u32,
    attr_bools: u32,
    attr_bools_seen: u32,
    attr_types1: Vec<u64>,
    attr_count1: u32,
    attr_total1: u32,
    attr_bools1: u32,
    attr_bools_seen1: u32,
    capture: u32,
    target_function: u32,
    task_cookie: u64,
    exec_id: u64,
}

fn snapshot_stop_gate_state(
    session: &mut crate::attach::Session,
    endpoints: u32,
) -> Result<StopGateCaptureState> {
    let stats_map: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS")?)?;
    let mut stats = Vec::with_capacity(endpoints as usize);
    for slot in 0..endpoints {
        let mut cpus = Vec::new();
        for cpu in stats_map.get(&slot, 0)?.iter() {
            cpus.push((
                cpu.entered,
                cpu.returned,
                cpu.errors,
                cpu.total_ns,
                cpu.max_ns,
                cpu.buckets.to_vec(),
            ));
        }
        stats.push(cpus);
    }
    let rv_map: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS")?)?;
    let mut rvs = BTreeMap::new();
    for entry in rv_map.iter() {
        let (key, counts) = entry?;
        ensure!(
            key.slot < endpoints && key._pad == 0,
            "foreign Detailed RV key in stop-gate snapshot"
        );
        ensure!(
            rvs.insert((key.slot, key.rv), counts.iter().copied().collect())
                .is_none(),
            "duplicate Detailed RV key in stop-gate snapshot"
        );
    }
    let start_map: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(session.ebpf.map("START").context("START")?)?;
    let mut starts = BTreeMap::new();
    for entry in start_map.iter() {
        let (key, start) = entry?;
        ensure!(
            key.slot < endpoints && key._pad == 0,
            "foreign Detailed START key in stop-gate snapshot"
        );
        let row = StopGateStartRow {
            ts_ns: start.ts_ns,
            session: start.session,
            slot_id: start.slot_id,
            mechanism: start.mechanism,
            mechanism_ptr: start.mechanism_ptr,
            flags: start.flags,
            out_ptr: start.out_ptr,
            user_type: start.user_type,
            shape: start.shape,
            p0: start.p0,
            p1: start.p1,
            p2: start.p2,
            async_value: start.async_value,
            attr_types: start.attr_types.to_vec(),
            attr_count: start.attr_count,
            attr_total: start.attr_total,
            attr_bools: start.attr_bools,
            attr_bools_seen: start.attr_bools_seen,
            attr_types1: start.attr_types1.to_vec(),
            attr_count1: start.attr_count1,
            attr_total1: start.attr_total1,
            attr_bools1: start.attr_bools1,
            attr_bools_seen1: start.attr_bools_seen1,
            capture: start.capture,
            target_function: start.target_function,
            task_cookie: start.image.task_cookie,
            exec_id: start.image.exec_id,
        };
        ensure!(
            starts.insert((key.pid_tgid, key.slot), row).is_none(),
            "duplicate Detailed START key in stop-gate snapshot"
        );
    }
    let events_producer = session.event_drain_positions()?.producer;
    let discovery_producer = session.discovery_positions()?.producer;
    Ok(StopGateCaptureState {
        stats,
        rvs,
        starts,
        events_producer,
        discovery_producer,
    })
}

/// Request the stop, then poll for Q under the owner budget while servicing
/// both drains, exactly like the production terminal path.
fn stop_gate_request_and_quiesce(
    session: &mut crate::attach::Session,
    events: &mut Vec<Event>,
) -> Result<crate::run::StopState> {
    session.stop_gate().request_stop();
    let mut discovery_malformed = 0u64;
    let state = session.quiesce_terminal(
        crate::run::STOP_QUIESCE_BUDGET,
        Some(|drain: &mut crate::events::OwnedDrain| {
            drain.poll(Some(256), |event| {
                events.push(event);
                ControlFlow::Continue(())
            });
        }),
        |discovery: &mut crate::events::OwnedDiscoveryDrain| {
            while let Some(item) = discovery.dequeue() {
                if matches!(item, crate::events::DiscoveryItem::Malformed) {
                    discovery_malformed += 1;
                }
            }
        },
        Instant::now,
    )?;
    ensure!(
        discovery_malformed == 0,
        "stop-gate quiesce serviced malformed discovery"
    );
    Ok(state)
}

fn stop_gate_start_session(
    plan: &AttachPlan,
    caller: &OwnedCaller,
    pins: &PinnedObjects,
) -> Result<crate::attach::Session> {
    crate::attach::Session::start(
        plan,
        &Scope::Pid(caller.child.id()),
        pins,
        crate::attach::CapturePolicy::Allowlisted,
        None,
        None,
        None,
        crate::attach::BackendSelection::Singles,
    )
}

#[test]
#[ignore = "root-owned BPF lane; Detailed stop gate freezes capture state after quiescence"]
fn privileged_stop_gate_freezes_capture_state_after_quiescence() -> Result<()> {
    const ENDPOINTS: u32 = 8;
    let fixture = OwnedFixture::build_n(false, ENDPOINTS)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    let mut session = stop_gate_start_session(&plan, &caller, &fixture.pins)?;
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * ENDPOINTS as usize,
        "stop-gate fixture did not retain every paired static probe"
    );
    let ids = OwnedIds::detailed(&session)?;
    let mut events = Vec::new();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    for id in 0..ENDPOINTS {
        caller.call_exact(id, 0)?;
        caller.call_exact(id, 5)?;
    }
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 2 * ENDPOINTS as usize,
        "stop-gate fixture completed-call count differs"
    );
    let stop_state = stop_gate_request_and_quiesce(&mut session, &mut events)?;
    ensure!(
        matches!(stop_state, crate::run::StopState::Quiesced { .. }),
        "stop gate did not reach Q: {stop_state:?}"
    );
    let frozen = snapshot_stop_gate_state(&mut session, ENDPOINTS)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        caller.calls(0, 1_000)?;
        let current = snapshot_stop_gate_state(&mut session, ENDPOINTS)?;
        ensure!(
            current == frozen,
            "capture state moved after Q while calls continued"
        );
        ensure!(
            session.stop_gate().in_flight() == 0,
            "stop gate shows bodies in flight after Q"
        );
        if Instant::now() >= deadline {
            break;
        }
    }
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 2 * ENDPOINTS as usize,
        "post-Q calls emitted Detailed events"
    );
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "stop-gate detach retained failures");
    Ok(())
}

#[cfg(feature = "wide-detailed-2112")]
#[test]
#[ignore = "root-owned BPF lane; 2112-slot Detailed stop publishes before cleanup"]
fn privileged_detailed_2112_stop_publishes_before_cleanup() -> Result<()> {
    const ENDPOINTS: u32 = 2_112;
    let origin = Instant::now();
    let fixture = OwnedFixture::build_n(false, ENDPOINTS)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    let mut session = stop_gate_start_session(&plan, &caller, &fixture.pins)?;
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * ENDPOINTS as usize,
        "stop-gate fixture did not retain every paired static probe"
    );
    let ids = OwnedIds::detailed(&session)?;
    let mut events = Vec::with_capacity(2 * ENDPOINTS as usize);
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    for id in 0..ENDPOINTS {
        caller.call_exact(id, 0)?;
        caller.call_exact(id, 5)?;
        if id % 32 == 31 {
            drain_task4_detailed(&mut session, &mut events)?;
        }
    }
    drain_task4_detailed(&mut session, &mut events)?;
    let ack_start = Instant::now();
    session.stop_gate().request_stop();
    eprintln!("p11scope: stopping (stop-gate timing selector requested the stop)");
    let ack_ms = ack_start.elapsed().as_millis();
    let q_start = Instant::now();
    let mut discovery_malformed = 0u64;
    let stop_state = session.quiesce_terminal(
        crate::run::STOP_QUIESCE_BUDGET,
        Some(|drain: &mut crate::events::OwnedDrain| {
            drain.poll(Some(256), |event| {
                events.push(event);
                ControlFlow::Continue(())
            });
        }),
        |discovery: &mut crate::events::OwnedDiscoveryDrain| {
            while let Some(item) = discovery.dequeue() {
                if matches!(item, crate::events::DiscoveryItem::Malformed) {
                    discovery_malformed += 1;
                }
            }
        },
        Instant::now,
    )?;
    let q_ms = q_start.elapsed().as_millis();
    ensure!(
        matches!(stop_state, crate::run::StopState::Quiesced { .. }),
        "stop gate did not reach Q: {stop_state:?}"
    );
    ensure!(
        discovery_malformed == 0,
        "stop-gate quiesce serviced malformed discovery"
    );
    let publish_start = Instant::now();
    let events_q = session.event_drain_positions()?.producer;
    let discovery_q = session.discovery_positions()?.producer;
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.len() == 2 * ENDPOINTS as usize,
        "terminal drain missed pre-Q Detailed events"
    );
    assert_task4_detailed_maps(&session, true, ENDPOINTS)?;
    ensure!(
        session.event_drain_positions()?.producer == events_q
            && session.discovery_positions()?.producer == discovery_q,
        "rings moved between Q and the terminal drain"
    );
    let publish_ms = publish_start.elapsed().as_millis();
    let cleanup_start = Instant::now();
    let detached = session.detach_producers();
    let cleanup_ms = cleanup_start.elapsed().as_millis();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "stop-gate detach retained failures");
    ensure!(
        ack_ms <= 500,
        "stop acknowledgement exceeded the 500 ms owner budget: {ack_ms} ms"
    );
    ensure!(
        q_ms <= 5_000,
        "quiescence wait exceeded the 5 s owner budget: {q_ms} ms"
    );
    ensure!(
        ack_ms + q_ms + publish_ms <= 10_000,
        "stop report exceeded the 10 s owner budget"
    );
    ensure!(
        publish_ms * 4 < cleanup_ms,
        "publish {publish_ms} ms is not well below cleanup {cleanup_ms} ms"
    );
    eprintln!(
        "STOPGATE_TIMING links={} ack_ms={ack_ms} q_ms={q_ms} publish_ms={publish_ms} cleanup_ms={cleanup_ms} elapsed_ms={}",
        ids.links.len(),
        origin.elapsed().as_millis()
    );
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; Detailed stop keeps in-flight calls as residual evidence"]
fn privileged_stop_gate_keeps_calls_in_flight_as_residual() -> Result<()> {
    const ENDPOINTS: u32 = 8;
    let fixture = OwnedFixture::build_n(false, ENDPOINTS)?;
    let plan =
        AttachPlan::from_slots_with_policy(fixture.plan.slots.clone(), AdmissionPolicy::Detailed)
            .map_err(anyhow::Error::msg)?;
    let mut caller = fixture.spawn_gated()?;
    let mut session = stop_gate_start_session(&plan, &caller, &fixture.pins)?;
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 2 * ENDPOINTS as usize,
        "stop-gate fixture did not retain every paired static probe"
    );
    let ids = OwnedIds::detailed(&session)?;
    let mut events = Vec::new();
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(events.is_empty(), "Detailed events preceded GO");
    caller.go()?;
    caller.hold_call_in_body(0, 23)?;
    let stop_state = stop_gate_request_and_quiesce(&mut session, &mut events)?;
    ensure!(
        matches!(stop_state, crate::run::StopState::Quiesced { .. }),
        "stop gate did not reach Q with a call held in the provider body: {stop_state:?}"
    );
    ensure!(
        events.is_empty(),
        "held Detailed entry emitted a completed CALL"
    );
    let at_q = snapshot_stop_gate_state(&mut session, ENDPOINTS)?;
    ensure!(
        at_q.starts.len() == 1,
        "held Detailed call left no sole START residual"
    );
    let leader = u64::from(caller.child.id()) << 32 | u64::from(caller.child.id());
    let ((pid_tgid, slot), row) = at_q.starts.iter().next().context("sole START row")?;
    ensure!(
        (*pid_tgid, *slot) == (leader, 0) && row.ts_ns != 0,
        "START residual is not the held owned call"
    );
    for (slot, cpus) in at_q.stats.iter().enumerate() {
        let mut entered = 0u64;
        let mut returned = 0u64;
        for cpu in cpus {
            entered += cpu.0;
            returned += cpu.1;
        }
        ensure!(
            (entered, returned) == if slot == 0 { (1, 0) } else { (0, 0) },
            "slot {slot} counted a completion for the held call"
        );
    }
    ensure!(
        at_q.rvs.is_empty(),
        "held Detailed call fabricated an RV row"
    );
    caller.assert_body_held()?;
    caller.resume_body(0)?;
    caller.finish_calls(0, 23)?;
    let after_release = snapshot_stop_gate_state(&mut session, ENDPOINTS)?;
    ensure!(
        after_release == at_q,
        "releasing the held call changed post-Q capture state"
    );
    drain_task4_detailed(&mut session, &mut events)?;
    ensure!(
        events.is_empty(),
        "post-Q completions emitted Detailed events"
    );
    let detached = session.detach_producers();
    let clean_detach = session.detach_failures().is_empty();
    drop(session);
    ids.released_with_budget(Duration::from_secs(60))?;
    caller.finish()?;
    detached?;
    ensure!(clean_detach, "stop-gate detach retained failures");
    Ok(())
}
