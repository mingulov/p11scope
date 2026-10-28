//! SPDX-License-Identifier: GPL-3.0-or-later
//! Kernel-side image-bank proof prototype (Choice B feasibility).
//!
//! This module exists only in `#[cfg(test)]` proof builds
//! (`P11SCOPE_IMAGE_BANK_PROOF=1`). It loads the proof object the build
//! emits under `OUT_DIR/image-bank-proof-v1/`, drives the dispatcher and
//! bank programs through real uprobe/uretprobe/tracepoint/fentry/iter
//! attachment to a compiled fixture binary, and asserts the fixed N-row
//! numbers (N1-N4, N6-N16) exactly as the feasibility table states. The
//! proof flavor never ships; production rollover decides separately on
//! the verdict.
//!
//! Mechanism under test: one permanently attached dispatcher reads
//! `BANK_SELECT` (bank slot, incarnation), takes a short ref in `BANK_GATE`
//! and tail-calls exactly one immutable bank program from the owner-shaped
//! `BANK_PROGS` array; entry records the chosen bank in a per-call route
//! word inside the existing START row (R0, no new map); the return path
//! follows the route, never the current bank. Identity is `(incarnation,
//! ticket)`; a slot is reused only as a new incarnation with fresh map
//! objects after closed-zero and reclaim.

use sha2::Digest as _;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

/// Build-output directory name for the proof object, mirroring the
/// counter-bank `counts-bank-growth-v2` selection contract.
pub(crate) const PROOF_OUTPUTS: &str = "image-bank-proof-v1";
/// Proof object file name inside [`PROOF_OUTPUTS`].
pub(crate) const PROOF_OBJECT_NAME: &str = "p11scope-ebpf-image-bank-proof-v1";
/// Cut headroom `H`: the Session prepares the next bank once the live
/// bank's `next_ticket` reaches `LIMIT - H`.
pub(crate) const CUT_HEADROOM: u64 = 1024;
/// Real per-bank ticket limit. Never raised, never reset.
pub(crate) const TICKET_LIMIT: u64 = 16384;
/// Cut trigger: `LIMIT - H`.
pub(crate) const CUT_TRIGGER: u64 = TICKET_LIMIT - CUT_HEADROOM;
/// Attach cookie for every Singles link (one value so
/// dispatcher-observed and directly-observed cookies must be identical).
pub(crate) const COOKIE_SINGLES: u64 = 0x5151_5151_5151_5151;
/// Attach cookie for every Multi link.
pub(crate) const COOKIE_MULTI: u64 = 0x6d6d_6d6d_6d6d_6d6d;

/// Proof roots, in load order: Rust dispatcher/slot/return/reference
/// roots, then the native birth-dispatcher, birth, exec and query roots.
pub(crate) const PROOF_ROOTS: [&str; 11] = [
    "p11_bank_disp_enter",
    "p11_bank_disp_enter_multi",
    "p11_bank_entry_a",
    "p11_bank_entry_b",
    "p11_bank_return",
    "p11_bank_ref_entry",
    "p11_bank_disp_birth",
    "p11_bank_birth_a",
    "p11_bank_birth_b",
    "p11_bank_exec_cover",
    "p11_bank_query_cover",
];

/// Query request/row slot word layout: low 10 bits stay the production
/// row index, bit 10 carries the bank, bits 11+ the incarnation.
pub(crate) const ROW_INDEX_MASK: u64 = 0x3ff;
/// Bit carrying the bank slot in a request/row slot word.
pub(crate) const ROW_BANK_BIT: u32 = 10;
/// Shift of the incarnation in a request/row slot word.
pub(crate) const ROW_INCARNATION_SHIFT: u32 = 11;
/// R0 route word offset inside the 288-byte START value (`async_value`).
pub(crate) const ROUTE_OFF: usize = 88;
/// Marker offset inside the START value (`object_required`, zero here).
pub(crate) const MARKER_OFF: usize = 264;
/// Cookie offset inside the START value (`image.task_cookie`).
pub(crate) const COOKIE_OFF: usize = 272;
/// Exec-id offset inside the START value (`image.exec_id`).
pub(crate) const EXEC_OFF: usize = 280;
/// START value size.
pub(crate) const START_SIZE: usize = 288;
/// Route word bit 63: route valid.
pub(crate) const ROUTE_VALID: u64 = 1 << 63;
/// Route word bit 62: bank slot.
pub(crate) const ROUTE_BANK: u64 = 1 << 62;
/// Route word low 32 bits: incarnation.
pub(crate) const ROUTE_INC_MASK: u64 = 0xffff_ffff;
/// Query row status READY.
pub(crate) const ROW_STATUS_READY: u32 = 1;
/// Query row status UNKNOWN.
pub(crate) const ROW_STATUS_UNKNOWN: u32 = 2;
/// Fixture probed symbol.
pub(crate) const TARGET_SYMBOL: &str = "p11_bank_target";
/// Fixture source, compiled at test time like the instance fixtures.
const FIXTURE_SOURCE: &str = include_str!("../../tests/fixtures/image-bank-proof.c");

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(bytes[off..off + 8].try_into().expect("u64 field"))
}

fn put_u64(bytes: &mut [u8], off: usize, value: u64) {
    bytes[off..off + 8].copy_from_slice(&value.to_ne_bytes());
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + 4].try_into().expect("u32 field"))
}

/// Decoded `BANK_SELECT` value: the flip word (bank, incarnation)
/// plus the fixed per-slot incarnation each bank entry stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BankSelect {
    pub bank: u64,
    pub incarnation: u64,
    pub fixed: [u64; 2],
}

/// `IMAGE_BANK_ACCOUNT` value size: 8 attribution words plus 5
/// per-cause admission-failure words (C `struct bank_account`).
const BANK_ACCOUNT_SIZE: usize = 104;

/// Decoded `IMAGE_BANK_ACCOUNT` row: the named proof-only per-bank
/// attribution counter (T-F2 names it, T-I0 disposes it). Every
/// enter-core refusal lands in exactly one failure bucket, so
/// `admitted + cookie_failures + seed_failures + start_present +
/// start_insert_failures` equals the ledger calls; `start_insert_errno`
/// carries the last START insert failure as a negative errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BankAccount {
    pub admitted: u64,
    pub completed: u64,
    pub live: u64,
    pub faults: u64,
    pub obs_cookie: u64,
    pub obs_ip: u64,
    pub stash_cookie: u64,
    pub stash_ip: u64,
    pub cookie_failures: u64,
    pub seed_failures: u64,
    pub start_present: u64,
    pub start_insert_failures: u64,
    pub start_insert_errno: u64,
}

/// Decoded ticket-control prefix (shared by `COOKIE_CTL`/`COOKIE_CTL_B`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BankControl {
    pub limit: u64,
    pub next_ticket: u64,
    pub unavailable: u64,
    pub create_failures: u64,
    pub retry_exhausted: u64,
}

/// Decoded query row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryRow {
    pub generation: u64,
    pub cookie: u64,
    pub exec_id: u64,
    pub sequence: u64,
    pub slot: u32,
    pub status: u32,
}

fn decode_select(bytes: &[u8; BANK_SELECT_SIZE]) -> BankSelect {
    BankSelect {
        bank: u64_at(bytes, 0),
        incarnation: u64_at(bytes, 8),
        fixed: [u64_at(bytes, 16), u64_at(bytes, 24)],
    }
}

fn decode_account(bytes: &[u8; BANK_ACCOUNT_SIZE]) -> BankAccount {
    BankAccount {
        admitted: u64_at(bytes, 0),
        completed: u64_at(bytes, 8),
        live: u64_at(bytes, 16),
        faults: u64_at(bytes, 24),
        obs_cookie: u64_at(bytes, 32),
        obs_ip: u64_at(bytes, 40),
        stash_cookie: u64_at(bytes, 48),
        stash_ip: u64_at(bytes, 56),
        cookie_failures: u64_at(bytes, 64),
        seed_failures: u64_at(bytes, 72),
        start_present: u64_at(bytes, 80),
        start_insert_failures: u64_at(bytes, 88),
        start_insert_errno: u64_at(bytes, 96),
    }
}

fn decode_control(bytes: &[u8; 40]) -> BankControl {
    BankControl {
        limit: u64_at(bytes, 0),
        next_ticket: u64_at(bytes, 8),
        unavailable: u64_at(bytes, 16),
        create_failures: u64_at(bytes, 24),
        retry_exhausted: u64_at(bytes, 32),
    }
}

fn decode_row(bytes: &[u8; 40]) -> QueryRow {
    QueryRow {
        generation: u64_at(bytes, 0),
        cookie: u64_at(bytes, 8),
        exec_id: u64_at(bytes, 16),
        sequence: u64_at(bytes, 24),
        slot: u32_at(bytes, 32),
        status: u32_at(bytes, 36),
    }
}

/// Slot lifecycle, driver side (mirrors the E1 model states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotState {
    Empty,
    Prepared,
    Current,
    Retained,
    Reclaimed,
}

/// Which dispatcher shape a cell attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Singles,
    Multi,
}

/// One loaded proof object: the dispatcher load (role `Dispatch`, owns
/// the shared select/gate/arrays in multi-load cells) or a bank load.
pub(crate) struct BankLoad {
    pub bpf: aya::Ebpf,
}

impl BankLoad {
    fn array<const N: usize>(&self, name: &str, key: u32) -> anyhow::Result<[u8; N]> {
        let map = self.bpf.map(name).expect("proof map present");
        let array = aya::maps::Array::<_, [u8; N]>::try_from(map)?;
        Ok(array.get(&key, 0)?)
    }

    fn array_set<const N: usize>(
        &mut self,
        name: &str,
        key: u32,
        value: [u8; N],
    ) -> anyhow::Result<()> {
        let map = self.bpf.map_mut(name).expect("proof map present");
        let mut array = aya::maps::Array::<_, [u8; N]>::try_from(map)?;
        array.set(key, value, 0)?;
        Ok(())
    }

    fn hash_get<const K: usize, const V: usize>(
        &self,
        name: &str,
        key: &[u8; K],
    ) -> anyhow::Result<Option<[u8; V]>> {
        let map = self.bpf.map(name).expect("proof map present");
        let hash = aya::maps::HashMap::<_, [u8; K], [u8; V]>::try_from(map)?;
        match hash.get(key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound) => {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn hash_insert<const K: usize, const V: usize>(
        &mut self,
        name: &str,
        key: &[u8; K],
        value: [u8; V],
    ) -> anyhow::Result<()> {
        let map = self.bpf.map_mut(name).expect("proof map present");
        let mut hash = aya::maps::HashMap::<_, [u8; K], [u8; V]>::try_from(map)?;
        hash.insert(key, value, 0)?;
        Ok(())
    }

    fn hash_remove<const K: usize, const V: usize>(
        &mut self,
        name: &str,
        key: &[u8; K],
    ) -> anyhow::Result<()> {
        let map = self.bpf.map_mut(name).expect("proof map present");
        let mut hash = aya::maps::HashMap::<_, [u8; K], [u8; V]>::try_from(map)?;
        hash.remove(key)?;
        Ok(())
    }

    /// Clear an owner array slot (tail calls through it fail closed).
    fn array_clear(&mut self, array: &str, index: u32) -> anyhow::Result<()> {
        let map = self.bpf.map_mut(array).expect("proof array present");
        let mut programs = aya::maps::ProgramArray::try_from(map)?;
        programs.clear_index(&index)?;
        Ok(())
    }

    fn map_data(&self, name: &str) -> &aya::maps::MapData {
        let map = self.bpf.map(name).expect("proof map present");
        match map {
            aya::maps::Map::Array(data)
            | aya::maps::Map::HashMap(data)
            | aya::maps::Map::ProgramArray(data)
            | aya::maps::Map::Unsupported(data) => data,
            _ => panic!("unexpected {name} proof map variant"),
        }
    }

    fn map_id(&self, name: &str) -> anyhow::Result<u32> {
        Ok(self.map_data(name).info()?.id())
    }

    /// Kernel `memlock` bytes charged for one map, from fdinfo.
    fn map_memlock(&self, name: &str) -> anyhow::Result<u64> {
        let raw = self.map_data(name).fd().as_fd().as_raw_fd();
        let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw}"))?;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("memlock:") {
                return Ok(value.trim().parse()?);
            }
        }
        anyhow::bail!("fdinfo for {name} has no memlock line")
    }
}

/// Shared maps every bank load reuses through pins in multi-load cells.
/// Bank loads keep only their own ticket/cookie/index/continuity maps.
/// Both query maps are shared: the driver publishes requests+control in
/// `shared` but runs the cover in the owning bank load, whose private
/// control would read generation 0 and return 1 (EAGAIN) on entry.
const SHARED_PIN_MAPS: [&str; 9] = [
    "BANK_SELECT",
    "BANK_GATE",
    "BANK_PROGS_SINGLES",
    "BANK_PROGS_MULTI",
    "BANK_PROGS_BIRTH",
    "IMAGE_BANK_ACCOUNT",
    "START",
    "IMAGE_QUERY_REQUESTS",
    "IMAGE_QUERY_CTL",
];
/// Proof-owned map names for the N4 count (10 added maps under R0).
const PROOF_MAP_NAMES: [&str; 10] = [
    "TASK_COOKIE_B",
    "COOKIE_CTL_B",
    "IMAGE_CONTINUITY_B",
    "IMAGE_TGID_INDEX_B",
    "BANK_SELECT",
    "BANK_GATE",
    "BANK_PROGS_SINGLES",
    "BANK_PROGS_MULTI",
    "BANK_PROGS_BIRTH",
    "IMAGE_BANK_ACCOUNT",
];

/// Cgroup-free private bpffs mount point name inside the cell dir.
const BPFFS_DIR: &str = "bpffs";

/// Compile the fixture binary into `dir`.
fn compile_fixture(dir: &Path) -> anyhow::Result<PathBuf> {
    let pinned = std::env::var(PROOF_FIXTURE_OVERRIDE_ENV)
        .ok()
        .filter(|path| !path.is_empty());
    let output = resolve_fixture_path(dir, pinned.as_deref());
    if pinned.is_some() {
        let bytes = std::fs::read(&output)?;
        let digest = sha2::Sha256::digest(&bytes);
        println!(
            "P11_BANK_PROOF_FIXTURE path={} sha256={}",
            output.display(),
            p11scope_manifest::identity::hex(&digest)
        );
        return Ok(output);
    }
    let source = dir.join("image-bank-proof.c");
    std::fs::write(&source, FIXTURE_SOURCE)?;
    let result = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread"])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(output)
}

/// Runtime override for the proof object path, read by
/// [`proof_object_path`]. Proof flavor only: this module exists solely
/// in cfg(test) proof builds. Lets a root run pin the exact object
/// bytes a libtest loads, so a pre-fix control carries its own object
/// instead of whatever a rebuilding worktree's `OUT_DIR` holds.
pub(crate) const PROOF_OBJECT_OVERRIDE_ENV: &str = "P11SCOPE_IMAGE_BANK_PROOF_OBJECT";

/// Resolve the proof object path: an explicit non-empty override
/// wins, otherwise the baked `OUT_DIR` object.
fn resolve_proof_object_path(override_path: Option<&str>) -> PathBuf {
    match override_path {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => Path::new(env!("OUT_DIR"))
            .join(PROOF_OUTPUTS)
            .join(PROOF_OBJECT_NAME),
    }
}

fn proof_object_path() -> PathBuf {
    resolve_proof_object_path(std::env::var(PROOF_OBJECT_OVERRIDE_ENV).ok().as_deref())
}

/// Runtime override for the proof fixture path. Proof flavor only:
/// this module exists solely in cfg(test) proof builds. Lets a root
/// run pin a prebuilt fixture (the Fedora E4 leg builds nothing on
/// that host) instead of compiling the fixture in the cell.
pub(crate) const PROOF_FIXTURE_OVERRIDE_ENV: &str = "P11SCOPE_IMAGE_BANK_PROOF_FIXTURE";

/// Resolve the proof fixture path: an explicit non-empty override
/// wins, otherwise the cell-local build output.
fn resolve_fixture_path(dir: &Path, override_path: Option<&str>) -> PathBuf {
    match override_path {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => dir.join("image-bank-fixture"),
    }
}

/// Read the proof object plus its identity line for the cell log, so
/// every root run names the object bytes it loaded.
fn proof_object_bytes() -> anyhow::Result<Vec<u8>> {
    let path = proof_object_path();
    let bytes = std::fs::read(&path)?;
    let digest = sha2::Sha256::digest(&bytes);
    println!(
        "P11_BANK_PROOF_OBJECT path={} sha256={}",
        path.display(),
        p11scope_manifest::identity::hex(&digest)
    );
    Ok(bytes)
}

fn default_object_bytes() -> anyhow::Result<Vec<u8>> {
    let path = Path::new(env!("OUT_DIR")).join("p11scope-ebpf");
    Ok(std::fs::read(&path)?)
}

fn cell_dir(tag: &str) -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "p11scope-image-bank-proof-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Mount a private bpffs for pin reuse, owned by this cell only.
fn mount_bpffs(dir: &Path) -> anyhow::Result<PathBuf> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let point = dir.join(BPFFS_DIR);
    std::fs::create_dir_all(&point)?;
    let source = CString::new("bpf")?;
    let target = CString::new(point.as_os_str().as_bytes())?;
    let fstype = CString::new("bpf")?;
    // SAFETY: mount(2) with valid NUL-terminated arguments; the cell runs
    // as root and unmounts this private mount when done.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        anyhow::bail!(
            "mounting private bpffs failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(point)
}

fn unmount_bpffs(point: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if let Ok(target) = CString::new(point.as_os_str().as_bytes()) {
        // SAFETY: unmount(2) on a mount this cell owns.
        unsafe {
            libc::umount(target.as_ptr());
        }
    }
}

/// Drop guard for a cell-private bpffs mount: unmounts when dropped,
/// including panic unwinding anywhere in multi-load setup. The guard is
/// armed the moment the mount succeeds, before any fallible step.
struct BpffsGuard {
    point: Option<PathBuf>,
    unmount: fn(&Path),
}

impl BpffsGuard {
    fn armed(point: PathBuf) -> Self {
        Self {
            point: Some(point),
            unmount: unmount_bpffs,
        }
    }

    #[cfg(test)]
    fn armed_with(point: PathBuf, unmount: fn(&Path)) -> Self {
        Self {
            point: Some(point),
            unmount,
        }
    }

    fn point(&self) -> &Path {
        self.point.as_ref().expect("armed bpffs guard")
    }
}

impl Drop for BpffsGuard {
    fn drop(&mut self) {
        if let Some(point) = self.point.take() {
            (self.unmount)(&point);
        }
    }
}

/// Publish a fresh ticket control (limit set, counters zero, no reset).
fn fresh_control() -> [u8; 40] {
    let mut control = [0u8; 40];
    put_u64(&mut control, 0, TICKET_LIMIT);
    control
}

/// N12 birth accounting: `task_newtask` fires system-wide for every
/// fork/clone without `CLONE_THREAD` -- including the fixture runner
/// process the driver spawns for the phase itself. Each such birth
/// spends one ticket; only target calls admit.
fn fork_birth_tickets(spent: u64, children: u64) -> u64 {
    spent + children + 1
}

/// N12 saturation accounting: at quota the runner's own birth also
/// refuses with QUOTA, so `unavailable` grows by calls plus one.
fn quota_unavailable_after(before: u64, calls: u64) -> u64 {
    before + calls + 1
}

/// N4 second-bank tables budget: plan's per-element 88x16384+72x16384
/// plus buckets 2x262144, within the plan's +-5% fdinfo-vs-computed
/// rule. Newer kernels report buckets+htab+locks in fdinfo memlock
/// via htab_map_mem_usage (kernel/bpf/hashtab.c); 5.15 reports the
/// static footprint via bpf_map_memory_footprint (kernel/bpf/syscall.c),
/// far under this budget.
fn n4_second_bank_tables_budget() -> u64 {
    n4_second_bank_tables_figure() * 105 / 100
}

/// Ambient births during a fork window: observed ticket delta minus
/// the test-owned births (children + runner). The birth hook
/// (`p11_bank_birth_a` via system-wide `task_newtask`) spends one
/// ticket per non-thread birth, including ambient forks. Returns None
/// if observed is short (a test-owned birth failed to spend, not
/// ambient): the caller must stop with a named message, never a
/// count mismatch.
fn ambient_births(observed_delta: u64, test_owned: u64) -> Option<u64> {
    observed_delta.checked_sub(test_owned)
}

/// N7 ledger with counted burns: admitted plus task-storage creation
/// failures (tickets burned without admission, e.g. under host load)
/// must equal the fixture's ledger calls. Mirrors N6's
/// successful+burned; the N7 cell has no birth hook, so ambient
/// forks cannot spend tickets there.
fn n7_ledger_with_burns(admitted: u64, create_failures: u64) -> u64 {
    admitted + create_failures
}

/// Counted admission failures behind one bank account: every
/// enter-core refusal lands in exactly one bucket, so admitted plus
/// this sum equals the fixture's ledger calls.
fn counted_admission_failures(account: &BankAccount) -> u64 {
    account.cookie_failures
        + account.seed_failures
        + account.start_present
        + account.start_insert_failures
}

/// Conservation over one bank's account values: every ledger call was
/// admitted or landed in a counted failure bucket. Refuses an
/// uncounted shortfall ("silent admission loss"); accepts an exact
/// count and a fully-counted shortfall.
fn admission_conserved(account: &BankAccount, calls: u64) -> bool {
    account.admitted + counted_admission_failures(account) == calls
}

/// N6/N7 ledger with every counted burn: admitted plus the control
/// task-storage creation failures plus the per-cause account buckets
/// (cookie failures ride the control word in these cells, so the
/// account buckets counted here are seed, present and insert). A
/// ticket burned in any counted bucket is reported, not lost.
fn ledger_with_all_burns(admitted: u64, create_failures: u64, account: &BankAccount) -> u64 {
    n7_ledger_with_burns(admitted, create_failures)
        + account.seed_failures
        + account.start_present
        + account.start_insert_failures
}

/// Conservation over one bank's ticket control: every issued ticket
/// was admitted or burned in a counted bucket. Exact: an over-count
/// fails closed like a shortfall.
fn tickets_conserved(account: &BankAccount, control: &BankControl) -> bool {
    ledger_with_all_burns(account.admitted, control.create_failures, account) == control.next_ticket
}

/// Quiescence for a bank checkpoint: nothing live and every ticket
/// accounted for. Reported burns do not block quiescence; a stuck
/// live ref or an uncounted shortfall never quiesces.
fn bank_quiescent(account: &BankAccount, control: &BankControl) -> bool {
    account.live == 0 && tickets_conserved(account, control)
}

/// Bounded quiescence poll over fresh control/account reads. A
/// healthy bank is quiescent on the first read (every workload task
/// is reaped before the checkpoint), so the deadline only fires on a
/// stuck live ref or an uncounted shortfall. Returns the final reads
/// and whether they were quiescent; the checkpoint asserts exactly
/// on the final reads, so a loss fails after the deadline instead of
/// passing through the wait.
/// Poll step between quiescence reads.
const QUIESCE_POLL_STEP: Duration = Duration::from_millis(10);

fn poll_bank_until_quiescent(
    mut read: impl FnMut() -> (BankAccount, BankControl),
    deadline: Duration,
) -> ((BankAccount, BankControl), bool) {
    let start = Instant::now();
    loop {
        let reads = read();
        if bank_quiescent(&reads.0, &reads.1) {
            return (reads, true);
        }
        if start.elapsed() >= deadline {
            return (reads, false);
        }
        std::thread::sleep(QUIESCE_POLL_STEP);
    }
}

/// Running kernel release for the per-kernel proof verdicts (the N2,
/// N4 and N8 class lines), read the way the doctor reads it.
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|raw| raw.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// N2 verifier-count gate outcome: check the count against the gates,
/// or record the root as explicitly load-only (5.15 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum N2Gate {
    Check(u32),
    LoadOnly,
}

/// N2 verifier-count gate: a present count is always checked; an
/// absent count is explicitly load-only on kernels without
/// `verified_insns` (5.15) and a named failure everywhere else. An
/// unparsable release fails closed. Never a silent pass.
///
/// The verifier stats log would carry the processed count on 5.15,
/// but the proof loader cannot return a successful load's log: the
/// patched aya drops it on success (LoadError carries it only on
/// failure). Plumbing it would change production loader code, so
/// 5.15 roots stay explicitly load-only.
fn n2_count_gate(
    root: &str,
    verified_insns: Option<u32>,
    kernel_release: &str,
) -> Result<N2Gate, String> {
    match verified_insns {
        Some(processed) => Ok(N2Gate::Check(processed)),
        None if kernel_has_verified_insns(kernel_release) => Err(format!(
            "N2 {root}: kernel {kernel_release} provides verified_insns but the load returned no count"
        )),
        None => Ok(N2Gate::LoadOnly),
    }
}

/// Whether the running kernel provides `verified_insns` in program
/// info (added in 5.16; the patched aya documents the boundary). An
/// unparsable release claims the field, so an absent count fails
/// closed instead of passing as load-only.
fn kernel_has_verified_insns(release: &str) -> bool {
    match crate::doctor::parse_major_minor(release) {
        Some(version) => version >= (5, 16),
        None => true,
    }
}

/// N8 verdict class from the running kernel: the product's multi
/// functional probe decides, never a version check. Probe success
/// (uprobe_multi kernels) means exactly 40,000 admitted with zero
/// counted failures; probe failure (older kernels) keeps
/// conservation with per-cause buckets.
fn n8_requires_exact_count(multi_possible: bool) -> bool {
    multi_possible
}

/// N8 capacity rule: a failure in a capacity cause -- the bank map
/// full at its declared worst case -- fails named on every kernel.
/// Two signals: a START insert refused with E2BIG (the START map is
/// full; N8 holds at most 4 live rows), and ticket saturation at the
/// 16,384 limit with any counted failure on that bank (the per-bank
/// maps are full, so every refusal there is plausibly capacity; the
/// seed errno is unrecorded, hence fail-closed). The START errno is
/// last-writer under concurrent failures, exact at observed rates.
fn n8_capacity_failure(
    bank: &str,
    phase: &str,
    account: &BankAccount,
    control: &BankControl,
) -> Option<String> {
    if account.start_insert_failures > 0
        && account.start_insert_errno as i64 == -(libc::E2BIG as i64)
    {
        return Some(format!(
            "N8 {phase} bank {bank} capacity: START insert refused with E2BIG ({} failures, bank map full at declared worst case)",
            account.start_insert_failures
        ));
    }
    if control.next_ticket >= TICKET_LIMIT && counted_admission_failures(account) > 0 {
        return Some(format!(
            "N8 {phase} bank {bank} capacity: tickets saturated at {TICKET_LIMIT} with {} counted failures (bank map full at declared worst case)",
            counted_admission_failures(account)
        ));
    }
    None
}

/// N5 fixed numbers (plan row N5: quiet lane, same tree dispatcher
/// off/on, 1 and 4 threads, 5 runs x 1M completed controlled calls;
/// any miss is FAIL, not a retune).
pub(crate) const N5_CALLS_PER_RUN: u64 = 1_000_000;
pub(crate) const N5_RUNS_PER_LEG: usize = 5;
pub(crate) const N5_ADDED_BUDGET_NS: f64 = 250.0;
pub(crate) const N5_PCT_BUDGET: f64 = 15.0;

/// Nanoseconds per completed call for one N5 run.
fn n5_ns_per_call(elapsed_ns: u64, calls: u64) -> f64 {
    elapsed_ns as f64 / calls as f64
}

/// Median of per-run values. Even counts average the two middles;
/// empty input has no median.
fn n5_median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[mid])
    } else {
        Some((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// Spread (min, max) of per-run values; empty input has no spread.
fn n5_spread(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    let mut min = values[0];
    let mut max = values[0];
    for &value in &values[1..] {
        min = min.min(value);
        max = max.max(value);
    }
    Some((min, max))
}

/// Added dispatcher cost for one run: dispatcher-on minus
/// dispatcher-off. Negative values are scheduling noise, not errors.
fn n5_added(dispatch_on_ns: f64, dispatch_off_ns: f64) -> f64 {
    dispatch_on_ns - dispatch_off_ns
}

/// Added cost as a percentage of the traced per-call cost for one
/// run. None when the traced baseline is not positive: no
/// denominator, no ratio, and the cell fails closed.
fn n5_run_pct(untraced_ns: f64, traced_ns: f64, dispatch_on_ns: f64) -> Option<f64> {
    let traced = traced_ns - untraced_ns;
    if traced <= 0.0 {
        return None;
    }
    Some(n5_added(dispatch_on_ns, traced_ns) * 100.0 / traced)
}

/// Completeness for one traced N5 run: the programs must report
/// exactly the calls made, with nothing live, faulted, refused or
/// extra-ticketed. Err names the first mismatch; the cell fails the
/// run (never a timing from an incomplete run).
fn n5_check_counts(
    made: u64,
    account: &BankAccount,
    control: &BankControl,
    expected_tickets: u64,
) -> Result<(), String> {
    if account.admitted != made {
        return Err(format!(
            "admitted={} != {made} calls made",
            account.admitted
        ));
    }
    if account.completed != made {
        return Err(format!(
            "completed={} != {made} calls made",
            account.completed
        ));
    }
    if account.live != 0 {
        return Err(format!("live={} (accepted-but-uncounted)", account.live));
    }
    if account.faults != 0 {
        return Err(format!("faults={}", account.faults));
    }
    let failures = counted_admission_failures(account);
    if failures != 0 {
        return Err(format!(
            "counted admission failures={failures} (cookie={} seed={} present={} insert={})",
            account.cookie_failures,
            account.seed_failures,
            account.start_present,
            account.start_insert_failures
        ));
    }
    if control.next_ticket != expected_tickets {
        return Err(format!(
            "next_ticket={} != {expected_tickets} expected tickets",
            control.next_ticket
        ));
    }
    Ok(())
}

/// N5 verdict for one thread count: medians and spreads plus
/// PASS/FAIL. Pass needs median added within budget AND median
/// percentage within budget; empty inputs never pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct N5Verdict {
    pub median_added_ns: f64,
    pub min_added_ns: f64,
    pub max_added_ns: f64,
    pub median_pct: f64,
    pub min_pct: f64,
    pub max_pct: f64,
    pub pass: bool,
}

fn n5_verdict(added_ns: &[f64], pct: &[f64]) -> N5Verdict {
    let median_added_ns = n5_median(added_ns).unwrap_or(f64::NAN);
    let (min_added_ns, max_added_ns) = n5_spread(added_ns).unwrap_or((f64::NAN, f64::NAN));
    let median_pct = n5_median(pct).unwrap_or(f64::NAN);
    let (min_pct, max_pct) = n5_spread(pct).unwrap_or((f64::NAN, f64::NAN));
    // Both gates are inclusive; a NaN median (empty input) compares
    // false, so it never passes.
    let pass = median_added_ns <= N5_ADDED_BUDGET_NS && median_pct <= N5_PCT_BUDGET;
    N5Verdict {
        median_added_ns,
        min_added_ns,
        max_added_ns,
        median_pct,
        min_pct,
        max_pct,
        pass,
    }
}

/// N5 workload for a thread count: 1M completed calls per run. Only
/// 1 and 4 threads exist (the plan fixes both); anything else is
/// None. The 4-thread mode reuses the N8 barrier handshake with
/// stdin null (EOF releases each thread after HALF): the one mid-run
/// barrier is a leg-independent additive term that cancels in the
/// leg differences.
fn n5_workload_args(threads: u64) -> Option<Vec<String>> {
    match threads {
        1 => Some(vec!["call".to_string(), N5_CALLS_PER_RUN.to_string()]),
        4 => Some(vec![
            "threads".to_string(),
            "4".to_string(),
            (N5_CALLS_PER_RUN / 4).to_string(),
        ]),
        _ => None,
    }
}

/// Whole-nanosecond wall time for one N5 run.
fn n5_elapsed_ns(elapsed: Duration) -> u64 {
    elapsed.as_secs() * 1_000_000_000 + u64::from(elapsed.subsec_nanos())
}

/// `BANK_SELECT` value size: the flip word (bank, incarnation) plus the
/// fixed per-slot incarnation each bank entry stamps (never the flip
/// word's incarnation, which a later flip can move under an admission).
const BANK_SELECT_SIZE: usize = 32;

/// Seed-failure status every enter core returns
/// (`BANK_FAIL_SEED, 0, COOKIE_STATUS_ZERO_CELL` in
/// `crates/ebpf/native/image_bank_proof.c`, `COOKIE_STATUS_ZERO_CELL =
/// 8` in `crates/ebpf/native/image_identity.h`). Recorded in every
/// admission-failure evidence line.
pub(crate) const SEED_FAILURE_STATUS: u32 = 8;

/// Production traced per-call cost inputs (ns/call) for the N5 15%
/// denominator, one per measured thread count, from the
/// `scripts/bench-count-overhead.sh` method (observed minus
/// unobserved on the `mt_count` workload) on the same host and
/// window. Absent or unparsable input leaves the percentage
/// not-computed and gates the 250 ns budget only.
pub(crate) const N5_PRODUCTION_ENV_1: &str = "P11_BANK_N5_PRODUCTION_NS_1";
pub(crate) const N5_PRODUCTION_ENV_4: &str = "P11_BANK_N5_PRODUCTION_NS_4";

/// In-flight N8 fixture shape (`inflight <threads> <calls>`): every
/// thread makes this many warmup calls before the STARTED barrier
/// (all deterministically pre-flip), then `INFLIGHT_CALLS` free
/// calls while the controller cuts. Each phase runs
/// `INFLIGHT_THREADS` threads.
pub(crate) const INFLIGHT_WARMUP: u64 = 100;
pub(crate) const INFLIGHT_CALLS: u64 = 10000;
pub(crate) const INFLIGHT_THREADS: u64 = 4;

/// One in-flight phase total: threads times warmup plus free calls.
fn inflight_total_calls(threads: u64) -> u64 {
    threads * (INFLIGHT_WARMUP + INFLIGHT_CALLS)
}

/// Fresh `BANK_SELECT` value: the flip word plus fixed words.
fn select_value(bank: u64, incarnation: u64, fixed: [u64; 2]) -> [u8; BANK_SELECT_SIZE] {
    let mut value = [0u8; BANK_SELECT_SIZE];
    put_u64(&mut value, 0, bank);
    put_u64(&mut value, 8, incarnation);
    put_u64(&mut value, 16, fixed[0]);
    put_u64(&mut value, 24, fixed[1]);
    value
}

/// Flip word update: replace bank and incarnation, preserve the
/// fixed per-slot incarnations.
fn flip_select_word(
    current: &[u8; BANK_SELECT_SIZE],
    bank: u64,
    incarnation: u64,
) -> [u8; BANK_SELECT_SIZE] {
    let mut next = *current;
    put_u64(&mut next, 0, bank);
    put_u64(&mut next, 8, incarnation);
    next
}

/// Prepare update: set one slot's fixed incarnation, preserve the
/// flip word and the other slot.
fn set_fixed_word(
    current: &[u8; BANK_SELECT_SIZE],
    slot: u32,
    incarnation: u64,
) -> [u8; BANK_SELECT_SIZE] {
    let mut next = *current;
    put_u64(&mut next, 16 + slot as usize * 8, incarnation);
    next
}

/// Next incarnation: past every incarnation any slot has carried (no
/// identity reuse by construction).
fn next_incarnation(seen: &[u64; 2]) -> u64 {
    seen[0].max(seen[1]) + 1
}

/// Admission closed-zero for one bank: its gate drained (no
/// selected-but-unadmitted call outstanding), nothing live, no START
/// rows. Every in-flight call holds at least one of the three, so a
/// bank reading all three is reclaimable.
fn closed_zero_admission(live: u64, start_rows: usize, gate: u64) -> bool {
    gate == 0 && live == 0 && start_rows == 0
}

/// Fresh-bank admission check: on a fresh, under-capacity bank any
/// seed, present or insert failure fails the cell by name (burns
/// stay only for the causes the row allows: task-storage creation
/// failures through the control word). The seed arm names the
/// `SEED_FAILURE_STATUS` code the enter cores return.
fn fresh_bank_admission_clean(bank: &str, account: &BankAccount) -> Result<(), String> {
    if account.seed_failures != 0 {
        return Err(format!(
            "bank {bank} fresh under-capacity bank seeded {} failures (status ZERO_CELL={})",
            account.seed_failures, SEED_FAILURE_STATUS
        ));
    }
    if account.start_present != 0 {
        return Err(format!(
            "bank {bank} fresh under-capacity bank refused {} present START rows",
            account.start_present
        ));
    }
    if account.start_insert_failures != 0 {
        return Err(format!(
            "bank {bank} fresh under-capacity bank failed {} START inserts (errno {})",
            account.start_insert_failures, account.start_insert_errno as i64
        ));
    }
    Ok(())
}

/// N5 percentage over the production traced per-call cost: added
/// dispatcher ns per call divided by the production input. None
/// when the production input is not positive: no denominator, no
/// ratio, and the cell reports pct not-computed.
fn n5_run_pct_production(added_ns: f64, production_ns: f64) -> Option<f64> {
    if production_ns <= 0.0 {
        return None;
    }
    Some(added_ns * 100.0 / production_ns)
}

/// N5 verdict without a production input: medians and spreads plus
/// PASS/FAIL over the 250 ns added gate only; the pct fields are
/// NaN and never gate.
fn n5_verdict_ns_only(added_ns: &[f64]) -> N5Verdict {
    let median_added_ns = n5_median(added_ns).unwrap_or(f64::NAN);
    let (min_added_ns, max_added_ns) = n5_spread(added_ns).unwrap_or((f64::NAN, f64::NAN));
    // The 250 ns gate only; a NaN median (empty input) never passes.
    let pass = median_added_ns <= N5_ADDED_BUDGET_NS;
    N5Verdict {
        median_added_ns,
        min_added_ns,
        max_added_ns,
        median_pct: f64::NAN,
        min_pct: f64::NAN,
        max_pct: f64::NAN,
        pass,
    }
}

/// Parse one production-cost input: a positive finite ns/call
/// number, else None (missing, unparsable, non-positive or
/// non-finite input never gates the percentage).
fn n5_production_ns(var: Option<&str>) -> Option<f64> {
    let value: f64 = var?.trim().parse().ok()?;
    if value.is_finite() && value > 0.0 {
        Some(value)
    } else {
        None
    }
}

/// N4 computed second-bank tables figure: per-element 88x16384 +
/// 72x16384 plus buckets 2x262144 = 3145728.
fn n4_second_bank_tables_figure() -> u64 {
    88 * 16384 + 72 * 16384 + 2 * 262144
}

/// N4 second-bank tables floor: 95% of the computed figure.
fn n4_second_bank_tables_floor() -> u64 {
    n4_second_bank_tables_figure() * 95 / 100
}

/// N4 tables band: the measured second-bank tables must fall within
/// +-5% of the computed figure.
fn n4_tables_within_band(measured: u64) -> bool {
    let floor = n4_second_bank_tables_floor();
    let budget = n4_second_bank_tables_budget();
    floor <= measured && measured <= budget
}

/// Whether the kernel's fdinfo reports htab usage for maps (6.6+,
/// the kernels with measured E3 evidence). 5.15 reports the static
/// footprint; the unmeasured 6.1 and unparsable releases stay
/// upper-only with the note (the upper bound is still a real gate).
fn kernel_reports_htab_usage(release: &str) -> bool {
    matches!(
        crate::doctor::parse_major_minor(release),
        Some(version) if version >= (6, 6)
    )
}

/// File offset of `want` in the fixture ELF for multi links, which
/// attach by offset, not symbol. Translates st_value via its section
/// (`st_value - sh_addr + sh_offset`), the same translation patched
/// aya uses for `Symbol` points (`symbol_translated_address` over
/// `Dynamic | Executable` in `programs/uprobe.rs`).
fn fixture_symbol_file_offset(path: &Path, want: &str) -> anyhow::Result<u64> {
    let bytes = std::fs::read(path)?;
    anyhow::ensure!(bytes.len() >= 64, "fixture too small for ELF64");
    anyhow::ensure!(&bytes[0..4] == b"\x7fELF", "not an ELF object");
    let shoff = u64_at_le(&bytes, 40) as usize;
    let shentsize = u16_at(&bytes, 58) as usize;
    let shnum = u16_at(&bytes, 60) as usize;
    let mut symtab = None;
    let mut strtab = None;
    for index in 0..shnum {
        let at = shoff + index * shentsize;
        if u32_at_le(&bytes, at + 4) == 2 {
            symtab = Some((
                u64_at_le(&bytes, at + 24) as usize,
                u64_at_le(&bytes, at + 32) as usize,
            ));
            let link = u32_at_le(&bytes, at + 40) as usize;
            let str_at = shoff + link * shentsize;
            strtab = Some((
                u64_at_le(&bytes, str_at + 24) as usize,
                u64_at_le(&bytes, str_at + 32) as usize,
            ));
        }
    }
    let (sym_off, sym_size) = symtab.ok_or_else(|| anyhow::anyhow!("fixture has no symtab"))?;
    let (str_off, str_size) = strtab.ok_or_else(|| anyhow::anyhow!("symtab links no strtab"))?;
    let mut at = sym_off;
    while at + 24 <= sym_off + sym_size {
        let name_at = u32_at_le(&bytes, at) as usize;
        let end = bytes[str_off + name_at..str_off + str_size]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        let name = String::from_utf8_lossy(&bytes[str_off + name_at..str_off + name_at + end]);
        if name == want {
            let shndx = u16_at(&bytes, at + 6) as usize;
            let value = u64_at_le(&bytes, at + 8);
            anyhow::ensure!(shndx < shnum, "symbol section out of range");
            let sec_at = shoff + shndx * shentsize;
            let sh_addr = u64_at_le(&bytes, sec_at + 16);
            let sh_offset = u64_at_le(&bytes, sec_at + 24);
            return value
                .checked_sub(sh_addr)
                .and_then(|rel| rel.checked_add(sh_offset))
                .ok_or_else(|| anyhow::anyhow!("symbol address not in its section"));
        }
        at += 24;
    }
    anyhow::bail!("fixture has no {want} symbol")
}

/// `CLOCK_MONOTONIC` in nanoseconds (the `bpf_ktime_get_ns` clock).
fn monotonic_ns() -> anyhow::Result<u64> {
    let mut spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid out-pointer.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut spec) };
    anyhow::ensure!(rc == 0, "clock_gettime failed");
    Ok(spec.tv_sec as u64 * 1_000_000_000 + spec.tv_nsec as u64)
}

/// Run the fixture to completion, capturing stdout (stdin null: the
/// `threads` mode releases itself on EOF after its barrier). Shared
/// by `run_simple` and the untraced N5 leg so every leg times the
/// same spawn path.
fn run_fixture_once(fixture: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Ok(Command::new(fixture)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// The cfg(test) proof driver: loads, maps, attachments and workload runs.
pub(crate) struct BankProofDriver {
    pub dir: PathBuf,
    pub fixture: PathBuf,
    /// Loads by role key (`shared` owns select/gate/arrays in every cell).
    pub loads: HashMap<String, BankLoad>,
    pub slot_state: [SlotState; 2],
    pub slot_load: [Option<String>; 2],
    pub slot_inc: [u64; 2],
    pub query_loaded: HashSet<String>,
    bpffs: Option<BpffsGuard>,
    bank_seq: u64,
    /// Live multi links (raw `BPF_LINK_CREATE` fds outside aya's link
    /// table, kept alive for the cell; dropping detaches).
    multi_links: Vec<OwnedFd>,
    /// The attach backend this driver serves. Chosen at setup; every
    /// slot-root load and every owner-array install in this driver
    /// uses this backend's attach type, so each program array keeps
    /// one expected attach type per map instance (CVE-2025-40123).
    backend: Backend,
}

impl BankProofDriver {
    /// Single-load cell: one object owns both banks' maps; slot A is
    /// installed and current, slot B is empty. No birth attach (ambient
    /// births must not spend tickets in deterministic cells). The
    /// driver serves `backend` only; attaching the other backend
    /// refuses, so no map instance ever sees two attach types.
    pub fn setup(pin_tag: &str, backend: Backend) -> anyhow::Result<Self> {
        let dir = cell_dir(pin_tag)?;
        let fixture = compile_fixture(&dir)?;
        let bytes = proof_object_bytes()?;
        let bpf = aya::EbpfLoader::new()
            .allow_unsupported_maps()
            .load(&bytes)?;
        let mut driver = Self {
            dir,
            fixture,
            loads: HashMap::new(),
            slot_state: [SlotState::Empty, SlotState::Empty],
            slot_load: [None, None],
            slot_inc: [0, 0],
            query_loaded: HashSet::new(),
            bpffs: None,
            bank_seq: 0,
            multi_links: Vec::new(),
            backend,
        };
        driver.loads.insert("shared".to_string(), BankLoad { bpf });
        driver.publish_shared()?;
        // Slot A: publish its control, load its programs, install it.
        {
            let shared = driver.loads.get_mut("shared").expect("shared load");
            shared.array_set("COOKIE_CTL", 0, fresh_control())?;
            shared.array_set("COOKIE_CTL_B", 0, fresh_control())?;
        }
        driver.load_bank_progs("shared", 0)?;
        driver.install_slot(0, "shared")?;
        driver.slot_state = [SlotState::Current, SlotState::Empty];
        driver.slot_load = [Some("shared".to_string()), None];
        driver.slot_inc = [1, 0];
        {
            let shared = driver.loads.get_mut("shared").expect("shared load");
            shared.array_set("BANK_SELECT", 0, select_value(0, 1, [1, 0]))?;
        }
        Ok(driver)
    }

    /// Multi-load cell: a dispatcher load owns the shared maps through a
    /// private bpffs; bank slot A gets its own load reusing those pins.
    /// Used by the second-rollover and late-incarnation cells. Serves
    /// `backend` only, like [`Self::setup`].
    pub fn setup_shared(pin_tag: &str, backend: Backend) -> anyhow::Result<Self> {
        let dir = cell_dir(pin_tag)?;
        let fixture = compile_fixture(&dir)?;
        let bpffs = BpffsGuard::armed(mount_bpffs(&dir)?);
        let bytes = proof_object_bytes()?;
        let mut loader = aya::EbpfLoader::new();
        loader.allow_unsupported_maps();
        for name in SHARED_PIN_MAPS {
            loader.map_pin_path(name, bpffs.point().join(name));
        }
        let bpf = loader.load(&bytes)?;
        let mut driver = Self {
            dir,
            fixture,
            loads: HashMap::new(),
            slot_state: [SlotState::Empty, SlotState::Empty],
            slot_load: [None, None],
            slot_inc: [0, 0],
            query_loaded: HashSet::new(),
            bpffs: Some(bpffs),
            bank_seq: 0,
            multi_links: Vec::new(),
            backend,
        };
        driver.loads.insert("shared".to_string(), BankLoad { bpf });
        driver.publish_shared()?;
        let key = driver.prepare_bank_load(0)?;
        driver.load_bank_progs(&key, 0)?;
        driver.install_slot(0, &key)?;
        driver.slot_state = [SlotState::Current, SlotState::Empty];
        driver.slot_load[0] = Some(key);
        driver.slot_inc = [1, 0];
        {
            let shared = driver.loads.get_mut("shared").expect("shared load");
            shared.array_set("BANK_SELECT", 0, select_value(0, 1, [1, 0]))?;
        }
        Ok(driver)
    }

    fn publish_shared(&mut self) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        shared.array_set("BANK_GATE", 0, [0u8; 8])?;
        shared.array_set("BANK_GATE", 1, [0u8; 8])?;
        for slot in 0..3u32 {
            shared.array_set("IMAGE_BANK_ACCOUNT", slot, [0u8; BANK_ACCOUNT_SIZE])?;
        }
        Ok(())
    }

    /// Load one more bank object reusing the shared pins; returns its key.
    fn prepare_bank_load(&mut self, slot: u32) -> anyhow::Result<String> {
        let bpffs = self
            .bpffs
            .as_ref()
            .expect("multi-load cell")
            .point()
            .to_path_buf();
        let bytes = proof_object_bytes()?;
        let mut loader = aya::EbpfLoader::new();
        loader.allow_unsupported_maps();
        for name in SHARED_PIN_MAPS {
            loader.map_pin_path(name, bpffs.join(name));
        }
        let bpf = loader.load(&bytes)?;
        self.bank_seq += 1;
        let key = format!("bank{slot}-{}", self.bank_seq);
        let mut load = BankLoad { bpf };
        if slot == 0 {
            load.array_set("COOKIE_CTL", 0, fresh_control())?;
        } else {
            load.array_set("COOKIE_CTL_B", 0, fresh_control())?;
        }
        self.loads.insert(key.clone(), load);
        Ok(key)
    }

    fn entry_prog(slot: u32) -> &'static str {
        if slot == 0 {
            "p11_bank_entry_a"
        } else {
            "p11_bank_entry_b"
        }
    }

    fn birth_prog(slot: u32) -> &'static str {
        if slot == 0 {
            "p11_bank_birth_a"
        } else {
            "p11_bank_birth_b"
        }
    }

    /// Load a bank's slot programs (entry + birth) in its own load.
    /// The entry loads exactly once, with this driver's backend
    /// attach type (plain under Singles, multi under Multi); since
    /// CVE-2025-40123 a program array keeps its first program's
    /// expected attach type, loading one entry both ways in one map
    /// instance is refused with EINVAL after verification (the guard
    /// array the entries reference would see two types). Birth is a
    /// BTF tracepoint under both backends.
    fn load_bank_progs(&mut self, key: &str, slot: u32) -> anyhow::Result<()> {
        let load = self.loads.get_mut(key).expect("bank load present");
        let entry: &mut aya::programs::UProbe = load
            .bpf
            .program_mut(Self::entry_prog(slot))
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        if self.backend == Backend::Multi {
            entry.load_multi()?;
        } else {
            entry.load()?;
        }
        let birth: &mut aya::programs::BtfTracePoint = load
            .bpf
            .program_mut(Self::birth_prog(slot))
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        let btf = aya::Btf::from_sys_fs()?;
        birth.load("task_newtask", &btf)?;
        Ok(())
    }

    /// The one owner array this driver's backend installs into (each
    /// driver loads its slot roots with one attach type); install_slot
    /// spells the same match inline for its completeness check.
    fn owner_array(&self) -> &'static str {
        match self.backend {
            Backend::Singles => "BANK_PROGS_SINGLES",
            Backend::Multi => "BANK_PROGS_MULTI",
        }
    }

    /// Install a bank's programs into this driver's owner array. Each
    /// entry-owner array holds a tail target carrying its own attach
    /// type: since CVE-2025-40123 a program array records the first
    /// program's expected attach type and refuses callers with a
    /// different one, so the Singles array holds a plain entry and
    /// the Multi array a multi entry (as the product does for its
    /// pair continuation, which likewise carries its caller's type).
    /// Each driver serves one backend, so each slot root is installed
    /// once and the guard array it references keeps one expected
    /// attach type per map instance. This is a pure install: the
    /// entry FD comes from the load above, nothing is detached or
    /// reloaded, and entry programs are never attached (only
    /// dispatcher, return, reference, birth, exec and query programs
    /// attach).
    fn install_slot(&mut self, slot: u32, key: &str) -> anyhow::Result<()> {
        let fd_entry = {
            let load = self.loads.get(key).expect("bank load present");
            load.bpf
                .program(Self::entry_prog(slot))
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .fd()?
                .try_clone()?
        };
        {
            let array = match self.backend {
                Backend::Singles => "BANK_PROGS_SINGLES",
                Backend::Multi => "BANK_PROGS_MULTI",
            };
            let shared = self.loads.get_mut("shared").expect("shared load");
            let map = shared.bpf.map_mut(array).expect("proof array present");
            let mut programs = aya::maps::ProgramArray::try_from(map)?;
            programs.set(slot, &fd_entry, 0)?;
        }
        let fd_birth = {
            let load = self.loads.get(key).expect("bank load present");
            load.bpf
                .program(Self::birth_prog(slot))
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .fd()?
                .try_clone()?
        };
        let shared = self.loads.get_mut("shared").expect("shared load");
        let map = shared
            .bpf
            .map_mut("BANK_PROGS_BIRTH")
            .expect("proof array present");
        let mut programs = aya::maps::ProgramArray::try_from(map)?;
        programs.set(slot, &fd_birth, 0)?;
        Ok(())
    }

    /// Re-install a slot's programs (restores service after the N11
    /// tail-call-failure injection without touching map contents).
    pub fn reinstall(&mut self, slot: u32) -> anyhow::Result<()> {
        let key = self.bank_load_key(slot).to_string();
        self.install_slot(slot, &key)
    }

    /// Clear one owner array slot (the N11 tail-call-failure injection).
    pub fn clear_array(&mut self, array: &str, slot: u32) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        shared.array_clear(array, slot)
    }

    /// Prepare a bank slot: assign its fixed incarnation, then fresh
    /// programs installed, not yet current. The fixed word is written
    /// while the slot is empty or reclaimed (nothing in flight) and
    /// verified by read-back; the bank entry stamps it from then on.
    /// Refuses unless the slot is empty or reclaimed (N11 third preparation
    /// while the old bank is retained refuses here).
    pub fn prepare(&mut self, slot: u32) -> anyhow::Result<()> {
        let index = slot as usize;
        anyhow::ensure!(
            matches!(
                self.slot_state[index],
                SlotState::Empty | SlotState::Reclaimed
            ),
            "preparing slot {slot} while {:?}: refused",
            self.slot_state[index]
        );
        let incarnation = next_incarnation(&self.slot_inc);
        {
            let shared = self.loads.get_mut("shared").expect("shared load");
            let current: [u8; BANK_SELECT_SIZE] = shared.array("BANK_SELECT", 0)?;
            shared.array_set(
                "BANK_SELECT",
                0,
                set_fixed_word(&current, slot, incarnation),
            )?;
            let back: [u8; BANK_SELECT_SIZE] = shared.array("BANK_SELECT", 0)?;
            let fixed = decode_select(&back).fixed[index];
            anyhow::ensure!(
                fixed == incarnation,
                "slot {slot} fixed incarnation read back as {fixed}"
            );
        }
        self.slot_inc[index] = incarnation;
        if self.bpffs.is_some() {
            let key = self.prepare_bank_load(slot)?;
            self.load_bank_progs(&key, slot)?;
            self.install_slot(slot, &key)?;
            self.slot_load[index] = Some(key);
        } else {
            self.load_bank_progs("shared", slot)?;
            self.install_slot(slot, "shared")?;
            self.slot_load[index] = Some("shared".to_string());
        }
        self.slot_state[index] = SlotState::Prepared;
        Ok(())
    }

    /// Flip `BANK_SELECT` to a prepared bank (Session-owned cut):
    /// publish the slot and the fixed incarnation its prepare
    /// assigned. Refuses an unprepared slot, an incarnation that is
    /// not the prepared one, and any reuse of another slot's
    /// identity; verifies the kernel carries the fixed word before
    /// the flip word moves, and that the flip preserved the fixed
    /// words after.
    pub fn flip(&mut self, bank: u64, incarnation: u64) -> anyhow::Result<()> {
        anyhow::ensure!(bank < 2, "bank slot out of range");
        let index = bank as usize;
        anyhow::ensure!(
            self.slot_state[index] == SlotState::Prepared,
            "flipping to unprepared slot {bank}"
        );
        anyhow::ensure!(
            incarnation == self.slot_inc[index],
            "flip publishes incarnation {incarnation} but slot {bank} prepared fixed {}",
            self.slot_inc[index]
        );
        for (slot, seen) in self.slot_inc.iter().enumerate() {
            if slot != index {
                anyhow::ensure!(
                    incarnation != *seen,
                    "incarnation {incarnation} reuses slot {slot} identity"
                );
            }
        }
        let shared = self.loads.get_mut("shared").expect("shared load");
        let current: [u8; BANK_SELECT_SIZE] = shared.array("BANK_SELECT", 0)?;
        let before = decode_select(&current);
        anyhow::ensure!(
            before.fixed[index] == incarnation,
            "slot {bank} fixed incarnation is {}, not the prepared {incarnation}",
            before.fixed[index]
        );
        shared.array_set(
            "BANK_SELECT",
            0,
            flip_select_word(&current, bank, incarnation),
        )?;
        let back: [u8; BANK_SELECT_SIZE] = shared.array("BANK_SELECT", 0)?;
        let after = decode_select(&back);
        anyhow::ensure!(
            after.bank == bank && after.incarnation == incarnation,
            "flip word read back as ({}, {})",
            after.bank,
            after.incarnation
        );
        anyhow::ensure!(
            after.fixed == before.fixed,
            "flip preserved fixed {:?}, read back {:?}",
            before.fixed,
            after.fixed
        );
        for (slot, state) in self.slot_state.iter_mut().enumerate() {
            if slot == index {
                *state = SlotState::Current;
            } else if *state == SlotState::Current {
                *state = SlotState::Retained;
            }
        }
        Ok(())
    }

    /// Closed-zero for a retained slot: its gate drained (no
    /// selected-but-unadmitted call outstanding), no live calls, no
    /// routes. Every in-flight call holds at least one of the
    /// three. Query links in these cells are run-and-done (never
    /// held), so no query or continuation lease can be outstanding
    /// here.
    pub fn closed_zero(&self, slot: u32) -> anyhow::Result<bool> {
        let account = self.account(slot)?;
        let gate = self.gate(slot)?;
        let rows = self.start_rows_for_slot(slot)?;
        Ok(closed_zero_admission(account.live, rows.len(), gate))
    }

    /// Reclaim a retained slot after closed-zero. Single-load cells clear
    /// the array slots; multi-load cells additionally drop the bank load,
    /// so its map objects are gone (A-prime asserts).
    pub fn reclaim(&mut self, slot: u32) -> anyhow::Result<()> {
        let index = slot as usize;
        anyhow::ensure!(
            self.slot_state[index] == SlotState::Retained,
            "reclaiming slot {slot} while {:?}: refused",
            self.slot_state[index]
        );
        anyhow::ensure!(self.closed_zero(slot)?, "slot {slot} not closed-zero");
        {
            // Clear exactly what install_slot set: the other backend's
            // array never held this slot, so deleting it fails ENOENT.
            let owner = self.owner_array();
            let shared = self.loads.get_mut("shared").expect("shared load");
            for array in [owner, "BANK_PROGS_BIRTH"] {
                shared.array_clear(array, slot)?;
            }
        }
        if self.bpffs.is_some() {
            let key = self.slot_load[index].take().expect("bank load key");
            self.loads.remove(&key);
        }
        self.slot_state[index] = SlotState::Reclaimed;
        Ok(())
    }

    /// Attach one bank slot's entry program directly (no dispatcher)
    /// plus the shared return path. N5 leg (b): the dispatcher-off
    /// baseline with identical per-call work (cookie, ticket, seed,
    /// START row, route, completion). The slot entry loads once per
    /// driver in `load_bank_progs` with this driver's backend type,
    /// so this method attaches the already-loaded program without
    /// reloading (Multi links it through a real multi link like
    /// `attach_entry`; Singles through aya attach). The directly
    /// attached entry still releases a gate ref once per call (the
    /// native enter cores release on every path) without a
    /// dispatcher taking them, so the N5 leg pre-takes its run's
    /// releases up front ([`Self::pre_take_gate`]) and asserts the
    /// gate ends back at 0 like every traced leg.
    pub fn attach_direct_entry(&mut self, backend: Backend, slot: u32) -> anyhow::Result<()> {
        anyhow::ensure!(
            backend == self.backend,
            "attaching {backend:?} direct on a {:?} driver: refused (one backend per driver keeps one attach type per program array)",
            self.backend
        );
        anyhow::ensure!(slot < 2, "direct slot {slot} out of range");
        let fixture = self.fixture.clone();
        let entry = Self::entry_prog(slot);
        if backend == Backend::Multi {
            let offset = fixture_symbol_file_offset(&fixture, TARGET_SYMBOL)?;
            let pid =
                crate::attach::multi_link_pid(aya::programs::uprobe::UProbeScope::AllProcesses);
            let prog_fd = {
                let shared = self.loads.get_mut("shared").expect("shared load");
                let probe: &mut aya::programs::UProbe = shared
                    .bpf
                    .program_mut(entry)
                    .ok_or_else(|| anyhow::anyhow!("no such program"))?
                    .try_into()?;
                // No load here: load_bank_progs already loaded this
                // entry once with the driver's type; reloading would
                // fail AlreadyLoaded.
                probe.fd()?.as_fd().as_raw_fd()
            };
            let link = p11scope_bpf_multi::attach_group(
                prog_fd,
                pid,
                &fixture,
                &[offset],
                &[COOKIE_MULTI],
                false,
            )
            .map_err(|error| anyhow::anyhow!("multi link direct entry: {error}"))?;
            self.multi_links.push(link);
            let prog_fd = {
                let shared = self.loads.get_mut("shared").expect("shared load");
                let ret: &mut aya::programs::UProbe = shared
                    .bpf
                    .program_mut("p11_bank_return")
                    .ok_or_else(|| anyhow::anyhow!("no such program"))?
                    .try_into()?;
                ret.load_multi()?;
                ret.fd()?.as_fd().as_raw_fd()
            };
            let link =
                p11scope_bpf_multi::attach_group(prog_fd, pid, &fixture, &[offset], &[0], true)
                    .map_err(|error| anyhow::anyhow!("multi link direct return: {error}"))?;
            self.multi_links.push(link);
            return Ok(());
        }
        let shared = self.loads.get_mut("shared").expect("shared load");
        let probe: &mut aya::programs::UProbe = shared
            .bpf
            .program_mut(entry)
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        // No load here either: the entry is already loaded (see
        // above); aya attaches a link over its fd.
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::Symbol(TARGET_SYMBOL),
            cookie: Some(COOKIE_SINGLES),
        };
        probe.attach(
            [point],
            &fixture,
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )?;
        let ret: &mut aya::programs::UProbe = shared
            .bpf
            .program_mut("p11_bank_return")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        ret.load()?;
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::Symbol(TARGET_SYMBOL),
            cookie: None,
        };
        ret.attach(
            [point],
            &fixture,
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )?;
        Ok(())
    }

    /// Attach the entry dispatcher and the return path for one backend.
    /// Multi loads 48-typed and links through real multi links (the
    /// product's twins do the same: 48 load at `src/attach.rs:5572`,
    /// raw fd at `:3645`, pid at `:3664`, group links at `:6619` over
    /// `p11scope_bpf_multi` with attach_type 48 at
    /// `crates/bpf-multi/src/lib.rs:248`); aya attach would take the
    /// singles perf-event path for these plain sections and fail.
    pub fn attach_entry(&mut self, backend: Backend) -> anyhow::Result<()> {
        anyhow::ensure!(
            backend == self.backend,
            "attaching {backend:?} on a {:?} driver: refused (one backend per driver keeps one attach type per program array)",
            self.backend
        );
        let fixture = self.fixture.clone();
        if backend == Backend::Multi {
            let offset = fixture_symbol_file_offset(&fixture, TARGET_SYMBOL)?;
            let pid =
                crate::attach::multi_link_pid(aya::programs::uprobe::UProbeScope::AllProcesses);
            let prog_fd = {
                let shared = self.loads.get_mut("shared").expect("shared load");
                let probe: &mut aya::programs::UProbe = shared
                    .bpf
                    .program_mut("p11_bank_disp_enter_multi")
                    .ok_or_else(|| anyhow::anyhow!("no such program"))?
                    .try_into()?;
                probe.load_multi()?;
                probe.fd()?.as_fd().as_raw_fd()
            };
            let link = p11scope_bpf_multi::attach_group(
                prog_fd,
                pid,
                &fixture,
                &[offset],
                &[COOKIE_MULTI],
                false,
            )
            .map_err(|error| anyhow::anyhow!("multi link dispatcher: {error}"))?;
            self.multi_links.push(link);
            let prog_fd = {
                let shared = self.loads.get_mut("shared").expect("shared load");
                let ret: &mut aya::programs::UProbe = shared
                    .bpf
                    .program_mut("p11_bank_return")
                    .ok_or_else(|| anyhow::anyhow!("no such program"))?
                    .try_into()?;
                ret.load_multi()?;
                ret.fd()?.as_fd().as_raw_fd()
            };
            let link =
                p11scope_bpf_multi::attach_group(prog_fd, pid, &fixture, &[offset], &[0], true)
                    .map_err(|error| anyhow::anyhow!("multi link return: {error}"))?;
            self.multi_links.push(link);
            return Ok(());
        }
        let shared = self.loads.get_mut("shared").expect("shared load");
        let probe: &mut aya::programs::UProbe = shared
            .bpf
            .program_mut("p11_bank_disp_enter")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        probe.load()?;
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::Symbol(TARGET_SYMBOL),
            cookie: Some(COOKIE_SINGLES),
        };
        probe.attach(
            [point],
            &fixture,
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )?;
        let ret: &mut aya::programs::UProbe = shared
            .bpf
            .program_mut("p11_bank_return")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        ret.load()?;
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::Symbol(TARGET_SYMBOL),
            cookie: None,
        };
        ret.attach(
            [point],
            &fixture,
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )?;
        Ok(())
    }

    /// Attach the directly-attached reference probe (no dispatcher).
    /// Multi loads 48-typed and links through a real multi link (same
    /// product path as the entry dispatcher above).
    pub fn attach_ref(&mut self, backend: Backend, cookie: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            backend == self.backend,
            "attaching {backend:?} ref on a {:?} driver: refused (one backend per driver keeps one attach type per program array)",
            self.backend
        );
        let fixture = self.fixture.clone();
        if backend == Backend::Multi {
            let offset = fixture_symbol_file_offset(&fixture, TARGET_SYMBOL)?;
            let pid =
                crate::attach::multi_link_pid(aya::programs::uprobe::UProbeScope::AllProcesses);
            let prog_fd = {
                let shared = self.loads.get_mut("shared").expect("shared load");
                let probe: &mut aya::programs::UProbe = shared
                    .bpf
                    .program_mut("p11_bank_ref_entry")
                    .ok_or_else(|| anyhow::anyhow!("no such program"))?
                    .try_into()?;
                probe.load_multi()?;
                probe.fd()?.as_fd().as_raw_fd()
            };
            let link = p11scope_bpf_multi::attach_group(
                prog_fd,
                pid,
                &fixture,
                &[offset],
                &[cookie],
                false,
            )
            .map_err(|error| anyhow::anyhow!("multi link ref: {error}"))?;
            self.multi_links.push(link);
            return Ok(());
        }
        let shared = self.loads.get_mut("shared").expect("shared load");
        let probe: &mut aya::programs::UProbe = shared
            .bpf
            .program_mut("p11_bank_ref_entry")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        probe.load()?;
        let point = aya::programs::uprobe::UProbeAttachPoint {
            location: aya::programs::uprobe::UProbeAttachLocation::Symbol(TARGET_SYMBOL),
            cookie: Some(cookie),
        };
        probe.attach(
            [point],
            &fixture,
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )?;
        Ok(())
    }

    /// Attach the birth dispatcher to `task_newtask`.
    pub fn attach_birth(&mut self) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        let probe: &mut aya::programs::BtfTracePoint = shared
            .bpf
            .program_mut("p11_bank_disp_birth")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        let btf = aya::Btf::from_sys_fs()?;
        probe.load("task_newtask", &btf)?;
        probe.attach()?;
        Ok(())
    }

    /// Attach the exec cover to `exec_mm_release`.
    pub fn attach_exec(&mut self) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        let probe: &mut aya::programs::FEntry = shared
            .bpf
            .program_mut("p11_bank_exec_cover")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        let btf = aya::Btf::from_sys_fs()?;
        probe.load("exec_mm_release", &btf)?;
        probe.attach()?;
        Ok(())
    }

    /// Load the query cover in one load (attached fresh for every run).
    /// Multi-load cells load it in the bank load owning the slot under
    /// test: task-storage and continuity maps are per-load, so the
    /// shared load's copies cannot see that slot's cookies.
    pub fn load_query_in(&mut self, key: &str) -> anyhow::Result<()> {
        if self.query_loaded.contains(key) {
            return Ok(());
        }
        let load = self.loads.get_mut(key).expect("query load present");
        let probe: &mut aya::programs::Iter = load
            .bpf
            .program_mut("p11_bank_query_cover")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        let btf = aya::Btf::from_sys_fs()?;
        probe.load("task", &btf)?;
        self.query_loaded.insert(key.to_string());
        Ok(())
    }

    /// Load the query cover in the shared load (single-load cells).
    pub fn load_query(&mut self) -> anyhow::Result<()> {
        self.load_query_in("shared")
    }

    /// Load the query cover in a slot's bank load (multi-load cells).
    pub fn load_query_slot(&mut self, slot: u32) -> anyhow::Result<()> {
        let key = self.bank_load_key(slot).to_string();
        self.load_query_in(&key)
    }

    fn shared(&self) -> &BankLoad {
        self.loads.get("shared").expect("shared load")
    }

    fn bank_load_key(&self, slot: u32) -> &str {
        self.slot_load[slot as usize]
            .as_deref()
            .expect("slot has a bank load")
    }

    /// Read `BANK_SELECT`.
    pub fn select(&self) -> anyhow::Result<BankSelect> {
        Ok(decode_select(&self.shared().array("BANK_SELECT", 0)?))
    }

    /// Read one bank's `BANK_GATE` word (must be zero outside a call).
    pub fn gate(&self, slot: u32) -> anyhow::Result<u64> {
        let raw: [u8; 8] = self.shared().array("BANK_GATE", slot)?;
        Ok(u64::from_ne_bytes(raw))
    }

    /// Pre-take `refs` gate refs on one bank (N5 dispatcher-off leg,
    /// R-47): the directly attached entry releases one ref per call
    /// without a dispatcher taking them, so the leg takes its run's
    /// releases up front and asserts the gate ends back at 0. Never
    /// negative, never wrapped; verified by read-back.
    pub fn pre_take_gate(&mut self, slot: u32, refs: u64) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        shared.array_set("BANK_GATE", slot, refs.to_ne_bytes())?;
        let back: [u8; 8] = shared.array("BANK_GATE", slot)?;
        anyhow::ensure!(
            u64::from_ne_bytes(back) == refs,
            "gate {slot} pre-take read back"
        );
        Ok(())
    }

    /// Read one attribution row (slots 0/1 banks, 2 reference).
    pub fn account(&self, slot: u32) -> anyhow::Result<BankAccount> {
        Ok(decode_account(
            &self.shared().array("IMAGE_BANK_ACCOUNT", slot)?,
        ))
    }

    /// Read one bank's ticket control.
    pub fn control(&self, slot: u32) -> anyhow::Result<BankControl> {
        let name = if slot == 0 {
            "COOKIE_CTL"
        } else {
            "COOKIE_CTL_B"
        };
        let key = self.bank_load_key(slot).to_string();
        let load = self.loads.get(&key).expect("bank load present");
        Ok(decode_control(&load.array(name, 0)?))
    }

    fn start_key(pid_tgid: u64) -> [u8; 16] {
        let mut key = [0u8; 16];
        put_u64(&mut key, 0, pid_tgid);
        key
    }

    /// Read one START row, if present.
    pub fn start_row(&self, pid_tgid: u64) -> anyhow::Result<Option<[u8; START_SIZE]>> {
        self.shared().hash_get("START", &Self::start_key(pid_tgid))
    }

    /// Delete one START row (the N13 omitted-route injection).
    pub fn delete_start_row(&mut self, pid_tgid: u64) -> anyhow::Result<()> {
        let shared = self.loads.get_mut("shared").expect("shared load");
        shared.hash_remove::<16, START_SIZE>("START", &Self::start_key(pid_tgid))
    }

    /// All START rows whose route names `slot` (live calls per bank).
    pub fn start_rows_for_slot(&self, slot: u32) -> anyhow::Result<Vec<(u64, [u8; START_SIZE])>> {
        let map = self.shared().bpf.map("START").expect("START present");
        let hash = aya::maps::HashMap::<_, [u8; 16], [u8; START_SIZE]>::try_from(map)?;
        let mut rows = Vec::new();
        for entry in hash.iter() {
            let (key, value) = entry?;
            let route = u64_at(&value, ROUTE_OFF);
            if route & ROUTE_VALID == 0 {
                continue;
            }
            let bank = if route & ROUTE_BANK == 0 { 0 } else { 1 };
            if bank == slot {
                rows.push((u64_at(&key, 0), value));
            }
        }
        Ok(rows)
    }

    /// Publish query row 0 (this run's bank incarnations) plus requests.
    pub fn query_publish(
        &mut self,
        generation: u64,
        inc_a: u64,
        inc_b: u64,
        requests: &[(u64, u32, u64, u64)],
    ) -> anyhow::Result<()> {
        let mut row0 = [0u8; 24];
        put_u64(&mut row0, 0, 0);
        put_u64(&mut row0, 8, inc_a);
        put_u64(&mut row0, 16, inc_b);
        let shared = self.loads.get_mut("shared").expect("shared load");
        shared.hash_insert("IMAGE_QUERY_REQUESTS", &[0u8; 8], row0)?;
        for (index, (cookie, bank, inc, row)) in requests.iter().enumerate() {
            let _ = index;
            let key = cookie | ((*bank as u64) << 32);
            let slot = (row & ROW_INDEX_MASK)
                | ((*bank as u64) << ROW_BANK_BIT)
                | (inc << ROW_INCARNATION_SHIFT);
            let mut request = [0u8; 24];
            put_u64(&mut request, 0, generation);
            put_u64(&mut request, 8, *cookie);
            put_u64(&mut request, 16, slot);
            shared.hash_insert("IMAGE_QUERY_REQUESTS", &key.to_ne_bytes(), request)?;
        }
        let mut control = [0u8; 56];
        put_u64(&mut control, 0, generation);
        put_u64(&mut control, 8, monotonic_ns()? + 30_000_000_000);
        put_u64(&mut control, 16, 65536);
        put_u64(&mut control, 24, requests.len() as u64);
        shared.array_set("IMAGE_QUERY_CTL", 0, control)?;
        Ok(())
    }

    /// Run the iterator once in one load; returns data plus the END row.
    pub fn query_run_in(&mut self, key: &str) -> anyhow::Result<Vec<QueryRow>> {
        anyhow::ensure!(self.query_loaded.contains(key), "query cover not loaded");
        let load = self.loads.get_mut(key).expect("query load present");
        let probe: &mut aya::programs::Iter = load
            .bpf
            .program_mut("p11_bank_query_cover")
            .ok_or_else(|| anyhow::anyhow!("no such program"))?
            .try_into()?;
        let link_id = probe.attach()?;
        let link = probe.take_link(link_id)?;
        let mut file = link.into_file()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (rows, rest) = bytes.as_chunks::<40>();
        anyhow::ensure!(rest.is_empty(), "query rows are 40 bytes");
        Ok(rows.iter().map(decode_row).collect())
    }

    /// Run the iterator once in the shared load (single-load cells).
    pub fn query_run(&mut self) -> anyhow::Result<Vec<QueryRow>> {
        self.query_run_in("shared")
    }

    /// Run the iterator once in a slot's bank load (multi-load cells).
    pub fn query_run_slot(&mut self, slot: u32) -> anyhow::Result<Vec<QueryRow>> {
        let key = self.bank_load_key(slot).to_string();
        self.query_run_in(&key)
    }

    /// Read back the query control (visits/emitted/failed accounting).
    pub fn query_control(&self) -> anyhow::Result<[u64; 7]> {
        let raw: [u8; 56] = self.shared().array("IMAGE_QUERY_CTL", 0)?;
        Ok([
            u64_at(&raw, 0),
            u64_at(&raw, 8),
            u64_at(&raw, 16),
            u64_at(&raw, 24),
            u64_at(&raw, 32),
            u64_at(&raw, 40),
            u64_at(&raw, 48),
        ])
    }

    /// Kernel map id for A-prime inequality asserts.
    pub fn bank_map_id(&self, slot: u32, name: &str) -> anyhow::Result<u32> {
        let key = self.bank_load_key(slot).to_string();
        self.loads
            .get(&key)
            .expect("bank load present")
            .map_id(name)
    }

    /// Memlock bytes for the shared proof maps (select/gate/arrays/account).
    pub fn shared_memlock(&self) -> anyhow::Result<u64> {
        let mut total = 0;
        for name in [
            "BANK_SELECT",
            "BANK_GATE",
            "BANK_PROGS_SINGLES",
            "BANK_PROGS_MULTI",
            "BANK_PROGS_BIRTH",
            "IMAGE_BANK_ACCOUNT",
        ] {
            total += self.shared().map_memlock(name)?;
        }
        Ok(total)
    }

    /// Count the proof-owned maps in the shared load (N4: exactly 10).
    pub fn proof_map_count(&self) -> usize {
        PROOF_MAP_NAMES
            .iter()
            .filter(|name| self.shared().bpf.map(name).is_some())
            .count()
    }

    /// Run the fixture to completion, capturing stdout.
    pub fn run_simple(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        run_fixture_once(&self.fixture, args)
    }

    /// Spawn the fixture with a piped control channel.
    pub fn spawn_controlled(&self, args: &[&str]) -> anyhow::Result<ControlledChild> {
        let mut child = Command::new(&self.fixture)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(ControlledChild {
            child,
            stdin,
            stdout,
            pending: Vec::new(),
        })
    }
}

impl Drop for BankProofDriver {
    fn drop(&mut self) {
        drop(self.bpffs.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A fixture child with a line-oriented control handshake. Reads time out
/// after 30 seconds so a stuck cell fails loudly instead of hanging.
pub(crate) struct ControlledChild {
    pub child: Child,
    pub stdin: ChildStdin,
    stdout: std::process::ChildStdout,
    pending: Vec<u8>,
}

impl ControlledChild {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn read_line(&mut self, want: &str) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let fd = self.stdout.as_raw_fd();
        loop {
            if let Some(pos) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                anyhow::ensure!(
                    text.trim_end() == want,
                    "fixture said {text:?}, wanted {want:?}"
                );
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .map(|left| left.as_millis().min(30_000) as libc::c_int)
                .unwrap_or(0);
            anyhow::ensure!(remaining > 0, "timed out waiting for fixture line {want:?}");
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll(2) on a live pipe fd with a valid out-struct.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, remaining) };
            anyhow::ensure!(ready >= 0, "polling fixture stdout failed");
            if ready == 0 {
                continue;
            }
            let mut chunk = [0u8; 1024];
            let read = self.stdout.read(&mut chunk)?;
            anyhow::ensure!(read > 0, "fixture stdout closed waiting for {want:?}");
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    pub fn release(&mut self) -> anyhow::Result<()> {
        self.stdin.write_all(b"go\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<std::process::Output> {
        drop(self.stdin);
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_end(&mut stderr);
        }
        let mut stdout = std::mem::take(&mut self.pending);
        let _ = self.stdout.read_to_end(&mut stdout);
        let status = self.child.wait()?;
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }
}

/// Verifier outcome for one root load.
pub(crate) struct RootStats {
    pub name: String,
    pub loaded: bool,
    /// Kernel-impossible (no verifier log, errno-level refusal).
    pub impossible: bool,
    pub reason: String,
    pub verified_insns: Option<u32>,
    pub xlated_len: Option<u32>,
}

/// Verifier-log excerpt for a refusal line: the last 60 lines carry
/// the reason; the head is disassembly context and stays out of the N1
/// line. Short logs pass through whole.
fn verifier_tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let skip = lines.len().saturating_sub(60);
    lines[skip..].join("\n")
}

/// Classify a load failure: kernel-impossible (empty verifier log with
/// an errno-level refusal: unknown attach type on old kernels) versus a
/// genuine verifier refusal (log present). Never a silent skip.
fn classify_load_error(error: &aya::programs::ProgramError) -> (bool, String) {
    if let aya::programs::ProgramError::LoadError {
        io_error,
        verifier_log,
    } = error
    {
        let log = verifier_log.to_string();
        let errno = io_error.raw_os_error().unwrap_or(-1);
        if log.trim().is_empty() && matches!(errno, 22 | 38 | 95) {
            return (
                true,
                format!("kernel-impossible errno={errno} ({io_error})"),
            );
        }
        let excerpt = verifier_tail(&log);
        return (false, format!("verifier refused errno={errno}: {excerpt}"));
    }
    (false, format!("load failed: {error}"))
}

fn load_one_root(bpf: &mut aya::Ebpf, name: &str, multi: bool) -> anyhow::Result<RootStats> {
    let btf;
    let loaded = match name {
        "p11_bank_disp_birth" | "p11_bank_birth_a" | "p11_bank_birth_b" => {
            let probe: &mut aya::programs::BtfTracePoint = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .try_into()?;
            btf = aya::Btf::from_sys_fs()?;
            probe.load("task_newtask", &btf)
        }
        "p11_bank_exec_cover" => {
            let probe: &mut aya::programs::FEntry = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .try_into()?;
            btf = aya::Btf::from_sys_fs()?;
            probe.load("exec_mm_release", &btf)
        }
        "p11_bank_query_cover" => {
            let probe: &mut aya::programs::Iter = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .try_into()?;
            btf = aya::Btf::from_sys_fs()?;
            probe.load("task", &btf)
        }
        _ => {
            let probe: &mut aya::programs::UProbe = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .try_into()?;
            if multi {
                probe.load_multi()
            } else {
                probe.load()
            }
        }
    };
    match loaded {
        Ok(()) => {
            let info = bpf
                .program(name)
                .ok_or_else(|| anyhow::anyhow!("no such program"))?
                .info()?;
            Ok(RootStats {
                name: name.to_string(),
                loaded: true,
                impossible: false,
                reason: "loaded".to_string(),
                verified_insns: info.verified_instruction_count(),
                xlated_len: info.size_translated(),
            })
        }
        Err(error) => {
            let (impossible, reason) = classify_load_error(&error);
            Ok(RootStats {
                name: name.to_string(),
                loaded: false,
                impossible,
                reason,
                verified_insns: None,
                xlated_len: None,
            })
        }
    }
}

/// Static frame-depth upper bound per program: the deepest r10-relative
/// access plus one word, summed over the program and every transitively
/// reachable callee. Sound (the verifier's liveness can only come in
/// under it); load success independently proves the 512-byte ceiling.
/// Callee edges resolve through the real call relocations, and the proof
/// edge shape is asserted for every bank function (silence included, so
/// the pins cannot pass vacuously): each dispatcher root calls exactly
/// the scalar select core (the argument-free release core folds into the
/// root, its frame merging into the measured root frame), each slot and
/// return root calls exactly its core, the reference root is fully
/// inlined, and the only other callees anywhere are the compiler's
/// `memset`. An outlined helper outside that shape fails loudly instead
/// of silently escaping the sum.
fn stack_depths(bytes: &[u8]) -> anyhow::Result<HashMap<String, u32>> {
    let object = aya_obj::Object::parse(bytes)?;
    let mut own: HashMap<String, u32> = HashMap::new();
    for function in object.functions.values() {
        let mut depth = 0u32;
        for insn in &function.instructions {
            let class = insn.code & 7;
            if matches!(class, 0..=3)
                && (insn.dst_reg() == 10 || insn.src_reg() == 10)
                && insn.off < 0
            {
                depth = depth.max((-insn.off as u32) + 8);
            }
        }
        own.insert(function.name.clone(), depth);
    }
    let edges = call_edges(bytes)?;
    let mut callers: Vec<&str> = own
        .keys()
        .filter(|name| name.starts_with("p11_bank_"))
        .map(String::as_str)
        .collect();
    callers.sort_unstable();
    for caller in callers {
        let expected: &[&str] = match caller {
            "p11_bank_disp_enter" | "p11_bank_disp_enter_multi" => &["p11_bank_select"],
            "p11_bank_entry_a" => &["p11_bank_enter_a"],
            "p11_bank_entry_b" => &["p11_bank_enter_b"],
            "p11_bank_return" => &["p11_bank_complete"],
            _ => &[],
        };
        let mut actual: Vec<_> = edges
            .get(caller)
            .map(|callees| {
                callees
                    .iter()
                    .map(String::as_str)
                    .filter(|callee| *callee != "memset")
                    .collect()
            })
            .unwrap_or_default();
        actual.sort_unstable();
        anyhow::ensure!(
            actual == expected,
            "{caller} calls {:?}, expected {expected:?}",
            edges.get(caller).cloned().unwrap_or_default()
        );
    }
    let mut depths = HashMap::new();
    for name in object.programs.keys() {
        let mut depth = own.get(name).copied().unwrap_or(0);
        let mut seen = std::collections::HashSet::new();
        let mut pending: Vec<String> = edges.get(name).cloned().unwrap_or_default();
        while let Some(callee) = pending.pop() {
            if !seen.insert(callee.clone()) {
                continue;
            }
            depth += own.get(&callee).copied().unwrap_or(0);
            pending.extend(edges.get(&callee).cloned().unwrap_or_default());
        }
        depths.insert(name.clone(), depth);
    }
    Ok(depths)
}

fn u16_at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().expect("u16 field"))
}

fn u32_at_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().expect("u32 field"))
}

fn u64_at_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().expect("u64 field"))
}

/// Caller -> callee names through kind-10 call relocations (minimal ELF64
/// parse: symtab plus REL sections only).
fn call_edges(bytes: &[u8]) -> anyhow::Result<HashMap<String, Vec<String>>> {
    anyhow::ensure!(bytes.len() >= 64, "object too small for ELF64");
    anyhow::ensure!(&bytes[0..4] == b"\x7fELF", "not an ELF object");
    let shoff = u64_at_le(bytes, 40) as usize;
    let shentsize = u16_at(bytes, 58) as usize;
    let shnum = u16_at(bytes, 60) as usize;
    anyhow::ensure!(shentsize == 64, "unexpected section header size");
    let header = |index: usize| -> (u32, u32, usize, usize) {
        let at = shoff + index * shentsize;
        (
            u32_at_le(bytes, at),
            u32_at_le(bytes, at + 4),
            u64_at_le(bytes, at + 24) as usize,
            u64_at_le(bytes, at + 32) as usize,
        )
    };
    let mut symtab = None;
    for index in 0..shnum {
        let (_, kind, off, size) = header(index);
        if kind == 2 {
            symtab = Some((off, size));
        }
    }
    let (sym_off, sym_size) = symtab.expect("object has a symtab");
    let mut symbols: Vec<(String, u8, u16, u64, u64)> = Vec::new();
    // Symbol names resolve through the strtab linked from the symtab.
    let mut strtab = None;
    for index in 0..shnum {
        let at = shoff + index * shentsize;
        if u32_at_le(bytes, at + 4) == 2 {
            let link = u32_at_le(bytes, at + 40) as usize;
            let (_, _, off, size) = header(link);
            strtab = Some((off, size));
        }
    }
    let (str_off, str_size) = strtab.expect("symtab links a strtab");
    let symbol_name = |at: usize| -> String {
        let end = bytes[str_off + at..str_off + str_size]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        String::from_utf8_lossy(&bytes[str_off + at..str_off + at + end]).into_owned()
    };
    let mut at = sym_off;
    while at + 24 <= sym_off + sym_size {
        let name = symbol_name(u32_at_le(bytes, at) as usize);
        symbols.push((
            name,
            bytes[at + 4],
            u16_at(bytes, at + 6),
            u64_at_le(bytes, at + 8),
            u64_at_le(bytes, at + 16),
        ));
        at += 24;
    }
    // Function span by (section, offset) so call sites map to callers.
    let mut functions: Vec<(String, u16, u64, u64)> = Vec::new();
    for (name, info, section, value, size) in &symbols {
        if info & 15 == 2 && *size > 0 && !name.is_empty() {
            functions.push((name.clone(), *section, *value, *value + *size));
        }
    }
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    for index in 0..shnum {
        let row = shoff + index * shentsize;
        if u32_at_le(bytes, row + 4) != 9 {
            continue;
        }
        let target_section = u32_at_le(bytes, row + 44) as u16;
        let (_, _, off, size) = header(index);
        let mut pos = off;
        while pos + 16 <= off + size {
            let offset = u64_at_le(bytes, pos);
            let info = u64_at_le(bytes, pos + 8);
            let kind = (info & 0xffff_ffff) as u32;
            let sym = (info >> 32) as usize;
            pos += 16;
            if kind != 10 || sym >= symbols.len() {
                continue;
            }
            let callee = symbols[sym].0.clone();
            if callee.is_empty() {
                continue;
            }
            for (caller, section, start, end) in &functions {
                if *section == target_section && offset >= *start && offset < *end {
                    edges
                        .entry(caller.clone())
                        .or_default()
                        .push(callee.clone());
                    break;
                }
            }
        }
    }
    Ok(edges)
}

/// Function -> referenced map names through kind-1 data relocations
/// (minimal ELF64 parse: section headers plus symtab/strtab, mirroring
/// `call_edges` and the Python object's `map_at`). Each BPF `ld64`
/// map reference relocates against its map symbol; the instruction's
/// 64-bit immediate is the addend into that symbol (zero for the Rust
/// `maps` variables). A reference that does not resolve to exactly
/// one `maps`/`.maps` object is recorded as a `!`-prefixed marker
/// so the census tests fail on it loudly instead of dropping it.
fn map_edges(bytes: &[u8]) -> anyhow::Result<HashMap<String, Vec<String>>> {
    anyhow::ensure!(bytes.len() >= 64, "object too small for ELF64");
    anyhow::ensure!(&bytes[0..4] == b"\x7fELF", "not an ELF object");
    let shoff = u64_at_le(bytes, 40) as usize;
    let shentsize = u16_at(bytes, 58) as usize;
    let shnum = u16_at(bytes, 60) as usize;
    let shstrndx = u16_at(bytes, 62) as usize;
    anyhow::ensure!(shentsize == 64, "unexpected section header size");
    anyhow::ensure!(shstrndx < shnum, "no section name table");
    // (name offset, kind, file offset, size, link, info).
    let header = |index: usize| -> (usize, u32, usize, usize, usize, u32) {
        let at = shoff + index * shentsize;
        (
            u32_at_le(bytes, at) as usize,
            u32_at_le(bytes, at + 4),
            u64_at_le(bytes, at + 24) as usize,
            u64_at_le(bytes, at + 32) as usize,
            u32_at_le(bytes, at + 40) as usize,
            u32_at_le(bytes, at + 44),
        )
    };
    let (_, _, shstr_off, shstr_size, _, _) = header(shstrndx);
    let section_name = |index: usize| -> String {
        let (name_at, _, _, _, _, _) = header(index);
        let end = bytes[shstr_off + name_at..shstr_off + shstr_size]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        String::from_utf8_lossy(&bytes[shstr_off + name_at..shstr_off + name_at + end]).into_owned()
    };
    let mut symtab_index = None;
    for index in 0..shnum {
        let (_, kind, _, _, _, _) = header(index);
        if kind == 2 {
            symtab_index = Some(index);
        }
    }
    let symtab_index = symtab_index.expect("object has a symtab");
    let (_, _, sym_off, sym_size, sym_link, _) = header(symtab_index);
    let (_, _, str_off, str_size, _, _) = header(sym_link);
    let symbol_name = |at: usize| -> String {
        let end = bytes[str_off + at..str_off + str_size]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        String::from_utf8_lossy(&bytes[str_off + at..str_off + at + end]).into_owned()
    };
    // (name, type, section, value, size).
    let mut symbols: Vec<(String, u8, u16, u64, u64)> = Vec::new();
    let mut at = sym_off;
    while at + 24 <= sym_off + sym_size {
        symbols.push((
            symbol_name(u32_at_le(bytes, at) as usize),
            bytes[at + 4],
            u16_at(bytes, at + 6),
            u64_at_le(bytes, at + 8),
            u64_at_le(bytes, at + 16),
        ));
        at += 24;
    }
    // Function span by (section, offset) so reference sites map to owners.
    let mut functions: Vec<(String, u16, u64, u64)> = Vec::new();
    for (name, info, section, value, size) in &symbols {
        if info & 15 == 2 && *size > 0 && !name.is_empty() {
            functions.push((name.clone(), *section, *value, *value + *size));
        }
    }
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    for index in 0..shnum {
        let (_, kind, off, size, link, info) = header(index);
        if kind != 9 {
            continue;
        }
        anyhow::ensure!(
            link == symtab_index,
            "relocation table links a second symtab"
        );
        let target_section = info as u16;
        let (_, _, target_off, target_size, _, _) = header(target_section as usize);
        let mut pos = off;
        while pos + 16 <= off + size {
            let offset = u64_at_le(bytes, pos);
            let reloc = u64_at_le(bytes, pos + 8);
            let rel_kind = (reloc & 0xffff_ffff) as u32;
            let sym = (reloc >> 32) as usize;
            pos += 16;
            if rel_kind != 1 || sym >= symbols.len() {
                continue;
            }
            let (target_name, target_info, target_sym_section, target_value, _) =
                symbols[sym].clone();
            let site = target_off + offset as usize;
            let reference = if target_info & 15 != 1 && target_info & 15 != 3
                || site + 16 > target_off + target_size
            {
                format!("!bad-data-reloc:{target_name}")
            } else {
                let low = u32_at_le(bytes, site + 4) as u64;
                let high = u32_at_le(bytes, site + 12) as u64;
                let addend = (high << 32) | low;
                let found: Vec<String> = symbols
                    .iter()
                    .filter(|(_, info, section, value, _)| {
                        info & 15 == 1
                            && *section == target_sym_section
                            && *value == target_value + addend
                    })
                    .map(|(name, _, _, _, _)| name.clone())
                    .collect();
                if found.len() != 1 {
                    format!("!unresolved:{target_name}+{addend}")
                } else if section_name(target_sym_section as usize) != "maps"
                    && section_name(target_sym_section as usize) != ".maps"
                {
                    format!("!nonmap:{}", found[0])
                } else {
                    found[0].clone()
                }
            };
            for (caller, section, start, end) in &functions {
                if *section == target_section && offset >= *start && offset < *end {
                    edges
                        .entry(caller.clone())
                        .or_default()
                        .push(reference.clone());
                    break;
                }
            }
        }
    }
    Ok(edges)
}

/// Names of the program-array maps in the object (Rust `maps` and BTF
/// `.maps` alike), read from the map definitions rather than the
/// references, so a new array joins the attach-type census unasked.
fn program_array_maps(bytes: &[u8]) -> anyhow::Result<HashSet<String>> {
    let object = aya_obj::Object::parse(bytes)?;
    Ok(object
        .maps
        .iter()
        .filter(|(_, map)| {
            map.map_type() == aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY as u32
        })
        .map(|(name, _)| name.clone())
        .collect())
}

/// One traced N5 run: ns/call with the final reads.
struct N5TracedRun {
    ns_per_call: f64,
    elapsed_ns: u64,
    account: BankAccount,
    control: BankControl,
}

/// One untraced N5 run: ns/call only (no programs, no counts).
struct N5UntracedRun {
    ns_per_call: f64,
    elapsed_ns: u64,
}

/// One traced N5 run (legs b/c): the driver is attached already; run
/// the workload, wait for live-zero, check completeness, then time.
/// Any incomplete run is an error (never a timing from an
/// incomplete run). N5 uses slot 0 only (setup installs A, no cut).
fn n5_run_traced(
    driver: &BankProofDriver,
    args: &[&str],
    label: &str,
) -> anyhow::Result<N5TracedRun> {
    let start = Instant::now();
    let output = driver.run_simple(args)?;
    let elapsed_ns = n5_elapsed_ns(start.elapsed());
    anyhow::ensure!(
        output.status.success(),
        "{label}: fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "DONE"),
        "{label}: fixture printed no DONE"
    );
    let account = n5_poll_live_zero(driver, 0, Duration::from_secs(30))?;
    let control = driver.control(0)?;
    n5_check_counts(N5_CALLS_PER_RUN, &account, &control, 1)
        .map_err(|reason| anyhow::anyhow!("{label}: invalid run ({reason})"))?;
    Ok(N5TracedRun {
        ns_per_call: n5_ns_per_call(elapsed_ns, N5_CALLS_PER_RUN),
        elapsed_ns,
        account,
        control,
    })
}

/// One untraced N5 run (leg a): no BPF anywhere, just the workload.
/// A failed fixture or a missing DONE is an error.
fn n5_run_untraced(tag: &str, args: &[&str]) -> anyhow::Result<N5UntracedRun> {
    let dir = cell_dir(tag)?;
    let fixture = compile_fixture(&dir)?;
    let start = Instant::now();
    let output = run_fixture_once(&fixture, args)?;
    let elapsed_ns = n5_elapsed_ns(start.elapsed());
    anyhow::ensure!(
        output.status.success(),
        "N5 leg a: fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "DONE"),
        "N5 leg a: fixture printed no DONE"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(N5UntracedRun {
        ns_per_call: n5_ns_per_call(elapsed_ns, N5_CALLS_PER_RUN),
        elapsed_ns,
    })
}

/// Bounded live-zero poll for N5 checkpoints: at DONE every return
/// ran, so a healthy bank reads live==0 immediately; the deadline
/// only fires on a stuck live ref. N5 cannot reuse bank_quiescent:
/// one leader makes 1M calls, so admitted != next_ticket by design.
fn n5_poll_live_zero(
    driver: &BankProofDriver,
    slot: u32,
    deadline: Duration,
) -> anyhow::Result<BankAccount> {
    let start = Instant::now();
    loop {
        let account = driver.account(slot)?;
        if account.live == 0 {
            return Ok(account);
        }
        anyhow::ensure!(
            start.elapsed() < deadline,
            "N5 live stuck at {}",
            account.live
        );
        std::thread::sleep(QUIESCE_POLL_STEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Width bits of a stack-memory store to `[r10 - slot]`, if any.
    fn mem_store_width(store: &aya_obj::generated::bpf_insn, slot: i32) -> Option<u8> {
        let class = store.code & 7;
        if !matches!(class, 2 | 3)
            || store.code & 0xe0 != 0x60
            || store.dst_reg() != 10
            || store.off as i32 != -slot
        {
            return None;
        }
        Some(store.code & 0x18)
    }

    fn require_root() {
        // SAFETY: geteuid takes no arguments.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "privileged image-bank cells run as root"
        );
    }

    fn stats_loader(bytes: &[u8]) -> anyhow::Result<aya::Ebpf> {
        Ok(aya::EbpfLoader::new()
            .allow_unsupported_maps()
            .verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS)
            .load(bytes)?)
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N1-N4 verifier/object cells"]
    fn privileged_image_bank_verifier_stats() {
        require_root();
        let bytes = proof_object_bytes().expect("proof object present");
        let mut bpf = stats_loader(&bytes).expect("proof object maps create");
        let mut stats = Vec::new();
        for root in PROOF_ROOTS {
            let stat = load_one_root(&mut bpf, root, false).expect("stat load");
            println!(
                "P11_BANK_N1_{} loaded={} impossible={} reason={} verified={:?} xlated={:?}",
                stat.name,
                stat.loaded,
                stat.impossible,
                stat.reason,
                stat.verified_insns,
                stat.xlated_len
            );
            stats.push(stat);
        }
        for stat in &stats {
            assert!(stat.loaded, "N1 {}: {}", stat.name, stat.reason);
            assert!(
                !stat.impossible,
                "N1 {} impossible: {}",
                stat.name, stat.reason
            );
        }
        let mut multi_bpf = stats_loader(&bytes).expect("multi loader maps create");
        let multi =
            load_one_root(&mut multi_bpf, "p11_bank_disp_enter_multi", true).expect("multi stat");
        println!(
            "P11_BANK_N1_multi loaded={} impossible={} reason={} verified={:?} xlated={:?}",
            multi.loaded, multi.impossible, multi.reason, multi.verified_insns, multi.xlated_len
        );
        if multi.loaded {
            let single = stats
                .iter()
                .find(|stat| stat.name == "p11_bank_disp_enter_multi")
                .unwrap();
            assert_eq!(
                multi.verified_insns, single.verified_insns,
                "N1 multi/singles agree"
            );
            assert_eq!(
                multi.xlated_len, single.xlated_len,
                "N1 multi/singles agree"
            );
        } else {
            assert!(
                multi.impossible,
                "N1 multi refused by verifier: {}",
                multi.reason
            );
            println!("P11_BANK_N1_MULTI_IMPOSSIBLE reason={}", multi.reason);
        }
        // Load-vs-attach split: old kernels ignore the expected attach
        // type for kprobe-type programs at load, so load_multi succeeds
        // everywhere; only the multi link itself is impossible pre-6.6.
        // The product's own functional probe decides, never a version
        // check; its link errno is the recorded evidence.
        match crate::attach::multi_functional_probe() {
            Ok(()) => println!("P11_BANK_N1_multi_attach possible=true"),
            Err(reason) => println!("P11_BANK_N1_MULTI_IMPOSSIBLE reason={reason}"),
        }
        let default_bytes = default_object_bytes().expect("default object present");
        let mut default_bpf = stats_loader(&default_bytes).expect("default maps create");
        let entry = load_one_root(&mut default_bpf, "p11_entry", false).expect("entry stat");
        assert!(entry.loaded, "N2 baseline p11_entry: {}", entry.reason);
        // The ia32 root lives behind `unsafe-unvalidated-metadata`, absent
        // from default objects: record context when present, say so loudly
        // when absent. The N2 gate is the 64-bit p11_entry above.
        if default_bpf.program("p11_entry_ia32").is_some() {
            let ia32 = load_one_root(&mut default_bpf, "p11_entry_ia32", false).expect("ia32 stat");
            assert!(ia32.loaded, "N2 baseline p11_entry_ia32: {}", ia32.reason);
            println!(
                "P11_BANK_N2_baseline entry verified={:?} xlated={:?} ia32 verified={:?} xlated={:?}",
                entry.verified_insns, entry.xlated_len, ia32.verified_insns, ia32.xlated_len
            );
        } else {
            println!("P11_BANK_N1_IA32_ABSENT reason=unsafe-unvalidated-metadata-off");
            println!(
                "P11_BANK_N2_baseline entry verified={:?} xlated={:?} ia32=absent",
                entry.verified_insns, entry.xlated_len
            );
        }
        let release = kernel_release();
        println!(
            "P11_BANK_N2_kernel release={release} has_verified_insns={}",
            kernel_has_verified_insns(&release)
        );
        for stat in &stats {
            match n2_count_gate(&stat.name, stat.verified_insns, &release) {
                Ok(N2Gate::Check(processed)) => {
                    assert!(
                        processed <= 950_000,
                        "N2 {} processed {processed} exceeds 95%",
                        stat.name
                    );
                }
                Ok(N2Gate::LoadOnly) => println!(
                    "N2 {} kernel={release} verifier-count=unavailable load-only",
                    stat.name
                ),
                Err(reason) => panic!("{reason}"),
            }
            println!(
                "P11_BANK_N2_{} verified={:?} xlated={:?}",
                stat.name, stat.verified_insns, stat.xlated_len
            );
        }
        for name in [
            "p11_bank_disp_enter",
            "p11_bank_disp_enter_multi",
            "p11_bank_disp_birth",
        ] {
            let stat = stats.iter().find(|stat| stat.name == name).unwrap();
            match n2_count_gate(name, stat.verified_insns, &release) {
                Ok(N2Gate::Check(processed)) => {
                    assert!(
                        processed <= 5_000,
                        "N2 {name} dispatcher {processed} exceeds 5000"
                    );
                }
                // The per-root loop above already printed this root's
                // named load-only line.
                Ok(N2Gate::LoadOnly) => {}
                Err(reason) => panic!("{reason}"),
            }
        }
        for name in ["p11_bank_entry_a", "p11_bank_entry_b"] {
            let stat = stats.iter().find(|stat| stat.name == name).unwrap();
            match n2_count_gate(name, stat.verified_insns, &release) {
                Ok(N2Gate::Check(_)) => {}
                // The per-root loop above already printed this root's
                // named load-only line; the xlated proxy below is the
                // explicit 5.15 gate for the 110% bound.
                Ok(N2Gate::LoadOnly) => {}
                Err(reason) => panic!("{reason}"),
            }
            match (stat.verified_insns, entry.verified_insns) {
                (Some(processed), Some(baseline)) => {
                    assert!(
                        u64::from(processed) * 100 <= u64::from(baseline) * 110,
                        "N2 {name} {processed} exceeds 110% of p11_entry {baseline}"
                    );
                }
                _ => {
                    let (Some(xlated), Some(baseline)) = (stat.xlated_len, entry.xlated_len) else {
                        panic!("N2 {name}: no verified_insns and no xlated length");
                    };
                    assert!(
                        u64::from(xlated) * 100 <= u64::from(baseline) * 110,
                        "N2 {name} xlated {xlated} exceeds 110% of p11_entry {baseline}"
                    );
                    println!("P11_BANK_N2_{name}_xlated_proxy xlated={xlated} baseline={baseline}");
                }
            }
        }
        let depths = stack_depths(&bytes).expect("stack scan");
        for root in PROOF_ROOTS {
            println!("P11_BANK_N3_{root} chain={}", depths[root]);
        }
        for name in [
            "p11_bank_disp_enter",
            "p11_bank_disp_enter_multi",
            "p11_bank_disp_birth",
        ] {
            assert!(
                depths[name] <= 64,
                "N3 {name} dispatcher chain {} exceeds 64",
                depths[name]
            );
        }
        for name in ["p11_bank_entry_a", "p11_bank_entry_b"] {
            assert!(
                depths[name] <= 448,
                "N3 {name} bank chain {} exceeds 448",
                depths[name]
            );
        }
        for (name, depth) in &depths {
            if name.starts_with("p11_bank_") {
                assert!(*depth <= 512, "N3 {name} chain {depth} exceeds 512");
            }
        }
        let object = aya_obj::Object::parse(&bytes).expect("parse proof object");
        let have: Vec<_> = PROOF_MAP_NAMES
            .iter()
            .filter(|name| object.maps.contains_key(**name))
            .collect();
        assert_eq!(have.len(), 10, "N4 proof maps: {have:?}");
        let start = &object.maps["START"];
        assert_eq!(
            start.value_size(),
            288,
            "N4 START value carries the R0 route"
        );
        assert_eq!(start.key_size(), 16, "N4 START key");
        assert_eq!(start.max_entries(), 16384, "N4 START capacity");
        println!("P11_BANK_N4 maps=10 start_value=288 start_max=16384");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N6 exhaustion and N16 saturation cells"]
    fn privileged_image_bank_exhaustion_16384_then_quota() {
        require_root();
        let driver = BankProofDriver::setup("exhaustion", Backend::Singles).expect("setup");
        let mut driver = driver;
        driver.attach_entry(Backend::Singles).expect("attach entry");
        let before = driver.control(0).expect("control A");
        assert_eq!(before.next_ticket, 0, "N6 bank A starts fresh");
        for batch in 0..4 {
            let output = driver
                .run_simple(&["callfork", "4096"])
                .expect("callfork batch");
            assert!(
                output.status.success(),
                "N6 callfork batch {batch}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // Bounded quiescence poll: every fixture task is reaped above,
        // so a healthy bank is quiescent on the first read; a stuck
        // live ref or uncounted shortfall fails after the deadline,
        // never passes through the wait.
        let ((account, after), quiesced) = poll_bank_until_quiescent(
            || {
                (
                    driver.account(0).expect("account A"),
                    driver.control(0).expect("control A"),
                )
            },
            Duration::from_secs(30),
        );
        println!(
            "P11_BANK_N6 next={} unavailable={} create_failures={} retry_exhausted={} admitted={} completed={} live={}",
            after.next_ticket,
            after.unavailable,
            after.create_failures,
            after.retry_exhausted,
            account.admitted,
            account.completed,
            account.live
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=A cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            account.cookie_failures,
            account.seed_failures,
            account.start_present,
            account.start_insert_failures,
            account.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        println!(
            "P11_BANK_N6_quiesce quiesced={quiesced} gate0={} gate1={} start_rows={}",
            driver.gate(0).expect("gate A"),
            driver.gate(1).expect("gate B"),
            driver.start_rows_for_slot(0).expect("scan START").len()
        );
        assert_eq!(after.next_ticket, 16384, "N6 A.next_ticket reaches 16,384");
        assert_eq!(after.retry_exhausted, 0, "N6 no retry exhaustion");
        assert_eq!(
            ledger_with_all_burns(account.admitted, after.create_failures, &account),
            16384,
            "N6 successful + burned = 16,384"
        );
        assert_eq!(
            account.cookie_failures, after.create_failures,
            "N6 cookie burns are exactly the control-counted creation failures"
        );
        fresh_bank_admission_clean("A", &account).expect("N6 fresh bank admits clean");
        assert_eq!(
            account.completed, account.admitted,
            "N6 every admission completes"
        );
        assert_eq!(account.live, 0, "N6 nothing held");
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N6 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N6 gate B balanced");
        let output = driver
            .run_simple(&["callfork", "1"])
            .expect("16385th leader");
        assert!(
            output.status.success(),
            "N6 16385th: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let quota = driver.control(0).expect("control A");
        let quota_account = driver.account(0).expect("account A");
        println!(
            "P11_BANK_N6_quota next={} unavailable={} admitted={}",
            quota.next_ticket, quota.unavailable, quota_account.admitted
        );
        assert_eq!(quota.next_ticket, 16384, "N6 quota consumes no ticket");
        assert_eq!(
            quota.unavailable,
            after.unavailable + 1,
            "N6 unavailable +1"
        );
        assert_eq!(
            quota_account.admitted, account.admitted,
            "N6 quota admits nothing"
        );
        assert!(
            driver
                .start_rows_for_slot(0)
                .expect("scan START")
                .is_empty(),
            "N6 no record claims one"
        );
        fresh_bank_admission_clean("A", &quota_account).expect("N6 quota refuses clean");
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N6 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N6 gate B balanced");
        // N16: burst past H before the flip completes yields counted QUOTA
        // refusals, never silent loss or identity claims without a ticket.
        driver.prepare(1).expect("prepare B");
        let output = driver
            .run_simple(&["callfork", "2048"])
            .expect("saturation burst");
        assert!(
            output.status.success(),
            "N16 burst: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let saturated = driver.control(0).expect("control A");
        let saturated_account = driver.account(0).expect("account A");
        println!(
            "P11_BANK_N16 next={} unavailable={} admitted={}",
            saturated.next_ticket, saturated.unavailable, saturated_account.admitted
        );
        assert_eq!(saturated.next_ticket, 16384, "N16 burst consumes no ticket");
        assert_eq!(
            saturated.unavailable,
            quota.unavailable + 2048,
            "N16 unavailable delta = refused count"
        );
        assert_eq!(
            saturated_account.admitted, account.admitted,
            "N16 burst admits nothing"
        );
        assert!(
            driver
                .start_rows_for_slot(0)
                .expect("scan START")
                .is_empty(),
            "N16 no record claims one"
        );
        fresh_bank_admission_clean("A", &saturated_account).expect("N16 burst refuses clean");
        driver.flip(1, 2).expect("flip to B");
        let output = driver
            .run_simple(&["callfork", "1"])
            .expect("first B leader");
        assert!(
            output.status.success(),
            "N16 B: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bank_b = driver.control(1).expect("control B");
        assert_eq!(bank_b.next_ticket, 1, "N16 B serves after the flip");
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N16 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N16 gate B balanced");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N7 cut cell with 16,385 leaders"]
    fn privileged_image_bank_cut_16385th_leader_in_b() {
        require_root();
        let mut driver = BankProofDriver::setup("cut", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        for batch in 0..3 {
            let output = driver
                .run_simple(&["callfork", "5120"])
                .expect("trigger fill batch");
            assert!(
                output.status.success(),
                "N7 trigger fill batch {batch}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            driver.control(0).expect("control A").next_ticket,
            CUT_TRIGGER,
            "N7 trigger at LIMIT - H"
        );
        driver.prepare(1).expect("prepare B at trigger");
        let output = driver
            .run_simple(&["callfork", "1023"])
            .expect("fill to 16383");
        assert!(
            output.status.success(),
            "N7 top-up: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            driver.control(0).expect("control A").next_ticket,
            16383,
            "N7 A at 16,383"
        );
        let mut held = driver
            .spawn_controlled(&["hold"])
            .expect("spawn held A call");
        held.read_line("ENTERED").expect("held call entered");
        assert_eq!(
            driver.control(0).expect("control A").next_ticket,
            16384,
            "N7 held call takes A ticket 16,384"
        );
        let frozen = driver.control(0).expect("control A");
        let frozen_account = driver.account(0).expect("account A");
        driver.flip(1, 2).expect("flip to B");
        let select = driver.select().expect("select");
        assert_eq!(
            (select.bank, select.incarnation),
            (1, 2),
            "N7 SELECT names B incarnation 2"
        );
        let output = driver
            .run_simple(&["callfork", "1"])
            .expect("16385th leader");
        assert!(
            output.status.success(),
            "N7 16385th: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bank_b = driver.control(1).expect("control B");
        let account_b = driver.account(1).expect("account B");
        println!(
            "P11_BANK_N7 b_next={} b_admitted={} a_next={} a_admitted={} a_completed={}",
            bank_b.next_ticket,
            account_b.admitted,
            frozen.next_ticket,
            frozen_account.admitted,
            frozen_account.completed
        );
        assert_eq!(
            bank_b.next_ticket, 1,
            "N7 first allocation after the cut is B ticket 1"
        );
        assert_eq!(account_b.admitted, 1, "N7 leader 16,385 holds a B identity");
        let check = driver.control(0).expect("control A");
        assert_eq!(
            check.next_ticket, frozen.next_ticket,
            "N7 A.next_ticket unchanged"
        );
        assert_eq!(
            check.unavailable, frozen.unavailable,
            "N7 A unavailable frozen"
        );
        assert_eq!(
            check.create_failures, frozen.create_failures,
            "N7 A failures frozen"
        );
        let check_account = driver.account(0).expect("account A");
        assert_eq!(
            check_account.admitted, frozen_account.admitted,
            "N7 A admissions frozen"
        );
        assert_eq!(
            check_account.completed, frozen_account.completed,
            "N7 A completions frozen pre-release"
        );
        held.release().expect("release held A call");
        let output = held.finish().expect("held call exits");
        assert!(
            output.status.success(),
            "N7 held: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let released = driver.account(0).expect("account A");
        assert_eq!(
            released.completed,
            frozen_account.completed + 1,
            "N7 held return completes through its A route"
        );
        assert_eq!(released.live, 0, "N7 A live back to zero");
        let final_a = driver.account(0).expect("account A");
        let final_b = driver.account(1).expect("account B");
        let burns_a = driver.control(0).expect("control A").create_failures;
        let burns_b = driver.control(1).expect("control B").create_failures;
        println!("P11_BANK_N7_burns a={burns_a} b={burns_b}");
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=A cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_a.cookie_failures,
            final_a.seed_failures,
            final_a.start_present,
            final_a.start_insert_failures,
            final_a.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=B cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_b.cookie_failures,
            final_b.seed_failures,
            final_b.start_present,
            final_b.start_insert_failures,
            final_b.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        assert_eq!(
            ledger_with_all_burns(final_a.admitted, burns_a, &final_a)
                + ledger_with_all_burns(final_b.admitted, burns_b, &final_b),
            16385,
            "N7 bank counts plus counted burns sum to ledger calls"
        );
        assert_eq!(
            final_a.cookie_failures, burns_a,
            "N7 A cookie burns are exactly the control-counted creation failures"
        );
        assert_eq!(
            final_b.cookie_failures, burns_b,
            "N7 B cookie burns are exactly the control-counted creation failures"
        );
        fresh_bank_admission_clean("A", &final_a).expect("N7 A admits clean");
        fresh_bank_admission_clean("B", &final_b).expect("N7 B admits clean");
        assert_eq!(
            final_a.completed + final_b.completed,
            final_a.admitted + final_b.admitted,
            "N7 every admission completes"
        );
        assert_eq!(
            driver.select().expect("SELECT").fixed,
            [1, 2],
            "N7 fixed incarnations ride SELECT"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N7 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N7 gate B balanced");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N8 concurrent cut counting cell"]
    fn privileged_image_bank_concurrent_cut_counts_once() {
        require_root();
        let multi_possible = crate::attach::multi_functional_probe().is_ok();
        let release = kernel_release();
        let exact = n8_requires_exact_count(multi_possible);
        println!(
            "P11_BANK_N8_class multi_possible={multi_possible} kernel={release} verdict={}",
            if exact { "exact" } else { "conservation" }
        );
        let mut driver = BankProofDriver::setup("concurrent", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        driver.prepare(1).expect("prepare B");
        let mut workers = driver
            .spawn_controlled(&["threads", "4", "10000"])
            .expect("spawn workers");
        workers
            .read_line("HALF")
            .expect("workers reach the barrier");
        let half_a = driver.account(0).expect("account A");
        let half_b = driver.account(1).expect("account B");
        let half_ctl_a = driver.control(0).expect("control A");
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=A cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            half_a.cookie_failures,
            half_a.seed_failures,
            half_a.start_present,
            half_a.start_insert_failures,
            half_a.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=B cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            half_b.cookie_failures,
            half_b.seed_failures,
            half_b.start_present,
            half_b.start_insert_failures,
            half_b.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        if let Some(reason) = n8_capacity_failure("A", "first-half", &half_a, &half_ctl_a) {
            panic!("{reason}");
        }
        let half_failures = counted_admission_failures(&half_a);
        if exact {
            assert_eq!(
                half_a.admitted, 20000,
                "N8 first half exact on A (Multi kernel)"
            );
            assert_eq!(
                half_failures, 0,
                "N8 first half zero counted failures on A (Multi kernel)"
            );
        } else {
            assert!(
                admission_conserved(&half_a, 20000),
                "N8 first half conserved on A: admitted={} failures={half_failures} != 20000 calls (silent admission loss)",
                half_a.admitted
            );
            if half_failures == 0 {
                assert_eq!(half_a.admitted, 20000, "N8 first half exact on A");
            }
        }
        assert_eq!(
            half_a.completed, half_a.admitted,
            "N8 first-half completions match admissions on A"
        );
        assert_eq!(half_b.admitted, 0, "N8 B admits nothing before the cut");
        assert_eq!(
            counted_admission_failures(&half_b),
            0,
            "N8 B refuses nothing before the cut"
        );
        driver.flip(1, 2).expect("cut mid-run");
        for _ in 0..4 {
            workers.release().expect("release one thread");
        }
        let output = workers.finish().expect("workers exit");
        assert!(
            output.status.success(),
            "N8 workers: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let final_a = driver.account(0).expect("account A");
        let final_b = driver.account(1).expect("account B");
        let final_ctl_a = driver.control(0).expect("control A");
        let final_ctl_b = driver.control(1).expect("control B");
        println!(
            "P11_BANK_N8 a_admitted={} a_completed={} b_admitted={} b_completed={} a_live={} b_live={}",
            final_a.admitted,
            final_a.completed,
            final_b.admitted,
            final_b.completed,
            final_a.live,
            final_b.live
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=A cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_a.cookie_failures,
            final_a.seed_failures,
            final_a.start_present,
            final_a.start_insert_failures,
            final_a.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=B cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_b.cookie_failures,
            final_b.seed_failures,
            final_b.start_present,
            final_b.start_insert_failures,
            final_b.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        if let Some(reason) = n8_capacity_failure("A", "final", &final_a, &final_ctl_a) {
            panic!("{reason}");
        }
        if let Some(reason) = n8_capacity_failure("B", "final", &final_b, &final_ctl_b) {
            panic!("{reason}");
        }
        let fail_a = counted_admission_failures(&final_a);
        let fail_b = counted_admission_failures(&final_b);
        if exact {
            assert_eq!(
                final_a.admitted, 20000,
                "N8 A keeps exactly its half (Multi kernel)"
            );
            assert_eq!(fail_a, 0, "N8 A zero counted failures (Multi kernel)");
            assert_eq!(
                final_b.admitted, 20000,
                "N8 B takes exactly its half (Multi kernel)"
            );
            assert_eq!(fail_b, 0, "N8 B zero counted failures (Multi kernel)");
            assert_eq!(
                final_a.admitted + final_b.admitted,
                40000,
                "N8 exactly 40,000 admitted (Multi kernel)"
            );
        } else {
            assert!(
                admission_conserved(&final_a, 20000),
                "N8 A half conserved: admitted={} failures={fail_a} != 20000 calls (silent admission loss)",
                final_a.admitted
            );
            assert!(
                admission_conserved(&final_b, 20000),
                "N8 B half conserved: admitted={} failures={fail_b} != 20000 calls (silent admission loss)",
                final_b.admitted
            );
            if fail_a == 0 {
                assert_eq!(final_a.admitted, 20000, "N8 A keeps exactly its half");
            }
            if fail_b == 0 {
                assert_eq!(final_b.admitted, 20000, "N8 B takes exactly its half");
            }
            assert_eq!(
                final_a.admitted + fail_a + final_b.admitted + fail_b,
                40000,
                "N8 all 40,000 calls accounted exactly once"
            );
        }
        assert_eq!(
            final_a.completed, final_a.admitted,
            "N8 A completions match admissions"
        );
        assert_eq!(
            final_b.completed, final_b.admitted,
            "N8 B completions match admissions"
        );
        assert_eq!(
            final_a.live + final_b.live,
            0,
            "N8 nothing accepted-but-uncounted"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N8 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N8 gate B balanced");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N9 held-return-across-cut cell"]
    fn privileged_image_bank_held_return_across_cut() {
        require_root();
        let mut driver = BankProofDriver::setup("held", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        let mut held = driver.spawn_controlled(&["hold"]).expect("spawn held call");
        held.read_line("ENTERED").expect("held call entered");
        let live = driver.account(0).expect("account A");
        assert_eq!(live.admitted, 1, "N9 held call admitted on A");
        assert_eq!(live.live, 1, "N9 held call live on A");
        let pid = held.pid() as u64;
        let row = driver
            .start_row((pid << 32) | pid)
            .expect("held START row")
            .expect("row present");
        let route = u64_at(&row, ROUTE_OFF);
        println!(
            "P11_BANK_N9_route route={route:#x} marker={} cookie={} exec={}",
            u64_at(&row, MARKER_OFF),
            u64_at(&row, COOKIE_OFF),
            u64_at(&row, EXEC_OFF)
        );
        assert_eq!(route & ROUTE_VALID, ROUTE_VALID, "N9 route valid");
        assert_eq!(route & ROUTE_BANK, 0, "N9 route names bank A");
        assert_eq!(route & ROUTE_INC_MASK, 1, "N9 route names incarnation 1");
        assert_eq!(u64_at(&row, MARKER_OFF), 0, "N9 marker zero");
        assert_eq!(u64_at(&row, COOKIE_OFF), 1, "N9 row carries ticket 1");
        assert_ne!(u64_at(&row, EXEC_OFF), 0, "N9 row carries live exec id");
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("cut under the held call");
        assert!(
            !driver.closed_zero(0).expect("closed-zero check"),
            "N9 A not closed-zero while held"
        );
        assert!(
            driver.reclaim(0).is_err(),
            "N9 A not reclaimable while held"
        );
        held.release().expect("release held call");
        let output = held.finish().expect("held call exits");
        assert!(
            output.status.success(),
            "N9 held: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let done = driver.account(0).expect("account A");
        println!(
            "P11_BANK_N9 admitted={} completed={} live={}",
            done.admitted, done.completed, done.live
        );
        assert_eq!(
            done.completed, 1,
            "N9 held return completes through its A route"
        );
        assert_eq!(done.live, 0, "N9 A live back to zero");
        assert!(
            driver.closed_zero(0).expect("closed-zero check"),
            "N9 release reaches closed-zero"
        );
        driver.reclaim(0).expect("reclaim A after release");
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N9 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N9 gate B balanced");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N10 late-incarnation refusal cell"]
    fn privileged_image_bank_late_incarnation_refused() {
        require_root();
        let mut driver = BankProofDriver::setup_shared("late", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        let output = driver.run_simple(&["callfork", "2"]).expect("A tickets");
        assert!(
            output.status.success(),
            "N10 A: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        let output = driver.run_simple(&["callfork", "1"]).expect("B ticket");
        assert!(
            output.status.success(),
            "N10 B: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        driver.reclaim(0).expect("reclaim A");
        driver.prepare(0).expect("prepare A-prime");
        driver.flip(0, 3).expect("flip to A-prime");
        // The query runs in the A-prime load: only its task-storage
        // and continuity maps hold the holder's cookie.
        driver.load_query_slot(0).expect("load query in A-prime");
        // The A-prime ticket holder stays alive (held call): the cover can
        // only match requests against live tasks.
        let mut holder = driver
            .spawn_controlled(&["hold"])
            .expect("spawn A-prime holder");
        holder.read_line("ENTERED").expect("holder entered");
        assert_eq!(
            driver.control(0).expect("control A-prime").next_ticket,
            1,
            "N10 A-prime ticket 1 issued"
        );
        // Stale run: A-incarnation request against the A-prime slot refuses.
        let before_control = driver.control(0).expect("control A-prime");
        let before_account = driver.account(0).expect("account A-prime");
        driver
            .query_publish(1, 3, 2, &[(1, 0, 1, 0)])
            .expect("publish stale request");
        let rows = driver.query_run_slot(0).expect("stale query run");
        let faults = driver.account(0).expect("account A-prime").faults;
        let control = driver.query_control().expect("query control");
        println!(
            "P11_BANK_N10_stale rows={} faults={faults:#x} failed={}",
            rows.len(),
            control[6]
        );
        assert!(rows.is_empty(), "N10 stale run emits no row");
        assert_eq!(control[6], 1, "N10 stale run marks coverage failed");
        assert_eq!(faults & 1, 1, "N10 incarnation mismatch fault recorded");
        let after_control = driver.control(0).expect("control A-prime");
        let after_account = driver.account(0).expect("account A-prime");
        assert_eq!(
            after_control, before_control,
            "N10 zero successor mutations (control)"
        );
        assert_eq!(
            after_account.admitted, before_account.admitted,
            "N10 zero successor mutations (admitted)"
        );
        assert_eq!(
            after_account.completed, before_account.completed,
            "N10 zero successor mutations (completed)"
        );
        assert_eq!(
            after_account.live, before_account.live,
            "N10 zero successor mutations (live)"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N10 ref A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N10 ref B balanced");
        // Fresh twin: the current incarnation joins.
        driver
            .query_publish(2, 3, 2, &[(1, 0, 3, 0)])
            .expect("publish fresh request");
        let rows = driver.query_run_slot(0).expect("fresh query run");
        let control = driver.query_control().expect("query control");
        println!(
            "P11_BANK_N10_fresh rows={} failed={}",
            rows.len(),
            control[6]
        );
        assert_eq!(rows.len(), 2, "N10 fresh run emits data plus END");
        assert_eq!(
            rows[0].status, ROW_STATUS_READY,
            "N10 fresh request joins READY"
        );
        assert_eq!(rows[0].cookie, 1, "N10 fresh row names A-prime ticket 1");
        assert_eq!(
            rows[0].slot,
            (3 << ROW_INCARNATION_SHIFT) as u32,
            "N10 fresh row carries incarnation 3"
        );
        assert_eq!(control[6], 0, "N10 fresh run covers");
        holder.release().expect("release holder");
        let output = holder.finish().expect("holder exits");
        assert!(
            output.status.success(),
            "N10 holder: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N11 failure-modes cell"]
    fn privileged_image_bank_failure_modes_refuse_and_balance() {
        require_root();
        let mut driver = BankProofDriver::setup("failure", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        // Tail-call failure releases exactly its refs and admits nothing.
        let before = driver.account(0).expect("account A");
        let before_control = driver.control(0).expect("control A");
        driver
            .clear_array("BANK_PROGS_SINGLES", 0)
            .expect("clear slot A");
        let output = driver
            .run_simple(&["call", "5"])
            .expect("calls through empty slot");
        assert!(
            output.status.success(),
            "N11 tailfail: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let failed = driver.account(0).expect("account A");
        let failed_control = driver.control(0).expect("control A");
        println!(
            "P11_BANK_N11_tailfail admitted={} gate0={} gate1={} unavailable={}",
            failed.admitted,
            driver.gate(0).expect("gate A"),
            driver.gate(1).expect("gate B"),
            failed_control.unavailable
        );
        assert_eq!(
            failed.admitted, before.admitted,
            "N11 failed tail call admits nothing"
        );
        assert_eq!(
            failed_control.next_ticket, before_control.next_ticket,
            "N11 failed tail call mints nothing"
        );
        assert_eq!(
            failed_control.unavailable, before_control.unavailable,
            "N11 failed tail call refuses nothing"
        );
        assert_eq!(
            driver.gate(0).expect("gate A"),
            0,
            "N11 failed tail call releases its A ref"
        );
        assert_eq!(
            driver.gate(1).expect("gate B"),
            0,
            "N11 failed tail call touches no B ref"
        );
        driver.reinstall(0).expect("restore slot A");
        let output = driver
            .run_simple(&["call", "1"])
            .expect("call after restore");
        assert!(
            output.status.success(),
            "N11 restore: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            driver.account(0).expect("account A").admitted,
            before.admitted + 1,
            "N11 slot works after restore"
        );
        // Third preparation while A is retained refuses; A stays intact.
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        let retained = driver.control(0).expect("control A");
        assert!(
            driver.prepare(0).is_err(),
            "N11 third preparation while A retained refuses"
        );
        let intact = driver.control(0).expect("control A");
        assert_eq!(intact, retained, "N11 refused preparation leaves A intact");
        let output = driver.run_simple(&["callfork", "1"]).expect("B serves");
        assert!(
            output.status.success(),
            "N11 B: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            driver.control(1).expect("control B").next_ticket,
            1,
            "N11 B usable after refusal"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N11 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N11 gate B balanced");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N12 fork-burn and N4 memlock cells"]
    fn privileged_image_bank_fork_burn_sentinel() {
        require_root();
        let mut driver = BankProofDriver::setup("forkburn", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        driver.attach_birth().expect("attach birth");
        // Sentinel phase 1: exact counts before the burn.
        let output = driver
            .run_simple(&["call", "100"])
            .expect("sentinel phase 1");
        assert!(
            output.status.success(),
            "N12 sentinel 1: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let phase1 = driver.account(0).expect("account A");
        assert_eq!(
            (phase1.admitted, phase1.completed),
            (100, 100),
            "N12 sentinel exact before burn"
        );
        // Birth spends install usable identity: the next leader's call
        // reuses its birth ticket instead of minting. Every fork is a
        // birth, including the fixture runner of the phase itself.
        let spent = driver.control(0).expect("control A").next_ticket;
        let output = driver
            .run_simple(&["fork", "100"])
            .expect("spend 100 births");
        assert!(
            output.status.success(),
            "N12 spend: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed = driver.control(0).expect("control A").next_ticket;
        let ambient = ambient_births(observed - spent, 101)
            .expect("N12 fork 100: test-owned births missing during the window");
        println!("P11_BANK_AMBIENT births={ambient} phase=fork100");
        let after_fork = observed;
        assert_eq!(
            after_fork,
            spent + 101 + ambient,
            "N12 births spend tickets plus ambient"
        );
        let output = driver.run_simple(&["callfork", "1"]).expect("reuse check");
        assert!(
            output.status.success(),
            "N12 reuse: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed = driver.control(0).expect("control A").next_ticket;
        let ambient = ambient_births(observed - after_fork, 2)
            .expect("N12 callfork 1: test-owned births missing during the window");
        println!("P11_BANK_AMBIENT births={ambient} phase=callfork1");
        assert_eq!(
            observed,
            fork_birth_tickets(after_fork, 1) + ambient,
            "N12 birth-installed ticket reused by the call, plus ambient"
        );
        // The burn: 17,000 more births saturate A and trigger the cut.
        for batch in 0..4 {
            let output = driver
                .run_simple(&["fork", "4250"])
                .expect("fork burn batch");
            assert!(
                output.status.success(),
                "N12 burn batch {batch}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let burned = driver.control(0).expect("control A");
        println!(
            "P11_BANK_N12 next={} unavailable={} create_failures={} retry_exhausted={}",
            burned.next_ticket, burned.unavailable, burned.create_failures, burned.retry_exhausted
        );
        assert_eq!(burned.next_ticket, 16384, "N12 births saturate A");
        assert_eq!(burned.retry_exhausted, 0, "N12 no retry exhaustion");
        // Sentinel phase 2: quota refusals counted exactly through saturation.
        let unavailable_before = burned.unavailable;
        let output = driver
            .run_simple(&["call", "100"])
            .expect("sentinel phase 2");
        assert!(
            output.status.success(),
            "N12 sentinel 2: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let phase2 = driver.control(0).expect("control A");
        assert_eq!(phase2.next_ticket, 16384, "N12 saturated admits nothing");
        let ambient = ambient_births(phase2.unavailable - unavailable_before, 101)
            .expect("N12 call 100: test-owned quota refusals missing during the window");
        println!("P11_BANK_AMBIENT births={ambient} phase=call100quota");
        assert_eq!(
            phase2.unavailable,
            quota_unavailable_after(unavailable_before, 100) + ambient,
            "N12 sentinel quota exact through saturation, plus ambient"
        );
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("cut after burn");
        // Sentinel phase 3: exact counts on the new bank. The birth
        // hook stays attached across the cut, so ambient forks during
        // this window spend B tickets; count them like the other N12
        // phases, with test-owned exact and a named stop on shortfall.
        let output = driver
            .run_simple(&["call", "100"])
            .expect("sentinel phase 3");
        assert!(
            output.status.success(),
            "N12 sentinel 3: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let phase3 = driver.account(1).expect("account B");
        assert_eq!(
            (phase3.admitted, phase3.completed),
            (100, 100),
            "N12 sentinel exact after cut"
        );
        let b_next = driver.control(1).expect("control B").next_ticket;
        let ambient = ambient_births(b_next, 1)
            .expect("N12 sentinel 3: test-owned B birth missing during the window");
        println!("P11_BANK_AMBIENT births={ambient} phase=sentinel3");
        assert_eq!(
            b_next,
            1 + ambient,
            "N12 one B ticket for one sentinel leader, plus ambient"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N12 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N12 gate B balanced");
        drop(driver);
        // N4 memlock at worst state: both banks seeded full at 16,384.
        let mut driver =
            BankProofDriver::setup("memlock", Backend::Singles).expect("memlock setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        assert_eq!(
            driver.proof_map_count(),
            10,
            "N4 exactly 10 added maps under R0"
        );
        for batch in 0..4 {
            let output = driver
                .run_simple(&["callfork", "4096"])
                .expect("seed bank A batch");
            assert!(
                output.status.success(),
                "N4 seed A batch {batch}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            driver.control(0).expect("control A").next_ticket,
            16384,
            "N4 A full"
        );
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        for batch in 0..4 {
            let output = driver
                .run_simple(&["callfork", "4096"])
                .expect("seed bank B batch");
            assert!(
                output.status.success(),
                "N4 seed B batch {batch}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            driver.control(1).expect("control B").next_ticket,
            16384,
            "N4 B full"
        );
        let shared = driver.loads.get("shared").expect("shared load");
        let continuity_b = shared
            .map_memlock("IMAGE_CONTINUITY_B")
            .expect("continuity memlock");
        let tgid_b = shared
            .map_memlock("IMAGE_TGID_INDEX_B")
            .expect("tgid memlock");
        let cookie_b = shared.map_memlock("TASK_COOKIE_B").expect("cookie memlock");
        let ctl_b = shared.map_memlock("COOKIE_CTL_B").expect("ctl memlock");
        let small = driver.shared_memlock().expect("shared memlock");
        let start = shared.map_memlock("START").expect("START memlock");
        println!(
            "P11_BANK_N4 continuity_b={continuity_b} tgid_b={tgid_b} cookie_b={cookie_b} ctl_b={ctl_b} small={small} start={start}"
        );
        let release = kernel_release();
        let tables = continuity_b + tgid_b;
        let tables_budget = n4_second_bank_tables_budget();
        if kernel_reports_htab_usage(&release) {
            let tables_floor = n4_second_bank_tables_floor();
            assert!(
                n4_tables_within_band(tables),
                "N4 second-bank tables within plan 3145728 +-5%: {tables} not in [{tables_floor}, {tables_budget}]"
            );
        } else {
            println!(
                "P11_BANK_N4_static_accounting kernel={release} note=fdinfo-reports-bpf_map_memory_footprint-static-footprint-far-under-htab-usage upper-bound-only"
            );
            assert!(
                tables <= tables_budget,
                "N4 second-bank tables fit plan 3145728 within 5%: {continuity_b} + {tgid_b} <= {tables_budget}"
            );
        }
        assert!(
            cookie_b + ctl_b + small <= 2 * 262144 + 65536,
            "N4 rest fits 2x262144 + headroom: {cookie_b} + {ctl_b} + {small}"
        );
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N11 second-rollover cell"]
    fn privileged_image_bank_second_rollover() {
        require_root();
        let mut driver =
            BankProofDriver::setup_shared("rollover2", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        let output = driver.run_simple(&["callfork", "5"]).expect("A tickets");
        assert!(
            output.status.success(),
            "A-prime A: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ids_a = [
            driver.bank_map_id(0, "TASK_COOKIE").expect("A cookie id"),
            driver.bank_map_id(0, "COOKIE_CTL").expect("A ctl id"),
            driver
                .bank_map_id(0, "IMAGE_CONTINUITY")
                .expect("A continuity id"),
            driver
                .bank_map_id(0, "IMAGE_TGID_INDEX")
                .expect("A index id"),
        ];
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        let output = driver.run_simple(&["callfork", "3"]).expect("B tickets");
        assert!(
            output.status.success(),
            "A-prime B: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        driver.reclaim(0).expect("reclaim A");
        // Kernel-side teardown of the dropped load (program-array slot
        // release, program unload) can lag the last FD close by an RCU
        // grace period, so the disappearance check polls briefly. The
        // requirement stays exact: every A map must be gone.
        const RECLAIM_MAPS: [&str; 4] = [
            "TASK_COOKIE",
            "COOKIE_CTL",
            "IMAGE_CONTINUITY",
            "IMAGE_TGID_INDEX",
        ];
        let started = Instant::now();
        let waited_ms = loop {
            let live: Vec<u32> = aya::maps::loaded_maps()
                .filter_map(|info| info.ok().map(|info| info.id()))
                .collect();
            let lingering: Vec<(&str, u32)> = RECLAIM_MAPS
                .iter()
                .zip(ids_a.iter())
                .filter(|(_, id)| live.contains(id))
                .map(|(name, id)| (*name, *id))
                .collect();
            if lingering.is_empty() {
                break started.elapsed().as_millis();
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "A-prime: A maps still loaded 30s after reclaim: {lingering:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        println!("P11_BANK_APRIME_reclaim waited_ms={waited_ms}");
        driver.prepare(0).expect("prepare A-prime");
        let ids_aprime = [
            driver
                .bank_map_id(0, "TASK_COOKIE")
                .expect("A-prime cookie id"),
            driver.bank_map_id(0, "COOKIE_CTL").expect("A-prime ctl id"),
            driver
                .bank_map_id(0, "IMAGE_CONTINUITY")
                .expect("A-prime continuity id"),
            driver
                .bank_map_id(0, "IMAGE_TGID_INDEX")
                .expect("A-prime index id"),
        ];
        println!("P11_BANK_APRIME a={ids_a:?} aprime={ids_aprime:?}");
        for (old, new) in ids_a.iter().zip(ids_aprime.iter()) {
            assert_ne!(old, new, "A-prime map ids differ from A's");
        }
        driver.flip(0, 3).expect("flip to A-prime");
        // The query runs in the A-prime load: only its task-storage
        // and continuity maps hold the holder's cookie.
        driver.load_query_slot(0).expect("load query in A-prime");
        let mut holder = driver
            .spawn_controlled(&["hold"])
            .expect("spawn A-prime holder");
        holder.read_line("ENTERED").expect("holder entered");
        assert_eq!(
            driver.control(0).expect("control A-prime").next_ticket,
            1,
            "A-prime ticket 1 issued"
        );
        // A-prime ticket 1 joins under incarnation 3.
        driver
            .query_publish(1, 3, 2, &[(1, 0, 3, 0)])
            .expect("publish fresh request");
        let rows = driver.query_run_slot(0).expect("fresh query run");
        assert_eq!(rows.len(), 2, "A-prime fresh run emits data plus END");
        assert_eq!(
            rows[0].status, ROW_STATUS_READY,
            "A-prime ticket 1 joins READY"
        );
        // A ticket 1 never joins A-prime: incarnation 1 refuses.
        driver
            .query_publish(2, 3, 2, &[(1, 0, 1, 0)])
            .expect("publish stale request");
        let rows = driver.query_run_slot(0).expect("stale query run");
        assert!(rows.is_empty(), "A-prime: A ticket 1 never joins");
        holder.release().expect("release holder");
        let output = holder.finish().expect("holder exits");
        assert!(
            output.status.success(),
            "A-prime holder: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            driver.select().expect("SELECT").fixed,
            [3, 2],
            "A-prime fixed 3 rides SELECT"
        );
        assert_eq!(
            driver.gate(0).expect("gate A"),
            0,
            "A-prime gate A balanced"
        );
        assert_eq!(
            driver.gate(1).expect("gate B"),
            0,
            "A-prime gate B balanced"
        );
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N13 omitted-route cell"]
    fn privileged_image_bank_omitted_route_refuses() {
        require_root();
        let mut driver = BankProofDriver::setup("omitted", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        let mut held = driver.spawn_controlled(&["hold"]).expect("spawn held call");
        held.read_line("ENTERED").expect("held call entered");
        let pid = held.pid() as u64;
        let before = driver.account(1).expect("account B");
        assert_eq!(
            (before.admitted, before.live),
            (1, 1),
            "N13 held call live on B"
        );
        // Omit the route: the return finds no row and fabricates nothing.
        driver
            .delete_start_row((pid << 32) | pid)
            .expect("omit the route");
        held.release().expect("release held call");
        let output = held.finish().expect("held call exits");
        assert!(
            output.status.success(),
            "N13 held: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let refused = driver.account(1).expect("account B");
        println!(
            "P11_BANK_N13 admitted={} completed={} live={}",
            refused.admitted, refused.completed, refused.live
        );
        assert_eq!(refused.completed, 0, "N13 missing route completes nothing");
        assert_eq!(
            refused.live, 1,
            "N13 missing route leaks its live ref honestly"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N13 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N13 gate B balanced");
        // Useful-new-bank twin: the bank still serves after the refusal.
        let output = driver.run_simple(&["callfork", "1"]).expect("twin call");
        assert!(
            output.status.success(),
            "N13 twin: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let twin = driver.account(1).expect("account B");
        assert_eq!(twin.admitted, 2, "N13 twin admitted");
        assert_eq!(twin.completed, 1, "N13 twin completed");
        assert_eq!(twin.live, 1, "N13 only the omitted call stays live");
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N14 exec/query-span cell"]
    fn privileged_image_bank_exec_query_span_cut() {
        require_root();
        let mut driver = BankProofDriver::setup("execquery", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        driver.attach_exec().expect("attach exec");
        driver.load_query().expect("load query");
        // Live holders on both banks across the cut.
        let mut holder_a = driver.spawn_controlled(&["hold"]).expect("spawn A holder");
        holder_a.read_line("ENTERED").expect("A holder entered");
        driver.prepare(1).expect("prepare B");
        driver.flip(1, 2).expect("flip to B");
        let mut holder_b = driver.spawn_controlled(&["hold"]).expect("spawn B holder");
        holder_b.read_line("ENTERED").expect("B holder entered");
        // Control query covers both banks READY.
        driver
            .query_publish(1, 1, 2, &[(1, 0, 1, 0), (1, 1, 2, 1)])
            .expect("publish control");
        let rows = driver.query_run().expect("control query run");
        let control = driver.query_control().expect("query control");
        println!(
            "P11_BANK_N14_control rows={} failed={}",
            rows.len(),
            control[6]
        );
        assert_eq!(rows.len(), 3, "N14 control emits two data rows plus END");
        assert_eq!(control[6], 0, "N14 control covers");
        assert!(
            rows[..2].iter().all(|row| row.status == ROW_STATUS_READY),
            "N14 both banks READY"
        );
        // Exec lands between query and re-seed: poison spans, then heals.
        let mut exec = driver.spawn_controlled(&["exec_prep"]).expect("spawn exec");
        exec.read_line("EXECED").expect("child execed");
        driver
            .query_publish(2, 1, 2, &[(2, 1, 2, 0), (1, 0, 1, 1)])
            .expect("publish poison check");
        let rows = driver.query_run().expect("poison query run");
        let control = driver.query_control().expect("query control");
        println!(
            "P11_BANK_N14_poison rows={} failed={}",
            rows.len(),
            control[6]
        );
        assert_eq!(rows.len(), 3, "N14 poison run emits two data rows plus END");
        assert_eq!(control[6], 0, "N14 poison run covers");
        let poisoned = rows
            .iter()
            .find(|row| row.cookie == 2)
            .expect("exec row present");
        assert_eq!(
            poisoned.status, ROW_STATUS_UNKNOWN,
            "N14 exec row UNKNOWN while poisoned"
        );
        let steady = rows
            .iter()
            .find(|row| row.cookie == 1)
            .expect("A row present");
        assert_eq!(
            steady.status, ROW_STATUS_READY,
            "N14 other bank stays READY"
        );
        exec.release().expect("release post-exec call");
        exec.read_line("CALLED").expect("post-exec call ran");
        driver
            .query_publish(3, 1, 2, &[(2, 1, 2, 0)])
            .expect("publish reseed check");
        let rows = driver.query_run().expect("reseed query run");
        let control = driver.query_control().expect("query control");
        println!(
            "P11_BANK_N14_reseed rows={} failed={}",
            rows.len(),
            control[6]
        );
        assert_eq!(rows.len(), 2, "N14 reseed run emits data plus END");
        assert_eq!(
            rows[0].status, ROW_STATUS_READY,
            "N14 post-exec call re-seeds READY"
        );
        assert_eq!(rows[0].cookie, 2, "N14 re-seed keeps B ticket 2");
        assert_eq!(control[6], 0, "N14 reseed run covers");
        exec.release().expect("release exec child");
        let output = exec.finish().expect("exec exits");
        assert!(
            output.status.success(),
            "N14 exec: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        holder_a.release().expect("release A holder");
        holder_b.release().expect("release B holder");
        let output_a = holder_a.finish().expect("A holder exits");
        let output_b = holder_b.finish().expect("B holder exits");
        assert!(
            output_a.status.success() && output_b.status.success(),
            "N14 holders exit"
        );
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N14 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N14 gate B balanced");
    }

    /// ELF symbol value for the N15 IP assert: st_value is a link-time
    /// virtual address, so the runtime address is load bias plus
    /// st_value for ET_DYN (identity for a non-PIE executable).
    fn elf_symbol_address(path: &Path, bias: u64, want: &str) -> anyhow::Result<u64> {
        let bytes = std::fs::read(path)?;
        let is_dyn = u16_at(&bytes, 16) == 3;
        let shoff = u64_at_le(&bytes, 40) as usize;
        let shentsize = u16_at(&bytes, 58) as usize;
        let shnum = u16_at(&bytes, 60) as usize;
        let mut symtab = None;
        let mut strtab = None;
        for index in 0..shnum {
            let at = shoff + index * shentsize;
            if u32_at_le(&bytes, at + 4) == 2 {
                symtab = Some((
                    u64_at_le(&bytes, at + 24) as usize,
                    u64_at_le(&bytes, at + 32) as usize,
                ));
                let link = u32_at_le(&bytes, at + 40) as usize;
                let str_at = shoff + link * shentsize;
                strtab = Some((
                    u64_at_le(&bytes, str_at + 24) as usize,
                    u64_at_le(&bytes, str_at + 32) as usize,
                ));
            }
        }
        let (sym_off, sym_size) = symtab.expect("fixture symtab");
        let (str_off, str_size) = strtab.expect("fixture strtab");
        let mut at = sym_off;
        while at + 24 <= sym_off + sym_size {
            let name_at = u32_at_le(&bytes, at) as usize;
            let end = bytes[str_off + name_at..str_off + str_size]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(0);
            let name = String::from_utf8_lossy(&bytes[str_off + name_at..str_off + name_at + end]);
            if name == want {
                let value = u64_at_le(&bytes, at + 8);
                return Ok(if is_dyn { bias + value } else { value });
            }
            at += 24;
        }
        anyhow::bail!("fixture has no {want} symbol")
    }

    /// Load bias of the fixture's executable mapping in `pid`: the
    /// mapping base minus its file offset, so bias plus a link-time
    /// virtual address is the runtime address.
    fn fixture_load_bias(pid: u32, fixture: &Path) -> anyhow::Result<u64> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let fixture = fixture.to_string_lossy();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().unwrap_or("");
            let perms = fields.next().unwrap_or("");
            let offset = fields.next().unwrap_or("");
            let _dev = fields.next().unwrap_or("");
            let _inode = fields.next().unwrap_or("");
            let path = fields.next().unwrap_or("");
            if perms.starts_with("r-x") && path == fixture {
                let base = range.split('-').next().unwrap_or("0");
                let base = u64::from_str_radix(base, 16)?;
                let offset = u64::from_str_radix(offset, 16)?;
                return Ok(base - offset);
            }
        }
        anyhow::bail!("no executable fixture mapping in {pid}")
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N15 attach-cookie cell"]
    fn privileged_image_bank_attach_cookie_through_dispatcher() {
        require_root();
        let mut driver = BankProofDriver::setup("cookie", Backend::Singles).expect("setup");
        driver.attach_entry(Backend::Singles).expect("attach entry");
        driver
            .attach_ref(Backend::Singles, COOKIE_SINGLES)
            .expect("attach ref");
        let mut held = driver.spawn_controlled(&["hold"]).expect("spawn held call");
        held.read_line("ENTERED").expect("held call entered");
        let entry = driver.account(0).expect("account A");
        let direct = driver.account(2).expect("reference account");
        let bias = fixture_load_bias(held.pid(), &driver.fixture).expect("load bias");
        let symbol =
            elf_symbol_address(&driver.fixture, bias, TARGET_SYMBOL).expect("symbol address");
        println!(
            "P11_BANK_N15_singles stash_cookie={:#x} obs_cookie={:#x} stash_ip={:#x} obs_ip={:#x} symbol={:#x}",
            entry.stash_cookie, direct.obs_cookie, entry.stash_ip, direct.obs_ip, symbol
        );
        assert_eq!(direct.obs_cookie, COOKIE_SINGLES, "N15 direct cookie exact");
        assert_eq!(
            entry.stash_cookie, COOKIE_SINGLES,
            "N15 dispatched cookie identical"
        );
        assert_ne!(entry.stash_ip, 0, "N15 dispatched IP nonzero");
        assert_eq!(direct.obs_ip, entry.stash_ip, "N15 dispatched IP identical");
        assert_eq!(entry.stash_ip, symbol, "N15 IP is the target entry");
        held.release().expect("release held call");
        let output = held.finish().expect("held call exits");
        assert!(
            output.status.success(),
            "N15 held: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(driver);
        // Multi phase: identical cookies through the Multi dispatcher, or a
        // recorded Multi-impossible on kernels without uprobe.multi links.
        // The functional probe gates the attach: it proves a real link,
        // never a version, so the loader's singles fallback cannot
        // silently substitute a non-multi link.
        let mut driver =
            BankProofDriver::setup("cookie-multi", Backend::Multi).expect("multi setup");
        match crate::attach::multi_functional_probe() {
            Err(reason) => {
                println!("P11_BANK_N15_MULTI_IMPOSSIBLE reason={reason}");
            }
            Ok(()) => {
                driver.attach_entry(Backend::Multi).expect("multi attach");
                driver
                    .attach_ref(Backend::Multi, COOKIE_MULTI)
                    .expect("attach multi ref");
                let mut held = driver
                    .spawn_controlled(&["hold"])
                    .expect("spawn multi held call");
                held.read_line("ENTERED").expect("held call entered");
                let entry = driver.account(0).expect("account A");
                let direct = driver.account(2).expect("reference account");
                let bias = fixture_load_bias(held.pid(), &driver.fixture).expect("load bias");
                let symbol = elf_symbol_address(&driver.fixture, bias, TARGET_SYMBOL)
                    .expect("symbol address");
                println!(
                    "P11_BANK_N15_multi stash_cookie={:#x} obs_cookie={:#x} stash_ip={:#x} obs_ip={:#x} symbol={:#x}",
                    entry.stash_cookie, direct.obs_cookie, entry.stash_ip, direct.obs_ip, symbol
                );
                assert_eq!(
                    direct.obs_cookie, COOKIE_MULTI,
                    "N15 multi direct cookie exact"
                );
                assert_eq!(
                    entry.stash_cookie, COOKIE_MULTI,
                    "N15 multi dispatched cookie identical"
                );
                assert_ne!(entry.stash_ip, 0, "N15 multi dispatched IP nonzero");
                assert_eq!(
                    direct.obs_ip, entry.stash_ip,
                    "N15 multi dispatched IP identical"
                );
                assert_eq!(entry.stash_ip, symbol, "N15 multi IP is the target entry");
                held.release().expect("release held call");
                let output = held.finish().expect("held call exits");
                assert!(
                    output.status.success(),
                    "N15 multi held: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        assert_eq!(driver.gate(0).expect("gate A"), 0, "N15 gate A balanced");
        assert_eq!(driver.gate(1).expect("gate B"), 0, "N15 gate B balanced");
    }

    /// One in-flight N8 phase: cut while four threads are actively
    /// calling (no barrier pause). The warmup calls land in A
    /// deterministically (all complete before STARTED, the flip
    /// after); the free calls split across banks wherever the flip
    /// lands. Exact counts on kernels the probe clears (nothing
    /// counted by both banks: any double-count would inflate the
    /// exact sums, and any loss would short them), conservation
    /// below. Both banks must serve some calls, proving the flip
    /// landed mid-run instead of a vacuous all-A or all-B split.
    fn run_inflight_phase(backend: Backend, exact: bool) {
        let tag = match backend {
            Backend::Singles => "singles",
            Backend::Multi => "multi",
        };
        let mut driver =
            BankProofDriver::setup(&format!("inflight-{tag}"), backend).expect("setup");
        driver.attach_entry(backend).expect("attach entry");
        driver.prepare(1).expect("prepare B");
        let total = inflight_total_calls(INFLIGHT_THREADS);
        let threads = INFLIGHT_THREADS.to_string();
        let calls = INFLIGHT_CALLS.to_string();
        let mut workers = driver
            .spawn_controlled(&["inflight", &threads, &calls])
            .expect("spawn inflight");
        workers.read_line("STARTED").expect("threads past warmup");
        driver.flip(1, 2).expect("cut mid-run");
        let output = workers.finish().expect("inflight exits");
        assert!(
            output.status.success(),
            "N8I {tag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let final_a = driver.account(0).expect("account A");
        let final_b = driver.account(1).expect("account B");
        let final_ctl_a = driver.control(0).expect("control A");
        let final_ctl_b = driver.control(1).expect("control B");
        let burns_a = final_ctl_a.create_failures;
        let burns_b = final_ctl_b.create_failures;
        println!(
            "P11_BANK_N8I_{tag} admitted_a={} admitted_b={} completed_a={} completed_b={} live_a={} live_b={} burns_a={burns_a} burns_b={burns_b}",
            final_a.admitted,
            final_b.admitted,
            final_a.completed,
            final_b.completed,
            final_a.live,
            final_b.live
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=A cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_a.cookie_failures,
            final_a.seed_failures,
            final_a.start_present,
            final_a.start_insert_failures,
            final_a.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        println!(
            "P11_BANK_ADMISSION_FAILURES bank=B cookie={} seed={} start_present={} insert={} errno={} seed_status={}",
            final_b.cookie_failures,
            final_b.seed_failures,
            final_b.start_present,
            final_b.start_insert_failures,
            final_b.start_insert_errno as i64,
            SEED_FAILURE_STATUS
        );
        let accounted_a = ledger_with_all_burns(final_a.admitted, burns_a, &final_a);
        let accounted_b = ledger_with_all_burns(final_b.admitted, burns_b, &final_b);
        assert!(
            accounted_a > 0 && accounted_b > 0,
            "N8I {tag} both banks served (flip landed mid-run)"
        );
        if let Some(reason) = n8_capacity_failure("A", "inflight", &final_a, &final_ctl_a) {
            panic!("{reason}");
        }
        if let Some(reason) = n8_capacity_failure("B", "inflight", &final_b, &final_ctl_b) {
            panic!("{reason}");
        }
        if exact {
            for (name, account) in [("A", &final_a), ("B", &final_b)] {
                assert_eq!(
                    (
                        account.cookie_failures,
                        account.seed_failures,
                        account.start_present,
                        account.start_insert_failures,
                        account.live
                    ),
                    (0, 0, 0, 0, 0),
                    "N8I {tag} bank {name} exact"
                );
            }
            assert_eq!(
                final_a.admitted + final_b.admitted,
                total,
                "N8I {tag} exact split across both banks"
            );
        } else {
            assert_eq!(
                accounted_a + accounted_b,
                total,
                "N8I {tag} conservation across both banks"
            );
        }
        assert_eq!(
            final_a.completed, final_a.admitted,
            "N8I {tag} every A admission completes"
        );
        assert_eq!(
            final_b.completed, final_b.admitted,
            "N8I {tag} every B admission completes"
        );
        assert_eq!(
            driver.gate(0).expect("gate A"),
            0,
            "N8I {tag} gate A balanced"
        );
        assert_eq!(
            driver.gate(1).expect("gate B"),
            0,
            "N8I {tag} gate B balanced"
        );
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N8 in-flight cut counting cell (flip while calling)"]
    fn privileged_image_bank_inflight_cut_counts_once() {
        require_root();
        let multi_possible = crate::attach::multi_functional_probe().is_ok();
        let release = kernel_release();
        let exact = n8_requires_exact_count(multi_possible);
        println!(
            "P11_BANK_N8I_class multi_possible={multi_possible} kernel={release} verdict={}",
            if exact { "exact" } else { "conservation" }
        );
        run_inflight_phase(Backend::Singles, exact);
        // Multi phase, or a recorded Multi-impossible on kernels
        // without uprobe.multi links (the functional probe gates the
        // attach, never a version).
        match crate::attach::multi_functional_probe() {
            Err(reason) => {
                println!("P11_BANK_N8I_MULTI_IMPOSSIBLE reason={reason}");
            }
            Ok(()) => {
                run_inflight_phase(Backend::Multi, exact);
            }
        }
    }

    #[test]
    #[ignore = "image-bank-proof build (P11SCOPE_IMAGE_BANK_PROOF=1) and root BPF lane; N5 per-call overhead cell (quiet lane E4)"]
    fn privileged_image_bank_per_call_overhead() {
        // N5: same tree dispatcher off/on, 1 and 4 threads, 5 runs x
        // 1M completed controlled calls. Leg (a) runs the workload
        // with nothing attached; leg (b) attaches the bank entry and
        // return directly in its own load with a consistent gate
        // (dispatcher off, the traced baseline); leg (c) attaches
        // the proof dispatcher plus the same bank programs
        // (dispatcher on). Added cost is (c)-(b) per completed call;
        // the percentage divides by the production traced per-call
        // cost input (R-47), or reports not-computed and gates
        // 250 ns only. Both thread counts print their verdict before
        // the cell asserts, so a FAIL log still shows every number.
        require_root();
        let release = kernel_release();
        let cpus = std::thread::available_parallelism()
            .map(|slots| slots.get())
            .unwrap_or(0);
        let multi_possible = crate::attach::multi_functional_probe().is_ok();
        let production_1 = n5_production_ns(std::env::var(N5_PRODUCTION_ENV_1).ok().as_deref());
        let production_4 = n5_production_ns(std::env::var(N5_PRODUCTION_ENV_4).ok().as_deref());
        println!(
            "P11_BANK_N5_env kernel={release} cpus={cpus} multi_possible={multi_possible} backend=multi production_ns_1={} production_ns_4={}",
            production_1
                .map(|cost| cost.to_string())
                .as_deref()
                .unwrap_or("none"),
            production_4
                .map(|cost| cost.to_string())
                .as_deref()
                .unwrap_or("none")
        );
        if !multi_possible {
            // Strict numbers apply only on uprobe_multi kernels
            // (R-21/R-22): on older kernels nothing is measured here.
            println!("P11_BANK_N5_SKIP reason=no-uprobe-multi kernel={release} cpus={cpus}");
            return;
        }
        let mut thread_pass = Vec::new();
        for threads in [1u64, 4u64] {
            let args = n5_workload_args(threads).expect("N5 threads 1 or 4");
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let mut leg_a = Vec::new();
            let mut leg_b = Vec::new();
            let mut leg_c = Vec::new();
            for run in 0..N5_RUNS_PER_LEG {
                let untraced =
                    n5_run_untraced(&format!("n5-a-{threads}-{run}"), &arg_refs).expect("N5 leg a");
                println!(
                    "P11_BANK_N5_run threads={threads} leg=a run={run} calls={} elapsed_ns={} ns_per_call={:.3}",
                    N5_CALLS_PER_RUN, untraced.elapsed_ns, untraced.ns_per_call
                );
                leg_a.push(untraced.ns_per_call);
                let mut driver =
                    BankProofDriver::setup(&format!("n5-b-{threads}-{run}"), Backend::Multi)
                        .expect("N5 leg b setup");
                driver
                    .attach_direct_entry(Backend::Multi, 0)
                    .expect("N5 leg b attach");
                // R-47: the directly attached entry releases one gate
                // ref per call without a dispatcher taking them, so
                // the leg pre-takes its run's releases up front
                // (outside the timed region) and the gate ends back
                // at 0 instead of wrapping.
                driver
                    .pre_take_gate(0, N5_CALLS_PER_RUN)
                    .expect("N5 leg b pre-take");
                let baseline = n5_run_traced(&driver, &arg_refs, "N5 leg b").expect("N5 leg b");
                println!(
                    "P11_BANK_N5_run threads={threads} leg=b run={run} calls={} elapsed_ns={} ns_per_call={:.3} admitted={} completed={} live={} faults={} failures={} next_ticket={} gate0={} gate1={}",
                    N5_CALLS_PER_RUN,
                    baseline.elapsed_ns,
                    baseline.ns_per_call,
                    baseline.account.admitted,
                    baseline.account.completed,
                    baseline.account.live,
                    baseline.account.faults,
                    counted_admission_failures(&baseline.account),
                    baseline.control.next_ticket,
                    driver.gate(0).expect("N5 leg b gate A"),
                    driver.gate(1).expect("N5 leg b gate B")
                );
                leg_b.push(baseline.ns_per_call);
                assert_eq!(
                    driver.gate(0).expect("N5 leg b gate A"),
                    0,
                    "N5 leg b gate A balanced"
                );
                assert_eq!(
                    driver.gate(1).expect("N5 leg b gate B"),
                    0,
                    "N5 leg b gate B balanced"
                );
                drop(driver);
                let mut driver =
                    BankProofDriver::setup(&format!("n5-c-{threads}-{run}"), Backend::Multi)
                        .expect("N5 leg c setup");
                driver
                    .attach_entry(Backend::Multi)
                    .expect("N5 leg c attach");
                let dispatched = n5_run_traced(&driver, &arg_refs, "N5 leg c").expect("N5 leg c");
                println!(
                    "P11_BANK_N5_run threads={threads} leg=c run={run} calls={} elapsed_ns={} ns_per_call={:.3} admitted={} completed={} live={} faults={} failures={} next_ticket={} gate0={} gate1={}",
                    N5_CALLS_PER_RUN,
                    dispatched.elapsed_ns,
                    dispatched.ns_per_call,
                    dispatched.account.admitted,
                    dispatched.account.completed,
                    dispatched.account.live,
                    dispatched.account.faults,
                    counted_admission_failures(&dispatched.account),
                    dispatched.control.next_ticket,
                    driver.gate(0).expect("N5 leg c gate A"),
                    driver.gate(1).expect("N5 leg c gate B")
                );
                leg_c.push(dispatched.ns_per_call);
                assert_eq!(
                    driver.gate(0).expect("N5 leg c gate A"),
                    0,
                    "N5 leg c gate A balanced"
                );
                assert_eq!(
                    driver.gate(1).expect("N5 leg c gate B"),
                    0,
                    "N5 leg c gate B balanced"
                );
                drop(driver);
            }
            let added: Vec<f64> = leg_c
                .iter()
                .zip(leg_b.iter())
                .map(|(on, off)| n5_added(*on, *off))
                .collect();
            // Informational continuity with the pre-R-47 baseline:
            // the traced cost (b)-(a) and the added ratio over it.
            // Neither gates: the 15% denominator is the production
            // traced per-call cost input.
            let traced: Vec<f64> = leg_b
                .iter()
                .zip(leg_a.iter())
                .map(|(baseline, untraced)| baseline - untraced)
                .collect();
            let traced_pct: Vec<f64> = (0..N5_RUNS_PER_LEG)
                .filter_map(|run| n5_run_pct(leg_a[run], leg_b[run], leg_c[run]))
                .collect();
            println!(
                "P11_BANK_N5_traced threads={threads} median_traced_ns={:.3} median_pct_over_traced={}",
                n5_median(&traced).expect("five traced runs"),
                n5_median(&traced_pct)
                    .map(|pct| format!("{pct:.3}"))
                    .as_deref()
                    .unwrap_or("none")
            );
            let production = if threads == 1 {
                production_1
            } else {
                production_4
            };
            let verdict = match production {
                Some(denominator) => {
                    let pct: Vec<f64> = added
                        .iter()
                        .map(|added| {
                            n5_run_pct_production(*added, denominator)
                                .expect("N5 production denominator positive")
                        })
                        .collect();
                    n5_verdict(&added, &pct)
                }
                None => {
                    println!(
                        "P11_BANK_N5_pct threads={threads} status=not-computed reason=no-production-input"
                    );
                    n5_verdict_ns_only(&added)
                }
            };
            println!(
                "P11_BANK_N5_verdict threads={threads} runs={} calls={} median_a_ns={:.3} median_b_ns={:.3} median_c_ns={:.3} median_added_ns={:.3} min_added_ns={:.3} max_added_ns={:.3} median_pct={:.3} min_pct={:.3} max_pct={:.3} production_ns={} verdict={}",
                N5_RUNS_PER_LEG,
                N5_CALLS_PER_RUN,
                n5_median(&leg_a).expect("five untraced runs"),
                n5_median(&leg_b).expect("five baseline runs"),
                n5_median(&leg_c).expect("five dispatched runs"),
                verdict.median_added_ns,
                verdict.min_added_ns,
                verdict.max_added_ns,
                verdict.median_pct,
                verdict.min_pct,
                verdict.max_pct,
                production
                    .map(|cost| cost.to_string())
                    .as_deref()
                    .unwrap_or("none"),
                if verdict.pass { "PASS" } else { "FAIL" }
            );
            thread_pass.push((threads, verdict.pass));
        }
        for (threads, pass) in thread_pass {
            assert!(
                pass,
                "N5 threads={threads}: dispatcher overhead over budget (see P11_BANK_N5_verdict)"
            );
        }
    }

    #[test]
    fn verifier_tail_keeps_last_60_lines() {
        let log: String = (0..100)
            .map(|line| format!("line {line:03}"))
            .collect::<Vec<_>>()
            .join("\n");
        let tail = super::verifier_tail(&log);
        let kept: Vec<_> = tail.lines().collect();
        assert_eq!(kept.len(), 60, "tail keeps exactly 60 lines");
        assert_eq!(kept[0], "line 040", "tail starts at the 41st line");
        assert_eq!(kept[59], "line 099", "tail ends at the reason");
        assert!(
            !tail.contains("line 000"),
            "head stays out of the refusal line"
        );
    }

    #[test]
    fn verifier_tail_keeps_short_logs_whole() {
        let tail = super::verifier_tail("only\ntwo");
        assert_eq!(tail, "only\ntwo", "short logs pass through whole");
    }

    static FAKE_UNMOUNT_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static FAKE_UNMOUNT_LAST: std::sync::Mutex<PathBuf> = std::sync::Mutex::new(PathBuf::new());
    static GUARD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn record_unmount(point: &Path) {
        FAKE_UNMOUNT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *FAKE_UNMOUNT_LAST.lock().expect("fake unmount lock") = point.to_path_buf();
    }

    #[test]
    fn bpffs_guard_unmounts_on_drop() {
        let _serial = GUARD_TEST_LOCK.lock().expect("guard test lock");
        let before = FAKE_UNMOUNT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let point = std::env::temp_dir().join("p11-bank-guard-drop");
        let guard = super::BpffsGuard::armed_with(point.clone(), record_unmount);
        assert_eq!(guard.point(), point.as_path(), "guard names its mount");
        drop(guard);
        let after = FAKE_UNMOUNT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(after, before + 1, "drop runs the mount op once");
        assert_eq!(
            *FAKE_UNMOUNT_LAST.lock().expect("fake unmount lock"),
            point,
            "drop unmounts the guarded point"
        );
    }

    #[test]
    fn bpffs_guard_unmounts_on_panic() {
        let _serial = GUARD_TEST_LOCK.lock().expect("guard test lock");
        let before = FAKE_UNMOUNT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let point = std::env::temp_dir().join("p11-bank-guard-panic");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = super::BpffsGuard::armed_with(point, record_unmount);
            panic!("controlled setup panic");
        }));
        assert!(outcome.is_err(), "controlled panic unwinds");
        let after = FAKE_UNMOUNT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(after, before + 1, "panic unwind runs the mount op once");
    }

    #[test]
    fn elf_symbol_address_matches_readelf() {
        let dir = std::env::temp_dir().join(format!("p11-bank-elf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("elf test dir");
        let fixture = super::compile_fixture(&dir).expect("compile fixture");
        let value = elf_symbol_address(&fixture, 0, super::TARGET_SYMBOL).expect("symbol address");
        let output = std::process::Command::new("readelf")
            .args(["-sW"])
            .arg(&fixture)
            .output()
            .expect("readelf runs");
        assert!(output.status.success(), "readelf succeeds");
        let text = String::from_utf8_lossy(&output.stdout);
        let mut want = None;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.last() == Some(&super::TARGET_SYMBOL) {
                want = Some(u64::from_str_radix(fields[1], 16).expect("hex value"));
            }
        }
        let want = want.expect("readelf names the target");
        assert_eq!(value, want, "harness symbol value matches readelf");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_object_dispatchers_call_scalar_select() {
        let bytes = super::proof_object_bytes().expect("proof object present");
        let edges = super::call_edges(&bytes).expect("call edges");
        for root in ["p11_bank_disp_enter", "p11_bank_disp_enter_multi"] {
            let mut callees = edges.get(root).cloned().unwrap_or_default();
            callees.sort();
            // The argument-free release core folds into the root; select
            // stays the one outlined call, and no context crosses it.
            assert_eq!(
                callees,
                ["p11_bank_select"],
                "{root} calls exactly the scalar select core"
            );
        }
        let object = aya_obj::Object::parse(&bytes).expect("parse proof object");
        for function in object.functions.values() {
            assert!(
                !function.name.starts_with("p11_bank_dispatch_"),
                "no stale context-taking dispatch core: {}",
                function.name
            );
        }
        // The real N3 computation runs unprivileged on the same object.
        let depths = super::stack_depths(&bytes).expect("stack scan");
        for root in [
            "p11_bank_disp_enter",
            "p11_bank_disp_enter_multi",
            "p11_bank_disp_birth",
        ] {
            assert!(
                depths[root] <= 64,
                "N3 {root} dispatcher chain {} exceeds 64",
                depths[root]
            );
        }
        for root in ["p11_bank_entry_a", "p11_bank_entry_b"] {
            assert!(
                depths[root] <= 448,
                "N3 {root} bank chain {} exceeds 448",
                depths[root]
            );
        }
    }

    #[test]
    fn proof_query_cover_lookup_keys_are_wide() {
        // Every bpf_map_lookup_elem (helper 1) key slot in the
        // dual-bank query cover must be initialized by a 64-bit
        // store -- except the ACCOUNT bank index, the one u32-keyed
        // lookup. A 32-bit store leaves the high key word as stack
        // garbage, so the affected lookup silently matches nothing
        // whenever that garbage is nonzero.
        let bytes = super::proof_object_bytes().expect("proof object present");
        let object = aya_obj::Object::parse(&bytes).expect("parse proof object");
        let function = object
            .functions
            .values()
            .find(|function| function.name == "p11_bank_query_cover")
            .expect("query cover function");
        let insns = &function.instructions;
        // Key slot per helper-1 call: walk back to `r2 = r10` plus
        // `r2 += -off` (stack offsets are negative, which skips
        // counter increments sharing the same opcode).
        let mut slots = Vec::new();
        for (index, insn) in insns.iter().enumerate() {
            if insn.code != 0x85 || insn.imm != 1 {
                continue;
            }
            let mut found = None;
            let mut cursor = index;
            while cursor > 0 && index - cursor <= 8 {
                cursor -= 1;
                let prev = &insns[cursor];
                if prev.code == 0x07 && prev.dst_reg() == 2 && prev.imm < 0 {
                    found = Some(-prev.imm);
                    break;
                }
            }
            slots.push(found.expect("lookup key materialized via r2 += -off"));
        }
        assert!(
            slots.len() >= 2,
            "query cover reads CTL then row 0 first: {slots:?}"
        );
        let wide = |store: &aya_obj::generated::bpf_insn, slot: i32| {
            mem_store_width(store, slot) == Some(0x18)
        };
        assert!(
            insns.iter().any(|store| wide(store, slots[1])),
            "row-0 key slot {} has no 64-bit store",
            slots[1]
        );
        let mut distinct = slots.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let mut narrow = Vec::new();
        for slot in &distinct {
            if insns.iter().any(|store| wide(store, *slot)) {
                continue;
            }
            assert!(
                insns
                    .iter()
                    .any(|store| mem_store_width(store, *slot).is_some()),
                "key slot {slot} has no store at all (backtrack wrong?)"
            );
            narrow.push(*slot);
        }
        assert_eq!(
            narrow.len(),
            1,
            "exactly one u32 key slot (ACCOUNT bank index); narrow={narrow:?} all={distinct:?}"
        );
    }

    #[test]
    fn elf_symbol_address_uses_load_bias() {
        // The fixture is PIE: st_value is a link-time virtual
        // address, but the r-x mapping starts one page in (file
        // offset 0x1000). The harness must subtract the mapping
        // offset (load bias); mapping base plus st_value lands
        // exactly one page too high.
        use std::io::BufRead;
        let dir = std::env::temp_dir().join(format!("p11-bank-bias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("bias test dir");
        let fixture = super::compile_fixture(&dir).expect("compile fixture");
        let mut child = Command::new(&fixture)
            .arg("hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn hold");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut line)
            .expect("read ENTERED");
        assert_eq!(line.trim_end(), "ENTERED", "holder reaches the target");
        let pid = child.id();
        let bias = fixture_load_bias(pid, &fixture).expect("load bias");
        let harness = elf_symbol_address(&fixture, bias, super::TARGET_SYMBOL).expect("symbol");
        // Independent oracle: readelf LOAD segments plus the live
        // mapping offset straight from /proc/PID/maps.
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
        let want = fixture.to_string_lossy().into_owned();
        let mut mapping = None;
        for text in maps.lines() {
            let fields: Vec<_> = text.split_whitespace().collect();
            if fields.len() >= 6 && fields[1].starts_with("r-x") && fields[5] == want {
                let start = fields[0].split('-').next().expect("range start");
                mapping = Some((
                    u64::from_str_radix(start, 16).expect("hex base"),
                    u64::from_str_radix(fields[2], 16).expect("hex offset"),
                ));
                break;
            }
        }
        let (map_base, map_offset) = mapping.expect("live r-x fixture mapping");
        assert_eq!(map_base, bias + map_offset, "oracle reads the same mapping");
        assert_ne!(
            map_offset, 0,
            "the offset path is exercised (else this test is vacuous)"
        );
        let segments = Command::new("readelf")
            .args(["-lW"])
            .arg(&fixture)
            .output()
            .expect("readelf runs");
        assert!(segments.status.success(), "readelf -lW succeeds");
        let mut text_segment = None;
        for text in String::from_utf8_lossy(&segments.stdout).lines() {
            let fields: Vec<_> = text.split_whitespace().collect();
            if fields.first() == Some(&"LOAD") && fields.contains(&"R") && fields.contains(&"E") {
                let hex = |field: &str| {
                    u64::from_str_radix(field.trim_start_matches("0x"), 16).expect("hex field")
                };
                text_segment = Some((hex(fields[1]), hex(fields[2]), hex(fields[4])));
                break;
            }
        }
        let (seg_off, seg_virt, seg_filesiz) = text_segment.expect("readelf names the text LOAD");
        let symbols = Command::new("readelf")
            .args(["-sW"])
            .arg(&fixture)
            .output()
            .expect("readelf runs");
        assert!(symbols.status.success(), "readelf -sW succeeds");
        let mut value = None;
        for text in String::from_utf8_lossy(&symbols.stdout).lines() {
            let fields: Vec<_> = text.split_whitespace().collect();
            if fields.last() == Some(&super::TARGET_SYMBOL) {
                value = Some(
                    u64::from_str_radix(fields[1].trim_start_matches("0x"), 16).expect("hex value"),
                );
            }
        }
        let st_value = value.expect("readelf names the target");
        assert!(
            seg_virt <= st_value && st_value < seg_virt + seg_filesiz,
            "the target lives in the text LOAD"
        );
        let symbol_file_off = st_value - seg_virt + seg_off;
        let oracle = map_base + symbol_file_off - map_offset;
        assert_eq!(
            harness, oracle,
            "harness symbol equals the segment-aware oracle"
        );
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(b"go\n")
            .expect("release");
        let status = child.wait().expect("wait");
        assert!(status.success(), "holder exits cleanly");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fork_births_spend_runner_plus_children() {
        // 100 forked children plus the fork-runner's own birth.
        assert_eq!(super::fork_birth_tickets(1, 100), 102);
        assert_eq!(
            super::fork_birth_tickets(0, 0),
            1,
            "even an empty fork run is born"
        );
    }

    #[test]
    fn quota_unavailable_counts_runner_birth() {
        assert_eq!(super::quota_unavailable_after(7, 100), 108);
    }

    #[test]
    fn fixture_fork_modes_clone_exact_children() {
        // Independent pin of the N12 process model: `fork N`
        // performs exactly N clones (no threads, no hidden
        // double-fork), so the kernel cell must observe N + 1
        // births: the children plus the runner itself.
        let dir = std::env::temp_dir().join(format!("p11-bank-clone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("clone test dir");
        let fixture = super::compile_fixture(&dir).expect("compile fixture");
        for (mode, count) in [("fork", 3), ("callfork", 2)] {
            let trace = dir.join(format!("{mode}.trace"));
            let status = Command::new("strace")
                .args(["-f", "-e", "trace=clone,clone3", "-o"])
                .arg(&trace)
                .arg(&fixture)
                .arg(mode)
                .arg(count.to_string())
                .status()
                .expect("strace runs (required for the birth-model pin)");
            assert!(status.success(), "{mode} {count} exits cleanly");
            let text = std::fs::read_to_string(&trace).expect("trace written");
            let calls: Vec<_> = text
                .lines()
                .filter(|line| line.contains(" clone(") || line.contains(" clone3("))
                .collect();
            assert_eq!(calls.len(), count, "{mode} {count} clones exactly {count}");
            for call in &calls {
                assert!(
                    !call.contains("CLONE_THREAD"),
                    "{mode} births are non-thread: {call}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_pin_maps_include_both_query_maps() {
        // Multi-load query runs in the bank load but publishes in
        // shared: both IMAGE_QUERY_REQUESTS and IMAGE_QUERY_CTL must
        // be shared-pinned, or the bank load sees a zeroed control
        // (generation 0) and its cover returns 1 (EAGAIN) on the
        // first visit.
        assert!(
            super::SHARED_PIN_MAPS.contains(&"IMAGE_QUERY_REQUESTS"),
            "requests map is shared"
        );
        assert!(
            super::SHARED_PIN_MAPS.contains(&"IMAGE_QUERY_CTL"),
            "query control is shared (bank-load runs read it)"
        );
    }

    #[test]
    fn n4_tables_budget_covers_measured_kernels() {
        // Controller r3-8-input memlock at worst state (both banks
        // full): host 7.0 and guest 6.6 report buckets+header via
        // htab_map_mem_usage, 5.15 reports the static footprint.
        let budget = super::n4_second_bank_tables_budget();
        assert!(
            1704832 + 1442688 <= budget,
            "host 7.0 tables fit the plan budget"
        );
        assert!(
            1704960 + 1442816 <= budget,
            "guest 6.6 tables fit the plan budget"
        );
        assert!(
            524288 + 262144 <= budget,
            "guest 5.15 tables fit the plan budget"
        );
        let host_tables = 1704832u64 + 1442688;
        let old_budget = 88u64 * 16384 + 72 * 16384;
        assert!(
            host_tables > old_budget,
            "the old per-element-only budget fails on host (non-vacuous)"
        );
    }

    #[test]
    fn ambient_births_counts_excess_only() {
        assert_eq!(super::ambient_births(101, 101), Some(0));
        assert_eq!(super::ambient_births(103, 101), Some(2));
        assert_eq!(
            super::ambient_births(100, 101),
            None,
            "a shortfall is a test-owned miss, never negative ambient"
        );
    }

    #[test]
    fn n7_burns_keep_ledger_exact() {
        // Host r3-8-input: admitted 16383 + 1 B = 16384; one counted
        // burn (task-storage creation failure under load) keeps the
        // 16385 ledger exact, mirroring N6's successful+burned.
        assert_eq!(super::n7_ledger_with_burns(16384, 1), 16385);
        assert_eq!(super::n7_ledger_with_burns(16385, 0), 16385);
    }

    #[test]
    fn install_slot_never_loads_an_already_loaded_program() {
        // Patched aya refuses load()/load_multi() while the program
        // holds an fd (ProgramError::AlreadyLoaded). install_slot is
        // a pure install: it reads the entry FD that load_bank_progs
        // loaded and sets it into this driver's owner array, so no
        // load-while-loaded is possible by construction (the old
        // plain -> multi -> plain reload sequence is gone: loading
        // one entry both ways in one map instance is refused with
        // EINVAL after verification). Each load_bank_progs arm loads
        // the entry exactly once.
        let source = include_str!("image_bank_proof.rs");
        let install_start = source
            .find("fn install_slot")
            .expect("install_slot present");
        let tail = source[install_start..]
            .find("/// Re-install")
            .expect("install_slot end");
        let body = &source[install_start..install_start + tail];
        for op in ["entry.unload()", "entry.load_multi()", "entry.load()"] {
            assert!(
                !body.contains(op),
                "install_slot performs no {op} (pure install, no reload)"
            );
        }
        let bank_start = source
            .find("fn load_bank_progs")
            .expect("load_bank_progs present");
        let bank_body = &source[bank_start..install_start];
        assert!(
            bank_body.contains("Backend::Multi") && bank_body.contains("backend"),
            "load_bank_progs selects the entry load by backend"
        );
        assert_eq!(
            bank_body.matches("entry.load()").count(),
            1,
            "load_bank_progs loads the entry plain exactly once"
        );
        assert_eq!(
            bank_body.matches("entry.load_multi()").count(),
            1,
            "load_bank_progs loads the entry multi exactly once"
        );
        assert!(
            bank_body.contains("birth.load("),
            "load_bank_progs still loads the birth program"
        );
    }

    #[test]
    fn multi_backend_attaches_through_multi_links() {
        // Patched aya's load_multi leaves attach_mode untouched, so
        // probe.attach follows the ELF section (plain uprobe -> Single
        // -> perf-event link), which the kernel refuses with EINVAL for
        // a 48-loaded program. Every multi-loaded program must attach
        // through a real uprobe-multi link (BPF_LINK_CREATE
        // attach_type=48), the way the product does for its twins.
        let source = include_str!("image_bank_proof.rs");
        let entry_start = source
            .find("pub fn attach_entry")
            .expect("attach_entry present");
        let ref_start = source
            .find("pub fn attach_ref")
            .expect("attach_ref present");
        let entry_body = &source[entry_start..ref_start];
        let birth_start = source
            .find("pub fn attach_birth")
            .expect("attach_birth present");
        let ref_body = &source[ref_start..birth_start];
        assert_eq!(
            entry_body.matches("load_multi()").count(),
            2,
            "attach_entry multi-loads dispatcher and return"
        );
        assert_eq!(
            entry_body.matches("attach_group").count(),
            2,
            "attach_entry multi-links dispatcher and return"
        );
        assert_eq!(
            ref_body.matches("load_multi()").count(),
            1,
            "attach_ref multi-loads ref"
        );
        assert_eq!(
            ref_body.matches("attach_group").count(),
            1,
            "attach_ref multi-links ref"
        );
        assert!(
            entry_body.contains("probe.attach") || entry_body.contains("ret.attach"),
            "singles path keeps aya attach"
        );
        assert!(
            ref_body.contains("probe.attach"),
            "singles ref keeps aya attach"
        );
    }

    #[test]
    fn sentinel3_counts_ambient_births() {
        // The birth hook stays attached across the cut, so ambient
        // forks during sentinel phase 3 spend B tickets. Phase 3 must
        // count them like the other N12 phases, with test-owned exact
        // and a named stop on shortfall.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("Sentinel phase 3")
            .expect("sentinel phase 3 present");
        let tail = source[start..]
            .find("// N4 memlock")
            .expect("sentinel phase 3 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("ambient_births"),
            "sentinel3 counts ambient births"
        );
        assert!(
            body.contains("phase=sentinel3"),
            "sentinel3 prints its ambient line"
        );
        assert!(
            body.contains("1 + ambient") || body.contains("1+ambient"),
            "sentinel3 expects one test-owned ticket plus ambient"
        );
        assert!(
            body.contains("test-owned") && body.contains("missing during the window"),
            "sentinel3 stops loudly on a test-owned shortfall"
        );
    }

    #[test]
    fn fixture_symbol_file_offset_matches_readelf() {
        // Multi links attach by file offset, not symbol: the helper
        // must translate st_value via its section (st_value - sh_addr
        // + sh_offset), the same translation aya uses for Symbol
        // points. Pinned against readelf LOAD segments (independent
        // of the helper's section walk), not the helper itself.
        let dir = std::env::temp_dir().join(format!("p11-bank-off-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("offset test dir");
        let fixture = super::compile_fixture(&dir).expect("compile fixture");
        let got =
            super::fixture_symbol_file_offset(&fixture, super::TARGET_SYMBOL).expect("file offset");
        let symbols = std::process::Command::new("readelf")
            .args(["-sW"])
            .arg(&fixture)
            .output()
            .expect("readelf runs");
        assert!(symbols.status.success(), "readelf -sW succeeds");
        let mut st_value = None;
        for line in String::from_utf8_lossy(&symbols.stdout).lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.last() == Some(&super::TARGET_SYMBOL) {
                st_value = Some(u64::from_str_radix(fields[1], 16).expect("hex value"));
            }
        }
        let st_value = st_value.expect("readelf names the target");
        let segments = std::process::Command::new("readelf")
            .args(["-lW"])
            .arg(&fixture)
            .output()
            .expect("readelf runs");
        assert!(segments.status.success(), "readelf -lW succeeds");
        let mut text_segment = None;
        for line in String::from_utf8_lossy(&segments.stdout).lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.first() == Some(&"LOAD") && fields.contains(&"R") && fields.contains(&"E") {
                let hex = |field: &str| {
                    u64::from_str_radix(field.trim_start_matches("0x"), 16).expect("hex field")
                };
                text_segment = Some((hex(fields[1]), hex(fields[2]), hex(fields[4])));
                break;
            }
        }
        let (seg_off, seg_virt, seg_filesiz) = text_segment.expect("readelf names the text LOAD");
        assert!(
            seg_virt <= st_value && st_value < seg_virt + seg_filesiz,
            "the target lives in the text LOAD"
        );
        let want = st_value - seg_virt + seg_off;
        assert_eq!(got, want, "file offset matches the readelf translation");
        assert_ne!(got, 0, "the offset path is exercised");
        assert!(
            super::fixture_symbol_file_offset(&fixture, "no_such_p11_bank_symbol_xyz").is_err(),
            "missing symbols fail loudly"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_conservation_counts_failures_per_cause() {
        // Conservation over one bank's account values: admitted plus
        // the counted failure buckets must equal the ledger calls.
        // Refuses an uncounted shortfall (silent admission loss) and
        // any over-count; accepts an exact count and a shortfall each
        // of whose causes is counted. One row per bucket.
        let cases: [(u64, u64, u64, u64, u64, u64, bool); 8] = [
            // (admitted, cookie, seed, present, insert, calls, conserved)
            (20000, 0, 0, 0, 0, 20000, true),
            (19999, 1, 0, 0, 0, 20000, true),
            (19999, 0, 1, 0, 0, 20000, true),
            (19999, 0, 0, 1, 0, 20000, true),
            (19999, 0, 0, 0, 1, 20000, true),
            (19998, 1, 0, 0, 1, 20000, true),
            (19999, 0, 0, 0, 0, 20000, false),
            (20000, 0, 0, 0, 1, 20000, false),
        ];
        for (admitted, cookie, seed, present, insert, calls, want) in cases {
            let account = super::BankAccount {
                admitted,
                cookie_failures: cookie,
                seed_failures: seed,
                start_present: present,
                start_insert_failures: insert,
                ..Default::default()
            };
            assert_eq!(
                super::counted_admission_failures(&account),
                cookie + seed + present + insert,
                "every bucket lands in the failure sum"
            );
            assert_eq!(
                super::admission_conserved(&account, calls),
                want,
                "admitted={admitted} cookie={cookie} seed={seed} \
                 present={present} insert={insert} calls={calls}"
            );
        }
    }

    #[test]
    fn decode_account_reads_failure_counters() {
        // The Rust decode must read the five failure words at the C
        // layout offsets (64/72/80/88/96) with the attribution words
        // undisturbed. Distinct values per field, so any swapped or
        // shifted offset fails.
        let mut bytes = [0u8; super::BANK_ACCOUNT_SIZE];
        for (index, slot) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *slot = (index as u64 + 1).to_ne_bytes();
        }
        let account = super::decode_account(&bytes);
        assert_eq!(
            [
                account.admitted,
                account.completed,
                account.live,
                account.faults,
                account.obs_cookie,
                account.obs_ip,
                account.stash_cookie,
                account.stash_ip,
                account.cookie_failures,
                account.seed_failures,
                account.start_present,
                account.start_insert_failures,
                account.start_insert_errno,
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            "decode reads the 13-word account in order"
        );
        assert_eq!(super::BANK_ACCOUNT_SIZE, 104, "account value size");
    }

    #[test]
    fn concurrent_cut_asserts_conservation() {
        // N8 races 4 threads x 10,000 calls through concurrent hash-map
        // inserts, which can refuse transiently; the cell must assert
        // conservation (admitted + counted failures == ledger) instead
        // of an exact admitted count, print both banks' failure lines,
        // and fail a shortfall with no counted failure by name.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_concurrent_cut_counts_once")
            .expect("N8 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_held_return_across_cut")
            .expect("N8 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("admission_conserved"),
            "N8 asserts conservation, not an exact admitted count"
        );
        assert!(
            body.contains("P11_BANK_ADMISSION_FAILURES"),
            "N8 prints its admission-failure lines"
        );
        assert!(
            body.contains("bank=A") && body.contains("bank=B"),
            "N8 prints both banks"
        );
        assert!(
            body.contains("silent admission loss"),
            "N8 fails an uncounted shortfall by name"
        );
    }

    #[test]
    fn bank_account_carries_failure_counters() {
        // The C account must carry one word per admission-failure
        // cause plus the last START insert errno, growing the value
        // to 104 bytes (Rust decode and the checker shape move with
        // it; the attribution offsets stay put).
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        for field in [
            "u64 cookie_failures;",
            "u64 seed_failures;",
            "u64 start_present;",
            "u64 start_insert_failures;",
            "u64 start_insert_errno;",
        ] {
            assert!(native.contains(field), "C account carries {field}");
        }
        assert!(
            native.contains("sizeof(struct bank_account) == 104"),
            "C account ABI is 104 bytes"
        );
    }

    #[test]
    fn enter_cores_count_every_failure() {
        // No enter-core failure path may return without a counter:
        // every return in p11_bank_enter_a/b is the success return or
        // the counting funnel, and each core funnels each cause (bad
        // task and cookie status share the cookie bucket).
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let start_a = native
            .find("u32 p11_bank_enter_a(")
            .expect("enter A present");
        let start_b = native
            .find("u32 p11_bank_enter_b(")
            .expect("enter B present");
        let end = native
            .find("u32 p11_bank_complete(")
            .expect("enter cores end");
        for (name, body) in [
            ("enter_a", &native[start_a..start_b]),
            ("enter_b", &native[start_b..end]),
        ] {
            let mut returns = 0u32;
            let mut cursor = 0;
            while let Some(rel) = body[cursor..].find("return ") {
                let at = cursor + rel + "return ".len();
                let tail = &body[at..];
                assert!(
                    tail.starts_with("COOKIE_STATUS_OK;") || tail.starts_with("bank_enter_fail("),
                    "{name} returns only success or the counting funnel"
                );
                returns += 1;
                cursor = at;
            }
            assert_eq!(returns, 6, "{name} keeps its six returns");
            assert_eq!(
                body.matches("BANK_FAIL_COOKIE").count(),
                2,
                "{name} counts bad-task and cookie-status failures"
            );
            for cause in ["BANK_FAIL_SEED", "BANK_FAIL_PRESENT", "BANK_FAIL_INSERT"] {
                assert_eq!(body.matches(cause).count(), 1, "{name} counts {cause} once");
            }
        }
    }

    #[test]
    fn kernel_release_is_parseable() {
        // Scaffolding for the per-kernel verdict lines: the release
        // reads from the live kernel and parses to a version.
        let release = super::kernel_release();
        assert!(!release.is_empty(), "kernel release is present");
        assert!(
            crate::doctor::parse_major_minor(&release).is_some(),
            "kernel release {release} parses to a version"
        );
    }

    #[test]
    fn n2_count_gate_checks_present_counts() {
        // A present verifier count is checked against the gates on
        // every kernel, old or new.
        for release in ["5.15.221", "6.1.188", "6.6.157", "7.0.0-38-generic"] {
            assert_eq!(
                super::n2_count_gate("p11_bank_disp_enter", Some(2366), release),
                Ok(super::N2Gate::Check(2366)),
                "present count checked on {release}"
            );
        }
    }

    #[test]
    fn n2_count_gate_is_load_only_on_515() {
        // 5.15 has no `verified_insns` in program info: an absent
        // count there is explicitly load-only, never a silent pass.
        assert_eq!(
            super::n2_count_gate("p11_bank_disp_enter", None, "5.15.221"),
            Ok(super::N2Gate::LoadOnly),
            "absent count is load-only on 5.15"
        );
    }

    #[test]
    fn n2_count_gate_fails_named_where_counts_exist() {
        // An absent count on a kernel that provides `verified_insns`
        // (5.16+, including 6.1/6.6/host) fails named; an unparsable
        // release fails closed the same way.
        for release in ["6.1.188", "6.6.157", "7.0.0-38-generic", "unknown"] {
            let outcome = super::n2_count_gate("p11_bank_disp_enter", None, release);
            assert!(
                outcome.is_err(),
                "absent count fails on {release}: {outcome:?}"
            );
            let reason = outcome.expect_err("absent count fails");
            assert!(
                reason.contains("p11_bank_disp_enter"),
                "failure names the root: {reason}"
            );
        }
    }

    #[test]
    fn n2_cells_name_load_only_roots() {
        // The N2 cell must route every root through the count gate
        // and print one named line per load-only root.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_verifier_stats")
            .expect("N2 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_exhaustion_16384_then_quota")
            .expect("N2 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("n2_count_gate"),
            "N2 routes every root through the count gate"
        );
        assert!(
            body.contains("verifier-count=unavailable load-only"),
            "N2 prints the named load-only line"
        );
    }

    #[test]
    fn n8_multi_probe_success_means_exact_count() {
        // On uprobe_multi kernels the N8 verdict is exact: the
        // functional probe's success selects it, never a version.
        assert!(
            super::n8_requires_exact_count(true),
            "a successful multi probe means the exact N8 verdict"
        );
    }

    #[test]
    fn n8_probe_failure_means_conservation() {
        // Where the multi probe fails (older kernels), N8 keeps the
        // conservation verdict with per-cause buckets.
        assert!(
            !super::n8_requires_exact_count(false),
            "a failed multi probe means the conservation N8 verdict"
        );
    }

    #[test]
    fn n8_capacity_failure_names_map_full_inserts() {
        // A START insert refused with E2BIG is the bank map full at
        // its declared worst case: a capacity failure on every
        // kernel. Other errnos and clean accounts are not capacity.
        let control = super::BankControl {
            limit: super::TICKET_LIMIT,
            next_ticket: 1,
            ..Default::default()
        };
        let full = super::BankAccount {
            admitted: 19999,
            start_insert_failures: 1,
            start_insert_errno: (-(libc::E2BIG as i64)) as u64,
            ..Default::default()
        };
        let reason = super::n8_capacity_failure("A", "final", &full, &control)
            .expect("E2BIG insert is a capacity failure");
        assert!(
            reason.contains("capacity") && reason.contains("bank A"),
            "capacity names its cause and bank: {reason}"
        );
        let busy = super::BankAccount {
            start_insert_errno: (-(libc::EBUSY as i64)) as u64,
            ..full
        };
        assert_eq!(
            super::n8_capacity_failure("A", "final", &busy, &control),
            None,
            "a transient errno is not a capacity failure"
        );
        assert_eq!(
            super::n8_capacity_failure("A", "final", &super::BankAccount::default(), &control),
            None,
            "a clean account is not a capacity failure"
        );
    }

    #[test]
    fn n8_capacity_failure_names_ticket_saturation() {
        // Tickets saturated at the 16,384 limit means the per-bank
        // maps are full at the declared worst case: any counted
        // failure there is capacity, failing closed (the seed errno
        // is unrecorded). Saturation alone, without a failure, and
        // race failures below the limit, are not capacity.
        let saturated = super::BankControl {
            limit: super::TICKET_LIMIT,
            next_ticket: super::TICKET_LIMIT,
            ..Default::default()
        };
        let room = super::BankControl {
            next_ticket: 1,
            ..saturated
        };
        for (cookie, seed) in [(1, 0), (0, 1)] {
            let account = super::BankAccount {
                admitted: 19999,
                cookie_failures: cookie,
                seed_failures: seed,
                ..Default::default()
            };
            assert!(
                super::n8_capacity_failure("B", "final", &account, &saturated).is_some(),
                "saturation plus cookie={cookie} seed={seed} is capacity"
            );
            assert_eq!(
                super::n8_capacity_failure("B", "final", &account, &room),
                None,
                "the same failures below the limit are not capacity"
            );
        }
        assert_eq!(
            super::n8_capacity_failure("B", "final", &super::BankAccount::default(), &saturated),
            None,
            "saturation without a failure is not a capacity failure"
        );
    }

    #[test]
    fn n8_cell_branches_verdict_on_multi_probe() {
        // The N8 cell must decide its verdict from the multi
        // functional probe, print its class, and apply the capacity
        // rule before either verdict.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_concurrent_cut_counts_once")
            .expect("N8 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_held_return_across_cut")
            .expect("N8 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("multi_functional_probe"),
            "N8 decides its class from the multi probe"
        );
        assert!(
            body.contains("P11_BANK_N8_class"),
            "N8 prints its verdict class"
        );
        assert!(
            body.contains("n8_requires_exact_count"),
            "N8 branches exact vs conservation on the probe"
        );
        assert!(
            body.contains("n8_capacity_failure"),
            "N8 applies the capacity rule"
        );
    }

    #[test]
    fn n4_tables_figure_matches_plan() {
        // The computed second-bank figure and its +-5% band, pinned
        // as values: 88x16384+72x16384+2x262144 = 3145728.
        assert_eq!(super::n4_second_bank_tables_figure(), 3145728);
        assert_eq!(super::n4_second_bank_tables_floor(), 2988441);
        assert_eq!(super::n4_second_bank_tables_budget(), 3303014);
    }

    #[test]
    fn n4_htab_class_follows_kernel_release() {
        // Only kernels whose fdinfo reports htab usage (6.6+ with
        // measured evidence) take the two-sided band; 5.15, the
        // unmeasured 6.1, and unparsable releases stay upper-only.
        assert!(!super::kernel_reports_htab_usage("5.15.221"));
        assert!(!super::kernel_reports_htab_usage("6.1.188"));
        assert!(super::kernel_reports_htab_usage("6.6.157"));
        assert!(super::kernel_reports_htab_usage("7.0.0-38-generic"));
        assert!(!super::kernel_reports_htab_usage("unknown"));
    }

    #[test]
    fn n4_tables_band_binds_both_sides() {
        // The band admits the computed figure, its edges, and the
        // measured host/6.6 tables; it refuses above-budget and
        // below-floor sums, including the measured 5.15 static
        // footprint.
        for measured in [
            2988441,
            3145728,
            3303014,
            1704832 + 1442688,
            1704960 + 1442816,
        ] {
            assert!(
                super::n4_tables_within_band(measured),
                "band admits {measured}"
            );
        }
        for measured in [2988440, 3303015, 524288 + 262144] {
            assert!(
                !super::n4_tables_within_band(measured),
                "band refuses {measured}"
            );
        }
    }

    #[test]
    fn n4_cell_asserts_lower_bound_on_htab_kernels() {
        // The N4 cell must branch on the kernel's fdinfo accounting:
        // the two-sided band where htab usage is reported, upper
        // bound only with a named static-footprint note below.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_fork_burn_sentinel")
            .expect("N4 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_second_rollover")
            .expect("N4 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("kernel_reports_htab_usage"),
            "N4 branches on the kernel's fdinfo accounting"
        );
        assert!(
            body.contains("n4_second_bank_tables_floor"),
            "N4 asserts the lower bound on htab kernels"
        );
        assert!(
            body.contains("P11_BANK_N4_static_accounting"),
            "N4 prints the static-accounting note below"
        );
    }

    #[test]
    fn ledger_with_all_burns_sums_admitted_and_every_counted_burn() {
        // N6/N7 conservation must count every burn the per-cause
        // buckets name: a ticket burned in any of them is reported,
        // not lost.
        let plain = super::BankAccount {
            admitted: 16384,
            ..Default::default()
        };
        assert_eq!(super::ledger_with_all_burns(16384, 0, &plain), 16384);
        let buckets = super::BankAccount {
            admitted: 16383,
            ..Default::default()
        };
        assert_eq!(
            super::ledger_with_all_burns(16383, 1, &buckets),
            16384,
            "creation burn"
        );
        let seed = super::BankAccount {
            admitted: 16383,
            seed_failures: 1,
            ..Default::default()
        };
        assert_eq!(
            super::ledger_with_all_burns(16383, 0, &seed),
            16384,
            "seed burn"
        );
        let present = super::BankAccount {
            admitted: 16383,
            start_present: 1,
            ..Default::default()
        };
        assert_eq!(
            super::ledger_with_all_burns(16383, 0, &present),
            16384,
            "present burn"
        );
        let insert = super::BankAccount {
            admitted: 16383,
            start_insert_failures: 1,
            ..Default::default()
        };
        assert_eq!(
            super::ledger_with_all_burns(16383, 0, &insert),
            16384,
            "insert burn"
        );
        let combined = super::BankAccount {
            admitted: 16380,
            seed_failures: 1,
            start_present: 1,
            start_insert_failures: 1,
            ..Default::default()
        };
        assert_eq!(
            super::ledger_with_all_burns(16380, 1, &combined),
            16384,
            "combined burns"
        );
    }

    #[test]
    fn tickets_conserved_rejects_silent_drop() {
        // A dropped admission with no counted burn must never
        // conserve: the quiescence poll spins to its deadline and the
        // checkpoint asserts fail by name. An over-count fails closed
        // like a shortfall.
        let control = super::BankControl {
            next_ticket: 16384,
            ..Default::default()
        };
        let exact = super::BankAccount {
            admitted: 16384,
            ..Default::default()
        };
        assert!(
            super::tickets_conserved(&exact, &control),
            "exact count conserves"
        );
        let dropped = super::BankAccount {
            admitted: 16383,
            ..Default::default()
        };
        assert!(
            !super::tickets_conserved(&dropped, &control),
            "silent drop never conserves"
        );
        let over = super::BankAccount {
            admitted: 16384,
            seed_failures: 1,
            ..Default::default()
        };
        assert!(
            !super::tickets_conserved(&over, &control),
            "over-count never conserves"
        );
    }

    #[test]
    fn bank_quiescent_needs_live_zero_and_conservation() {
        let control = super::BankControl {
            next_ticket: 16384,
            ..Default::default()
        };
        let live = super::BankAccount {
            admitted: 16384,
            live: 1,
            ..Default::default()
        };
        assert!(
            !super::bank_quiescent(&live, &control),
            "live ref blocks quiescence"
        );
        let short = super::BankAccount {
            admitted: 16383,
            ..Default::default()
        };
        assert!(
            !super::bank_quiescent(&short, &control),
            "shortfall blocks quiescence"
        );
        let exact = super::BankAccount {
            admitted: 16384,
            ..Default::default()
        };
        assert!(
            super::bank_quiescent(&exact, &control),
            "exact count is quiescent"
        );
        let burned = super::BankAccount {
            admitted: 16383,
            seed_failures: 1,
            ..Default::default()
        };
        assert!(
            super::bank_quiescent(&burned, &control),
            "reported burns do not block quiescence"
        );
    }

    #[test]
    fn poll_bank_until_quiescent_returns_fresh_reads() {
        // The poll must re-read until quiescent and hand the
        // checkpoint the latest reads, not the first ones.
        let control = super::BankControl {
            next_ticket: 2,
            ..Default::default()
        };
        let unq = super::BankAccount {
            admitted: 1,
            live: 1,
            ..Default::default()
        };
        let mid = super::BankAccount {
            admitted: 1,
            ..Default::default()
        };
        let done = super::BankAccount {
            admitted: 2,
            ..Default::default()
        };
        let script = [unq, mid, done];
        let mut reads = 0;
        let ((account, _), quiesced) = super::poll_bank_until_quiescent(
            || {
                let step = script[reads.min(2)];
                reads += 1;
                (step, control)
            },
            std::time::Duration::from_secs(30),
        );
        assert!(quiesced, "quiescent reads stop the poll");
        assert_eq!(reads, 3, "the poll re-reads until quiescent");
        assert_eq!(account.admitted, 2, "the checkpoint gets the latest reads");
    }

    #[test]
    fn poll_bank_until_quiescent_gives_up_after_deadline() {
        // A stuck live ref or silent shortfall must come back with
        // the final reads and quiesced=false so the checkpoint
        // asserts fail by name; the wait never passes a loss through.
        let control = super::BankControl {
            next_ticket: 16384,
            ..Default::default()
        };
        let stuck = super::BankAccount {
            admitted: 16383,
            live: 1,
            ..Default::default()
        };
        let mut reads = 0;
        let ((account, _), quiesced) = super::poll_bank_until_quiescent(
            || {
                reads += 1;
                (stuck, control)
            },
            std::time::Duration::ZERO,
        );
        assert!(!quiesced, "a stuck bank never quiesces");
        assert_eq!(reads, 1, "an expired deadline reads once and gives up");
        assert_eq!(
            (account.admitted, account.live),
            (16383, 1),
            "final reads reach the asserts"
        );
    }

    #[test]
    fn n6_checkpoint_waits_for_quiescence_and_conserves_all_burns() {
        // The host-only 16383/16384 flake: the N6 checkpoint must poll
        // for quiescence with a bounded deadline, print every counted
        // bucket, and conserve over all of them; a silent shortfall or
        // stuck live ref fails by name after the deadline.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_exhaustion_16384_then_quota")
            .expect("N6 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_cut_16385th_leader_in_b")
            .expect("N6 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("poll_bank_until_quiescent"),
            "N6 polls for quiescence before reading"
        );
        assert!(
            body.contains("ledger_with_all_burns"),
            "N6 conserves over every counted burn"
        );
        assert!(
            body.contains("P11_BANK_ADMISSION_FAILURES"),
            "N6 prints its admission-failure line"
        );
        assert!(
            body.contains("cookie_failures"),
            "N6 names the cookie burn relation"
        );
        assert!(
            body.contains("P11_BANK_N6_quiesce"),
            "N6 records the quiescence outcome"
        );
    }

    #[test]
    fn n7_ledger_conserves_all_burns() {
        // N7's ledger is the same conservation sum as N6's: it must
        // count every per-cause bucket on both banks, not just the
        // task-storage creation failures.
        let source = include_str!("image_bank_proof.rs");
        let start = source
            .find("fn privileged_image_bank_cut_16385th_leader_in_b")
            .expect("N7 present");
        let tail = source[start..]
            .find("fn privileged_image_bank_concurrent_cut_counts_once")
            .expect("N7 end");
        let body = &source[start..start + tail];
        assert!(
            body.contains("ledger_with_all_burns"),
            "N7 conserves over every counted burn"
        );
        assert!(
            body.contains("P11_BANK_ADMISSION_FAILURES"),
            "N7 prints its admission-failure lines"
        );
        assert!(
            body.contains("bank=A") && body.contains("bank=B"),
            "N7 prints both banks"
        );
    }

    #[test]
    fn proof_slot_roots_keep_kernel_stack() {
        // Entry slots carry ~370-byte frames (N3); on 6.13+ they take
        // the shared per-CPU private stack unless they issue a tail
        // call of their own, and a same-CPU preemption then clobbers
        // keys and rows (host-only N6 16383/16384 flake). Both slot
        // roots must opt out through STACK_GUARD: each driver loads
        // them once with its backend's attach type (the
        // template_second precedent: one program, one type per map
        // instance).
        let source = include_str!("../../crates/ebpf/src/image_bank_proof.rs");
        let entry_a = source
            .find("pub fn p11_bank_entry_a")
            .expect("entry_a present");
        let entry_b = source
            .find("pub fn p11_bank_entry_b")
            .expect("entry_b present");
        let ret = source
            .find("pub fn p11_bank_return")
            .expect("return present");
        assert!(
            source[entry_a..entry_b].contains("keep_endpoint_stack"),
            "entry_a keeps the kernel stack"
        );
        assert!(
            source[entry_b..ret].contains("keep_endpoint_stack"),
            "entry_b keeps the kernel stack"
        );
    }

    /// Map names reachable from a root: its own references plus every
    /// transitively reachable callee's (the checker's census shape).
    fn reachable_maps(
        root: &str,
        edges: &HashMap<String, Vec<String>>,
        maps: &HashMap<String, Vec<String>>,
    ) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut pending = vec![root.to_string()];
        let mut touched = HashSet::new();
        while let Some(next) = pending.pop() {
            if !seen.insert(next.clone()) {
                continue;
            }
            touched.extend(maps.get(&next).cloned().unwrap_or_default());
            pending.extend(edges.get(&next).cloned().unwrap_or_default());
        }
        touched
    }

    /// Body of `name` up to (not including) the `end` marker.
    fn fn_body_between(source: &str, name: &str, end: &str) -> String {
        let start = source
            .find(name)
            .unwrap_or_else(|| panic!("{name} present"));
        let tail = source[start..]
            .find(end)
            .unwrap_or_else(|| panic!("{name} end"));
        source[start..start + tail].to_string()
    }

    #[test]
    fn reclaim_clears_only_the_arrays_install_sets() {
        // install_slot sets this driver's one owner array plus the birth
        // array; the other backend's array never holds the slot, so a
        // reclaim that deletes it fails ENOENT in every reclaiming cell.
        let source = include_str!("image_bank_proof.rs");
        let reclaim = fn_body_between(
            source,
            "    pub fn reclaim(",
            "    /// Attach the entry dispatcher",
        );
        assert!(
            reclaim.contains("self.owner_array()"),
            "reclaim clears the driver's owner array"
        );
        assert!(
            reclaim.contains("\"BANK_PROGS_BIRTH\""),
            "reclaim clears the birth array"
        );
        for array in ["\"BANK_PROGS_SINGLES\"", "\"BANK_PROGS_MULTI\""] {
            assert!(
                !reclaim.contains(array),
                "reclaim must not clear {array} by name: only the owner array was set"
            );
        }
        // The helper names the same array per backend as install_slot.
        let helper = fn_body_between(source, "    fn owner_array(", "    fn install_slot(");
        let install = fn_body_between(source, "    fn install_slot(", "/// Re-install");
        for arm in [
            "Backend::Singles => \"BANK_PROGS_SINGLES\"",
            "Backend::Multi => \"BANK_PROGS_MULTI\"",
        ] {
            assert!(helper.contains(arm), "owner_array maps {arm}");
            assert!(install.contains(arm), "install_slot maps {arm}");
        }
    }

    #[test]
    fn proof_slot_entry_loads_keep_one_attach_type_per_array() {
        // Since CVE-2025-40123 a program array keeps its first
        // program's expected attach type and refuses callers with a
        // different one after verification (EINVAL, not a verifier
        // refusal). The slot roots reference STACK_GUARD, so loading
        // one entry both plain and multi in one map instance fails
        // every cell in setup; each install flow must load each
        // entry with exactly one attach type.
        let bytes = super::proof_object_bytes().expect("proof object present");
        let edges = super::call_edges(&bytes).expect("call edges");
        let maps = super::map_edges(&bytes).expect("map edges");
        let arrays = super::program_array_maps(&bytes).expect("program arrays");
        for known in [
            "TAIL_CALLS",
            "STACK_GUARD",
            "BANK_PROGS_SINGLES",
            "BANK_PROGS_MULTI",
            "BANK_PROGS_BIRTH",
        ] {
            assert!(
                arrays.contains(known),
                "proof object keeps its {known} program array"
            );
        }
        let mut entry_arrays = HashSet::new();
        for root in ["p11_bank_entry_a", "p11_bank_entry_b"] {
            let touched = reachable_maps(root, &edges, &maps);
            let markers: Vec<&String> = touched
                .iter()
                .filter(|name| name.starts_with('!'))
                .collect();
            assert!(
                markers.is_empty(),
                "{root} has unresolvable map references: {markers:?}"
            );
            assert!(
                touched.contains("STACK_GUARD"),
                "{root} keeps the kernel stack through STACK_GUARD"
            );
            entry_arrays.extend(touched.into_iter().filter(|name| arrays.contains(name)));
        }
        assert!(
            !entry_arrays.is_empty(),
            "slot entries reference at least one program array"
        );
        // Install-flow load types from the load paths the cells take.
        let source = include_str!("image_bank_proof.rs");
        let bank_body = fn_body_between(source, "fn load_bank_progs", "fn install_slot");
        let install_body = fn_body_between(source, "fn install_slot", "/// Re-install");
        let mut cursor = 0;
        let mut ops = Vec::new();
        while let Some((at, op)) = ["entry.unload()", "entry.load_multi()", "entry.load()"]
            .iter()
            .filter_map(|op| {
                install_body[cursor..]
                    .find(op)
                    .map(|rel| (cursor + rel, *op))
            })
            .min()
        {
            ops.push(op);
            cursor = at + op.len();
        }
        if ops.is_empty() {
            // Pure install: the single entry load in load_bank_progs
            // selects the driver's backend type, so each flow loads
            // one type per array.
            assert!(
                bank_body.contains("Backend::Multi") && bank_body.contains("backend"),
                "load_bank_progs selects the entry load by backend"
            );
            assert_eq!(
                bank_body.matches("entry.load()").count(),
                1,
                "load_bank_progs loads the entry plain once (Singles arm)"
            );
            assert_eq!(
                bank_body.matches("entry.load_multi()").count(),
                1,
                "load_bank_progs loads the entry multi once (Multi arm)"
            );
            return;
        }
        // Reload shape: simulate the entry's loaded type over the
        // install flow and fail on the second attach type.
        let mut types = HashSet::new();
        if bank_body.contains("entry.load_multi()") {
            types.insert("multi");
        }
        if bank_body.contains("entry.load()") {
            types.insert("plain");
        }
        let mut loaded = types.iter().next().copied();
        for op in &ops {
            if *op == "entry.unload()" {
                loaded = None;
            } else if op.contains("multi") {
                loaded = Some("multi");
                types.insert("multi");
            } else {
                loaded = Some("plain");
                types.insert("plain");
            }
        }
        let _ = loaded;
        assert!(
            types.len() <= 1,
            "slot entries take {} attach types in one install flow while referencing program arrays {entry_arrays:?}: initial={} install ops={ops:?}",
            types.len(),
            if bank_body.contains("entry.load_multi()") {
                "multi"
            } else {
                "plain"
            },
        );
    }

    #[test]
    fn proof_owner_arrays_pair_callers_with_matching_targets() {
        // Owner-array census: each BANK_PROGS_* array has exactly one
        // caller root, pure targets touch no program array, and the
        // install paths complete every array. Jointly with the
        // single-type entry loads, each array keeps one expected
        // attach type in every load flow (Singles/Multi cells and
        // both verifier_stats loaders, which never install).
        let bytes = super::proof_object_bytes().expect("proof object present");
        let edges = super::call_edges(&bytes).expect("call edges");
        let maps = super::map_edges(&bytes).expect("map edges");
        let arrays = super::program_array_maps(&bytes).expect("program arrays");
        let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
        for root in super::PROOF_ROOTS {
            let touched = reachable_maps(root, &edges, &maps);
            let markers: Vec<&String> = touched
                .iter()
                .filter(|name| name.starts_with('!'))
                .collect();
            assert!(
                markers.is_empty(),
                "{root} has unresolvable map references: {markers:?}"
            );
            assert!(
                !touched.contains("TAIL_CALLS"),
                "{root} must not reference TAIL_CALLS (plain-owned by product interface programs)"
            );
            for array in ["BANK_PROGS_SINGLES", "BANK_PROGS_MULTI", "BANK_PROGS_BIRTH"] {
                if touched.contains(array) {
                    callers
                        .entry(array.to_string())
                        .or_default()
                        .insert(root.to_string());
                }
            }
        }
        for (array, caller) in [
            ("BANK_PROGS_SINGLES", "p11_bank_disp_enter"),
            ("BANK_PROGS_MULTI", "p11_bank_disp_enter_multi"),
            ("BANK_PROGS_BIRTH", "p11_bank_disp_birth"),
        ] {
            assert_eq!(
                callers.get(array).cloned().unwrap_or_default(),
                HashSet::from([caller.to_string()]),
                "{array} has exactly one caller root"
            );
        }
        for root in [
            "p11_bank_entry_a",
            "p11_bank_entry_b",
            "p11_bank_birth_a",
            "p11_bank_birth_b",
            "p11_bank_return",
            "p11_bank_ref_entry",
        ] {
            let touched = reachable_maps(root, &edges, &maps);
            let array_refs: Vec<&String> = touched
                .iter()
                .filter(|name| arrays.contains(*name))
                .collect();
            if root.starts_with("p11_bank_entry_") {
                assert!(
                    array_refs.iter().all(|name| name.as_str() != "TAIL_CALLS")
                        && !array_refs
                            .iter()
                            .any(|name| name.starts_with("BANK_PROGS_")),
                    "{root} is an owner-array target, not a caller: {array_refs:?}"
                );
            } else {
                assert!(
                    array_refs.is_empty(),
                    "{root} references no program array, else it joins the attach-type census: {array_refs:?}"
                );
            }
        }
        // Every program the cells load is in the census.
        let source = include_str!("image_bank_proof.rs");
        let mut loaded = HashSet::new();
        let mut rest = source;
        while let Some(at) = rest.find("program_mut(\"") {
            rest = &rest[at + 13..];
            let end = rest.find('"').expect("program name closes");
            loaded.insert(rest[..end].to_string());
            rest = &rest[end..];
        }
        assert!(
            source.contains("program_mut(Self::entry_prog(slot))"),
            "bank loads resolve the entry through entry_prog"
        );
        assert!(
            source.contains("program_mut(Self::birth_prog(slot))"),
            "bank loads resolve the birth program through birth_prog"
        );
        for (helper, end, names) in [
            (
                "fn entry_prog",
                "fn birth_prog",
                ["p11_bank_entry_a", "p11_bank_entry_b"],
            ),
            (
                "fn birth_prog",
                "/// Load a bank's slot programs",
                ["p11_bank_birth_a", "p11_bank_birth_b"],
            ),
        ] {
            let body = fn_body_between(source, helper, end);
            for name in names {
                assert!(body.contains(name), "{helper} resolves {name}");
                loaded.insert(name.to_string());
            }
        }
        let roots: HashSet<String> = super::PROOF_ROOTS.iter().map(ToString::to_string).collect();
        // load_one_root resolves its program through a variable, so
        // its call sites join the census by name.
        for site in [
            "load_one_root(&mut bpf, root, false)",
            "load_one_root(&mut multi_bpf, \"p11_bank_disp_enter_multi\", true)",
            "load_one_root(&mut default_bpf, \"p11_entry\", false)",
            "load_one_root(&mut default_bpf, \"p11_entry_ia32\", false)",
        ] {
            assert!(source.contains(site), "census covers call site {site}");
        }
        for name in ["p11_bank_disp_enter_multi", "p11_entry", "p11_entry_ia32"] {
            loaded.insert(name.to_string());
        }
        for name in &loaded {
            assert!(
                roots.contains(name) || ["p11_entry", "p11_entry_ia32"].contains(&name.as_str()),
                "loaded program {name} joins the census"
            );
        }
        for root in super::PROOF_ROOTS {
            assert!(loaded.contains(root), "census covers loaded root {root}");
        }
        // Install completeness: install_slot names and sets every
        // owner array.
        let install_body = fn_body_between(source, "fn install_slot", "/// Re-install");
        for array in ["BANK_PROGS_SINGLES", "BANK_PROGS_MULTI", "BANK_PROGS_BIRTH"] {
            let at = install_body
                .find(array)
                .unwrap_or_else(|| panic!("install_slot installs {array}"));
            assert!(
                install_body[at..]
                    .find("programs.set(")
                    .is_some_and(|rel| rel < 400),
                "install_slot sets {array}"
            );
        }
        // The verifier_stats loaders carry callers only and never
        // install targets.
        let stats_body = fn_body_between(
            source,
            "fn privileged_image_bank_verifier_stats",
            "fn privileged_image_bank_exhaustion_16384_then_quota",
        );
        assert!(
            !stats_body.contains("install_slot")
                && !stats_body.contains("load_bank_progs(")
                && !stats_body.contains(".prepare(")
                && !stats_body.contains(".reinstall("),
            "verifier_stats loads programs but installs nothing"
        );
        assert_eq!(
            stats_body.matches("stats_loader(&bytes)").count(),
            2,
            "verifier_stats splits plain and multi loads across fresh loaders"
        );
        // Dispatcher attach arms: plain Singles loads beside the
        // pinned multi loads.
        let entry_body = fn_body_between(source, "pub fn attach_entry", "pub fn attach_ref");
        assert_eq!(
            entry_body.matches("probe.load()").count(),
            1,
            "attach_entry loads the Singles dispatcher plain"
        );
        assert_eq!(
            entry_body.matches("ret.load()").count(),
            1,
            "attach_entry loads the Singles return plain"
        );
    }

    #[test]
    fn proof_object_override_selects_explicit_path() {
        // A pre-fix control carries its own object: an explicit
        // non-empty override wins, unset/empty falls back to the
        // baked OUT_DIR object.
        let explicit = super::resolve_proof_object_path(Some("/tmp/pinned-proof-object"));
        assert_eq!(
            explicit,
            PathBuf::from("/tmp/pinned-proof-object"),
            "explicit override wins"
        );
        for unset in [None, Some("")] {
            let path = super::resolve_proof_object_path(unset);
            assert!(
                path.ends_with("image-bank-proof-v1/p11scope-ebpf-image-bank-proof-v1"),
                "unset/empty override falls back to the baked object: {}",
                path.display()
            );
        }
    }

    #[test]
    fn proof_object_identity_names_resolved_path_and_sha256() {
        // Every root run names the object bytes it loaded; the
        // script greps this line and compares against the staged
        // object it pinned through the override.
        // proof_object_bytes emits the P11_BANK_PROOF_OBJECT line; this
        // test pins what it resolves to.
        let bytes = super::proof_object_bytes().expect("proof object present");
        let path = super::proof_object_path();
        assert!(!bytes.is_empty(), "proof object is non-empty");
        match std::env::var(super::PROOF_OBJECT_OVERRIDE_ENV)
            .ok()
            .filter(|path| !path.is_empty())
        {
            Some(pinned) => assert_eq!(path, PathBuf::from(pinned), "identity names the override"),
            None => assert!(
                path.ends_with("image-bank-proof-v1/p11scope-ebpf-image-bank-proof-v1"),
                "identity names the baked object: {}",
                path.display()
            ),
        }
    }

    #[test]
    fn n5_budgets_match_the_fixed_numbers() {
        // Plan row N5 fixes the numbers; any miss is FAIL, not a
        // retune, so the constants are pinned, not just used.
        assert_eq!(
            super::N5_CALLS_PER_RUN,
            1_000_000,
            "1M completed calls per run"
        );
        assert_eq!(super::N5_RUNS_PER_LEG, 5, "5 runs per leg");
        assert_eq!(super::N5_ADDED_BUDGET_NS, 250.0, "250 ns added budget");
        assert_eq!(super::N5_PCT_BUDGET, 15.0, "15% budget");
    }

    #[test]
    fn n5_ns_per_call_divides_elapsed_by_calls() {
        assert_eq!(
            super::n5_ns_per_call(2_500_000_000, 1_000_000),
            2500.0,
            "elapsed over completed calls"
        );
        assert_eq!(
            super::n5_ns_per_call(0, 1_000_000),
            0.0,
            "zero elapsed is zero per call"
        );
    }

    #[test]
    fn n5_median_picks_the_middle() {
        assert_eq!(
            super::n5_median(&[3.0, 1.0, 5.0, 2.0, 4.0]),
            Some(3.0),
            "middle of five unsorted runs"
        );
        assert_eq!(
            super::n5_median(&[1.0, 2.0, 3.0, 4.0]),
            Some(2.5),
            "even counts average the two middles"
        );
        assert_eq!(super::n5_median(&[7.0]), Some(7.0), "single value");
        assert_eq!(super::n5_median(&[]), None, "empty has no median");
    }

    #[test]
    fn n5_spread_reports_min_and_max() {
        assert_eq!(
            super::n5_spread(&[3.0, 1.0, 5.0, 2.0, 4.0]),
            Some((1.0, 5.0)),
            "min and max over unsorted runs"
        );
        assert_eq!(
            super::n5_spread(&[7.0]),
            Some((7.0, 7.0)),
            "single value spreads to itself"
        );
        assert_eq!(super::n5_spread(&[]), None, "empty has no spread");
    }

    #[test]
    fn n5_added_subtracts_the_baseline() {
        assert_eq!(
            super::n5_added(1200.0, 1000.0),
            200.0,
            "added is dispatcher-on minus dispatcher-off"
        );
        assert_eq!(
            super::n5_added(900.0, 1000.0),
            -100.0,
            "negative added is scheduling noise, not an error"
        );
    }

    #[test]
    fn n5_run_pct_ratios_added_over_traced() {
        assert_eq!(
            super::n5_run_pct(100.0, 1100.0, 1250.0),
            Some(15.0),
            "150 added over 1000 traced is exactly 15"
        );
        assert_eq!(
            super::n5_run_pct(100.0, 1100.0, 1100.0),
            Some(0.0),
            "zero added is zero percent"
        );
        assert_eq!(
            super::n5_run_pct(1000.0, 1000.0, 1200.0),
            None,
            "zero traced baseline has no ratio"
        );
        assert_eq!(
            super::n5_run_pct(1200.0, 1000.0, 1200.0),
            None,
            "negative traced baseline has no ratio"
        );
    }

    #[test]
    fn n5_verdict_needs_both_budgets() {
        let pass = super::n5_verdict(&[200.0; 5], &[10.0; 5]);
        assert!(pass.pass, "within both budgets passes");
        assert_eq!(pass.median_added_ns, 200.0, "added median");
        assert_eq!(
            (pass.min_added_ns, pass.max_added_ns),
            (200.0, 200.0),
            "added spread"
        );
        assert_eq!(pass.median_pct, 10.0, "pct median");
        assert_eq!((pass.min_pct, pass.max_pct), (10.0, 10.0), "pct spread");
        let over_added = super::n5_verdict(&[300.0, 100.0, 300.0, 100.0, 300.0], &[10.0; 5]);
        assert_eq!(over_added.median_added_ns, 300.0, "added median over 250");
        assert!(!over_added.pass, "median added over budget fails");
        let over_pct = super::n5_verdict(&[200.0; 5], &[30.0, 1.0, 30.0, 1.0, 30.0]);
        assert_eq!(over_pct.median_pct, 30.0, "pct median over 15");
        assert!(!over_pct.pass, "median pct over budget fails");
        let empty = super::n5_verdict(&[], &[]);
        assert!(!empty.pass, "empty inputs never pass");
    }

    #[test]
    fn n5_verdict_boundary_budgets_pass() {
        // Both gates are inclusive: exactly 250 ns and exactly 15%
        // pass.
        let exact = super::n5_verdict(&[250.0; 5], &[15.0; 5]);
        assert!(exact.pass, "exactly the added and pct budgets passes");
    }

    #[test]
    fn n5_check_counts_accepts_exact_counts_only() {
        fn base() -> (super::BankAccount, super::BankControl) {
            let account = super::BankAccount {
                admitted: 1_000_000,
                completed: 1_000_000,
                ..Default::default()
            };
            let control = super::BankControl {
                limit: super::TICKET_LIMIT,
                next_ticket: 1,
                ..Default::default()
            };
            (account, control)
        }
        let (account, control) = base();
        assert!(
            super::n5_check_counts(1_000_000, &account, &control, 1).is_ok(),
            "exact counts pass"
        );
        let mut bad = base();
        bad.0.admitted = 999_999;
        let short = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            short.is_err_and(|reason| reason.contains("admitted")),
            "short admitted names admitted"
        );
        let mut bad = base();
        bad.0.admitted = 1_000_001;
        let over = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            over.is_err_and(|reason| reason.contains("admitted")),
            "over admitted names admitted"
        );
        let mut bad = base();
        bad.0.completed = 999_999;
        let incomplete = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            incomplete.is_err_and(|reason| reason.contains("completed")),
            "missing completions name completed"
        );
        let mut bad = base();
        bad.0.live = 1;
        let live = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            live.is_err_and(|reason| reason.contains("live")),
            "live names live"
        );
        let mut bad = base();
        bad.0.faults = 1;
        let faults = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            faults.is_err_and(|reason| reason.contains("faults")),
            "faults name faults"
        );
        for bucket in ["cookie", "seed", "present", "insert"] {
            let mut bad = base();
            match bucket {
                "cookie" => bad.0.cookie_failures = 1,
                "seed" => bad.0.seed_failures = 1,
                "present" => bad.0.start_present = 1,
                _ => bad.0.start_insert_failures = 1,
            }
            let refused = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
            assert!(
                refused.is_err_and(|reason| reason.contains("failures")),
                "{bucket} refusals name failures"
            );
        }
        let mut bad = base();
        bad.1.next_ticket = 2;
        let extra_ticket = super::n5_check_counts(1_000_000, &bad.0, &bad.1, 1);
        assert!(
            extra_ticket.is_err_and(|reason| reason.contains("next_ticket")),
            "extra ticket names next_ticket"
        );
    }

    #[test]
    fn n5_workload_args_cover_one_and_four_threads() {
        assert_eq!(
            super::n5_workload_args(1),
            Some(vec!["call".to_string(), "1000000".to_string()]),
            "one thread calls 1M times"
        );
        assert_eq!(
            super::n5_workload_args(4),
            Some(vec![
                "threads".to_string(),
                "4".to_string(),
                "250000".to_string()
            ]),
            "four threads split 1M calls"
        );
        for threads in [0, 2, 3, 5, 8] {
            assert_eq!(
                super::n5_workload_args(threads),
                None,
                "no N5 workload for {threads} threads"
            );
        }
    }

    #[test]
    fn n5_elapsed_ns_counts_whole_nanoseconds() {
        assert_eq!(
            super::n5_elapsed_ns(Duration::new(2, 500_000_000)),
            2_500_000_000,
            "seconds plus subsecond nanos"
        );
        assert_eq!(super::n5_elapsed_ns(Duration::ZERO), 0, "zero stays zero");
    }

    #[test]
    fn per_call_overhead_cell_checks_completeness_before_timing() {
        // The N5 cell gates every traced run on exact counts before it
        // times anything: a timing from an incomplete run is never
        // evidence. The traced-run helper orders the completeness
        // check before the ns/call computation; the cell drives it
        // for both traced legs and prints the run, verdict, env and
        // skip lines the E4 script greps.
        let source = include_str!("image_bank_proof.rs");
        let body = fn_body_between(
            source,
            "fn privileged_image_bank_per_call_overhead",
            "fn verifier_tail_keeps_last_60_lines",
        );
        for marker in [
            "P11_BANK_N5_env",
            "P11_BANK_N5_run",
            "P11_BANK_N5_verdict",
            "P11_BANK_N5_SKIP",
        ] {
            assert!(body.contains(marker), "N5 prints {marker}");
        }
        assert!(
            body.contains("multi_functional_probe"),
            "N5 gates on the functional probe, never a version"
        );
        assert!(
            body.contains("attach_direct_entry"),
            "N5 leg b attaches the bank entry directly"
        );
        assert!(
            body.matches("n5_run_traced").count() >= 2,
            "both traced legs run through the completeness gate"
        );
        let helper = fn_body_between(source, "fn n5_run_traced", "fn n5_run_untraced");
        let check = helper
            .find("n5_check_counts")
            .expect("traced runs gate on completeness");
        let timed = helper
            .find("n5_ns_per_call")
            .expect("traced runs compute ns per call");
        assert!(check < timed, "never a timing from an incomplete run");
    }

    #[test]
    fn proof_fixture_override_selects_explicit_path() {
        // A prebuilt fixture carries the E4 Fedora leg (no build on
        // that host): an explicit non-empty override wins,
        // unset/empty falls back to the cell-local build.
        let dir = PathBuf::from("/tmp/n5-cell");
        let explicit = super::resolve_fixture_path(&dir, Some("/tmp/pinned-fixture"));
        assert_eq!(
            explicit,
            PathBuf::from("/tmp/pinned-fixture"),
            "explicit override wins"
        );
        for unset in [None, Some("")] {
            let path = super::resolve_fixture_path(&dir, unset);
            assert_eq!(
                path,
                dir.join("image-bank-fixture"),
                "unset/empty override falls back to the cell build"
            );
        }
    }

    #[test]
    fn direct_entry_attaches_without_reloading() {
        // The N5 dispatcher-off leg attaches the already-loaded slot
        // entry: reloading it would fail AlreadyLoaded at the root
        // run. The entry links through a real multi link (Multi) or
        // aya attach (Singles) with no load of its own; only the
        // return loads here.
        let source = include_str!("image_bank_proof.rs");
        let body = fn_body_between(source, "pub fn attach_direct_entry", "pub fn attach_entry");
        assert_eq!(
            body.matches("attach_group").count(),
            2,
            "direct entry and return multi-link"
        );
        assert_eq!(
            body.matches("load_multi()").count(),
            1,
            "only the return multi-loads; the entry is already loaded"
        );
        assert_eq!(
            body.matches("ret.load()").count(),
            1,
            "the Singles return loads plain"
        );
        assert!(
            !body.contains("probe.load()"),
            "the entry never reloads (AlreadyLoaded)"
        );
        assert!(
            body.contains("probe.attach"),
            "Singles entry keeps aya attach"
        );
    }

    #[test]
    fn select_value_round_trips_flip_and_fixed_words() {
        let value = super::select_value(1, 2, [7, 8]);
        assert_eq!(u64_at(&value, 0), 1, "flip word names bank B");
        assert_eq!(u64_at(&value, 8), 2, "flip word names incarnation 2");
        assert_eq!(u64_at(&value, 16), 7, "slot A keeps fixed 7");
        assert_eq!(u64_at(&value, 24), 8, "slot B keeps fixed 8");
    }

    #[test]
    fn flip_select_word_preserves_fixed_incarnations() {
        let current = super::select_value(0, 1, [1, 0]);
        let flipped = super::flip_select_word(&current, 1, 2);
        assert_eq!(u64_at(&flipped, 0), 1, "flip publishes bank B");
        assert_eq!(u64_at(&flipped, 8), 2, "flip publishes incarnation 2");
        assert_eq!(u64_at(&flipped, 16), 1, "flip keeps fixed A");
        assert_eq!(u64_at(&flipped, 24), 0, "flip keeps fixed B");
    }

    #[test]
    fn set_fixed_word_preserves_flip_word_and_other_slot() {
        let preparing = super::select_value(0, 1, [1, 0]);
        let fixed = super::set_fixed_word(&preparing, 1, 2);
        assert_eq!(u64_at(&fixed, 0), 0, "prepare keeps the flip bank");
        assert_eq!(u64_at(&fixed, 8), 1, "prepare keeps the flip incarnation");
        assert_eq!(u64_at(&fixed, 16), 1, "prepare keeps fixed A");
        assert_eq!(u64_at(&fixed, 24), 2, "prepare sets fixed B");
        let aprime = super::select_value(1, 2, [1, 2]);
        let refixed = super::set_fixed_word(&aprime, 0, 3);
        assert_eq!(u64_at(&refixed, 16), 3, "A-prime replaces fixed A");
        assert_eq!(u64_at(&refixed, 24), 2, "A-prime keeps fixed B");
    }

    #[test]
    fn next_incarnation_advances_past_seen() {
        assert_eq!(super::next_incarnation(&[1, 0]), 2, "B follows A");
        assert_eq!(super::next_incarnation(&[1, 2]), 3, "A-prime follows B");
        assert_eq!(super::next_incarnation(&[3, 2]), 4, "never reuses");
    }

    #[test]
    fn closed_zero_admission_needs_gate_live_and_rows() {
        assert!(
            super::closed_zero_admission(0, 0, 0),
            "drained gate with nothing live and no rows is closed-zero"
        );
        assert!(
            !super::closed_zero_admission(0, 0, 1),
            "a held gate ref blocks closed-zero with nothing else outstanding"
        );
        assert!(
            !super::closed_zero_admission(1, 0, 0),
            "a live call blocks closed-zero"
        );
        assert!(
            !super::closed_zero_admission(0, 1, 0),
            "one START row blocks closed-zero"
        );
        assert!(
            !super::closed_zero_admission(0, 5, 0),
            "rows block closed-zero"
        );
        assert!(
            !super::closed_zero_admission(1, 1, 1),
            "everything outstanding blocks closed-zero"
        );
    }

    #[test]
    fn fresh_bank_admission_clean_fails_any_seed_present_or_insert() {
        let mut account = super::BankAccount {
            admitted: 16384,
            completed: 16384,
            ..Default::default()
        };
        assert!(
            super::fresh_bank_admission_clean("A", &account).is_ok(),
            "exact admissions pass"
        );
        account.cookie_failures = 3;
        assert!(
            super::fresh_bank_admission_clean("A", &account).is_ok(),
            "control-counted creation burns stay allowed"
        );
        account.cookie_failures = 0;
        account.seed_failures = 1;
        let seed = super::fresh_bank_admission_clean("A", &account);
        assert!(
            seed.is_err_and(|reason| reason.contains("seed") && reason.contains('8')),
            "seed failures name the seed code"
        );
        account.seed_failures = 0;
        account.start_present = 1;
        let present = super::fresh_bank_admission_clean("B", &account);
        assert!(
            present.is_err_and(|reason| reason.contains("present")),
            "present failures name present"
        );
        account.start_present = 0;
        account.start_insert_failures = 2;
        account.start_insert_errno = (-(libc::E2BIG as i64)) as u64;
        let insert = super::fresh_bank_admission_clean("B", &account);
        assert!(
            insert.is_err_and(|reason| reason.contains("insert")),
            "insert failures name insert"
        );
    }

    #[test]
    fn n5_run_pct_production_ratios_over_production() {
        assert_eq!(
            super::n5_run_pct_production(150.0, 1000.0),
            Some(15.0),
            "150 added over 1000 production is exactly 15"
        );
        assert_eq!(
            super::n5_run_pct_production(0.0, 1000.0),
            Some(0.0),
            "zero added is zero percent"
        );
        assert_eq!(
            super::n5_run_pct_production(150.0, 0.0),
            None,
            "zero production input has no ratio"
        );
        assert_eq!(
            super::n5_run_pct_production(150.0, -5.0),
            None,
            "negative production input has no ratio"
        );
    }

    #[test]
    fn n5_absolute_only_does_not_qualify_full_cell() {
        // Missing production cost leaves the 15% gate unmeasured even
        // when the independent absolute budget is met, including its
        // inclusive boundary. This must not green the full N5 cell.
        for added in [200.0, 250.0] {
            let verdict = super::n5_verdict_ns_only(&[added; 5]);
            assert!(
                !verdict.pass,
                "absolute-only {added} ns cannot qualify the missing percentage gate"
            );
        }
    }

    #[test]
    fn n5_verdict_ns_only_covers_the_added_gate() {
        let pass = super::n5_verdict_ns_only(&[200.0; 5]);
        assert!(pass.pass, "within the added budget passes");
        assert_eq!(pass.median_added_ns, 200.0, "added median");
        assert_eq!(
            (pass.min_added_ns, pass.max_added_ns),
            (200.0, 200.0),
            "added spread"
        );
        assert!(pass.median_pct.is_nan(), "no pct median without input");
        assert!(
            pass.min_pct.is_nan() && pass.max_pct.is_nan(),
            "no pct spread"
        );
        let over = super::n5_verdict_ns_only(&[300.0, 100.0, 300.0, 100.0, 300.0]);
        assert_eq!(over.median_added_ns, 300.0, "added median over 250");
        assert!(!over.pass, "median added over budget fails");
        let exact = super::n5_verdict_ns_only(&[250.0; 5]);
        assert!(exact.pass, "exactly the added budget passes");
        let empty = super::n5_verdict_ns_only(&[]);
        assert!(!empty.pass, "empty inputs never pass");
    }

    #[test]
    fn n5_production_ns_parses_positive_finite() {
        assert_eq!(
            super::n5_production_ns(Some("123.5")),
            Some(123.5),
            "positive finite parses"
        );
        for var in [None, Some(""), Some("abc"), Some("0"), Some("0.0")] {
            assert_eq!(super::n5_production_ns(var), None, "no ratio for {var:?}");
        }
        for var in [Some("-3"), Some("nan"), Some("NaN"), Some("inf")] {
            assert_eq!(super::n5_production_ns(var), None, "no ratio for {var:?}");
        }
    }

    #[test]
    fn inflight_total_calls_counts_warmup_and_free() {
        assert_eq!(super::INFLIGHT_WARMUP, 100, "100 warmup calls per thread");
        assert_eq!(super::INFLIGHT_CALLS, 10000, "10k free calls per thread");
        assert_eq!(super::INFLIGHT_THREADS, 4, "4 threads per phase");
        assert_eq!(
            super::inflight_total_calls(4),
            40400,
            "4 threads times warmup plus free calls"
        );
        assert_eq!(super::inflight_total_calls(1), 10100, "one thread total");
    }

    #[test]
    fn bank_select_carries_fixed_slot_incarnations() {
        // The flip word (bank, incarnation) moves under admissions, so
        // each bank entry stamps its slot's fixed incarnation instead.
        // SELECT carries both: words 0-1 flip, words 2-3 are written at
        // prepare while the slot is empty or reclaimed, never live.
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let start = native
            .find("struct bank_select {")
            .expect("select struct present");
        let tail = native[start..].find("};").expect("select struct ends");
        let body = &native[start..start + tail];
        assert!(
            body.contains("fixed_inc[2]"),
            "SELECT carries one fixed incarnation per slot"
        );
        assert!(
            native.contains("_Static_assert(sizeof(struct bank_select) == 32"),
            "SELECT ABI is 32 bytes"
        );
    }

    #[test]
    fn bank_gate_is_per_bank() {
        // One gate word per bank (no new map): a selected call holds
        // its bank's ref until it admits or backs out, and closed-zero
        // waits for that bank's word to drain.
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let at = native.find("} BANK_GATE").expect("gate map present");
        let window = &native[at.saturating_sub(300)..at];
        assert!(
            window.contains("max_entries, 2"),
            "BANK_GATE holds one word per bank"
        );
    }

    #[test]
    fn bank_select_takes_a_per_bank_ref_and_rechecks() {
        // Select reads the flip word, takes that bank's gate ref,
        // re-reads, and on any bank or incarnation change releases
        // and retries (bounded), refusing past the bound. A call
        // racing one flip still admits (into the current bank); a
        // torn or stale read never mints a ref for the wrong bank.
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let body = fn_body_between(native, "u32 p11_bank_select(", "u32 p11_bank_gate_release(");
        assert!(
            body.contains("BANK_SELECT_TRIES"),
            "select retries across a flip under a named bound"
        );
        assert!(
            body.contains("u32 key = (u32)bank"),
            "select takes the ref on the bank it read"
        );
        assert!(
            body.contains("bank_increment(gate)"),
            "select takes a gate ref"
        );
        assert!(
            body.contains("bank_decrement(gate)"),
            "select backs its ref out on change"
        );
        assert!(
            body.matches("select->bank").count() >= 2,
            "select reads the bank, then re-reads it"
        );
        assert!(
            body.matches("select->incarnation").count() >= 2,
            "select reads the incarnation, then re-reads it"
        );
    }

    #[test]
    fn bank_gate_release_takes_the_serving_slot() {
        // The tail-call-failure path releases exactly the ref its
        // select took: the serving bank travels from select's return
        // into the release, so a per-bank gate never unbalances.
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        assert!(
            native.contains("u32 p11_bank_gate_release(u32 slot)"),
            "the release core takes the serving slot"
        );
        let roots = include_str!("../../crates/ebpf/src/image_bank_proof.rs");
        assert!(
            roots.contains("fn p11_bank_gate_release(slot: u32)"),
            "the dispatcher roots declare the slotted release"
        );
        assert!(
            roots.contains("p11_bank_gate_release(slot)"),
            "the dispatcher releases the selected slot on tail-call failure"
        );
    }

    #[test]
    fn enter_cores_stamp_the_fixed_slot_incarnation() {
        // The bank-switch race: an entry that reads the flip word's
        // incarnation at admission stamps a route its bank never
        // owned once a flip lands first. Each enter core stamps its
        // slot's fixed word; only the selecting paths read the flip
        // incarnation (to validate it, never to stamp it).
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let start_a = native
            .find("u32 p11_bank_enter_a(")
            .expect("enter A present");
        let start_b = native
            .find("u32 p11_bank_enter_b(")
            .expect("enter B present");
        let end = native
            .find("u32 p11_bank_complete(")
            .expect("enter cores end");
        for (name, body) in [
            ("enter_a", &native[start_a..start_b]),
            ("enter_b", &native[start_b..end]),
        ] {
            assert!(
                body.contains("fixed_inc[slot]"),
                "{name} stamps its slot's fixed incarnation"
            );
            assert!(
                !body.contains("->incarnation"),
                "{name} never reads the flip word's incarnation"
            );
        }
        for (name, start, end) in [
            (
                "select",
                "u32 p11_bank_select(",
                "u32 p11_bank_gate_release(",
            ),
            (
                "birth dispatcher",
                "int p11_bank_disp_birth(",
                "int p11_bank_birth_a(",
            ),
        ] {
            let body = fn_body_between(native, start, end);
            assert!(
                body.contains("->incarnation"),
                "{name} still validates the flip incarnation (non-vacuous fence)"
            );
        }
    }

    #[test]
    fn birth_dispatcher_rechecks_before_tail_call() {
        // Births route like entries: the birth dispatcher takes the
        // read bank's ref and rechecks, so a birth racing the flip
        // spends the current bank's ticket, never the stale bank's.
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        let body = fn_body_between(native, "int p11_bank_disp_birth(", "int p11_bank_birth_a(");
        assert!(
            body.contains("BANK_SELECT_TRIES"),
            "the birth dispatcher retries across a flip under the same bound"
        );
        assert!(
            body.matches("select->bank").count() >= 2,
            "the birth dispatcher reads the bank, then re-reads it"
        );
        assert!(
            body.matches("select->incarnation").count() >= 2,
            "the birth dispatcher reads the incarnation, then re-reads it"
        );
    }

    #[test]
    fn closed_zero_waits_for_the_gate_to_drain() {
        // A call sitting between select and its START insert holds no
        // live ref and no row yet: without the gate, its bank reads
        // closed-zero under it and a successor reuses the account row.
        let source = include_str!("image_bank_proof.rs");
        let body = fn_body_between(source, "pub fn closed_zero(", "pub fn reclaim(");
        assert!(
            body.contains("closed_zero_admission"),
            "closed-zero decides through the admission predicate"
        );
        assert!(
            body.contains("self.gate(slot)"),
            "closed-zero waits for its bank's gate to drain"
        );
    }

    #[test]
    fn n6_n7_fail_seed_present_insert_on_a_fresh_bank() {
        // Fresh under-capacity banks admit cleanly: any seed, present
        // or insert failure fails N6/N7 by name instead of hiding in
        // the burn ledger (the old object shows its private-stack seed
        // failures here; the control run proves it).
        let source = include_str!("image_bank_proof.rs");
        let n6 = fn_body_between(
            source,
            "fn privileged_image_bank_exhaustion_16384_then_quota",
            "fn privileged_image_bank_cut_16385th_leader_in_b",
        );
        assert!(
            n6.contains("fresh_bank_admission_clean"),
            "N6 fails seed/present/insert on its fresh bank"
        );
        let n7 = fn_body_between(
            source,
            "fn privileged_image_bank_cut_16385th_leader_in_b",
            "fn privileged_image_bank_concurrent_cut_counts_once",
        );
        assert!(
            n7.matches("fresh_bank_admission_clean").count() >= 2,
            "N7 checks both banks"
        );
    }

    #[test]
    fn admission_failure_line_records_the_seed_code() {
        // Every admission-failure evidence line records the status the
        // enter cores return for a seed failure, so a seed count is
        // never a bare number.
        let source = include_str!("image_bank_proof.rs");
        // Needles built at runtime so this pin's own text never
        // satisfies them: every admission-failure evidence line
        // records the seed code.
        let bank_marker: String = ["P11_BANK_ADMISSION_FAILURES", " bank="].concat();
        let code_marker: String = ["seed_status", "="].concat();
        let lines = source.matches(bank_marker.as_str()).count();
        let coded = source.matches(code_marker.as_str()).count();
        assert!(lines > 0, "admission-failure lines exist");
        assert_eq!(
            coded, lines,
            "every admission-failure line records the seed code"
        );
        assert_eq!(
            super::SEED_FAILURE_STATUS,
            8,
            "the recorded code is COOKIE_STATUS_ZERO_CELL"
        );
        let native = include_str!("../../crates/ebpf/native/image_bank_proof.c");
        assert!(
            native
                .matches("BANK_FAIL_SEED, 0, COOKIE_STATUS_ZERO_CELL")
                .count()
                == 2,
            "both enter cores return ZERO_CELL for a seed failure"
        );
        let header = include_str!("../../crates/ebpf/native/image_identity.h");
        assert!(
            header.contains("COOKIE_STATUS_ZERO_CELL = 8"),
            "ZERO_CELL is status 8"
        );
    }

    #[test]
    fn prepare_assigns_and_flip_publishes_the_fixed_incarnation() {
        // The fixed word is written at prepare (slot empty or
        // reclaimed, nothing in flight) and verified at flip before
        // the flip word moves; the bank entry stamps it from then on.
        let source = include_str!("image_bank_proof.rs");
        let prepare = fn_body_between(source, "pub fn prepare(", "pub fn flip(");
        assert!(
            prepare.contains("fixed"),
            "prepare assigns the slot's fixed incarnation"
        );
        let flip = fn_body_between(source, "pub fn flip(", "pub fn closed_zero(");
        assert!(
            flip.contains("fixed"),
            "flip publishes only the prepared fixed incarnation"
        );
    }

    #[test]
    fn n5_off_leg_pre_takes_its_gate_and_balances() {
        // The dispatcher-off leg runs the same bank work with a
        // consistent gate: it pre-takes exactly the run's releases up
        // front (no wrapped gate from an entry that never took a
        // ref), and both gates end at 0 in every traced leg.
        let source = include_str!("image_bank_proof.rs");
        let body = fn_body_between(
            source,
            "fn privileged_image_bank_per_call_overhead",
            "fn verifier_tail_keeps_last_60_lines",
        );
        assert!(
            body.contains("pre_take_gate"),
            "the off leg pre-takes its gate"
        );
        assert!(
            body.matches("gate(1)").count() >= 2,
            "both traced legs assert the idle bank's gate too"
        );
    }

    #[test]
    fn n5_cell_reports_production_pct_or_not_computed() {
        // The 15% denominator is the production traced per-call cost
        // (bench method on the same host and window), taken as an
        // input per thread count; without it the cell prints its ns
        // numbers with a named not-computed line and gates 250 ns.
        let source = include_str!("image_bank_proof.rs");
        let body = fn_body_between(
            source,
            "fn privileged_image_bank_per_call_overhead",
            "fn verifier_tail_keeps_last_60_lines",
        );
        assert!(
            body.contains("N5_PRODUCTION_ENV_1") && body.contains("N5_PRODUCTION_ENV_4"),
            "the cell takes the production cost per thread count"
        );
        assert!(
            body.contains("P11_BANK_N5_pct") && body.contains("not-computed"),
            "the cell reports a named not-computed pct without input"
        );
    }

    #[test]
    fn inflight_phase_cuts_with_calls_in_flight() {
        // The in-flight N8 variant cuts while threads are actively
        // calling (no barrier pause): exact counts split across both
        // banks (each serves some), nothing double-counted, gates
        // balanced, on Singles and on Multi.
        let source = include_str!("image_bank_proof.rs");
        let phase = fn_body_between(
            source,
            "fn run_inflight_phase(",
            "fn privileged_image_bank_inflight_cut_counts_once",
        );
        for marker in ["inflight", "STARTED", "flip", "gate(0)", "gate(1)"] {
            assert!(phase.contains(marker), "the phase drives {marker}");
        }
        let cell = fn_body_between(
            source,
            "fn privileged_image_bank_inflight_cut_counts_once",
            "fn privileged_image_bank_per_call_overhead",
        );
        assert!(
            cell.matches("run_inflight_phase").count() >= 2,
            "the cell cuts once per backend"
        );
        assert!(
            cell.contains("Backend::Singles") && cell.contains("Backend::Multi"),
            "the cell covers Singles and Multi"
        );
        assert!(
            cell.contains("multi_functional_probe"),
            "the Multi phase gates on the functional probe"
        );
    }

    #[test]
    fn inflight_fixture_calls_through_the_cut() {
        // The fixture's inflight mode warms up, prints STARTED once
        // every thread is past warmup, then calls free (no stdin
        // pause) so the controller's flip lands mid-run.
        assert!(
            super::FIXTURE_SOURCE.contains("inflight"),
            "the fixture has an inflight mode"
        );
        assert!(
            super::FIXTURE_SOURCE.contains("STARTED"),
            "the fixture signals past-warmup"
        );
        assert!(
            super::FIXTURE_SOURCE.contains("#define INFLIGHT_WARMUP 100"),
            "the fixture warmup matches INFLIGHT_WARMUP"
        );
    }

    /// The inflight fixture mode runs free past STARTED (no stdin
    /// pause) and exits cleanly; exercises the mode the in-flight
    /// N8 phase drives.
    #[test]
    fn inflight_fixture_runs_free_past_started() {
        let dir = std::env::temp_dir().join(format!("p11-bank-inflight-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("inflight test dir");
        let fixture = super::compile_fixture(&dir).expect("compile fixture");
        let output = std::process::Command::new(&fixture)
            .args(["inflight", "2", "200"])
            .output()
            .expect("run inflight");
        assert!(
            output.status.success(),
            "inflight exits 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.lines().collect::<Vec<_>>(),
            ["STARTED", "DONE"],
            "inflight signals past-warmup, then finishes"
        );
    }

    #[test]
    fn proof_fixture_identity_names_resolved_path() {
        // compile_fixture honors the override (staged prebuilt) or
        // compiles under the cell dir by default; run with
        // P11SCOPE_IMAGE_BANK_PROOF_FIXTURE set to cover the override
        // branch the way the object identity test does.
        let dir = super::cell_dir("n5-fixture-identity").expect("cell dir");
        let path = super::compile_fixture(&dir).expect("fixture resolves");
        match std::env::var(super::PROOF_FIXTURE_OVERRIDE_ENV)
            .ok()
            .filter(|pinned| !pinned.is_empty())
        {
            Some(pinned) => assert_eq!(path, PathBuf::from(pinned), "identity names the override"),
            None => {
                assert!(path.starts_with(&dir), "default builds under the cell dir");
                assert!(path.is_file(), "default build exists");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
