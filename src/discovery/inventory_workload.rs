//! SPDX-License-Identifier: GPL-3.0-or-later
//! The reusable inventory workload harness (Phase 4 breadth).
//!
//! ONE harness for every scale, churn, and failure workload. A workload
//! is a [`ScaleSpec`] (or churn/failure script) plus its exact [`Ledger`];
//! the JSON backend drives the REAL coordinator path — adapter
//! reconcile/admit, registry staging, [`InventoryCoordinator::commit_batch`],
//! [`render_json`](crate::inventory::render_json) — and the assertion API
//! checks the rendered document against the ledger.
//!
//! The spec/ledger/assertion API is public and stable: integration
//! tests drive it against real `p11scope inventory` output, and the
//! U-track (dashboard) and S-track (semantics) replay the SAME
//! workloads later through their own backends. The JSON backend here
//! depends on neither dashboard nor semantic code.
//!
//! E1 decision: replay is in-crate — the S-track
//! ([`crate::semantics`]) already lives in this crate and the U-track
//! dashboard lands here too — so the scripted execution backend
//! (`ScriptedSource`, `ChurnSpec`, `Harness`) is `#[cfg(test)]`-gated:
//! unit tests pin it, no external bench replays it, and no
//! `allow(dead_code)` carries it in production builds.
//!
//! Unit vocabulary (no conflation): attach *endpoints* project into
//! inventory as per-module `admission.endpoints`, summed into the
//! `endpoints` budget; inventory *edges* are (caller, module) pairs.
//! `owners` on the inventory side are caller incarnations — each owns
//! its usage evidence — with native engine owners 1:1 behind native
//! callers.

#[cfg(test)]
use crate::attach::Scope;
#[cfg(test)]
use crate::discovery::caller_registry::{
    AdmissionState, CallerEvent, CallerId, ExeIdentity, ImageAuthority, ModuleInfo, ModuleKey,
    ProcessSource, RegistryLimits,
};
#[cfg(test)]
use crate::discovery::engine::inventory::UnavailableImageGuard;
#[cfg(test)]
use crate::discovery::engine::inventory_coordinator::{
    BatchReceipt, InventoryCoordinator, PassReport,
};
#[cfg(test)]
use crate::discovery::hooks::HookRegistry;
#[cfg(test)]
use crate::semantics_edge::SemanticCall;
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet, HashSet};
#[cfg(test)]
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Public spec/ledger/assertion API (stable for U/S-track replay).
// ---------------------------------------------------------------------------

/// One scale workload: `callers` caller incarnations each mapping
/// `edges_per_caller` of `modules` modules (striped layout, exact and
/// deterministic — see [`ScaleSpec::layout`]). Every module is admitted
/// with `endpoints_per_module` attach endpoints. Requires
/// `edges_per_caller <= modules` (each caller maps distinct modules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleSpec {
    pub name: &'static str,
    pub callers: usize,
    pub modules: usize,
    pub edges_per_caller: usize,
    pub endpoints_per_module: usize,
    pub first_pid: u32,
}

impl ScaleSpec {
    /// The exact (caller index, module index) pairs the workload stages:
    /// caller `i` maps modules `(i * edges_per_caller + k) % modules`
    /// for `k` in `0..edges_per_caller`. Every pair is distinct, so the
    /// edge count is exactly `callers * edges_per_caller`.
    pub fn layout(&self) -> Vec<(usize, usize)> {
        assert!(
            self.edges_per_caller <= self.modules,
            "edges_per_caller must not exceed modules ({} > {})",
            self.edges_per_caller,
            self.modules,
        );
        let mut pairs = Vec::with_capacity(self.callers * self.edges_per_caller);
        for caller in 0..self.callers {
            for k in 0..self.edges_per_caller {
                pairs.push((caller, (caller * self.edges_per_caller + k) % self.modules));
            }
        }
        pairs
    }

    /// The exact ledger of a refusal-free run: admitted callers,
    /// modules touched by the layout, edges, and the endpoint census.
    /// Over-budget runs derive their ledgers by hand (see the B-track
    /// tests), never by editing this function.
    pub fn expected_ledger(&self) -> Ledger {
        let layout = self.layout();
        let modules: BTreeSet<usize> = layout.iter().map(|(_, module)| *module).collect();
        Ledger {
            callers: self.callers as u64,
            modules: modules.len() as u64,
            edges: layout.len() as u64,
            endpoints: (modules.len() * self.endpoints_per_module) as u64,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(0),
            gaps_suppressed: 0,
        }
    }
}

/// The exact expected outcome of one workload: admitted/retained counts
/// plus per-resource refusals. `gaps` is `Some` only where the gap count
/// is deterministic (scripted runs); command-level runs over a live
/// machine leave it `None` and pin `gaps_suppressed` plus settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub callers: u64,
    pub modules: u64,
    pub edges: u64,
    pub endpoints: u64,
    pub callers_refused: u64,
    pub modules_refused: u64,
    pub edges_refused: u64,
    pub endpoints_refused: u64,
    pub gaps: Option<usize>,
    pub gaps_suppressed: u64,
}

/// Assert the rendered document carries exactly the ledger: array
/// lengths, per-resource budgets (limit/occupied/refused), the endpoint
/// census recomputed independently from the modules, unknown semantic
/// columns on every edge, and gap accounting.
pub fn assert_ledger(document: &serde_json::Value, ledger: &Ledger) {
    assert_eq!(document["schema"], "p11scope/inventory/v1");
    let callers = document["callers"].as_array().expect("callers array");
    let modules = document["modules"].as_array().expect("modules array");
    let edges = document["edges"].as_array().expect("edges array");
    assert_eq!(callers.len() as u64, ledger.callers, "caller ledger");
    assert_eq!(modules.len() as u64, ledger.modules, "module ledger");
    assert_eq!(edges.len() as u64, ledger.edges, "edge ledger");
    // The endpoint census, recomputed from the document — not trusted
    // from the budgets row.
    let mut census: u64 = 0;
    for module in modules {
        if module["admission"]["state"] == "admitted"
            && let Some(endpoints) = module["admission"]["endpoints"].as_u64()
        {
            census += endpoints;
        }
    }
    assert_eq!(census, ledger.endpoints, "endpoint census");
    assert_eq!(document["budgets"]["endpoints"]["occupied"], census);
    assert_eq!(
        document["budgets"]["callers"]["occupied"], ledger.callers,
        "caller occupancy",
    );
    assert_eq!(
        document["budgets"]["modules"]["occupied"], ledger.modules,
        "module occupancy",
    );
    assert_eq!(
        document["budgets"]["edges"]["occupied"], ledger.edges,
        "edge occupancy",
    );
    assert_eq!(
        document["budgets"]["callers"]["refused"].as_u64().unwrap(),
        ledger.callers_refused,
        "caller refusals",
    );
    assert_eq!(
        document["budgets"]["modules"]["refused"].as_u64().unwrap(),
        ledger.modules_refused,
        "module refusals",
    );
    assert_eq!(
        document["budgets"]["edges"]["refused"].as_u64().unwrap(),
        ledger.edges_refused,
        "edge refusals",
    );
    assert_eq!(
        document["budgets"]["endpoints"]["refused"]
            .as_u64()
            .unwrap(),
        ledger.endpoints_refused,
        "endpoint refusals",
    );
    // Semantic capture stays withheld: unknown on every edge, zero
    // occupancy in the budget row.
    for edge in edges {
        assert_eq!(
            edge["semantics"], "unknown (semantic capture withheld)",
            "semantic column for {} -> {}",
            edge["caller"], edge["module"],
        );
    }
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 0);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "withheld",);
    assert_eq!(
        document["budgets"]["semantic_state"]["unknown_edges"]
            .as_u64()
            .unwrap(),
        ledger.edges,
        "edges lacking semantic state",
    );
    if let Some(gaps) = ledger.gaps {
        assert_eq!(
            document["gaps"].as_array().unwrap().len(),
            gaps,
            "retained gaps"
        );
    }
    assert_eq!(
        document["gaps_suppressed"].as_u64().unwrap(),
        ledger.gaps_suppressed,
        "suppressed gaps",
    );
    assert_eq!(
        document["budgets"]["retained_history"]["suppressed"]
            .as_u64()
            .unwrap(),
        ledger.gaps_suppressed,
        "retained-history loss counter",
    );
}

/// Assert terminal settlement structurally: every admitted caller,
/// module, and edge is either live-with-evidence or retired-with-reason,
/// every edge endpoint resolves, and `gaps_suppressed` is exact.
/// Structural, never by example-count.
pub fn assert_settled(document: &serde_json::Value, expected_suppressed: u64) {
    let callers = document["callers"].as_array().expect("callers array");
    let modules = document["modules"].as_array().expect("modules array");
    let edges = document["edges"].as_array().expect("edges array");
    let caller_ids: HashSet<&str> = callers
        .iter()
        .map(|caller| caller["id"].as_str().unwrap())
        .collect();
    let module_ids: HashSet<&str> = modules
        .iter()
        .map(|module| module["id"].as_str().unwrap())
        .collect();
    assert_eq!(caller_ids.len(), callers.len(), "caller ids are unique");
    assert_eq!(module_ids.len(), modules.len(), "module ids are unique");
    for caller in callers {
        let lifecycle = caller["lifecycle"].as_str().unwrap();
        assert!(
            ["mapped", "exited", "exec_retired", "unknown"].contains(&lifecycle),
            "known caller lifecycle for {}",
            caller["id"],
        );
        if lifecycle == "mapped" {
            assert_eq!(
                caller["retired"], false,
                "live caller {} is not retired",
                caller["id"],
            );
        } else {
            assert_eq!(
                caller["retired"], true,
                "retired caller {} is marked",
                caller["id"],
            );
            assert!(
                caller["lifecycle_reason"].is_string(),
                "retired caller {} names its reason",
                caller["id"],
            );
        }
        assert!(
            caller["first_seen_ns"].as_u64().unwrap() <= caller["last_seen_ns"].as_u64().unwrap(),
            "caller {} last-seen never precedes first-seen",
            caller["id"],
        );
    }
    for module in modules {
        let lifecycle = module["lifecycle"].as_str().unwrap();
        assert!(
            ["mapped", "unloaded", "unknown"].contains(&lifecycle),
            "known module lifecycle for {}",
            module["id"],
        );
        if lifecycle == "unloaded" {
            assert_eq!(
                module["unloaded_observed"], true,
                "unloaded module {} retains its unload proof",
                module["id"],
            );
        }
    }
    for edge in edges {
        assert!(
            caller_ids.contains(edge["caller"].as_str().unwrap()),
            "edge caller {} resolves",
            edge["caller"],
        );
        assert!(
            module_ids.contains(edge["module"].as_str().unwrap()),
            "edge module {} resolves",
            edge["module"],
        );
        let mapping = edge["mapping"]["state"].as_str().unwrap();
        assert!(
            ["mapped", "ended", "uncertain"].contains(&mapping),
            "known mapping state for {} -> {}",
            edge["caller"],
            edge["module"],
        );
        if mapping == "ended" {
            assert!(
                edge["mapping"]["reason"].is_string(),
                "ended edge {} -> {} names its reason",
                edge["caller"],
                edge["module"],
            );
        }
        assert!(
            edge["entries"]["count"].is_number(),
            "edge {} -> {} carries a count",
            edge["caller"],
            edge["module"],
        );
        assert_eq!(
            edge["semantics"], "unknown (semantic capture withheld)",
            "semantic column for {} -> {}",
            edge["caller"], edge["module"],
        );
    }
    for gap in document["gaps"].as_array().expect("gaps array") {
        assert!(
            gap["subject"].is_string() && gap["reason"].is_string(),
            "every gap names its subject and reason",
        );
        if gap["budget"].is_null() {
            continue;
        }
        assert!(
            gap["budget"]["resource"].is_string()
                && gap["budget"]["limit"].is_number()
                && gap["budget"]["requested"].is_number(),
            "refusal gaps name resource, limit, and requested",
        );
    }
    assert_eq!(
        document["gaps_suppressed"].as_u64().unwrap(),
        expected_suppressed,
        "suppressed gaps are exact",
    );
}

/// Assert the exact edge ledger for an owned subset of a command-level
/// document: callers filtered by pid, modules by `.so` basename, edges
/// among them — every one mapped. The rest of the machine may appear in
/// the document; only the owned subset is pinned.
pub fn assert_subset_ledger(
    document: &serde_json::Value,
    pids: &[u32],
    sonames: &[&str],
    expected_edges: usize,
) {
    let pid_set: HashSet<u64> = pids.iter().map(|pid| u64::from(*pid)).collect();
    let caller_ids: HashSet<&str> = document["callers"]
        .as_array()
        .expect("callers array")
        .iter()
        .filter(|caller| pid_set.contains(&caller["pid"].as_u64().unwrap()))
        .map(|caller| caller["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        caller_ids.len(),
        pids.len(),
        "one incarnation per owned pid",
    );
    let module_ids: HashSet<&str> = document["modules"]
        .as_array()
        .expect("modules array")
        .iter()
        .filter(|module| {
            module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| sonames.contains(&basename(path.as_str().unwrap())))
        })
        .map(|module| module["id"].as_str().unwrap())
        .collect();
    assert_eq!(module_ids.len(), sonames.len(), "one module per owned .so");
    let owned: Vec<&serde_json::Value> = document["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .filter(|edge| {
            caller_ids.contains(edge["caller"].as_str().unwrap())
                && module_ids.contains(edge["module"].as_str().unwrap())
        })
        .collect();
    assert_eq!(owned.len(), expected_edges, "owned edge ledger");
    for edge in owned {
        assert_eq!(
            edge["mapping"]["state"], "mapped",
            "owned edge {} -> {} is mapped",
            edge["caller"], edge["module"],
        );
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Live file-descriptor census of this process (`/proc/self/fd`).
/// Failure-injection tests assert a zero (or exactly accounted) delta
/// across the injection.
pub fn count_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd is readable")
        .count()
}

/// Resident set size in bytes (`/proc/self/statm`).
pub fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("/proc/self/statm is readable");
    let resident_pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .expect("statm carries resident pages")
        .parse()
        .expect("resident pages parse");
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page > 0, "page size is positive");
    resident_pages.saturating_mul(page as u64)
}

/// Owned-FD census: pidfds this process retains for exactly `pids`.
///
/// The all-FD census counts every parallel test's transients; the
/// growth test needs its OWN pins only. Each `/proc/self/fd` entry
/// whose readlink is `anon_inode:[pidfd]` resolves through its fdinfo
/// `Pid:` line, so foreign pipes, sockets, eventfds — and foreign
/// tests' pidfds for other pids — cannot move the needle. Entries
/// that vanish mid-census (a parallel thread's transient) are
/// skipped, never counted; owned pins are retained, so every sample
/// sees all of them.
pub fn count_owned_pidfds(pids: &BTreeSet<u32>) -> usize {
    let mut owned = 0;
    for entry in std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd is readable")
        .flatten()
    {
        let path = entry.path();
        let is_pidfd = std::fs::read_link(&path)
            .is_ok_and(|target| target.to_string_lossy() == "anon_inode:[pidfd]");
        if !is_pidfd {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Ok(fdinfo) = std::fs::read_to_string(format!("/proc/self/fdinfo/{name}")) else {
            continue;
        };
        let pid = fdinfo.lines().find_map(|line| {
            line.strip_prefix("Pid:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|pid| pid.parse::<u32>().ok())
        });
        if pid.is_some_and(|pid| pids.contains(&pid)) {
            owned += 1;
        }
    }
    owned
}

/// An FD-measurement scope for an owned process: retain the baseline
/// resources and assert the exact number of added descriptors. Each
/// census retries until two consecutive attempts agree, so transient
/// churn from other threads (harness capture setup/teardown at test
/// boundaries) cannot fail the scope; sustained concurrent mutation
/// fails loudly instead of reporting a torn census. Stable resource
/// fingerprints do not prove open-file-description identity; closing
/// and reopening the same resource may be indistinguishable.
pub struct FdScope {
    before: BTreeMap<i32, FdResource>,
    label: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct FdResource {
    link: std::path::PathBuf,
    dev: u64,
    ino: u64,
    mode: u32,
    rdev: u64,
    pidfd_target: Option<i32>,
}

/// One FD census attempt: enumerate `/proc/self/fd`, then resolve every
/// entry. An entry that vanishes between enumeration and resolution (a
/// concurrent close on another thread) is skipped, never counted; any
/// other error stays hard.
fn fd_resources_attempt() -> std::io::Result<BTreeMap<i32, FdResource>> {
    use std::os::unix::fs::MetadataExt as _;

    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this guard owns the one opendir result.
            unsafe { libc::closedir(self.0) };
        }
    }
    // SAFETY: a static terminated path; ownership moves immediately to guard.
    let raw = unsafe { libc::opendir(c"/proc/self/fd".as_ptr()) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let directory = Directory(raw);
    // SAFETY: the directory is live and remains owned through enumeration.
    let census_fd = unsafe { libc::dirfd(directory.0) };
    if census_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut descriptors = BTreeSet::new();
    loop {
        // SAFETY: errno is thread-local; readdir uses this live DIR and its
        // returned entry remains valid until the next call on this DIR.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(directory.0)
        };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        // SAFETY: readdir returned a valid, terminated d_name.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let fd = name
            .to_str()
            .ok()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or_else(|| std::io::Error::other("non-descriptor in /proc/self/fd"))?;
        if fd != census_fd && !descriptors.insert(fd) {
            return Err(std::io::Error::other("duplicate descriptor in FD census"));
        }
    }
    // Finish enumeration before temporary fdinfo readers can affect it.
    // Only the positively identified directory FD is excluded. Entries
    // that vanish while resolving were closed concurrently; skipping
    // them keeps this attempt usable, and the quiescence loop below
    // retries until two consecutive attempts agree.
    let mut resources = BTreeMap::new();
    for fd in descriptors {
        let path = format!("/proc/self/fd/{fd}");
        let link = match std::fs::read_link(&path) {
            Ok(link) => link,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let pidfd_target = if link == std::path::Path::new("anon_inode:[pidfd]") {
            let info = match std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) {
                Ok(info) => info,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            Some(
                info.lines()
                    .find_map(|line| line.strip_prefix("Pid:"))
                    .and_then(|pid| pid.trim().parse().ok())
                    .ok_or_else(|| std::io::Error::other("pidfd census lacks target identity"))?,
            )
        } else {
            None
        };
        resources.insert(
            fd,
            FdResource {
                link,
                dev: metadata.dev(),
                ino: metadata.ino(),
                mode: metadata.mode(),
                rdev: metadata.rdev(),
                pidfd_target,
            },
        );
    }
    Ok(resources)
}

/// Census attempts until two consecutive attempts agree, so a burst of
/// concurrent descriptor churn (harness capture setup/teardown at test
/// boundaries) cannot fail the scope. A hard attempt error resets the
/// streak; when nothing ever agrees the last error (or a never-quiesced
/// marker) reports instead of a torn census.
const FD_CENSUS_QUIESCE_ATTEMPTS: u32 = 100;

fn quiesce_census<F>(mut attempt: F) -> std::io::Result<BTreeMap<i32, FdResource>>
where
    F: FnMut() -> std::io::Result<BTreeMap<i32, FdResource>>,
{
    let mut previous: Option<BTreeMap<i32, FdResource>> = None;
    let mut last_error = std::io::Error::other("FD census never quiesced");
    for _ in 0..FD_CENSUS_QUIESCE_ATTEMPTS {
        match attempt() {
            Ok(map) => {
                if previous.as_ref() == Some(&map) {
                    return Ok(map);
                }
                previous = Some(map);
            }
            Err(error) => {
                last_error = error;
                previous = None;
            }
        }
    }
    Err(last_error)
}

fn fd_resources_quiesced() -> std::io::Result<BTreeMap<i32, FdResource>> {
    quiesce_census(fd_resources_attempt)
}

/// The retained-FD floor: the minimum census over ten 10ms samples.
/// This is a sampling statistic, not ownership evidence: unrelated resources
/// can survive the whole window. Use FdScope only with its isolation premise,
/// or the owned-pidfd census when that narrower obligation is sufficient.
pub fn count_fds_floor() -> usize {
    let mut floor = usize::MAX;
    for _ in 0..10 {
        floor = floor.min(count_fds());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    floor
}

/// The owned-pidfd floor: the minimum owned census over ten 10ms
/// samples, mirroring [`count_fds_floor`]. Retained pins appear in
/// every sample; nothing else can.
pub fn count_owned_pidfds_floor(pids: &BTreeSet<u32>) -> usize {
    let mut floor = usize::MAX;
    for _ in 0..10 {
        floor = floor.min(count_owned_pidfds(pids));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    floor
}

impl FdScope {
    pub fn open(label: &'static str) -> Self {
        Self {
            before: fd_resources_quiesced().expect("complete baseline FD census"),
            label,
        }
    }

    pub fn assert_delta(&self, expected: usize) {
        let after = fd_resources_quiesced().expect("complete final FD census");
        for (fd, resource) in &self.before {
            assert_eq!(
                after.get(fd),
                Some(resource),
                "baseline FD {fd} changed across {}",
                self.label,
            );
        }
        assert_eq!(
            after.len(),
            self.before
                .len()
                .checked_add(expected)
                .expect("FD count bound"),
            "FD delta across {}",
            self.label,
        );
    }
}

/// Peak RSS of this process in bytes (`VmHWM` from `/proc/self/status`).
/// The RSS worker prints it; the parent test asserts the bound.
pub fn peak_rss_bytes() -> u64 {
    let status =
        std::fs::read_to_string("/proc/self/status").expect("/proc/self/status is readable");
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .expect("status carries VmHWM");
    let kb: u64 = line
        .split_whitespace()
        .nth(1)
        .expect("VmHWM carries kB")
        .parse()
        .expect("VmHWM parses");
    kb.saturating_mul(1024)
}

// ---------------------------------------------------------------------------
// Scripted JSON backend (in-crate, test-gated per the E1 decision
// above): the real coordinator path, programmed pids.
// ---------------------------------------------------------------------------

/// One programmed process: liveness, start-time, exe identity, and
/// whether identity reads succeed (a race or permission wall blinds
/// them while liveness still answers).
#[cfg(test)]
#[derive(Debug, Clone)]
struct ScriptedProcess {
    alive: bool,
    start_time: u64,
    exe: Option<ExeIdentity>,
    readable: bool,
}

/// Scripted process source: the pid/exit/reuse/exec/admission-failure
/// sequence is programmed, never observed from the host. Pins capture
/// the start-time they opened. Cloned handles share one script.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct ScriptedSource {
    state: Rc<RefCell<HashMap<u32, ScriptedProcess>>>,
    fail_open: Rc<RefCell<HashSet<u32>>>,
}

#[cfg(test)]
impl ScriptedSource {
    /// Spawn (or respawn, for reuse scripts) one programmed pid.
    pub(crate) fn spawn(&self, pid: u32, start_time: u64) {
        self.state.borrow_mut().insert(
            pid,
            ScriptedProcess {
                alive: true,
                start_time,
                exe: Some(ExeIdentity {
                    dev: 1,
                    ino: 100,
                    mtime_secs: 10,
                    mtime_nanos: 0,
                    path: Some("/bin/driver".into()),
                }),
                readable: true,
            },
        );
    }

    pub(crate) fn kill(&self, pid: u32) {
        if let Some(process) = self.state.borrow_mut().get_mut(&pid) {
            process.alive = false;
        }
    }

    #[allow(dead_code)] // E1: reserved scripted seam for exec scripts; churn respawns via `spawn` today.
    pub(crate) fn exec(&self, pid: u32, ino: u64, path: &str) {
        if let Some(process) = self.state.borrow_mut().get_mut(&pid) {
            process.exe = Some(ExeIdentity {
                dev: 1,
                ino,
                mtime_secs: 20,
                mtime_nanos: 0,
                path: Some(path.into()),
            });
        }
    }

    /// Blind one pid's identity reads (liveness still answers).
    #[allow(dead_code)] // E1: reserved scripted seam for blind-identity scripts; no workload blinds today.
    pub(crate) fn blind(&self, pid: u32) {
        if let Some(process) = self.state.borrow_mut().get_mut(&pid) {
            process.readable = false;
        }
    }

    /// Inject admission failure: `open` fails for this pid until cleared.
    pub(crate) fn set_fail_open(&self, pid: u32, fail: bool) {
        if fail {
            self.fail_open.borrow_mut().insert(pid);
        } else {
            self.fail_open.borrow_mut().remove(&pid);
        }
    }
}

#[cfg(test)]
impl ProcessSource for ScriptedSource {
    type Pin = (u32, u64);

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        if self.fail_open.borrow().contains(&pid) {
            return Err(format!("injected admission failure for pid {pid}"));
        }
        let state = self.state.borrow();
        let process = state
            .get(&pid)
            .filter(|process| process.alive)
            .ok_or_else(|| format!("no live scripted process {pid}"))?;
        Ok((pid, process.start_time))
    }

    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        self.state
            .borrow()
            .get(&pin.0)
            .is_some_and(|process| process.alive && process.start_time == pin.1)
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        self.state
            .borrow()
            .get(&pid)
            .filter(|process| process.alive && process.readable)
            .map(|process| process.start_time)
    }

    fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
        self.state
            .borrow()
            .get(&pid)
            .filter(|process| process.alive && process.readable)
            .and_then(|process| process.exe.clone())
    }

    fn gone(&self, pid: u32) -> bool {
        !self
            .state
            .borrow()
            .get(&pid)
            .is_some_and(|process| process.alive)
    }
}

/// One churn workload: `pids` pids turning over `generations` times
/// (spawn, map one of `modules` modules, die), each death reconciled.
/// Exact ledger: `pids * generations` incarnations admitted, every one
/// retired, every edge retained with its end reason.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChurnSpec {
    pub pids: usize,
    pub generations: usize,
    pub modules: usize,
    pub first_pid: u32,
}

/// The JSON backend: a real [`InventoryCoordinator`] over a scripted
/// source, driven through staging → `commit_batch` → `render_json`.
/// Every workload here runs the production batch boundary — never a
/// mock registry.
#[cfg(test)]
pub(crate) struct Harness {
    coordinator: InventoryCoordinator<ScriptedSource>,
    source: ScriptedSource,
    started_ns: u64,
    now_ns: u64,
    passes: u64,
}

#[cfg(test)]
impl Harness {
    pub(crate) fn new(limits: RegistryLimits) -> Result<Self> {
        let source = ScriptedSource::default();
        let coordinator = InventoryCoordinator::new(
            Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            source.clone(),
            limits,
        )?;
        let started_ns = crate::discovery::caller_registry::now_ns();
        Ok(Self {
            coordinator,
            source,
            started_ns,
            now_ns: started_ns,
            passes: 0,
        })
    }

    pub(crate) fn source(&self) -> &ScriptedSource {
        &self.source
    }

    pub(crate) fn coordinator(&self) -> &InventoryCoordinator<ScriptedSource> {
        &self.coordinator
    }

    pub(crate) fn coordinator_mut(&mut self) -> &mut InventoryCoordinator<ScriptedSource> {
        &mut self.coordinator
    }

    /// Move the harness clock forward (monotonic; deterministic scripts
    /// advance it explicitly between batches).
    pub(crate) fn advance(&mut self, delta_ns: u64) {
        self.now_ns = self.now_ns.saturating_add(delta_ns.max(1));
    }

    pub(crate) fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Stage one scale workload: spawn its pids, reconcile them through
    /// the production admission path, and stage its exact edge layout.
    /// Returns the reconcile events (admissions, or failures under
    /// injection). Invisible until [`Harness::commit`].
    pub(crate) fn stage_scale(&mut self, spec: &ScaleSpec) -> Vec<CallerEvent> {
        for index in 0..spec.callers {
            let pid = spec.first_pid + index as u32;
            self.source.spawn(pid, 1000 + index as u64);
        }
        let observed: BTreeSet<u32> = (0..spec.callers)
            .map(|index| spec.first_pid + index as u32)
            .collect();
        let mut adapter_events = self.coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            self.now_ns,
        );
        // Bind staged retirements and gap admission failures exactly as
        // a scanned pass would.
        let replay = std::mem::take(&mut adapter_events);
        self.coordinator
            .apply_reconcile_events(&replay, self.now_ns);
        let live: Vec<(u32, CallerId)> = observed
            .iter()
            .filter_map(|pid| {
                self.coordinator
                    .adapter()
                    .live_id(*pid)
                    .map(|id| (*pid, id))
            })
            .collect();
        let live_by_index: HashMap<u32, CallerId> = live.into_iter().collect();
        let infos: Vec<ModuleInfo> = (0..spec.modules)
            .map(|module| scale_module_info(module, spec.endpoints_per_module))
            .collect();
        for (caller_index, module_index) in spec.layout() {
            let pid = spec.first_pid + caller_index as u32;
            let Some(caller) = live_by_index.get(&pid).copied() else {
                continue;
            };
            self.coordinator.registry_mut().note_mapping(
                caller,
                pid,
                infos[module_index].clone(),
                self.now_ns,
            );
        }
        replay
    }

    /// Run one churn workload: every generation spawns, reconciles,
    /// maps one module per live caller, and commits; then every pid
    /// dies and the deaths reconcile and commit. Returns
    /// (incarnations admitted, reconcile events).
    pub(crate) fn run_churn(&mut self, spec: &ChurnSpec) -> (usize, Vec<CallerEvent>) {
        let mut admitted = 0;
        let mut events = Vec::new();
        let infos: Vec<ModuleInfo> = (0..spec.modules)
            .map(|module| scale_module_info(module, 4))
            .collect();
        for generation in 0..spec.generations {
            let observed: BTreeSet<u32> = (0..spec.pids)
                .map(|index| spec.first_pid + index as u32)
                .collect();
            for pid in &observed {
                self.source
                    .spawn(*pid, 1000 + (generation * spec.pids) as u64);
            }
            let mut batch = self.coordinator.adapter_mut().reconcile(
                &observed,
                &mut |_| ImageAuthority::ScanPinned,
                self.now_ns,
            );
            admitted += batch
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        CallerEvent::Admitted { .. }
                            | CallerEvent::Reused { .. }
                            | CallerEvent::ExecRetired { .. }
                    )
                })
                .count();
            self.coordinator.apply_reconcile_events(&batch, self.now_ns);
            events.append(&mut batch);
            for (index, pid) in observed.iter().enumerate() {
                let Some(caller) = self.coordinator.adapter().live_id(*pid) else {
                    continue;
                };
                self.coordinator.registry_mut().note_mapping(
                    caller,
                    *pid,
                    infos[(generation + index) % spec.modules].clone(),
                    self.now_ns,
                );
            }
            self.commit();
            self.advance(10);
            for pid in &observed {
                self.source.kill(*pid);
            }
            let batch = self.coordinator.adapter_mut().reconcile(
                &BTreeSet::new(),
                &mut |_| ImageAuthority::ScanPinned,
                self.now_ns,
            );
            self.coordinator.apply_reconcile_events(&batch, self.now_ns);
            events.extend(batch);
            self.commit();
            self.advance(10);
        }
        (admitted, events)
    }

    /// Stage one semantic call for an edge through the production
    /// batch boundary: the S-track reuses this SAME harness — no new
    /// seam. Invisible until [`Harness::commit`].
    pub(crate) fn observe_semantic(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        call: SemanticCall,
    ) {
        self.coordinator
            .registry_mut()
            .observe_semantic(caller, module, call);
    }

    /// Stage one pass-wide semantic capture-loss boundary (S1/C2):
    /// every live operation ends unknown and the loss is a gap.
    /// Invisible until [`Harness::commit`].
    pub(crate) fn note_semantic_loss(&mut self, reason: &str) {
        self.coordinator
            .registry_mut()
            .note_capture_loss(reason.to_string());
    }

    /// One pass over a scripted catalog through the production
    /// post-collection path (`apply_catalog`: attach-set absorb,
    /// reconcile over every attributable member, generation join,
    /// projection), then the batch commit. No native identity exists.
    pub(crate) fn apply_catalog(&mut self, catalog: crate::inspect_system::Catalog) -> PassReport {
        let mut guard = UnavailableImageGuard;
        let report = self.coordinator.apply_catalog(
            catalog,
            &mut guard,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            u64::MAX,
            self.now_ns,
        );
        self.commit();
        report
    }

    /// One pass with no observation behind it (discovery loss): the
    /// production empty-pass path, then the batch commit.
    pub(crate) fn observe_loss(&mut self, reason: &str) -> PassReport {
        let mut guard = UnavailableImageGuard;
        let report = self.coordinator.observe_empty_pass(
            &mut guard,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            reason,
            self.now_ns,
        );
        self.commit();
        report
    }

    /// The I4b batch: engine tail plus registry publish, counting one
    /// harness pass.
    pub(crate) fn commit(&mut self) -> BatchReceipt {
        self.passes += 1;
        self.coordinator
            .commit_batch(false)
            .expect("scripted batch commits")
    }

    /// Render the published snapshot through the real renderer.
    pub(crate) fn render(&self) -> serde_json::Value {
        crate::inventory::render_json(
            &self.coordinator,
            "workload",
            self.started_ns,
            self.now_ns,
            self.passes,
        )
    }
}

#[cfg(test)]
#[path = "inventory_workload_tests.rs"]
mod tests;

/// One scripted module: distinct physical identity per index, admitted
/// with its endpoint count.
#[cfg(test)]
pub(crate) fn scale_module_info(index: usize, endpoints: usize) -> ModuleInfo {
    let path = format!("/scale/m{index}.so");
    ModuleInfo {
        path: path.clone(),
        key: ModuleKey::physical(
            8,
            1,
            100_000 + index as u64,
            Some(format!("sha{index:06}")),
            &path,
        ),
        double_loaded: false,
        build_id: None,
        identity_source: Some("workload".into()),
        admission: AdmissionState::Admitted,
        admission_class: Some("exact".into()),
        admission_endpoints: Some(endpoints),
        admission_reasons: Vec::new(),
    }
}
