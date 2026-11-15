//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Run-tree first-map stop hooks: the standalone member-stop object
//! (`crates/ebpf/native/member_stop.c`) for an owned, pause-armed `run`
//! on its cgroup scope. The first time a run member maps an executable
//! file this capture has not cleared, the kernel stops the member with a
//! pending row; the engine (`discovery::engine::member_stop`) inspects the
//! file, attaches a provider's probes, clears the file and resumes the
//! member. This module owns only the kernel object: load, publish, the
//! pending table, the clearance table and the counters.

use std::fs::File;

use anyhow::{Context as _, Result, anyhow};
use aya::maps::{Array, CgroupArray, HashMap, MapError, PerCpuArray};
use p11scope_ebpf_common::{
    MEMBER_CLEARED_ENTRIES, MEMBER_STOP_COUNTERS, MEMBER_STOP_ENTRIES, MemberFileKey, MemberStop,
    MemberStopConfig,
};

use crate::discovery::engine::MemberStopIo;

pub(crate) mod watchdog;
pub(crate) use watchdog::{WatchdogLauncher, process_stopped};

static MEMBER_STOP_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-member-stop"));

/// The one hook program and its kernel attach target: every file VMA the
/// kernel creates passes `uprobe_mmap` once the mapping exists.
pub(crate) const MEMBER_STOP_PROGRAM: &str = "p11_member_map_stop";
const MEMBER_STOP_TARGET: &str = "uprobe_mmap";

/// The loaded, attached member-stop object. Dropping it deactivates and
/// detaches the hook, then resumes every member still pending, so no
/// early return can leave a member stopped by this capture.
pub(crate) struct MemberStopHooks {
    ebpf: aya::Ebpf,
    tree: RunTree,
    /// The attached hook; detached before the final release scan.
    link: Option<aya::programs::fentry::FEntryLinkId>,
    /// The process that resumes stopped members if this observer dies
    /// without its cleanup. No stop is activated without it.
    watchdog: Option<watchdog::Watchdog>,
}

/// The run cgroup tree the stops belong to: the cgroup v2 mount root
/// (`/proc/<pid>/cgroup` paths are relative to it) and the run cgroup.
#[derive(Debug, Clone)]
pub(crate) struct RunTree {
    pub(crate) cgroup_root: std::path::PathBuf,
    pub(crate) run_cgroup: std::path::PathBuf,
}

impl RunTree {
    pub(crate) fn of(group: &crate::scope::RunCgroup) -> Self {
        Self {
            cgroup_root: group.cgroup_root().to_path_buf(),
            run_cgroup: group.path().to_path_buf(),
        }
    }

    /// Whether `/proc/<pid>/cgroup` places `pid` in the run cgroup or
    /// below it.
    pub(crate) fn contains(&self, pid: u32) -> Result<bool, String> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|error| format!("reading the cgroup of {pid}: {error}"))?;
        let relative = crate::scope::parse_cgroup_v2_relative(&text)
            .ok_or_else(|| format!("no cgroup v2 line for {pid}"))?;
        Ok(self
            .cgroup_root
            .join(relative)
            .starts_with(&self.run_cgroup))
    }

    /// [`Self::contains`] for a pinned process: the read is accepted only
    /// while the pin still names the process it opened.
    pub(crate) fn contains_pinned(&self, pin: &crate::process::PidPin) -> Result<bool, String> {
        let inside = self.contains(pin.pid());
        if !pin.still_the_same() {
            return Ok(false);
        }
        inside
    }
}

impl MemberStopHooks {
    /// Loads the object against the host BTF, publishes the run cgroup and
    /// the owned child's exemption, validates the map shapes, attaches the
    /// hook and only then activates it.
    pub(crate) fn start(
        cgroup: &File,
        tree: RunTree,
        owned_tgid: u32,
        launcher: &WatchdogLauncher,
    ) -> Result<Self> {
        let btf = aya::Btf::from_sys_fs().context("reading the host BTF")?;
        let mut loader = aya::EbpfLoader::new();
        loader.btf(Some(&btf));
        let mut ebpf = loader
            .load(MEMBER_STOP_OBJECT)
            .context("loading the member-stop object")?;
        validate_shapes(&ebpf)?;
        {
            let mut groups: CgroupArray<_> =
                CgroupArray::try_from(ebpf.map_mut("MS_CGROUP").context("MS_CGROUP map")?)?;
            groups
                .set(0, cgroup.try_clone().context("cloning the run cgroup")?, 0)
                .context("publishing the run cgroup")?;
        }
        write_config(&mut ebpf, false, owned_tgid)?;
        // The watchdog runs before the hook can stop anyone.
        let watchdog =
            watchdog::Watchdog::start(launcher, &tree).map_err(|error| anyhow!(error))?;
        let link = {
            let program: &mut aya::programs::FEntry = ebpf
                .program_mut(MEMBER_STOP_PROGRAM)
                .ok_or_else(|| anyhow!("program {MEMBER_STOP_PROGRAM} missing from object"))?
                .try_into()?;
            program
                .load(MEMBER_STOP_TARGET, &btf)
                .with_context(|| format!("loading {MEMBER_STOP_PROGRAM}"))?;
            program
                .attach()
                .with_context(|| format!("attaching {MEMBER_STOP_PROGRAM}"))?
        };
        write_config(&mut ebpf, true, owned_tgid)?;
        Ok(Self {
            ebpf,
            tree,
            link: Some(link),
            watchdog: Some(watchdog),
        })
    }
}

fn write_config(ebpf: &mut aya::Ebpf, active: bool, exempt_tgid: u32) -> Result<()> {
    let mut config: Array<_, MemberStopConfig> =
        Array::try_from(ebpf.map_mut("MS_CFG").context("MS_CFG map")?)?;
    let row = MemberStopConfig {
        active: u32::from(active),
        exempt_tgid,
    };
    config.set(0, row, 0).context("publishing MS_CFG")?;
    if config.get(&0, 0).context("reading back MS_CFG")? != row {
        return Err(anyhow!("MS_CFG readback differs from the published row"));
    }
    Ok(())
}

/// Exact capacities, mirrored from ebpf-common: a drifted object refuses
/// to start instead of silently disagreeing with the engine.
fn validate_shapes(ebpf: &aya::Ebpf) -> Result<()> {
    let checks: [(&str, u32); 4] = [
        ("MS_STOPS", MEMBER_STOP_ENTRIES),
        ("MS_CLEARED", MEMBER_CLEARED_ENTRIES),
        ("MS_COUNTS", MEMBER_STOP_COUNTERS),
        ("MS_CFG", 1),
    ];
    for (name, expected) in checks {
        let map = ebpf.map(name).with_context(|| format!("{name} map"))?;
        let info = match map {
            aya::maps::Map::HashMap(data)
            | aya::maps::Map::LruHashMap(data)
            | aya::maps::Map::Array(data)
            | aya::maps::Map::PerCpuArray(data) => data.info()?,
            other => return Err(anyhow!("unexpected {name} map variant {other:?}")),
        };
        if info.max_entries() != expected {
            return Err(anyhow!(
                "{name} holds {} entries, expected {expected}",
                info.max_entries()
            ));
        }
    }
    Ok(())
}

impl MemberStopIo for MemberStopHooks {
    fn pending(&mut self) -> Result<Vec<(u32, MemberStop)>, String> {
        let stops: HashMap<_, u32, MemberStop> = HashMap::try_from(
            self.ebpf
                .map("MS_STOPS")
                .ok_or_else(|| "MS_STOPS map missing".to_string())?,
        )
        .map_err(|error| format!("MS_STOPS map: {error}"))?;
        let mut pending = Vec::new();
        for entry in stops.iter() {
            match entry {
                Ok((tgid, stop)) => pending.push((tgid, stop)),
                // A row deleted between the key walk and its lookup.
                Err(MapError::KeyNotFound) => {}
                Err(error) => return Err(format!("reading MS_STOPS: {error}")),
            }
            if pending.len() >= MEMBER_STOP_ENTRIES as usize {
                break;
            }
        }
        Ok(pending)
    }

    fn clear(&mut self, file: MemberFileKey) -> Result<(), String> {
        let mut cleared: HashMap<_, MemberFileKey, u8> = HashMap::try_from(
            self.ebpf
                .map_mut("MS_CLEARED")
                .ok_or_else(|| "MS_CLEARED map missing".to_string())?,
        )
        .map_err(|error| format!("MS_CLEARED map: {error}"))?;
        cleared
            .insert(file, 1, 0)
            .map_err(|error| format!("clearing a member file: {error}"))
    }

    fn withdraw(&mut self, tgid: u32) -> Result<(), String> {
        let mut stops: HashMap<_, u32, MemberStop> = HashMap::try_from(
            self.ebpf
                .map_mut("MS_STOPS")
                .ok_or_else(|| "MS_STOPS map missing".to_string())?,
        )
        .map_err(|error| format!("MS_STOPS map: {error}"))?;
        match stops.remove(&tgid) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(error) => Err(format!("withdrawing a member stop: {error}")),
        }
    }

    fn counters(&mut self) -> Result<[u64; 4], String> {
        let counts: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.ebpf
                .map("MS_COUNTS")
                .ok_or_else(|| "MS_COUNTS map missing".to_string())?,
        )
        .map_err(|error| format!("MS_COUNTS map: {error}"))?;
        let mut totals = [0u64; 4];
        for (index, total) in totals.iter_mut().enumerate() {
            let values = counts
                .get(&(index as u32), 0)
                .map_err(|error| format!("reading MS_COUNTS: {error}"))?;
            *total = values
                .iter()
                .fold(0u64, |sum, value| sum.saturating_add(*value));
        }
        Ok(totals)
    }

    fn deactivate(&mut self) -> Result<(), String> {
        let exempt = Array::<_, MemberStopConfig>::try_from(
            self.ebpf
                .map("MS_CFG")
                .ok_or_else(|| "MS_CFG map missing".to_string())?,
        )
        .and_then(|config| config.get(&0, 0))
        .map(|row| row.exempt_tgid)
        .unwrap_or(0);
        write_config(&mut self.ebpf, false, exempt).map_err(|error| format!("{error:#}"))
    }

    fn is_run_member(&mut self, pin: &crate::process::PidPin) -> Result<bool, String> {
        self.tree.contains_pinned(pin)
    }

    fn guard_lost(&mut self) -> bool {
        self.watchdog.as_mut().is_none_or(watchdog::Watchdog::lost)
    }

    fn tgid_in_run_tree(&mut self, tgid: u32) -> Result<bool, String> {
        self.tree.contains(tgid)
    }
}

impl MemberStopHooks {
    /// Detaches the hook: an invocation that read `active` before the
    /// deactivation may still insert a row and stop a member, so the
    /// final scan runs only after the detach, which waits for in-flight
    /// invocations. The maps stay readable while `ebpf` lives.
    fn detach(&mut self) {
        let Some(link) = self.link.take() else {
            return;
        };
        let program: Option<&mut aya::programs::FEntry> = self
            .ebpf
            .program_mut(MEMBER_STOP_PROGRAM)
            .and_then(|program| program.try_into().ok());
        if let Some(program) = program {
            let _ = program.detach(link);
        }
    }
}

impl Drop for MemberStopHooks {
    fn drop(&mut self) {
        let _ = self.deactivate();
        self.detach();
        let pending = self.pending().unwrap_or_default();
        for (tgid, stop) in pending {
            let Ok(pin) = crate::process::PidPin::open(tgid) else {
                continue;
            };
            let member = match self.tree.contains_pinned(&pin) {
                Ok(true) => true,
                Ok(false) => {
                    crate::discovery::engine::stopped_member_moved_out(&pin, stop.hook_ts_ns)
                }
                Err(_) => continue,
            };
            if !member {
                let _ = self.withdraw(tgid);
                continue;
            }
            // Signal first: a failed send of a live member keeps the row,
            // and the watchdog sweeps instead of ending in order.
            if pin.send_signal(libc::SIGCONT).is_ok() || matches!(pin.original_exited(), Ok(true)) {
                let _ = self.withdraw(tgid);
            }
        }
        // An orderly end only when nothing is left: a row this release
        // could not resume makes the watchdog sweep instead.
        if let Some(watchdog) = self.watchdog.take() {
            if self.pending().is_ok_and(|rows| rows.is_empty()) {
                watchdog.finish();
            } else {
                watchdog.abandon();
            }
        }
    }
}

#[cfg(test)]
impl MemberStopHooks {
    /// The observer's death, as far as a test can stage it: the hook is
    /// deactivated and detached (a dead observer's link closes with its
    /// descriptors) and the watchdog's pipe closes without an orderly
    /// end. Nothing is resumed here.
    pub(crate) fn simulate_observer_death(&mut self) {
        let _ = self.deactivate();
        self.detach();
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abandon_without_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_guard::DieWithParent as _;

    /// The built object carries exactly one fentry program and five maps
    /// of exact shapes: (name, type, key, value, entries, flags). Pins the
    /// C header against the ebpf-common mirror without a kernel.
    #[test]
    fn member_stop_object_carries_exact_program_and_maps() {
        let parsed = aya_obj::Object::parse(MEMBER_STOP_OBJECT).expect("member-stop object parses");
        let programs: Vec<&str> = parsed.programs.keys().map(String::as_str).collect();
        assert_eq!(programs, vec![MEMBER_STOP_PROGRAM]);
        assert!(
            matches!(
                parsed.programs[MEMBER_STOP_PROGRAM].section,
                aya_obj::ProgramSection::FEntry { .. }
            ),
            "the hook is an fentry program"
        );
        let stop_value = core::mem::size_of::<MemberStop>() as u32;
        let file_key = core::mem::size_of::<MemberFileKey>() as u32;
        let config = core::mem::size_of::<MemberStopConfig>() as u32;
        let expected: &[(&str, u32, u32, u32, u32, u32)] = &[
            ("MS_CFG", 2, 4, config, 1, 1 << 7),
            ("MS_CGROUP", 8, 4, 4, 1, 0),
            ("MS_STOPS", 1, 4, stop_value, MEMBER_STOP_ENTRIES, 0),
            ("MS_CLEARED", 9, file_key, 1, MEMBER_CLEARED_ENTRIES, 0),
            ("MS_COUNTS", 6, 4, 8, MEMBER_STOP_COUNTERS, 0),
        ];
        let mut names: Vec<&str> = parsed.maps.keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut wanted: Vec<&str> = expected.iter().map(|(name, ..)| *name).collect();
        wanted.sort_unstable();
        assert_eq!(names, wanted, "exactly five maps");
        for (name, map_type, key, value, entries, flags) in expected {
            let map = &parsed.maps[*name];
            assert_eq!(map.map_type(), *map_type, "{name} type");
            assert_eq!(map.key_size(), *key, "{name} key");
            assert_eq!(map.value_size(), *value, "{name} value");
            assert_eq!(map.max_entries(), *entries, "{name} entries");
            assert_eq!(map.map_flags(), *flags, "{name} flags");
        }
        assert_eq!(stop_value, 40);
    }

    /// Waits for `child` to exit within 10 s; on timeout fails with the
    /// pending rows and the child's executable maps rows, never hangs.
    fn wait_bounded(
        child: &mut std::process::Child,
        hooks: &mut MemberStopHooks,
        what: &str,
    ) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if std::time::Instant::now() >= deadline {
                let pending = hooks.pending().unwrap_or_default();
                let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.id()))
                    .unwrap_or_default();
                let exec: Vec<&str> = maps.lines().filter(|line| line.contains(" r-x")).collect();
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what} never finished: pending {pending:?}; maps {exec:#?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn task_states(pid: u32) -> Vec<u8> {
        crate::discovery::pause::read_task_states(pid)
            .map(|states| states.into_values().collect())
            .unwrap_or_default()
    }

    /// Real kernel cell: a member of the run cgroup that execs stops at
    /// its first executable mapping with one pending row naming that
    /// file; the owned (exempt) tgid never stops; clearing, withdrawing
    /// and SIGCONT let the member finish; and a cleared file never stops
    /// the next mapper. Loads and attaches the object on the host BTF.
    #[test]
    #[ignore = "privileged: loads the member-stop object on the host kernel"]
    fn privileged_member_stop_stops_members_at_first_exec_map() {
        let group =
            crate::scope::RunCgroup::create_under_observer(std::path::Path::new("/sys/fs/cgroup"))
                .expect("run cgroup");
        let dir = std::fs::File::open(group.path()).expect("cgroup dir");
        // Exempt: the "owned child", placed too, never stops.
        let mut exempt = std::process::Command::new("sh")
            .args(["-c", "read line; exec /bin/true"])
            .stdin(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .unwrap();
        group.place(exempt.id()).unwrap();
        let mut hooks = MemberStopHooks::start(
            &dir,
            RunTree::of(&group),
            exempt.id(),
            &WatchdogLauncher::TestHarness,
        )
        .expect("member-stop starts");
        let mut member = std::process::Command::new("sh")
            .args(["-c", "read line; exec /bin/true"])
            .stdin(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .unwrap();
        group.place(member.id()).unwrap();
        use std::io::Write as _;
        member.stdin.take().unwrap().write_all(b"go\n").unwrap();
        exempt.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let mut row = None;
        for _ in 0..1000 {
            row = hooks
                .pending()
                .unwrap()
                .into_iter()
                .find(|(tgid, _)| *tgid == member.id());
            if row.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let (_, stop) = row.expect("the member's first exec map left a pending row");
        assert!(stop.file.ino != 0 && stop.hook_ts_ns != 0, "{stop:?}");
        assert!(
            hooks
                .pending()
                .unwrap()
                .iter()
                .all(|(tgid, _)| *tgid != exempt.id()),
            "the exempt tgid never stops"
        );
        assert!(
            wait_bounded(&mut exempt, &mut hooks, "the exempt child").success(),
            "the exempt child runs through"
        );
        let mut stopped = false;
        for _ in 0..500 {
            let states = task_states(member.id());
            if !states.is_empty() && states.iter().all(|state| *state == b'T') {
                stopped = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(stopped, "the member is stopped by the hook");
        // Clear every file the member maps, then resume it.
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", member.id())).unwrap();
        for line in maps.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 && fields[1].contains('x') && fields[4] != "0" {
                let (major, minor) = fields[3].split_once(':').unwrap();
                let key = MemberFileKey {
                    dev: (u64::from_str_radix(major, 16).unwrap() << 20)
                        | u64::from_str_radix(minor, 16).unwrap(),
                    ino: fields[4].parse().unwrap(),
                };
                hooks.clear(key).unwrap();
            }
        }
        assert!(stop.vm_start < stop.vm_end, "{stop:?}");
        assert!(
            maps.lines().any(|line| {
                let Some((range, rest)) = line.split_once(' ') else {
                    return false;
                };
                let Some((start, end)) = range.split_once('-') else {
                    return false;
                };
                let start = u64::from_str_radix(start, 16).unwrap_or(u64::MAX);
                let end = u64::from_str_radix(end, 16).unwrap_or(0);
                rest.as_bytes().get(2) == Some(&b'x')
                    && start <= stop.vm_start
                    && stop.vm_start < end
            }),
            "the row's range names an executable mapping of the member: {stop:?}\n{maps}"
        );
        // The row's own kernel key: for an overlayfs mapping it differs
        // from the device `maps` prints, and clearing it is what the
        // engine does for the stopping file.
        hooks.clear(stop.file).unwrap();
        let mut cleared = std::collections::BTreeSet::from([stop.file]);
        hooks.withdraw(member.id()).unwrap();
        let pin = crate::process::PidPin::open(member.id()).unwrap();
        pin.send_signal(libc::SIGCONT).unwrap();
        // The loader still maps /bin/true's libraries after the first
        // stop: each new file stops the member once more; clear it and
        // resume until the member exits.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = member.try_wait().unwrap() {
                break status;
            }
            for (tgid, later) in hooks.pending().unwrap() {
                if tgid == member.id() {
                    hooks.clear(later.file).unwrap();
                    cleared.insert(later.file);
                    hooks.withdraw(tgid).unwrap();
                    let _ = pin.send_signal(libc::SIGCONT);
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the member never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        assert!(status.success());
        // A second mapper of the same, now cleared, files never stops.
        let mut again = std::process::Command::new("sh")
            .args(["-c", "read line; exec /bin/true"])
            .stdin(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .unwrap();
        group.place(again.id()).unwrap();
        again.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let counted_before = hooks.counters().unwrap()[0];
        assert!(counted_before >= 1);
        // A file it stops on must be new: never a cleared kernel key. (A
        // file `maps` named under another device on an overlay may still
        // stop it once; it is cleared under its own key and resumed.)
        let again_pin = crate::process::PidPin::open(again.id()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = again.try_wait().unwrap() {
                break status;
            }
            for (tgid, later) in hooks.pending().unwrap() {
                if tgid == again.id() {
                    assert!(
                        cleared.insert(later.file),
                        "a cleared file stopped the second mapper: {later:?}"
                    );
                    hooks.clear(later.file).unwrap();
                    hooks.withdraw(tgid).unwrap();
                    let _ = again_pin.send_signal(libc::SIGCONT);
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the second mapper never finished: pending {:?}",
                hooks.pending().unwrap()
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        assert!(status.success(), "the second mapper runs through");

        // The watchdog. An orderly end resumes nothing: a member stopped
        // by someone else (job control) stays as it is.
        let mut paused = std::process::Command::new("sleep")
            .arg("30")
            .die_with_parent()
            .spawn()
            .unwrap();
        group.place(paused.id()).unwrap();
        // SAFETY: signals our own child.
        unsafe {
            libc::kill(paused.id() as i32, libc::SIGSTOP);
        }
        let stopped = |pid: u32| {
            let states = task_states(pid);
            !states.is_empty() && states.iter().all(|state| *state == b'T')
        };
        while !stopped(paused.id()) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let orderly =
            watchdog::Watchdog::start(&WatchdogLauncher::TestHarness, &RunTree::of(&group))
                .expect("a second watchdog starts");
        orderly.finish();
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(stopped(paused.id()), "an orderly end resumes nothing");
        // The observer's death: a member stopped by the hook (and the
        // paused one) resume within the watchdog's last sweep, with no
        // help from this process.
        // A fresh copy: every file of /bin/true is cleared by now.
        let scratch = tempfile::tempdir().unwrap();
        let fresh = scratch.path().join("true-copy");
        std::fs::copy("/bin/true", &fresh).unwrap();
        let mut third = std::process::Command::new("sh")
            .args(["-c", "read line; exec \"$0\""])
            .arg(&fresh)
            .stdin(std::process::Stdio::piped())
            .die_with_parent()
            .spawn()
            .unwrap();
        group.place(third.id()).unwrap();
        third.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(hooks
            .pending()
            .unwrap()
            .iter()
            .any(|(tgid, _)| *tgid == third.id())
            && stopped(third.id()))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the third member never stopped"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let died = std::time::Instant::now();
        hooks.simulate_observer_death();
        let bound = std::time::Duration::from_millis(
            watchdog::SWEEP_DELAYS_MS[watchdog::SWEEP_DELAYS_MS.len() - 1] + 1000,
        );
        while stopped(third.id()) || stopped(paused.id()) {
            assert!(
                died.elapsed() < bound,
                "members still stopped {:?} after the observer's death",
                died.elapsed()
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        eprintln!(
            "member-stop watchdog: stopped members resumed {:?} after the observer's death",
            died.elapsed()
        );
        assert!(
            wait_bounded(&mut third, &mut hooks, "the third member").success(),
            "the resumed member runs through"
        );
        let _ = paused.kill();
        let _ = paused.wait();
        drop(hooks);
    }
}
