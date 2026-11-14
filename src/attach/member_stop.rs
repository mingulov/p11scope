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

static MEMBER_STOP_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-member-stop"));

/// The one hook program and its kernel attach target: every file VMA the
/// kernel creates passes `uprobe_mmap` once the mapping exists.
pub(crate) const MEMBER_STOP_PROGRAM: &str = "p11_member_map_stop";
const MEMBER_STOP_TARGET: &str = "uprobe_mmap";

/// The loaded, attached member-stop object. Dropping it deactivates the
/// hook and resumes every member still pending, so no early return can
/// leave a member stopped by this capture.
pub(crate) struct MemberStopHooks {
    ebpf: aya::Ebpf,
}

impl MemberStopHooks {
    /// Loads the object against the host BTF, publishes the run cgroup and
    /// the owned child's exemption, validates the map shapes, attaches the
    /// hook and only then activates it.
    pub(crate) fn start(cgroup: &File, owned_tgid: u32) -> Result<Self> {
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
        {
            let program: &mut aya::programs::FEntry = ebpf
                .program_mut(MEMBER_STOP_PROGRAM)
                .ok_or_else(|| anyhow!("program {MEMBER_STOP_PROGRAM} missing from object"))?
                .try_into()?;
            program
                .load(MEMBER_STOP_TARGET, &btf)
                .with_context(|| format!("loading {MEMBER_STOP_PROGRAM}"))?;
            program
                .attach()
                .with_context(|| format!("attaching {MEMBER_STOP_PROGRAM}"))?;
        }
        write_config(&mut ebpf, true, owned_tgid)?;
        Ok(Self { ebpf })
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
}

impl Drop for MemberStopHooks {
    fn drop(&mut self) {
        let _ = self.deactivate();
        let pending = self.pending().unwrap_or_default();
        for (tgid, _) in pending {
            let _ = self.withdraw(tgid);
            if let Ok(pin) = crate::process::PidPin::open(tgid) {
                let _ = pin.send_signal(libc::SIGCONT);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_guard::DieWithParent as _;

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
        let mut hooks = MemberStopHooks::start(&dir, exempt.id()).expect("member-stop starts");
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
            exempt.wait().unwrap().success(),
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
        assert!(
            maps.lines()
                .any(|line| line.contains(&format!(" {} ", stop.file.ino))),
            "the row names a file the member maps"
        );
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
        assert!(
            again.wait().unwrap().success(),
            "cleared files never stop a mapper"
        );
        assert_eq!(
            hooks.counters().unwrap()[0],
            counted_before,
            "no stop requested for cleared files"
        );
        assert!(counted_before >= 1);
        drop(hooks);
    }
}
