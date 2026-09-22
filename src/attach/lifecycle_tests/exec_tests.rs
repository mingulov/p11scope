//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned nonleader exec: old-key cleanup before explicit same-Session rebinding.
//! This does not qualify automatic Engine recovery across exec.

use super::*;
use anyhow::Context as _;
use p11scope_ebpf_common::{DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT, DiscoveryRecord};
use p11scope_manifest::maps::parse_maps;
use sha2::Digest as _;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

struct OwnedElf {
    file: File,
    device: u64,
    inode: u64,
    hash: String,
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_hash(file: &File) -> Result<String> {
    let length = file.metadata()?.len();
    ensure!(
        length > 0 && length <= 4 * 1024 * 1024,
        "bounded private fixture ELF"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(sha256_hex(bytes))
}

impl OwnedElf {
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file());
        ensure!(ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?.abi() == ElfAbi::Lp64);
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            hash: file_hash(&file)?,
            file,
        })
    }

    fn unchanged(&self) -> Result<()> {
        let metadata = self.file.metadata()?;
        ensure!((metadata.dev(), metadata.ino()) == (self.device, self.inode));
        ensure!(
            file_hash(&self.file)? == self.hash,
            "retained fixture bytes changed"
        );
        Ok(())
    }

    fn matches(&self, path: &Path, phase: &str) -> Result<()> {
        self.unchanged()?;
        let actual = Self::open(path)?;
        ensure!((actual.device, actual.inode) == (self.device, self.inode));
        ensure!(
            actual.hash == self.hash,
            "{phase}: actual executable bytes differ"
        );
        eprintln!(
            "LIFECYCLE_EXEC_ELF phase={phase} dev={} ino={} sha256={}",
            actual.device, actual.inode, actual.hash
        );
        Ok(())
    }
}

struct ExecFixture {
    fixture: Fixture,
    after: PathBuf,
    absent: PathBuf,
    before_elf: OwnedElf,
    after_elf: OwnedElf,
    provider_elf: OwnedElf,
    token: u64,
}

impl ExecFixture {
    fn build() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("nonleader-exec.c");
        std::fs::write(
            &source,
            include_str!("../../../tests/fixtures/detailed-nonleader-exec.c"),
        )?;
        let provider = directory.path().join("provider.so");
        let before = directory.path().join("before");
        let after = directory.path().join("after");
        for (path, defines) in [
            (
                &provider,
                &["-fPIC", "-shared", "-DDETAILED_EXEC_PROVIDER"][..],
            ),
            (&before, &[][..]),
            (&after, &["-DDETAILED_EXEC_AFTER"][..]),
        ] {
            let output = Command::new("cc")
                .args([
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-omit-frame-pointer",
                ])
                .args(defines)
                .arg(&source)
                .arg("-ldl")
                .arg("-o")
                .arg(path)
                .output()?;
            ensure!(
                output.status.success(),
                "exec fixture compilation failed: {} {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let absent = directory.path().join("must-not-exist");
        ensure!(!absent.try_exists()?);
        let before_elf = OwnedElf::open(&before)?;
        let after_elf = OwnedElf::open(&after)?;
        let provider_elf = OwnedElf::open(&provider)?;
        ensure!((before_elf.device, before_elf.inode) != (after_elf.device, after_elf.inode));
        ensure!(before_elf.hash != after_elf.hash);
        let mut token = [0_u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut token)?;
        Ok(Self {
            fixture: Fixture {
                _directory: directory,
                provider,
                driver: before,
                sibling: false,
            },
            after,
            absent,
            before_elf,
            after_elf,
            provider_elf,
            token: u64::from_ne_bytes(token) | 1,
        })
    }

    fn spawn(&self, failed: bool) -> Result<Caller> {
        let child = Command::new(&self.fixture.driver)
            .arg(&self.fixture.provider)
            .arg(&self.after)
            .arg(&self.absent)
            .arg(std::process::id().to_string())
            .arg(self.token.to_string())
            .arg(if failed { "1" } else { "0" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut custody = ChildCustody {
            child,
            pin: None,
            reaped: false,
        };
        let pin = PidPin::open(custody.child.id()).map_err(anyhow::Error::msg)?;
        pin.pidfd()
            .context("exec fixture requires original process pidfd")?;
        custody.pin = Some(pin);
        let input = custody.child.stdin.take().context("exec input pipe")?;
        let output = custody.child.stdout.take().context("exec output pipe")?;
        let birth = task_birth(custody.child.id(), custody.child.id())?;
        let mut child = Caller {
            custody,
            input,
            output,
            birth,
            last_ns: 0,
            lines: 0,
            max_lines: if failed { 6 } else { 7 },
        };
        self.ready_record(&mut child, "READY")?;
        self.before_elf.matches(&Self::exe_path(&child), "before")?;
        child.same_leader()?;
        eprintln!(
            "LIFECYCLE_EXEC_GENERATION leader={} birth={} token={} failed={failed}",
            child.pid(),
            child.birth,
            self.token
        );
        Ok(child)
    }

    fn exe_path(child: &Caller) -> PathBuf {
        PathBuf::from(format!("/proc/{}/exe", child.pid()))
    }

    fn ready_record(&self, child: &mut Caller, phase: &str) -> Result<()> {
        self.provider_elf
            .matches(&self.fixture.provider, "provider_retained")?;
        ensure!(
            child.record(phase, 5)?
                == [
                    u64::from(child.pid()),
                    u64::from(child.pid()),
                    self.provider_elf.device,
                    self.provider_elf.inode,
                    self.token,
                ]
        );
        Ok(())
    }

    fn start_worker(&self, child: &mut Caller) -> Result<Worker> {
        child.same_leader()?;
        child.send(b'G')?;
        let fields = child.record("THREAD", 3)?;
        let tid = u32::try_from(fields[1])?;
        ensure!(tid != 0 && tid != child.pid());
        ensure!(fields == [u64::from(child.pid()), u64::from(tid), u64::from(tid)]);
        let worker = Worker {
            tid,
            birth: task_birth(child.pid(), tid)?,
        };
        ensure!(
            child.record("WORKER_DONE", 5)? == [u64::from(child.pid()), u64::from(tid), 11, 6, 5]
        );
        ensure!(
            child.record("EXEC_BODY", 3)? == [u64::from(child.pid()), u64::from(tid), self.token]
        );
        eprintln!(
            "LIFECYCLE_EXEC_GENERATION worker={tid} birth={}",
            worker.birth
        );
        Ok(worker)
    }

    fn tasks(child: &Caller) -> Result<BTreeSet<u32>> {
        std::fs::read_dir(format!("/proc/{}/task", child.pid()))?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().parse()?))
            .collect()
    }

    fn require_old_image(&self, child: &Caller, worker: Worker) -> Result<()> {
        child.assert_worker_body_held(worker)?;
        self.before_elf
            .matches(&Self::exe_path(child), "old_held")?;
        ensure!(Self::tasks(child)? == BTreeSet::from([child.pid(), worker.tid]));
        Ok(())
    }

    fn new_ready(&self, child: &mut Caller, worker: Worker) -> Result<()> {
        self.ready_record(child, "NEW_READY")?;
        child.same_leader()?;
        self.after_elf
            .matches(&Self::exe_path(child), "new_ready")?;
        ensure!(Self::tasks(child)? == BTreeSet::from([child.pid()]));
        ensure!(!Path::new(&format!("/proc/{}/task/{}", child.pid(), worker.tid)).try_exists()?);
        child.assert_leader_body_held()?;
        eprintln!(
            "LIFECYCLE_EXEC_CUSTODY original_pidfd_live=true same_process_birth={} old_tid_absent={} successor_tid={}",
            child.birth,
            worker.tid,
            child.pid()
        );
        Ok(())
    }

    fn post_body(&self, child: &mut Caller) -> Result<()> {
        ensure!(
            child.record("POST_BODY", 3)?
                == [u64::from(child.pid()), u64::from(child.pid()), self.token]
        );
        child.same_leader()
    }

    fn new_done(&self, child: &mut Caller) -> Result<()> {
        ensure!(
            child.record("NEW_DONE", 6)?
                == [
                    u64::from(child.pid()),
                    u64::from(child.pid()),
                    17,
                    9,
                    8,
                    self.token
                ]
        );
        child.same_leader()
    }

    fn failed(&self, child: &mut Caller, worker: Worker) -> Result<()> {
        ensure!(
            child.record("EXEC_FAILED", 4)?
                == [u64::from(child.pid()), u64::from(worker.tid), 2, self.token]
        );
        self.require_old_image(child, worker)
    }

    fn failed_done(&self, child: &mut Caller, worker: Worker) -> Result<()> {
        ensure!(
            child.record("DONE", 6)?
                == [u64::from(child.pid()), u64::from(worker.tid), 29, 15, 14, 5]
        );
        self.require_old_image(child, worker)
    }

    fn mapping(&self, child: &Caller, pins: &PinnedObjects, plan: &AttachPlan) -> Result<()> {
        child.same_leader()?;
        self.provider_elf.unchanged()?;
        ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
        let slot = &plan.slots[0];
        let pinned = pins
            .summary(slot.object)
            .context("same retained provider ID")?;
        ensure!(pinned.sha256 == self.provider_elf.hash);
        let bytes = std::fs::read(format!("/proc/{}/maps", child.pid()))?;
        let maps = parse_maps(&bytes).map_err(anyhow::Error::msg)?;
        let found = maps
            .iter()
            .find(|entry| {
                ObjectKey::of(entry) == pinned.key
                    && entry.permissions[2] == b'x'
                    && entry.file_offset <= slot.file_offset
                    && slot.file_offset - entry.file_offset < entry.end - entry.start
            })
            .context("actual provider executable mapping contains the probed file offset")?;
        // The bridge used by Fixture::pin supplies maps' device, which need not
        // equal stat.st_dev on btrfs. The retained physical file/hash stays fixed.
        eprintln!(
            "LIFECYCLE_EXEC_MAPPING pid={} object={:?} key={:?} sha256={} offset={} start={} end={}",
            child.pid(),
            slot.object,
            pinned.key,
            pinned.sha256,
            slot.file_offset,
            found.start,
            found.end
        );
        child.same_leader()
    }
}

#[derive(Default)]
struct ExecRecords {
    calls: Vec<Event>,
    lifecycle: Vec<DiscoveryRecord>,
}

impl ExecRecords {
    fn drain(&mut self, session: &mut Session, child: &Caller, failed: bool) -> Result<()> {
        let mut overflow = false;
        let drain = session.event_drain()?;
        let more = drain.poll(Some(64), |event| {
            if self.calls.len() == 29 {
                overflow = true;
                return ControlFlow::Break(());
            }
            eprintln!(
                "LIFECYCLE_EXEC_CALL pid_tgid={} slot={} rv={} ts_ns={} image={:?}",
                event.pid_tgid, event.slot, event.rv, event.ts_ns, event.image
            );
            self.calls.push(event);
            ControlFlow::Continue(())
        });
        ensure!(!more && !overflow && drain.malformed() == 0);
        for event in &self.calls {
            ensure!(event.event_type == event_type::CALL && event.slot == 0);
            ensure!(event.pid_tgid >> 32 == u64::from(child.pid()));
            ensure!(event.image.task_cookie != 0);
        }
        while let Some(item) = session.discovery_dequeue()? {
            let events::DiscoveryItem::Record(record) = item else {
                bail!("malformed exec lifecycle discovery");
            };
            eprintln!(
                "LIFECYCLE_EXEC_DISCOVERY kind={} pid_tgid={} hook_ts_ns={}",
                record.kind, record.pid_tgid, record.hook_ts_ns
            );
            ensure!(
                !failed && self.lifecycle.len() < 2,
                "unexpected exec lifecycle record"
            );
            ensure!(record.pid_tgid == (u64::from(child.pid()) << 32 | u64::from(child.pid())));
            ensure!(
                record.kind
                    == [DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_EXEC][self.lifecycle.len()]
            );
            self.lifecycle.push(record);
        }
        Ok(())
    }

    fn calls_match(&self, expected: &[(u64, ImageIdentity, Vec<u64>)]) -> Result<()> {
        ensure!(self.calls.len() == expected.iter().map(|(_, _, rvs)| rvs.len()).sum::<usize>());
        let mut position = 0;
        for (owner, image, rvs) in expected {
            for rv in rvs {
                let event = &self.calls[position];
                ensure!(event.pid_tgid == *owner && event.image == *image && event.rv == *rv);
                position += 1;
            }
        }
        Ok(())
    }

    fn lifecycle_matches(&self, lower: u64, upper: u64) -> Result<()> {
        ensure!(self.lifecycle.len() == 2);
        let mut previous = lower;
        for record in &self.lifecycle {
            ensure!(record.hook_ts_ns >= previous && record.hook_ts_ns <= upper);
            previous = record.hook_ts_ns;
        }
        Ok(())
    }
}

fn finish_exec(child: &mut Caller) -> Result<()> {
    ensure!(
        child.lines == child.max_lines,
        "missing exec protocol receipts"
    );
    child.finish()?;
    let mut readiness = libc::pollfd {
        fd: child.output.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    ensure!(unsafe { libc::poll(&mut readiness, 1, 0) } == 1);
    let mut byte = [0];
    ensure!(
        child.output.read(&mut byte)? == 0,
        "extra receipt after complete exec protocol"
    );
    Ok(())
}

const EMPTY: Expected = Expected {
    entered: 0,
    returned: 0,
    errors: 0,
    starts: 0,
    outstanding: 0,
    abandoned: 0,
    rv_zero: 0,
    rv_five: 0,
};
const OLD_HELD: Expected = Expected {
    entered: 12,
    returned: 11,
    errors: 5,
    starts: 1,
    outstanding: 1,
    abandoned: 0,
    rv_zero: 6,
    rv_five: 5,
};
const OLD_CLEANED: Expected = Expected {
    starts: 0,
    outstanding: 0,
    abandoned: 1,
    ..OLD_HELD
};
const NEW_HELD: Expected = Expected {
    entered: 13,
    starts: 1,
    outstanding: 1,
    ..OLD_CLEANED
};
const SUCCESS_DONE: Expected = Expected {
    entered: 29,
    returned: 28,
    errors: 13,
    starts: 0,
    outstanding: 0,
    abandoned: 1,
    rv_zero: 15,
    rv_five: 13,
};
const FAILED_DONE: Expected = Expected {
    entered: 29,
    returned: 29,
    errors: 14,
    starts: 0,
    outstanding: 0,
    abandoned: 0,
    rv_zero: 15,
    rv_five: 14,
};
const OLD_RVS: [u64; 11] = [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0];
const NEW_RVS: [u64; 17] = [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0];

fn exact_start(rows: &[(StartKey, CallStart)], owner: u64) -> Result<(StartKey, CallStart)> {
    ensure!(rows.len() == 1);
    let (key, value) = rows[0];
    ensure!(key.pid_tgid == owner && key.slot == 0 && key._pad == 0);
    ensure!(value.image.task_cookie != 0 && value.ts_ns > 0);
    Ok((key, value))
}

fn detailed_nonleader_exec_gate(failed: bool) -> Result<()> {
    let fixture = ExecFixture::build()?;
    let mut child = fixture.spawn(failed)?;
    let (view, pins, plan) = fixture.fixture.pin(&child)?;
    fixture.mapping(&child, &pins, &plan)?;
    eprintln!("LIFECYCLE_OBJECT sha256={}", sha256_hex(crate::EBPF_OBJECT));
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
    let mut ids = OwnedIds::observe(&session)?;
    let mut records = ExecRecords::default();
    let result = (|| -> Result<()> {
        assert_maps(&session, "exec_baseline", EMPTY)?;
        records.drain(&mut session, &child, failed)?;
        ensure!(records.calls.is_empty() && records.lifecycle.is_empty());
        let domain = session.event_drain()?.domain_id();
        let worker = fixture.start_worker(&mut child)?;
        fixture.require_old_image(&child, worker)?;
        let body_ns = child.last_ns;
        let old_owner = u64::from(child.pid()) << 32 | u64::from(worker.tid);
        let rows = assert_maps(&session, "exec_body", OLD_HELD)?;
        let (old_key, old_start) = exact_start(&rows, old_owner)?;
        let saved = start_bytes(&session, &old_key)?;
        let old_hash = sha256_hex(saved);
        ensure!(old_start.ts_ns <= body_ns);
        eprintln!(
            "LIFECYCLE_EXEC_START phase=old_held pid_tgid={old_owner} bytes={} sha256={old_hash} image={:?}",
            saved.len(),
            old_start.image
        );
        records.drain(&mut session, &child, failed)?;
        records.calls_match(&[(old_owner, old_start.image, OLD_RVS.to_vec())])?;
        ensure!(records.lifecycle.is_empty());
        child.send(b'X')?;

        if failed {
            fixture.failed(&mut child, worker)?;
            let rows = assert_maps(&session, "exec_failed_still_held", OLD_HELD)?;
            exact_start(&rows, old_owner)?;
            ensure!(
                start_bytes(&session, &old_key)? == saved,
                "failed exec changed original START bytes"
            );
            eprintln!(
                "LIFECYCLE_EXEC_START phase=failed_still_held pid_tgid={old_owner} preserved=true sha256={old_hash} syscall_errno=2"
            );
            records.drain(&mut session, &child, true)?;
            records.calls_match(&[(old_owner, old_start.image, OLD_RVS.to_vec())])?;
            let unchanged = OwnedIds::observe(&session)?;
            ensure!(
                unchanged.maps == ids.maps
                    && unchanged.programs == ids.programs
                    && unchanged.links == ids.links
            );
            ensure!(session.event_drain()?.domain_id() == domain && session.has_slot_link(0));
            child.send(b'R')?;
            fixture.failed_done(&mut child, worker)?;
            assert_maps(&session, "failed_exec_done", FAILED_DONE)?;
            records.drain(&mut session, &child, true)?;
            records.calls_match(&[
                (old_owner, old_start.image, OLD_RVS.to_vec()),
                (old_owner, old_start.image, vec![5]),
                (old_owner, old_start.image, NEW_RVS.to_vec()),
            ])?;
            eprintln!(
                "LIFECYCLE_EXEC_ACCOUNTED failed=true completed=29 rv0=15 rv5=14 abandoned=0 syscall_errno=2 actual_function_rv=5 image={:?} rebind=false",
                old_start.image
            );
        } else {
            fixture.new_ready(&mut child, worker)?;
            let ready_ns = child.last_ns;
            fixture.mapping(&child, &pins, &plan)?;
            // Decisive original-TID cleanup checkpoint: no detach, rebind,
            // map mutation or successor call may precede these assertions.
            assert_maps(&session, "new_ready_before_rebind", OLD_CLEANED)?;
            let starts: HashMap<_, StartKey, CallStart> =
                HashMap::try_from(session.ebpf.map("START").context("old START absence")?)?;
            ensure!(matches!(
                starts.get(&old_key, 0),
                Err(MapError::KeyNotFound)
            ));
            records.drain(&mut session, &child, false)?;
            records.calls_match(&[(old_owner, old_start.image, OLD_RVS.to_vec())])?;
            records.lifecycle_matches(body_ns, ready_ns)?;
            eprintln!(
                "LIFECYCLE_EXEC_CLEANED_BEFORE_REBIND old_pid_tgid={old_owner} old_start_absent=true owner_debt=0 abandoned=1 body_ns={body_ns} new_ready_ns={ready_ns} domain={domain}"
            );

            let rebuild = session.detach_slots(&plan.slots)?;
            ensure!(rebuild == DetachOutcome::default());
            ensure!(session.detach_failures().is_empty() && !session.has_slot_link(0));
            let roots = OwnedIds::observe(&session)?;
            ensure!(roots.maps == ids.maps && roots.programs == ids.programs);
            ensure!(roots.links.is_subset(&ids.links) && ids.links.len() == roots.links.len() + 2);
            let removed: BTreeSet<_> = ids.links.difference(&roots.links).copied().collect();
            OwnedIds {
                maps: BTreeSet::new(),
                programs: BTreeSet::new(),
                links: removed.clone(),
            }
            .released()?;
            let attachment = session.attach_targets(&plan.slots, &pins);
            // Observe every retained replacement link even if the attach result
            // fails; the final absence oracle owns old/new link IDs together.
            let replacement = OwnedIds::observe(&session)?;
            ids.links.extend(replacement.links.iter().copied());
            let (failed_slots, completed) = attachment?;
            ensure!(failed_slots.is_empty() && session.attach_failures().is_empty());
            ensure!(
                completed.len() == 1
                    && completed[0].0 == 0
                    && completed[0].1.is_some_and(|time| time > 0)
            );
            ensure!(replacement.maps == ids.maps && replacement.programs == ids.programs);
            ensure!(roots.links.is_subset(&replacement.links));
            ensure!(replacement.links.len() == roots.links.len() + 2);
            ensure!(replacement.links.is_disjoint(&removed));
            ensure!(session.has_slot_link(0) && session.event_drain()?.domain_id() == domain);
            ensure!(pins.check_unchanged().map_err(anyhow::Error::msg)?);
            assert_maps(&session, "same_session_rebound_no_new_call", OLD_CLEANED)?;
            records.drain(&mut session, &child, false)?;
            records.calls_match(&[(old_owner, old_start.image, OLD_RVS.to_vec())])?;
            records.lifecycle_matches(body_ns, ready_ns)?;
            eprintln!(
                "LIFECYCLE_EXEC_REBIND explicit=true same_maps=true same_programs=true same_domain={domain} old_links={removed:?} replacement_links={:?} completed={completed:?}",
                replacement.links
            );

            child.send(b'P')?;
            fixture.post_body(&mut child)?;
            child.assert_leader_body_held()?;
            let new_owner = u64::from(child.pid()) << 32 | u64::from(child.pid());
            let rows = assert_maps(&session, "post_exec_body", NEW_HELD)?;
            let (new_key, new_start) = exact_start(&rows, new_owner)?;
            ensure!(new_start.image != old_start.image);
            ensure!(Some(new_start.image.exec_id) == old_start.image.exec_id.checked_add(1));
            ensure!(new_start.ts_ns >= ready_ns && new_start.ts_ns <= child.last_ns);
            let new_bytes = start_bytes(&session, &new_key)?;
            eprintln!(
                "LIFECYCLE_EXEC_START phase=new_held pid_tgid={new_owner} bytes={} sha256={} old_image={:?} new_image={:?}",
                new_bytes.len(),
                sha256_hex(new_bytes),
                old_start.image,
                new_start.image
            );
            records.drain(&mut session, &child, false)?;
            records.calls_match(&[(old_owner, old_start.image, OLD_RVS.to_vec())])?;
            records.lifecycle_matches(body_ns, ready_ns)?;
            child.send(b'R')?;
            fixture.new_done(&mut child)?;
            assert_maps(&session, "successful_exec_done", SUCCESS_DONE)?;
            records.drain(&mut session, &child, false)?;
            records.calls_match(&[
                (old_owner, old_start.image, OLD_RVS.to_vec()),
                (new_owner, new_start.image, NEW_RVS.to_vec()),
            ])?;
            records.lifecycle_matches(body_ns, ready_ns)?;
            eprintln!(
                "LIFECYCLE_EXEC_ACCOUNTED failed=false old_completed=11 new_completed=17 abandoned=1 old_image={:?} new_image={:?} rebind=true automatic_engine=false",
                old_start.image, new_start.image
            );
        }
        ensure!(view.still_the_same());
        fixture.mapping(&child, &pins, &plan)?;
        child.same_leader()?;
        Ok(())
    })();
    if let Err(error) = &result {
        eprintln!("LIFECYCLE_FAILURE {error:#}");
    }
    let detach = session.detach_producers();
    let detached_cleanly = session.detach_failures().is_empty();
    let terminal_health = session.counter_snapshot();
    drop(session);
    let released = ids.released();
    if let Err(error) = &detach {
        eprintln!("LIFECYCLE_EXEC_CLEANUP_FAILURE detach={error:#}");
    }
    if !detached_cleanly {
        eprintln!("LIFECYCLE_EXEC_CLEANUP_FAILURE retained_detach_failure=true");
    }
    eprintln!("LIFECYCLE_EXEC_TERMINAL_HEALTH {terminal_health:?}");
    if let Err(error) = &released {
        eprintln!("LIFECYCLE_EXEC_CLEANUP_FAILURE owned_ids={error:#}");
    }
    let cleanup_proven = detach.is_ok()
        && detached_cleanly
        && terminal_health
            .as_ref()
            .is_ok_and(|health| *health == CounterSnapshot::default())
        && released.is_ok();
    // F is never sent into an unknown phase on failure; retained ChildCustody
    // then performs its explicit, reported last-resort kill/reap cleanup. Even
    // a successful ledger cannot release F before actual BPF cleanup is proven.
    if result.is_ok() && cleanup_proven {
        finish_exec(&mut child)?;
    }
    result?;
    detach?;
    ensure!(detached_cleanly);
    ensure!(terminal_health? == CounterSnapshot::default());
    released?;
    Ok(())
}

#[test]
fn detailed_nonleader_exec_fixture_requires_new_image_and_explicit_post_release() -> Result<()> {
    let fixture = ExecFixture::build()?;
    let mut child = fixture.spawn(false)?;
    let worker = fixture.start_worker(&mut child)?;
    fixture.require_old_image(&child, worker)?;
    child.send(b'X')?;
    fixture.new_ready(&mut child, worker)?;
    child.assert_leader_body_held()?;
    child.send(b'P')?;
    fixture.post_body(&mut child)?;
    child.assert_leader_body_held()?;
    child.send(b'R')?;
    fixture.new_done(&mut child)?;
    finish_exec(&mut child)
}

#[test]
fn detailed_failed_exec_fixture_preserves_image_and_checks_function_rv() -> Result<()> {
    let fixture = ExecFixture::build()?;
    let mut child = fixture.spawn(true)?;
    let worker = fixture.start_worker(&mut child)?;
    fixture.require_old_image(&child, worker)?;
    child.send(b'X')?;
    fixture.failed(&mut child, worker)?;
    child.assert_worker_body_held(worker)?;
    child.send(b'R')?;
    fixture.failed_done(&mut child, worker)?;
    finish_exec(&mut child)
}

#[test]
#[ignore = "root-owned BPF lane; actual nonleader exec cleanup before explicit same-Session rebinding"]
fn privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind() -> Result<()> {
    detailed_nonleader_exec_gate(false)
}

#[test]
#[ignore = "root-owned BPF lane; failed raw exec preserves held Detailed START and actual function RV"]
fn privileged_detailed_failed_nonleader_exec_preserves_start_and_image() -> Result<()> {
    detailed_nonleader_exec_gate(true)
}
