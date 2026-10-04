//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture facade contracts. Only kernel link/map IO is replaced: the
//! attach set, its retained pins, and the entry validators are production.

use super::super::activation::InventoryAttachRequest;
use super::super::callers::CallerUseIo;
use super::*;
use crate::discovery::inventory_attach_set::tests as fx;
use crate::plan::AdmissionPolicy;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn budget(n: u64) -> InventoryBudget {
    InventoryBudget::new(n, n * 8).unwrap()
}

/// A book at instant 100 whose PID scope (if any) has no start time.
fn test_book(n: u64, pair_limit: usize, scope_pid: Option<u32>) -> CaptureBook {
    CaptureBook::new(
        budget(n),
        pair_limit,
        scope_pid.map(|pid| ScopeIncarnation {
            pid,
            start_time: None,
        }),
        100,
    )
}

fn regression(book: &mut CaptureBook, health: &CaptureHealth) -> Option<String> {
    assess_health(book, health).regression
}

/// An attach set that absorbed one module per `(name, endpoints)`, each
/// in its own provider file, plus the deltas each absorb produced.
struct SetFixture {
    dir: tempfile::TempDir,
    set: InventoryAttachSet,
    paths: Vec<PathBuf>,
}

impl SetFixture {
    fn new(n: u64) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            set: InventoryAttachSet::new(budget(n)),
            paths: Vec::new(),
        }
    }

    /// One pass that adds provider `name` with `endpoints` offsets (and
    /// re-presents every earlier provider, as a real pass would).
    fn pass(&mut self, name: &str, endpoints: u64) -> TargetDelta {
        let path = fx::provider(&self.dir, name, &format!("provider-{name}"));
        self.paths.push(path);
        let files: Vec<(&std::path::Path, String)> = self
            .paths
            .iter()
            .map(|path| (path.as_path(), format!("sha-{}", path.display())))
            .collect();
        let borrowed: Vec<(&std::path::Path, &str)> = files
            .iter()
            .map(|(path, sha)| (*path, sha.as_str()))
            .collect();
        let pins = fx::pass_pins(&borrowed);
        let modules: Vec<_> = self
            .paths
            .iter()
            .map(|path| fx::module(&pins, path, &fx::offsets(endpoints)))
            .collect();
        let plan = fx::lower_named(
            &modules,
            &pins,
            AdmissionPolicy::Inventory(self.set.budget()),
        );
        self.set.absorb(&plan, &pins).delta
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Publish(u32, u32),
    Attach(u32),
    /// One uprobe-multi link over these endpoint IDs (Multi).
    Group(&'static str, Vec<u32>),
}

#[derive(Default)]
struct Log {
    ops: Vec<Op>,
    live: usize,
}

struct FakeLink {
    log: Arc<Mutex<Log>>,
}

impl Drop for FakeLink {
    fn drop(&mut self) {
        self.log.lock().unwrap().live -= 1;
    }
}

#[derive(Default)]
struct FakeIo {
    log: Arc<Mutex<Log>>,
    /// attach() fails with no link for these endpoint IDs.
    refuse: BTreeSet<u32>,
    /// attach() hands back a link whose custody check then fails.
    poison: BTreeSet<u32>,
    /// attach() fails with EMFILE (no link) for these endpoint IDs.
    emfile: BTreeSet<u32>,
    /// attach_entry_group() halts as an unsupported kernel would.
    unsupported: bool,
    /// Leaf links an EMFILE halt creates (as a bisect would, after a
    /// poison split) before halting; the halt closes them.
    leaves_before_halt: usize,
    /// attach_entry_group() takes this long (a slow registration walk).
    group_delay: Duration,
    /// ... plus this long per site (per `slow` site when that is set).
    site_delay: Duration,
    /// Only these endpoint IDs cost `site_delay` (empty: every site).
    slow: BTreeSet<u32>,
}

fn entry_id(cookie: u64) -> u32 {
    cookie as u32
}

impl InventoryLinkIo for FakeIo {
    type Link = (FakeLink, u32);

    fn publish_endpoint(&mut self, endpoint: u32, object: PinnedObjectId) -> Result<()> {
        self.log
            .lock()
            .unwrap()
            .ops
            .push(Op::Publish(endpoint, object.0));
        Ok(())
    }

    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> Result<Self::Link> {
        let id = match request {
            InventoryAttachRequest::Entry { cookie, .. } => entry_id(cookie),
            InventoryAttachRequest::Lifecycle { .. } => u32::MAX,
        };
        if self.refuse.contains(&id) {
            bail!("kernel refused entry {id}");
        }
        if self.emfile.contains(&id) {
            return Err(
                anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EMFILE))
                    .context(format!("perf_event_open for entry {id}")),
            );
        }
        let mut log = self.log.lock().unwrap();
        log.ops.push(Op::Attach(id));
        log.live += 1;
        Ok((
            FakeLink {
                log: self.log.clone(),
            },
            id,
        ))
    }

    fn detach(&mut self, _link: &mut Self::Link) -> Result<()> {
        Ok(())
    }

    fn attachment_error(&self, link: &Self::Link) -> Option<String> {
        self.poison
            .contains(&link.1)
            .then(|| format!("post-acquisition failure on {}", link.1))
    }

    /// One link per group, the kernel's bisect modelled exactly: refused
    /// sites fail alone and the accepted ones share one link; EMFILE or an
    /// unsupported kernel halt with no link. The link carries the group's
    /// first accepted ID (so `poison` can target a group).
    fn attach_entry_group(
        &mut self,
        request: InventoryGroupRequest<'_>,
    ) -> std::result::Result<
        super::super::activation::InventoryGroupAttach<Self::Link>,
        p11scope_bpf_multi::BisectHalt,
    > {
        let ids: Vec<u32> = request
            .sites
            .iter()
            .map(|(_, cookie)| entry_id(*cookie))
            .collect();
        let costly = ids
            .iter()
            .filter(|id| self.slow.is_empty() || self.slow.contains(id))
            .count();
        std::thread::sleep(self.group_delay + self.site_delay * costly as u32);
        // Leaves linked before a halt live briefly, then close.
        let halt_leaves = |io: &Self| {
            let leaves: Vec<FakeLink> = (0..io.leaves_before_halt)
                .map(|_| {
                    let mut log = io.log.lock().unwrap();
                    log.ops.push(Op::Group(request.program, ids.clone()));
                    log.live += 1;
                    FakeLink {
                        log: io.log.clone(),
                    }
                })
                .collect();
            leaves.len()
        };
        if self.unsupported {
            let closed_leaves = halt_leaves(self);
            return Err(p11scope_bpf_multi::BisectHalt {
                halt: p11scope_bpf_multi::GroupHalt::Unsupported(
                    std::io::Error::from_raw_os_error(libc::EOPNOTSUPP),
                ),
                closed_leaves,
            });
        }
        if ids.iter().any(|id| self.emfile.contains(id)) {
            let closed_leaves = halt_leaves(self);
            return Err(p11scope_bpf_multi::BisectHalt {
                halt: p11scope_bpf_multi::GroupHalt::Exhausted(std::io::Error::from_raw_os_error(
                    libc::EMFILE,
                )),
                closed_leaves,
            });
        }
        let refused: Vec<(usize, std::io::Error)> = ids
            .iter()
            .enumerate()
            .filter(|(_, id)| self.refuse.contains(id))
            .map(|(index, _)| (index, std::io::Error::from_raw_os_error(libc::EINVAL)))
            .collect();
        let accepted: Vec<u32> = ids
            .iter()
            .copied()
            .filter(|id| !self.refuse.contains(id))
            .collect();
        let mut links = Vec::new();
        if let Some(first) = accepted.first().copied() {
            let mut log = self.log.lock().unwrap();
            log.ops.push(Op::Group(request.program, accepted));
            log.live += 1;
            links.push((
                FakeLink {
                    log: self.log.clone(),
                },
                first,
            ));
        }
        Ok(super::super::activation::InventoryGroupAttach { links, refused })
    }
}

struct Harness {
    io: FakeIo,
    targets: InventoryTargets,
    links: Vec<InventoryLinked<(FakeLink, u32)>>,
    book: CaptureBook,
    clock: u64,
}

impl Harness {
    fn new(n: u64, scope_pid: Option<u32>) -> Self {
        Self {
            io: FakeIo::default(),
            targets: InventoryTargets::for_capture(budget(n)),
            links: Vec::new(),
            book: test_book(n, 16, scope_pid),
            clock: 1_000,
        }
    }

    /// A Multi capture's harness: entries attach as groups.
    fn multi(n: u64, scope_pid: Option<u32>) -> Self {
        let mut harness = Self::new(n, scope_pid);
        harness.book.backend = AttachBackend::Multi;
        harness
    }

    /// The groups the IO created, in order: (program, member IDs).
    fn group_ops(&self) -> Vec<(&'static str, Vec<u32>)> {
        self.ops()
            .into_iter()
            .filter_map(|op| match op {
                Op::Group(program, ids) => Some((program, ids)),
                _ => None,
            })
            .collect()
    }

    /// The capture-wide group invariants: every endpoint is a member of at
    /// most one group, every member is attached, every group's links are
    /// still in custody under that group's identity, and no Singles link
    /// exists beside groups.
    fn assert_group_invariants(&self) {
        let mut seen = BTreeSet::new();
        for group in &self.book.groups {
            for member in &group.members {
                assert!(
                    seen.insert(member.0),
                    "endpoint {} is a member of two groups: {:?}",
                    member.0,
                    self.book.groups
                );
            }
            let held = self
                .links
                .iter()
                .filter(|link| {
                    link.target
                        == super::super::activation::InventoryLinkIdentity::EntryGroup(group.serial)
                })
                .count();
            assert_eq!(held, group.links, "group {} link custody", group.serial);
        }
        assert!(
            self.links.iter().all(|link| !matches!(
                link.target,
                super::super::activation::InventoryLinkIdentity::Entry(_)
            )),
            "a Singles link beside groups"
        );
        assert!(
            self.book.attached.iter().all(|id| seen.contains(id)),
            "an attached endpoint outside every group"
        );
    }

    fn extend_with_custody(
        &mut self,
        delta: TargetDelta,
        source: &dyn CaptureTargets,
        window: ExtendWindow,
        custody: &mut dyn FnMut() -> std::result::Result<(), String>,
    ) -> ExtendReceipt {
        let mut receipt = ExtendReceipt::default();
        let clock = &mut self.clock;
        let mut now = || {
            *clock += 10;
            *clock
        };
        extend_entries_with(
            &mut self.io,
            &mut self.targets,
            &mut self.links,
            &mut self.book,
            delta,
            source,
            window,
            custody,
            &mut now,
            &mut receipt,
        );
        receipt
    }

    fn extend(&mut self, delta: TargetDelta, source: &dyn CaptureTargets) -> ExtendReceipt {
        self.extend_with_custody(delta, source, wide(), &mut || Ok(()))
    }

    fn ops(&self) -> Vec<Op> {
        self.io.log.lock().unwrap().ops.clone()
    }

    fn attached_ops(&self) -> Vec<u32> {
        self.ops()
            .into_iter()
            .filter_map(|op| match op {
                Op::Attach(id) => Some(id),
                Op::Publish(..) | Op::Group(..) => None,
            })
            .collect()
    }
}

fn wide() -> ExtendWindow {
    ExtendWindow::new(1024, Instant::now() + Duration::from_secs(30)).unwrap()
}

fn ids(endpoints: &[AttachedEndpoint]) -> Vec<u32> {
    endpoints.iter().map(|endpoint| endpoint.id.0).collect()
}

fn delta_ids(delta: &TargetDelta) -> Vec<u32> {
    delta
        .endpoints
        .iter()
        .map(|endpoint| endpoint.id.0)
        .collect()
}

#[test]
fn extend_after_activation_attaches_only_new_ids_and_publishes_each_before_its_link() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 3);
    let mut harness = Harness::new(64, None);
    let receipt = harness.extend(first.clone(), &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 1, 2]);
    assert!(receipt.failed.is_empty() && receipt.known.is_empty());
    assert!(receipt.deferred.endpoints.is_empty());

    let second = fixture.pass("b.so", 2);
    assert_eq!(delta_ids(&second), [3, 4], "the set appends only B");
    let receipt = harness.extend(second.clone(), &fixture.set);
    assert_eq!(ids(&receipt.attached), [3, 4]);

    // A resubmitted (overlapping) delta attaches nothing again.
    let mut both = first;
    both.append(second);
    let receipt = harness.extend(both, &fixture.set);
    assert!(receipt.attached.is_empty() && receipt.failed.is_empty());
    assert_eq!(
        receipt.known.iter().map(|id| id.0).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4]
    );
    assert_eq!(
        harness.attached_ops(),
        [0, 1, 2, 3, 4],
        "each ID attached once"
    );
    // Publish strictly precedes its own attach, with the attach-set object.
    let ops = harness.ops();
    for id in 0..5u32 {
        let publish = ops
            .iter()
            .position(|op| matches!(op, Op::Publish(endpoint, _) if *endpoint == id))
            .unwrap();
        let attach = ops.iter().position(|op| *op == Op::Attach(id)).unwrap();
        assert!(
            publish < attach,
            "endpoint {id} attached before publication"
        );
    }
    assert!(ops.contains(&Op::Publish(0, 0)) && ops.contains(&Op::Publish(3, 1)));
    assert_eq!(harness.links.len(), 5);
    // Attach instants rise with the clock, after each entry's checks.
    assert!(harness.book.attached.len() == 5 && harness.book.failed.is_empty());
}

#[test]
fn a_mid_extend_failure_keeps_link_custody_and_other_endpoints_active() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 5);
    let mut harness = Harness::new(64, None);
    harness.io.refuse.insert(1);
    harness.io.poison.insert(3);
    let receipt = harness.extend(delta, &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 2, 4]);
    let failed: Vec<(u32, bool)> = receipt
        .failed
        .iter()
        .map(|failure| (failure.id.0, failure.link_retained))
        .collect();
    assert_eq!(failed, [(1, false), (3, true)]);
    assert!(receipt.failed[0].reason.contains("kernel refused entry 1"));
    assert!(
        receipt.failed[1]
            .reason
            .contains("post-acquisition failure on 3")
    );
    // Entry 3's link is still owned; nothing was closed behind the receipt.
    assert_eq!(harness.links.len(), 4);
    assert_eq!(harness.io.log.lock().unwrap().live, 4);
    assert!(
        harness
            .links
            .iter()
            .any(|link| link.target == super::super::activation::InventoryLinkIdentity::Entry(3))
    );
    // A failed ID is never retried, even when resubmitted.
    harness.io.refuse.clear();
    harness.io.poison.clear();
    let again = harness.extend(
        TargetDelta {
            endpoints: fixture.set.endpoints().copied().collect(),
            objects: vec![],
        },
        &fixture.set,
    );
    assert!(again.attached.is_empty());
    assert_eq!(again.known.len(), 5);
}

#[test]
fn an_extend_with_a_changed_pin_refuses_that_object_before_publication() {
    let mut fixture = SetFixture::new(64);
    let a = fixture.pass("a.so", 2);
    let b = fixture.pass("b.so", 2);
    let mut harness = Harness::new(64, None);
    // Rewrite a.so in place after the set retained it.
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture.paths[0])
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    let mut both = a;
    both.append(b);
    let receipt = harness.extend(both, &fixture.set);
    assert_eq!(ids(&receipt.attached), [2, 3], "b.so stays extendable");
    assert_eq!(
        receipt.failed.iter().map(|f| f.id.0).collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(
        receipt
            .failed
            .iter()
            .all(|failure| failure.reason.contains("changed") && !failure.link_retained),
        "{:?}",
        receipt.failed
    );
    assert!(
        !harness
            .ops()
            .iter()
            .any(|op| matches!(op, Op::Publish(0 | 1, _) | Op::Attach(0 | 1))),
        "a changed object was published or attached"
    );
}

#[test]
fn an_id_outside_the_prepared_capacity_or_an_abi_mismatch_never_publishes() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 3);
    // The capture was prepared with N = 2: endpoint 2 is out of range.
    let mut harness = Harness::new(2, None);
    let mut bad = delta.clone();
    bad.endpoints[1].abi = p11scope_manifest::elf::ElfAbi::Ilp32;
    let receipt = harness.extend(bad, &fixture.set);
    assert_eq!(ids(&receipt.attached), [0]);
    let reasons: Vec<&str> = receipt.failed.iter().map(|f| f.reason.as_str()).collect();
    assert!(reasons[0].contains("ABI"), "{reasons:?}");
    assert!(reasons[1].contains("exceeds N"), "{reasons:?}");
    assert_eq!(harness.attached_ops(), [0]);
}

#[test]
fn a_spent_window_defers_the_rest_and_a_later_extend_finishes_it() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 5);
    let mut harness = Harness::new(64, None);
    let receipt = harness.extend_with_custody(
        delta,
        &fixture.set,
        ExtendWindow::new(2, Instant::now() + Duration::from_secs(30)).unwrap(),
        &mut || Ok(()),
    );
    assert_eq!(ids(&receipt.attached), [0, 1]);
    assert_eq!(delta_ids(&receipt.deferred), [2, 3, 4]);
    let expired = harness.extend_with_custody(
        receipt.deferred,
        &fixture.set,
        ExtendWindow::new(8, Instant::now()).unwrap(),
        &mut || Ok(()),
    );
    assert!(expired.attached.is_empty());
    assert_eq!(delta_ids(&expired.deferred), [2, 3, 4]);
    let rest = harness.extend(expired.deferred, &fixture.set);
    assert_eq!(ids(&rest.attached), [2, 3, 4]);
}

#[test]
fn custody_lost_after_an_attach_fails_that_entry_with_its_link_and_defers_the_rest() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 4);
    let mut harness = Harness::new(64, Some(4242));
    let mut checks = 0;
    let receipt = harness.extend_with_custody(delta, &fixture.set, wide(), &mut || {
        checks += 1;
        if checks == 2 {
            Err("original exited".into())
        } else {
            Ok(())
        }
    });
    assert_eq!(ids(&receipt.attached), [0]);
    assert_eq!(receipt.failed.len(), 1);
    assert_eq!(receipt.failed[0].id.0, 1);
    assert!(
        receipt.failed[0].link_retained,
        "the suspect link stays owned"
    );
    assert!(receipt.failed[0].reason.contains("PID custody lost"));
    assert_eq!(delta_ids(&receipt.deferred), [2, 3]);
    assert!(matches!(
        harness.book.custody(),
        ScopeCustody::PidLost { .. }
    ));
    assert_eq!(harness.links.len(), 2);
}

#[test]
fn zero_windows_refuse() {
    assert!(ReadWindow::new(0, Instant::now()).is_err());
    assert!(ExtendWindow::new(0, Instant::now()).is_err());
    assert!(ReadWindow::new(1, Instant::now()).is_ok());
}

#[test]
fn pid_scope_without_a_live_original_pidfd_refuses_before_anything_loads() {
    // A start-time fallback pin is never PID-scope custody.
    let error = InventoryCapture::prepare(
        CaptureScope::Pid(PidPin::test_proc_only(std::process::id())),
        budget(4),
        caller_budget(budget(4), 2).unwrap(),
        AttachBackend::Singles,
    )
    .err()
    .expect("a start-time pin was accepted");
    assert!(format!("{error:#}").contains("original pidfd"), "{error:#}");

    // An exited original refuses, whatever now holds its PID.
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pin = PidPin::open(child.id()).unwrap();
    child.wait().unwrap();
    let error = InventoryCapture::prepare(
        CaptureScope::Pid(pin),
        budget(4),
        caller_budget(budget(4), 2).unwrap(),
        AttachBackend::Singles,
    )
    .err()
    .expect("an exited PID target was accepted");
    assert!(format!("{error:#}").contains("exited"), "{error:#}");

    // C5.11: the facade admits Multi; an unprivileged run fails only at
    // the object load, never at a backend refusal.
    if let Err(error) = InventoryCapture::prepare(
        CaptureScope::System,
        budget(4),
        caller_budget(budget(4), 2).unwrap(),
        AttachBackend::Multi,
    ) {
        assert!(!format!("{error:#}").contains("Singles"), "{error:#}");
    }
}

#[test]
fn capture_activation_admits_pid_only_with_matching_live_custody() {
    let targets = InventoryTargets::for_capture(budget(4));
    let me = PidPin::open(std::process::id()).unwrap();
    super::super::activation::validate_capture_activation(
        &Scope::Pid(std::process::id()),
        Some(&me),
        AttachBackend::Singles,
        budget(4),
        &targets,
    )
    .unwrap();
    for (scope, pin, expected) in [
        (Scope::Pid(std::process::id()), None, "custody"),
        (Scope::Pid(std::process::id() + 1), Some(&me), "instead of"),
        (
            Scope::Pid(std::process::id()),
            Some(&PidPin::test_proc_only(std::process::id())),
            "original pidfd",
        ),
    ] {
        let error = super::super::activation::validate_capture_activation(
            &scope,
            pin,
            AttachBackend::Singles,
            budget(4),
            &targets,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
    // C5.11: the capture path admits Multi (its entries attach as groups).
    super::super::activation::validate_capture_activation(
        &Scope::System,
        None,
        AttachBackend::Multi,
        budget(4),
        &targets,
    )
    .unwrap();
}

#[test]
fn the_default_caller_budget_is_p_65536_with_exact_payload() {
    let callers = default_caller_budget(budget(4096)).unwrap();
    assert_eq!(callers.pair_limit(), 65_536);
    assert_eq!(callers.endpoint_budget(), budget(4096));
    assert_eq!(callers.additional_payload_bytes(), 4096 * 8 + 65_536 * 56);
}

#[test]
fn the_seen_set_bound_is_exactly_the_caller_use_capacity() {
    // C5.2 review fix 3: the coordinator withholds (never demotes) on a
    // full seen set only because the set fills exactly when the
    // insert-only CALLER_USE map does.
    use super::super::callers::{caller_use_capacity, seen_limit};
    for callers in [
        default_caller_budget(budget(4096)).unwrap(),
        CallerBudget::new(budget(4), 5, 4 * 8 + 5 * 56).unwrap(),
    ] {
        let capacity = caller_use_capacity(callers).unwrap();
        assert_eq!(u64::from(capacity), callers.pair_limit());
        assert_eq!(seen_limit(callers).unwrap(), capacity as usize);
        let mut book = test_book(4, seen_limit(callers).unwrap(), None);
        let batch = read_witnesses_from(
            None,
            &mut book,
            CapturePhase::Active,
            ReadWindow::new(1, Instant::now()).unwrap(),
        );
        assert_eq!(batch.pair_limit, capacity as usize);
    }
}

/// A scripted CALLER_USE map in BTreeMap key order.
#[derive(Default)]
struct FakeRows {
    rows: BTreeMap<super::super::callers::CallerRowKey, (CallerObjectKey, Option<CallerObjectUse>)>,
    syscalls: usize,
    /// lookup() fails for rows with these cookies.
    unreadable: BTreeSet<u64>,
}

impl FakeRows {
    fn insert(&mut self, key: CallerObjectKey, value: Option<CallerObjectUse>) {
        self.rows
            .insert(super::super::callers::row_key(&key), (key, value));
    }
}

impl CallerUseIo for FakeRows {
    fn next_key(&mut self, after: Option<&CallerObjectKey>) -> Result<Option<CallerObjectKey>> {
        self.syscalls += 1;
        let next = match after {
            None => self.rows.values().next(),
            Some(key) => self
                .rows
                .range((
                    std::ops::Bound::Excluded(super::super::callers::row_key(key)),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(_, row)| row),
        };
        Ok(next.map(|(key, _)| *key))
    }

    fn lookup(&mut self, key: &CallerObjectKey) -> Result<Option<CallerObjectUse>> {
        self.syscalls += 1;
        if self.unreadable.contains(&key.image.task_cookie) {
            bail!("lookup of cookie {} failed", key.image.task_cookie);
        }
        Ok(self
            .rows
            .get(&super::super::callers::row_key(key))
            .and_then(|(_, value)| *value))
    }
}

fn key(cookie: u64, object: u32) -> CallerObjectKey {
    CallerObjectKey {
        image: ImageIdentity {
            task_cookie: cookie,
            exec_id: 7,
        },
        object_id: object,
        reserved: 0,
    }
}

fn value(tgid: u32, endpoint: u32) -> CallerObjectUse {
    CallerObjectUse {
        recorded_at_ns: 99,
        recent_bucket: 0,
        host_tgid: tgid,
        witness_endpoint: endpoint,
        flags: 1,
        reserved: 0,
    }
}

#[test]
fn the_caller_cursor_reports_each_row_once_and_keeps_every_invalid_row_as_integrity() {
    let mut rows = FakeRows::default();
    rows.insert(key(1, 0), Some(value(40, 0))); // valid
    rows.insert(key(2, 0), Some(value(41, 1))); // foreign tgid under PID scope 40
    rows.insert(key(3, 0), Some(value(40, 3))); // endpoint 3 < N, unpublished
    rows.insert(key(4, 1), Some(value(40, 0))); // endpoint 0 is bound to object 0
    rows.insert(
        key(5, 0),
        Some(CallerObjectUse {
            flags: 3,
            ..value(40, 0)
        }),
    );
    rows.insert(
        CallerObjectKey {
            reserved: 1,
            ..key(6, 0)
        },
        Some(value(40, 0)),
    );
    rows.insert(key(7, 0), None); // vanished between key and lookup
    let mut cursor = CallerUseCursor::new(64);
    let published: BTreeMap<u32, u32> = [(0, 0), (1, 0)].into();
    let read = |cursor: &mut CallerUseCursor, rows: &mut FakeRows, max| {
        cursor.read_with(
            rows,
            max,
            Instant::now() + Duration::from_secs(5),
            4,
            |endpoint| published.get(&endpoint).copied(),
            |_, value| (value.host_tgid != 40).then(|| "foreign".to_string()),
        )
    };
    let first = read(&mut cursor, &mut rows, 3);
    assert_eq!(first.visited, 3);
    assert!(first.row_bound_reached && !first.sweep_completed);
    let second = read(&mut cursor, &mut rows, 100);
    assert!(second.sweep_completed && !second.row_bound_reached);
    let all_rows: Vec<u64> = first
        .rows
        .iter()
        .chain(&second.rows)
        .map(|(key, _)| key.image.task_cookie)
        .collect();
    assert_eq!(all_rows, [1]);
    let faults: Vec<(u64, CallerRowFault)> = first
        .faults
        .iter()
        .chain(&second.faults)
        .map(|(key, _, fault)| (key.image.task_cookie, fault.clone()))
        .collect();
    assert_eq!(
        faults,
        [
            (2, CallerRowFault::Rejected("foreign".into())),
            (3, CallerRowFault::UnpublishedEndpoint),
            (4, CallerRowFault::BindingMismatch { published: 0 }),
            (5, CallerRowFault::InvalidValue),
            (6, CallerRowFault::InvalidKey),
            (7, CallerRowFault::Vanished),
        ]
    );
    assert_eq!(cursor.occupancy(), 7);
    // A new sweep reports only the new row; old rows are never repeated.
    rows.insert(key(8, 0), Some(value(40, 1)));
    let third = read(&mut cursor, &mut rows, 100);
    assert!(third.sweep_completed);
    assert_eq!(third.rows.len(), 1);
    assert_eq!(third.rows[0].0.image.task_cookie, 8);
    assert!(third.faults.is_empty());
    assert_eq!(cursor.sweeps_completed(), 2);
}

#[test]
fn the_caller_cursor_is_bounded_by_its_deadline_and_seen_limit() {
    let mut rows = FakeRows::default();
    for cookie in 1..=4 {
        rows.insert(key(cookie, 0), Some(value(40, 0)));
    }
    let mut cursor = CallerUseCursor::new(2);
    let expired = cursor.read_with(&mut rows, 10, Instant::now(), 4, |_| Some(0), |_, _| None);
    assert!(expired.deadline_reached && expired.visited == 0);
    assert_eq!(rows.syscalls, 0, "an expired deadline issues no syscall");
    let read = cursor.read_with(
        &mut rows,
        10,
        Instant::now() + Duration::from_secs(5),
        4,
        |_| Some(0),
        |_, _| None,
    );
    assert_eq!(read.rows.len(), 2);
    assert_eq!(read.unrecorded, 2, "rows past the bound are counted");
    assert_eq!(cursor.occupancy(), 2);
}

#[test]
fn witness_batches_name_the_attach_object_and_count_integrity_rows() {
    let mut book = test_book(8, 8, None);
    let mut fixture = SetFixture::new(8);
    let delta = fixture.pass("a.so", 2);
    for endpoint in &delta.endpoints {
        book.published.insert(endpoint.id.0, endpoint.object);
    }
    let mut rows = FakeRows::default();
    rows.insert(key(1, 0), Some(value(40, 1)));
    rows.insert(key(2, 5), Some(value(41, 0)));
    let published = book.published.clone();
    let read = book.cursor.read_with(
        &mut rows,
        16,
        Instant::now() + Duration::from_secs(5),
        8,
        |endpoint| published.get(&endpoint).map(|object| object.index()),
        |_, _| None,
    );
    let mut batch = read_witnesses_from(
        None,
        &mut book,
        CapturePhase::Active,
        ReadWindow::new(1, Instant::now()).unwrap(),
    );
    absorb_rows(&mut book, &mut batch, read);
    assert_eq!(batch.rows.len(), 1);
    assert_eq!(batch.rows[0].object, delta.endpoints[1].object);
    assert_eq!(batch.rows[0].endpoint, EndpointId(1));
    assert_eq!(batch.rows[0].domain, book.domain);
    assert_eq!(batch.integrity.len(), 1);
    assert!(batch.integrity[0].reason.contains("bound to object 0"));
    assert_eq!(batch.integrity_total, 1);
    assert_eq!(book.integrity_total, 1);
}

fn control(unavailable: u64) -> ImageIdentityControl {
    ImageIdentityControl {
        limit: 16_384,
        next_ticket: 3,
        unavailable,
        create_failures: 0,
        retry_exhausted: 0,
    }
}

fn health(caller: [u64; 4], usage: [u64; 3], unavailable: u64) -> CaptureHealth {
    CaptureHealth {
        caller_evidence: Some(caller),
        caller_control: Some(control(unavailable)),
        usage_evidence: Some(usage),
        evidence: Some([0; 9]),
        owner: Some(ThreadOwnerControl::default()),
        ..CaptureHealth::default()
    }
}

#[test]
fn a_watch_counter_rise_is_one_regression_and_unreadable_health_is_unproven_not_sticky() {
    let mut book = test_book(8, 8, None);
    assert_eq!(regression(&mut book, &health([0; 4], [0; 3], 0)), None);
    let rose = regression(&mut book, &health([0, 0, 2, 0], [0; 3], 0)).unwrap();
    assert!(rose.contains("CALLER_EVIDENCE[2] 0->2"), "{rose}");
    // The same elevated counters are not a second regression.
    assert_eq!(
        regression(&mut book, &health([0, 0, 2, 0], [0; 3], 0)),
        None
    );
    let identity = regression(&mut book, &health([0, 0, 2, 0], [0, 1, 0], 4)).unwrap();
    assert!(identity.contains("USAGE_EVIDENCE[1]") && identity.contains("COOKIE_CTL"));
    // I5: unreadable health is unproven for that read only — never a
    // regression, never sticky — and the baseline stays, so a rise hidden
    // behind it is reported by the next readable read.
    let unreadable = CaptureHealth {
        failures: vec!["CALLER_EVIDENCE[0]: denied".into()],
        ..health([0, 0, 2, 0], [0, 1, 0], 4)
    };
    let assessed = assess_health(&mut book, &unreadable);
    assert_eq!(assessed.regression, None);
    assert!(
        assessed
            .unproven
            .as_deref()
            .is_some_and(|reason| reason.contains("unreadable")),
        "{assessed:?}"
    );
    let missing = CaptureHealth {
        owner: None,
        ..health([0, 0, 2, 0], [0, 1, 0], 4)
    };
    assert!(assess_health(&mut book, &missing).unproven.is_some());
    assert_eq!(
        assess_health(&mut book, &health([0, 0, 2, 0], [0, 1, 0], 4)),
        HealthAssessment::default(),
        "readable again: proven, nothing rose"
    );
    let _ = assess_health(&mut book, &unreadable);
    let hidden = assess_health(&mut book, &health([0, 0, 3, 0], [0, 1, 0], 4));
    assert!(
        hidden
            .regression
            .as_deref()
            .is_some_and(|reason| reason.contains("CALLER_EVIDENCE[2] 2->3")),
        "{hidden:?}"
    );
    assert_eq!(hidden.unproven, None);
}

#[test]
fn a_cookie_answer_needs_the_pidfd_live_before_and_after_the_lookup() {
    let domain = NativeDomainId::mint();
    let found = query_cookie_with(
        domain,
        || Ok(false),
        |value| {
            *value = 17;
            Ok(())
        },
    );
    assert_eq!(found, CookieQuery::Cookie(DomainCookie::new(domain, 17)));
    let CookieQuery::Cookie(cookie) = found else {
        unreachable!()
    };
    assert_eq!(cookie.domain(), domain);
    assert_ne!(NativeDomainId::mint(), domain, "domains are never shared");
    let absent = query_cookie_with(
        domain,
        || Ok(false),
        |_| Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
    );
    assert_eq!(absent, CookieQuery::NoCookie);
    let mut looked_up = false;
    let before = query_cookie_with(
        domain,
        || Ok(true),
        |_| {
            looked_up = true;
            Ok(())
        },
    );
    assert_eq!(before, CookieQuery::Exited);
    assert!(!looked_up, "a dead pidfd is never looked up");
    let polls = std::cell::Cell::new(0);
    let after = query_cookie_with(
        domain,
        || {
            polls.set(polls.get() + 1);
            Ok(polls.get() > 1)
        },
        |value| {
            *value = 17;
            Ok(())
        },
    );
    assert_eq!(
        after,
        CookieQuery::Exited,
        "exit during the lookup voids it"
    );
    assert!(matches!(
        query_cookie_with(domain, || Ok(false), |_| Ok(())),
        CookieQuery::Unavailable(reason) if reason.contains("zero")
    ));
}

#[test]
fn pid_scope_marks_an_exec_of_its_target_and_ignores_other_processes() {
    let mut book = test_book(8, 8, Some(40));
    assert_eq!(book.custody(), ScopeCustody::PidHeld);
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_EXEC;
    record.pid_tgid = (41u64 << 32) | 41;
    record.hook_ts_ns = 5;
    book.observe_record(&record);
    assert_eq!(book.custody(), ScopeCustody::PidHeld);
    record.pid_tgid = (40u64 << 32) | 40;
    record.hook_ts_ns = 6;
    book.observe_record(&record);
    record.hook_ts_ns = 9;
    book.observe_record(&record);
    assert!(
        matches!(book.custody(), ScopeCustody::PidUnproven { at_ns: 6, ref reason } if reason.contains("exec")),
        "{:?}",
        book.custody()
    );
    let mut system = test_book(8, 8, None);
    system.observe_record(&record);
    assert_eq!(system.custody(), ScopeCustody::System);
}

// ---- Review fixes (RED first) ----

fn owner(poison: u64, admission: u64, reclamation: u64) -> ThreadOwnerControl {
    ThreadOwnerControl {
        limit: 64,
        poison,
        admission_failures: admission,
        reclamation_failures: reclamation,
        ..ThreadOwnerControl::default()
    }
}

fn full_health(evidence: [u64; 9], owner: ThreadOwnerControl) -> CaptureHealth {
    CaptureHealth {
        evidence: Some(evidence),
        owner: Some(owner),
        ..health([0; 4], [0; 3], 0)
    }
}

#[test]
fn owner_poison_owner_failures_and_any_evidence_rise_are_regressions() {
    // I1: scope_auth drops every entry once OWNER_CTL is poisoned, and an
    // ABI refusal drops an entry counting only EVIDENCE; both silence use.
    let mut book = test_book(8, 8, None);
    assert_eq!(
        regression(&mut book, &full_health([0; 9], owner(0, 0, 0))),
        None
    );
    let poison = regression(&mut book, &full_health([0; 9], owner(1, 0, 0)));
    assert!(
        poison.as_deref().is_some_and(|r| r.contains("poison")),
        "{poison:?}"
    );
    assert_eq!(
        regression(&mut book, &full_health([0; 9], owner(1, 0, 0))),
        None,
        "one poison transition is one regression"
    );
    let failures = regression(&mut book, &full_health([0; 9], owner(1, 1, 0)));
    assert!(
        failures
            .as_deref()
            .is_some_and(|r| r.contains("admission_failures")),
        "{failures:?}"
    );
    let reclamation = regression(&mut book, &full_health([0; 9], owner(1, 1, 2)));
    assert!(
        reclamation
            .as_deref()
            .is_some_and(|r| r.contains("reclamation_failures")),
        "{reclamation:?}"
    );
    for cell in 0..9 {
        let mut evidence = [0; 9];
        evidence[cell] = 1;
        let mut fresh = test_book(8, 8, None);
        let rose = regression(&mut fresh, &full_health(evidence, owner(0, 0, 0)));
        assert!(
            rose.as_deref()
                .is_some_and(|r| r.contains(&format!("EVIDENCE[{cell}]"))),
            "EVIDENCE[{cell}] rise was not a regression: {rose:?}"
        );
    }
}

#[test]
fn an_older_deferred_backlog_attaches_after_a_newer_delta() {
    // I6: extend(new) before the older deferred IDs must not fail them.
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 4);
    let mut harness = Harness::new(64, None);
    let receipt = harness.extend_with_custody(
        first,
        &fixture.set,
        ExtendWindow::new(1, Instant::now() + Duration::from_secs(30)).unwrap(),
        &mut || Ok(()),
    );
    assert_eq!(ids(&receipt.attached), [0]);
    let backlog = receipt.deferred;
    let newer = fixture.pass("b.so", 2);
    assert_eq!(ids(&harness.extend(newer, &fixture.set).attached), [4, 5]);
    let older = harness.extend(backlog, &fixture.set);
    assert!(older.failed.is_empty(), "{:?}", older.failed);
    assert_eq!(ids(&older.attached), [1, 2, 3]);
    // The table stays sorted for the per-ID binary searches, and an ID is
    // never recorded twice.
    assert_eq!(harness.targets.entry_ids(), [0, 1, 2, 3, 4, 5]);
    let again = InventoryEndpoint {
        id: 2,
        object: PinnedObjectId(0),
        file_offset: 0,
        abi: p11scope_manifest::elf::ElfAbi::Lp64,
    };
    let error = harness.targets.record_entry(again).unwrap_err();
    assert!(
        format!("{error:#}").contains("already recorded"),
        "{error:#}"
    );
    assert_eq!(harness.targets.entry_ids(), [0, 1, 2, 3, 4, 5]);
}

#[test]
fn a_row_inserted_behind_the_cursor_mid_sweep_is_reported_next_sweep() {
    // M5: hash order puts a new row before the cursor; never lost.
    let mut rows = FakeRows::default();
    for cookie in [10, 20, 30] {
        rows.insert(key(cookie, 0), Some(value(40, 0)));
    }
    let mut cursor = CallerUseCursor::new(64);
    let read = |cursor: &mut CallerUseCursor, rows: &mut FakeRows, max| {
        cursor.read_with(
            rows,
            max,
            Instant::now() + Duration::from_secs(5),
            4,
            |_| Some(0),
            |_, _| None,
        )
    };
    let first = read(&mut cursor, &mut rows, 2);
    assert_eq!(first.rows.len(), 2);
    rows.insert(key(5, 0), Some(value(40, 0)));
    let rest = read(&mut cursor, &mut rows, 100);
    assert!(rest.sweep_completed);
    assert_eq!(
        rest.rows
            .iter()
            .map(|(k, _)| k.image.task_cookie)
            .collect::<Vec<_>>(),
        [30]
    );
    let next = read(&mut cursor, &mut rows, 100);
    assert!(next.sweep_completed);
    assert_eq!(
        next.rows
            .iter()
            .map(|(k, _)| k.image.task_cookie)
            .collect::<Vec<_>>(),
        [5],
        "the row behind the cursor arrives in the next sweep"
    );
}

#[test]
fn an_emfile_attach_stops_the_window_defers_and_retries_without_republishing() {
    // I4: descriptor exhaustion is not an entry failure. The entry stays
    // published-unattached; a later extend retries only its attach.
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 5);
    let mut harness = Harness::new(64, None);
    harness.io.emfile.insert(2);
    let receipt = harness.extend(delta, &fixture.set);
    assert!(receipt.fd_exhausted);
    assert_eq!(ids(&receipt.attached), [0, 1]);
    assert!(receipt.failed.is_empty(), "{:?}", receipt.failed);
    assert_eq!(delta_ids(&receipt.deferred), [2, 3, 4]);
    assert!(harness.book.published.contains_key(&2) && !harness.book.knows(2));
    assert!(
        !harness.book.published.contains_key(&3),
        "the window stopped at EMFILE"
    );
    harness.io.emfile.clear();
    let retry = harness.extend(receipt.deferred, &fixture.set);
    assert!(!retry.fd_exhausted && retry.failed.is_empty(), "{retry:?}");
    assert_eq!(ids(&retry.attached), [2, 3, 4]);
    let publishes_of_2 = harness
        .ops()
        .iter()
        .filter(|op| matches!(op, Op::Publish(2, _)))
        .count();
    assert_eq!(publishes_of_2, 1, "the retry republished");
    assert_eq!(harness.attached_ops(), [0, 1, 2, 3, 4]);
}

#[test]
fn the_fd_preflight_refuses_a_named_fds_capacity() {
    // N + 2 roots + DISCOVERY + reserve must fit the free soft limit.
    let need = 128 + 3 + FD_RESERVE;
    assert!(fd_preflight(AttachBackend::Singles, 128, need + 10, 10).is_ok());
    let refused = fd_preflight(AttachBackend::Singles, 128, need + 10, 11).unwrap_err();
    assert_eq!(refused.resource, FD_RESOURCE);
    assert!(
        refused.to_string().starts_with("capacity limited (fds)"),
        "{refused}"
    );
    let error = anyhow::Error::new(refused.clone());
    assert_eq!(
        error.downcast_ref::<CaptureCapacityLimited>(),
        Some(&refused)
    );
    assert!(
        fd_preflight(AttachBackend::Singles, u64::MAX, 1 << 20, 0).is_err(),
        "N saturates, never wraps"
    );
    assert!(fds_in_use().unwrap() > 2);
}

fn stat(state: char, start_time: u64) -> std::io::Result<LeaderStat> {
    Ok(LeaderStat {
        state,
        flags: 0x40_0000,
        start_time,
    })
}

#[test]
fn custody_polls_prove_the_pidfd_and_the_leader_thread() {
    assert_eq!(
        poll_custody_with(Some(7), || Ok(false), || stat('S', 7)),
        CustodyPoll::Held
    );
    // Probe-backed: a leader that exited while a worker runs silences the
    // OneProcess entries though the pidfd stays live.
    for state in ['Z', 'X'] {
        assert!(matches!(
            poll_custody_with(Some(7), || Ok(false), || stat(state, 7)),
            CustodyPoll::Unproven(reason) if reason.contains("leader")
        ));
    }
    assert!(matches!(
        poll_custody_with(Some(7), || Ok(false), || stat('R', 8)),
        CustodyPoll::Unproven(reason) if reason.contains("start time")
    ));
    assert!(matches!(
        poll_custody_with(Some(7), || Ok(false), || Err(std::io::Error::from_raw_os_error(libc::EACCES))),
        CustodyPoll::Unproven(reason) if reason.contains("unreadable")
    ));
    let mut read = false;
    assert!(matches!(
        poll_custody_with(
            Some(7),
            || Ok(true),
            || {
                read = true;
                stat('S', 7)
            }
        ),
        CustodyPoll::Lost(_)
    ));
    assert!(!read, "an exited pidfd is never followed by a stat read");
    let polls = std::cell::Cell::new(0);
    assert!(
        matches!(
            poll_custody_with(
                Some(7),
                || {
                    polls.set(polls.get() + 1);
                    Ok(polls.get() > 1)
                },
                || stat('Z', 7)
            ),
            CustodyPoll::Lost(_)
        ),
        "an exit during the stat read voids it"
    );
    // The live test process: its leader runs.
    let me = PidPin::open(std::process::id()).unwrap();
    assert_eq!(poll_custody(Some(&me)), CustodyPoll::Held);
    assert!(matches!(poll_custody(None), CustodyPoll::Lost(_)));

    // Unproven is dated at the last held poll, sticky, first reason wins.
    let mut book = test_book(8, 8, Some(40));
    book.absorb_poll(CustodyPoll::Held, 150);
    book.absorb_poll(CustodyPoll::Unproven("leader exited".into()), 300);
    book.absorb_poll(CustodyPoll::Held, 400);
    book.absorb_poll(CustodyPoll::Unproven("other".into()), 500);
    assert_eq!(
        book.custody(),
        ScopeCustody::PidUnproven {
            at_ns: 150,
            reason: "leader exited".into()
        }
    );
    book.absorb_poll(CustodyPoll::Lost("the PID target exited".into()), 600);
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidLost { at_ns: 150, ref reason } if reason.contains("PID custody lost")
    ));
    let mut system = test_book(8, 8, None);
    system.absorb_poll(CustodyPoll::Unproven("x".into()), 1);
    assert_eq!(system.custody(), ScopeCustody::System);
}

#[test]
fn pid_scope_lifecycle_loss_makes_custody_unproven() {
    // I3: ring loss, malformed records, and a failed discovery quantum may
    // have hidden an exec of the target.
    let ring = CaptureHealth {
        discovery_counters: Some([2, 0, 0, 0, 0]),
        ..CaptureHealth::default()
    };
    let mut book = test_book(8, 8, Some(40));
    book.health_ns = 170;
    book.observe_lifecycle(&CaptureHealth {
        discovery_counters: Some([0; 5]),
        ..CaptureHealth::default()
    });
    assert_eq!(book.custody(), ScopeCustody::PidHeld);
    book.observe_lifecycle(&ring);
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidUnproven { at_ns: 170, ref reason } if reason.contains("ring loss 0 -> 2")
    ));

    let mut book = test_book(8, 8, Some(40));
    book.observe_lifecycle(&CaptureHealth {
        malformed_discovery: 1,
        ..CaptureHealth::default()
    });
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidUnproven { at_ns: 100, ref reason } if reason.contains("malformed")
    ));

    let mut book = test_book(8, 8, Some(40));
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    let batch = service_with(&mut book, window, |_, _, _| {
        let failure = super::super::activation::InventoryDispatchFailure {
            record: None,
            error: anyhow::anyhow!("short DISCOVERY record"),
            dispatched: 0,
        };
        (Err(failure), true)
    });
    assert!(batch.failure.is_some());
    assert!(!batch.head_pending && !batch.drained());
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidUnproven { ref reason, .. } if reason.contains("short DISCOVERY record")
    ));

    // System scope has no custody: its loss rides the batches instead.
    let mut system = test_book(8, 8, None);
    system.observe_lifecycle(&ring);
    assert_eq!(system.custody(), ScopeCustody::System);
}

#[test]
fn a_system_lifecycle_loss_rides_every_later_batch() {
    // C5.2 D4: system scope has no custody, but a lost exec or exit record
    // may belong to any watched caller: the earliest loss is sticky on
    // every later batch. PID scope keeps reporting it as unproven custody.
    let window = || ReadWindow::new(1, Instant::now()).unwrap();
    let ring = |loss| CaptureHealth {
        discovery_counters: Some([loss, 0, 0, 0, 0]),
        ..CaptureHealth::default()
    };
    let mut system = test_book(8, 8, None);
    system.observe_lifecycle(&ring(0));
    let batch = read_witnesses_from(None, &mut system, CapturePhase::Active, window());
    assert_eq!(batch.lifecycle_loss, None);
    system.health_ns = 170;
    system.observe_lifecycle(&ring(2));
    system.health_ns = 190;
    system.observe_lifecycle(&ring(3));
    for _ in 0..2 {
        let batch = read_witnesses_from(None, &mut system, CapturePhase::Active, window());
        assert!(
            matches!(&batch.lifecycle_loss, Some(LifecycleLoss { at_ns: 170, reason })
                if reason.contains("ring loss 0 -> 2")),
            "{:?}",
            batch.lifecycle_loss
        );
        assert_eq!(batch.custody, ScopeCustody::System);
    }

    let mut system = test_book(8, 8, None);
    let failed = service_with(&mut system, window(), |_, _, _| {
        let failure = super::super::activation::InventoryDispatchFailure {
            record: None,
            error: anyhow::anyhow!("short DISCOVERY record"),
            dispatched: 0,
        };
        (Err(failure), true)
    });
    assert!(failed.failure.is_some());
    let batch = read_witnesses_from(None, &mut system, CapturePhase::Active, window());
    assert!(
        matches!(&batch.lifecycle_loss, Some(LifecycleLoss { at_ns: 100, reason })
            if reason.contains("short DISCOVERY record")),
        "{:?}",
        batch.lifecycle_loss
    );

    let mut pid = test_book(8, 8, Some(40));
    pid.observe_lifecycle(&ring(2));
    let batch = read_witnesses_from(None, &mut pid, CapturePhase::Active, window());
    assert_eq!(batch.lifecycle_loss, None);
    assert!(matches!(batch.custody, ScopeCustody::PidUnproven { .. }));
}

#[test]
fn a_row_naming_a_failed_endpoint_is_integrity_not_a_witness() {
    // M1: a failed endpoint's link may be suspect; its rows never witness.
    let mut book = test_book(8, 8, None);
    let mut fixture = SetFixture::new(8);
    let delta = fixture.pass("a.so", 2);
    for endpoint in &delta.endpoints {
        book.published.insert(endpoint.id.0, endpoint.object);
    }
    book.failed.insert(1, "post-acquisition failure".into());
    let mut rows = FakeRows::default();
    rows.insert(key(1, 0), Some(value(40, 0)));
    rows.insert(key(2, 0), Some(value(40, 1)));
    let published = book.published.clone();
    let failed = book.failed.clone();
    let read = book.cursor.read_with(
        &mut rows,
        16,
        Instant::now() + Duration::from_secs(5),
        8,
        |endpoint| published.get(&endpoint).map(|object| object.index()),
        |_, value| witness_rejection(&failed, None, value),
    );
    let mut batch = read_witnesses_from(
        None,
        &mut book,
        CapturePhase::Active,
        ReadWindow::new(1, Instant::now()).unwrap(),
    );
    absorb_rows(&mut book, &mut batch, read);
    assert_eq!(batch.rows.len(), 1);
    assert_eq!(batch.rows[0].endpoint, EndpointId(0));
    assert_eq!(batch.integrity.len(), 1);
    assert!(
        batch.integrity[0].reason.contains("failed its attach"),
        "{:?}",
        batch.integrity
    );
    assert_eq!(
        witness_rejection(&BTreeMap::new(), Some(40), &value(41, 0)).as_deref(),
        Some("host tgid 41 is outside PID scope 40")
    );
}

#[test]
fn a_sweep_that_skipped_a_row_completes_with_gaps() {
    // M4: a lookup failure (or the seen bound) leaves that sweep with gaps.
    let mut rows = FakeRows::default();
    for cookie in [1, 2, 3] {
        rows.insert(key(cookie, 0), Some(value(40, 0)));
    }
    rows.unreadable.insert(2);
    let mut cursor = CallerUseCursor::new(64);
    let read = |cursor: &mut CallerUseCursor, rows: &mut FakeRows| {
        cursor.read_with(
            rows,
            100,
            Instant::now() + Duration::from_secs(5),
            4,
            |_| Some(0),
            |_, _| None,
        )
    };
    let first = read(&mut cursor, &mut rows);
    assert!(
        first.sweep_completed && first.sweep_gaps,
        "{:?}",
        first.read_failures
    );
    assert_eq!(first.rows.len(), 2);
    rows.unreadable.clear();
    let second = read(&mut cursor, &mut rows);
    assert!(second.sweep_completed && !second.sweep_gaps);
    assert_eq!(second.rows.len(), 1, "the skipped row arrives next sweep");
    let mut bounded = CallerUseCursor::new(1);
    let read = bounded.read_with(
        &mut rows,
        100,
        Instant::now() + Duration::from_secs(5),
        4,
        |_| Some(0),
        |_, _| None,
    );
    assert!(read.sweep_completed && read.sweep_gaps && read.unrecorded == 2);
}

#[test]
fn a_failure_makes_every_later_read_unsettled() {
    // M2: once a capture fails its producers detach: never a settled read.
    let mut capture = InventoryCapture {
        state: CaptureState::Moving,
        book: test_book(8, 8, None),
    };
    capture.fail_with("activation failed".into());
    let batch = capture.read_witnesses(ReadWindow::new(1, Instant::now()).unwrap());
    assert!(batch.unsettled);
    assert!(
        batch.health_unproven.is_some(),
        "no object: health unproven"
    );
    assert_eq!(batch.health_regression, None);
}

#[test]
fn cookies_compare_only_within_their_domain() {
    // M6: one minting point; a ticket never equals another domain's.
    let (one, two) = (NativeDomainId::mint(), NativeDomainId::mint());
    assert_ne!(one, two);
    assert_eq!(DomainCookie::new(one, 5), DomainCookie::new(one, 5));
    assert_ne!(DomainCookie::new(one, 5), DomainCookie::new(two, 5));
    let row = WitnessRow {
        domain: two,
        image: ImageIdentity {
            task_cookie: 5,
            exec_id: 1,
        },
        object: SetFixture::new(4).pass("a.so", 1).endpoints[0].object,
        endpoint: EndpointId(0),
        host_tgid: 1,
        recorded_at_ns: 1,
    };
    assert_eq!(row.cookie(), DomainCookie::new(two, 5));
    assert_eq!(row.cookie().domain(), two);
}

#[test]
fn a_leader_with_pf_exiting_is_unproven_and_polls_stamp_before_the_read() {
    // C3 closure 3: an exiting leader (PF_EXITING, stat field 9) has not
    // reached `Z` yet but its entries are going away.
    let exiting = || {
        Ok(LeaderStat {
            state: 'R',
            flags: 0x40_0004,
            start_time: 7,
        })
    };
    assert!(matches!(
        poll_custody_with(Some(7), || Ok(false), exiting),
        CustodyPoll::Unproven(reason) if reason.contains("exiting")
    ));
    // The real stat of this process parses to its start time, not exiting.
    let me = read_leader_stat(std::process::id()).unwrap();
    assert_eq!(
        me.start_time,
        crate::process::process_start_time(std::process::id()).unwrap()
    );
    assert_eq!(me.flags & 0x4, 0);
    // The held instant is the one taken before the stat read: a leader
    // that exits during the read is never claimed held past it.
    let mut book = test_book(8, 8, Some(40));
    let clock = std::cell::Cell::new(200);
    poll_into(&mut book, &mut || clock.get(), || {
        clock.set(900);
        CustodyPoll::Held
    });
    assert_eq!(book.held_ns, 200);
}

#[test]
fn a_read_with_unproven_health_is_unsettled() {
    // C3 closure 4: a read whose health is unproven is never a settled
    // terminal read, so it can never close a watch as clean.
    let mut book = test_book(8, 8, None);
    let batch = read_witnesses_from(
        None,
        &mut book,
        CapturePhase::Retired,
        ReadWindow::new(1, Instant::now()).unwrap(),
    );
    assert!(batch.health_unproven.is_some());
    assert!(batch.unsettled, "{batch:?}");
}

#[test]
fn a_batch_carries_its_custody_proof_instant() {
    // Closure 2 I-1(b): PID scope reports the last held poll; the machine
    // has no custody to prove.
    let mut book = test_book(8, 8, Some(40));
    book.absorb_poll(CustodyPoll::Held, 170);
    let window = || ReadWindow::new(1, Instant::now()).unwrap();
    let batch = read_witnesses_from(None, &mut book, CapturePhase::Active, window());
    assert_eq!(batch.custody_proven_ns, Some(170));
    let mut system = test_book(8, 8, None);
    let batch = read_witnesses_from(None, &mut system, CapturePhase::Active, window());
    assert_eq!(batch.custody_proven_ns, None);
}

#[test]
fn a_quantum_ending_at_a_busy_head_is_tagged_and_not_drained() {
    // M1/M2 (C4 review): the facade tags the batch with its own domain and
    // reports a busy head, so an empty read never passes for a drain.
    use super::super::activation::InventoryDiscoveryService;
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    let mut book = test_book(8, 8, None);
    let domain = book.domain;

    let batch = service_with(&mut book, window, |_, _, _| {
        (Ok(InventoryDiscoveryService::default()), true)
    });
    assert_eq!(batch.domain, domain);
    assert!(batch.head_pending && !batch.drained());

    let batch = service_with(&mut book, window, |_, _, _| {
        (Ok(InventoryDiscoveryService::default()), false)
    });
    assert!(!batch.head_pending && batch.drained());

    // A bound or deadline stop already says "not drained": the flag stays
    // reserved for an otherwise-empty read.
    let batch = service_with(&mut book, window, |_, _, _| {
        let service = InventoryDiscoveryService {
            deadline_reached: true,
            ..InventoryDiscoveryService::default()
        };
        (Ok(service), true)
    });
    assert!(!batch.head_pending && !batch.drained());
}

/// A live child to pin, killed and reaped by `end`.
struct PinnedChild(std::process::Child);

impl PinnedChild {
    fn spawn() -> Self {
        Self(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep"),
        )
    }

    fn pin(&self) -> PidPin {
        PidPin::open(self.0.id()).expect("pin the child")
    }

    fn end(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for PinnedChild {
    fn drop(&mut self) {
        self.end();
    }
}

#[test]
fn reads_after_stop_repoll_custody_instead_of_reusing_the_last_poll() {
    // C5.2 M-3: a retiring or retired read reports custody as of its own
    // poll: a held poll advances the proof instant past the last active
    // poll, and an exit after stop reads lost, never a stale `PidHeld`.
    let window = || ReadWindow::new(1, Instant::now()).unwrap();
    let mut child = PinnedChild::spawn();
    let pid = child.0.id();
    let mut retiring = RetiringCapture {
        inner: RetiringInner::Unactivated(Some(child.pin())),
        book: test_book(8, 8, Some(pid)),
        failure: None,
    };
    let batch = retiring.read_witnesses(window());
    assert_eq!(batch.custody, ScopeCustody::PidHeld);
    assert!(
        batch.custody_proven_ns.is_some_and(|proven| proven > 100),
        "the retiring read reused the active poll: {:?}",
        batch.custody_proven_ns
    );
    child.end();
    let batch = retiring.read_witnesses(window());
    assert!(
        matches!(&batch.custody, ScopeCustody::PidLost { reason, .. } if reason.contains("exited")),
        "{:?}",
        batch.custody
    );

    let mut child = PinnedChild::spawn();
    let pid = child.0.id();
    let mut retired = RetiredCapture {
        inner: None,
        unactivated_pin: Some(child.pin()),
        book: test_book(8, 8, Some(pid)),
        cleanup: CleanupSummary::default(),
        failure: None,
    };
    let batch = retired.read_witnesses(window());
    assert_eq!(batch.custody, ScopeCustody::PidHeld);
    assert!(
        batch.custody_proven_ns.is_some_and(|proven| proven > 100),
        "the retired read reused the active poll: {:?}",
        batch.custody_proven_ns
    );
    child.end();
    let batch = retired.read_witnesses(window());
    assert!(
        matches!(&batch.custody, ScopeCustody::PidLost { reason, .. } if reason.contains("exited")),
        "{:?}",
        batch.custody
    );
}

/// A drained discovery quantum at `at_ns` (scripted clock).
fn drained_service(book: &mut CaptureBook, at_ns: u64) {
    use super::super::activation::InventoryDiscoveryService;
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    let batch = service_with_clock(book, window, &mut || at_ns, |_, _, _| {
        (Ok(InventoryDiscoveryService::default()), false)
    });
    assert!(batch.drained());
}

/// The C5.2 review scenario up to the clean health read: the ring was
/// last proven drained at 60; a nonleader exec at 150 left a malformed
/// record that is still in the ring when health reads clean at 200.
fn book_with_a_pending_bad_record(scope_pid: Option<u32>) -> CaptureBook {
    let mut book = CaptureBook::new(
        budget(8),
        8,
        scope_pid.map(|pid| ScopeIncarnation {
            pid,
            start_time: None,
        }),
        50,
    );
    drained_service(&mut book, 60);
    book.observe_lifecycle(&CaptureHealth {
        discovery_counters: Some([0; 5]),
        ..CaptureHealth::default()
    });
    book.health_ns = 200;
    book
}

#[test]
fn an_undatable_lifecycle_loss_is_dated_at_the_last_proven_drain() {
    // C5.2 review fix 1: a record that cannot be decoded (or decodes as
    // malformed) carries no instant and may have sat in the ring before
    // the last clean health read. It is dated at the start of the last
    // drain that emptied the ring, never at that health read.
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    for scope in [Some(40), None] {
        // The service at 220 cannot decode the pending record.
        let mut book = book_with_a_pending_bad_record(scope);
        let failed = service_with_clock(&mut book, window, &mut || 220, |_, _, _| {
            let failure = super::super::activation::InventoryDispatchFailure {
                record: None,
                error: anyhow::anyhow!("short DISCOVERY record"),
                dispatched: 0,
            };
            (Err(failure), true)
        });
        assert!(failed.failure.is_some());
        let at = match (book.custody(), book.lifecycle_loss()) {
            (ScopeCustody::PidUnproven { at_ns, .. }, None) => at_ns,
            (ScopeCustody::System, Some(loss)) => loss.at_ns,
            other => panic!("{other:?}"),
        };
        assert_eq!(at, 60, "{scope:?}: dated past the last proven drain");

        // The drain at 220 dequeues it as malformed; health at 260 sees
        // the count. The drain at 220 itself proves nothing about it.
        let mut book = book_with_a_pending_bad_record(scope);
        drained_service(&mut book, 220);
        book.observe_lifecycle(&CaptureHealth {
            discovery_counters: Some([0; 5]),
            malformed_discovery: 1,
            ..CaptureHealth::default()
        });
        let at = match (book.custody(), book.lifecycle_loss()) {
            (ScopeCustody::PidUnproven { at_ns, .. }, None) => at_ns,
            (ScopeCustody::System, Some(loss)) => loss.at_ns,
            other => panic!("{other:?}"),
        };
        assert_eq!(at, 60, "{scope:?}: dated past the drain before the read");
    }
    // Ring loss is a producer counter: it rose after the last health read
    // that saw it lower, so that read still dates it.
    let mut book = book_with_a_pending_bad_record(Some(40));
    book.observe_lifecycle(&CaptureHealth {
        discovery_counters: Some([3, 0, 0, 0, 0]),
        ..CaptureHealth::default()
    });
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidUnproven { at_ns: 200, .. }
    ));
}

/// A discovery quantum that fails to decode a record at `at_ns`.
fn failed_service(book: &mut CaptureBook, at_ns: u64) {
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    let batch = service_with_clock(book, window, &mut || at_ns, |_, _, _| {
        let failure = super::super::activation::InventoryDispatchFailure {
            record: None,
            error: anyhow::anyhow!("short DISCOVERY record"),
            dispatched: 0,
        };
        (Err(failure), true)
    });
    assert!(batch.failure.is_some());
}

fn loss_at(book: &CaptureBook) -> u64 {
    match (book.custody(), book.lifecycle_loss()) {
        (ScopeCustody::PidUnproven { at_ns, .. } | ScopeCustody::PidLost { at_ns, .. }, None) => {
            at_ns
        }
        (ScopeCustody::System, Some(loss)) => loss.at_ns,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_read_carries_the_lifecycle_drain_horizon() {
    // C5.2 closure I-1: the last pass drains the ring at 1000; a record
    // reserved at 1010 is still pending at the clean terminal read at
    // 1020 and is dequeued only after stop. The read is capped at the
    // drain horizon, and the loss found later dates at or after it.
    let window = || ReadWindow::new(1, Instant::now()).unwrap();
    for scope in [Some(40), None] {
        let mut book = CaptureBook::new(
            budget(8),
            8,
            scope.map(|pid| ScopeIncarnation {
                pid,
                start_time: None,
            }),
            50,
        );
        let batch = read_witnesses_from(None, &mut book, CapturePhase::Active, window());
        assert_eq!(batch.lifecycle_proven_ns, 50, "no producer before creation");
        drained_service(&mut book, 1000);
        let terminal = read_witnesses_from(None, &mut book, CapturePhase::Retired, window());
        assert_eq!(terminal.lifecycle_proven_ns, 1000);
        failed_service(&mut book, 1040);
        assert!(loss_at(&book) >= terminal.lifecycle_proven_ns);
    }
}

#[test]
fn a_book_keeps_the_earliest_loss_instant() {
    // C5.2 closure I-1(b), L-2: a later-found loss dated earlier wins, and a
    // lost custody never hides an earlier-dated unproven one (probe B):
    // drained at 60, held poll at 200, an undecodable record at 220, then
    // the target exits.
    let mut book = book_with_a_pending_bad_record(Some(40));
    book.absorb_poll(CustodyPoll::Held, 200);
    failed_service(&mut book, 220);
    book.absorb_poll(CustodyPoll::Lost("the PID target exited".into()), 250);
    assert!(
        matches!(book.custody(), ScopeCustody::PidLost { at_ns: 60, ref reason } if reason.contains("exited")),
        "{:?}",
        book.custody()
    );
    let mut book = test_book(8, 8, Some(40));
    book.mark_unproven(150, "an exec of the PID target was observed".into());
    book.mark_unproven(120, "a lifecycle record was lost".into());
    book.mark_unproven(130, "later".into());
    assert!(matches!(
        book.custody(),
        ScopeCustody::PidUnproven { at_ns: 120, ref reason } if reason.contains("record was lost")
    ));
    // Probe A: a ring-loss rise and a malformed rise in one observation
    // date at the earlier of the two (the malformed record's floor).
    for scope in [Some(40), None] {
        let mut book = book_with_a_pending_bad_record(scope);
        book.observe_lifecycle(&CaptureHealth {
            discovery_counters: Some([3, 0, 0, 0, 0]),
            malformed_discovery: 1,
            ..CaptureHealth::default()
        });
        assert_eq!(loss_at(&book), 60, "{scope:?}");
    }
}

#[test]
fn only_a_complete_drain_moves_the_undatable_floor_and_from_its_start() {
    // C5.2 closure M-1: a quantum that stops at its bound, its deadline, or
    // a busy head leaves records in the ring, so it proves nothing.
    use super::super::activation::InventoryDiscoveryService;
    let window = ReadWindow::new(8, Instant::now() + Duration::from_secs(5)).unwrap();
    let partials: [(InventoryDiscoveryService, bool); 3] = [
        (
            InventoryDiscoveryService {
                record_bound_reached: true,
                ..InventoryDiscoveryService::default()
            },
            false,
        ),
        (
            InventoryDiscoveryService {
                deadline_reached: true,
                ..InventoryDiscoveryService::default()
            },
            false,
        ),
        (InventoryDiscoveryService::default(), true),
    ];
    for (service, head_pending) in partials {
        let mut book = book_with_a_pending_bad_record(Some(40));
        let batch = service_with_clock(&mut book, window, &mut || 150, |_, _, _| {
            (Ok(service), head_pending)
        });
        assert!(!batch.drained());
        failed_service(&mut book, 220);
        assert_eq!(loss_at(&book), 60, "a partial quantum moved the floor");
    }
    // A drain that runs from 300 to 340 proves records before 300 only.
    let mut book = book_with_a_pending_bad_record(Some(40));
    let clock = std::cell::Cell::new(300);
    let batch = service_with_clock(
        &mut book,
        window,
        &mut || {
            let now = clock.get();
            clock.set(now + 40);
            now
        },
        |_, _, _| (Ok(InventoryDiscoveryService::default()), false),
    );
    assert!(batch.drained() && batch.finished_ns == 340);
    failed_service(&mut book, 400);
    assert_eq!(loss_at(&book), 300);
}

#[test]
fn a_clock_failure_never_becomes_the_undatable_floor() {
    // C5.2 closure L-1: CLOCK_MONOTONIC failure stamps u64::MAX, safe for a
    // read stamp but not for a floor.
    let mut book = book_with_a_pending_bad_record(Some(40));
    drained_service(&mut book, u64::MAX);
    failed_service(&mut book, 220);
    assert_eq!(loss_at(&book), 60);
    let mut book = CaptureBook::new(
        budget(8),
        8,
        Some(ScopeIncarnation {
            pid: 40,
            start_time: None,
        }),
        u64::MAX,
    );
    failed_service(&mut book, 220);
    assert_eq!(loss_at(&book), 0, "an unstamped creation proves no drain");
}

// ---- C5.11: uprobe-multi attach groups -----------------------------------

#[test]
fn a_multi_extend_attaches_one_group_per_object_after_publishing_every_member() {
    let mut fixture = SetFixture::new(64);
    let _ = fixture.pass("a.so", 3);
    let _ = fixture.pass("b.so", 2);
    let mut both = TargetDelta {
        endpoints: fixture.set.endpoints().copied().collect(),
        objects: vec![],
    };
    assert_eq!(delta_ids(&both), [0, 1, 2, 3, 4]);
    let mut harness = Harness::multi(64, None);
    let receipt = harness.extend(std::mem::take(&mut both), &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 1, 2, 3, 4]);
    assert!(receipt.failed.is_empty() && receipt.deferred.endpoints.is_empty());
    assert_eq!(
        harness.group_ops(),
        [
            ("p11_usage_entry_lp64", vec![0, 1, 2]),
            ("p11_usage_entry_lp64", vec![3, 4])
        ],
        "one link per (object, program)"
    );
    assert!(harness.attached_ops().is_empty(), "no Singles attach");
    // Every member's binding is published before its group's link exists.
    let ops = harness.ops();
    for (position, op) in ops.iter().enumerate() {
        if let Op::Group(_, members) = op {
            for id in members {
                let publish = ops
                    .iter()
                    .position(|op| matches!(op, Op::Publish(endpoint, _) if endpoint == id))
                    .unwrap();
                assert!(publish < position, "member {id} published after its group");
            }
        }
    }
    assert_eq!(harness.links.len(), 2);
    assert_eq!(receipt.groups.len(), 2);
    assert_eq!(receipt.groups[0].members.len(), 3);
    assert_eq!(receipt.groups[1].links, 1);
    // A group's members share one attach instant, stamped after its checks.
    assert_eq!(receipt.attached[0].at_ns, receipt.attached[2].at_ns);
    assert!(receipt.attached[2].at_ns < receipt.attached[3].at_ns);
    harness.assert_group_invariants();
}

#[test]
fn a_later_multi_extend_adds_a_new_group_and_never_touches_an_existing_one() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 3);
    let mut harness = Harness::multi(64, None);
    let receipt = harness.extend(first.clone(), &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 1, 2]);
    let live_before = harness.io.log.lock().unwrap().live;
    let ops_before = harness.ops().len();

    // The next pass re-presents A and adds B: only B forms a group.
    let second = fixture.pass("b.so", 2);
    let mut both = first;
    both.append(second);
    let receipt = harness.extend(both, &fixture.set);
    assert_eq!(ids(&receipt.attached), [3, 4]);
    assert_eq!(
        receipt.known.iter().map(|id| id.0).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    // The old group's link was neither closed nor recreated: one more link
    // only, and the IO saw exactly one new group (B's), nothing for A.
    assert_eq!(harness.io.log.lock().unwrap().live, live_before + 1);
    assert_eq!(
        harness.ops()[ops_before..]
            .iter()
            .filter(|op| matches!(op, Op::Group(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [Op::Group("p11_usage_entry_lp64", vec![3, 4])]
    );
    assert_eq!(harness.book.groups.len(), 2);
    assert_eq!(
        harness.book.groups[0]
            .members
            .iter()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
        [0, 1, 2],
        "the first group's members are unchanged"
    );
    harness.assert_group_invariants();

    // A resubmission of everything forms no group at all.
    let all = TargetDelta {
        endpoints: fixture.set.endpoints().copied().collect(),
        objects: vec![],
    };
    let receipt = harness.extend(all, &fixture.set);
    assert!(receipt.attached.is_empty() && receipt.groups.is_empty());
    assert_eq!(harness.group_ops().len(), 2);
    harness.assert_group_invariants();
}

#[test]
fn a_kernel_refused_site_fails_alone_and_its_siblings_stay_in_one_group() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 5);
    let mut harness = Harness::multi(64, None);
    harness.io.refuse.insert(1);
    let receipt = harness.extend(delta.clone(), &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 2, 3, 4]);
    let failed: Vec<(u32, bool)> = receipt
        .failed
        .iter()
        .map(|failure| (failure.id.0, failure.link_retained))
        .collect();
    assert_eq!(failed, [(1, false)]);
    assert!(receipt.failed[0].reason.contains("in group 0"));
    assert_eq!(
        harness.book.groups[0]
            .members
            .iter()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
        [0, 2, 3, 4]
    );
    // The refused endpoint is never retried.
    harness.io.refuse.clear();
    let again = harness.extend(delta, &fixture.set);
    assert!(again.attached.is_empty() && again.groups.is_empty());
    harness.assert_group_invariants();
}

#[test]
fn a_post_attach_failure_fails_every_member_and_keeps_the_group_link() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 3);
    let second = fixture.pass("b.so", 2);
    let mut harness = Harness::multi(64, None);
    // The group link of A carries its first member, 0.
    harness.io.poison.insert(0);
    let mut both = first;
    both.append(second);
    let receipt = harness.extend(both, &fixture.set);
    assert_eq!(ids(&receipt.attached), [3, 4], "B's group is unaffected");
    let failed: Vec<(u32, bool)> = receipt
        .failed
        .iter()
        .map(|failure| (failure.id.0, failure.link_retained))
        .collect();
    assert_eq!(failed, [(0, true), (1, true), (2, true)]);
    // The link stays in custody under its group (closed whole at stop).
    assert_eq!(harness.links.len(), 2);
    assert_eq!(harness.io.log.lock().unwrap().live, 2);
    assert!(harness.book.attached.iter().all(|id| *id >= 3));
}

#[test]
fn fd_exhaustion_defers_the_group_and_the_rest_published_for_an_attach_only_retry() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 2);
    let second = fixture.pass("b.so", 2);
    let mut harness = Harness::multi(64, None);
    harness.io.emfile.insert(0);
    let mut both = first;
    both.append(second);
    let receipt = harness.extend(both, &fixture.set);
    assert!(receipt.fd_exhausted);
    assert!(receipt.attached.is_empty() && receipt.failed.is_empty());
    let mut deferred = delta_ids(&receipt.deferred);
    deferred.sort_unstable();
    assert_eq!(deferred, [0, 1, 2, 3]);
    assert!(harness.links.is_empty());
    let publishes = harness
        .ops()
        .iter()
        .filter(|op| matches!(op, Op::Publish(..)))
        .count();
    assert_eq!(publishes, 4);
    // The retry attaches without republishing.
    harness.io.emfile.clear();
    let receipt = harness.extend(receipt.deferred, &fixture.set);
    assert_eq!(ids(&receipt.attached), [0, 1, 2, 3]);
    let republished = harness
        .ops()
        .iter()
        .filter(|op| matches!(op, Op::Publish(..)))
        .count();
    assert_eq!(republished, 4, "a published entry retries its attach only");
    harness.assert_group_invariants();
}

/// The attach set with a fixed mapper count for every object: what
/// discovery would report for a provider mapped by `mappers` processes.
struct Mapped<'a> {
    set: &'a InventoryAttachSet,
    mappers: MapperEstimate,
}

impl CaptureTargets for Mapped<'_> {
    fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget> {
        self.set.target(object)
    }

    fn mappers(&self, _object: AttachObjectId) -> MapperEstimate {
        self.mappers
    }
}

fn long_window(n: u64) -> ExtendWindow {
    ExtendWindow::new(n as usize, Instant::now() + Duration::from_secs(30)).unwrap()
}

fn group_sizes(harness: &Harness) -> Vec<usize> {
    harness
        .group_ops()
        .iter()
        .map(|(_, members)| members.len())
        .collect()
}

/// Review M1 (controller ruling): link sizes come from the cost model and
/// the mapper count first, then from the measured per-site cost.
#[test]
fn the_link_size_keeps_whole_tables_for_few_mappers_and_fits_the_target_for_many() {
    let target = MULTI_LINK_TARGET.as_nanos() as u64;
    // Few or unknown mappers: a whole v2.40 / v3.0 table in one link.
    assert_eq!(
        multi_link_sites(MapperEstimate::Unknown, None),
        MULTI_LINK_MAX_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::System(1), None),
        MULTI_LINK_MAX_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::System(50), None),
        MULTI_LINK_MAX_SITES
    );
    // 500 mappers: the estimate fits the 200 ms target.
    let sites = multi_link_sites(MapperEstimate::System(500), None);
    let per_site = MULTI_LINK_SITE_BASE_NS + 500 * MULTI_LINK_SITE_PER_MAPPER_NS;
    assert!(
        sites < MULTI_LINK_MAX_SITES && sites as u64 * per_site <= target,
        "{sites}"
    );
    assert!(
        (sites as u64 + 1) * per_site > target,
        "the largest that fits: {sites}"
    );
    // Clamps at both ends.
    assert_eq!(
        multi_link_sites(MapperEstimate::System(1_000_000), None),
        MULTI_LINK_MIN_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::Unknown, Some(u64::MAX)),
        MULTI_LINK_MIN_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::Unknown, Some(0)),
        MULTI_LINK_MAX_SITES
    );
    // The measured cost overrides the estimate both ways.
    assert_eq!(
        multi_link_sites(MapperEstimate::System(500), Some(1_000)),
        MULTI_LINK_MAX_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::System(1), Some(10_000_000)),
        20
    );
    // Review R4: a scope-limited view starts conservatively, whatever a
    // count would say, and only a measurement grows it.
    assert_eq!(
        multi_link_sites(MapperEstimate::ScopeLimited, None),
        MULTI_LINK_SCOPE_LIMITED_SITES
    );
    assert_eq!(
        multi_link_sites(MapperEstimate::ScopeLimited, Some(1_000)),
        MULTI_LINK_MAX_SITES
    );
}

/// Review M1: with few mappers an (object, program) group attaches in
/// links of the maximum size, the remainder in a last one.
#[test]
fn a_large_object_with_few_mappers_attaches_in_maximum_size_links() {
    let n = (MULTI_LINK_MAX_SITES + 54) as u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let mut harness = Harness::multi(n, None);
    let source = Mapped {
        set: &fixture.set,
        mappers: MapperEstimate::System(1),
    };
    let receipt = harness.extend_with_custody(delta, &source, long_window(n), &mut || Ok(()));
    assert_eq!(receipt.attached.len(), n as usize);
    assert_eq!(group_sizes(&harness), [MULTI_LINK_MAX_SITES, 54]);
    assert_eq!(receipt.groups.len(), 2);
    harness.assert_group_invariants();
}

/// Review M1: the first link of a provider mapped by 500 processes is
/// sized from the estimate; the next ones from what the first measured
/// (here cheap, so they grow to the maximum).
#[test]
fn a_cheap_measured_link_grows_the_next_links_of_that_object() {
    let n = 150u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let mut harness = Harness::multi(n, None);
    let source = Mapped {
        set: &fixture.set,
        mappers: MapperEstimate::System(500),
    };
    let receipt = harness.extend_with_custody(delta, &source, long_window(n), &mut || Ok(()));
    assert_eq!(receipt.attached.len(), n as usize);
    let first = multi_link_sites(MapperEstimate::System(500), None);
    assert_eq!(
        group_sizes(&harness),
        [
            first,
            MULTI_LINK_MAX_SITES,
            n as usize - first - MULTI_LINK_MAX_SITES
        ]
    );
    harness.assert_group_invariants();
}

/// Review R4: under a scope-limited discovery view (`--pid`) the first
/// link of an object starts at the conservative size and the measured cost
/// grows the next ones to the maximum.
#[test]
fn a_scope_limited_view_starts_small_and_grows_from_what_it_measured() {
    let n = 150u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let mut harness = Harness::multi(n, None);
    let source = Mapped {
        set: &fixture.set,
        mappers: MapperEstimate::ScopeLimited,
    };
    let receipt = harness.extend_with_custody(delta, &source, long_window(n), &mut || Ok(()));
    assert_eq!(receipt.attached.len(), n as usize);
    assert_eq!(
        group_sizes(&harness),
        [
            MULTI_LINK_SCOPE_LIMITED_SITES,
            MULTI_LINK_MAX_SITES,
            n as usize - MULTI_LINK_SCOPE_LIMITED_SITES - MULTI_LINK_MAX_SITES
        ]
    );
    harness.assert_group_invariants();
}

/// Review R3: the attach set's own mapper counts reach the link size (the
/// production `CaptureTargets`, not a test double).
#[test]
fn the_attach_sets_noted_mappers_size_the_first_link() {
    let n = 150u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let key = fixture
        .set
        .target(delta.endpoints[0].object)
        .unwrap()
        .object_key();
    fixture.set.note_mappers(true, [(&key, 500)]);
    let mut harness = Harness::multi(n, None);
    let receipt = harness.extend_with_custody(delta, &fixture.set, long_window(n), &mut || Ok(()));
    assert_eq!(receipt.attached.len(), n as usize);
    let first = multi_link_sites(MapperEstimate::System(500), None);
    assert!(first < MULTI_LINK_MAX_SITES, "{first}");
    assert_eq!(group_sizes(&harness)[0], first);
    harness.assert_group_invariants();
}

/// Review M1: an expensive measured link shrinks the next one.
#[test]
fn an_expensive_measured_link_shrinks_the_next_link_of_that_object() {
    let n = 200u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let mut harness = Harness::multi(n, None);
    harness.io.site_delay = Duration::from_millis(3);
    let source = Mapped {
        set: &fixture.set,
        mappers: MapperEstimate::System(1),
    };
    let receipt = harness.extend_with_custody(delta, &source, long_window(n), &mut || Ok(()));
    assert_eq!(receipt.attached.len(), n as usize);
    let sizes = group_sizes(&harness);
    assert_eq!(sizes[0], MULTI_LINK_MAX_SITES);
    // About 3 ms per site measured: 200 ms fits at most 66.
    assert!((40..=66).contains(&sizes[1]), "{sizes:?}");
    harness.assert_group_invariants();
}

/// Review M1: the extend deadline is checked between links, so a slow
/// registration overshoots the window by one link at most; the rest
/// stays published-unattached and retries its attach only.
#[test]
fn the_extend_deadline_stops_between_links() {
    let n = (3 * MULTI_LINK_MAX_SITES) as u64;
    let mut fixture = SetFixture::new(n);
    let delta = fixture.pass("a.so", n);
    let mut harness = Harness::multi(n, None);
    harness.io.group_delay = Duration::from_millis(80);
    let window = ExtendWindow::new(n as usize, Instant::now() + Duration::from_millis(50)).unwrap();
    let receipt = harness.extend_with_custody(delta, &fixture.set, window, &mut || Ok(()));
    assert_eq!(receipt.attached.len(), MULTI_LINK_MAX_SITES);
    assert_eq!(receipt.deferred.endpoints.len(), 2 * MULTI_LINK_MAX_SITES);
    harness.io.group_delay = Duration::ZERO;
    let publishes_before = harness
        .ops()
        .iter()
        .filter(|op| matches!(op, Op::Publish(..)))
        .count();
    let receipt = harness.extend(receipt.deferred, &fixture.set);
    assert_eq!(receipt.attached.len(), 2 * MULTI_LINK_MAX_SITES);
    let publishes_after = harness
        .ops()
        .iter()
        .filter(|op| matches!(op, Op::Publish(..)))
        .count();
    assert_eq!(publishes_before, publishes_after, "a retry attaches only");
    harness.assert_group_invariants();
}

/// Review I1: an entry submitted twice in one delta, its first copy
/// admitted and its second past the window break, is attached once and
/// never also deferred.
#[test]
fn a_duplicate_past_the_window_break_is_known_not_deferred() {
    let mut fixture = SetFixture::new(64);
    let mut delta = fixture.pass("a.so", 4);
    let first = delta.endpoints[0];
    delta.endpoints.push(first);
    let mut harness = Harness::multi(64, None);
    // The window breaks at entry 3; the rest is [3, 0].
    let window = ExtendWindow::new(3, Instant::now() + Duration::from_secs(30)).unwrap();
    let receipt = harness.extend_with_custody(delta, &fixture.set, window, &mut || Ok(()));
    assert_eq!(ids(&receipt.attached), [0, 1, 2]);
    assert_eq!(delta_ids(&receipt.deferred), [3]);
    assert_eq!(receipt.known.iter().map(|id| id.0).collect::<Vec<_>>(), [0]);
    harness.assert_group_invariants();
}

/// Review L1: an EMFILE halt after a bisect leaf already linked closes that
/// leaf and counts it; nothing reaches custody and the members defer.
#[test]
fn a_halt_after_a_linked_leaf_counts_the_closed_leaf_and_defers_the_group() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 4);
    let mut harness = Harness::multi(64, None);
    harness.io.refuse.insert(0);
    harness.io.emfile.insert(3);
    harness.io.leaves_before_halt = 1;
    let receipt = harness.extend(delta, &fixture.set);
    assert!(receipt.fd_exhausted);
    assert_eq!(receipt.halt_closed_links, 1);
    assert!(receipt.attached.is_empty() && receipt.failed.is_empty());
    let mut deferred = delta_ids(&receipt.deferred);
    deferred.sort_unstable();
    assert_eq!(deferred, [0, 1, 2, 3]);
    assert!(harness.links.is_empty(), "no halted leaf reached custody");
    assert_eq!(
        harness.io.log.lock().unwrap().live,
        0,
        "the leaf was closed"
    );
    assert!(harness.book.groups.is_empty());
    assert!(
        harness.book.link_ns_per_site.is_empty(),
        "a halted attach measures no per-site cost"
    );
    harness.assert_group_invariants();
}

/// Review R3: an unsupported-kernel halt after a bisect leaf already
/// linked counts the closed leaf too, fails the members, and records no
/// per-site cost.
#[test]
fn an_unsupported_halt_after_a_linked_leaf_counts_the_closed_leaf() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 3);
    let mut harness = Harness::multi(64, None);
    harness.io.unsupported = true;
    harness.io.leaves_before_halt = 2;
    let receipt = harness.extend(delta, &fixture.set);
    assert_eq!(receipt.halt_closed_links, 2);
    assert_eq!(receipt.failed.len(), 3);
    assert!(receipt.attached.is_empty() && !receipt.fd_exhausted);
    assert!(harness.links.is_empty(), "no halted leaf reached custody");
    assert_eq!(harness.io.log.lock().unwrap().live, 0, "the leaves closed");
    assert!(harness.book.link_ns_per_site.is_empty());
}

/// Review R3: the measured per-site cost sizes only the object that
/// measured it: an expensive first object never shrinks the first link of
/// a cheap one.
#[test]
fn an_expensive_object_does_not_shrink_another_objects_links() {
    let n = MULTI_LINK_MAX_SITES as u64;
    let mut fixture = SetFixture::new(4 * n);
    let mut harness = Harness::multi(4 * n, None);
    // a.so's sites cost 3 ms each: alone, 200 ms would fit 66 per link.
    harness.io.site_delay = Duration::from_millis(3);
    harness.io.slow = (0..n as u32).collect();
    let a = fixture.pass("a.so", n);
    let receipt = harness.extend(a, &fixture.set);
    assert_eq!(receipt.attached.len(), n as usize);
    assert_eq!(group_sizes(&harness), [MULTI_LINK_MAX_SITES]);
    // b.so arrives in a later pass, a whole table of cheap sites.
    let b = fixture.pass("b.so", n);
    assert_eq!(b.endpoints.len(), n as usize);
    let receipt = harness.extend(b, &fixture.set);
    assert_eq!(receipt.attached.len(), n as usize);
    assert_eq!(
        group_sizes(&harness),
        [MULTI_LINK_MAX_SITES, MULTI_LINK_MAX_SITES],
        "b.so keeps whole-table links"
    );
    assert_eq!(
        harness.book.link_ns_per_site.len(),
        2,
        "one cost per object"
    );
    harness.assert_group_invariants();
}

#[test]
fn a_kernel_refusing_multi_after_preparation_fails_the_group_without_fallback() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 2);
    let mut harness = Harness::multi(64, None);
    harness.io.unsupported = true;
    let receipt = harness.extend(delta, &fixture.set);
    assert!(receipt.attached.is_empty());
    assert_eq!(receipt.failed.len(), 2);
    assert!(
        receipt.failed[0]
            .reason
            .contains("uprobe-multi refused by the running kernel"),
        "{:?}",
        receipt.failed
    );
    assert!(harness.attached_ops().is_empty(), "never a Singles attach");
    assert!(harness.links.is_empty());
}

#[test]
fn pid_custody_lost_after_a_group_fails_its_members_and_defers_later_groups() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 2);
    let second = fixture.pass("b.so", 2);
    let mut harness = Harness::multi(64, Some(42));
    let mut both = first;
    both.append(second);
    let mut checks = 0;
    let receipt = harness.extend_with_custody(both, &fixture.set, wide(), &mut || {
        checks += 1;
        Err("the PID target exited".into())
    });
    assert_eq!(checks, 1, "custody is checked after the first group");
    assert!(receipt.attached.is_empty());
    let failed: Vec<(u32, bool)> = receipt
        .failed
        .iter()
        .map(|failure| (failure.id.0, failure.link_retained))
        .collect();
    assert_eq!(failed, [(0, true), (1, true)]);
    assert_eq!(delta_ids(&receipt.deferred), [2, 3]);
    assert!(harness.book.custody_lost.is_some());
    assert_eq!(harness.group_ops().len(), 1);
}

/// Review I2: a group whose every site the kernel refused (a target that
/// died since the extend's custody check refuses with ESRCH) re-checks
/// custody and names its loss, then defers the later groups.
#[test]
fn an_all_refused_group_names_lost_custody_and_defers_later_groups() {
    let mut fixture = SetFixture::new(64);
    let first = fixture.pass("a.so", 2);
    let second = fixture.pass("b.so", 2);
    let mut harness = Harness::multi(64, Some(42));
    harness.io.refuse.extend([0, 1]);
    let mut both = first;
    both.append(second);
    let receipt = harness.extend_with_custody(both, &fixture.set, wide(), &mut || {
        Err("the PID target exited".into())
    });
    assert!(receipt.attached.is_empty());
    let failed: Vec<(u32, bool)> = receipt
        .failed
        .iter()
        .map(|failure| (failure.id.0, failure.link_retained))
        .collect();
    assert_eq!(failed, [(0, false), (1, false)]);
    assert!(
        receipt
            .failed
            .iter()
            .all(|failure| failure.reason.contains("PID custody lost before group")),
        "{:?}",
        receipt.failed
    );
    assert_eq!(delta_ids(&receipt.deferred), [2, 3]);
    assert!(harness.book.custody_lost.is_some());
    harness.assert_group_invariants();
}

#[test]
fn a_multi_extend_honours_the_window_and_defers_the_rest_unpublished() {
    let mut fixture = SetFixture::new(64);
    let delta = fixture.pass("a.so", 5);
    let mut harness = Harness::multi(64, None);
    let window = ExtendWindow::new(3, Instant::now() + Duration::from_secs(30)).unwrap();
    let receipt = harness.extend_with_custody(delta, &fixture.set, window, &mut || Ok(()));
    assert_eq!(ids(&receipt.attached), [0, 1, 2]);
    assert_eq!(delta_ids(&receipt.deferred), [3, 4]);
    let receipt = harness.extend(receipt.deferred, &fixture.set);
    assert_eq!(ids(&receipt.attached), [3, 4]);
    assert_eq!(
        harness.group_ops(),
        [
            ("p11_usage_entry_lp64", vec![0, 1, 2]),
            ("p11_usage_entry_lp64", vec![3, 4])
        ]
    );
    // The same object's later entries form a second group: the first
    // group's record is neither grown nor reused (groups are immutable).
    let groups: Vec<(u32, Vec<u32>)> = harness
        .book
        .groups
        .iter()
        .map(|group| (group.serial, group.members.iter().map(|id| id.0).collect()))
        .collect();
    assert_eq!(groups, [(0, vec![0, 1, 2]), (1, vec![3, 4])]);
    harness.assert_group_invariants();
}

#[test]
fn the_multi_fd_preflight_needs_the_group_bound_not_n() {
    let n = 4096;
    let singles = n + 3 + FD_RESERVE;
    let multi = MULTI_LINK_BOUND + 3 + FD_RESERVE;
    assert!(fd_preflight(AttachBackend::Singles, n, singles - 1, 0).is_err());
    assert!(fd_preflight(AttachBackend::Multi, n, singles - 1, 0).is_ok());
    assert!(fd_preflight(AttachBackend::Multi, n, multi, 0).is_ok());
    let refused = fd_preflight(AttachBackend::Multi, n, multi - 1, 0).unwrap_err();
    assert!(refused.detail.contains("attach-group links"), "{refused}");
    // A small N bounds Multi too.
    assert_eq!(entry_link_bound(AttachBackend::Multi, 16), 16);
    assert_eq!(entry_link_bound(AttachBackend::Singles, n), n);
}

/// Review R1: the loaded-host mode of the I3a cells asserts through this
/// seam, so it must reflect the consumer: reported ring loss marks
/// lifecycle loss naming the count; no loss marks nothing.
#[test]
fn the_system_book_seam_demotes_exactly_on_reported_ring_loss() {
    let health = |ring_loss| super::super::activation::InventoryHealthSnapshot {
        discovery_counters: Some([ring_loss, 0, 0, 0, 0]),
        ..Default::default()
    };
    let demoted = system_book_lifecycle_loss(health(7), 0, 0).expect("ring loss demotes");
    assert!(demoted.contains("0 -> 7"), "{demoted}");
    assert_eq!(system_book_lifecycle_loss(health(0), 0, 0), None);
    let unread = super::super::activation::InventoryHealthSnapshot::default();
    assert_eq!(system_book_lifecycle_loss(unread, 0, 0), None);
}

/// Review R1: every consumer applies one ring-loss rule.
#[test]
fn ring_loss_rises_only_above_what_was_seen() {
    assert_eq!(ring_loss_rose(0, Some([3, 0, 0, 0, 0])), Some(3));
    assert_eq!(ring_loss_rose(3, Some([3, 9, 9, 9, 9])), None);
    assert_eq!(ring_loss_rose(3, Some([4, 0, 0, 0, 0])), Some(4));
    assert_eq!(ring_loss_rose(0, None), None);
}
