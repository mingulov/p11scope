//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private first-use evidence. Never compiled into the public executable.

use p11scope_ebpf_common::Event;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::sync::mpsc::SyncSender;

use crate::discovery::identity::PinnedObjects;
use crate::discovery::scan::{CaptureWorkBudget, ScanOutcome};
use crate::events::EventsDomain;
use crate::process::ProcessView;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    device: u64,
    inode: u64,
    sha256: String,
    file_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Object {
    device: u64,
    inode: u64,
    size: u64,
    ctime_sec: i64,
    ctime_nsec: i64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Endpoint {
    object: Object,
    file_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiscoveryStage {
    LifecycleActive,
    StaticAttached,
    LoaderArmingFinished,
    InitialExportsFinished,
    BeforeLoop,
    BeforeFirstDiscovery,
    AfterFirstDiscovery,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
enum Fact {
    Known {
        object: Object,
        pinned_ns: Option<u64>,
    },
    ScanReturned {
        pid: u32,
        birth_ticks: Option<u64>,
        view: u32,
        mount_ns_device: u64,
        mount_ns_inode: u64,
        memory_requested: bool,
        outcome: &'static str,
        skipped: usize,
        budget_stopped: bool,
        // Raw maps-device identities: never relabeled as file st_dev.
        matching_inode_modules: Vec<(u64, u64, u64, usize)>,
        returned_ns: Option<u64>,
    },
    LoopStarted {
        domain: u64,
        at_ns: Option<u64>,
    },
    DiscoveryLoss {
        stage: DiscoveryStage,
        domain: u64,
        read_started_ns: Option<u64>,
        read_finished_ns: Option<u64>,
        ring_loss: Option<u64>,
    },
    PublicationValidated {
        pid: u32,
        birth_ticks: Option<u64>,
        view: u32,
        mount_ns_device: u64,
        mount_ns_inode: u64,
        mapping_device_major: u64,
        mapping_device_minor: u64,
        mapping_inode: u64,
        tables: usize,
        entries: usize,
        publication_hook_ns: Option<u64>,
        validated_ns: Option<u64>,
    },
    Attached {
        domain: u64,
        slot: u32,
        endpoint: Endpoint,
        post_attach_ns: Option<u64>,
    },
    Call {
        domain: u64,
        slot: u32,
        endpoint: Option<Endpoint>,
        pid_tgid: u64,
        task_cookie: u64,
        exec_id: u64,
        return_ns: u64,
        duration_ns: u64,
        entry_ns: Option<u64>,
        consumed_ns: Option<u64>,
    },
}

#[derive(Serialize)]
pub(crate) struct Journal {
    target: Target,
    owned_pid: u32,
    limit: usize,
    facts: Vec<Fact>,
    dropped: u64,
    dropped_bindings: u64,
    binding_conflicts: u64,
    object_read_errors: u64,
    unsupported_rebuilds: u64,
    notification_drops: u64,
    truncated_scans: u64,
    #[serde(skip)]
    bindings: BTreeMap<(u64, u32), Option<Endpoint>>,
}

impl Journal {
    fn new(target: Target, owned_pid: u32, limit: usize) -> Self {
        assert!((1..=8192).contains(&limit));
        Self {
            target,
            owned_pid,
            limit,
            facts: Vec::with_capacity(limit),
            dropped: 0,
            dropped_bindings: 0,
            binding_conflicts: 0,
            object_read_errors: 0,
            unsupported_rebuilds: 0,
            notification_drops: 0,
            truncated_scans: 0,
            bindings: BTreeMap::new(),
        }
    }

    fn wanted(&self, endpoint: &Endpoint) -> bool {
        endpoint.object.device == self.target.device
            && endpoint.object.inode == self.target.inode
            && endpoint.object.sha256 == self.target.sha256
            && endpoint.file_offset == self.target.file_offset
    }

    fn push(&mut self, fact: Fact) {
        if self.facts.len() < self.limit {
            self.facts.push(fact);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn bind(&mut self, domain: u64, slot: u32, endpoint: Endpoint, at: Option<u64>) {
        if domain == 0 {
            self.dropped_bindings = self.dropped_bindings.saturating_add(1);
            return;
        }
        let key = (domain, slot);
        if let Some(previous) = self.bindings.get_mut(&key) {
            if previous.as_ref() != Some(&endpoint) {
                *previous = None;
                self.binding_conflicts = self.binding_conflicts.saturating_add(1);
                return;
            }
        } else {
            if self.bindings.len() == self.limit {
                self.dropped_bindings = self.dropped_bindings.saturating_add(1);
                return;
            }
            self.bindings.insert(key, Some(endpoint.clone()));
        }
        if self.wanted(&endpoint) {
            self.push(Fact::Attached {
                domain,
                slot,
                endpoint,
                post_attach_ns: at,
            });
        }
    }

    fn call(&mut self, domain: u64, event: &Event, consumed: Option<u64>) {
        if event.event_type != p11scope_ebpf_common::event_type::CALL
            || event.pid_tgid >> 32 != u64::from(self.owned_pid)
        {
            return;
        }
        // Snapshot the binding now. Neither later discovery nor the final
        // display plan may retroactively attribute this consumed record.
        let endpoint = self.bindings.get(&(domain, event.slot)).cloned().flatten();
        self.push(Fact::Call {
            domain,
            slot: event.slot,
            endpoint,
            pid_tgid: event.pid_tgid,
            task_cookie: event.image.task_cookie,
            exec_id: event.image.exec_id,
            return_ns: event.ts_ns,
            duration_ns: event.duration_ns,
            entry_ns: event
                .ts_ns
                .checked_sub(event.duration_ns)
                .filter(|ns| *ns != 0),
            consumed_ns: consumed,
        });
    }

    fn intact(&self) -> bool {
        self.dropped == 0
            && self.dropped_bindings == 0
            && self.binding_conflicts == 0
            && self.object_read_errors == 0
            && self.unsupported_rebuilds == 0
            && self.notification_drops == 0
            && self.truncated_scans == 0
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum NoticeKind {
    LoopStarted,
    TargetAttached,
}

#[derive(Serialize)]
struct Notice {
    kind: NoticeKind,
    domain: u64,
    at_ns: Option<u64>,
}

struct Active {
    journal: Journal,
    // Retain map identity until the journal stops, even if a failed session
    // is replaced. A later kernel map cannot reuse a recorded domain ID.
    domains: BTreeMap<u64, EventsDomain>,
    loss_stages: BTreeSet<(u64, DiscoveryStage)>,
    notices: Option<SyncSender<Notice>>,
    loop_notified: bool,
    attached_notified: bool,
}

impl Active {
    fn hold(&mut self, domain: &EventsDomain) -> bool {
        if !self.domains.contains_key(&domain.id()) {
            if self.domains.len() == self.journal.limit {
                self.journal.dropped_bindings = self.journal.dropped_bindings.saturating_add(1);
                return false;
            }
            self.domains.insert(domain.id(), domain.clone());
        }
        true
    }

    fn notify(&mut self, kind: NoticeKind, domain: u64, at_ns: Option<u64>) {
        let notified = match kind {
            NoticeKind::LoopStarted => &mut self.loop_notified,
            NoticeKind::TargetAttached => &mut self.attached_notified,
        };
        if !*notified {
            *notified = true;
            if let Some(sender) = &self.notices
                && sender
                    .try_send(Notice {
                        kind,
                        domain,
                        at_ns,
                    })
                    .is_err()
            {
                self.journal.notification_drops = self.journal.notification_drops.saturating_add(1);
            }
        }
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
}

fn with_active(action: impl FnOnce(&mut Active)) {
    ACTIVE.with(|state| {
        if let Some(active) = state.borrow_mut().as_mut() {
            action(active);
        }
    });
}

pub(crate) struct Probe {
    // Installation and shutdown belong to the same capture thread.
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Probe {
    fn install(journal: Journal, notices: Option<SyncSender<Notice>>) -> Self {
        ACTIVE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(state.is_none(), "nested first-use probes are not supported");
            *state = Some(Active {
                journal,
                domains: BTreeMap::new(),
                loss_stages: BTreeSet::new(),
                notices,
                loop_notified: false,
                attached_notified: false,
            });
        });
        Self {
            _not_send: std::marker::PhantomData,
        }
    }

    pub(crate) fn finish(self) -> Journal {
        ACTIVE.with(|state| state.borrow_mut().take().expect("installed probe").journal)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        ACTIVE.with(|state| state.borrow_mut().take());
    }
}

fn object(file: &File, sha256: &str) -> std::io::Result<Object> {
    let metadata = file.metadata()?;
    Ok(Object {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        ctime_sec: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        sha256: sha256.to_owned(),
    })
}

pub(crate) fn known(file: &File, sha256: &str) {
    with_active(|a| {
        if sha256 != a.journal.target.sha256 {
            return;
        }
        match object(file, sha256) {
            Ok(object)
                if object.device == a.journal.target.device
                    && object.inode == a.journal.target.inode =>
            {
                a.journal.push(Fact::Known {
                    object,
                    pinned_ns: crate::attach::monotonic_ns(),
                });
            }
            Ok(_) => {}
            Err(_) => a.journal.object_read_errors = a.journal.object_read_errors.saturating_add(1),
        }
    });
}

pub(crate) fn scan_returned(
    view: &ProcessView,
    memory_requested: bool,
    budget: &CaptureWorkBudget,
    result: &Result<ScanOutcome, String>,
) {
    with_active(|a| {
        if view.pid() != a.journal.owned_pid {
            return;
        }
        let returned_ns = crate::attach::monotonic_ns();
        let (outcome, skipped, mut matching_inode_modules) = match result {
            Ok(outcome) => (
                if outcome.unavailable_reason().is_some() {
                    "unavailable"
                } else {
                    "scanned"
                },
                outcome.skipped().len(),
                outcome
                    .modules()
                    .iter()
                    .filter(|m| m.key.inode == a.journal.target.inode)
                    .map(|m| {
                        (
                            m.key.device.major,
                            m.key.device.minor,
                            m.key.inode,
                            m.tables.len(),
                        )
                    })
                    .take(65)
                    .collect::<Vec<_>>(),
            ),
            Err(_) => ("error", 0, Vec::new()),
        };
        if matching_inode_modules.len() > 64 {
            matching_inode_modules.truncate(64);
            a.journal.truncated_scans = a.journal.truncated_scans.saturating_add(1);
        }
        a.journal.push(Fact::ScanReturned {
            pid: view.pid(),
            birth_ticks: view.first_use_birth_ticks(),
            view: view.id().0,
            mount_ns_device: view.mount_namespace().device,
            mount_ns_inode: view.mount_namespace().inode,
            memory_requested,
            outcome,
            skipped,
            budget_stopped: budget.stopped_reason().is_some(),
            matching_inode_modules,
            returned_ns,
        });
    });
}

pub(crate) fn attached(
    domain: &EventsDomain,
    targets: &[crate::plan::Slot],
    objects: &PinnedObjects,
    completed: &[(u32, Option<u64>)],
) {
    with_active(|a| {
        if !a.hold(domain) {
            return;
        }
        for &(index, at) in completed {
            let endpoint = targets.iter().find(|s| s.index == index).and_then(|slot| {
                let file = objects.file_for(slot.object)?;
                let summary = objects.summary(slot.object)?;
                Some(Endpoint {
                    object: object(file, summary.sha256).ok()?,
                    file_offset: slot.file_offset,
                })
            });
            let Some(endpoint) = endpoint else {
                a.journal.object_read_errors = a.journal.object_read_errors.saturating_add(1);
                continue;
            };
            let wanted = a.journal.wanted(&endpoint);
            a.journal.bind(domain.id(), index, endpoint, at);
            if wanted && a.journal.intact() {
                a.notify(NoticeKind::TargetAttached, domain.id(), at);
            }
        }
    });
}

/// This is a successful live-publication validation, not a process sweep.
/// Preserve its distinct authority for tables published after the scan.
pub(crate) fn publication_validated(
    view: &ProcessView,
    module: &crate::discovery::scan::ScannedModule,
    hook_ns: u64,
) {
    with_active(|a| {
        if view.pid() != a.journal.owned_pid || module.key.inode != a.journal.target.inode {
            return;
        }
        a.journal.push(Fact::PublicationValidated {
            pid: view.pid(),
            birth_ticks: view.first_use_birth_ticks(),
            view: view.id().0,
            mount_ns_device: view.mount_namespace().device,
            mount_ns_inode: view.mount_namespace().inode,
            mapping_device_major: module.key.device.major,
            mapping_device_minor: module.key.device.minor,
            mapping_inode: module.key.inode,
            tables: module.tables.len(),
            entries: module.tables.iter().map(|t| t.entries.len()).sum(),
            publication_hook_ns: (hook_ns != 0).then_some(hook_ns),
            validated_ns: crate::attach::monotonic_ns(),
        });
    });
}

pub(crate) fn loop_started(domain: &EventsDomain, at_ns: Option<u64>) {
    with_active(|a| {
        if a.hold(domain) {
            a.journal.push(Fact::LoopStarted {
                domain: domain.id(),
                at_ns,
            });
            a.notify(NoticeKind::LoopStarted, domain.id(), at_ns);
        }
    });
}

/// Read the actual producer counter, never Engine's cached projection. The
/// per-CPU aggregate has a read interval, not an invented atomic timestamp.
pub(crate) fn discovery_loss(stage: DiscoveryStage, session: &crate::attach::Session) {
    discovery_loss_with(
        stage,
        || session.events_domain(),
        || {
            session
                .counter_snapshot()
                .ok()
                .map(|snapshot| snapshot.ring_loss)
        },
        crate::attach::monotonic_ns,
    );
}

fn discovery_loss_with(
    stage: DiscoveryStage,
    domain: impl FnOnce() -> EventsDomain,
    read: impl FnOnce() -> Option<u64>,
    mut clock: impl FnMut() -> Option<u64>,
) {
    with_active(|active| {
        let domain = domain();
        if !active.hold(&domain) {
            return;
        }
        let key = (domain.id(), stage);
        if active.loss_stages.contains(&key) {
            return;
        }
        if active.loss_stages.len() == active.journal.limit {
            active.journal.dropped = active.journal.dropped.saturating_add(1);
            return;
        }
        active.loss_stages.insert(key);
        let read_started_ns = clock();
        let ring_loss = read();
        let read_finished_ns = clock();
        active.journal.push(Fact::DiscoveryLoss {
            stage,
            domain: domain.id(),
            read_started_ns,
            read_finished_ns,
            ring_loss,
        });
    });
}

pub(crate) fn call(domain: u64, event: &Event) {
    with_active(|a| {
        if event.pid_tgid >> 32 == u64::from(a.journal.owned_pid)
            && event.event_type == p11scope_ebpf_common::event_type::CALL
        {
            a.journal.call(domain, event, crate::attach::monotonic_ns());
        }
    });
}

pub(crate) fn unsupported_rebuild() {
    with_active(|a| {
        a.journal.unsupported_rebuilds = a.journal.unsupported_rebuilds.saturating_add(1)
    });
}

pub(crate) fn test_probe(pid: u32) -> Probe {
    Probe::install(
        Journal::new(
            Target {
                device: 0,
                inode: 1,
                sha256: "ab".repeat(32),
                file_offset: 1,
            },
            pid,
            32,
        ),
        None,
    )
}

#[cfg(test)]
mod tests;

mod native;
