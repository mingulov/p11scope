//! SPDX-License-Identifier: GPL-3.0-or-later
//! Producer-owned historical state. Control/liveness is a separate authority.
use crate::semantics::ProcessKey;
use p11scope_ebpf_common::ImageIdentity;
use std::{collections::BTreeMap, os::fd::OwnedFd, sync::Arc};

// Optional control seam retained for the separate preseed/cursor integration.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum Membership {
    Live { domain: u64, cookie: u64 },
    Exited,
    Unavailable,
}

/// The adapter retains authenticated original pidfds. Candidate selection is
/// an external task-membership decision, not authority granted by a PID/event.
/// `sample` must operate on this SAME descriptor; it supplies no exec counter.
#[allow(dead_code)]
pub(crate) trait TaskMembership {
    fn candidate(&mut self, pid: u32) -> Option<Arc<OwnedFd>>;
    fn sample(&mut self, original: &OwnedFd) -> Membership;
}
struct Task {
    key: ProcessKey,
    closed: bool,
    called: bool,
    forked: bool,
    root_positive: bool,
}
pub(crate) struct Registry {
    limit: usize,
    tasks: BTreeMap<u64, Task>,
    // Keep map identity retained through destruction of the indexed tasks.
    domain: Option<crate::events::EventsDomain>,
    root_completed: bool,
}
impl Registry {
    // Legacy-ladder support only (SYSPLAN residual F-44): the production
    // tracker always carries a live registry from `for_producer`.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            domain: None,
            limit: 0,
            tasks: BTreeMap::new(),
            root_completed: false,
        }
    }
    pub(crate) fn new(domain: crate::events::EventsDomain, limit: usize) -> Self {
        Self {
            domain: Some(domain),
            limit,
            tasks: BTreeMap::new(),
            root_completed: false,
        }
    }
    pub(crate) fn domain(&self) -> u64 {
        self.domain
            .as_ref()
            .map_or(0, crate::events::EventsDomain::id)
    }
    /// The domain comes from the sole retained EVENTS consumer, never a wire
    /// field or a live process lookup. The producer authenticates the tuple.
    pub(crate) fn admit(
        &mut self,
        domain: u64,
        pid: u32,
        image: ImageIdentity,
    ) -> (Option<ProcessKey>, Vec<ProcessKey>) {
        let mut retired = Vec::new();
        if domain == 0 || domain != self.domain() || image.task_cookie == 0 || pid == 0 {
            return (None, retired);
        }
        if let Some(task) = self.tasks.get_mut(&image.task_cookie) {
            if task.closed || image.exec_id < task.key.exec_id {
                return (None, retired);
            }
            if image.exec_id > task.key.exec_id {
                retired.push(task.key);
                task.key = ProcessKey::history(domain, image.task_cookie, image.exec_id, pid);
                task.called = false;
                task.forked = false;
            }
            return (Some(task.key), retired);
        }
        if self.tasks.len() >= self.limit {
            return (None, retired);
        }
        let key = ProcessKey::history(domain, image.task_cookie, image.exec_id, pid);
        self.tasks.insert(
            image.task_cookie,
            Task {
                key,
                closed: false,
                called: false,
                forked: false,
                root_positive: false,
            },
        );
        (Some(key), retired)
    }
    /// Exact-key like every other mutator: a retired generation's CALL must
    /// never mark the successor generation as called.
    pub(crate) fn mark_call(&mut self, key: ProcessKey) {
        if let Some(task) = self.tasks.get_mut(&key.generation)
            && task.key == key
            && !task.closed
        {
            task.called = true;
        }
    }
    pub(crate) fn mark_root(&mut self, key: ProcessKey, affiliation: u64) {
        if affiliation == 1
            && let Some(task) = self.tasks.get_mut(&key.generation)
            && task.key == key
            && !task.closed
        {
            task.root_positive = true;
        }
    }
    pub(crate) fn check_root(&self, domain: u64, affiliation: u64) -> anyhow::Result<()> {
        anyhow::ensure!(affiliation <= 1, "invalid root affiliation");
        anyhow::ensure!(
            !(domain == self.domain() && affiliation == 1 && self.root_completed),
            "positive root event after completed fixed EVENTS tail"
        );
        Ok(())
    }
    pub(crate) fn complete_root(
        &mut self,
        tail: &crate::events::ConsumedOriginalRootTail,
    ) -> anyhow::Result<Vec<ProcessKey>> {
        anyhow::ensure!(
            tail.domain() == self.domain() && !self.root_completed,
            "foreign or repeated root retirement"
        );
        let keys: Vec<_> = self
            .tasks
            .values()
            .filter(|task| task.root_positive && !task.closed)
            .map(|task| task.key)
            .collect();
        self.root_completed = true;
        Ok(keys
            .into_iter()
            .filter_map(|key| self.confirm_retirement(key))
            .collect())
    }
    pub(crate) fn birth(&mut self, parent: ProcessKey, child: ProcessKey) -> bool {
        if parent == child {
            return false;
        }
        // An authentic first FORK can establish an empty parent history.
        if !self
            .tasks
            .get(&parent.generation)
            .is_some_and(|t| !t.closed && t.key == parent)
        {
            return false;
        }
        let Some(task) = self.tasks.get_mut(&child.generation) else {
            return false;
        };
        if task.closed || task.key != child || task.called || task.forked {
            return false;
        }
        task.forked = true;
        true
    }
    /// Exact-key reducer used by token-gated root completion and the legacy
    /// test-only retirement adapter. Liveness observations never call this.
    pub(crate) fn confirm_retirement(&mut self, key: ProcessKey) -> Option<ProcessKey> {
        if key.domain != self.domain() {
            return None;
        }
        let task = self.tasks.get_mut(&key.generation)?;
        if task.closed || task.key != key {
            return None;
        }
        task.closed = true;
        Some(task.key)
    }
}
