//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded identity re-projection from one immutable publication revision.

use crate::discovery::caller_registry::{CallerId, ModuleId};
use crate::inventory_present::{CallerView, EdgeView, ModuleView, Presentation};
use serde_json::{Value, json};
use std::collections::HashMap;

pub(crate) const MAX_IDENTITY_PATH_BYTES: usize = 4096;
pub(crate) const MAX_IDENTITY_CONTEXT_BYTES: usize = 65536;

/// Only references are indexed: large shared metadata stays in Presentation.
pub(crate) struct IdentityIndex<'a> {
    callers: HashMap<CallerId, &'a CallerView>,
    modules: HashMap<ModuleId, ModuleIdentity<'a>>,
}

struct ModuleIdentity<'a> {
    record: &'a ModuleView,
    path: Option<&'a str>,
}

impl<'a> IdentityIndex<'a> {
    pub(crate) fn new(presentation: &'a Presentation) -> Self {
        Self {
            callers: presentation
                .callers
                .iter()
                .map(|caller| (caller.id, caller))
                .collect(),
            modules: presentation
                .modules
                .iter()
                .map(|module| {
                    (
                        module.id,
                        ModuleIdentity {
                            record: module,
                            path: module.paths.iter().min().map(String::as_str),
                        },
                    )
                })
                .collect(),
        }
    }

    pub(crate) fn edge_context(&self, edge: &EdgeView) -> Value {
        let context = json!({
            "version": 1,
            "caller": self.caller_context(edge.caller),
            "module": self.module_context(edge.module),
        });
        bounded_context(context, || {
            json!({
                "version": 1,
                "caller": context_budget_caller(edge.caller),
                "module": missing_module(edge.module, IdentityStatus::ContextBudget),
            })
        })
    }

    pub(crate) fn caller_context(&self, id: CallerId) -> Value {
        let Some(caller) = self.callers.get(&id) else {
            return missing_caller(id, IdentityStatus::Unavailable);
        };
        let (executable, status) = match &caller.exe {
            Some(exe) => {
                let (path, status) = identity_path(exe.path.as_deref());
                (
                    json!({
                        "dev": exe.dev,
                        "ino": exe.ino,
                        "mtime_secs": exe.mtime_secs,
                        "mtime_nanos": exe.mtime_nanos,
                        "path": path,
                    }),
                    status,
                )
            }
            None => (Value::Null, IdentityStatus::Unavailable),
        };
        json!({
            "id": id.label(),
            "pid": caller.pid,
            "incarnation": caller.incarnation,
            "start_time": caller.start_time,
            "authority": caller.authority.label(),
            "lifecycle": caller.lifecycle.label(),
            "executable": executable,
            "status": status.label(),
        })
    }

    fn module_context(&self, id: ModuleId) -> Value {
        let Some(identity) = self.modules.get(&id) else {
            return missing_module(id, IdentityStatus::Unavailable);
        };
        let module = identity.record;
        let (path, status) = identity_path(identity.path);
        json!({
            "id": id.label(),
            "device_major": module.device_major,
            "device_minor": module.device_minor,
            "inode": module.inode,
            "path": path,
            "status": status.label(),
        })
    }
}

#[derive(Clone, Copy)]
enum IdentityStatus {
    Observed,
    Unavailable,
    PathBudget,
    ContextBudget,
}

impl IdentityStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Unavailable => "unavailable",
            Self::PathBudget => "path_budget",
            Self::ContextBudget => "context_budget",
        }
    }
}

fn identity_path(path: Option<&str>) -> (Option<&str>, IdentityStatus) {
    match path {
        Some(path) if path.len() > MAX_IDENTITY_PATH_BYTES => (None, IdentityStatus::PathBudget),
        Some(path) => (Some(path), IdentityStatus::Observed),
        None => (None, IdentityStatus::Unavailable),
    }
}

fn missing_caller(id: CallerId, status: IdentityStatus) -> Value {
    json!({
        "id": id.label(),
        "pid": null,
        "incarnation": null,
        "start_time": null,
        "authority": null,
        "lifecycle": null,
        "executable": null,
        "status": status.label(),
    })
}

fn missing_module(id: ModuleId, status: IdentityStatus) -> Value {
    json!({
        "id": id.label(),
        "device_major": null,
        "device_minor": null,
        "inode": null,
        "path": null,
        "status": status.label(),
    })
}

pub(crate) fn context_budget_caller(id: CallerId) -> Value {
    missing_caller(id, IdentityStatus::ContextBudget)
}

/// Count actual serialized bytes, including escaping, without allocating an
/// encoded copy. The fallback is built only on a refusal and holds IDs only.
pub(crate) fn bounded_context(context: Value, fallback: impl FnOnce() -> Value) -> Value {
    struct EncodedBudget(usize);
    impl std::io::Write for EncodedBudget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let Some(total) = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_IDENTITY_CONTEXT_BYTES)
            else {
                return Err(std::io::Error::other("identity context byte budget"));
            };
            self.0 = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    if serde_json::to_writer(&mut EncodedBudget(0), &context).is_ok() {
        context
    } else {
        fallback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::caller_registry::RegistryLimits;
    use crate::discovery::inventory_workload::{Harness, ScaleSpec};

    fn fixture() -> Presentation {
        let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
        harness.stage_scale(&ScaleSpec {
            name: "identity-bounds",
            callers: 1,
            modules: 1,
            edges_per_caller: 1,
            endpoints_per_module: 4,
            first_pid: 91_000,
        });
        harness.commit();
        Presentation::capture(harness.coordinator(), "workload", 1, 2, 1)
    }

    #[test]
    fn stream_identity_paths_are_bounded_without_truncation() {
        let mut view = fixture();
        let mut edge = view.edges[0].clone();
        view.modules[0].paths = vec!["z-last".into(), "a-first".into()];
        let index = IdentityIndex::new(&view);
        assert_eq!(index.edge_context(&edge)["module"]["path"], "a-first");
        for path in ["\u{1}".repeat(4096), "é".repeat(2048)] {
            view.callers[0].exe.as_mut().unwrap().path = Some(path.clone());
            view.modules[0].paths = vec![path.clone()];
            let context = IdentityIndex::new(&view).edge_context(&edge);
            assert_eq!(context["caller"]["executable"]["path"], path);
            assert_eq!(context["caller"]["status"], "observed");
            assert_eq!(context["module"]["path"], path);
            assert!(serde_json::to_vec(&context).unwrap().len() <= MAX_IDENTITY_CONTEXT_BYTES);
        }
        view.callers[0].exe.as_mut().unwrap().path = Some("é".repeat(2049));
        view.modules[0].paths = vec!["x".repeat(MAX_IDENTITY_PATH_BYTES + 1)];
        let context = IdentityIndex::new(&view).edge_context(&edge);
        assert!(context["caller"]["executable"]["path"].is_null());
        assert_eq!(context["caller"]["status"], "path_budget");
        assert_eq!(context["caller"]["executable"]["ino"], 100);
        assert!(context["module"]["path"].is_null());
        assert_eq!(context["module"]["status"], "path_budget");
        edge.caller = CallerId(999);
        edge.module = ModuleId(999);
        let missing = IdentityIndex::new(&view).edge_context(&edge);
        assert_eq!(missing["caller"]["id"], "c999");
        assert!(missing["caller"]["pid"].is_null());
        assert_eq!(missing["caller"]["status"], "unavailable");
        assert_eq!(missing["module"]["id"], "m999");
        assert_eq!(missing["module"]["status"], "unavailable");
    }

    #[test]
    fn stream_identity_index_borrows_shared_metadata() {
        let mut view = fixture();
        view.modules[0].admission_reasons = vec!["sentinel".repeat(1_000_000)];
        let (index, _, allocated) =
            crate::test_alloc::count_allocs_during(|| IdentityIndex::new(&view));
        assert!(allocated < 4096, "index allocated {allocated} bytes");
        assert!(std::ptr::eq(
            index.modules[&ModuleId(0)].record,
            &view.modules[0]
        ));
        assert!(std::ptr::eq(index.callers[&CallerId(0)], &view.callers[0]));
        let (context, _, allocated) =
            crate::test_alloc::count_allocs_during(|| index.edge_context(&view.edges[0]));
        assert!(
            allocated < 65536,
            "compact projection allocated {allocated} bytes"
        );
        assert_eq!(context["caller"]["executable"]["path"], "/bin/driver");
        assert_eq!(context["module"]["path"], "/scale/m0.so");
    }

    #[test]
    fn stream_identity_encoded_context_guard_is_exact() {
        // Artificially widen the finite projection to exercise the fail-closed
        // guard itself; this grants no producer field or larger path budget.
        let fallback = || serde_json::json!({"version": 1, "caller": {"id": "c0", "status": "context_budget"}, "module": {"id": "m0", "status": "context_budget"}});
        let base = serde_json::json!({"version": 1, "test_guard": ""});
        let overhead = serde_json::to_vec(&base).unwrap().len();
        let at_limit = serde_json::json!({"version": 1, "test_guard": "x".repeat(MAX_IDENTITY_CONTEXT_BYTES - overhead)});
        assert_eq!(serde_json::to_vec(&at_limit).unwrap().len(), 65536);
        assert_eq!(bounded_context(at_limit.clone(), fallback), at_limit);
        let over_limit = serde_json::json!({"version": 1, "test_guard": "x".repeat(MAX_IDENTITY_CONTEXT_BYTES - overhead + 1)});
        let bounded = bounded_context(over_limit, fallback);
        assert_eq!(bounded["caller"]["id"], "c0");
        assert_eq!(bounded["caller"]["status"], "context_budget");
        assert_eq!(bounded["module"]["status"], "context_budget");
        assert!(bounded.get("test_guard").is_none());
    }
}
