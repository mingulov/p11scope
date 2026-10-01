//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope inventory`: which module is used by whom.
//!
//! One snapshot pass, or a `--duration` observation window of passes,
//! over `--pid` or `--system`: every pass collects the scope, reconciles
//! caller incarnations, and publishes caller/module/edge facts through
//! the coordinator batch. The JSON document (`p11scope/inventory/v1`)
//! carries stable capture-local IDs, timestamps on the capture clock,
//! lifecycle state, and explicit gaps. Scan-only like inspect: usage
//! columns read unknown unless an entry feed observed them, and mappings
//! are never reported as observed calls.

use crate::attach::Scope;
use crate::cli::InspectScope;
use crate::discovery::caller_registry::{
    CallerEvent, CallerId, ImageAuthority, ModuleId, ModuleKey, OsProcessSource, RegistryLimits,
    now_ns,
};
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, InventoryScope, PassReport,
};
use crate::discovery::hooks::HookRegistry;
use crate::output::AtomicFile;
use crate::render::escape_controls;
use anyhow::{Context as _, Result};
use p11scope_ebpf_common::ImageIdentity;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DOC_ID: &str = "p11scope/inventory/v1";

/// Rescan interval inside a `--duration` observation window.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

fn no_native_images(_: u32) -> Option<ImageIdentity> {
    None
}

/// `p11scope inventory` — observe, render, report. Exit 0 with the text
/// summary (or the JSON document under `--json`) on stdout; `-o` writes
/// the JSON document atomically. Hard failures (an unreadable target, an
/// unwritable `-o`) are errors, never empty-success reports.
pub fn run(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
) -> Result<i32> {
    run_with_writer(
        scope,
        modules,
        hooks,
        json,
        max_scan_pids,
        duration,
        out,
        &mut std::io::stdout().lock(),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with_writer(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
    stdout: &mut dyn std::io::Write,
) -> Result<i32> {
    // Fail fast before scanning: an unwritable `-o` must not cost a pass.
    let sink = match out {
        Some(path) => Some(
            AtomicFile::create(path)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .with_context(|| format!("opening inventory report {}", path.display()))?,
        ),
        None => None,
    };
    let (inventory_scope, engine_scope, scope_label) = match scope {
        InspectScope::Pid(pid) => (
            InventoryScope::Pid(pid),
            Scope::Pid(pid),
            format!("pid:{pid}"),
        ),
        InspectScope::System => (InventoryScope::System, Scope::System, "system".to_string()),
    };
    let started_ns = now_ns();
    let mut coordinator = InventoryCoordinator::new(
        engine_scope,
        hooks.clone(),
        modules.to_vec(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )?;
    // The scan lane stages no entries: entry columns read unknown. Only a
    // BPF usage feed (the privileged lane) may flip this.
    coordinator.registry_mut().set_usage_feed(false);
    let mut guard = UnavailableImageGuard;
    let deadline = duration.map(|window| Instant::now() + window);
    loop {
        let now = now_ns();
        let pass_deadline = match deadline {
            Some(end) => {
                let remaining = end.saturating_duration_since(Instant::now());
                now.saturating_add(remaining.as_nanos().min(u128::from(u64::MAX)) as u64)
            }
            None => u64::MAX,
        };
        let scope_context = match scope {
            InspectScope::Pid(pid) => format!("inventory --pid {pid}"),
            InspectScope::System => "inventory --system".to_string(),
        };
        let report = match coordinator.scan_pass(
            &inventory_scope,
            max_scan_pids,
            &mut guard,
            no_native_images,
            pass_deadline,
            now,
        ) {
            Ok(report) => report,
            // A failed first pass is a hard error (nothing was ever
            // observed); a later failure is an empty pass — lifecycle
            // still reconciles, and the observation survives its
            // target's death.
            Err(error) if coordinator.passes() == 0 => {
                return Err(error).with_context(|| scope_context);
            }
            Err(error) => {
                eprintln!("p11scope: pass failed, continuing without its scan: {error:#}");
                coordinator.observe_empty_pass(
                    &mut guard,
                    no_native_images,
                    &format!("{error:#}"),
                    now,
                )
            }
        };
        coordinator.commit_batch(report.engine_changed)?;
        report_progress(&coordinator, &report);
        match deadline {
            None => break,
            Some(end) => {
                let now_instant = Instant::now();
                if now_instant >= end {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL.min(end - now_instant));
            }
        }
    }
    let ended_ns = now_ns();
    let passes = coordinator.passes();
    let document = render_json(&coordinator, &scope_label, started_ns, ended_ns, passes);
    if let Some(mut sink) = sink {
        serde_json::to_writer_pretty(sink.file(), &document)?;
        // Same bytes stdout carries: the pretty document plus its
        // trailing newline, so the two sinks agree byte for byte.
        sink.file().write_all(b"\n")?;
        sink.file().flush()?;
        sink.commit().map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    if json {
        let text = serde_json::to_string_pretty(&document)?;
        writeln!(stdout, "{text}")?;
    } else {
        write!(
            stdout,
            "{}",
            render_text(&coordinator, &scope_label, started_ns, ended_ns, passes)
        )?;
    }
    Ok(0)
}

/// Per-pass progress on stderr (stdout stays parseable): what the pass
/// scanned and which caller incarnations turned over.
fn report_progress(coordinator: &InventoryCoordinator<OsProcessSource>, report: &PassReport) {
    eprintln!(
        "p11scope: pass {}: {} scanned ({} native, {} scan-pinned){}",
        report.pass,
        report.scanned,
        report.native_callers,
        report.scan_callers,
        if report.pending_refresh.is_empty() {
            String::new()
        } else {
            format!("; {} refresh pending", report.pending_refresh.len())
        }
    );
    for event in &report.events {
        let line = match event {
            CallerEvent::Admitted { id } => {
                let pid = coordinator
                    .adapter()
                    .record(*id)
                    .map(|record| record.pid)
                    .unwrap_or(0);
                format!("caller {} admitted (pid {pid})", id.label())
            }
            CallerEvent::Exited { id, reason } => {
                format!("caller {} exited: {reason}", id.label())
            }
            CallerEvent::ExecRetired { old, new } => {
                format!("caller {} exec-retired, now {}", old.label(), new.label())
            }
            CallerEvent::Reused { old, new } => {
                format!("caller {} reused, now {}", old.label(), new.label())
            }
            CallerEvent::AdmitFailed { pid, reason } => {
                format!("caller admission failed for pid {pid}: {reason}")
            }
        };
        eprintln!("p11scope: pass {}: {line}", report.pass);
    }
}

fn caller_json(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    id: CallerId,
) -> serde_json::Value {
    let record = coordinator
        .adapter()
        .record(id)
        .expect("rendered callers are adapter records");
    let (task_cookie, exec_id) = match record.authority {
        ImageAuthority::NativeExact {
            task_cookie,
            exec_id,
        } => (
            serde_json::Value::from(task_cookie),
            serde_json::Value::from(exec_id),
        ),
        ImageAuthority::ScanPinned => (serde_json::Value::Null, serde_json::Value::Null),
    };
    let exe = record.exe.as_ref().map(|exe| {
        serde_json::json!({
            "dev": exe.dev,
            "ino": exe.ino,
            "mtime_secs": exe.mtime_secs,
            "mtime_nanos": exe.mtime_nanos,
            "path": exe.path,
        })
    });
    serde_json::json!({
        "id": id.label(),
        "pid": record.pid,
        "start_time": record.start_time,
        "start_time_unit": "clock_ticks_since_boot",
        "incarnation": record.incarnation,
        "image": {
            "authority": record.authority.label(),
            "task_cookie": task_cookie,
            "exec_id": exec_id,
            "exe": exe,
            "exec_observed": record.exec_observed,
        },
        "lifecycle": record.lifecycle.label(),
        "lifecycle_reason": record.lifecycle_reason,
        "first_seen_ns": record.first_seen_ns,
        "last_seen_ns": record.last_seen_ns,
        "retired": record.retired,
    })
}

fn module_json(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    id: ModuleId,
) -> serde_json::Value {
    let record = coordinator
        .registry()
        .module(id)
        .expect("rendered modules are registry records");
    let (dev_major, dev_minor, ino, sha256) = match &record.key {
        ModuleKey::Physical {
            dev_major,
            dev_minor,
            ino,
            sha256,
        } => (
            *dev_major,
            *dev_minor,
            *ino,
            sha256
                .clone()
                .map(serde_json::Value::from)
                .unwrap_or_default(),
        ),
        ModuleKey::Unidentified { .. } => (0, 0, 0, serde_json::Value::Null),
    };
    serde_json::json!({
        "id": id.label(),
        "paths": record.paths.iter().collect::<Vec<_>>(),
        "identity": {
            "device": {"major": dev_major, "minor": dev_minor},
            "inode": ino,
            "sha256": sha256,
            "build_id": record.build_id,
            "source": record.identity_source,
        },
        "admission": {
            "state": record.admission.label(),
            "class": record.admission_class,
            "endpoints": record.admission_endpoints,
            "reasons": record.admission_reasons,
            "note": crate::inspect_system::SCAN_ONLY_NOTE,
        },
        "lifecycle": record.lifecycle.label(),
        "unloaded_observed": record.unloaded_observed,
    })
}

fn edge_json(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    caller: CallerId,
    module: ModuleId,
) -> serde_json::Value {
    let registry = coordinator.registry();
    let edge = registry
        .edge(caller, module)
        .expect("rendered edges are registry records");
    serde_json::json!({
        "caller": caller.label(),
        "module": module.label(),
        "mapping": {
            "state": edge.mapping.label(),
            "reason": edge.mapping_reason,
            "first_seen_ns": edge.mapping_first_seen_ns,
            "last_seen_ns": edge.mapping_last_seen_ns,
            "interruptions": edge.mapping_interruptions,
        },
        "entries": {
            "count": edge.entry_count,
            "saturated": edge.entry_saturated,
            "cap": crate::discovery::caller_registry::MAX_EDGE_ENTRY_COUNT,
            "first_seen_ns": edge.entry_first_seen_ns,
            "last_seen_ns": edge.entry_last_seen_ns,
            "in_flight": edge.entry_in_flight,
            "observation": registry.entry_observation(edge).label(),
        },
    })
}

/// Render the published snapshot as `p11scope/inventory/v1`. Every edge
/// endpoint resolves: a dangling reference is a coordinator bug, and the
/// debug assertion names it instead of emitting a partial document.
pub(crate) fn render_json(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    scope_label: &str,
    started_ns: u64,
    ended_ns: u64,
    passes: u64,
) -> serde_json::Value {
    let mut callers: Vec<CallerId> = coordinator
        .adapter()
        .records()
        .map(|record| record.id)
        .collect();
    callers.sort();
    let mut modules: Vec<ModuleId> = coordinator
        .registry()
        .modules()
        .map(|module| module.id)
        .collect();
    modules.sort();
    let mut edges: Vec<(CallerId, ModuleId)> = coordinator
        .registry()
        .edges()
        .map(|edge| (edge.caller, edge.module))
        .collect();
    edges.sort();
    debug_assert!(
        edges
            .iter()
            .all(|(caller, _)| coordinator.adapter().record(*caller).is_some()),
        "every rendered edge caller resolves in the adapter"
    );
    let gaps: Vec<serde_json::Value> = coordinator
        .registry()
        .gaps()
        .iter()
        .map(|gap| {
            serde_json::json!({
                "caller": gap.caller.map(|caller| caller.label()),
                "module": gap.module.map(|module| module.label()),
                "pid": gap.pid,
                "subject": gap.subject,
                "reason": gap.reason,
            })
        })
        .collect();
    serde_json::json!({
        "schema": DOC_ID,
        "scope": scope_label,
        "clock": {
            "basis": crate::discovery::caller_registry::CLOCK_BASIS,
            "unit": crate::discovery::caller_registry::CLOCK_UNIT,
        },
        "observation": {
            "started_ns": started_ns,
            "ended_ns": ended_ns,
            "passes": passes,
            "usage_feed": coordinator.registry().usage_feed(),
        },
        "callers": callers.iter().map(|caller| caller_json(coordinator, *caller)).collect::<Vec<_>>(),
        "modules": modules.iter().map(|module| module_json(coordinator, *module)).collect::<Vec<_>>(),
        "edges": edges.iter().map(|(caller, module)| edge_json(coordinator, *caller, *module)).collect::<Vec<_>>(),
        "gaps": gaps,
        "gaps_suppressed": coordinator.registry().gaps_suppressed(),
    })
}

pub(crate) fn render_text(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    scope_label: &str,
    started_ns: u64,
    ended_ns: u64,
    passes: u64,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let callers: Vec<_> = coordinator.adapter().records().collect();
    let modules: Vec<_> = coordinator.registry().modules().collect();
    let edges: Vec<_> = coordinator.registry().edges().collect();
    let _ = writeln!(
        out,
        "inventory {scope_label} ({} pass{}, {} caller{}, {} module{}, {} edge{})",
        passes,
        if passes == 1 { "" } else { "es" },
        callers.len(),
        if callers.len() == 1 { "" } else { "s" },
        modules.len(),
        if modules.len() == 1 { "" } else { "s" },
        edges.len(),
        if edges.len() == 1 { "" } else { "s" },
    );
    for record in &callers {
        let exe = record
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_deref())
            .unwrap_or("?");
        let _ = writeln!(
            out,
            "caller {} pid {} incarnation {} {} ({})",
            record.id.label(),
            record.pid,
            record.incarnation,
            record.lifecycle.label(),
            escape_controls(exe)
        );
    }
    for module in &modules {
        let path = module
            .paths
            .iter()
            .next()
            .map(String::as_str)
            .unwrap_or("?");
        let _ = writeln!(
            out,
            "module {} {} {} ({})",
            module.id.label(),
            escape_controls(path),
            module.lifecycle.label(),
            module.admission.label()
        );
    }
    // "Active now" for the text summary means an entry observed during
    // this observation (or in flight at its end) — recency, not a sticky
    // bit. The JSON keeps the raw last-seen so readers choose their own
    // window.
    let window_ns = ended_ns.saturating_sub(started_ns);
    for edge in &edges {
        let registry = coordinator.registry();
        let observation = registry.entry_observation(edge).label();
        let active = registry.entry_active_within(edge, ended_ns, window_ns);
        let _ = writeln!(
            out,
            "edge {} -> {} mapping {} entries {} ({observation}{})",
            edge.caller.label(),
            edge.module.label(),
            edge.mapping.label(),
            edge.entry_count,
            if active { ", active" } else { "" }
        );
    }
    for gap in coordinator.registry().gaps() {
        let _ = writeln!(out, "gap [{}] {}", gap.subject, gap.reason);
    }
    let suppressed = coordinator.registry().gaps_suppressed();
    if suppressed > 0 {
        let _ = writeln!(out, "gaps suppressed: {suppressed}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::caller_registry::{AdmissionState, ModuleInfo, ModuleKey};

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap()
    }

    #[test]
    fn json_document_carries_the_exact_schema_id_and_clock_basis() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 100)
            .unwrap();
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/lib/a.so".into(),
                key: key.clone(),
                build_id: None,
                identity_source: Some("mountinfo".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            100,
        );
        coordinator.commit_batch(false).unwrap();
        let document = render_json(&coordinator, "pid:7", 90, 120, 1);
        assert_eq!(document["schema"], "p11scope/inventory/v1");
        assert_eq!(document["scope"], "pid:7");
        assert_eq!(document["clock"]["basis"], "CLOCK_MONOTONIC");
        assert_eq!(document["clock"]["unit"], "ns");
        assert_eq!(document["observation"]["passes"], 1);
        assert_eq!(document["observation"]["usage_feed"], false);
        assert_eq!(document["callers"].as_array().unwrap().len(), 1);
        assert_eq!(document["callers"][0]["id"], caller.label());
        assert_eq!(document["callers"][0]["image"]["authority"], "scan_pinned");
        assert_eq!(document["modules"].as_array().unwrap().len(), 1);
        assert_eq!(document["modules"][0]["paths"][0], "/lib/a.so");
        assert_eq!(
            document["edges"][0]["entries"]["observation"],
            "unknown (usage observation unavailable)"
        );
        assert_eq!(document["edges"][0]["entries"]["count"], 0);
        // Mappings are never reported as observed calls.
        assert!(document["edges"][0]["entries"]["last_seen_ns"].is_null());
    }

    #[test]
    fn text_summary_names_callers_modules_edges_and_gaps() {
        let coordinator = coordinator();
        let text = render_text(&coordinator, "system", 90, 120, 2);
        assert!(
            text.starts_with("inventory system (2 passes, 0 callers, 0 modules, 0 edges)"),
            "{text}"
        );
    }
}
