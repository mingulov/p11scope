//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope inspect --pid N`: renders a completed memory scan as text or JSON.
//! No BPF, no pause, no capture, and zero PKCS #11 calls (spec §4.6) — reads
//! `/proc` and nothing else, so
//! it works unprivileged against a same-uid target and answers "which providers
//! does this process actually use". Interface names are shown here on purpose:
//! `inspect` is a discovery tool, not capture output (spec §4.3).

use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{PinnedObjects, pin_scanned_view_objects};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedModule, Skipped, scan_process_view,
};
use crate::process::{ProcessView, ProcessViewId};
use anyhow::Result;
use std::fmt::Write as _;
use std::path::PathBuf;

const DOC_ID: &str = "p11scope/inspect/v1";

/// The scan's refusal when it could not take the target's mapping snapshot
/// at all (`/proc/<pid>/maps` unreadable, empty, or unparseable). No module
/// inventory exists behind it, so `inspect` must not render it as a scan
/// that found nothing (HIGH-2).
const INITIAL_MAPS_REFUSAL: &str = "memory scan refused: initial mapping validation unavailable";

/// Renders a completed scan. Pure: takes the scan result and the pinned identities,
/// returns the text — so the layout is unit-testable without a target process.
pub fn render_text(pid: u32, outcome: &ScanOutcome, pinned: &PinnedObjects) -> String {
    let modules = outcome.modules();
    let word = if modules.len() == 1 {
        "module"
    } else {
        "modules"
    };
    let mut out = String::new();
    let _ = write!(out, "pid {pid} — {} PKCS#11 {word} mapped", modules.len());
    match outcome {
        ScanOutcome::Scanned { scan_ms, .. } => {
            let _ = writeln!(out, " (scan {scan_ms}ms)");
        }
        ScanOutcome::Unavailable { reason, .. } => {
            out.push('\n');
            if *reason == "ptrace" {
                let _ = writeln!(
                    out,
                    "table scan unavailable: /proc/{pid}/mem is not readable (ptrace)."
                );
                let _ = writeln!(
                    out,
                    "  Same-uid targets need kernel.yama.ptrace_scope=0 or the target to be a \
                     descendant;"
                );
                let _ = writeln!(
                    out,
                    "  otherwise CAP_SYS_PTRACE. Modules below come from /proc/{pid}/maps and \
                     .dynsym only."
                );
            } else {
                let _ = writeln!(
                    out,
                    "table scan unavailable: {reason}. Modules below come from /proc/{pid}/maps \
                     and .dynsym only."
                );
            }
        }
    }
    out.push('\n');

    for module in modules {
        render_module(&mut out, module, pinned);
        out.push('\n');
    }

    for skipped in outcome.skipped() {
        let _ = writeln!(
            out,
            "skipped: {} — {}",
            crate::render::escape_controls(&skipped.subject),
            crate::render::escape_controls(&skipped.reason)
        );
    }
    out
}

fn render_module(out: &mut String, module: &ScannedModule, pinned: &PinnedObjects) {
    let _ = writeln!(
        out,
        "module  {}",
        crate::render::escape_controls(&module.path)
    );

    let pin = pinned.pinned().find(|p| p.key == module.key);
    let sha256 = pin.map_or("-", |p| p.sha256);
    let build_id = pin.and_then(|p| p.build_id).unwrap_or("-");
    let _ = writeln!(
        out,
        "  identity   sha256 {sha256}  build-id {build_id}  dev {}:{}  ino {}",
        module.key.device.major, module.key.device.minor, module.key.inode
    );

    let _ = writeln!(out, "  exports    {}", module.exports.join(", "));

    for table in &module.tables {
        let count = table.entries.len();
        let entry_word = if count == 1 { "entry" } else { "entries" };
        let nulls = if table.null_entries.is_empty() {
            String::new()
        } else {
            format!("  (NULL: {})", table.null_entries.join(", "))
        };
        let _ = writeln!(
            out,
            "  table      {}.{}  {}  {count} {entry_word}{nulls}",
            table.version.0, table.version.1, table.walk
        );
    }

    for interface in &module.interfaces {
        let name = interface
            .name_lossy
            .as_deref()
            .unwrap_or(match interface.name_class {
                "null" => "(null)",
                "unreadable" => "(unreadable)",
                _ => "(unknown)",
            });
        let name = name.escape_default();
        let target = interface
            .table
            .and_then(|index| module.tables.get(index))
            .map_or("-".to_string(), |t| {
                format!("{}.{}", t.version.0, t.version.1)
            });
        let _ = writeln!(
            out,
            "  interface  [{}] \"{name}\"  flags {:#x}  -> table {target}",
            interface.index, interface.flags
        );
    }

    // Table entries whose slot pointer resolved into a different mapped object —
    // real evidence about what this module actually pulls in at runtime.
    let mut others: Vec<(&str, usize)> = Vec::new();
    for entry in module.tables.iter().flat_map(|table| &table.entries) {
        if entry.object_path == module.path {
            continue;
        }
        match others
            .iter_mut()
            .find(|(path, _)| *path == entry.object_path)
        {
            Some((_, count)) => *count += 1,
            None => others.push((&entry.object_path, 1)),
        }
    }
    if !others.is_empty() {
        let parts: Vec<String> = others
            .iter()
            .map(|(path, count)| format!("{} ({count})", crate::render::escape_controls(path)))
            .collect();
        let _ = writeln!(out, "  entries in other objects: {}", parts.join(", "));
    }
}

/// Renders a completed scan as JSON. Document id: `p11scope/inspect/v1`.
pub fn render_json(pid: u32, outcome: &ScanOutcome, pinned: &PinnedObjects) -> serde_json::Value {
    let scan = match outcome {
        ScanOutcome::Scanned { scan_ms, .. } => {
            serde_json::json!({ "status": "scanned", "scan_ms": scan_ms })
        }
        ScanOutcome::Unavailable { reason, .. } => {
            serde_json::json!({ "status": "unavailable", "reason": reason })
        }
    };
    let modules: Vec<serde_json::Value> = outcome
        .modules()
        .iter()
        .map(|module| module_json(module, pinned))
        .collect();
    let skipped: Vec<serde_json::Value> = outcome
        .skipped()
        .iter()
        .map(|s| serde_json::json!({ "subject": s.subject, "reason": s.reason }))
        .collect();
    serde_json::json!({
        "schema": DOC_ID,
        "pid": pid,
        "scan": scan,
        "modules": modules,
        "skipped": skipped,
    })
}

fn module_json(module: &ScannedModule, pinned: &PinnedObjects) -> serde_json::Value {
    let pin = pinned.pinned().find(|p| p.key == module.key);
    let identity = serde_json::json!({
        "sha256": pin.map(|p| p.sha256),
        "build_id": pin.and_then(|p| p.build_id),
        "identity_source": pin.map(|p| p.identity_source),
        "note": pin.and_then(|p| p.note),
    });
    let tables: Vec<serde_json::Value> = module
        .tables
        .iter()
        .map(|table| {
            serde_json::json!({
                "version": format!("{}.{}", table.version.0, table.version.1),
                "walk": table.walk,
                "entries": table.entries.len(),
                "null_entries": table.null_entries,
                "address": format!("{:#x}", table.address),
            })
        })
        .collect();
    let interfaces: Vec<serde_json::Value> = module
        .interfaces
        .iter()
        .map(|interface| {
            serde_json::json!({
                "index": interface.index,
                "name_class": interface.name_class,
                "name": interface.name_lossy,
                "flags": interface.flags,
                "table": interface.table,
            })
        })
        .collect();
    serde_json::json!({
        "path": module.path,
        "device": { "major": module.key.device.major, "minor": module.key.device.minor },
        "inode": module.key.inode,
        "identity": identity,
        "exports": module.exports,
        "tables": tables,
        "interfaces": interfaces,
    })
}

/// Combines a scan's own skips with the ones pinning turned up — pinning skips
/// must not be dropped on the floor (a scan-visible module the observer could
/// not pin is exactly the kind of gap `inspect` exists to surface).
fn with_extra_skips(outcome: ScanOutcome, extra: Vec<Skipped>) -> ScanOutcome {
    if extra.is_empty() {
        return outcome;
    }
    match outcome {
        ScanOutcome::Scanned {
            modules,
            mut skipped,
            scan_ms,
        } => {
            skipped.extend(extra);
            ScanOutcome::Scanned {
                modules,
                skipped,
                scan_ms,
            }
        }
        ScanOutcome::Unavailable {
            reason,
            modules,
            mut skipped,
        } => {
            skipped.extend(extra);
            ScanOutcome::Unavailable {
                reason,
                modules,
                skipped,
            }
        }
    }
}

fn scan_and_pin_retained_with<C, S, P>(
    context: &mut C,
    mut still_the_same: impl FnMut(&mut C) -> bool,
    scan: impl FnOnce(&mut C) -> Result<S, String>,
    pin: impl FnOnce(&mut C, &S) -> Result<P, String>,
) -> Result<(S, P), String> {
    if !still_the_same(context) {
        return Err("process generation changed before inspect".into());
    }
    let scanned = scan(context)?;
    if !still_the_same(context) {
        return Err("process generation changed while inspect was scanning".into());
    }
    let pinned = pin(context, &scanned)?;
    if !still_the_same(context) {
        return Err("process generation changed while inspect was pinning".into());
    }
    Ok((scanned, pinned))
}

/// `p11scope inspect` — scans, pins, prints. Exit code: 0 when the scan ran
/// (even with zero modules), 1 when the target could not be read at all.
pub fn run(pid: u32, hints: &[PathBuf], hooks: &HookRegistry, json: bool) -> Result<i32> {
    run_with_writer(pid, hints, hooks, json, &mut std::io::stdout().lock())
}

fn run_with_writer(
    pid: u32,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    out: &mut dyn std::io::Write,
) -> Result<i32> {
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(anyhow::Error::msg)?;
    let mut context = (&view, CaptureWorkBudget::default());
    let result = scan_and_pin_retained_with(
        &mut context,
        |context| context.0.still_the_same(),
        |context| {
            scan_process_view(
                &ScanRequest { pid, hints, hooks },
                context.0,
                &mut context.1,
            )
        },
        |context, outcome| pin_scanned_view_objects(context.0, outcome.modules(), &mut context.1),
    );
    emit_diagnosis(pid, json, out, result)
}

/// Renders a finished — or failed — diagnosis to `out`. Pure over the
/// diagnosis result, so both branches are unit-testable. A soft failure
/// (the target changed mid-scan or mid-pin) still exits 1, but with
/// `--json` it prints a machine-readable failure document instead of
/// breaking the JSON stream with a text line (F-20). Hard failures (the
/// view never opened) never reach here: they return `Err`, which `main`
/// reports on stderr with stdout left empty.
fn emit_diagnosis(
    pid: u32,
    json: bool,
    out: &mut dyn std::io::Write,
    result: Result<(ScanOutcome, (PinnedObjects, Vec<Skipped>)), String>,
) -> Result<i32> {
    let (outcome, (pinned, pin_skips)) = match result {
        Ok(result) => result,
        Err(error) => {
            if json {
                let document = serde_json::to_string_pretty(&failure_json(pid, &error))?;
                writeln!(out, "{document}")?;
            } else {
                writeln!(out, "p11scope: cannot inspect pid {pid}: {error}")?;
            }
            return Ok(1);
        }
    };
    if let Some(reason) = unreadable_mappings(&outcome) {
        return Err(unreadable_target_error(pid, reason));
    }
    let outcome = with_extra_skips(outcome, pin_skips);

    if json {
        let document = serde_json::to_string_pretty(&render_json(pid, &outcome, &pinned))?;
        writeln!(out, "{document}")?;
    } else {
        write!(out, "{}", render_text(pid, &outcome, &pinned))?;
    }
    Ok(0)
}

/// The cause, when the scan could not read the target's mappings at all:
/// no module was found and the initial mapping snapshot was refused.
fn unreadable_mappings(outcome: &ScanOutcome) -> Option<&str> {
    if !outcome.modules().is_empty() {
        return None;
    }
    outcome.skipped().iter().find_map(|skipped| {
        let rest = skipped.reason.strip_prefix(INITIAL_MAPS_REFUSAL)?;
        Some(rest.strip_prefix(": ").unwrap_or(rest))
    })
}

/// "The target could not be read at all" (docs/usage.md, exit codes): a hard
/// error, so `main` prints one stderr line and stdout stays empty. A
/// permission refusal names the fix: another user's process needs root.
fn unreadable_target_error(pid: u32, reason: &str) -> anyhow::Error {
    let denied = reason.contains("Permission denied") || reason.contains("not permitted");
    let fix = if denied {
        format!(
            "; its modules are unknown, not absent. A process owned by another user needs \
             root: run `sudo p11scope inspect --pid {pid}`"
        )
    } else {
        "; its modules are unknown, not absent".to_string()
    };
    anyhow::anyhow!("cannot read /proc/{pid}/maps ({reason}){fix}")
}

/// The machine-readable soft-failure document: the success schema with
/// `scan.status` failed and the reason, no modules. A failed inspect
/// must neither break `| jq` nor validate as a successful one.
fn failure_json(pid: u32, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": DOC_ID,
        "pid": pid,
        "scan": { "status": "failed", "reason": reason },
        "modules": [],
        "skipped": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedModule, ScannedTable};
    use p11scope_manifest::maps::{Device, ObjectKey};

    fn key(inode: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode,
        }
    }

    /// F-20: a soft diagnosis failure (the target changed mid-scan or
    /// mid-pin) with `--json` prints a machine-readable failure document
    /// on stdout and exits 1 — never a text line that breaks `| jq`.
    #[test]
    fn soft_diagnosis_failure_with_json_prints_a_failure_document() {
        let mut stdout = Vec::new();
        let code = emit_diagnosis(
            4242,
            true,
            &mut stdout,
            Err("process generation changed while inspect was scanning".into()),
        )
        .unwrap();
        assert_eq!(code, 1);
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(document["schema"], DOC_ID);
        assert_eq!(document["pid"], 4242);
        assert_eq!(document["scan"]["status"], "failed");
        assert_eq!(
            document["scan"]["reason"],
            "process generation changed while inspect was scanning"
        );
        assert_eq!(document["modules"], serde_json::json!([]));
        assert_eq!(document["skipped"], serde_json::json!([]));
    }

    /// HIGH-2: when the scan could not read the target's mappings at all
    /// (another user's process: `/proc/<pid>/maps` is EACCES), inspect knows
    /// nothing about its modules. That is the documented hard error — one
    /// stderr line naming the cause and the fix, empty stdout, exit 1 — never
    /// "0 PKCS#11 modules mapped" with `scan.status: scanned` and exit 0.
    #[test]
    fn unreadable_target_mappings_are_a_hard_error_not_zero_modules() {
        let unreadable = || {
            Ok((
                ScanOutcome::Scanned {
                    modules: Vec::new(),
                    skipped: vec![Skipped {
                        subject: "capture discovery".into(),
                        reason: "memory scan refused: initial mapping validation unavailable: \
                                 Permission denied (os error 13)"
                            .into(),
                    }],
                    scan_ms: 0,
                },
                (PinnedObjects::empty(), Vec::new()),
            ))
        };
        for json in [false, true] {
            let mut stdout = Vec::new();
            let result = emit_diagnosis(1379, json, &mut stdout, unreadable());
            assert!(
                stdout.is_empty(),
                "json={json}: {}",
                String::from_utf8_lossy(&stdout)
            );
            let error = format!("{:#}", result.expect_err("an unreadable target must fail"));
            assert!(error.contains("/proc/1379/maps"), "{error}");
            assert!(error.contains("Permission denied"), "{error}");
            assert!(
                error.contains("sudo p11scope inspect --pid 1379"),
                "{error}"
            );
            assert!(!error.contains("0 PKCS#11 modules"), "{error}");
        }
    }

    /// The scan's refusal wording is what `inspect` keys on; if the scan
    /// ever renames it, this fails instead of silently reporting 0 modules.
    #[test]
    fn the_initial_maps_refusal_prefix_matches_the_scan() {
        let scan = include_str!("discovery/scan.rs");
        assert!(
            scan.contains(&format!("\"{INITIAL_MAPS_REFUSAL}\"")),
            "src/discovery/scan.rs no longer emits {INITIAL_MAPS_REFUSAL:?}"
        );
    }

    /// A same-uid target whose `mem` is refused still has an inventory from
    /// maps: that stays a success (`status: unavailable`, exit 0).
    #[test]
    fn a_readable_inventory_without_memory_is_not_an_unreadable_target() {
        let outcome = ScanOutcome::Unavailable {
            reason: "ptrace",
            modules: Vec::new(),
            skipped: Vec::new(),
        };
        assert_eq!(unreadable_mappings(&outcome), None);
        let mut stdout = Vec::new();
        let code = emit_diagnosis(
            4242,
            true,
            &mut stdout,
            Ok((outcome, (PinnedObjects::empty(), Vec::new()))),
        )
        .unwrap();
        assert_eq!(code, 0);
    }

    /// The text contract is unchanged: same line, same exit code.
    #[test]
    fn soft_diagnosis_failure_without_json_keeps_the_text_line() {
        let mut stdout = Vec::new();
        let code = emit_diagnosis(
            4242,
            false,
            &mut stdout,
            Err("process generation changed while inspect was pinning".into()),
        )
        .unwrap();
        assert_eq!(code, 1);
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "p11scope: cannot inspect pid 4242: process generation changed while inspect was \
             pinning\n"
        );
    }

    /// Hard errors never reach the diagnosis renderer: a pid that names
    /// nothing fails before a single byte is written, so stdout stays
    /// empty and `main` reports the error on stderr instead.
    #[test]
    fn hard_errors_write_nothing_to_stdout() {
        let mut stdout = Vec::new();
        let error = run_with_writer(u32::MAX, &[], &HookRegistry::builtin(), true, &mut stdout)
            .unwrap_err();
        assert!(stdout.is_empty(), "hard errors must not touch stdout");
        assert!(!format!("{error:#}").is_empty());
    }

    /// The full success wiring through the writer: scanning this
    /// process always succeeds (its pidfd generation is stable) and
    /// prints a parseable success document.
    #[test]
    fn successful_inspect_writes_a_parseable_success_document() {
        let mut stdout = Vec::new();
        let pid = std::process::id();
        let code = run_with_writer(pid, &[], &HookRegistry::builtin(), true, &mut stdout).unwrap();
        assert_eq!(code, 0);
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(document["schema"], DOC_ID);
        assert_eq!(document["pid"], pid);
        assert!(
            document["scan"]["status"] == "scanned" || document["scan"]["status"] == "unavailable",
            "unexpected success status: {}",
            document["scan"]["status"]
        );
    }

    /// Mutation caught: reopening the PID for pinning, omitting the check between
    /// scan and pin, or rendering after the final check fails would mix generations.
    #[test]
    fn inspect_uses_one_generation_through_its_final_target_operation() {
        struct Lifecycle {
            checks: usize,
            events: Vec<&'static str>,
        }
        let mut changed_after_scan = Lifecycle {
            checks: 0,
            events: Vec::new(),
        };
        let result = scan_and_pin_retained_with(
            &mut changed_after_scan,
            |state| {
                state.checks += 1;
                state.checks < 2
            },
            |state| {
                state.events.push("scan");
                Ok(17)
            },
            |state, _| {
                state.events.push("pin");
                Ok(23)
            },
        );
        if result.is_ok() {
            changed_after_scan.events.push("render");
        }

        assert!(result.is_err(), "the post-scan mismatch must fail inspect");
        assert_eq!(changed_after_scan.events, ["scan"]);
        assert_eq!(
            changed_after_scan.checks, 2,
            "scan has a pre/post generation check"
        );

        let mut changed_after_pin = Lifecycle {
            checks: 0,
            events: Vec::new(),
        };
        let result = scan_and_pin_retained_with(
            &mut changed_after_pin,
            |state| {
                state.checks += 1;
                state.checks < 3
            },
            |state| {
                state.events.push("scan");
                Ok(17)
            },
            |state, _| {
                state.events.push("pin");
                Ok(23)
            },
        );
        if result.is_ok() {
            changed_after_pin.events.push("render");
        }
        assert!(result.is_err(), "the post-pin mismatch must fail inspect");
        assert_eq!(changed_after_pin.events, ["scan", "pin"]);
        assert_eq!(
            changed_after_pin.checks, 3,
            "pin has a final generation check before render"
        );
    }

    fn sample() -> ScanOutcome {
        ScanOutcome::Scanned {
            modules: vec![ScannedModule {
                view: crate::process::ProcessViewId(0),
                mount_namespace: crate::process::MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key: key(11),
                path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into(), "C_GetInterfaceList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Initialize",
                        object: key(11),
                        object_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                        file_offset: 0x1234,
                    }],
                    null_entries: vec!["C_GetFunctionStatus"],
                    unpinned: vec![],
                    address: 0x7f0000001000,
                    file_offset: Some(0),
                    live_return: false,
                    manifest_supported: false,
                }],
                interfaces: vec![ScannedInterface {
                    index: 0,
                    name_class: "exact_standard",
                    name_lossy: Some("PKCS 11".into()),
                    name_private: Some(b"PKCS 11".to_vec()),
                    flags: 0,
                    table: Some(0),
                }],
            }],
            skipped: vec![],
            scan_ms: 3,
        }
    }

    #[test]
    fn text_names_the_module_version_counts_and_null_entries() {
        let out = render_text(4242, &sample(), &PinnedObjects::empty());
        assert!(out.contains("pid 4242"), "{out}");
        assert!(out.contains("/usr/lib/softhsm/libsofthsm2.so"), "{out}");
        assert!(out.contains("2.40"), "{out}");
        assert!(
            out.contains("1 entry") || out.contains("1 entries"),
            "{out}"
        );
        assert!(
            out.contains("C_GetFunctionStatus"),
            "NULL slots are evidence: {out}"
        );
        assert!(
            out.contains("PKCS 11"),
            "inspect may show interface names: {out}"
        );
    }

    #[test]
    fn text_escapes_interface_name_quotes_and_ascii_controls() {
        let mut outcome = sample();
        let ScanOutcome::Scanned { modules, .. } = &mut outcome else {
            unreachable!()
        };
        modules[0].interfaces[0].name_lossy = Some("quote\"\\\n\r\t\u{1b}".into());

        let out = render_text(4242, &outcome, &PinnedObjects::empty());
        assert!(out.contains(r#""quote\"\\\n\r\t\u{1b}""#), "{out:?}");
        assert!(
            !out.contains("quote\"\\\n"),
            "raw controls reached text output: {out:?}"
        );
    }

    #[test]
    fn text_escapes_module_path_controls_while_json_preserves_them() {
        const HOSTILE: &str = "/opt/p\u{1b}[2Jevil\r.so";
        let mut outcome = sample();
        let ScanOutcome::Scanned { modules, .. } = &mut outcome else {
            unreachable!()
        };
        modules[0].path = HOSTILE.into();

        let text = render_text(4242, &outcome, &PinnedObjects::empty());
        assert!(
            !text.contains('\u{1b}') && !text.contains('\r'),
            "raw controls reached text: {text:?}"
        );
        assert!(text.contains(r"\u{1b}[2Jevil\r"), "{text:?}");

        let json = render_json(4242, &outcome, &PinnedObjects::empty());
        assert_eq!(
            json["modules"][0]["path"], HOSTILE,
            "JSON keeps original bytes"
        );
        assert!(
            serde_json::to_string(&json).unwrap().contains(r"\u001b"),
            "serde escapes on the wire"
        );
    }

    #[test]
    fn an_unavailable_scan_still_lists_the_modules_and_says_why() {
        let outcome = ScanOutcome::Unavailable {
            reason: "ptrace",
            modules: vec![ScannedModule {
                view: crate::process::ProcessViewId(0),
                mount_namespace: crate::process::MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key: key(11),
                path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![],
                interfaces: vec![],
            }],
            skipped: vec![],
        };
        let out = render_text(4242, &outcome, &PinnedObjects::empty());
        assert!(
            out.contains("libsofthsm2.so"),
            "modules are known without mem: {out}"
        );
        assert!(out.contains("ptrace"), "the reason must be named: {out}");
        assert!(
            out.contains("CAP_SYS_PTRACE") || out.contains("ptrace_scope"),
            "say what would fix it: {out}"
        );
    }

    #[test]
    fn json_is_stable_and_carries_the_document_id() {
        let value = render_json(4242, &sample(), &PinnedObjects::empty());
        assert_eq!(value["schema"], "p11scope/inspect/v1");
        assert_eq!(value["pid"], 4242);
        assert_eq!(
            value["modules"][0]["path"],
            "/usr/lib/softhsm/libsofthsm2.so"
        );
        assert_eq!(value["modules"][0]["tables"][0]["version"], "2.40");
        assert_eq!(value["modules"][0]["tables"][0]["entries"], 1);
    }
}
