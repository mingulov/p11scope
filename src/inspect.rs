//! `p11scope inspect --pid N`: renders a completed memory scan as text or JSON.
//! No BPF, no pause, no capture (spec §4.6) — reads `/proc` and nothing else, so
//! it works unprivileged against a same-uid target and answers "which providers
//! does this process actually use". Interface names are shown here on purpose:
//! `inspect` is a discovery tool, not capture output (spec §4.3).

use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{PinnedObjects, pin_scanned_objects};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedModule, Skipped, scan_pid,
};
use crate::process::PidPin;
use anyhow::Result;
use std::fmt::Write as _;
use std::path::PathBuf;

const DOC_ID: &str = "pkcs11-scope/inspect/v1";

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
        let _ = writeln!(out, "skipped: {} — {}", skipped.subject, skipped.reason);
    }
    out
}

fn render_module(out: &mut String, module: &ScannedModule, pinned: &PinnedObjects) {
    let _ = writeln!(out, "module  {}", module.path);

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
            .map(|(path, count)| format!("{path} ({count})"))
            .collect();
        let _ = writeln!(out, "  entries in other objects: {}", parts.join(", "));
    }
}

/// Renders a completed scan as JSON. Document id: `pkcs11-scope/inspect/v1`.
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

/// `p11scope inspect` — scans, pins, prints. Exit code: 0 when the scan ran
/// (even with zero modules), 1 when the target could not be read at all.
pub fn run(pid: u32, hints: &[PathBuf], hooks: &HookRegistry, json: bool) -> Result<i32> {
    // Fails fast, before any /proc/<pid>/maps read is attempted, when the pid
    // names nothing at all (no pidfd, no /proc/<pid>/stat).
    PidPin::open(pid).map_err(anyhow::Error::msg)?;

    let mut budget = CaptureWorkBudget::default();
    let outcome = match scan_pid(&ScanRequest { pid, hints, hooks }, &mut budget) {
        Ok(outcome) => outcome,
        Err(error) => {
            println!("p11scope: cannot inspect pid {pid}: {error}");
            return Ok(1);
        }
    };

    let (pinned, pin_skips) =
        pin_scanned_objects(pid, outcome.modules(), &mut budget).map_err(anyhow::Error::msg)?;
    let outcome = with_extra_skips(outcome, pin_skips);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&render_json(pid, &outcome, &pinned))?
        );
    } else {
        print!("{}", render_text(pid, &outcome, &pinned));
    }
    Ok(0)
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
                }],
                interfaces: vec![ScannedInterface {
                    index: 0,
                    name_class: "exact_standard",
                    name_lossy: Some("PKCS 11".into()),
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
        assert_eq!(value["schema"], "pkcs11-scope/inspect/v1");
        assert_eq!(value["pid"], 4242);
        assert_eq!(
            value["modules"][0]["path"],
            "/usr/lib/softhsm/libsofthsm2.so"
        );
        assert_eq!(value["modules"][0]["tables"][0]["version"], "2.40");
        assert_eq!(value["modules"][0]["tables"][0]["entries"], 1);
    }
}
