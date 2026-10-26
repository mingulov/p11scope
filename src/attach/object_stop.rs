//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retire private object pointers only after the native STOP gate proves Q.

use super::stop_gate::StopGate;
use super::{map_metadata, read_map_metadata, validate_map_metadata};
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{HashMap, Map, MapType};

pub(super) fn scrub_after_quiescence(ebpf: &mut Ebpf, gate: &StopGate) -> Result<usize> {
    if !gate.quiescent() {
        bail!("OBJECT_START scrub requires proven native quiescence");
    }
    let start_max = match ebpf.map("START").context("START map for object scrub")? {
        Map::HashMap(data) => read_map_metadata("START", data)?.max_entries,
        _ => bail!("unexpected START map variant for object scrub"),
    };
    scrub_map_after_quiescence(
        ebpf.map_mut("OBJECT_START")
            .context("OBJECT_START map for stop scrub")?,
        gate,
        start_max,
    )
}

fn scrub_map_after_quiescence(map: &mut Map, gate: &StopGate, max_entries: u32) -> Result<usize> {
    if !gate.quiescent() {
        bail!("OBJECT_START scrub requires proven native quiescence");
    }
    let Map::HashMap(data) = &*map else {
        bail!("unexpected OBJECT_START map variant for stop scrub");
    };
    validate_map_metadata(
        "OBJECT_START",
        data,
        map_metadata(MapType::Hash, 16, 432, max_entries, 0),
    )?;
    let mut table: HashMap<_, [u8; 16], [u8; 432]> = HashMap::try_from(map)?;
    // Restart at the first key after removal. Deleting the iterator's current
    // key would make GET_NEXT_KEY restart too; Q prevents producer insertion,
    // and the actual capacity bounds both visits and total retirement work.
    for cleared in 0..max_entries {
        let Some(key) = table
            .keys()
            .next()
            .transpose()
            .context("enumerating stopped OBJECT_START")?
        else {
            return Ok(cleared as usize);
        };
        if !gate.quiescent() {
            bail!("OBJECT_START scrub lost native quiescence");
        }
        // BPF_EXIST forbids manufacturing an owner. Zero and verify before
        // removal so a failed delete leaves no private pointer/capacity bytes.
        table
            .insert(key, [0; 432], 2)
            .context("zeroing stopped OBJECT_START")?;
        if table
            .get(&key, 0)
            .context("reading stopped OBJECT_START zero")?
            != [0; 432]
        {
            bail!("stopped OBJECT_START zero readback differs");
        }
        table
            .remove(&key)
            .context("removing stopped OBJECT_START")?;
    }
    if table
        .keys()
        .next()
        .transpose()
        .context("checking stopped OBJECT_START emptiness")?
        .is_some()
    {
        bail!("OBJECT_START remains populated after its exact capacity bound");
    }
    Ok(max_entries as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya::maps::{Array, MapData};
    use p11scope_ebpf_common::STOP_GATE_STOP;
    use std::os::fd::{AsFd as _, AsRawFd as _};

    fn create_map(name: &str, max_entries: u32) -> Result<MapData> {
        // Use the actual emitted definition, not a hand-built lookalike map.
        let mut object = aya_obj::Object::parse(crate::EBPF_OBJECT)?;
        let mut definition = object
            .maps
            .remove(name)
            .context("actual object map definition")?;
        definition.set_max_entries(max_entries);
        Ok(MapData::create(definition, name, None)?)
    }

    /// Pinned OBJECT_START/STOP_GATE scratch for the quiescence tests.
    type StopFixture = (Map, Map, StopGate, HashMap<MapData, [u8; 16], [u8; 432]>);

    fn fixture() -> Result<StopFixture> {
        let data = create_map("OBJECT_START", 2)?;
        let retained = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        let object = Map::HashMap(data);
        let gate_data = create_map("STOP_GATE", 1)?;
        let gate = StopGate::from_map_fd(gate_data.fd().as_fd())?;
        let gate_map = Map::Array(gate_data);
        let mut retained = HashMap::try_from(Map::HashMap(retained))?;
        retained.insert([0x11; 16], [0xa5; 432], 0)?;
        retained.insert([0x22; 16], [0x5a; 432], 0)?;
        Ok((object, gate_map, gate, retained))
    }

    #[test]
    #[ignore = "privileged: creates actual native BPF map definitions and retains map FDs"]
    fn object_stop_scrubs_real_retained_map_after_q() -> Result<()> {
        let (mut object, _gate_map, gate, retained) = fixture()?;
        gate.request_stop();
        assert!(gate.quiescent());
        assert_eq!(scrub_map_after_quiescence(&mut object, &gate, 2)?, 2);
        drop(object);
        assert_eq!(
            retained.keys().count(),
            0,
            "retained FD must observe complete removal"
        );
        assert_eq!(
            scrub_map_after_quiescence(
                &mut Map::HashMap(create_map("OBJECT_START", 2)?),
                &gate,
                2
            )?,
            0
        );
        Ok(())
    }

    #[test]
    #[ignore = "privileged: actual STOP_GATE no-Q and admitted-body refusal controls"]
    fn object_stop_refuses_real_unproven_q_without_mutation() -> Result<()> {
        let (mut object, mut gate_map, gate, retained) = fixture()?;
        for word in [0, 1, STOP_GATE_STOP | 1] {
            let mut table: Array<_, u64> = Array::try_from(&mut gate_map)?;
            table.set(0, word, 0)?;
            assert!(!gate.quiescent());
            assert!(scrub_map_after_quiescence(&mut object, &gate, 2).is_err());
            assert_eq!(retained.get(&[0x11; 16], 0)?, [0xa5; 432]);
            assert_eq!(retained.get(&[0x22; 16], 0)?, [0x5a; 432]);
            assert_eq!(retained.keys().count(), 2);
        }
        Ok(())
    }

    /// Why a program outside the 17-program source scan needs no uprobe
    /// stop gate (Opus stop-gate ruling, 2026-10-25).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ClassifiedReason {
        /// Gated in native code (`p11_stop_gate_enter`, the task_newtask shape).
        GatedNative,
        /// Per-file epoch bookkeeping only; endpoint state only via gated callers.
        FileEpochOnly,
        /// Invalidation-only hook; writes no endpoint state.
        NegativeOnly,
        /// Userspace-driven iterator; "slot" is the request index.
        UserspaceIter,
        /// Inventory usage flavor with no stop gate by construction; its owner
        /// is not an EngineSession, never partially detaches, never reuses a cell.
        InventoryNoStopGate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ClassifiedObject {
        Detailed,
        Inventory,
        Callers,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ClassifiedKind {
        TpBtf,
        FEntry,
        FExit,
        Iter,
        UProbe,
    }

    impl ClassifiedKind {
        fn matches_section(self, section: &aya_obj::ProgramSection) -> bool {
            use aya_obj::ProgramSection as Section;
            matches!(
                (self, section),
                (Self::TpBtf, Section::BtfTracePoint)
                    | (Self::FEntry, Section::FEntry { sleepable: false })
                    | (Self::FExit, Section::FExit { sleepable: false })
                    | (Self::Iter, Section::Iter { sleepable: false })
                    | (
                        Self::UProbe,
                        Section::UProbe {
                            sleepable: false,
                            multi: false,
                        }
                    )
            )
        }
    }

    struct ClassifiedRow {
        name: &'static str,
        objects: &'static [ClassifiedObject],
        kind: ClassifiedKind,
        source_file: &'static str,
        section_or_attr: &'static str,
        reason: ClassifiedReason,
    }

    /// Pinned 11-row table: every capture-object program outside the
    /// 17-program source scan, with the object(s) holding it, its section
    /// kind and why it needs no gate. A new program fails closed.
    const CLASSIFIED: &[ClassifiedRow] = &[
        ClassifiedRow {
            name: "task_newtask",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::TpBtf,
            source_file: "image_identity_fork.c",
            section_or_attr: "tp_btf/task_newtask",
            reason: ClassifiedReason::GatedNative,
        },
        ClassifiedRow {
            name: "p11_inst_vma_map",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::FEntry,
            source_file: "instance_epoch.c",
            section_or_attr: "fentry/uprobe_mmap",
            reason: ClassifiedReason::FileEpochOnly,
        },
        ClassifiedRow {
            name: "p11_inst_vma_unmap",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::FEntry,
            source_file: "instance_epoch.c",
            section_or_attr: "fentry/uprobe_munmap",
            reason: ClassifiedReason::FileEpochOnly,
        },
        ClassifiedRow {
            name: "p11_inst_vma_copy",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::FExit,
            source_file: "instance_epoch.c",
            section_or_attr: "fexit/copy_vma",
            reason: ClassifiedReason::FileEpochOnly,
        },
        ClassifiedRow {
            name: "p11_image_exec_release",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::FEntry,
            source_file: "image_identity_query.c",
            section_or_attr: "fentry/exec_mm_release",
            reason: ClassifiedReason::NegativeOnly,
        },
        ClassifiedRow {
            name: "p11_selected_cgroup_migrate",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::FEntry,
            source_file: "selected_detailed.c",
            section_or_attr: "fentry/cgroup_migrate",
            reason: ClassifiedReason::NegativeOnly,
        },
        ClassifiedRow {
            name: "p11_image_query",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::Iter,
            source_file: "image_identity_query.c",
            section_or_attr: "iter/task",
            reason: ClassifiedReason::UserspaceIter,
        },
        ClassifiedRow {
            name: "p11_selected_bootstrap",
            objects: &[ClassifiedObject::Detailed],
            kind: ClassifiedKind::Iter,
            source_file: "selected_detailed.c",
            section_or_attr: "iter/task",
            reason: ClassifiedReason::UserspaceIter,
        },
        ClassifiedRow {
            name: "p11_inventory_image_baseline",
            objects: &[ClassifiedObject::Callers],
            kind: ClassifiedKind::Iter,
            source_file: "selected_detailed_baseline.c",
            section_or_attr: "iter/task",
            reason: ClassifiedReason::UserspaceIter,
        },
        ClassifiedRow {
            name: "p11_usage_entry_lp64",
            objects: &[ClassifiedObject::Inventory, ClassifiedObject::Callers],
            kind: ClassifiedKind::UProbe,
            source_file: "inventory.rs",
            section_or_attr: "#[uprobe]",
            reason: ClassifiedReason::InventoryNoStopGate,
        },
        ClassifiedRow {
            name: "p11_usage_entry_ia32",
            objects: &[ClassifiedObject::Inventory, ClassifiedObject::Callers],
            kind: ClassifiedKind::UProbe,
            source_file: "inventory.rs",
            section_or_attr: "#[uprobe]",
            reason: ClassifiedReason::InventoryNoStopGate,
        },
    ];

    /// One capture-object program is either scanned (with a scanned section
    /// kind) or a table row listing this object with a matching section kind.
    fn check_object_program(
        object: ClassifiedObject,
        name: &str,
        section: &aya_obj::ProgramSection,
        scanned: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        use aya_obj::ProgramSection as Section;
        if scanned.contains(name) {
            anyhow::ensure!(
                matches!(
                    section,
                    Section::UProbe {
                        sleepable: false,
                        multi: false,
                    } | Section::URetProbe {
                        sleepable: false,
                        multi: false,
                    } | Section::RawTracePoint
                ),
                "{name} is scanned but has an unscanned section kind {section:?}"
            );
            return Ok(());
        }
        let Some(row) = CLASSIFIED.iter().find(|row| row.name == name) else {
            bail!("{name} is neither scanned nor classified");
        };
        anyhow::ensure!(
            row.objects.contains(&object),
            "{name} is classified but not for {object:?}"
        );
        anyhow::ensure!(
            row.kind.matches_section(section),
            "{name} has section kind {section:?}, classified as {:?}",
            row.kind
        );
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum RustProgramAttr {
        UProbe,
        URetProbe,
        RawTracePoint,
    }

    struct RustProgram {
        name: String,
        attr: RustProgramAttr,
        body: String,
    }

    /// Strip balanced `#[...]` attribute groups from the front of one
    /// source line, returning the remainder. A capture attribute may
    /// carry `#[cfg(..)]` or other attributes between itself and its
    /// fn, or share the fn line; anything else before the fn fails
    /// closed at the call site.
    fn strip_rust_attributes(line: &str) -> &str {
        let mut rest = line.trim_start();
        while let Some(after_open) = rest.strip_prefix("#[") {
            let mut depth = 1usize;
            let mut end = None;
            for (offset, byte) in after_open.bytes().enumerate() {
                if byte == b'[' {
                    depth += 1;
                } else if byte == b']' {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(offset);
                        break;
                    }
                }
            }
            let Some(end) = end else {
                break;
            };
            rest = after_open[end + 1..].trim_start();
        }
        rest
    }

    /// OD-1 capture-program inventory: every `#[uprobe]` /
    /// `#[uretprobe]` / `#[raw_tracepoint(..)]` function in a capture
    /// source, including `#[cfg(feature = ..)]`-gated ones. Attribute
    /// lines between the probe attribute and its fn are skipped; the
    /// body runs from the `pub fn` line through its column-zero closing
    /// brace.
    fn scan_rust_programs(source: &str) -> Vec<RustProgram> {
        let lines: Vec<&str> = source.lines().collect();
        let mut programs = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            let attr = if lines[index] == "#[uprobe]" {
                Some(RustProgramAttr::UProbe)
            } else if lines[index] == "#[uretprobe]" {
                Some(RustProgramAttr::URetProbe)
            } else if lines[index].starts_with("#[raw_tracepoint") {
                Some(RustProgramAttr::RawTracePoint)
            } else {
                None
            };
            let Some(attr) = attr else {
                index += 1;
                continue;
            };
            // Attribute lines between the probe attribute and its fn
            // are skipped; the fn may also share its line with a
            // trailing attribute prefix. Anything else fails closed.
            let mut head_index = index + 1;
            let head = loop {
                let line = lines
                    .get(head_index)
                    .expect("a capture attribute is followed by its fn");
                let trimmed = line.trim_start();
                if let Some(head) = strip_rust_attributes(trimmed).strip_prefix("pub fn ") {
                    break head;
                }
                assert!(
                    trimmed.starts_with("#[") && strip_rust_attributes(trimmed).is_empty(),
                    "a capture attribute is immediately followed by its fn"
                );
                head_index += 1;
            };
            let name = head.split('(').next().expect("a fn name").to_string();
            let end = lines[head_index + 1..]
                .iter()
                .position(|line| *line == "}")
                .map(|offset| head_index + 1 + offset)
                .expect("a top-level fn ends at column zero");
            programs.push(RustProgram {
                name,
                attr,
                body: lines[head_index..=end].join("\n"),
            });
            index = end + 1;
        }
        programs
    }

    /// The enter-before-map rule, shared by the source contract and the
    /// counter-bank roots: a non-carried program reaches the code line
    /// `if !stop_gate_enter() {` before any other code, and always leaves;
    /// a carried continuation never re-checks and always releases. The gate
    /// is a whole code line, never a substring a comment could satisfy.
    fn check_rust_gate(name: &str, body: &str, carried: bool) -> Result<()> {
        const GATE_LINE: &str = "if !stop_gate_enter() {";
        let gate = body.lines().position(|line| line.trim() == GATE_LINE);
        let leave = body.find("stop_gate_leave()");
        if carried {
            anyhow::ensure!(
                gate.is_none(),
                "{name} carries admission and must not re-check the gate"
            );
            anyhow::ensure!(
                leave.is_some(),
                "{name} carries admission and must release it"
            );
            return Ok(());
        }
        let gate = gate.context("a non-carried program enters the stop gate")?;
        anyhow::ensure!(
            leave.is_some(),
            "{name} enters the stop gate and must leave it"
        );
        // Fail closed: before the gate line, only comments, blanks and
        // the register/stack-discipline tail calls may run. Those calls
        // touch no map data (out-of-range index, immediate return); any
        // other pre-gate code — including a map data accessor — fails.
        // Complete lines before the gate line, minus the fn signature.
        for line in body.lines().skip(1).take(gate.saturating_sub(1)) {
            let code = line.trim();
            if code.is_empty() || code.starts_with("//") {
                continue;
            }
            anyhow::ensure!(
                code == "keep_kernel_stack(&ctx);" || code == "keep_endpoint_stack(&ctx);",
                "{name} runs before the stop gate: {code}"
            );
        }
        Ok(())
    }

    struct CProgram {
        file: &'static str,
        section: String,
        name: String,
        body: String,
    }

    /// Every `SEC(`/`IMG_SEC(`/`INST_SEC(` program in a native C source:
    /// the section string, then `int NAME(` on the next line, with the body
    /// through its column-zero closing brace. Map and license sections are
    /// not programs.
    fn scan_c_programs(file: &'static str, source: &str) -> Vec<CProgram> {
        fn section_of(line: &str) -> Option<&str> {
            for prefix in ["SEC(\"", "IMG_SEC(\"", "INST_SEC(\""] {
                if let Some(rest) = line.strip_prefix(prefix) {
                    let section = rest
                        .strip_suffix(')')
                        .and_then(|bare| bare.strip_suffix('"'));
                    return section;
                }
            }
            None
        }
        let lines: Vec<&str> = source.lines().collect();
        let mut programs = Vec::new();
        let mut index = 0;
        while index + 1 < lines.len() {
            let Some(section) = section_of(lines[index]) else {
                index += 1;
                continue;
            };
            if section.starts_with('.') || section.starts_with("license") {
                index += 1;
                continue;
            }
            let head = lines[index + 1]
                .strip_prefix("int ")
                .expect("a section macro is immediately followed by its int fn");
            let name = head.split('(').next().expect("a fn name").to_string();
            let end = lines[index + 2..]
                .iter()
                .position(|line| *line == "}")
                .map(|offset| index + 2 + offset)
                .expect("a top-level fn ends at column zero");
            programs.push(CProgram {
                file,
                section: section.to_string(),
                name,
                body: lines[index + 1..=end].join("\n"),
            });
            index = end + 1;
        }
        programs
    }

    /// The gated `task_newtask` shape: before the gate only the signature,
    /// a lone `{`, blanks, comments and bare declarations (end `;`, no `(`
    /// or `=`, and no statement keyword, so a smuggled `return` cannot pass
    /// as a declaration); the first code line enters, and the body leaves.
    fn check_gated_c_body(name: &str, body: &str) -> Result<()> {
        const GATE_LINE: &str = "if (!p11_stop_gate_enter())";
        let mut lines = body.lines();
        let signature = lines.next().unwrap_or("");
        anyhow::ensure!(
            signature.starts_with("int ") && signature.contains(name),
            "{name} body starts with its signature, found {signature:?}"
        );
        let mut entered = false;
        let mut in_block = false;
        for line in lines {
            let mut code = line.trim();
            if in_block {
                if let Some(end) = code.find("*/") {
                    in_block = false;
                    code = code[end + 2..].trim();
                } else {
                    continue;
                }
            }
            if let Some(hash) = code.find("//") {
                code = code[..hash].trim();
            }
            if code.is_empty() || code == "{" {
                continue;
            }
            if let Some(rest) = code.strip_prefix("/*") {
                if rest.find("*/").is_none() {
                    in_block = true;
                }
                continue;
            }
            if !entered
                && code.ends_with(';')
                && !code.contains('(')
                && !code.contains('=')
                && !matches!(
                    code.split_whitespace().next(),
                    Some(
                        "return"
                            | "if"
                            | "for"
                            | "while"
                            | "do"
                            | "switch"
                            | "goto"
                            | "break"
                            | "continue"
                            | "case"
                    )
                )
            {
                continue;
            }
            if !entered {
                anyhow::ensure!(
                    code == GATE_LINE,
                    "{name} runs before the stop gate: {code}"
                );
                entered = true;
            }
        }
        anyhow::ensure!(entered, "{name} never enters the stop gate");
        anyhow::ensure!(
            body.contains("p11_stop_gate_leave();"),
            "{name} enters the stop gate and must leave it"
        );
        Ok(())
    }

    /// Every other classified C row stays outside the gate entirely.
    fn check_ungated_c_body(name: &str, body: &str) -> Result<()> {
        anyhow::ensure!(
            !body.contains("stop_gate_enter"),
            "{name} must not enter the stop gate"
        );
        Ok(())
    }

    const NATIVE_C_SOURCES: &[(&str, &str)] = &[
        (
            "image_identity_fork.c",
            include_str!("../../crates/ebpf/native/image_identity_fork.c"),
        ),
        (
            "image_identity_query.c",
            include_str!("../../crates/ebpf/native/image_identity_query.c"),
        ),
        (
            "instance_epoch.c",
            include_str!("../../crates/ebpf/native/instance_epoch.c"),
        ),
        (
            "selected_detailed.c",
            include_str!("../../crates/ebpf/native/selected_detailed.c"),
        ),
        (
            "selected_detailed_baseline.c",
            include_str!("../../crates/ebpf/native/selected_detailed_baseline.c"),
        ),
    ];

    #[test]
    fn capture_objects_programs_are_scanned() -> Result<()> {
        let programs = scan_rust_programs(include_str!("../../crates/ebpf/src/main.rs"));
        let scanned: std::collections::BTreeSet<String> = programs
            .iter()
            .map(|program| program.name.clone())
            .collect();
        assert_eq!(CLASSIFIED.len(), 11, "the classified table pins 11 rows");
        for row in CLASSIFIED {
            assert!(
                !scanned.contains(row.name),
                "scanned and classified names are disjoint, both hold {}",
                row.name
            );
            eprintln!(
                "classified {} in {:?} as {:?} from {} ({:?})",
                row.name, row.objects, row.kind, row.source_file, row.reason
            );
        }
        #[cfg(feature = "unsafe-unvalidated-metadata")]
        let detailed_expected = 25;
        #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
        let detailed_expected = 20;
        let objects = [
            (
                ClassifiedObject::Detailed,
                crate::EBPF_OBJECT,
                detailed_expected,
            ),
            (
                ClassifiedObject::Inventory,
                crate::EBPF_INVENTORY_OBJECT,
                12,
            ),
            (
                ClassifiedObject::Callers,
                crate::EBPF_INVENTORY_CALLERS_OBJECT,
                13,
            ),
        ];
        let mut parsed = Vec::new();
        for (id, bytes, expected) in objects {
            let object = aya_obj::Object::parse(bytes)?;
            let mut names: Vec<&str> = object.programs.keys().map(String::as_str).collect();
            names.sort_unstable();
            eprintln!("{id:?} programs ({}): {names:?}", names.len());
            assert_eq!(
                names.len(),
                expected,
                "{id:?} holds its pinned program count"
            );
            for (name, program) in &object.programs {
                check_object_program(id, name, &program.section, &scanned)?;
            }
            parsed.push((id, object));
        }
        for row in CLASSIFIED {
            for (id, object) in &parsed {
                assert_eq!(
                    object.programs.contains_key(row.name),
                    row.objects.contains(id),
                    "{} is in exactly its listed objects",
                    row.name
                );
            }
        }
        assert!(
            parsed[0].1.maps.contains_key("STOP_GATE"),
            "STOP_GATE is in the Detailed maps"
        );
        assert!(
            !parsed[1].1.maps.contains_key("STOP_GATE"),
            "STOP_GATE is in neither inventory object"
        );
        assert!(
            !parsed[2].1.maps.contains_key("STOP_GATE"),
            "STOP_GATE is in neither inventory object"
        );
        Ok(())
    }

    #[test]
    fn capture_source_programs_enter_stop_gate_or_carry_admission() {
        const CARRIED: &[&str] = &["interface_list_worker", "p11_entry_template_second"];
        let programs = scan_rust_programs(include_str!("../../crates/ebpf/src/main.rs"));
        let names: Vec<&str> = programs
            .iter()
            .map(|program| program.name.as_str())
            .collect();
        eprintln!("scanned capture programs ({}): {names:?}", names.len());
        assert_eq!(names.len(), 17, "the capture source names 17 programs");
        for carried in CARRIED {
            assert!(
                names.contains(carried),
                "carried continuation {carried} is a scanned program"
            );
        }
        for program in &programs {
            check_rust_gate(
                &program.name,
                &program.body,
                CARRIED.contains(&program.name.as_str()),
            )
            .unwrap();
        }
    }

    #[test]
    fn capture_native_programs_match_classified_gate() {
        // The 9 C rows: scan every classified C source, then compare
        // (name, file, section) triples against the pinned table exactly.
        let mut found = Vec::new();
        for (file, source) in NATIVE_C_SOURCES {
            for program in scan_c_programs(file, source) {
                found.push((program.name, program.file, program.section, program.body));
            }
        }
        let mut expected: Vec<(&str, &str, &str)> = CLASSIFIED
            .iter()
            .filter(|row| row.source_file.ends_with(".c"))
            .map(|row| (row.name, row.source_file, row.section_or_attr))
            .collect();
        expected.sort_unstable();
        let mut actual: Vec<(&str, &str, &str)> = found
            .iter()
            .map(|(name, file, section, _)| (name.as_str(), *file, section.as_str()))
            .collect();
        actual.sort_unstable();
        eprintln!("scanned C programs ({}): {actual:?}", actual.len());
        assert_eq!(actual, expected, "the C sources hold exactly the 9 C rows");
        let body_of = |name: &str| {
            found
                .iter()
                .find(|(candidate, _, _, _)| candidate == name)
                .map(|(_, _, _, body)| body.as_str())
                .expect("a pinned row was scanned")
        };
        // The gated row enters first and leaves; its file owns the header.
        check_gated_c_body("task_newtask", body_of("task_newtask")).unwrap();
        let fork = NATIVE_C_SOURCES
            .iter()
            .find(|(file, _)| *file == "image_identity_fork.c")
            .map(|(_, source)| *source)
            .expect("the fork source is scanned");
        assert!(
            fork.contains("#include \"stop_gate.h\""),
            "the gated row includes stop_gate.h"
        );
        for (file, source) in NATIVE_C_SOURCES {
            if *file == "image_identity_fork.c" {
                continue;
            }
            assert!(
                !source.contains("stop_gate.h"),
                "only image_identity_fork.c includes stop_gate.h, not {file}"
            );
        }
        for (name, _, _, body) in &found {
            if name == "task_newtask" {
                continue;
            }
            check_ungated_c_body(name, body).unwrap();
        }
        // The 2 inventory.rs rows: exactly the usage pair, ungated, owned
        // by the inventory-only module line in main.rs.
        let usage = scan_rust_programs(include_str!("../../crates/ebpf/src/inventory.rs"));
        let mut usage_names: Vec<(&str, RustProgramAttr)> = usage
            .iter()
            .map(|program| (program.name.as_str(), program.attr))
            .collect();
        usage_names.sort_unstable();
        assert_eq!(
            usage_names,
            [
                ("p11_usage_entry_ia32", RustProgramAttr::UProbe),
                ("p11_usage_entry_lp64", RustProgramAttr::UProbe),
            ],
            "inventory.rs holds exactly the 2 usage rows"
        );
        for program in &usage {
            assert!(
                !program.body.contains("stop_gate_enter"),
                "{} must not enter the stop gate",
                program.name
            );
        }
        assert!(
            include_str!("../../crates/ebpf/src/main.rs")
                .contains("#[cfg(feature = \"inventory-only\")]\nmod inventory;"),
            "the usage rows are owned by the inventory-only module line"
        );
        // The 4 counter-bank roots: the counts pair, gated on their
        // signature lines, then the timing pair, gated before their
        // attributes. Private bank-proof build only, so this source
        // check is their only guard; each passes the gate rule.
        let banks = scan_rust_programs(include_str!("../../crates/ebpf/src/counter_bank_proof.rs"));
        let bank_names: Vec<(&str, RustProgramAttr)> = banks
            .iter()
            .map(|program| (program.name.as_str(), program.attr))
            .collect();
        assert_eq!(
            bank_names,
            [
                ("p11_counter_bank_entry", RustProgramAttr::UProbe),
                ("p11_counter_bank_return", RustProgramAttr::URetProbe),
                ("p11_counter_bank_entry", RustProgramAttr::UProbe),
                ("p11_counter_bank_return", RustProgramAttr::URetProbe),
            ],
            "counter_bank_proof.rs holds exactly its 4 roots"
        );
        for program in &banks {
            check_rust_gate(&program.name, &program.body, false).unwrap();
        }
    }

    #[test]
    fn classified_check_fails_on_unclassified_name() {
        use aya_obj::ProgramSection as Section;
        let scanned = std::collections::BTreeSet::from(["p11_entry".to_string()]);
        assert!(
            check_object_program(
                ClassifiedObject::Detailed,
                "p11_entry",
                &Section::UProbe {
                    sleepable: false,
                    multi: false,
                },
                &scanned,
            )
            .is_ok(),
            "a scanned uprobe passes its control"
        );
        let error = check_object_program(
            ClassifiedObject::Detailed,
            "p11_no_such_program",
            &Section::UProbe {
                sleepable: false,
                multi: false,
            },
            &scanned,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("neither scanned nor classified"),
            "unexpected failure: {error:?}"
        );
    }

    #[test]
    fn classified_check_fails_on_row_in_wrong_object() {
        use aya_obj::ProgramSection as Section;
        let scanned = std::collections::BTreeSet::new();
        assert!(
            check_object_program(
                ClassifiedObject::Detailed,
                "task_newtask",
                &Section::BtfTracePoint,
                &scanned,
            )
            .is_ok(),
            "the gated row passes in its own object"
        );
        let error = check_object_program(
            ClassifiedObject::Inventory,
            "task_newtask",
            &Section::BtfTracePoint,
            &scanned,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not for"),
            "unexpected failure: {error:?}"
        );
    }

    #[test]
    fn classified_check_fails_on_wrong_section_kind() {
        use aya_obj::ProgramSection as Section;
        let scanned = std::collections::BTreeSet::new();
        let error = check_object_program(
            ClassifiedObject::Detailed,
            "task_newtask",
            &Section::UProbe {
                sleepable: false,
                multi: false,
            },
            &scanned,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("section kind"),
            "unexpected failure: {error:?}"
        );
    }

    #[test]
    fn classified_check_fails_on_code_before_gate() {
        let fork = NATIVE_C_SOURCES
            .iter()
            .find(|(file, _)| *file == "image_identity_fork.c")
            .map(|(_, source)| *source)
            .expect("the fork source is scanned");
        let body = scan_c_programs("image_identity_fork.c", fork)
            .into_iter()
            .find(|program| program.name == "task_newtask")
            .map(|program| program.body)
            .expect("the gated row is scanned");
        assert!(
            check_gated_c_body("task_newtask", &body).is_ok(),
            "the real gated row passes its control"
        );
        let moved_call = body.replacen(
            "    if (!p11_stop_gate_enter())",
            "    rc = task_newtask_impl(ctx);\n    if (!p11_stop_gate_enter())",
            1,
        );
        assert_ne!(
            moved_call, body,
            "the call mutant differs from the real body"
        );
        let error = check_gated_c_body("task_newtask", &moved_call).unwrap_err();
        assert!(
            error.to_string().contains("runs before the stop gate"),
            "unexpected failure: {error:?}"
        );
        let early_return = body.replacen(
            "    if (!p11_stop_gate_enter())",
            "    return 0;\n    if (!p11_stop_gate_enter())",
            1,
        );
        let error = check_gated_c_body("task_newtask", &early_return).unwrap_err();
        assert!(
            error.to_string().contains("runs before the stop gate"),
            "a smuggled return is code, not a declaration: {error:?}"
        );
    }

    #[test]
    fn classified_check_gate_match_ignores_comment_mention() {
        // The old substring find() passed this body: the gate text appears,
        // but only inside a comment. The code-line match must refuse it.
        let commented = "pub fn commented(ctx: ProbeContext) -> u32 {\n    // if !stop_gate_enter() {\n    stop_gate_leave();\n    0\n}";
        let error = check_rust_gate("commented", commented, false).unwrap_err();
        assert!(
            error.to_string().contains("enters the stop gate"),
            "unexpected failure: {error:?}"
        );
        let gated = "pub fn gated(ctx: ProbeContext) -> u32 {\n    keep_endpoint_stack(&ctx);\n    if !stop_gate_enter() {\n        return 0;\n    }\n    stop_gate_leave();\n    0\n}";
        assert!(
            check_rust_gate("gated", gated, false).is_ok(),
            "a real indented gate line passes its control"
        );
    }

    #[test]
    fn classified_check_fails_on_outside_row_gaining_gate_enter() {
        let query = NATIVE_C_SOURCES
            .iter()
            .find(|(file, _)| *file == "image_identity_query.c")
            .map(|(_, source)| *source)
            .expect("the query source is scanned");
        let body = scan_c_programs("image_identity_query.c", query)
            .into_iter()
            .find(|program| program.name == "p11_image_query")
            .map(|program| program.body)
            .expect("the outside row is scanned");
        assert!(
            check_ungated_c_body("p11_image_query", &body).is_ok(),
            "the real outside row passes its control"
        );
        let gated = body.replacen("{\n", "{\n    (void)p11_stop_gate_enter();\n", 1);
        assert_ne!(gated, body, "the gate mutant differs from the real body");
        let error = check_ungated_c_body("p11_image_query", &gated).unwrap_err();
        assert!(
            error.to_string().contains("must not enter the stop gate"),
            "unexpected failure: {error:?}"
        );
    }

    #[test]
    #[ignore = "privileged: frozen real OBJECT_START must not produce false scrub success"]
    fn object_stop_reports_real_scrub_failure() -> Result<()> {
        let (mut object, _gate_map, gate, retained) = fixture()?;
        #[repr(C)]
        struct Freeze {
            map_fd: u32,
            padding: u32,
        }
        let Map::HashMap(data) = &object else {
            unreachable!()
        };
        let mut attr = Freeze {
            map_fd: data.fd().as_fd().as_raw_fd() as u32,
            padding: 0,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                22u32,
                &mut attr,
                std::mem::size_of::<Freeze>(),
            )
        };
        assert_eq!(
            result,
            0,
            "freeze actual map: {}",
            std::io::Error::last_os_error()
        );
        gate.request_stop();
        assert!(scrub_map_after_quiescence(&mut object, &gate, 2).is_err());
        assert_eq!(retained.get(&[0x11; 16], 0)?, [0xa5; 432]);
        Ok(())
    }
}
