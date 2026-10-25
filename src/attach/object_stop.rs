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

    /// OD-1 capture-program inventory: every `#[uprobe]` /
    /// `#[uretprobe]` / `#[raw_tracepoint(..)]` function in the capture
    /// source, including `#[cfg(feature = ..)]`-gated ones. Returns
    /// `(name, body)` with the body from the `pub fn` line through its
    /// column-zero closing brace.
    fn scanned_capture_programs() -> Vec<(String, String)> {
        let source = include_str!("../../crates/ebpf/src/main.rs");
        let lines: Vec<&str> = source.lines().collect();
        let mut programs = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            let is_program = line == "#[uprobe]"
                || line == "#[uretprobe]"
                || line.starts_with("#[raw_tracepoint");
            if !is_program {
                index += 1;
                continue;
            }
            let head = lines[index + 1]
                .strip_prefix("pub fn ")
                .expect("a capture attribute is immediately followed by its fn");
            let name = head.split('(').next().expect("a fn name").to_string();
            let end = lines[index + 2..]
                .iter()
                .position(|line| *line == "}")
                .map(|offset| index + 2 + offset)
                .expect("a top-level fn ends at column zero");
            programs.push((name, lines[index + 1..=end].join("\n")));
            index = end + 1;
        }
        programs
    }

    #[test]
    fn capture_source_programs_enter_stop_gate_or_carry_admission() {
        const CARRIED: &[&str] = &["interface_list_worker", "p11_entry_template_second"];
        let programs = scanned_capture_programs();
        let names: Vec<&str> = programs.iter().map(|(name, _)| name.as_str()).collect();
        eprintln!("scanned capture programs ({}): {names:?}", names.len());
        assert_eq!(names.len(), 17, "the capture source names 17 programs");
        for carried in CARRIED {
            assert!(
                names.contains(carried),
                "carried continuation {carried} is a scanned program"
            );
        }
        for (name, body) in &programs {
            let carried = CARRIED.contains(&name.as_str());
            let enter = body.find("stop_gate_enter()");
            let leave = body.find("stop_gate_leave()");
            if carried {
                assert!(
                    enter.is_none(),
                    "{name} carries admission and must not re-check the gate"
                );
                assert!(
                    leave.is_some(),
                    "{name} carries admission and must release it"
                );
                continue;
            }
            let enter = enter.expect("a non-carried program enters the stop gate");
            assert!(
                leave.is_some(),
                "{name} enters the stop gate and must leave it"
            );
            // Fail closed: before the gate line, only comments, blanks and
            // the register/stack-discipline tail calls may run. Those calls
            // touch no map data (out-of-range index, immediate return); any
            // other pre-gate code — including a map data accessor — fails.
            // Complete lines before the gate line, minus the fn signature.
            let gate_line = body[..enter].lines().count();
            for line in body.lines().skip(1).take(gate_line.saturating_sub(2)) {
                let code = line.trim();
                if code.is_empty() || code.starts_with("//") {
                    continue;
                }
                assert!(
                    code == "keep_kernel_stack(&ctx);" || code == "keep_endpoint_stack(&ctx);",
                    "{name} runs before the stop gate: {code}"
                );
            }
        }
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
