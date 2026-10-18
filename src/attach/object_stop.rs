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

    fn fixture() -> Result<(Map, Map, StopGate, HashMap<MapData, [u8; 16], [u8; 432]>)> {
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
