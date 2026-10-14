//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 adapters tail: wire the read-protocol core to object storage.
//!
//! Entry-fill runs after the ABI record (dispatch on the frozen descriptor
//! via `object_capture`, write verdicts into the side row, advance ENTRY to
//! READY, fault plus abandon on refusal). Return-fill runs after the
//! required=1 ready query (return-phase reads, write side fields, advance
//! READY to RETURNING, fault plus drain on refusal). No tail is constructed:
//! production publication stays gated for slice D. These tests pin the
//! adapter call sites, ordering and ELF presence; the existing
//! `object_producer_compiled_frames_are_bounded` test enforces the 512-byte
//! root call-chain budget over the new levels.

use std::path::{Path, PathBuf};
use std::process::Command;

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from + start.len()..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source marker {end:?}"));
    &rest[..until]
}

fn embedded_object(directory: &Path) -> PathBuf {
    let object = directory.join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    object
}

fn nm_text_symbols(object: &Path) -> String {
    let output = Command::new("nm")
        .arg("--defined-only")
        .arg(object)
        .output()
        .expect("run nm on embedded object");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn object_producer_adapters_entry_fill_shape() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF entry root");
    // Adapter helpers are outlined like the marker/ABI helpers: one
    // rounding quantum per level, never inlined into the hot root frame.
    for helper in ["fn object_fill_entry", "fn object_fill_return"] {
        assert!(source.contains(helper), "missing adapter helper {helper}");
    }
    let marker = source.find("fn object_fill_entry").expect("entry helper");
    let window = &source[marker.saturating_sub(400)..marker];
    assert!(
        window.contains("#[inline(never)]"),
        "entry helper must be #[inline(never)]"
    );
    let marker = source.find("fn object_fill_return").expect("return helper");
    let window = &source[marker.saturating_sub(400)..marker];
    assert!(
        window.contains("#[inline(never)]"),
        "return helper must be #[inline(never)]"
    );

    // Entry: ABI record, then fill, then abandon on refusal.
    let entry = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8>(ctx: ProbeContext) -> u32 {",
        "fn rv_count_add(key: &RvKey) -> bool {",
    );
    let abi = entry
        .find("object_record_entry_abi(&key,")
        .expect("entry must record the ABI before filling");
    let fill = entry
        .find("object_fill_entry(")
        .expect("entry must fill the side row after the ABI record");
    assert!(abi < fill, "entry fill must run after the ABI record");
    // Refusal abandons through the ordinary removal plus the fault leaf.
    let abandon = entry[fill..]
        .find("owned_start_remove(&key, true)")
        .expect("entry fill refusal must abandon through the ordinary removal");
    let fault = entry[fill..]
        .find("p11_object_fault()")
        .expect("entry fill refusal must fault");
    // Both abandon sites (ABI record + fill) retire through the same removal.
    assert!(
        entry.matches("owned_start_remove(&key, true)").count() >= 2,
        "entry keeps ABI-record and fill abandon arms"
    );
    let _ = (abandon, fault);

    // Slice tail emits nothing.
    assert!(
        !source.contains("ObjectCallWire {"),
        "adapters must not construct an object tail"
    );
}

#[test]
fn object_producer_adapters_return_fill_shape() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root");
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // Return: required=1 ready query, then fill, then the drain retire.
    let ready = returned
        .find("p11_object_side_get(&key, descriptor, 1)")
        .expect("return fill must query ready with required=1");
    let fill = returned
        .find("object_fill_return(")
        .expect("return must fill before draining");
    let drain = returned
        .rfind("owned_start_remove(&key, true)")
        .expect("drain arm retires");
    assert!(
        ready < fill && fill < drain,
        "return must query ready before filling before draining"
    );
    // The drain still queries (required=0, all sane phases) and gates on
    // agreement plus retire before any target read in the return body. The
    // fill itself is outlined, so its reads do not appear here.
    let query = returned
        .find("p11_object_side_get(&key, descriptor, 0)")
        .expect("drain must query the side row before retiring");
    let fault = returned
        .find("p11_object_fault()")
        .expect("failed settle must fault");
    let first_read = returned
        .find("read_word(")
        .expect("return reads target words");
    for (name, site) in [
        ("ready", ready),
        ("fill", fill),
        ("query", query),
        ("fault", fault),
    ] {
        assert!(
            site < first_read,
            "{name} must precede the first target read in the return body"
        );
    }
    assert!(
        drain < first_read,
        "drain retire must precede the first target read in the return body"
    );
    // No emission yet.
    assert!(
        !source.contains("ObjectCallWire {"),
        "adapters must not construct an object tail"
    );
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        1,
        "return keeps its single ring reservation"
    );
}

#[test]
fn object_producer_adapters_helpers_in_elf() {
    let directory = tempfile::tempdir().expect("temporary adapter ELF check");
    let object = embedded_object(directory.path());
    let symbols = nm_text_symbols(&object);
    for helper in ["object_fill_entry", "object_fill_return"] {
        let hits: Vec<&str> = symbols
            .lines()
            .filter(|line| line.contains(helper) && line.contains(" T "))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "expected one .text {helper}, saw {}: {hits:?}",
            hits.len()
        );
        println!("{}", hits[0]);
    }
    // Still no tail construction symbol and no monolithic drain.
    assert!(
        !symbols.contains("p11_object_return_remove"),
        "no monolithic native drain"
    );
}
