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
    for helper in [
        "fn object_fill_entry",
        "fn object_entry_derive",
        "fn object_entry_results",
        "fn object_entry_find",
        "fn object_fill_return",
    ] {
        assert!(source.contains(helper), "missing adapter helper {helper}");
        let marker = source.find(helper).expect("adapter helper");
        let window = &source[marker.saturating_sub(400)..marker];
        assert!(
            window.contains("#[inline(never)]"),
            "{helper} must be #[inline(never)]"
        );
    }

    // The two slice-D emission levels are outlined like the adapters:
    // one rounding quantum each, never inlined into the hot root frame.
    for helper in ["fn object_tail_fill", "fn object_emit_find"] {
        assert!(source.contains(helper), "missing emission helper {helper}");
        let marker = source.find(helper).expect("emission helper");
        let window = &source[marker.saturating_sub(400)..marker];
        assert!(
            window.contains("#[inline(never)]"),
            "{helper} must be #[inline(never)]"
        );
    }

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

    // Slice D lifts the gate on the return path only: entry fills
    // side storage and never constructs a tail.
    assert!(
        !entry.contains("ObjectCallWire")
            && !entry.contains("ObjectEventRecord")
            && !entry.contains("object_tail_fill")
            && !entry.contains("object_emit_find"),
        "entry must not construct an object tail"
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
    // Return (slice D): ready/agreement queries, then the complete
    // 608-byte reservation, then fill, tail and Find emission, then the
    // drain retire, then submit (discard plus fault on failure). The
    // reservation precedes every object read; the retire precedes the
    // submit. (Slice C retired before reading; slice D lifts the gate
    // and the side row must stay alive through emission.)
    let ready = returned
        .find("p11_object_side_get(&key, descriptor, 1)")
        .expect("return fill must query ready with required=1");
    let reserve = returned
        .find("reserve::<ObjectEventRecord>")
        .expect("emission must reserve the complete object record");
    let fill = returned
        .find("object_fill_return(")
        .expect("return must fill after reserving");
    let tail = returned
        .find("object_tail_fill(")
        .expect("return must fill the tail after filling results");
    let find = returned
        .find("object_emit_find(")
        .expect("return must emit the Find section after the tail");
    let drain = returned
        .rfind("owned_start_remove(&key, true)")
        .expect("emission arm retires");
    assert!(
        ready < reserve && reserve < fill && fill < tail && tail < find && find < drain,
        "return must query ready, reserve, fill, tail, find, then retire"
    );
    let submit = returned.find("entry.submit(0)").expect("emission submits");
    let discard = returned
        .find("entry.discard(0)")
        .expect("failed emission discards");
    assert!(
        drain < submit && drain < discard,
        "the drain retire must precede submit and discard"
    );
    // The drain still queries (required=0, all sane phases) and the
    // failed settle still faults; emission reads stay outlined.
    let query = returned
        .find("p11_object_side_get(&key, descriptor, 0)")
        .expect("drain must query the side row before retiring");
    assert!(
        query < reserve,
        "the agreement query must precede the object reservation"
    );
    let fault = returned
        .find("p11_object_fault()")
        .expect("failed settle must fault");
    let _ = fault;
    // Slice D emits behind the required-object marker: exactly the two
    // record forms are reserved.
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        2,
        "return reserves exactly the ordinary and the object record forms"
    );
}

#[test]
fn object_producer_adapters_helpers_in_elf() {
    let directory = tempfile::tempdir().expect("temporary adapter ELF check");
    let object = embedded_object(directory.path());
    let symbols = nm_text_symbols(&object);
    // Helpers are private like the marker/ABI levels, so their symbols are
    // local text (`t`), not global (`T`). Either proves the outline survived.
    for helper in [
        "object_fill_entry",
        "object_entry_derive",
        "object_entry_results",
        "object_entry_find",
        "object_fill_return",
    ] {
        let hits: Vec<&str> = symbols
            .lines()
            .filter(|line| line.contains(helper) && (line.contains(" T ") || line.contains(" t ")))
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
