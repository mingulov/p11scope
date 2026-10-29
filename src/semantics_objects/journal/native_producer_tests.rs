//! P1 native BEGIN against the real shared return writers and P0a predicate.
//! Root wires this private child after the concurrent parent writer closes.

use super::end_agrees_with_begin;
use p11scope_ebpf_common::object_capture::handle_status;
use p11scope_ebpf_common::object_flow::{ReturnEventFacts, adapter_tail_fill, fill_call_event};
use p11scope_ebpf_common::object_journal::{
    JOURNAL_END_FULL_BYTES, JOURNAL_END_TAIL_ABSENT, JOURNAL_KIND_END, JOURNAL_VERSION,
    JournalRecord, decode_journal_record,
};
use p11scope_ebpf_common::object_wire::{ObjectCallWire, ObjectStart, publish_object_descriptors};
use p11scope_ebpf_common::{ARG_NONE, CallStart, EventRecord, InstanceEntry, StartKey, capture};
use std::path::Path;
use std::process::Command;

// SAFETY: callers select only the integer-only repr(C) shared wire/row types
// named below, all of whose bit patterns are valid; exact sizes are checked.
unsafe fn native_row<T: Copy>(path: &Path) -> T {
    let bytes = std::fs::read(path).expect("read actual native row snapshot");
    assert_eq!(bytes.len(), std::mem::size_of::<T>(), "{}", path.display());
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // The call sites use initialized, padding-free EventRecord/ObjectCallWire.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

#[test]
fn native_producer_begin_agrees_with_actual_return_constructor() {
    let temporary = tempfile::tempdir().expect("private native producer agreement");
    let binary = temporary.path().join("native-producer");
    let mut compiler = Command::new("clang-18");
    compiler
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-DP11SCOPE_OBJECT_JOURNAL",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/object-journal/journal_owner_tests.c",
            "-o",
        ])
        .arg(&binary);
    if cfg!(feature = "stub-object-attributes") {
        compiler.arg("-DP11_JOURNAL_FIXTURE_UNINSPECTED");
    }
    let output = compiler.output().expect("compile actual native producer");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dump = temporary.path().join("rows");
    std::fs::create_dir(&dump).unwrap();
    let output = Command::new(binary)
        .arg("producer-pairs")
        .env("P11_JOURNAL_PRODUCER_SNAPSHOT_DIR", &dump)
        .output()
        .expect("snapshot native inputs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let descriptors = publish_object_descriptors();
    for (name, function_name) in [
        ("object", "C_CreateObject"),
        ("neutral", "C_GetOperationState"),
        ("open-session", "C_OpenSession"),
        ("mechanism", "C_EncryptInit"),
        ("zero-session", "C_GetOperationState"),
        ("sentinel", "C_GetOperationState"),
    ] {
        let path = |extension: &str| dump.join(format!("{name}.{extension}"));
        // These are the actual rows captured BEFORE the C BEGIN function ran,
        // independent of the emitted BEGIN bytes whose agreement is tested.
        let start: CallStart = unsafe { native_row(&path("start")) };
        let key: StartKey = unsafe { native_row(&path("key")) };
        let instance: InstanceEntry = unsafe { native_row(&path("instance")) };
        let context: [u32; 4] = unsafe { native_row(&path("context")) };
        let returning: [u64; 3] = unsafe { native_row(&path("return")) };
        assert_eq!(
            returning,
            [1, 1, 0],
            "all actual native return words: {name}"
        );
        let function = crate::kinds::function_id(function_name).unwrap();
        assert_eq!(
            context,
            [function + 1, 1, 1, 0],
            "frozen native context {name}"
        );
        let mut facts = ReturnEventFacts {
            ts_ns: start.ts_ns + 100,
            duration_ns: 100,
            rv: 0,
            mechanism: start.mechanism,
            session: start.session,
            async_value: 0,
            capture_flags: start.capture,
            pid_tgid: key.pid_tgid,
            cgroup_id: 1,
            root_affiliation: 1,
        };
        if name == "open-session" {
            assert_ne!(start.out_ptr, 0);
            facts.session = 0x9090;
        }
        if name == "mechanism" {
            assert_ne!(start.mechanism_ptr, 0);
            facts.mechanism = 0x250;
            facts.capture_flags =
                (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
        }
        let mut base = EventRecord::default();
        // SAFETY: exclusively owned, aligned output and independent native
        // snapshot. This is the production shared S1 return constructor.
        unsafe { fill_call_event(&mut base.event, &start, key.slot, &facts) };
        base.continuity.entry_ip = instance.entry_ip;
        base.continuity.entry_stamp = instance.entry_stamp;
        base.continuity.return_stamp = instance.entry_stamp;
        let mut end = [0u8; JOURNAL_END_FULL_BYTES];
        end[..2].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
        end[2..4].copy_from_slice(&(JOURNAL_END_FULL_BYTES as u16).to_le_bytes());
        end[4] = JOURNAL_KIND_END;
        // Invocation words are the output of the native returning function
        // for this fixture's first physical thread and first call.
        end[8..16].copy_from_slice(&returning[0].to_le_bytes());
        end[16..24].copy_from_slice(&returning[1].to_le_bytes());
        end[24..392].copy_from_slice(bytes_of(&base));
        if path("object").exists() {
            let mut side: ObjectStart = unsafe { native_row(&path("object")) };
            side.phase = 3;
            for (index, argument) in descriptors[(function + 1) as usize]
                .result_args
                .iter()
                .enumerate()
            {
                if *argument != ARG_NONE {
                    side.result_ptrs[index] = 0x9090;
                    side.result_statuses[index] = handle_status::VALUE;
                }
            }
            let mut tail = ObjectCallWire::default();
            // Actual production tail writer, using the native OBJECT_START
            // snapshot and explicitly captured scalar return results.
            assert!(unsafe {
                adapter_tail_fill(
                    &mut tail,
                    Some(&side),
                    context[0],
                    Some(&descriptors[context[0] as usize]),
                )
            });
            end[392..].copy_from_slice(bytes_of(&tail));
        } else {
            end[5] = JOURNAL_END_TAIL_ABSENT;
        }
        let begin_bytes = std::fs::read(path("begin")).unwrap();
        let JournalRecord::Begin(begin) = decode_journal_record(&begin_bytes, &descriptors)
            .unwrap_or_else(|| panic!("native BEGIN validates: {name}"))
        else {
            panic!("BEGIN kind")
        };
        let JournalRecord::End(decoded) = decode_journal_record(&end, &descriptors)
            .unwrap_or_else(|| panic!("actual return END validates: {name}"))
        else {
            panic!("END kind")
        };
        assert!(
            end_agrees_with_begin(&begin, &decoded),
            "real native/shared-writer agreement: {name}"
        );
        let mut poison = end;
        poison[24 + 16] ^= 1;
        let Some(JournalRecord::End(poison)) = decode_journal_record(&poison, &descriptors) else {
            panic!("shaped poison")
        };
        assert!(
            !end_agrees_with_begin(&begin, &poison),
            "wrong carrier refuses: {name}"
        );
    }
}
