//! One attach plan over many modules: distinct slots per module, one slot for a
//! target two modules share, and a capacity ceiling that refuses whole modules.

use p11scope::discovery::identity::{PinnedObjectId, ReconciledModule};
use p11scope::plan::{AttachPlan, ModuleId, build_from_reconciled_modules};
use p11scope::process::{MountNamespaceId, ProcessViewId};
use p11scope::semantics::{ProcessKey, State};
use p11scope_ebpf_common::{Event, SESSION_NONE, event_type};
use p11scope_manifest::maps::{Device, ObjectKey};
use pkcs11_proxy_ng_types::CkRv;

fn key(inode: u64) -> ObjectKey {
    ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode,
    }
}

fn module(
    inode: u64,
    path: &str,
    entries: &[(&'static str, u64, u64)],
) -> p11scope::discovery::scan::ScannedModule {
    use p11scope::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    ScannedModule {
        view: ProcessViewId(inode as u32),
        mount_namespace: MountNamespaceId { device: 1, inode },
        key: key(inode),
        path: path.to_string(),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: entries
                .iter()
                .map(|&(name, object_inode, offset)| ScannedEntry {
                    name,
                    object: key(object_inode),
                    object_path: format!("/opt/obj{object_inode}.so"),
                    file_offset: offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x1000 + inode,
            file_offset: Some(0),
        }],
        interfaces: vec![],
    }
}

fn build_from_modules(modules: &[p11scope::discovery::scan::ScannedModule]) -> AttachPlan {
    let reconciled: Vec<_> = modules
        .iter()
        .cloned()
        .map(|scanned| ReconciledModule {
            object: PinnedObjectId(scanned.key.inode as u32),
            entry_objects: scanned
                .tables
                .iter()
                .map(|table| {
                    table
                        .entries
                        .iter()
                        .map(|entry| PinnedObjectId(entry.object.inode as u32))
                        .collect()
                })
                .collect(),
            scanned,
        })
        .collect();
    build_from_reconciled_modules(&reconciled)
}

/// These tests exercise module-scoped semantic state, not discovery trust.
/// Model the accepted-manifest authority their semantic inputs require.
fn build_authorized_from_modules(
    modules: &[p11scope::discovery::scan::ScannedModule],
) -> AttachPlan {
    let mut plan = build_from_modules(modules);
    for slot in &mut plan.slots {
        slot.semantic_authorized = true;
        let (descriptor_index, _) = p11scope::kinds::descriptor_index(&slot.names);
        slot.descriptor_index = descriptor_index;
        slot.semantics = p11scope::kinds::DESCRIPTORS[descriptor_index as usize];
    }
    plan
}

#[test]
fn equal_raw_keys_with_distinct_pinned_objects_never_share_slots() {
    let reconcile = |module, object, targets: Vec<u32>| ReconciledModule {
        scanned: module,
        object: PinnedObjectId(object),
        entry_objects: vec![targets.into_iter().map(PinnedObjectId).collect()],
    };
    let raw_key = 10;
    let plan = build_from_reconciled_modules(&[
        reconcile(
            module(
                raw_key,
                "/views/a/provider.so",
                &[("C_Sign", raw_key, 0x400)],
            ),
            1,
            vec![1],
        ),
        reconcile(
            module(
                raw_key,
                "/views/b/provider.so",
                &[("C_Sign", raw_key, 0x400)],
            ),
            2,
            vec![2],
        ),
    ]);

    assert_eq!(
        plan.modules.len(),
        2,
        "a raw ObjectKey is not physical identity"
    );
    assert_eq!(
        plan.slots.len(),
        2,
        "neither fd/offset may be borrowed by the other view"
    );
    assert_ne!(plan.slots[0].object, plan.slots[1].object);
}

#[test]
fn one_exact_pinned_object_keeps_every_views_nonempty_target_union() {
    let reconcile = |module, targets: Vec<u32>| ReconciledModule {
        scanned: module,
        object: PinnedObjectId(7),
        entry_objects: vec![targets.into_iter().map(PinnedObjectId).collect()],
    };
    let plan = build_from_reconciled_modules(&[
        reconcile(
            module(10, "/same/provider.so", &[("C_Initialize", 10, 0x100)]),
            vec![7],
        ),
        reconcile(
            module(10, "/same/provider.so", &[("C_Sign", 10, 0x200)]),
            vec![7],
        ),
    ]);

    assert_eq!(plan.modules.len(), 1, "exact identity is one module");
    assert_eq!(
        plan.slots.len(),
        2,
        "neither process view's target set is first-wins"
    );
    assert_eq!(
        plan.slots
            .iter()
            .flat_map(|slot| &slot.names)
            .collect::<Vec<_>>(),
        vec![&"C_Initialize".to_string(), &"C_Sign".to_string()]
    );
}

#[test]
fn two_modules_get_distinct_slots_and_distinct_module_ids() {
    let plan = build_from_modules(&[
        module(
            10,
            "/opt/proxy.so",
            &[("C_Initialize", 10, 0x100), ("C_Sign", 10, 0x200)],
        ),
        module(
            20,
            "/opt/backend.so",
            &[("C_Initialize", 20, 0x100), ("C_Sign", 20, 0x200)],
        ),
    ]);
    assert_eq!(plan.slots.len(), 4, "no target is shared here");
    assert_eq!(plan.modules.len(), 2);
    assert_eq!(plan.module_ambiguous, 0);
    let ids: Vec<ModuleId> = plan.slots.iter().map(|s| s.module_ids[0]).collect();
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(0)).count(), 2);
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(1)).count(), 2);
    // Slot indices are dense and unique across modules.
    let mut indices: Vec<u32> = plan.slots.iter().map(|s| s.index).collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}

#[test]
fn a_target_claimed_by_two_modules_is_attached_once_and_marked_ambiguous() {
    let plan = build_from_modules(&[
        module(10, "/opt/proxy.so", &[("C_Sign", 30, 0x400)]),
        module(20, "/opt/backend.so", &[("C_Sign", 30, 0x400)]),
    ]);
    assert_eq!(
        plan.slots.len(),
        1,
        "one {{object, offset}} ⇒ one slot, never two probes"
    );
    assert_eq!(plan.slots[0].module_ids, vec![ModuleId(0), ModuleId(1)]);
    assert_eq!(plan.module_ambiguous, 1);
    assert_eq!(
        plan.slots[0].semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
        "an ambiguous slot may not carry semantics"
    );
    assert!(plan.slots[0].semantic_ambiguous);
}

#[test]
fn a_target_three_modules_share_is_one_ambiguity_not_three() {
    let plan = build_from_modules(&[
        module(10, "/opt/a.so", &[("C_Sign", 30, 0x400)]),
        module(20, "/opt/b.so", &[("C_Sign", 30, 0x400)]),
        module(40, "/opt/c.so", &[("C_Sign", 30, 0x400)]),
    ]);
    assert_eq!(plan.slots.len(), 1);
    assert_eq!(
        plan.slots[0].module_ids,
        vec![ModuleId(0), ModuleId(1), ModuleId(2)]
    );
    assert_eq!(
        plan.module_ambiguous, 1,
        "one shared target, however many modules claim it"
    );
    assert_eq!(
        plan.module_of_slot(0),
        None,
        "no single module owns an ambiguous slot"
    );
}

#[test]
fn capacity_overflow_skips_whole_modules_and_says_which() {
    // 512 slots available; three modules of 200 unique targets each.
    let big = |inode: u64| {
        let entries: Vec<(&'static str, u64, u64)> = (0..200u64)
            .map(|i| ("C_Sign", inode, 0x1000 + i * 0x10))
            .collect();
        module(inode, "/opt/big.so", &entries)
    };
    let plan = build_from_modules(&[big(1), big(2), big(3)]);
    assert!(plan.slots.len() <= 512, "never exceed MAX_SLOTS");
    assert_eq!(plan.modules.len(), 2, "two modules fit");
    assert_eq!(plan.modules_skipped.len(), 1);
    assert!(
        plan.modules_skipped[0].reason.contains("512"),
        "the ceiling must be named: {:?}",
        plan.modules_skipped[0]
    );
}

#[test]
fn an_oversized_module_does_not_refuse_a_later_module_that_fits() {
    let oversized_entries: Vec<(&'static str, u64, u64)> = (0..513u64)
        .map(|i| ("C_Sign", 1, 0x1000 + i * 0x10))
        .collect();
    let plan = build_from_modules(&[
        module(1, "/opt/oversized.so", &oversized_entries),
        module(
            2,
            "/opt/small.so",
            &[("C_Initialize", 2, 0x100), ("C_Sign", 2, 0x200)],
        ),
    ]);

    assert_eq!(
        plan.slots.len(),
        2,
        "the later module fits and must attach whole"
    );
    assert!(
        plan.slots
            .iter()
            .all(|slot| slot.object == PinnedObjectId(2))
    );
    assert_eq!(plan.modules.len(), 1);
    assert_eq!(plan.modules[0].path, "/opt/small.so");
    assert!(plan.slots.len() <= p11scope_ebpf_common::MAX_SLOTS as usize);
    assert_eq!(
        plan.modules_skipped.len(),
        1,
        "only the oversized module is refused"
    );
    assert_eq!(plan.modules_skipped[0].subject, "/opt/oversized.so");
    let reason = &plan.modules_skipped[0].reason;
    assert!(reason.contains("module needs 513 more"), "{reason}");
    assert!(reason.contains("0 are in use"), "{reason}");
    assert!(reason.contains("512 attach slots"), "{reason}");
}

// Session-scoped semantic state is keyed by the module that issued the handle:
// a proxy and the backend it loads live in one process and each hand out their
// own handle space, so handle 5 from one is not handle 5 from the other.

fn slot_of(plan: &p11scope::plan::AttachPlan, inode: u64, name: &str) -> u32 {
    plan.slots
        .iter()
        .find(|s| s.object == PinnedObjectId(inode as u32) && s.names == [name])
        .unwrap()
        .index
}

/// A completed `C_OpenSession`/`C_CloseSession` call on `slot` carrying the
/// session handle the module issued.
fn session_event(slot: u32, handle: u64) -> Event {
    Event {
        slot,
        session: handle,
        pid_tgid: 4242 << 32,
        rv: 0,
        event_type: event_type::CALL,
        ..Event::default()
    }
}

#[test]
fn equal_session_handles_from_two_modules_do_not_interact() {
    let plan = build_authorized_from_modules(&[
        module(
            10,
            "/opt/proxy.so",
            &[("C_OpenSession", 10, 0x100), ("C_CloseSession", 10, 0x108)],
        ),
        module(
            20,
            "/opt/backend.so",
            &[("C_OpenSession", 20, 0x100), ("C_CloseSession", 20, 0x108)],
        ),
    ]);
    let proxy_open = slot_of(&plan, 10, "C_OpenSession");
    let backend_open = slot_of(&plan, 20, "C_OpenSession");
    let proxy_close = slot_of(&plan, 10, "C_CloseSession");

    let mut state = State::new(&plan);
    let process = ProcessKey::from_pid(4242);
    // The same numeric handle 5 opened through both modules.
    state.observe_process(process, &session_event(proxy_open, 5));
    state.observe_process(process, &session_event(backend_open, 5));
    assert_eq!(state.sessions().opened, 2, "two distinct sessions, not one");
    assert_eq!(
        state.sessions().peak_concurrent,
        2,
        "both handle-5 sessions are open at once"
    );
    assert_eq!(
        state.semantic_evidence().state_reconciliations,
        0,
        "the backend's open is not a re-open of the proxy's handle 5"
    );
    let proxy_pseudonym = state.session_pseudonym_process(process, proxy_open, 5);
    let backend_pseudonym = state.session_pseudonym_process(process, backend_open, 5);
    assert!(proxy_pseudonym.is_some() && backend_pseudonym.is_some());
    assert_ne!(
        proxy_pseudonym, backend_pseudonym,
        "the two handle-5 sessions must render as different pseudonyms"
    );

    // Closing the proxy's 5 must leave the backend's 5 open.
    state.observe_process(process, &session_event(proxy_close, 5));
    assert_eq!(state.sessions().closed, 1);
    assert_eq!(
        state.unmatched_closes(),
        0,
        "the close matched the proxy's session"
    );
    assert!(
        state.has_process_state(process),
        "the backend's session is still open, so the process still has state"
    );
    assert_eq!(
        state.session_pseudonym_process(process, proxy_open, 5),
        None,
        "the proxy's handle 5 is retired"
    );
    assert_eq!(
        state.session_pseudonym_process(process, backend_open, 5),
        backend_pseudonym,
        "the backend's handle 5 is untouched"
    );

    // Retiring the process still sweeps every module's state, not just one.
    state.retire_process(process);
    assert!(!state.has_process_state(process));
}

#[test]
fn one_modules_finalize_does_not_retire_another_modules_state() {
    let plan = build_authorized_from_modules(&[
        module(
            10,
            "/opt/proxy.so",
            &[("C_OpenSession", 10, 0x100), ("C_Finalize", 10, 0x110)],
        ),
        module(
            20,
            "/opt/backend.so",
            &[("C_OpenSession", 20, 0x100), ("C_CloseSession", 20, 0x108)],
        ),
    ]);
    let proxy_open = slot_of(&plan, 10, "C_OpenSession");
    let proxy_finalize = slot_of(&plan, 10, "C_Finalize");
    let backend_open = slot_of(&plan, 20, "C_OpenSession");
    let backend_close = slot_of(&plan, 20, "C_CloseSession");

    let mut state = State::new(&plan);
    let process = ProcessKey::from_pid(4242);
    state.observe_process(process, &session_event(proxy_open, 5));
    state.observe_process(process, &session_event(backend_open, 5));

    // The proxy tears down its own Cryptoki; the backend's is untouched.
    state.observe_process(process, &session_event(proxy_finalize, SESSION_NONE));
    assert!(
        state.has_process_state(process),
        "the backend's session must survive the proxy's C_Finalize"
    );
    assert_eq!(
        state.sessions().closed,
        1,
        "only the proxy's session closed"
    );
    assert!(
        state
            .session_pseudonym_process(process, backend_open, 5)
            .is_some(),
        "the backend's handle 5 is still open"
    );
    assert_eq!(
        state.session_pseudonym_process(process, proxy_open, 5),
        None,
        "the proxy's handle 5 is gone"
    );

    // And the backend's own close still matches its own session.
    state.observe_process(process, &session_event(backend_close, 5));
    assert_eq!(state.sessions().closed, 2);
    assert_eq!(
        state.unmatched_closes(),
        0,
        "the backend's close matched a session we still knew about"
    );
    assert!(!state.has_process_state(process));
}

#[test]
fn a_second_finalize_reporting_not_initialized_stays_within_its_module() {
    // The standard idempotent teardown: C_Finalize, then C_Finalize again,
    // which the module answers CKR_CRYPTOKI_NOT_INITIALIZED. That answer is
    // about the module that gave it, never about the process.
    let plan = build_authorized_from_modules(&[
        module(
            10,
            "/opt/proxy.so",
            &[("C_OpenSession", 10, 0x100), ("C_Finalize", 10, 0x110)],
        ),
        module(
            20,
            "/opt/backend.so",
            &[("C_OpenSession", 20, 0x100), ("C_CloseSession", 20, 0x108)],
        ),
    ]);
    let proxy_open = slot_of(&plan, 10, "C_OpenSession");
    let proxy_finalize = slot_of(&plan, 10, "C_Finalize");
    let backend_open = slot_of(&plan, 20, "C_OpenSession");
    let backend_close = slot_of(&plan, 20, "C_CloseSession");

    let mut state = State::new(&plan);
    let process = ProcessKey::from_pid(4242);
    state.observe_process(process, &session_event(proxy_open, 5));
    state.observe_process(process, &session_event(backend_open, 5));
    state.observe_process(process, &session_event(proxy_finalize, SESSION_NONE));

    let mut again = session_event(proxy_finalize, SESSION_NONE);
    again.rv = CkRv::CRYPTOKI_NOT_INITIALIZED.0;
    state.observe_process(process, &again);
    assert!(
        state.has_process_state(process),
        "the backend's session must survive the proxy's second C_Finalize"
    );
    assert!(
        state
            .session_pseudonym_process(process, backend_open, 5)
            .is_some(),
        "the backend's handle 5 is still open"
    );
    assert_eq!(
        state.semantic_evidence().state_reconciliations,
        0,
        "the proxy had no state left to reconcile — counting one would be a false signal"
    );

    // The backend's own close still matches.
    state.observe_process(process, &session_event(backend_close, 5));
    assert_eq!(state.sessions().closed, 2);
    assert_eq!(state.unmatched_closes(), 0);
}
