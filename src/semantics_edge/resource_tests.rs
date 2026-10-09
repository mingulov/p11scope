//! SPDX-License-Identifier: GPL-3.0-or-later
//! Resource controls and an isolated host probe over the production reducer.
//! Allocation requests, glibc heap occupancy and process RSS are different
//! measurements. No result below declares an aggregate admission limit.

use super::*;
use std::mem::size_of;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn call(name: &str, session: u64) -> SemanticCall {
    SemanticCall {
        function: name.into(),
        session,
        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
        mechanism: 0x1087,
        ..SemanticCall::default()
    }
}

#[test]
fn native_semantic_resource_usage_counts_owned_live_and_history() {
    let mut edge = EdgeSemantics::default();
    assert_eq!(edge.resource_usage(), S1Occupancy::default());
    edge.observe(&call("C_OpenSession", 1));
    edge.observe(&call("C_SignInit", 1));
    edge.observe(&call("C_EncryptInit", 1));
    let pending = SemanticCall {
        rv: CkRv::PENDING.0,
        ..call("C_SignEncryptUpdate", 1)
    };
    edge.observe(&pending);
    edge.observe(&call("C_OpenSession", 2));
    edge.observe(&call("C_SignInit", 2));
    edge.observe(&SemanticCall {
        rv: CkRv::PENDING.0,
        ..call("C_Sign", 2)
    });
    edge.observe(&SemanticCall {
        target_function: crate::kinds::function_id("C_Sign").unwrap(),
        async_value: 91,
        ..call("C_AsyncGetID", 2)
    });
    let usage = edge.resource_usage();
    assert_eq!(usage.open_bindings, 2);
    assert_eq!(usage.active_machines, 3);
    assert_eq!((usage.pending_calls, usage.detached_calls), (1, 1));
    assert_eq!(usage.mechanisms, 1);
    assert_eq!(usage.operation_categories, 2);
    assert_eq!(usage.provenance_functions, 2);
    assert_eq!(usage.provenance_returns, 1);
    assert_eq!(
        usage.provenance_function_bytes,
        "C_SignInitC_EncryptInit".len()
    );
    assert_eq!(
        usage.async_function_bytes,
        "C_SignEncryptUpdateC_Sign".len()
    );
    assert_eq!(usage.origin_vectors, 2);
    assert_eq!(usage.origin_elements, 3);
    assert!(usage.origin_capacity_elements >= 3);
    assert!(usage.provenance_function_capacity_bytes >= usage.provenance_function_bytes);
    assert!(usage.async_function_capacity_bytes >= usage.async_function_bytes);
    // A read-only accounting pass neither allocates nor changes semantic facts.
    let (again, allocations, bytes) =
        crate::test_alloc::count_allocs_during(|| edge.resource_usage());
    assert_eq!(again, usage);
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!((edge.started(), edge.completed()), (3, 0));
}

#[test]
fn native_semantic_resource_usage_loss_releases_live_not_history() {
    let mut edge = EdgeSemantics::default();
    edge.observe(&call("C_OpenSession", 1));
    edge.observe(&call("C_SignInit", 1));
    edge.observe(&SemanticCall {
        rv: CkRv::PENDING.0,
        ..call("C_Sign", 1)
    });
    let before = edge.resource_usage();
    assert_eq!(
        (
            before.open_bindings,
            before.active_machines,
            before.pending_calls
        ),
        (1, 1, 1)
    );
    edge.invalidate();
    let after = edge.resource_usage();
    assert_eq!(
        (
            after.open_bindings,
            after.active_machines,
            after.pending_calls,
            after.detached_calls
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (
            after.origin_vectors,
            after.origin_elements,
            after.origin_capacity_elements
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            after.async_function_bytes,
            after.async_function_capacity_bytes
        ),
        (0, 0)
    );
    assert_eq!(after.mechanisms, 1);
    assert_eq!(after.provenance_functions, 1);
    assert_eq!(after.provenance_returns, 1);
    assert_eq!(
        after.provenance_function_capacity_bytes,
        before.provenance_function_capacity_bytes
    );
    assert_eq!(edge.unknown(), 1);
}

pub(crate) fn occupancy_json(usage: S1Occupancy) -> serde_json::Value {
    serde_json::json!({
        "open_bindings": usage.open_bindings,
        "active_machines": usage.active_machines,
        "pending_calls": usage.pending_calls,
        "detached_calls": usage.detached_calls,
        "mechanisms": usage.mechanisms,
        "operation_categories": usage.operation_categories,
        "provenance_functions": usage.provenance_functions,
        "provenance_function_bytes": usage.provenance_function_bytes,
        "provenance_function_capacity_bytes": usage.provenance_function_capacity_bytes,
        "provenance_returns": usage.provenance_returns,
        "async_function_bytes": usage.async_function_bytes,
        "async_function_capacity_bytes": usage.async_function_capacity_bytes,
        "origin_vectors": usage.origin_vectors,
        "origin_elements": usage.origin_elements,
        "origin_capacity_elements": usage.origin_capacity_elements,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct Memory {
    heap_used: usize,
    heap_free: usize,
    mmap_reserved: usize,
    peak_rss: u64,
}

impl Memory {
    pub(crate) fn read() -> Self {
        // SAFETY: mallinfo2 takes no pointers and returns a copied allocator
        // snapshot; getrusage writes only the initialized local output.
        let heap = unsafe { libc::mallinfo2() };
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
            0
        );
        let usage = unsafe { usage.assume_init() };
        Self {
            heap_used: heap.uordblks,
            heap_free: heap.fordblks,
            mmap_reserved: heap.hblkhd,
            peak_rss: u64::try_from(usage.ru_maxrss)
                .unwrap()
                .checked_mul(1024)
                .unwrap(),
        }
    }

    pub(crate) fn json(self) -> serde_json::Value {
        serde_json::json!({
            "glibc_heap_used_bytes": self.heap_used,
            "glibc_heap_free_bytes": self.heap_free,
            "glibc_mmap_reserved_bytes": self.mmap_reserved,
            "process_peak_rss_bytes": self.peak_rss,
        })
    }

    pub(crate) fn delta_json(self, before: Self) -> serde_json::Value {
        serde_json::json!({
            "glibc_heap_used_delta_bytes": self.heap_used as i128 - before.heap_used as i128,
            "glibc_mmap_reserved_delta_bytes": self.mmap_reserved as i128 - before.mmap_reserved as i128,
        })
    }
}

/// Report an actual allocator-request count and process snapshots around one
/// stage. Requests include temporary allocations and realloc destinations;
/// retained heap is the process-wide allocator snapshot, never their sum.
pub(crate) fn measure<T>(name: &str, run: impl FnOnce() -> T) -> (T, serde_json::Value) {
    let before = Memory::read();
    let (value, allocations, requested_bytes) = crate::test_alloc::count_allocs_during(run);
    let after = Memory::read();
    (
        value,
        serde_json::json!({
            "stage": name,
            "allocation_requests": allocations,
            "requested_allocation_bytes": requested_bytes,
            "before": before.json(),
            "after": after.json(),
            "delta": after.delta_json(before),
        }),
    )
}

struct OwnedProbeChild(Child);

impl Drop for OwnedProbeChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Each profile runs in a fresh copy of the test binary with a 40-second
/// deadline. File-backed output avoids a full-pipe wait; the owned child is
/// killed and reaped on every unsuccessful return/unwind.
pub(crate) fn run_child(test: &str, profile: &str) -> serde_json::Value {
    use std::io::{Read, Seek};
    let mut output = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env("P11SCOPE_S1_RESOURCE_PROFILE", profile)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let mut child = OwnedProbeChild(child);
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "resource child exceeded its deadline: {profile}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    output.rewind().unwrap();
    let mut text = String::new();
    output.read_to_string(&mut text).unwrap();
    assert!(status.success(), "resource child {profile} failed: {text}");
    assert!(
        text.contains("1 passed; 0 failed"),
        "child selector did not execute exactly one test: {text}"
    );
    let rows: Vec<_> = text
        .lines()
        .filter_map(|line| line.split_once("S1_RESOURCE_ROW ").map(|(_, row)| row))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "resource child must return exactly one measurement: {text}"
    );
    serde_json::from_str(rows[0]).unwrap()
}

fn functions() -> impl Iterator<Item = &'static str> {
    pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
        .map(|field| field.name)
}

fn initialize_all(edge: &mut EdgeSemantics, session: u64, mechanism: u64) {
    for name in functions()
        .filter(|name| crate::kinds::descriptor(name).unwrap().transition == transition::INITIALIZE)
    {
        edge.observe(&SemanticCall {
            mechanism,
            ..call(name, session)
        });
    }
}

fn fill_history(edge: &mut EdgeSemantics, count: usize) {
    for mechanism in 0..count as u64 {
        for name in functions() {
            let descriptor = crate::kinds::descriptor(name).unwrap();
            if descriptor.transition == transition::INITIALIZE || descriptor.direct != direct::NONE
            {
                edge.observe(&SemanticCall {
                    mechanism,
                    ..call(name, 1)
                });
            } else if descriptor.operations != 0 {
                initialize_all(edge, 1, mechanism);
                edge.observe(&call(name, 1));
            }
        }
        for code in 1..MAX_EDGE_PROVENANCE_RETURNS {
            // An error Update ends its originating machine. Establish a
            // fresh binding for every distinct retained error observation.
            edge.observe(&SemanticCall {
                mechanism,
                ..call("C_EncryptInit", 1)
            });
            edge.observe(&SemanticCall {
                rv: 0x8000_0000 + code as u64,
                ..call("C_EncryptUpdate", 1)
            });
        }
    }
    edge.invalidate();
}

fn fill_open(edge: &mut EdgeSemantics, count: usize) {
    for session in 1..=count as u64 {
        edge.observe(&call("C_OpenSession", session));
    }
}

fn fill_active(edge: &mut EdgeSemantics, count: usize) {
    for index in 0..count {
        edge.observe(&SemanticCall {
            capture: capture::MECHANISM_UNREADABLE | capture::OUTPUT_NON_NULL,
            ..call(
                if index % 2 == 0 {
                    "C_SignInit"
                } else {
                    "C_EncryptInit"
                },
                (index / 2 + 1) as u64,
            )
        });
    }
}

fn fill_async(edge: &mut EdgeSemantics, count: usize, detached: bool) {
    for session in 1..=count as u64 {
        edge.observe(&SemanticCall {
            rv: CkRv::PENDING.0,
            ..call("C_SignEncryptUpdate", session)
        });
        if detached {
            edge.observe(&SemanticCall {
                target_function: crate::kinds::function_id("C_SignEncryptUpdate").unwrap(),
                async_value: session,
                ..call("C_AsyncGetID", session)
            });
        }
    }
}

fn build_profile(profile: &str) -> Vec<EdgeSemantics> {
    let (kind, population) = profile.rsplit_once(':').unwrap();
    let population = population.parse::<usize>().unwrap();
    assert!(
        population <= 32,
        "the probe never materializes the full 4096-reducer product"
    );
    (0..population)
        .map(|_| {
            let mut edge = EdgeSemantics::default();
            match kind {
                "empty" => {}
                "sparse" => {
                    fill_open(&mut edge, 1);
                    fill_active(&mut edge, 2);
                    fill_async(&mut edge, 1, false);
                }
                "open" => fill_open(&mut edge, MAX_EDGE_SESSIONS),
                "active" => fill_active(&mut edge, MAX_EDGE_ACTIVE_OPS),
                "mechanisms" => {
                    for mechanism in 0..MAX_EDGE_MECHANISMS as u64 {
                        edge.observe(&SemanticCall {
                            mechanism,
                            ..call("C_GenerateKey", 1)
                        });
                    }
                }
                "history" => fill_history(&mut edge, MAX_EDGE_MECHANISMS),
                "pending" | "detached" => {
                    fill_open(&mut edge, MAX_EDGE_PENDING);
                    fill_active(&mut edge, MAX_EDGE_PENDING * 2);
                    fill_async(&mut edge, MAX_EDGE_PENDING, kind == "detached");
                }
                "mixed" | "loss" | "churn" => {
                    fill_history(&mut edge, MAX_EDGE_MECHANISMS);
                    fill_open(&mut edge, MAX_EDGE_SESSIONS);
                    fill_active(&mut edge, MAX_EDGE_ACTIVE_OPS);
                    fill_async(&mut edge, MAX_EDGE_PENDING, true);
                    if kind == "churn" {
                        // Churn replacements/evictions through real transitions;
                        // provenance survives while live allocations are reused.
                        for _ in 0..4 {
                            fill_async(&mut edge, MAX_EDGE_PENDING, false);
                            fill_active(&mut edge, MAX_EDGE_ACTIVE_OPS);
                        }
                    }
                    if kind == "loss" {
                        edge.invalidate();
                    }
                }
                _ => panic!("unknown bounded probe profile {kind}"),
            }
            edge
        })
        .collect()
}

#[test]
fn native_semantic_resource_probe_child() {
    let Ok(profile) = std::env::var("P11SCOPE_S1_RESOURCE_PROFILE") else {
        return;
    };
    let (edges, stage) = measure("build_reducers", || build_profile(&profile));
    let kind = profile.split(':').next().unwrap();
    for edge in &edges {
        let usage = edge.resource_usage();
        match kind {
            "open" => assert_eq!(usage.open_bindings, MAX_EDGE_SESSIONS),
            "active" => assert_eq!(usage.active_machines, MAX_EDGE_ACTIVE_OPS),
            "mechanisms" => assert_eq!(usage.mechanisms, MAX_EDGE_MECHANISMS),
            "history" => {
                assert_eq!(usage.mechanisms, MAX_EDGE_MECHANISMS);
                assert_eq!(
                    usage.provenance_returns,
                    MAX_EDGE_MECHANISMS * MAX_EDGE_PROVENANCE_RETURNS
                );
                assert_eq!(usage.active_machines, 0);
            }
            "pending" => assert_eq!(usage.pending_calls, MAX_EDGE_PENDING),
            "detached" => assert_eq!(usage.detached_calls, MAX_EDGE_PENDING),
            "mixed" => {
                assert_eq!(usage.open_bindings, MAX_EDGE_SESSIONS);
                assert_eq!(usage.active_machines, MAX_EDGE_ACTIVE_OPS);
                assert_eq!(usage.mechanisms, MAX_EDGE_MECHANISMS);
                assert_eq!(usage.detached_calls, MAX_EDGE_PENDING);
                assert_eq!(
                    usage.provenance_returns,
                    MAX_EDGE_MECHANISMS * MAX_EDGE_PROVENANCE_RETURNS
                );
            }
            "loss" => {
                assert_eq!(usage.active_machines, 0);
                assert_eq!(usage.mechanisms, MAX_EDGE_MECHANISMS);
            }
            "empty" => assert_eq!(usage, S1Occupancy::default()),
            _ => assert!(usage.active_machines > 0),
        }
    }
    let usage: Vec<_> = edges
        .iter()
        .map(|edge| occupancy_json(edge.resource_usage()))
        .collect();
    let retained = Memory::read();
    let row = serde_json::json!({
        "profile": profile, "reducers": edges.len(), "stage": stage, "occupancy": usage,
        "after_measurement": retained.json(),
        "actual_type_sizes": {
            "EdgeSemantics": size_of::<EdgeSemantics>(), "S1Occupancy": size_of::<S1Occupancy>(),
            "SemanticCall": size_of::<SemanticCall>(), "OpMachine": size_of::<OpMachine>(),
            "PendingCall": size_of::<PendingCall>(), "AsyncId": size_of::<AsyncId>(),
            "CallOrigin": size_of::<CallOrigin>(), "origin_element": size_of::<(u16, Option<u64>)>(),
            "EdgeMechStat": size_of::<EdgeMechStat>(),
        },
    });
    println!("\nS1_RESOURCE_ROW {row}");
    std::hint::black_box(edges);
}

#[test]
#[ignore = "explicit controller-granted host measurement; spawns bounded children"]
fn native_semantic_resource_probe() {
    for profile in [
        "empty:1",
        "empty:32",
        "sparse:32",
        "open:1",
        "active:1",
        "mechanisms:1",
        "history:1",
        "pending:1",
        "detached:1",
        "mixed:1",
        "mixed:8",
        "mixed:32",
        "loss:1",
        "churn:1",
    ] {
        let row = run_child(
            "semantics_edge::resource_tests::native_semantic_resource_probe_child",
            profile,
        );
        println!("S1_RESOURCE_RESULT {row}");
    }
}
