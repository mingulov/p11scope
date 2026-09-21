//! SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit privileged checks over real maps and the production self-probe.
//!
//! Build with ordinary Cargo, then run the resulting test executable with
//! `events::runtime_tests:: --ignored --test-threads=1 --nocapture` under the
//! privileges needed to load BPF. Missing privileges or kernel prerequisites
//! are failures here, never successful skips. These checks do not activate a
//! capture Session or qualify original-root lifecycle ordering.

use super::*;

#[test]
#[ignore = "requires privileged BPF map creation on a supported kernel"]
fn real_retained_consumer_keeps_one_cursor_across_all_drains() {
    // The retained consumer over the actual object keeps one cursor
    // across an ordinary poll, a root-tail fence and the terminal poll,
    // refuses the foreign map with equal cursors, and retains the map
    // after every loader is gone. No producers are attached, so every
    // phase observes the empty ring at cursor zero.
    let load = || {
        aya::EbpfLoader::new()
            .allow_unsupported_maps()
            .load(crate::EBPF_OBJECT)
            .expect("load actual embedded object with required task-storage maps")
    };
    let first = load();
    let second = load();
    let first_domain = EventsDomain::from_events(&first).expect("first actual EVENTS domain");
    let second_domain = EventsDomain::from_events(&second).expect("second actual EVENTS domain");
    assert_ne!(first_domain.id(), second_domain.id());

    let mut consumer =
        OwnedDrain::for_session(&first, &first_domain).expect("retained consumer over same map");
    assert_eq!(consumer.domain_id(), first_domain.id());
    // A separate load of the same object starts from identical cursors
    // on its own ring; comparing across loads pins that down.
    let second_positions = OwnedDrain::for_session(&second, &second_domain)
        .expect("second retained consumer")
        .source()
        .snapshot_positions();
    assert_eq!(second_positions, consumer.source().snapshot_positions());
    let backlog = consumer.poll(poll_quantum(false), |_| std::ops::ControlFlow::Continue(()));
    assert!(!backlog, "empty ring reads empty on the ordinary poll");
    assert_eq!(consumer.take_malformed_delta(), 0);
    let ordinary = consumer.source().snapshot_positions();

    let mut tail = OwnedRootTail::new(
        crate::run::OriginalRootExit::test_reaped(first_domain.clone()),
        std::time::Instant::now() + ROOT_TAIL_FENCE_TIMEOUT,
    );
    consumer.begin_root_tail(&mut tail).expect("tail snapshot");
    assert_eq!(
        consumer
            .poll_root_tail(&mut tail, LIVE_POLL_QUANTUM, |_| Ok(()))
            .unwrap(),
        RootTailProgress::Reached
    );
    tail.complete().expect("empty tail completes");

    let backlog = consumer.poll(poll_quantum(true), |_| std::ops::ControlFlow::Continue(()));
    assert!(!backlog, "empty ring reads empty on the terminal poll");
    let terminal = consumer.source().snapshot_positions();
    assert_eq!((ordinary.consumer, ordinary.producer), (0, 0));
    assert_eq!(terminal, ordinary);
    assert!(ordinary.capacity > 0);

    match OwnedDrain::for_session(&second, &first_domain) {
        Ok(_) => panic!("foreign EVENTS map accepted with equal cursors"),
        Err(error) => assert_eq!(
            error.to_string(),
            "EVENTS map does not match retained domain"
        ),
    }

    drop(first);
    drop(second);
    drop(second_domain);
    drop(consumer);
    // Inspect a duplicate of the actually retained descriptor after both
    // loaders and the retained consumer are gone. No map-ID reopen
    // supplies lifetime authority, and no synthetic domain or caller-set
    // ID is used.
    let retained = MapData::from_fd(first_domain.0._fd.try_clone().unwrap())
        .expect("retained descriptor still identifies a live BPF map");
    assert_eq!(u64::from(retained.info().unwrap().id()), first_domain.id());
    assert_eq!(retained.info().unwrap().name(), b"EVENTS");
    println!(
        "actual EVENTS domain {} retained; one cursor {ordinary:?} across ordinary/tail/terminal; distinct equal-cursor map refused",
        first_domain.id()
    );
}

#[test]
#[ignore = "loads p11_return and probes a fresh owned seccomp-confined child"]
fn real_uretprobe_hazard_self_probe_reaches_a_verdict() {
    let verdict = crate::uretprobe_hazard::probe_kernel();
    println!("actual uretprobe self-probe: {verdict:?}");
    assert!(
        matches!(
            verdict,
            crate::uretprobe_hazard::KernelVerdict::Clean
                | crate::uretprobe_hazard::KernelVerdict::Affected(_)
        ),
        "self-probe did not reach a measured verdict: {verdict:?}"
    );
}
