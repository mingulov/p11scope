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
fn real_events_domains_reject_foreign_maps_and_retain_original_map() {
    let load = || {
        aya::EbpfLoader::new()
            .allow_unsupported_maps()
            .load(crate::EBPF_OBJECT)
            .expect("load actual embedded object with required task-storage maps")
    };
    let mut first = load();
    let mut second = load();
    let first_domain = EventsDomain::from_events(&first).expect("first actual EVENTS domain");
    let second_domain = EventsDomain::from_events(&second).expect("second actual EVENTS domain");
    assert_ne!(first_domain.id(), second_domain.id());

    let positions = |object: &mut Ebpf, domain: EventsDomain| {
        let mut drain = Drain::new(object, domain).expect("same-map drain");
        let positions = drain.source.snapshot_positions();
        assert!(matches!(
            drain.source.next_before(positions.producer).unwrap(),
            aya::maps::ring_buf::BoundedRingBufRead::Reached
        ));
        (positions.consumer, positions.producer, positions.capacity)
    };
    let first_positions = positions(&mut first, first_domain.clone());
    let second_positions = positions(&mut second, second_domain.clone());
    assert_eq!(first_positions, second_positions);
    assert_eq!(first_positions.0, 0);
    assert_eq!(first_positions.1, 0);
    assert!(first_positions.2 > 0);
    assert_eq!(positions(&mut first, first_domain.clone()), first_positions);

    match Drain::new(&mut second, first_domain.clone()) {
        Ok(_) => panic!("foreign EVENTS map accepted with equal cursors"),
        Err(error) => assert_eq!(
            error.to_string(),
            "EVENTS map does not match retained domain"
        ),
    }

    drop(first);
    drop(second);
    drop(second_domain);
    // Inspect a duplicate of the actually retained descriptor after both
    // loaders and every temporary drain are gone. No map-ID reopen supplies
    // lifetime authority, and no synthetic domain or caller-set ID is used.
    let retained = MapData::from_fd(first_domain.0._fd.try_clone().unwrap())
        .expect("retained descriptor still identifies a live BPF map");
    assert_eq!(u64::from(retained.info().unwrap().id()), first_domain.id());
    assert_eq!(retained.info().unwrap().name(), b"EVENTS");
    println!(
        "actual EVENTS domain {} retained; distinct equal-cursor map refused; positions {first_positions:?}",
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
