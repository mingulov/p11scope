//! SPDX-License-Identifier: GPL-3.0-or-later
//! Gated native-closer controls for live batches and terminal accounting.

use super::*;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::time::Instant;

fn link(producer: ProducerProgram) -> (OwnedLink, ProducerProgram) {
    (
        OwnedLink::Multi(vec![File::open("/dev/null").unwrap().into()]),
        producer,
    )
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "gated cleanup did not reach its expected boundary"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn live_retirement_batch_returns_before_close_and_reuses_one_running_worker() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut worker = CleanupWorker::pre_start_with(
        Box::new(move |owned, _| {
            entered_tx.send(std::thread::current().id()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    let first = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_entry"))],
            DetachOrder,
        )
        .expect("prestarted worker accepts the first live batch");
    let first_thread = entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(first.status(), BatchStatus::Pending);
    assert!(
        !worker.handle.as_ref().unwrap().is_finished(),
        "live polling must not shut down or join the worker"
    );
    release_tx.send(()).unwrap();
    wait_for(|| first.status() == BatchStatus::Released);
    let second = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_return"))],
            DetachOrder,
        )
        .expect("same running worker accepts a later live batch");
    let second_thread = entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        first_thread, second_thread,
        "retirement uses exactly the prestarted thread"
    );
    release_tx.send(()).unwrap();
    wait_for(|| second.status() == BatchStatus::Released);
    let receipt = worker.join();
    assert!(receipt.completed);
    assert_eq!((receipt.released, receipt.total), (2, 2));
}

#[test]
fn live_retirement_final_inflight_close_has_zero_remaining_but_ticket_stays_pending() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut worker = CleanupWorker::pre_start_with(
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                entered_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| error.to_string())?;
            }
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    let ticket = worker
        .submit_live(
            vec![
                link(ProducerProgram::UProbe("p11_return")),
                link(ProducerProgram::UProbe("p11_entry")),
            ],
            DetachOrder,
        )
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(worker.progress().remaining, 0);
    assert_eq!(worker.progress().released, 1);
    assert_eq!(
        ticket.status(),
        BatchStatus::Pending,
        "attempting the final close does not settle it"
    );
    release_tx.send(()).unwrap();
    wait_for(|| ticket.status() == BatchStatus::Released);
    assert!(worker.join().completed);
}

#[test]
fn live_retirement_ticket_cannot_borrow_another_batch_success() {
    let mut worker = CleanupWorker::pre_start_with(
        Box::new(|owned, producer| {
            drop(owned);
            if producer == ProducerProgram::UProbe("p11_entry") {
                Err("actual closer failure".into())
            } else {
                Ok(())
            }
        }),
        Arc::new(|| Duration::ZERO),
    );
    let failed = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_entry"))],
            DetachOrder,
        )
        .unwrap();
    let released = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_return"))],
            DetachOrder,
        )
        .unwrap();
    wait_for(|| released.status() == BatchStatus::Released);
    assert_eq!(failed.status(), BatchStatus::Failed);
    let receipt = worker.join();
    assert!(!receipt.completed);
    assert_eq!(
        (receipt.released, receipt.total, receipt.uncertain),
        (1, 2, 1)
    );
}

#[test]
fn live_retirement_submission_failure_returns_still_owned_payload() {
    let mut worker = CleanupWorker::pre_start_with(
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    // Keep the actual worker channel alive, but close the receiver selected for
    // this submission. This exercises real SendError ownership, not counters.
    let (closed_tx, closed_rx) = mpsc::channel();
    drop(closed_rx);
    let original_tx = std::mem::replace(&mut worker.tx, closed_tx);
    let fd = File::open("/dev/null").unwrap();
    let raw_fd = fd.as_raw_fd();
    let failure = worker
        .submit_live(
            vec![(
                OwnedLink::Multi(vec![fd.into()]),
                ProducerProgram::UProbe("p11_entry"),
            )],
            DetachOrder,
        )
        .unwrap_err();
    assert_eq!(failure.links.len(), 1);
    // SAFETY: fcntl only inspects this test's still-owned descriptor.
    assert!(
        unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0,
        "failed submission must not close/drop the returned link"
    );
    worker.tx = original_tx;
    worker.retain_unsubmitted(failure);
    let receipt = worker.join();
    assert!(!receipt.completed);
    assert_eq!(
        (receipt.released, receipt.total, receipt.uncertain),
        (0, 1, 1)
    );
    drop(worker);
    // The actual failed-submission/destruction route deliberately leaves this
    // descriptor to process-exit cleanup; it cannot close on the foreground.
    // SAFETY: fcntl only inspects this test's explicitly abandoned descriptor.
    assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
    // SAFETY: the worker explicitly abandoned ownership and there is no Rust
    // owner left. Reclaim this test-only /dev/null fd without leaking the test.
    assert_eq!(unsafe { libc::close(raw_fd) }, 0);
}

#[test]
fn live_retirement_worker_start_failure_preserves_payload_and_refuses_readiness() {
    let mut worker = CleanupWorker::pre_start_with_spawn(
        Box::new(|owned, _| {
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
        |_| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
    );
    assert!(worker.live_admission().is_err());
    let failure = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_entry"))],
            DetachOrder,
        )
        .unwrap_err();
    assert_eq!(failure.links.len(), 1);
    drop(failure.links);
    assert!(!worker.join().completed);
}

#[test]
fn live_retirement_terminal_receipt_is_cumulative_and_excludes_capture_idle() {
    let now = Arc::new(Mutex::new(Duration::ZERO));
    let clock = Arc::clone(&now);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = CleanupWorker::pre_start_with(
        Box::new(move |owned, producer| {
            if producer == ProducerProgram::UProbe("p11_return") {
                entered_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|error| error.to_string())?;
            }
            drop(owned);
            Ok(())
        }),
        Arc::new(move || *clock.lock().unwrap()),
    );
    let live = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_entry"))],
            DetachOrder,
        )
        .unwrap();
    wait_for(|| live.status() == BatchStatus::Released);
    *now.lock().unwrap() = Duration::from_secs(60);
    worker.submit(
        vec![link(ProducerProgram::UProbe("p11_return"))],
        DetachOrder,
    );
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    *now.lock().unwrap() = Duration::from_secs(65);
    release_tx.send(()).unwrap();
    let mut out = Vec::new();
    let CleanupExit::Completed(receipt) =
        drive_cleanup(worker, || false, &mut out, Duration::from_millis(1))
    else {
        panic!("no second signal");
    };
    assert_eq!(
        (receipt.released, receipt.total, receipt.uncertain),
        (2, 2, 0)
    );
    assert_eq!(
        receipt.elapsed,
        Duration::from_secs(5),
        "terminal elapsed must not include capture idle after a live batch"
    );
}

#[test]
fn live_retirement_only_pending_batch_remains_second_signal_responsive_at_stop() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = CleanupWorker::pre_start_with(
        Box::new(move |owned, _| {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            drop(owned);
            Ok(())
        }),
        Arc::new(|| Duration::ZERO),
    );
    let ticket = worker
        .submit_live(
            vec![link(ProducerProgram::UProbe("p11_entry"))],
            DetachOrder,
        )
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let mut out = Vec::new();
    let exit = drive_cleanup(worker, || true, &mut out, Duration::from_millis(1));
    assert_eq!(settle_cleanup_exit(exit), Err(CleanupInterrupted));
    assert_eq!(ticket.status(), BatchStatus::Pending);
    release_tx.send(()).unwrap();
    wait_for(|| ticket.status() == BatchStatus::Released);
}
