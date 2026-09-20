//! SPDX-License-Identifier: GPL-3.0-or-later
//! Compile-only by default. Execution needs separately reviewed runtime custody.
//! Regresses premature retirement on reap/first dequeue: pending state must
//! survive both reductions and token construction until explicit retirement.

use super::*;
use crate::events::{OwnedRootTail, RootTailProgress};
use anyhow::ensure;
use p11scope_ebpf_common::{Event, SESSION_NONE, capture, event_type};
use std::io::Read;
use std::net::Shutdown;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};

const TIMEOUT: Duration = Duration::from_secs(10);
const PENDING: u64 = pkcs11_types::CkRv::PENDING.0;

/// Socket readiness is protocol coordination only, never process-exit proof.
fn ready(fd: i32, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .context("native protocol deadline")?;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one initialized descriptor is valid for this bounded poll.
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        ensure!(result > 0, "native protocol deadline");
        ensure!(
            descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "native protocol descriptor failure: {}",
            descriptor.revents
        );
        if descriptor.revents & (events | libc::POLLHUP) != 0 {
            return Ok(());
        }
    }
}

fn receive(stream: &mut UnixStream, expected: &[u8], deadline: Instant) -> Result<()> {
    for wanted in expected {
        loop {
            ready(stream.as_raw_fd(), libc::POLLIN, deadline)?;
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(1) => {
                    ensure!(byte[0] == *wanted, "unexpected native protocol byte");
                    break;
                }
                Ok(_) => anyhow::bail!("unexpected native protocol EOF"),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn send_go(stream: &mut UnixStream, deadline: Instant) -> Result<()> {
    let mut bytes = b"GO\n".as_slice();
    while !bytes.is_empty() {
        ready(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => anyhow::bail!("native protocol write returned zero"),
            Ok(n) => bytes = &bytes[n..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

fn accept_owned(listener: &UnixListener, child: &OwnedChild) -> Result<UnixStream> {
    let deadline = Instant::now() + TIMEOUT;
    let stream = loop {
        ready(listener.as_raw_fd(), libc::POLLIN, deadline)?;
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    };
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: output pointer and size describe one live ucred value.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let identity = ChildIdentity::for_invoker()?;
    ensure!(
        size as usize == std::mem::size_of_val(&credentials)
            && credentials.pid > 0
            && credentials.pid as u32 == child.pid()
            && credentials.uid == identity.uid
            && credentials.gid == identity.gid,
        "control peer is not the exact owned child"
    );
    stream.set_nonblocking(true)?;
    Ok(stream)
}

fn sessions(state: &semantics::State, opened: u64, closed: u64, pending: u64) -> Result<()> {
    let actual = state.sessions();
    ensure!(
        actual.opened == opened && actual.closed == closed && state.pending_at_end() == pending,
        "unexpected session/pending state: {actual:?}; pending={}",
        state.pending_at_end()
    );
    Ok(())
}

fn check_call(event: &Event, pid: u32, slot: u32, rv: u64) -> Result<()> {
    ensure!(
        event.event_type == event_type::CALL
            && event.slot == slot
            && event.pid_tgid >> 32 == u64::from(pid)
            && event.pid_tgid as u32 == pid
            && event.root_affiliation == 1
            && event.image.task_cookie != 0
            && event.session != SESSION_NONE
            && event.capture & capture::ARG_READ_FAILURE == 0
            && event.rv == rv,
        "unexpected call, identity, session validity, or return value"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn document(
    engine: &Engine,
    session: &Session,
    scope: &Scope,
    state: &semantics::State,
    tracker: &process::Tracker,
    malformed: u64,
    started: SystemTime,
    label: &str,
) -> Result<String> {
    let reports = metrics::read(session, engine.plan())?;
    let kernel = metrics::kernel_evidence(session)?;
    ensure!(
        reports.iter().map(|report| report.calls).sum::<u64>() == 2,
        "aggregate completed-call count is not two"
    );
    for (name, rv) in [
        ("C_OpenSession", 0),
        ("C_FindObjectsInit", PENDING),
        ("C_GetFunctionList", 0),
    ] {
        let report = reports
            .iter()
            .find(|report| report.names == [name])
            .context("missing aggregate slot")?;
        let calls = u64::from(name != "C_GetFunctionList");
        ensure!(
            report.calls == calls
                && report.in_flight == 0
                && report.rv_counts.len() == calls as usize
                && (calls == 0 || report.rv_counts.get(&rv) == Some(&1)),
            "unexpected aggregate count or return-code row for {name}"
        );
    }
    ensure!(
        kernel == metrics::KernelEvidence::default() && metrics::lost_events(session)? == 0,
        "kernel capture gap: {kernel:?}"
    );
    ensure!(
        engine
            .pinned()
            .check_unchanged()
            .map_err(anyhow::Error::msg)?,
        "provider changed"
    );
    let mut evidence = evidence_for(
        engine,
        engine.capture_facts(),
        session.attached_probes(),
        session.dynamic_per_offset_attached(),
        session.attach_failures(),
        &reports,
        kernel,
        tracker.evidence(),
        malformed,
        state,
        engine.pinned().provider_changed(),
        true,
        Default::default(),
        None,
        initial_tracking_evidence(
            scope,
            session.process_creation_tracking_unavailable().is_some(),
            session.lifecycle_tracking_unavailable().is_some(),
        ),
        render::SchedulingEvidence::default(),
    );
    evidence.mark_terminal_drain_unproven();
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let output = render::profile_json(
        &reports,
        &evidence,
        state,
        &render::CaptureMeta {
            started: &fmt_rfc3339(started),
            ended: &fmt_rfc3339(SystemTime::now()),
            kernel: kernel_release.trim(),
            policy: session.capture_policy(),
            scope: scope.kind(),
            ring_bytes: resolve_ring_bytes(None),
            drain_interval_ms: PROFILE_CADENCE.as_millis() as u64,
        },
    );
    let actual = state.sessions();
    ensure!(
        output["sessions"]["opened"] == actual.opened
            && output["sessions"]["closed"] == actual.closed
            && output["sessions"]["async_opened"] == actual.async_opened
            && output["sessions"]["inherited"] == actual.inherited
            && output["sessions"]["peak_concurrent"] == actual.peak_concurrent
            && output["sessions"]["balance"] == actual.opened + actual.inherited - actual.closed
            && output["evidence"]["pending_at_end"] == state.pending_at_end(),
        "production rendered session/pending values disagree"
    );
    ensure!(
        output["evidence"]["completeness"] == "PARTIAL",
        "static fixture must retain partial evidence"
    );
    writeln!(io::stdout(), "root-runtime {label} {output}")?;
    Ok(trace::evidence_line(
        &evidence,
        session.capture_policy(),
        false,
    ))
}

fn scenario(
    stage: &Path,
    socket: &Path,
    listener: &UnixListener,
    kind: Kind,
    owner: &mut Option<OwnedChild>,
    active: &mut Option<Session>,
) -> Result<()> {
    let started = SystemTime::now();
    *owner = Some(OwnedChild::spawn(
        stage.join("driver").into_os_string(),
        vec![
            stage.join("provider.so").into_os_string(),
            socket.as_os_str().into(),
        ],
    )?);
    let child = owner.as_mut().context("owned child")?;
    let pid = child.pid();
    let original_pin = child.seed_pin();
    child.release_until(Instant::now() + TIMEOUT, || None)?;
    let mut stream = accept_owned(listener, child)?;
    receive(&mut stream, b"READY\n", Instant::now() + TIMEOUT)?;
    let scope = Scope::Pid(pid);
    let args = CaptureArgs {
        kind,
        modules: vec![stage.join("provider.so")],
        manifests: vec![stage.join("provider.json")],
        hooks: crate::discovery::hooks::HookRegistry::builtin(),
        scope: ScopeArg::Pid(pid),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    };
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(anyhow::Error::msg)?;
    let engine = Engine::discover(&args, &scope, Some(view))?;
    let plan = engine.plan();
    ensure!(
        plan.slots.len() == 3,
        "unexpected native plan: {:?}",
        plan.slots
    );
    let slot_index = |name: &str| -> Result<u32> {
        let slot = plan
            .slots
            .iter()
            .find(|slot| slot.names == [name])
            .with_context(|| format!("missing native slot {name}"))?;
        ensure!(
            !slot.aliased
                && slot.semantic_authorized
                && !slot.semantic_ambiguous
                && slot.module_ids.len() == 1,
            "slot lacks unique semantic authority: {name}"
        );
        Ok(slot.index)
    };
    let open_slot = slot_index("C_OpenSession")?;
    let find_slot = slot_index("C_FindObjectsInit")?;
    slot_index("C_GetFunctionList")?;
    ensure!(
        plan.slots
            .iter()
            .map(|slot| (slot.object, slot.file_offset))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 3,
        "aliased native targets"
    );
    writeln!(
        io::stdout(),
        "root-runtime {kind:?} selected slots={:?}; skipped={:?}",
        plan.slots,
        plan.skipped
    )?;

    *active = Some(Session::start(
        plan,
        &scope,
        engine.pinned(),
        CapturePolicy::Allowlisted,
        None,
        None,
        owner.as_ref(),
        BackendSelection::Auto,
    )?);
    let session = active.as_mut().context("capture session")?;
    ensure!(
        session.attach_failures().is_empty() && session.attached_probes() == 6,
        "native slot attachment incomplete: {:?}",
        session.attach_failures()
    );
    ensure!(
        Arc::ptr_eq(&original_pin, &owner.as_ref().context("owner")?.seed_pin()),
        "original owner pin changed"
    );
    let mut seed = session.take_root_seed();
    ensure!(seed.is_some(), "session did not acknowledge original root");
    let domain = session.events_domain();
    let mut state = semantics::State::for_capture(plan, session.capture_policy(), domain.clone());
    let mut tracker = process::Tracker::for_producer(domain.clone(), 16_384);
    let mut tracer = trace::Tracer::new(plan);
    let mut trace_bytes = Vec::new();
    let mut remaining = None;
    let mut stdout_open = true;
    let mut out_file: Option<Vec<u8>> = None;
    let mut write_error = None;
    ensure!(
        owner.as_mut().context("owner")?.try_reap()?.is_none(),
        "live original unexpectedly reaped"
    );
    ensure!(
        OriginalRootExit::take(owner, &mut seed)?.is_none() && owner.is_some() && seed.is_some(),
        "live original produced retirement authority"
    );
    send_go(&mut stream, Instant::now() + TIMEOUT)?;
    receive(&mut stream, b"DONE 2 0 516\n", Instant::now() + TIMEOUT)?;
    ensure!(
        owner
            .as_mut()
            .context("owner")?
            .wait_for(Some(TIMEOUT), false)?
            == ChildOutcome::Exited(0),
        "original child did not genuinely exit zero"
    );
    writeln!(io::stdout(), "root-runtime {kind:?} genuine-reap")?;
    ready(stream.as_raw_fd(), libc::POLLIN, Instant::now() + TIMEOUT)?;
    ensure!(stream.read(&mut [0])? == 0, "unexpected DONE protocol tail");
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        _ => anyhow::bail!("unexpected second control peer"),
    }
    sessions(&state, 0, 0, 0)?;
    ensure!(
        !state.pid_has_process_state(pid),
        "state existed before dequeue"
    );
    let exit = OriginalRootExit::take(owner, &mut seed)?.context("genuine original exit")?;
    ensure!(
        owner.is_none() && seed.is_none(),
        "original capabilities were not moved"
    );
    let mut tail = OwnedRootTail::new(exit, Instant::now() + TIMEOUT);
    let mut first_identity = None;
    let mut consumed = 0;
    let malformed;
    {
        let mut drain = session.event_drain()?;
        drain.begin_root_tail(&mut tail)?;
        let (positions, bytes, reached) = tail.observed_boundary();
        let boundary = positions.context("stored boundary")?;
        // Kernel ring records have an eight-byte header and eight-byte alignment.
        // Derive payload size from the actual shared wire type; do not parse it here.
        let stride = (std::mem::size_of::<Event>()
            + aya_obj::generated::BPF_RINGBUF_HDR_SZ as usize)
            .next_multiple_of(8);
        ensure!(
            boundary.consumer == 0
                && bytes > 0
                && bytes < boundary.capacity
                && bytes == 2 * stride
                && boundary.producer == bytes
                && !reached,
            "unexpected first EVENTS boundary: {boundary:?}; bytes={bytes}"
        );
        writeln!(
            io::stdout(),
            "root-runtime {kind:?} stored-boundary {boundary:?} bytes={bytes}"
        )?;
        let mut reduce = |event: Event, state: &mut semantics::State| -> Result<()> {
            match kind {
                Kind::Profile => {
                    reduce_profile_event(domain.id(), &mut tracker, state, &scope, event)
                }
                Kind::Trace => reduce_trace_event(
                    domain.id(),
                    &mut remaining,
                    state,
                    &mut tracker,
                    &scope,
                    &mut tracer,
                    &mut trace_bytes,
                    &mut stdout_open,
                    &mut out_file,
                    &mut write_error,
                    event,
                ),
            }
        };
        let progress = drain.poll_root_tail(&mut tail, 1, |event| {
            check_call(&event, pid, open_slot, 0)?;
            ensure!(
                event.capture & capture::OUTPUT_MASK == capture::OUTPUT_NON_NULL
                    && event.capture & capture::ASYNC_SESSION != 0,
                "OpenSession output or async-session capture is invalid"
            );
            first_identity = Some((event.image, event.pid_tgid, event.session));
            reduce(event, &mut state)?;
            consumed += 1;
            sessions(&state, 1, 0, 0)?;
            writeln!(io::stdout(), "root-runtime {kind:?} first-reducer-call")?;
            Ok(())
        })?;
        ensure!(
            progress == RootTailProgress::Yielded && consumed == 1,
            "first quantum did not yield after one call"
        );
        let (positions, bytes, reached) = tail.observed_boundary();
        let positions = positions.context("first progress")?;
        ensure!(
            positions.consumer == stride
                && positions.producer == boundary.producer
                && bytes == stride
                && !reached,
            "unexpected first quantum progress"
        );
        sessions(&state, 1, 0, 0)?;
        let progress = drain.poll_root_tail(&mut tail, 1, |event| {
            check_call(&event, pid, find_slot, PENDING)?;
            ensure!(
                first_identity == Some((event.image, event.pid_tgid, event.session)),
                "second call changed image/task/session identity"
            );
            reduce(event, &mut state)?;
            consumed += 1;
            sessions(&state, 1, 0, 1)?;
            writeln!(io::stdout(), "root-runtime {kind:?} pending-admission")?;
            Ok(())
        })?;
        let (positions, bytes, reached) = tail.observed_boundary();
        let positions = positions.context("reached progress")?;
        ensure!(
            progress == RootTailProgress::Reached
                && consumed == 2
                && bytes == 0
                && reached
                && positions.consumer == boundary.producer
                && positions.producer == boundary.producer,
            "fixed boundary was not reached"
        );
        malformed = drain.malformed();
        ensure!(malformed == 0, "malformed EVENTS records");
        writeln!(io::stdout(), "root-runtime {kind:?} reached-boundary")?;
    }
    sessions(&state, 1, 0, 1)?;
    let token = tail.complete()?;
    sessions(&state, 1, 0, 1)?;
    writeln!(io::stdout(), "root-runtime {kind:?} consumed-token")?;
    document(
        &engine,
        session,
        &scope,
        &state,
        &tracker,
        malformed,
        started,
        "before-retirement",
    )?;
    apply_original_root_retirement(&mut tracker, &mut state, token)?;
    sessions(&state, 1, 1, 0)?;
    ensure!(
        state.sessions().async_opened == 1
            && state.sessions().inherited == 0
            && state.sessions().peak_concurrent == 1
            && !state.pid_has_process_state(pid),
        "retirement left modeled process state or wrong session totals"
    );
    writeln!(io::stdout(), "root-runtime {kind:?} retirement")?;
    let final_evidence = document(
        &engine,
        session,
        &scope,
        &state,
        &tracker,
        malformed,
        started,
        "after-retirement",
    )?;
    combine_trace_errors(Ok(()), write_error)?;
    if kind == Kind::Trace {
        ensure!(
            stdout_open && remaining.is_none() && out_file.is_none() && tracer.raw_calls() == 2,
            "unexpected trace output state"
        );
        let text = std::str::from_utf8(&trace_bytes)?;
        let lines: Vec<_> = text.lines().collect();
        ensure!(
            lines.len() == 2
                && lines[0].contains(" C_OpenSession ")
                && lines[0].contains("→ CKR_OK ")
                && lines[1].contains(" C_FindObjectsInit ")
                && lines[1].contains("→ CKR_PENDING ")
                && !text.contains("semantics unverified"),
            "unexpected production trace: {text}"
        );
        let session_label = |line: &str| {
            line.split_whitespace()
                .find(|part| part.starts_with("sess#"))
                .map(str::to_owned)
        };
        ensure!(
            session_label(lines[0]).is_some() && session_label(lines[0]) == session_label(lines[1]),
            "rendered session identity missing or inconsistent"
        );
        io::stdout().write_all(text.as_bytes())?;
    }
    writeln!(io::stdout(), "{final_evidence}")?;
    Ok(())
}

// TMPDIR-honoring: test temp lives under the workspace tmp dir (see AGENTS.md); the 108-byte control-socket guard below still fails loudly if a TMPDIR is ever too long.
fn control_dir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix("p11root-").tempdir()
}

fn run_mode(stage: &Path, kind: Kind) -> Result<()> {
    let directory = control_dir()?;
    let mut owner = None;
    let mut active = None;
    let result = (|| {
        let identity = ChildIdentity::for_invoker()?;
        chown(directory.path(), Some(identity.uid), Some(identity.gid))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("control");
        ensure!(
            socket.as_os_str().as_bytes().len() < 108,
            "control socket path too long"
        );
        let listener = UnixListener::bind(&socket)?;
        chown(&socket, Some(identity.uid), Some(identity.gid))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        scenario(stage, &socket, &listener, kind, &mut owner, &mut active)
    })();
    // Preserve the initial failure alongside every owned cleanup failure.
    let settlement = match owner.as_mut() {
        Some(child) if !child.is_reaped() => child
            .terminate_and_reap()
            .map(|_| ())
            .context("settling runtime fixture owned child"),
        _ => Ok(()),
    };
    let detach = match active.as_mut() {
        Some(session) => session
            .detach_producers()
            .context("detaching runtime fixture producers"),
        None => Ok(()),
    };
    let close = directory
        .close()
        .context("removing owned control directory");
    combine_finish_errors(
        result,
        combine_finish_errors(settlement, combine_finish_errors(detach, close)),
    )
}

#[test]
#[ignore = "requires separately reviewed native stage, capture activation derivative, and kernel privileges"]
fn actual_original_exit_delayed_first_admission_retires_pending() -> Result<()> {
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "runtime fixture requires Linux x86-64"
    );
    let stage = std::env::var_os("P11SCOPE_ROOT_RUNTIME_STAGE")
        .context("P11SCOPE_ROOT_RUNTIME_STAGE is required; no runtime skip")?;
    let stage = PathBuf::from(stage);
    ensure!(stage.is_absolute(), "runtime stage must be absolute");
    for name in ["provider.so", "driver", "provider.json"] {
        ensure!(stage.join(name).is_file(), "missing staged {name}");
    }
    // Separate owned process, session, map, reducer state, and consumed token.
    run_mode(&stage, Kind::Profile)?;
    run_mode(&stage, Kind::Trace)
}

#[test]
fn control_directory_honors_the_process_temp_dir() {
    let directory = control_dir().expect("control dir must create");
    assert_eq!(
        directory.path().parent(),
        Some(std::env::temp_dir().as_path()),
        "staging must live under TMPDIR, not /tmp"
    );
}
