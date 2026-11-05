//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private installed-acceptance rendezvous. Absent an explicit inherited
//! controller socket, this module performs no descriptor operations.
//! It observes real transactions; only the existing collection control stops
//! work. A release message can resume a healthy gate, never cancel a pass.

use crate::inspect_system::inventory_cgroup::ScopedCollectionOutcome;
use crate::scope::inventory_cgroup::{CollectionControl, CollectionStop};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FD_ENV: &str = "P11SCOPE_CGROUP_STOP_FD";
const MAX_FRAME: usize = 1024;
const MAX_EVENTS: u64 = 256;
const MAX_WAIT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Traversed,
    FinalPreRead,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u8,
    stage: Stage,
    timeout_ms: u32,
    pid: u32,
    start_time: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    version: u8,
    release: u64,
}

struct State {
    stream: UnixStream,
    deadline: Instant,
    selection: Selection,
    sequence: u64,
    transaction: u64,
    selected: Option<u64>,
    failed: bool,
}

/// Owned by one Inventory run; clones only carry that socket into its worker
/// and returned collection. CLOEXEC keeps it out of discovery/workload execs.
#[derive(Clone)]
pub(crate) struct Observer(Arc<Mutex<State>>);

pub(crate) struct Transaction {
    observer: Observer,
    id: u64,
    candidate_admitted: bool,
}

fn outcome(value: ScopedCollectionOutcome) -> &'static str {
    match value {
        ScopedCollectionOutcome::Complete => "complete",
        ScopedCollectionOutcome::Cancelled(CollectionStop::OperatorStop) => "operator_stop",
        ScopedCollectionOutcome::Cancelled(CollectionStop::Deadline) => "deadline",
        ScopedCollectionOutcome::Incomplete(_) => "incomplete",
    }
}

fn poll(stream: &UnixStream, events: i16, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("cgroup stop observer deadline exhausted");
    }
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    // A fixed service quantum lets a gated wait inspect the real control.
    let milliseconds = remaining.as_millis().clamp(1, 10) as i32;
    let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
    if ready < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(error.into());
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        bail!("cgroup stop observer socket failed");
    }
    Ok(()) // HUP is settled by the bounded read/write itself.
}

fn read_frame(
    stream: &mut UnixStream,
    frame: &mut Vec<u8>,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    loop {
        if Instant::now() >= deadline {
            bail!("cgroup stop observer deadline exhausted");
        }
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => bail!("cgroup stop observer socket closed"),
            Ok(_) if byte[0] == b'\n' => return Ok(Some(std::mem::take(frame))),
            Ok(_) => {
                if frame.len() == MAX_FRAME {
                    bail!("cgroup stop observer frame too large");
                }
                frame.push(byte[0]);
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

impl State {
    fn send(&mut self, event: &'static str, transaction: u64, facts: Value) -> Result<()> {
        if self.sequence == MAX_EVENTS {
            bail!("cgroup stop observer event allowance exhausted");
        }
        let mut message = facts;
        let object = message.as_object_mut().expect("bounded metadata object");
        object.insert("version".into(), json!(1));
        object.insert("event".into(), json!(event));
        object.insert("sequence".into(), json!(self.sequence));
        object.insert("transaction".into(), json!(transaction));
        let mut bytes = serde_json::to_vec(&message)?;
        if bytes.len() > MAX_FRAME {
            bail!("cgroup stop observer metadata too large");
        }
        bytes.push(b'\n');
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            if Instant::now() >= self.deadline {
                bail!("cgroup stop observer deadline exhausted");
            }
            match self.stream.write(rest) {
                Ok(0) => bail!("cgroup stop observer socket closed"),
                Ok(count) => rest = &rest[count..],
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    poll(&self.stream, libc::POLLOUT, self.deadline)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.sequence += 1;
        Ok(())
    }
    fn emit(&mut self, event: &'static str, transaction: u64, facts: Value) {
        if !self.failed && self.send(event, transaction, facts).is_err() {
            self.failed = true;
        }
    }
    fn gate(&mut self, id: u64, stage: Stage, control: &CollectionControl) {
        if self.failed || self.selected.is_some() || self.selection.stage != stage {
            return;
        }
        self.selected = Some(id);
        let event = match stage {
            Stage::Traversed => "traversed",
            Stage::FinalPreRead => "final_pre_read",
        };
        self.emit(
            event,
            id,
            json!({"pid": self.selection.pid,
            "start_time": self.selection.start_time, "requested": stage == Stage::FinalPreRead}),
        );
        // No collection budget mutex is held here. Failure only retires the
        // observer; it never supplies a cancellation/admission decision.
        let mut pending = Vec::with_capacity(MAX_FRAME);
        while !self.failed && control.check().is_ok() {
            match read_frame(&mut self.stream, &mut pending, self.deadline) {
                Ok(Some(frame)) => {
                    let release = serde_json::from_slice::<Release>(&frame);
                    if !matches!(release, Ok(Release { version: 1, release }) if release == id) {
                        self.failed = true;
                    }
                    break;
                }
                Ok(None) => {
                    if poll(&self.stream, libc::POLLIN, self.deadline).is_err() {
                        self.failed = true;
                    }
                }
                Err(_) => self.failed = true,
            }
        }
        // A real stop must not wait for a partial frame, and the unfinished
        // exchange must not acquire positive completion metadata afterward.
        if !pending.is_empty() {
            self.failed = true;
        }
    }
}

impl Observer {
    pub(crate) fn from_environment() -> Result<Option<Self>> {
        let Some(value) = std::env::var_os(FD_ENV) else {
            return Ok(None);
        };
        let fd = value
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|fd| *fd > 2)
            .context("invalid inherited cgroup stop observer descriptor")?;
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            bail!("inherited cgroup stop observer descriptor is unavailable");
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let status = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if status != 0
            || length as usize != std::mem::size_of::<libc::ucred>()
            || peer.pid != unsafe { libc::getppid() }
            || peer.uid != unsafe { libc::geteuid() }
        {
            bail!("cgroup stop observer socket is not owned by the inherited controller");
        }
        let mut socket_type = 0_i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || socket_type != libc::SOCK_STREAM
        {
            bail!("cgroup stop observer requires a connected Unix stream");
        }
        let mut stream = UnixStream::from(owned);
        stream
            .peer_addr()
            .context("cgroup stop observer requires a connected Unix stream")?;
        stream.set_nonblocking(true)?;
        let started = Instant::now();
        let mut deadline = started + MAX_WAIT;
        let mut pending = Vec::with_capacity(MAX_FRAME);
        let frame = loop {
            if let Some(frame) = read_frame(&mut stream, &mut pending, deadline)? {
                break frame;
            }
            poll(&stream, libc::POLLIN, deadline)?;
        };
        let selection: Selection =
            serde_json::from_slice(&frame).context("invalid cgroup stop observer selection")?;
        if selection.version != 1
            || selection.timeout_ms == 0
            || selection.timeout_ms > 180_000
            || (selection.stage == Stage::Traversed
                && (selection.pid != 0 || selection.start_time != 0))
            || (selection.stage == Stage::FinalPreRead
                && (selection.pid == 0 || selection.start_time == 0))
        {
            bail!("unsupported cgroup stop observer selection");
        }
        deadline = deadline.min(started + Duration::from_millis(u64::from(selection.timeout_ms)));
        let mut state = State {
            stream,
            deadline,
            selection,
            sequence: 0,
            transaction: 0,
            selected: None,
            failed: false,
        };
        state.send("armed", 0, json!({}))?;
        Ok(Some(Self(Arc::new(Mutex::new(state)))))
    }
    pub(crate) fn launch(&self) -> Transaction {
        let mut state = self.0.lock().unwrap();
        state.transaction += 1; // bounded exchange, not an authority generation
        let id = state.transaction;
        state.emit("launch", id, json!({}));
        Transaction {
            observer: self.clone(),
            id,
            candidate_admitted: false,
        }
    }
    pub(crate) fn retiring(&self) {
        self.0.lock().unwrap().emit("retiring", 0, json!({}));
    }
    pub(crate) fn retired(&self) {
        self.0.lock().unwrap().emit("retired", 0, json!({}));
    }
}

impl Transaction {
    pub(crate) fn traversed(&self, control: &CollectionControl) {
        if self.id == 1 {
            self.observer
                .0
                .lock()
                .unwrap()
                .gate(self.id, Stage::Traversed, control);
        }
    }
    pub(crate) fn final_pre_read(
        &self,
        requested: impl FnOnce(u32, u64) -> bool,
        control: &CollectionControl,
    ) {
        let mut state = self.observer.0.lock().unwrap();
        if requested(state.selection.pid, state.selection.start_time) {
            state.gate(self.id, Stage::FinalPreRead, control);
        }
    }
    pub(crate) fn returned(&self, result: ScopedCollectionOutcome) {
        self.observer.0.lock().unwrap().emit(
            "worker_returned",
            self.id,
            json!({"outcome": outcome(result)}),
        );
    }
    pub(crate) fn joined(&self) {
        self.observer
            .0
            .lock()
            .unwrap()
            .emit("worker_joined", self.id, json!({}));
    }
    pub(crate) fn sampled(&self, result: ScopedCollectionOutcome, present: &BTreeSet<u32>) {
        let mut state = self.observer.0.lock().unwrap();
        let present = present.contains(&state.selection.pid);
        state.emit(
            "end_sampled",
            self.id,
            json!({"outcome": outcome(result), "present": present}),
        );
    }
    pub(crate) fn allowed(&mut self, allowed: &BTreeSet<u32>) {
        self.candidate_admitted = allowed.contains(&self.observer.0.lock().unwrap().selection.pid);
    }
    pub(crate) fn published(
        &self,
        result: ScopedCollectionOutcome,
        admitted: usize,
        callers: usize,
        endpoints: usize,
    ) {
        self.observer.0.lock().unwrap().emit(
            "published",
            self.id,
            json!({"outcome": outcome(result), "admitted": admitted, "callers": callers,
                "endpoints": endpoints, "candidate_admitted": self.candidate_admitted}),
        );
    }
}
