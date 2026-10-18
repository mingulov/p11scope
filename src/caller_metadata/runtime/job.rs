// SPDX-License-Identifier: GPL-3.0-or-later
//! Original-custody jobs and the only native-qualified metadata commit path.

use super::work_lane::{WorkFailure, WorkOwner, WorkSlot};
use super::{
    JOB_BUDGET, JobTicket, MemoryCharge, MetadataFrame, MetadataRuntime, WORKER_STORAGE_BYTES,
};
use crate::attach::capture::{CallerImageObservation, ReadWindow};
use crate::caller_metadata::acquisition::UncommittedSample;
use crate::caller_metadata::presentation::MetadataReason;
use crate::discovery::caller_registry::{CallerAdapter, ProcessSource};
use crate::discovery::native_binding::{BinderMetadataImage, NativeBinder};
use crate::process::PidPin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

struct Request {
    ticket: JobTicket,
    original: Arc<PidPin>,
    expected: BinderMetadataImage,
    deadline: Instant,
}
struct Completion {
    request: Request,
    before: CallerImageObservation,
    sample: Result<UncommittedSample, MetadataReason>,
    started_ns: u64,
    ended_ns: u64,
}

/// The process-lifetime slot retains a dropped capture's actual JoinHandle and
/// leases. No new owner may bypass an old blocked worker; no Drop path joins a
/// running job on the output thread. Production budgets also span owners.
static WORK: WorkSlot<Completion, MemoryCharge> = WorkSlot::new();

pub(crate) struct MetadataLane {
    runtime: MetadataRuntime,
    worker: WorkOwner<'static, Completion, MemoryCharge>,
    active: Option<JobTicket>,
    stopped: bool,
}
impl MetadataLane {
    pub(crate) fn try_new(epoch: u64) -> Result<Self, MetadataReason> {
        if epoch == 0 {
            return Err(MetadataReason::IdentityUnavailable);
        }
        let worker = WORK.claim().map_err(|_| MetadataReason::LookupLimit)?;
        let runtime = MetadataRuntime::try_new(epoch).ok_or(MetadataReason::LookupLimit)?;
        Ok(Self {
            runtime,
            worker,
            active: None,
            stopped: false,
        })
    }

    pub(crate) fn synchronize<Source: ProcessSource>(
        &mut self,
        adapter: &CallerAdapter<Source>,
        binder: &NativeBinder,
        now_ns: u64,
    ) {
        self.runtime
            .synchronize(adapter.metadata_callers(binder), now_ns);
    }

    /// Called only at the serial native service seam. The observation closure
    /// borrows the actual InventoryCapture facade exclusively; it never hands
    /// native maps/programs to the worker or uses a promotion request/view.
    pub(crate) fn tick<Source: ProcessSource>(
        &mut self,
        adapter: &CallerAdapter<Source>,
        binder: &NativeBinder,
        now_ns: u64,
        mut observe: impl FnMut(&Arc<PidPin>, ReadWindow) -> anyhow::Result<CallerImageObservation>,
    ) {
        self.runtime
            .synchronize(adapter.metadata_callers(binder), now_ns);
        if let Some((result, _storage)) = self.worker.poll_retained() {
            let active = self.active.take();
            match result {
                Err(_) => {
                    if let Some(ticket) = active {
                        self.runtime.refuse(ticket, MetadataReason::ReadFailed);
                    }
                }
                Ok(completion) => self.complete(completion, adapter, binder, &mut observe),
            }
        }
        if self.stopped || !self.worker.idle() || self.active.is_some() {
            return;
        }
        let Some(ticket) = self.runtime.next(now_ns) else {
            return;
        };
        let target = match adapter.metadata_target(binder, ticket.caller.id) {
            Ok(target) if target.caller == ticket.caller => target,
            _ => {
                self.runtime
                    .refuse(ticket, MetadataReason::IdentityUnavailable);
                return;
            }
        };
        let Some(storage) = self.runtime.reserve_worker() else {
            self.runtime.refuse(ticket, MetadataReason::LookupLimit);
            return;
        };
        let anchor = Instant::now();
        let request = Request {
            ticket,
            original: target.original,
            expected: target.expected,
            deadline: anchor + JOB_BUDGET,
        };
        // The complete retained job, completion and fixed slot/flag wrappers
        // have a measured envelope. Membership buffers/thread stack are the
        // separately bounded temporary sample scratch, not retained rows.
        assert!(
            size_of::<Completion>()
                + size_of::<Request>()
                + size_of::<WorkSlot<Completion, MemoryCharge>>()
                + size_of::<Self>()
                + super::arc_bytes::<AtomicBool>()
                + 8 * super::ALLOCATION_PADDING
                <= WORKER_STORAGE_BYTES
        );
        let before = match observe(
            &request.original,
            ReadWindow::new(1, request.deadline).expect("one row"),
        ) {
            Ok(before) if matches_expected(&before, &request) => before,
            Ok(_) => {
                self.runtime
                    .refuse(ticket, MetadataReason::GenerationChanged);
                return;
            }
            Err(_) => {
                self.runtime.refuse(
                    ticket,
                    if Instant::now() >= request.deadline {
                        MetadataReason::Deadline
                    } else {
                        MetadataReason::IdentityUnavailable
                    },
                );
                return;
            }
        };
        if Instant::now() >= request.deadline {
            self.runtime.refuse(ticket, MetadataReason::Deadline);
            return;
        }
        let result = self.worker.start_retained(
            move |cancelled| {
                let started = crate::attach::monotonic_ns();
                let mut sample = if started.is_some() {
                    sample_original(&request.original, &cancelled, request.deadline)
                } else {
                    Err(MetadataReason::Deadline)
                };
                let ended = crate::attach::monotonic_ns();
                if started.zip(ended).is_none_or(|(start, end)| end < start) {
                    sample = Err(MetadataReason::Deadline);
                }
                Completion {
                    request,
                    before,
                    sample,
                    started_ns: started.unwrap_or(0),
                    ended_ns: ended.unwrap_or(0),
                }
            },
            storage,
        );
        match result {
            Ok(()) => self.active = Some(ticket),
            Err(
                WorkFailure::Busy
                | WorkFailure::Exhausted
                | WorkFailure::Spawn
                | WorkFailure::Panic,
            ) => {
                self.runtime.refuse(ticket, MetadataReason::LookupLimit);
            }
        }
    }

    fn complete<Source: ProcessSource>(
        &mut self,
        completion: Completion,
        adapter: &CallerAdapter<Source>,
        binder: &NativeBinder,
        observe: &mut impl FnMut(&Arc<PidPin>, ReadWindow) -> anyhow::Result<CallerImageObservation>,
    ) {
        let Completion {
            request,
            before,
            sample,
            started_ns,
            ended_ns,
        } = completion;
        let current = adapter.metadata_target(binder, request.ticket.caller.id);
        let same = current.as_ref().is_ok_and(|target| {
            target.caller == request.ticket.caller
                && Arc::ptr_eq(&target.original, &request.original)
        });
        // No new native/proc I/O after cancellation or a changed incarnation.
        if self.stopped
            || !same
            || !self
                .runtime
                .ticket_current(request.ticket, request.ticket.caller)
        {
            let current = current.map(|target| target.caller).unwrap_or_else(|_| {
                let mut ended = request.ticket.caller;
                ended.retired = true;
                ended
            });
            self.runtime.finish(
                request.ticket,
                current,
                Err(MetadataReason::Stopped),
                request.ticket.started_ns,
            );
            return;
        }
        let current = current.expect("checked original");
        let mut result = sample;
        if result.is_ok() {
            if Instant::now() >= request.deadline {
                result = Err(MetadataReason::Deadline);
            } else {
                result = match observe(
                    &request.original,
                    ReadWindow::new(1, request.deadline).expect("one row"),
                ) {
                    Ok(after)
                        if matches_expected(&after, &request) && before.same_image(&after) =>
                    {
                        result
                    }
                    Ok(_) => Err(MetadataReason::GenerationChanged),
                    Err(_) => Err(if Instant::now() >= request.deadline {
                        MetadataReason::Deadline
                    } else {
                        MetadataReason::IdentityUnavailable
                    }),
                };
            }
        }
        self.runtime.finish_with_times(
            request.ticket,
            current.caller,
            result,
            started_ns,
            ended_ns,
        );
    }

    pub(crate) fn stop(&mut self) {
        self.stopped = true;
        self.runtime.stop();
        self.worker.cancel();
    }
    pub(crate) fn invalidate(&mut self) {
        self.runtime.invalidate();
    }
    pub(crate) fn idle(&self) -> bool {
        self.worker.idle() && self.active.is_none()
    }
    pub(crate) fn frame(&self) -> MetadataFrame {
        self.runtime
            .frame_at(crate::discovery::caller_registry::now_ns())
    }
}
impl Drop for MetadataLane {
    fn drop(&mut self) {
        self.stop();
    }
}

fn matches_expected(observation: &CallerImageObservation, request: &Request) -> bool {
    request
        .expected
        .matches_observation(&request.original, observation)
}

/// This returns UNCOMMITTED private metadata. Only complete(), with the real
/// pre/post native observations and still-current original identity, can commit.
fn sample_original(
    original: &Arc<PidPin>,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<UncommittedSample, MetadataReason> {
    let gate = || {
        if cancelled.load(Ordering::Acquire) {
            Err(MetadataReason::Stopped)
        } else if Instant::now() >= deadline {
            Err(MetadataReason::Deadline)
        } else {
            Ok(())
        }
    };
    gate()?;
    let pin = original
        .try_clone()
        .map_err(|_| MetadataReason::IdentityUnavailable)?;
    gate()?;
    let proc = pin
        .open_proc_dir()
        .map_err(|_| MetadataReason::IdentityUnavailable)?;
    gate()?;
    crate::process::cgroup_context::acquire_retained_cgroup_sample(&proc, cancelled, deadline)
        .map_err(MetadataReason::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_retained_worker_sample_and_cancel_deadline_twins() {
        let original = Arc::new(PidPin::open(std::process::id()).unwrap());
        let cancelled = AtomicBool::new(false);
        let sample = sample_original(
            &original,
            &cancelled,
            Instant::now() + std::time::Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(
            sample.validity,
            crate::caller_metadata::acquisition::SampleValidity::EndpointSampleOnly
        );
        assert_eq!(
            sample.numeric,
            crate::caller_metadata::acquisition::NumericAbsence::NamespaceUnresolved
        );
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            sample_original(&original, &cancelled, Instant::now()),
            Err(MetadataReason::Stopped)
        );
        cancelled.store(false, Ordering::Release);
        assert_eq!(
            sample_original(&original, &cancelled, Instant::now()),
            Err(MetadataReason::Deadline)
        );
    }
}
