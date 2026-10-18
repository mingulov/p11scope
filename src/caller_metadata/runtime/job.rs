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

pub(super) fn owner_storage_bytes() -> usize {
    size_of::<MetadataLane>() + size_of::<WorkSlot<Completion, MemoryCharge>>()
}

/// Enrichment failure never disables the caller/provider capture. An
/// unavailable lane retains only a finite mode/reason/census, no table or job.
pub(crate) struct MetadataLane {
    active: Option<ActiveMetadataLane>,
    unavailable: MetadataFrame,
}
impl MetadataLane {
    pub(crate) fn try_new(epoch: u64) -> Result<Self, MetadataReason> {
        Ok(Self {
            active: Some(ActiveMetadataLane::try_new(epoch)?),
            unavailable: MetadataFrame::default(),
        })
    }
    pub(crate) fn unavailable(reason: MetadataReason) -> Self {
        Self {
            active: None,
            unavailable: MetadataFrame::unavailable(reason),
        }
    }
    pub(crate) fn synchronize<Source: ProcessSource>(
        &mut self,
        adapter: &CallerAdapter<Source>,
        binder: &NativeBinder,
        now_ns: u64,
    ) {
        if let Some(active) = self.active.as_mut() {
            active.synchronize(adapter, binder, now_ns);
        } else {
            self.unavailable.summary.unknown = adapter.len();
        }
    }
    pub(crate) fn tick<Source: ProcessSource>(
        &mut self,
        adapter: &CallerAdapter<Source>,
        binder: &NativeBinder,
        now_ns: u64,
        observe: impl FnMut(&Arc<PidPin>, ReadWindow) -> anyhow::Result<CallerImageObservation>,
    ) {
        if let Some(active) = self.active.as_mut() {
            active.tick(adapter, binder, now_ns, observe);
        } else {
            self.unavailable.summary.unknown = adapter.len();
        }
    }
    pub(crate) fn stop(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.stop();
        }
    }
    pub(crate) fn invalidate(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.invalidate();
        }
    }
    pub(crate) fn idle(&self) -> bool {
        self.active.as_ref().is_none_or(ActiveMetadataLane::idle)
    }
    pub(crate) fn frame(&self) -> MetadataFrame {
        self.active
            .as_ref()
            .map_or_else(|| self.unavailable.clone(), ActiveMetadataLane::frame)
    }
}

struct ActiveMetadataLane {
    runtime: MetadataRuntime,
    worker: WorkOwner<'static, Completion, MemoryCharge>,
    active: Option<JobTicket>,
    stopped: bool,
}
impl ActiveMetadataLane {
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
impl Drop for ActiveMetadataLane {
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
    fn startup_busy_worker_keeps_inventory_and_public_unknown_frame() {
        use crate::discovery::caller_registry::RegistryLimits;
        use crate::discovery::inventory_workload::{Harness, ScaleSpec};
        use crate::inventory_event_identity::IdentityIndex;
        use crate::inventory_events::EventWriter;
        use crate::inventory_present::Presentation;
        use std::io::{Read as _, Seek as _};

        fn population(first_pid: u32) -> Harness {
            let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
            harness.stage_scale(&ScaleSpec {
                name: "metadata-startup",
                callers: 2,
                modules: 1,
                edges_per_caller: 1,
                endpoints_per_module: 4,
                first_pid,
            });
            harness.commit();
            harness
        }

        let mut healthy = population(92_000);
        healthy
            .coordinator_mut()
            .enable_caller_metadata(41)
            .unwrap();
        let mut reads = 0;
        healthy.coordinator_mut().service_caller_metadata(
            |_, _| {
                reads += 1;
                anyhow::bail!("unbound callers must not start native metadata reads")
            },
            10,
        );
        let healthy_frame = healthy.coordinator().metadata_frame();
        assert!(healthy_frame.summary.enabled);
        assert!(healthy_frame.summary.retained_bytes > 0);
        assert_eq!(healthy_frame.summary.unknown, 2);
        assert_eq!(reads, 0);
        assert_eq!(
            healthy_frame
                .metadata(healthy.coordinator().adapter().records().next().unwrap().id)
                .unwrap()
                .reason,
            Some(MetadataReason::IdentityUnavailable)
        );
        assert!(
            WORK.claim().is_err(),
            "healthy capture owns the actual worker slot"
        );

        let mut refused = population(93_000);
        let before = crate::inventory::render_json_from_presentation(&Presentation::capture(
            refused.coordinator(),
            "workload",
            1,
            2,
            1,
        ));
        assert!(before["callers"][0].get("metadata").is_none());
        refused
            .coordinator_mut()
            .enable_caller_metadata(42)
            .unwrap();
        refused.coordinator_mut().service_caller_metadata(
            |_, _| {
                reads += 1;
                anyhow::bail!("unavailable lane must not perform native metadata reads")
            },
            20,
        );
        assert_eq!(reads, 0);
        let view = Presentation::capture(refused.coordinator(), "workload", 1, 2, 1);
        assert_eq!(view.caller_metadata.summary.unknown, 2);
        assert_eq!(view.caller_metadata.summary.budget_refusals, 1);
        assert_eq!(view.caller_metadata.summary.retained_bytes, 0);
        let json = crate::inventory::render_json_from_presentation(&view);
        assert_eq!(json["caller_metadata"]["mode"], "cgroup");
        assert_eq!(json["budgets"], before["budgets"]);
        assert_eq!(json["edges"], before["edges"]);
        assert_eq!(json["callers"].as_array().unwrap().len(), 2);
        let identities = IdentityIndex::new(&view);
        for (caller, row) in view.callers.iter().zip(json["callers"].as_array().unwrap()) {
            assert_eq!(row["metadata"]["status"], "unknown");
            assert_eq!(row["metadata"]["reason"], "lookup_limit");
            assert_eq!(
                row["metadata"],
                identities.caller_context(caller.id)["metadata"]
            );
        }

        let file = tempfile::tempfile().unwrap();
        let mut reader = file.try_clone().unwrap();
        let mut writer = EventWriter::anonymous_test_sink(file);
        let mut emitter = crate::caller_metadata::consumer::MetadataEmitter::default();
        assert_eq!(emitter.emit(&mut writer, &view, 20, false).unwrap(), 2);
        assert_eq!(emitter.emit(&mut writer, &view, 30, false).unwrap(), 0);
        reader.rewind().unwrap();
        let mut bytes = String::new();
        reader.read_to_string(&mut bytes).unwrap();
        let records: Vec<serde_json::Value> = bytes
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        for (record, row) in records.iter().zip(json["callers"].as_array().unwrap()) {
            assert_eq!(record["kind"], "caller_metadata_changed");
            assert_eq!(record["event"]["metadata"], row["metadata"]);
        }
        refused.coordinator_mut().stop_caller_metadata();
        drop(healthy);
        let mut next = MetadataLane::try_new(43).unwrap();
        assert!(next.idle(), "stopped idle owner releases the actual slot");
        next.stop();
    }

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
