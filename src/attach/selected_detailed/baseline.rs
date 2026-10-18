//! SPDX-License-Identifier: GPL-3.0-or-later
//! Inventory-domain kernel image acquisition. Results are private identity
//! facts; the view/request binder must qualify them before Detailed preparation.
use super::super::capture::{NativeDomainId, ReadWindow};
use crate::discovery::caller_registry::{CallerId, CallerLifecycle, ModuleId};
use crate::inventory_present::Presentation;
use crate::inventory_promotion::{CaptureId, PromotionRequest, PromotionView, RequestId};
use crate::process::{PidPin, WeakProcessCustody};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal,
};
use anyhow::{Context as _, Result, ensure};
use aya::maps::{Array, HashMap};
use std::os::fd::AsFd as _;
use std::sync::Arc;

#[path = "caller_image.rs"]
mod caller_image;
pub(crate) use caller_image::{CallerImageObservation, observe_caller_image};

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Request {
    generation: u64,
    tgid: u32,
    slot: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Control {
    generation: u64,
    deadline_ns: u64,
    visit_limit: u64,
    count: u64,
    visits: u64,
    emitted: u64,
    failed: u64,
}
// SAFETY: repr(C), integer-only wire values admit all bit patterns.
unsafe impl aya::Pod for Request {}
// SAFETY: repr(C), integer-only wire values admit all bit patterns.
unsafe impl aya::Pod for Control {}
const _: () = assert!(size_of::<Request>() == 16);
const _: () = assert!(size_of::<Control>() == 56);

/// Input coordinates and custody, not a native identity receipt. The query
/// validates these against the exact candidate Presentation before allocation.
pub(crate) struct BaselineTarget {
    pub(crate) caller: CallerId,
    pub(crate) incarnation: u32,
    pub(crate) original: Arc<PidPin>,
}
impl std::fmt::Debug for BaselineTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BaselineTarget(<retained>)")
    }
}

struct ImageRow {
    caller: CallerId,
    incarnation: u32,
    original: WeakProcessCustody,
    cookie: u64,
    exec_id: u64,
}
/// Constructed only after the actual native iterator and original-pidfd checks.
/// No public numeric constructor, Clone, raw image getter or serialization.
struct KernelBaselineBatch {
    domain: NativeDomainId,
    generation: u64,
    rows: Vec<ImageRow>,
}
impl std::fmt::Debug for KernelBaselineBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KernelBaselineBatch(<retained>)")
    }
}

/// Immutable candidate-side pairing. Only the actual acquisition below can
/// construct it; there is no binder accepting a caller-minted native batch.
pub(crate) struct PromotionBaselineBatch {
    capture: CaptureId,
    presentation: Arc<Presentation>,
    core: KernelBaselineBatch,
    // Drop retained rows/paired Weak identities before refunding their storage.
    _storage: ResourceLease,
}
impl PromotionBaselineBatch {
    pub(crate) fn matches_view(
        &self,
        capture: CaptureId,
        presentation: &Arc<Presentation>,
    ) -> bool {
        self.capture == capture
            && Arc::ptr_eq(&self.presentation, presentation)
            && self.core.generation != 0
    }

    pub(crate) fn for_request(
        self: &Arc<Self>,
        request: &PromotionRequest,
        original: &Arc<PidPin>,
        actual_incarnation: u32,
    ) -> Result<PromotionImageBaseline> {
        let viewed = request.viewed();
        ensure!(
            self.matches_view(viewed.capture(), viewed.presentation())
                && viewed
                    .baseline()
                    .is_some_and(|held| Arc::ptr_eq(held, self)),
            "selected request has no matching immutable viewed baseline"
        );
        ensure!(
            request.id().get() != 0
                && request.id().get() != RequestId::EXHAUSTED
                && viewed.revision().get() != 0
                && viewed.revision().get() != crate::inventory_promotion::ViewRevision::EXHAUSTED,
            "selected request/view serial is invalid"
        );
        ensure!(
            self.presentation
                .edges
                .iter()
                .any(|edge| edge.caller == request.caller() && edge.module == request.provider()),
            "selected request pair is absent from the acquired frame"
        );
        let row = self
            .core
            .rows
            .iter()
            .position(|row| {
                row.caller == request.caller()
                    && row.incarnation == actual_incarnation
                    && row.original.matches_original(original)
            })
            .context("selected request has no original retained image baseline")?;
        ensure!(
            self.presentation
                .callers
                .iter()
                .any(|caller| caller.id == request.caller()
                    && caller.incarnation == actual_incarnation
                    && caller.pid == original.pid()
                    && caller.start_time == original.start_time()
                    && !caller.retired
                    && caller.lifecycle == CallerLifecycle::Mapped),
            "selected original caller/incarnation differs from acquired frame"
        );
        original.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            !original.original_exited().map_err(anyhow::Error::msg)?,
            "selected original process exited after displayed baseline"
        );
        Ok(PromotionImageBaseline {
            batch: Arc::clone(self),
            viewed: Arc::clone(viewed),
            request: request.id(),
            provider: request.provider(),
            row,
        })
    }
}
impl std::fmt::Debug for PromotionBaselineBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromotionBaselineBatch(<retained>)")
    }
}

/// Request-qualified selection of the genuine pre-view batch. Neither numeric
/// cookie equality across domains nor a later query can create this wrapper.
pub(crate) struct PromotionImageBaseline {
    batch: Arc<PromotionBaselineBatch>,
    viewed: Arc<PromotionView>,
    request: RequestId,
    provider: ModuleId,
    row: usize,
}
impl PromotionImageBaseline {
    pub(crate) fn matches_request(&self, request: &PromotionRequest) -> bool {
        self.request == request.id()
            && self.provider == request.provider()
            && Arc::ptr_eq(&self.viewed, request.viewed())
            && request
                .viewed()
                .baseline()
                .is_some_and(|held| Arc::ptr_eq(held, &self.batch))
            && self
                .batch
                .matches_view(request.viewed().capture(), request.viewed().presentation())
            && self
                .batch
                .core
                .rows
                .get(self.row)
                .is_some_and(|row| row.caller == request.caller())
    }
    pub(crate) fn matches_original_and_exec(
        &self,
        original: &Arc<PidPin>,
        full_exec_id: u64,
    ) -> bool {
        self.batch.core.rows.get(self.row).is_some_and(|row| {
            row.exec_id == full_exec_id && row.original.matches_original(original)
        })
    }
}
impl std::fmt::Debug for PromotionImageBaseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromotionImageBaseline(<retained>)")
    }
}

/// Requested-allocation envelope on pinned Rust x86-64. Per row covers both
/// BTreeSet internal nodes (u32/u64), old/new parser Vecs, final row Vec, and
/// old/new iterator byte Vecs together. Fixed scratch covers <=1024 old map
/// keys including Vec growth. Caller-owned target/Presentation storage is
/// charged by its existing owner; this lease follows all retained row overlap.
fn requested_bytes(rows: usize) -> Option<usize> {
    let arc = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<PromotionBaselineBatch>())
        .ok()?
        .0
        .pad_to_align()
        .size();
    rows.checked_mul(1024)?
        .checked_add(128 * 1024)?
        .checked_add(arc)?
        .checked_add(OWNED_ALLOCATION_PADDING)
}
const _: () = {
    assert!(std::mem::size_of::<ImageRow>() <= 64);
    // Full internal BTree nodes + padding: (16+11*K+12*8+32) each.
    assert!(
        (16 + 11 * 4 + 12 * 8 + 32) + (16 + 11 * 8 + 12 * 8 + 32) + 3 * 40 + 3 * 32 + 64 + 6 * 32
            <= 1024
    );
};

/// Called under the exclusive Inventory capture borrow, on explicit baseline
/// work only. Loading the iterator is deferred so ordinary startup is unchanged.
pub(crate) fn query(
    ebpf: &mut aya::Ebpf,
    domain: NativeDomainId,
    generation: u64,
    capture: CaptureId,
    presentation: Arc<Presentation>,
    targets: &[BaselineTarget],
    window: ReadWindow,
    reserve: impl FnOnce(usize) -> std::result::Result<ResourceLease, SemanticResourceRefusal>,
) -> Result<PromotionBaselineBatch> {
    validate_query_window(generation, targets.len(), window)?;
    ensure!(capture.get() != 0, "baseline capture is invalid");
    let storage = reserve(requested_bytes(targets.len()).context("baseline storage overflow")?)
        .map_err(|_| anyhow::anyhow!("baseline shared storage refused"))?;
    for target in targets {
        let pin = &target.original;
        ensure!(
            presentation
                .callers
                .iter()
                .any(|caller| caller.id == target.caller
                    && caller.incarnation == target.incarnation
                    && caller.pid == pin.pid()
                    && caller.start_time == pin.start_time()
                    && caller.start_time.is_some()
                    && !caller.retired
                    && caller.lifecycle == CallerLifecycle::Mapped),
            "baseline target does not belong to exact candidate frame"
        );
    }
    let images = query_native(
        ebpf,
        generation,
        targets.len(),
        |slot| &targets[slot].original,
        window,
    )?;
    let mut rows = Vec::with_capacity(targets.len());
    for (target, image) in targets.iter().zip(images) {
        rows.push(ImageRow {
            caller: target.caller,
            incarnation: target.incarnation,
            original: PidPin::downgrade_shared(&target.original)
                .context("baseline original custody charge unavailable")?,
            cookie: image.cookie,
            exec_id: image.exec_id,
        });
    }
    super::super::image_query::check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))?;
    Ok(PromotionBaselineBatch {
        capture,
        presentation,
        core: KernelBaselineBatch {
            domain,
            generation,
            rows,
        },
        _storage: storage,
    })
}

fn validate_query_window(generation: u64, count: usize, window: ReadWindow) -> Result<()> {
    ensure!(
        generation != 0 && count != 0 && count <= window.max_rows().min(1024),
        "baseline window/capacity/generation refused"
    );
    super::super::image_query::check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))
}

/// Shared native acquisition only: no Presentation, promotion request, caller
/// admission or mutable object escapes this exclusive Inventory operation.
fn query_native<'a>(
    ebpf: &mut aya::Ebpf,
    generation: u64,
    count: usize,
    original_at: impl Fn(usize) -> &'a Arc<PidPin>,
    window: ReadWindow,
) -> Result<Vec<super::wire::BaselineImage>> {
    use super::super::image_query::{
        check_deadline, conservative_deadline, read_iterator, task_link,
    };
    validate_query_window(generation, count, window)?;
    ensure!(
        crate::pidns::numbering().agrees(),
        "baseline PID numbering disagrees"
    );
    let mut seen = std::collections::BTreeSet::new();
    for slot in 0..count {
        let pin = original_at(slot);
        ensure!(
            seen.insert(pin.pid()),
            "baseline original pins contain duplicate TGIDs"
        );
        pin.pidfd().context("baseline requires original pidfd")?;
        pin.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            !pin.original_exited().map_err(anyhow::Error::msg)?,
            "baseline original process exited"
        );
    }
    let host = super::super::host_btf::shared()?;
    let program: &mut aya::programs::Iter = ebpf
        .program_mut("p11_inventory_image_baseline")
        .context("Inventory image baseline program unavailable")?
        .try_into()?;
    if program.fd().is_err() {
        program
            .load("task", host.btf())
            .context("loading explicit Inventory image baseline iterator")?;
    }
    let mut requests: HashMap<_, u32, Request> = HashMap::try_from(
        ebpf.map_mut("INV_BASELINE_REQUESTS")
            .context("baseline requests map")?,
    )?;
    let old = requests
        .keys()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        old.len() <= 1024,
        "baseline old request map exceeds its exact bound"
    );
    for key in old {
        requests.remove(&key)?;
    }
    for slot in 0..count {
        let pin = original_at(slot);
        requests.insert(
            pin.pid(),
            Request {
                generation,
                tgid: pin.pid(),
                slot: slot as u32,
            },
            1,
        )?;
    }
    for slot in 0..count {
        let pin = original_at(slot);
        ensure!(
            requests.get(&pin.pid(), 0)?
                == Request {
                    generation,
                    tgid: pin.pid(),
                    slot: slot as u32
                },
            "baseline request readback differs"
        );
    }
    let control = Control {
        generation,
        deadline_ns: conservative_deadline(window.deadline())
            .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))?,
        visit_limit: 65536,
        count: count as u64,
        ..Control::default()
    };
    let mut ctl: Array<_, Control> = Array::try_from(
        ebpf.map_mut("INV_BASELINE_CTL")
            .context("baseline control map")?,
    )?;
    ctl.set(0, control, 0)?;
    ensure!(
        ctl.get(&0, 0)? == control,
        "baseline control readback differs"
    );
    let pidfd_selector = host.supports_pidfd_iter_selector();
    let program = ebpf.program("p11_inventory_image_baseline").unwrap().fd()?;
    let link = task_link(
        program.as_fd(),
        if count == 1 && pidfd_selector {
            Some(original_at(0).pidfd()?)
        } else {
            None
        },
    )
    .map_err(|error| anyhow::anyhow!("baseline original-pidfd iterator link: {error:?}"))?;
    let iterator = super::super::identity_iter::iter_create(link.as_fd())?;
    let bytes = read_iterator(iterator.as_fd(), window.deadline(), (count + 1) * 40)
        .map_err(|error| anyhow::anyhow!("baseline stream: {error:?}"))?;
    let parsed = super::wire::parse_baseline(&bytes, generation, count, 65536)
        .context("baseline requires exact identity slots and END")?;
    let ctl: Array<_, Control> = Array::try_from(ebpf.map("INV_BASELINE_CTL").unwrap())?;
    let done = ctl.get(&0, 0)?;
    ensure!(
        done.generation == control.generation
            && done.deadline_ns == control.deadline_ns
            && done.visit_limit == control.visit_limit
            && done.count == control.count
            && done.failed == 0
            && done.emitted == control.count
            && done.visits == parsed.visits,
        "baseline completion readback differs"
    );
    for (slot, image) in parsed.images.iter().enumerate() {
        let pin = original_at(slot);
        ensure!(
            !pin.original_exited().map_err(anyhow::Error::msg)?,
            "baseline original process exited during query"
        );
        pin.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            super::super::InstanceMaps { ebpf }.cookie(pin.pidfd()?)? == Some(image.cookie),
            "baseline differs from original retained pidfd storage"
        );
    }
    check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))?;
    Ok(parsed.images)
}

#[cfg(test)]
#[path = "baseline_tests.rs"]
mod tests;
