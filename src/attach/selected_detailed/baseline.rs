//! SPDX-License-Identifier: GPL-3.0-or-later
//! Inventory-domain kernel image acquisition. Results are private identity
//! facts; the view/request binder must qualify them before Detailed preparation.
use super::super::capture::{NativeDomainId, ReadWindow};
use crate::process::{PidPin, WeakProcessCustody};
use anyhow::{Context as _, Result, ensure};
use aya::maps::{Array, HashMap};
use std::os::fd::AsFd as _;
use std::sync::Arc;

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

struct ImageRow {
    original: WeakProcessCustody,
    cookie: u64,
    exec_id: u64,
}
/// Constructed only after the actual native iterator and original-pidfd checks.
/// No public numeric constructor, Clone, raw image getter or serialization.
pub(crate) struct KernelBaselineBatch {
    domain: NativeDomainId,
    generation: u64,
    rows: Vec<ImageRow>,
}
impl std::fmt::Debug for KernelBaselineBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KernelBaselineBatch(<retained>)")
    }
}

/// The view/request binder (next integration seam) alone will construct this
/// wrapper over an actual KernelBaselineBatch. No post-click query can create
/// a displayed-view receipt; no constructor is exposed here.
pub(crate) struct PromotionImageBaseline {
    core: Arc<KernelBaselineBatch>,
    row: usize,
}
impl PromotionImageBaseline {
    pub(crate) fn matches_original_and_exec(
        &self,
        original: &Arc<PidPin>,
        full_exec_id: u64,
    ) -> bool {
        self.core.rows.get(self.row).is_some_and(|row| {
            row.exec_id == full_exec_id && row.original.matches_original(original)
        })
    }
}
impl std::fmt::Debug for PromotionImageBaseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromotionImageBaseline(<retained>)")
    }
}

/// Called under the exclusive Inventory capture borrow, on explicit baseline
/// work only. Loading the iterator is deferred so ordinary startup is unchanged.
pub(crate) fn query(
    ebpf: &mut aya::Ebpf,
    domain: NativeDomainId,
    generation: u64,
    pins: &[Arc<PidPin>],
    window: ReadWindow,
) -> Result<KernelBaselineBatch> {
    use super::super::image_query::{
        check_deadline, conservative_deadline, read_iterator, task_link,
    };
    ensure!(
        generation != 0 && !pins.is_empty() && pins.len() <= window.max_rows().min(1024),
        "baseline window/capacity/generation refused"
    );
    ensure!(
        crate::pidns::numbering().agrees(),
        "baseline PID numbering disagrees"
    );
    check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))?;
    let mut seen = std::collections::BTreeSet::new();
    for pin in pins {
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
    let btf = aya::Btf::from_sys_fs()?;
    let program: &mut aya::programs::Iter = ebpf
        .program_mut("p11_inventory_image_baseline")
        .context("Inventory image baseline program unavailable")?
        .try_into()?;
    if program.fd().is_err() {
        program
            .load("task", &btf)
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
    for (slot, pin) in pins.iter().enumerate() {
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
    for (slot, pin) in pins.iter().enumerate() {
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
        count: pins.len() as u64,
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
    let pidfd_selector = btf
        .id_by_type_name_kind("bpf_iter_attach_task", aya_obj::btf::BtfKind::Func)
        .is_ok();
    let program = ebpf.program("p11_inventory_image_baseline").unwrap().fd()?;
    let link = task_link(
        program.as_fd(),
        if pins.len() == 1 && pidfd_selector {
            Some(pins[0].pidfd()?)
        } else {
            None
        },
    )
    .map_err(|error| anyhow::anyhow!("baseline original-pidfd iterator link: {error:?}"))?;
    let iterator = super::super::identity_iter::iter_create(link.as_fd())?;
    let bytes = read_iterator(iterator.as_fd(), window.deadline(), (pins.len() + 1) * 40)
        .map_err(|error| anyhow::anyhow!("baseline stream: {error:?}"))?;
    let parsed = super::wire::parse_baseline(&bytes, generation, pins.len(), 65536)
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
    let mut rows = Vec::with_capacity(pins.len());
    for (pin, image) in pins.iter().zip(parsed.images) {
        ensure!(
            !pin.original_exited().map_err(anyhow::Error::msg)?,
            "baseline original process exited during query"
        );
        pin.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            super::super::InstanceMaps { ebpf }.cookie(pin.pidfd()?)? == Some(image.cookie),
            "baseline differs from original retained pidfd storage"
        );
        rows.push(ImageRow {
            original: PidPin::downgrade_shared(pin)
                .context("baseline original custody charge unavailable")?,
            cookie: image.cookie,
            exec_id: image.exec_id,
        });
    }
    check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("baseline deadline: {error:?}"))?;
    Ok(KernelBaselineBatch {
        domain,
        generation,
        rows,
    })
}
