//! Loading and attaching. One uprobe + one uretprobe program serve every
//! slot; the attach cookie carries the slot index.

use crate::plan::AttachPlan;
use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};

/// Which processes the capture covers. Scope is always explicit.
#[derive(Debug, Clone)]
pub enum Scope {
    Pid(u32),
    Cgroup(u64),
}

pub struct Session {
    pub ebpf: Ebpf,
    attach_failures: Vec<(u32, String)>,
    attached: usize,
}

impl Session {
    pub fn start(plan: &AttachPlan, scope: &Scope) -> Result<Self> {
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        crate::scope::apply(&mut ebpf, scope).context("installing scope filter")?;
        {
            let mut kinds: aya::maps::Array<_, u32> =
                aya::maps::Array::try_from(ebpf.map_mut("SLOT_KIND").context("SLOT_KIND map")?)?;
            for slot in &plan.slots {
                kinds.set(slot.index, slot.kind, 0)?;
            }
        }
        let uprobe_scope = match scope {
            Scope::Pid(pid) => UProbeScope::OneProcess(
                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
            ),
            // Cgroup scoping is enforced in BPF, so the probe itself is
            // process-wide and the filter map decides.
            Scope::Cgroup(_) => UProbeScope::AllProcesses,
        };

        let mut attach_failures = Vec::new();
        let mut attached = 0usize;

        for prog_name in ["p11_entry", "p11_return"] {
            let prog: &mut UProbe = ebpf
                .program_mut(prog_name)
                .with_context(|| format!("program {prog_name} missing from object"))?
                .try_into()?;
            prog.load().with_context(|| format!("loading {prog_name}"))?;
            for slot in &plan.slots {
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &slot.object, uprobe_scope) {
                    Ok(_) => attached += 1,
                    Err(e) => attach_failures.push((
                        slot.index,
                        format!("{prog_name} at {}+{:#x}: {e}", slot.object, slot.file_offset),
                    )),
                }
            }
        }

        Ok(Self { ebpf, attach_failures, attached })
    }

    /// Attach points that failed — reported as an evidence gap, never
    /// silently treated as zero calls.
    pub fn attach_failures(&self) -> &[(u32, String)] {
        &self.attach_failures
    }

    /// Successful attachments across both programs (2 per fully-attached slot).
    pub fn attached_probes(&self) -> usize {
        self.attached
    }
}
