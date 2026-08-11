//! Loading and attaching. One uprobe + one uretprobe program serve every
//! slot; the attach cookie carries the slot index.

use crate::plan::AttachPlan;
use anyhow::{Context as _, Result, anyhow};
use aya::Ebpf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;

/// Which processes the capture covers. Scope is always explicit.
#[derive(Debug, Clone)]
pub enum Scope {
    Pid(u32),
    /// Target cgroup id plus its ancestor level under `/sys/fs/cgroup`
    /// (root = 0). The level is what lets the BPF side match any
    /// descendant of the target, not just tasks in that exact cgroup —
    /// see `scope::cgroup_level`.
    Cgroup { id: u64, level: u32 },
}

pub struct Session {
    pub ebpf: Ebpf,
    attach_failures: Vec<(u32, String)>,
    attached: usize,
}

/// Renders `e` and every `.source()` beneath it, joined by `: `. Several
/// of aya's error variants (e.g. `ProgramError::SyscallError`) are
/// `#[error(transparent)]`, so `{e}` alone prints only the outer
/// message (`` `perf_event_open` failed ``) and silently drops the
/// actual OS error (`EPERM`/`EACCES`/...) that explains *why* — that
/// detail lives one level down in `.source()`. `anyhow`'s `{:#}` does
/// this same walk for an `anyhow::Error`; this is the equivalent for a
/// plain `std::error::Error` this code does not otherwise wrap, so the
/// per-slot attach failure text below is not silently missing the one
/// fact an operator needs (was it a permission error, and which one).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        msg.push_str(": ");
        msg.push_str(&src.to_string());
        cur = src.source();
    }
    msg
}

/// A kernel/environment that cannot load or attach BPF programs at all
/// fails somewhere in `start_inner` below (map creation, program load,
/// or the mechanism registry step never reaches that far) — never at
/// the per-slot attach loop, which is reached only after those succeed.
/// Every realistic cause at that point is an unsupported-environment
/// one, so every early failure gets the same actionable hint appended,
/// naming the concrete things to check instead of leaving a bare
/// syscall error for the operator to diagnose alone.
const UNSUPPORTED_ENV_HINT: &str = "hint: this usually means the environment cannot load or \
attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel \
lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF \
(/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See \
docs/notes/phase5-unsupported.md for what each looks like when observed.";

impl Session {
    pub fn start(plan: &AttachPlan, scope: &Scope) -> Result<Self> {
        Self::start_inner(plan, scope).map_err(|e| anyhow!("{e:#}\n{UNSUPPORTED_ENV_HINT}"))
    }

    fn start_inner(plan: &AttachPlan, scope: &Scope) -> Result<Self> {
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        crate::scope::apply(&mut ebpf, scope).context("installing scope filter")?;
        {
            let mut kinds: aya::maps::Array<_, u32> =
                aya::maps::Array::try_from(ebpf.map_mut("SLOT_KIND").context("SLOT_KIND map")?)?;
            for slot in &plan.slots {
                kinds.set(slot.index, slot.kind, 0)?;
            }
        }
        {
            // Embedded defaults: this binary ships statically and has no
            // config-file plumbing yet, so `None` is the only reachable
            // path today. A future task can thread a path through here
            // without touching the publish-before-attach placement.
            let registry = MechanismRegistry::load(None)
                .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
            crate::shapes::publish(&mut ebpf, &registry).context("publishing MECH_SHAPE")?;
        }
        let uprobe_scope = match scope {
            Scope::Pid(pid) => UProbeScope::OneProcess(
                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
            ),
            // Cgroup scoping is enforced in BPF, so the probe itself is
            // process-wide and the filter map decides.
            Scope::Cgroup { .. } => UProbeScope::AllProcesses,
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
                        format!(
                            "{prog_name} at {}+{:#x}: {}",
                            slot.object,
                            slot.file_offset,
                            error_chain(&e)
                        ),
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
