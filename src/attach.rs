//! Loading and attaching. One selected entry uprobe + one uretprobe serve
//! each slot; the attach cookie carries the slot index.

use crate::plan::AttachPlan;
use crate::verify::VerifiedObjects;
use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::ProgramArray;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
use aya::programs::{TracePoint, UProbe};
use p11scope_ebpf_common::{
    ARG_NONE, FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED,
    FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, SlotSemantics,
};
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;
use std::path::PathBuf;

/// Which processes the capture covers. Scope is always explicit.
#[derive(Debug, Clone)]
pub enum Scope {
    Pid(u32),
    /// Native cgroup-array membership matches this cgroup and descendants.
    Cgroup {
        id: u64,
        path: PathBuf,
    },
}

/// Immutable capture behavior selected by userspace before attachment.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapturePolicy {
    Allowlisted,
    UnsafeUnvalidatedMetadata,
    AggregateOnly,
}

impl CapturePolicy {
    pub const fn config_bit(self) -> u64 {
        match self {
            Self::Allowlisted => FLAG_POLICY_ALLOWLISTED,
            Self::UnsafeUnvalidatedMetadata => FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
            Self::AggregateOnly => FLAG_POLICY_AGGREGATE,
        }
    }

    pub const fn privacy_mode(self) -> &'static str {
        match self {
            Self::Allowlisted => "allowlisted",
            Self::UnsafeUnvalidatedMetadata => "unsafe-unvalidated-metadata",
            Self::AggregateOnly => "aggregate-only",
        }
    }

    pub const fn uses_events(self) -> bool {
        !matches!(self, Self::AggregateOnly)
    }

    pub const fn uses_unsafe_decoders(self) -> bool {
        matches!(self, Self::UnsafeUnvalidatedMetadata)
    }
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

fn entry_program(semantics: &SlotSemantics) -> &'static str {
    if semantics.template1_arg != ARG_NONE {
        "p11_entry_template_pair"
    } else if semantics.semantic_flags & p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY
        != 0
    {
        "p11_entry_template_types"
    } else if semantics.template0_arg != ARG_NONE {
        "p11_entry_template"
    } else {
        "p11_entry"
    }
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
    pub fn start(plan: &AttachPlan, scope: &Scope, objects: &VerifiedObjects) -> Result<Self> {
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("checking authorized provider objects before attach")?;
        let session = Self::start_inner(plan, scope, objects)
            .map_err(|e| anyhow!("{e:#}\n{UNSUPPORTED_ENV_HINT}"))?;
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("checking authorized provider objects after attach")?;
        Ok(session)
    }

    fn start_inner(plan: &AttachPlan, scope: &Scope, objects: &VerifiedObjects) -> Result<Self> {
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        crate::scope::apply(&mut ebpf, scope).context("installing scope filter")?;
        {
            let mut semantics: aya::maps::Array<_, p11scope_ebpf_common::SlotSemantics> =
                aya::maps::Array::try_from(
                    ebpf.map_mut("SLOT_SEMANTICS")
                        .context("SLOT_SEMANTICS map")?,
                )?;
            for slot in &plan.slots {
                if let Some(index) = slot.semantics.argument_indices().find(|index| *index > 6) {
                    bail!(
                        "slot {} requests forbidden argument index {index}",
                        slot.index
                    );
                }
                semantics.set(slot.index, slot.semantics, 0)?;
            }
        }
        {
            let fields = pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
                .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS);
            let mut hashes = std::collections::BTreeMap::new();
            let mut names: aya::maps::HashMap<_, u64, u32> = aya::maps::HashMap::try_from(
                ebpf.map_mut("ASYNC_FUNCTIONS")
                    .context("ASYNC_FUNCTIONS map")?,
            )?;
            for (id, field) in fields.enumerate() {
                let hash = p11scope_ebpf_common::function_name_hash(field.name);
                if let Some(previous) = hashes.insert(hash, field.name) {
                    bail!(
                        "standard function-name hash collision: {previous} and {}",
                        field.name
                    );
                }
                names.insert(hash, id as u32, 0)?;
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
        {
            let mut bits: aya::maps::HashMap<_, u32, u32> = aya::maps::HashMap::try_from(
                ebpf.map_mut("ATTR_BOOL_BITS")
                    .context("ATTR_BOOL_BITS map")?,
            )?;
            for (attribute, bit) in p11scope_ebpf_common::attr_bool::TYPES_AND_BITS {
                bits.insert(attribute, 1u32 << bit, 0)?;
            }
        }
        let uprobe_scope = match scope {
            Scope::Pid(pid) => UProbeScope::OneProcess(
                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
            ),
            // Cgroup scoping is enforced in BPF, so the probe itself is
            // process-wide and the filter map decides.
            Scope::Cgroup { .. } => UProbeScope::AllProcesses,
        };

        if matches!(scope, Scope::Cgroup { .. }) {
            let fork: &mut TracePoint = ebpf
                .program_mut("sched_process_fork")
                .context("program sched_process_fork missing from object")?
                .try_into()?;
            fork.load().context("loading sched_process_fork")?;
            fork.attach("sched", "sched_process_fork")
                .context("attaching sched_process_fork")?;
        }

        let mut attach_failures = Vec::new();
        let mut attached = 0usize;
        let attach_paths: Vec<PathBuf> = plan
            .slots
            .iter()
            .map(|slot| {
                objects
                    .attach_path(&slot.object)
                    .map_err(anyhow::Error::msg)
            })
            .collect::<Result<_>>()?;

        for prog_name in [
            "p11_return",
            "p11_entry",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
            "p11_entry_template_second",
        ] {
            let prog: &mut UProbe = ebpf
                .program_mut(prog_name)
                .with_context(|| format!("program {prog_name} missing from object"))?
                .try_into()?;
            prog.load()
                .with_context(|| format!("loading {prog_name}"))?;
        }
        {
            let tail_fd = {
                let tail: &UProbe = ebpf
                    .program("p11_entry_template_second")
                    .context("program p11_entry_template_second missing from object")?
                    .try_into()?;
                tail.fd()?.try_clone()?
            };
            let mut tails: ProgramArray<_> = ProgramArray::try_from(
                ebpf.map_mut("TEMPLATE_TAIL").context("TEMPLATE_TAIL map")?,
            )?;
            tails.set(0, &tail_fd, 0)?;
        }

        let mut return_attached = vec![false; plan.slots.len()];
        {
            let prog: &mut UProbe = ebpf.program_mut("p11_return").unwrap().try_into()?;
            for (position, slot) in plan.slots.iter().enumerate() {
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &attach_paths[position], uprobe_scope) {
                    Ok(_) => {
                        attached += 1;
                        return_attached[position] = true;
                    }
                    Err(e) => attach_failures.push((
                        slot.index,
                        format!(
                            "p11_return at {}+{:#x}: {}",
                            slot.object,
                            slot.file_offset,
                            error_chain(&e)
                        ),
                    )),
                }
            }
        }
        for prog_name in [
            "p11_entry",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ] {
            let prog: &mut UProbe = ebpf.program_mut(prog_name).unwrap().try_into()?;
            for (position, slot) in plan.slots.iter().enumerate() {
                if !return_attached[position] || entry_program(&slot.semantics) != prog_name {
                    continue;
                }
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &attach_paths[position], uprobe_scope) {
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

        Ok(Self {
            ebpf,
            attach_failures,
            attached,
        })
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

#[cfg(test)]
mod capture_policy {
    use super::CapturePolicy;

    #[test]
    fn capture_policies_have_distinct_bits_and_visible_behavior() {
        let policies = [
            (CapturePolicy::Allowlisted, "allowlisted", true, false),
            (
                CapturePolicy::UnsafeUnvalidatedMetadata,
                "unsafe-unvalidated-metadata",
                true,
                true,
            ),
            (CapturePolicy::AggregateOnly, "aggregate-only", false, false),
        ];

        for (policy, privacy_mode, uses_events, uses_unsafe_decoders) in policies {
            assert_eq!(policy.privacy_mode(), privacy_mode);
            assert_eq!(policy.uses_events(), uses_events);
            assert_eq!(policy.uses_unsafe_decoders(), uses_unsafe_decoders);
        }
        assert_ne!(
            CapturePolicy::Allowlisted.config_bit(),
            CapturePolicy::UnsafeUnvalidatedMetadata.config_bit()
        );
        assert_ne!(
            CapturePolicy::Allowlisted.config_bit(),
            CapturePolicy::AggregateOnly.config_bit()
        );
        assert_ne!(
            CapturePolicy::UnsafeUnvalidatedMetadata.config_bit(),
            CapturePolicy::AggregateOnly.config_bit()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{ARG_NONE, SlotSemantics};

    #[test]
    fn entry_program_is_selected_by_template_capture() {
        assert_eq!(entry_program(&SlotSemantics::COUNT_ONLY), "p11_entry");

        let mut template = SlotSemantics::COUNT_ONLY;
        template.template0_arg = 1;
        assert_eq!(entry_program(&template), "p11_entry_template");

        let mut second_template = SlotSemantics::COUNT_ONLY;
        second_template.template0_arg = 2;
        second_template.template1_arg = 4;
        assert_eq!(entry_program(&second_template), "p11_entry_template_pair");

        let mut types_only = SlotSemantics::COUNT_ONLY;
        types_only.template0_arg = 2;
        types_only.semantic_flags = p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY;
        assert_eq!(entry_program(&types_only), "p11_entry_template_types");

        let mut async_call = SlotSemantics::COUNT_ONLY;
        async_call.async_name_arg = 1;
        assert_ne!(async_call.async_name_arg, ARG_NONE);
        assert_eq!(entry_program(&async_call), "p11_entry");
    }
}
