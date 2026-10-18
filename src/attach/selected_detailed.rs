//! SPDX-License-Identifier: GPL-3.0-or-later
//! Closed selected Detailed preparation. Native integration is deliberately
//! unavailable until the real coordinator activation proof is connected.

#[cfg(test)]
mod native_tests;

pub(crate) mod baseline;
mod wire;
use wire::{BootstrapControl, SelectedTarget};

pub(super) const PROGRAMS: [&str; 2] = ["p11_selected_bootstrap", "p11_selected_cgroup_migrate"];
// SAFETY: repr(C) integer-only fields, explicit size assertions in wire.rs.
unsafe impl aya::Pod for SelectedTarget {}
// SAFETY: repr(C) integer-only fields, explicit size assertions in wire.rs.
unsafe impl aya::Pod for BootstrapControl {}

pub(super) fn validate_maps(ebpf: &aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context as _;
    for (name, size, flags) in [
        ("SELECTED_DETAILED", 32, super::BPF_F_RDONLY_PROG),
        ("SELECTED_DETAILED_STATE", 8, super::BPF_F_MMAPABLE),
        ("SELECTED_BOOTSTRAP_CTL", 48, 0),
    ] {
        let data =
            super::policy_map_data(name, ebpf.map(name).with_context(|| format!("{name} map"))?)?;
        super::validate_map_metadata(
            name,
            data,
            super::map_metadata(aya::maps::MapType::Array, 4, size, 1, flags),
        )?;
    }
    Ok(())
}

use anyhow::{Context as _, Result, bail, ensure};
use aya::maps::Array;
use p11scope_ebpf_common::ImageIdentity;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

const CLOSED: u64 = 1;
const TERMINAL: u64 = 3;

/// An owned fd moves safely with Session. Atomic mappings are short lived and
/// never cross a thread boundary; no new unsafe Send/Sync promise is needed.
struct StateControl(OwnedFd);
impl StateControl {
    fn new(fd: BorrowedFd<'_>) -> Result<Self> {
        Ok(Self(fd.try_clone_to_owned()?))
    }
    fn with_cell<R>(&self, run: impl FnOnce(&AtomicU64) -> R) -> Result<R> {
        let len = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        ensure!(len >= 8, "invalid selected state page size");
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.0.as_raw_fd(),
                0,
            )
        };
        ensure!(
            base != libc::MAP_FAILED,
            "mapping selected state: {}",
            std::io::Error::last_os_error()
        );
        struct Mapping(*mut libc::c_void, usize);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, self.1);
                }
            }
        }
        let _mapping = Mapping(base, len);
        // SAFETY: mmap succeeded, is page aligned, and remains owned above.
        Ok(run(unsafe { &*base.cast::<AtomicU64>() }))
    }
    fn closed(&self) -> Result<()> {
        ensure!(
            self.with_cell(|cell| cell.load(Ordering::SeqCst))? == CLOSED,
            "selected preparation is no longer closed"
        );
        Ok(())
    }
    fn close(&self) -> Result<()> {
        self.with_cell(|cell| {
            let _ = cell.compare_exchange(CLOSED, TERMINAL, Ordering::SeqCst, Ordering::SeqCst);
            let _ = cell.compare_exchange(2, TERMINAL, Ordering::SeqCst, Ordering::SeqCst);
        })
    }
}

/// Native control stays inside its original Session. This is NOT a final
/// activation proof and deliberately has no activation method yet.
pub(super) struct NativeSelection {
    state: StateControl,
    target: SelectedTarget,
}
impl NativeSelection {
    pub(super) fn publish(
        ebpf: &mut aya::Ebpf,
        parent: &super::Scope,
        selected: Option<&crate::process::PidPin>,
    ) -> Result<Option<Self>> {
        validate_maps(ebpf)?;
        let target_map = || -> Result<Array<_, SelectedTarget>> {
            Ok(Array::try_from(
                ebpf.map("SELECTED_DETAILED")
                    .context("selected target map")?,
            )?)
        };
        ensure!(
            target_map()?.get(&0, 0)? == SelectedTarget::default(),
            "selected target was not zero before links"
        );
        let ctl: Array<_, BootstrapControl> = Array::try_from(
            ebpf.map("SELECTED_BOOTSTRAP_CTL")
                .context("selected bootstrap map")?,
        )?;
        ensure!(
            ctl.get(&0, 0)? == BootstrapControl::default(),
            "selected bootstrap was not zero before links"
        );
        let data = super::policy_map_data(
            "SELECTED_DETAILED_STATE",
            ebpf.map("SELECTED_DETAILED_STATE")
                .context("selected state map")?,
        )?;
        let state = StateControl::new(data.fd().as_fd())?;
        ensure!(
            state.with_cell(|cell| cell.load(Ordering::SeqCst))? == 0,
            "selected state was not zero before links"
        );
        let Some(pin) = selected else {
            super::freeze_map("SELECTED_DETAILED", ebpf.map("SELECTED_DETAILED").unwrap())?;
            return Ok(None);
        };
        pin.pidfd()
            .context("selected target requires the original pidfd")?;
        pin.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            !pin.original_exited().map_err(anyhow::Error::msg)?,
            "selected target exited"
        );
        let parent_kind = match parent {
            super::Scope::Pid(pid) => {
                ensure!(*pid == pin.pid(), "selected target is outside PID parent");
                1
            }
            super::Scope::System => 3,
            super::Scope::Cgroup { .. } => {
                bail!("selected cgroup migration hook coverage is not qualified")
            }
        };
        let target = SelectedTarget {
            mode: 1,
            tgid: pin.pid(),
            parent_kind,
            ..SelectedTarget::default()
        };
        let mut map: Array<_, SelectedTarget> =
            Array::try_from(ebpf.map_mut("SELECTED_DETAILED").unwrap())?;
        map.set(0, target, 0)?;
        ensure!(
            map.get(&0, 0)? == target,
            "selected pre-link target readback differs"
        );
        state
            .with_cell(|cell| cell.compare_exchange(0, CLOSED, Ordering::SeqCst, Ordering::SeqCst))?
            .map_err(|_| anyhow::anyhow!("selected state changed before links"))?;
        state.closed()?;
        Ok(Some(Self { state, target }))
    }
    pub(super) fn require_closed(&self) -> Result<()> {
        self.state.closed()
    }
    pub(super) fn complete_identity(
        &mut self,
        ebpf: &mut aya::Ebpf,
        image: ImageIdentity,
    ) -> Result<()> {
        self.state.closed()?;
        ensure!(
            (1..=p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT).contains(&image.task_cookie),
            "invalid selected identity cookie"
        );
        self.target.cookie = image.task_cookie;
        self.target.exec_id = image.exec_id;
        let mut map: Array<_, SelectedTarget> = Array::try_from(
            ebpf.map_mut("SELECTED_DETAILED")
                .context("selected target map")?,
        )?;
        map.set(0, self.target, 0)?;
        ensure!(
            map.get(&0, 0)? == self.target,
            "selected full identity readback differs"
        );
        super::freeze_map("SELECTED_DETAILED", ebpf.map("SELECTED_DETAILED").unwrap())?;
        self.state.closed()
    }
    pub(super) fn close(&self) -> Result<()> {
        self.state.close()
    }
}
impl Drop for NativeSelection {
    fn drop(&mut self) {
        let _ = self.state.close();
    }
}

pub(super) fn load_bootstrap(ebpf: &mut aya::Ebpf, btf: &aya::Btf) -> Result<()> {
    let program: &mut aya::programs::Iter = ebpf
        .program_mut("p11_selected_bootstrap")
        .context("selected bootstrap program")?
        .try_into()?;
    program
        .load("task", btf)
        .context("loading selected identity-only task iterator")
}

/// No user memory, call START or semantic permission is acquired here.
fn bootstrap(
    session: &mut super::Session,
    pin: &crate::process::PidPin,
    window: super::capture::ReadWindow,
) -> Result<ImageIdentity> {
    super::image_query::check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("selected bootstrap deadline: {error:?}"))?;
    ensure!(
        crate::pidns::numbering().agrees(),
        "selected bootstrap PID numbering disagrees"
    );
    session
        .native_selection
        .as_ref()
        .context("selected native owner missing")?
        .require_closed()?;
    session
        .audit_image_continuity()
        .map_err(|error| anyhow::anyhow!("selected image coverage: {error:?}"))?;
    let _proc = pin.open_proc_dir().map_err(anyhow::Error::msg)?;
    ensure!(
        !pin.original_exited().map_err(anyhow::Error::msg)?,
        "selected original process exited"
    );
    let control = BootstrapControl {
        generation: 1,
        deadline_ns: super::image_query::conservative_deadline(window.deadline())
            .map_err(|error| anyhow::anyhow!("selected deadline: {error:?}"))?,
        visit_limit: 65536,
        ..BootstrapControl::default()
    };
    let mut map: Array<_, BootstrapControl> = Array::try_from(
        session
            .ebpf
            .map_mut("SELECTED_BOOTSTRAP_CTL")
            .context("selected bootstrap map")?,
    )?;
    map.set(0, control, 0)?;
    ensure!(
        map.get(&0, 0)? == control,
        "selected bootstrap request readback differs"
    );
    let btf = aya::Btf::from_sys_fs()?;
    let pidfd_selector = btf
        .id_by_type_name_kind("bpf_iter_attach_task", aya_obj::btf::BtfKind::Func)
        .is_ok();
    let program = session
        .ebpf
        .program("p11_selected_bootstrap")
        .context("selected bootstrap program")?
        .fd()?;
    let link = super::image_query::task_link(
        program.as_fd(),
        if pidfd_selector {
            Some(pin.pidfd()?)
        } else {
            None
        },
    )
    .map_err(|error| anyhow::anyhow!("selected original-pidfd task link: {error:?}"))?;
    let iterator = super::identity_iter::iter_create(link.as_fd())?;
    let bytes = super::image_query::read_iterator(iterator.as_fd(), window.deadline(), 80)
        .map_err(|error| anyhow::anyhow!("selected bootstrap stream: {error:?}"))?;
    let image = wire::parse_bootstrap(&bytes, control.generation, pin.pid(), control.visit_limit)
        .context("selected bootstrap requires one exact identity and END")?;
    let map: Array<_, BootstrapControl> = Array::try_from(
        session
            .ebpf
            .map("SELECTED_BOOTSTRAP_CTL")
            .context("selected bootstrap map")?,
    )?;
    let done = map.get(&0, 0)?;
    ensure!(
        done.generation == control.generation
            && done.deadline_ns == control.deadline_ns
            && done.visit_limit == control.visit_limit
            && done.emitted == 1
            && done.failed == 0
            && done.visits == image.visits,
        "selected bootstrap completion readback differs"
    );
    ensure!(
        !pin.original_exited().map_err(anyhow::Error::msg)?,
        "selected original process exited during bootstrap"
    );
    pin.open_proc_dir().map_err(anyhow::Error::msg)?;
    ensure!(
        session.instance_maps().cookie(pin.pidfd()?)? == Some(image.cookie),
        "selected bootstrap differs from original retained pidfd task storage"
    );
    session
        .audit_image_continuity()
        .map_err(|error| anyhow::anyhow!("selected image coverage: {error:?}"))?;
    session
        .native_selection
        .as_ref()
        .context("selected native owner missing")?
        .require_closed()?;
    super::image_query::check_deadline(window.deadline())
        .map_err(|error| anyhow::anyhow!("selected bootstrap deadline: {error:?}"))?;
    Ok(ImageIdentity {
        task_cookie: image.cookie,
        exec_id: image.exec_id,
    })
}
