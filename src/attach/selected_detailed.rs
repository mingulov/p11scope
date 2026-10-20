//! SPDX-License-Identifier: GPL-3.0-or-later
//! Closed selected Detailed preparation. Native integration is deliberately
//! unavailable until the real coordinator activation proof is connected.

#[cfg(test)]
mod native_tests;

#[cfg(test)]
mod activation_tests {
    use super::*;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::FileExt as _;

    fn state_cell(initial: u64) -> (StateControl, std::fs::File) {
        // SAFETY: valid NUL-terminated name, no pointers escape the syscall.
        let fd =
            unsafe { libc::memfd_create(c"p11scope-selected-state".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: memfd_create returned a fresh owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let page =
            usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).expect("page size");
        file.set_len(page as u64).expect("size state backing");
        file.write_at(&initial.to_le_bytes(), 0)
            .expect("seed state");
        let control = StateControl::new(file.as_fd()).expect("wrap state fd");
        (control, file)
    }

    fn load(file: &std::fs::File) -> u64 {
        let mut word = [0u8; 8];
        file.read_at(&mut word, 0).expect("read state");
        u64::from_le_bytes(word)
    }

    #[test]
    fn active_value_matches_bpf_gate() {
        // The BPF gate (crates/ebpf/native/selected_detailed.h) admits
        // capture only at SELECTED_ACTIVE == 2; the C host test pins the
        // 1->2 CAS there. This pins the userspace mirror.
        assert_eq!(ACTIVE, 2);
        assert_eq!(CLOSED, 1);
        assert_eq!(TERMINAL, 3);
    }

    #[test]
    fn activation_wins_only_from_closed() {
        let (control, file) = state_cell(CLOSED);
        control.activate().expect("closed activates");
        assert_eq!(load(&file), ACTIVE);
        control.active().expect("active readback");
        assert!(control.closed().is_err());
        assert!(control.activate().is_err(), "second activation loses");
        assert_eq!(load(&file), ACTIVE);
    }

    #[test]
    fn activation_refuses_zero_and_terminal_without_mutation() {
        for initial in [0, TERMINAL, 99] {
            let (control, file) = state_cell(initial);
            assert!(control.activate().is_err());
            assert_eq!(load(&file), initial);
            assert!(control.active().is_err());
        }
    }

    #[test]
    fn close_after_active_reaches_terminal() {
        let (control, file) = state_cell(CLOSED);
        control.activate().expect("closed activates");
        control.close().expect("close active");
        assert_eq!(load(&file), TERMINAL);
        control.terminal().expect("terminal readback");
        assert!(control.activate().is_err());
        control.close().expect("close is idempotent");
        assert_eq!(load(&file), TERMINAL);
    }

    #[test]
    fn activation_race_never_manufactures_state() {
        for _ in 0..32 {
            let (control, file) = state_cell(CLOSED);
            let control = std::sync::Arc::new(control);
            // At most one winner per round; the loser refused honestly.
            std::thread::scope(|scope| {
                let worker = std::sync::Arc::clone(&control);
                let activated = scope.spawn(move || worker.activate().is_ok());
                control.close().expect("racy close");
                activated.join().expect("join racy activation")
            });
            let final_word = load(&file);
            assert!(
                final_word == ACTIVE || final_word == TERMINAL,
                "unexpected state {final_word}"
            );
            // Settlement is one-way from here.
            control.close().expect("settle");
            assert_eq!(load(&file), TERMINAL);
        }
    }

    #[test]
    fn selection_activation_requires_bound_original() {
        let (state, file) = state_cell(CLOSED);
        let selection = NativeSelection {
            state,
            target: SelectedTarget::default(),
            original: None,
            parent: None,
        };
        let error = selection
            .activate()
            .expect_err("unbound activation refuses");
        assert!(
            format!("{error:#}").contains("without bound original custody"),
            "unexpected refusal: {error:#}"
        );
        assert_eq!(load(&file), CLOSED);
    }

    /// DR37 native-minter twins: the production [`NativeActivationSource`]
    /// core mints only for a bound, live, still-closed selection whose
    /// domain and image name the expected binding, with readback. The
    /// state cell is a real mmapable fd (the `StateControl` mapping
    /// path), the original is a real pinned process, the CAS is the
    /// genuine `CLOSED -> ACTIVE` exchange: only BPF publication itself
    /// is absent.
    fn minter_target(cookie: u64, exec_id: u64) -> SelectedTarget {
        SelectedTarget {
            mode: 1,
            tgid: std::process::id(),
            cookie,
            exec_id,
            parent_kind: 1,
        }
    }

    fn minter_selection(
        initial: u64,
        target: SelectedTarget,
        original: Option<std::sync::Arc<crate::process::PidPin>>,
    ) -> (NativeSelection, std::fs::File) {
        let (state, file) = state_cell(initial);
        (
            NativeSelection {
                state,
                target,
                original,
                parent: None,
            },
            file,
        )
    }

    fn minter_binding(
        domain: crate::attach::capture::NativeDomainId,
        cookie: u64,
        exec_id: u64,
    ) -> crate::inventory_promotion::lifecycle::SelectedActivationBinding {
        crate::inventory_promotion::lifecycle::SelectedActivationBinding::new(
            domain,
            7,
            p11scope_ebpf_common::ImageIdentity {
                task_cookie: cookie,
                exec_id,
            },
        )
    }

    fn live_original() -> std::sync::Arc<crate::process::PidPin> {
        std::sync::Arc::new(
            crate::process::PidPin::open(std::process::id()).expect("the test process pins itself"),
        )
    }

    #[test]
    fn minter_activates_bound_closed_selection_with_readback() {
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
        let (selection, file) =
            minter_selection(CLOSED, minter_target(9, 10), Some(live_original()));
        let expected = minter_binding(domain, 9, 10);
        let receipt = activate_native_selection(Some(&selection), Some(domain), &expected)
            .expect("bound closed selection activates");
        assert!(
            receipt.matches(expected),
            "the minted receipt names the activated binding"
        );
        assert_eq!(load(&file), ACTIVE);
        // Exactly once: the second CAS loses honestly instead of
        // manufacturing a second receipt.
        assert!(
            matches!(
                activate_native_selection(Some(&selection), Some(domain), &expected),
                Err(NativeActivationRefusal::NotClosed)
            ),
            "a second activation loses"
        );
        assert_eq!(load(&file), ACTIVE);
    }

    #[test]
    fn minter_refuses_foreign_binding_without_mutation() {
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
        let foreign = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
        assert_ne!(domain, foreign);
        for expected in [
            minter_binding(foreign, 9, 10),
            minter_binding(domain, 11, 10),
            minter_binding(domain, 9, 12),
        ] {
            let (selection, file) =
                minter_selection(CLOSED, minter_target(9, 10), Some(live_original()));
            assert!(
                matches!(
                    activate_native_selection(Some(&selection), Some(domain), &expected),
                    Err(NativeActivationRefusal::BindingMismatch)
                ),
                "foreign binding refuses"
            );
            assert_eq!(load(&file), CLOSED);
        }
        // No domain at all (no image owner published) disagrees too.
        let (selection, file) =
            minter_selection(CLOSED, minter_target(9, 10), Some(live_original()));
        assert!(
            matches!(
                activate_native_selection(Some(&selection), None, &minter_binding(domain, 9, 10)),
                Err(NativeActivationRefusal::BindingMismatch)
            ),
            "missing domain refuses"
        );
        assert_eq!(load(&file), CLOSED);
    }

    #[test]
    fn minter_refuses_unpublished_and_settled_cells_without_mutation() {
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
        let expected = minter_binding(domain, 9, 10);
        // Never published: no selection exists.
        assert!(
            matches!(
                activate_native_selection(None, Some(domain), &expected),
                Err(NativeActivationRefusal::NotClosed)
            ),
            "unpublished selection refuses"
        );
        // Already active or terminal: the CAS precondition is gone.
        for initial in [ACTIVE, TERMINAL, 0, 99] {
            let (selection, file) =
                minter_selection(initial, minter_target(9, 10), Some(live_original()));
            assert!(
                matches!(
                    activate_native_selection(Some(&selection), Some(domain), &expected),
                    Err(NativeActivationRefusal::NotClosed)
                ),
                "non-closed cell refuses"
            );
            assert_eq!(load(&file), initial);
        }
    }

    #[test]
    fn minter_refuses_dead_original_without_mutation() {
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
        let expected = minter_binding(domain, 9, 10);
        // A child pinned live, then reaped: the pid cannot be reused
        // before the wait, so the pin names exactly the exited child.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn a short-lived child");
        let pid = child.id();
        let pin = crate::process::PidPin::open(pid).expect("pin the live child");
        assert!(child.wait().expect("reap the child").success());
        assert!(
            pin.original_exited().expect("exit reads"),
            "the reaped child reads exited"
        );
        let target = SelectedTarget {
            mode: 1,
            tgid: pid,
            cookie: 9,
            exec_id: 10,
            parent_kind: 1,
        };
        let (selection, file) = minter_selection(CLOSED, target, Some(std::sync::Arc::new(pin)));
        // Unbound custody refuses the same closed way.
        let (unbound, unbound_file) = minter_selection(CLOSED, minter_target(9, 10), None);
        for (selection, file) in [(&selection, &file), (&unbound, &unbound_file)] {
            assert!(
                matches!(
                    activate_native_selection(Some(selection), Some(domain), &expected),
                    Err(NativeActivationRefusal::NotClosed)
                ),
                "dead or missing original refuses"
            );
            assert_eq!(load(file), CLOSED);
        }
    }
}

pub(crate) mod baseline;
mod failure;
mod lifecycle;
pub(super) mod multi;
pub(crate) use failure::{SelectedCleanupStatus, SelectedPreparationFailure};
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
        ("SELECTED_DETAIL", 32, super::BPF_F_RDONLY_PROG),
        ("SELECTED_DSTATE", 8, super::BPF_F_MMAPABLE),
        ("SELECTED_BCTL", 48, 0),
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

use crate::inventory_promotion::lifecycle::{
    NativeActivationRefusal, NativeActivationSource, NativeCasReceipt, SelectedActivationBinding,
};
use anyhow::{Context as _, Result, bail, ensure};
use aya::maps::Array;
use p11scope_ebpf_common::ImageIdentity;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};

const CLOSED: u64 = 1;
// Mirrors SELECTED_ACTIVE in crates/ebpf/native/selected_detailed.h. The BPF
// gate admits capture only in this state; keep the values in lockstep.
const ACTIVE: u64 = 2;
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
            let _ = cell.compare_exchange(ACTIVE, TERMINAL, Ordering::SeqCst, Ordering::SeqCst);
        })
    }
    /// The sole CLOSED->ACTIVE activation CAS. Only a still-closed cell
    /// wins; a concurrent close (or a second activation) loses honestly
    /// instead of manufacturing an ACTIVE state.
    fn activate(&self) -> Result<()> {
        self.with_cell(|cell| {
            cell.compare_exchange(CLOSED, ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
        })?
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("selected preparation is no longer closed"))
    }
    fn active(&self) -> Result<()> {
        ensure!(
            self.with_cell(|cell| cell.load(Ordering::SeqCst))? == ACTIVE,
            "selected preparation is not active"
        );
        Ok(())
    }
    fn terminal(&self) -> Result<()> {
        ensure!(
            self.with_cell(|cell| cell.load(Ordering::SeqCst))? == TERMINAL,
            "selected native gate has not reached terminal"
        );
        Ok(())
    }
}

/// Native control stays inside its original Session. Activation performs
/// only the native CLOSED->ACTIVE CAS; the joint promotion proof that
/// authorizes calling it lives outside this owner.
pub(super) struct NativeSelection {
    state: StateControl,
    target: SelectedTarget,
    // These same original owners survive preparation refusal through joined
    // cleanup, including before the construction permit exists.
    original: Option<std::sync::Arc<crate::process::PidPin>>,
    parent: Option<super::Scope>,
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
                ebpf.map("SELECTED_DETAIL").context("selected target map")?,
            )?)
        };
        ensure!(
            target_map()?.get(&0, 0)? == SelectedTarget::default(),
            "selected target was not zero before links"
        );
        let ctl: Array<_, BootstrapControl> = Array::try_from(
            ebpf.map("SELECTED_BCTL")
                .context("selected bootstrap map")?,
        )?;
        ensure!(
            ctl.get(&0, 0)? == BootstrapControl::default(),
            "selected bootstrap was not zero before links"
        );
        let data = super::policy_map_data(
            "SELECTED_DSTATE",
            ebpf.map("SELECTED_DSTATE").context("selected state map")?,
        )?;
        let state = StateControl::new(data.fd().as_fd())?;
        ensure!(
            state.with_cell(|cell| cell.load(Ordering::SeqCst))? == 0,
            "selected state was not zero before links"
        );
        let Some(pin) = selected else {
            super::freeze_map("SELECTED_DETAIL", ebpf.map("SELECTED_DETAIL").unwrap())?;
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
            Array::try_from(ebpf.map_mut("SELECTED_DETAIL").unwrap())?;
        map.set(0, target, 0)?;
        ensure!(
            map.get(&0, 0)? == target,
            "selected pre-link target readback differs"
        );
        state
            .with_cell(|cell| cell.compare_exchange(0, CLOSED, Ordering::SeqCst, Ordering::SeqCst))?
            .map_err(|_| anyhow::anyhow!("selected state changed before links"))?;
        state.closed()?;
        Ok(Some(Self {
            state,
            target,
            original: None,
            parent: None,
        }))
    }
    pub(super) fn require_closed(&self) -> Result<()> {
        self.state.closed()
    }
    /// Run the native activation CAS. The caller must hold the joint
    /// promotion proof; native checks only its own custody (the bound
    /// original) and the CLOSED precondition the CAS itself enforces.
    /// A lost race against close refuses instead of activating.
    pub(super) fn activate(&self) -> Result<()> {
        let original = self
            .original
            .as_ref()
            .context("selected activation without bound original custody")?;
        ensure!(
            !original.original_exited().map_err(anyhow::Error::msg)?,
            "selected original process exited"
        );
        self.state.activate()
    }
    pub(super) fn require_active(&self) -> Result<()> {
        self.state.active()
    }
    pub(super) fn require_terminal(&self) -> Result<()> {
        self.state.terminal()
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
            ebpf.map_mut("SELECTED_DETAIL")
                .context("selected target map")?,
        )?;
        map.set(0, self.target, 0)?;
        ensure!(
            map.get(&0, 0)? == self.target,
            "selected full identity readback differs"
        );
        super::freeze_map("SELECTED_DETAIL", ebpf.map("SELECTED_DETAIL").unwrap())?;
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

/// The production native activation minter (DR37 D3): runs exactly one
/// `CLOSED -> ACTIVE` CAS with readback per accepted request and mints
/// the receipt the joint proof consumes. Stateless: the Session owns
/// the cell, the binding owns the expectation; this only proves they
/// agree before exchanging. The resolver supplies this as the joint
/// service's source, which is the trust chain the receipt relies on.
#[derive(Debug, Default)]
pub(crate) struct NativeActivationMinter;

impl NativeActivationMinter {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl NativeActivationSource for NativeActivationMinter {
    fn activate(
        &mut self,
        session: &super::Session,
        expected: &SelectedActivationBinding,
    ) -> Result<NativeCasReceipt, NativeActivationRefusal> {
        activate_native_selection(
            session.native_selection.as_ref(),
            session.native_domain(),
            expected,
        )
    }
}

/// The minter core, over the exact native parts. No selection was never
/// published; a domain or image disagreement names another binding;
/// otherwise the genuine CAS runs with readback. Custody gates (unbound
/// or exited original) refuse closed through the same variant: no
/// receipt mints, which is the fail-closed property the joint service
/// needs. The seal generation is not a native-cell value: the sealed
/// conversion proved it against this same owner
/// (`SelectedConstructionPermit::validate`), and the proof mint
/// re-checks the lane binding downstream.
fn activate_native_selection(
    selection: Option<&NativeSelection>,
    domain: Option<super::capture::NativeDomainId>,
    expected: &SelectedActivationBinding,
) -> Result<NativeCasReceipt, NativeActivationRefusal> {
    let Some(selection) = selection else {
        return Err(NativeActivationRefusal::NotClosed);
    };
    if domain != Some(expected.domain())
        || selection.target.cookie != expected.image().task_cookie
        || selection.target.exec_id != expected.image().exec_id
    {
        return Err(NativeActivationRefusal::BindingMismatch);
    }
    selection
        .activate()
        .map_err(|_| NativeActivationRefusal::NotClosed)?;
    selection
        .state
        .active()
        .map_err(|_| NativeActivationRefusal::NotClosed)?;
    Ok(NativeCasReceipt::minted(*expected))
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
            .map_mut("SELECTED_BCTL")
            .context("selected bootstrap map")?,
    )?;
    map.set(0, control, 0)?;
    ensure!(
        map.get(&0, 0)? == control,
        "selected bootstrap request readback differs"
    );
    let pidfd_selector = super::host_btf::shared()?.supports_pidfd_iter_selector();
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
            .map("SELECTED_BCTL")
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

/// Exact retained Session owner identity. This wraps the existing EVENTS
/// owner's Arc allocation; cloning it allocates no new Arc or descriptor.
#[derive(Clone)]
pub(crate) struct SelectedSessionIdentity(crate::events::EventsDomain);
impl SelectedSessionIdentity {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.0.same_allocation(&other.0)
    }
}
impl std::fmt::Debug for SelectedSessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SelectedSessionIdentity(<retained>)")
    }
}

/// Only actual closed preparation constructs this move-only factory permit.
/// It grants construction of the sealed provisional capsule, never activation.
pub(crate) struct SelectedConstructionPermit {
    owner: SelectedSessionIdentity,
    original: std::sync::Arc<crate::process::PidPin>,
    parent: super::Scope,
    domain: super::capture::NativeDomainId,
    image: ImageIdentity,
    generation: u64,
    baseline: baseline::PromotionImageBaseline,
}
impl SelectedConstructionPermit {
    pub(crate) fn identity(&self) -> &SelectedSessionIdentity {
        &self.owner
    }
    pub(crate) fn original(&self) -> &std::sync::Arc<crate::process::PidPin> {
        &self.original
    }
    pub(crate) fn parent(&self) -> &super::Scope {
        &self.parent
    }
    pub(crate) fn domain(&self) -> super::capture::NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn baseline(&self) -> &baseline::PromotionImageBaseline {
        &self.baseline
    }
    pub(crate) fn validate_conversion(
        &self,
        session: &super::Session,
        attached: &super::AttachedSemanticSet,
        convert: &crate::inventory_semantics::AttestedSubset,
    ) -> Result<()> {
        self.validate(session, attached)?;
        ensure!(
            attached.subset.same_retained_envelope(convert),
            "selected conversion envelope differs from sealed retained closure"
        );
        Ok(())
    }
    pub(crate) fn validate(
        &self,
        session: &super::Session,
        attached: &super::AttachedSemanticSet,
    ) -> Result<()> {
        ensure!(
            self.owner.0.same_allocation(&session.events_domain),
            "selected factory received a different native owner"
        );
        ensure!(
            session.native_domain() == Some(self.domain)
                && attached.domain() == self.domain
                && attached.generation() == self.generation,
            "selected factory received a different attachment seal"
        );
        let native = session
            .native_selection
            .as_ref()
            .context("selected native control missing")?;
        native.require_closed()?;
        ensure!(
            native
                .original
                .as_ref()
                .is_some_and(|held| std::sync::Arc::ptr_eq(held, &self.original)),
            "selected factory original custody differs from native owner"
        );
        ensure!(
            !session.stop_gate.stop_requested(),
            "selected native owner is stopping"
        );
        ensure!(
            self.baseline
                .matches_original_and_exec(&self.original, self.image.exec_id),
            "selected view baseline no longer matches original image"
        );
        self.original.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            !self
                .original
                .original_exited()
                .map_err(anyhow::Error::msg)?,
            "selected original process exited"
        );
        ensure!(
            session.instance_maps().cookie(self.original.pidfd()?)? == Some(self.image.task_cookie),
            "selected original pidfd image cookie differs"
        );
        let map: Array<_, SelectedTarget> = Array::try_from(
            session
                .ebpf
                .map("SELECTED_DETAIL")
                .context("selected target map")?,
        )?;
        ensure!(
            map.get(&0, 0)? == native.target
                && native.target.mode == 1
                && native.target.tgid == self.original.pid()
                && native.target.cookie == self.image.task_cookie
                && native.target.exec_id == self.image.exec_id,
            "selected frozen image differs from factory permit"
        );
        match &self.parent {
            super::Scope::Pid(pid) => ensure!(
                *pid == self.original.pid() && native.target.parent_kind == 1,
                "selected PID parent differs"
            ),
            super::Scope::System => ensure!(
                native.target.parent_kind == 3,
                "selected system parent differs"
            ),
            super::Scope::Cgroup { .. } => {
                bail!("selected cgroup negative migration coverage is not qualified")
            }
        }
        session.validate_semantic_set(attached)?;
        session
            .audit_image_continuity()
            .map_err(|error| anyhow::anyhow!("selected factory image coverage: {error:?}"))?;
        native.require_closed()
    }
}
impl std::fmt::Debug for SelectedConstructionPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SelectedConstructionPermit(<retained>)")
    }
}

/// The sole native preparation owner; fields never escape as generic raw parts.
pub(crate) struct PreparedSelectedSession {
    session: super::Session,
    attached: super::AttachedSemanticSet,
    permit: SelectedConstructionPermit,
}
impl PreparedSelectedSession {
    /// Caller must supply the pre-view receipt from the actual Inventory
    /// acquisition/binder. A later image query cannot construct that receipt.
    #[allow(clippy::result_large_err)] // Cold preparation path: the failure retains the native owner for joined cleanup.
    pub(crate) fn prepare(
        subset: crate::inventory_semantics::AttestedSubset,
        baseline: baseline::PromotionImageBaseline,
        original: std::sync::Arc<crate::process::PidPin>,
        parent: super::Scope,
        backend: super::BackendSelection,
        window: super::capture::ReadWindow,
    ) -> std::result::Result<Self, SelectedPreparationFailure> {
        let mut session = start_selected(
            subset.plan(),
            subset.pins(),
            &parent,
            &original,
            backend,
            window,
        )?;
        let prepared = (|| -> Result<_> {
            let image = bootstrap(&mut session, &original, window)?;
            ensure!(
                baseline.matches_original_and_exec(&original, image.exec_id),
                "selected image differs from displayed original image baseline"
            );
            session
                .native_selection
                .as_mut()
                .context("selected native control missing")?
                .complete_identity(&mut session.ebpf, image)?;
            // The normal same-domain query, not a bootstrap approximation, checks
            // READY continuity under the real installed image-hook audit.
            let current = session
                .query_images(&[&original], window)
                .map_err(|error| anyhow::anyhow!("selected final image query: {error:?}"))?;
            let domain = session
                .native_domain()
                .context("selected native image domain unavailable")?;
            ensure!(
                current.domain() == domain && current.image(image.task_cookie) == Some(image),
                "selected full image changed during preparation"
            );
            session.object_decode = Some(super::freeze_object_decode_table(&session.ebpf)?);
            let attached = super::seal_attached_subset_native(
                &session.ebpf,
                subset,
                domain,
                session.policy,
                session.semantic_descriptors(),
                &session.retained_static,
                &session.current_static_sides(),
                |object| {
                    session
                        .instance
                        .watched(object)
                        .map(|watched| watched.retained_target())
                },
            )
            .map_err(|reason| anyhow::anyhow!("selected semantic attachment refused: {reason}"))?;
            let permit = SelectedConstructionPermit {
                owner: SelectedSessionIdentity(session.events_domain()),
                original,
                parent,
                domain,
                image,
                generation: attached.generation(),
                baseline,
            };
            permit.validate(&session, &attached)?;
            Ok((attached, permit))
        })();
        match prepared {
            Ok((attached, permit)) => Ok(Self {
                session,
                attached,
                permit,
            }),
            Err(error) => Err(SelectedPreparationFailure::retaining(session, error)),
        }
    }
    pub(crate) fn identity(&self) -> &SelectedSessionIdentity {
        self.permit.identity()
    }

    /// Concrete one-way handoff. This is deliberately not into_parts or a
    /// generic callback that could export a usable provisional Session/H0.
    #[allow(clippy::result_large_err)] // Cold handoff: the failure retains the native owner for joined cleanup.
    pub(crate) fn into_provisional_lane(
        self,
        convert_subset: crate::inventory_semantics::AttestedSubset,
    ) -> std::result::Result<
        crate::inventory_semantics::selected::ProvisionalSelectedLane,
        SelectedPreparationFailure,
    > {
        crate::inventory_semantics::selected::ProvisionalSelectedLane::from_closed_native(
            self.session,
            self.attached,
            self.permit,
            convert_subset,
        )
    }
}

/// Runs on the preparation worker. Auto can retry only after the failed Multi
/// attempt's original worker has joined successfully. A deadline or uncertain
/// close returns the same retained failure owner instead of starting Singles.
#[allow(clippy::result_large_err)] // Cold preparation path: the failure retains the native owner for joined cleanup.
fn start_selected(
    plan: &super::AttachPlan,
    objects: &crate::discovery::identity::PinnedObjects,
    parent: &super::Scope,
    original: &std::sync::Arc<crate::process::PidPin>,
    selection: super::BackendSelection,
    window: super::capture::ReadWindow,
) -> std::result::Result<super::Session, SelectedPreparationFailure> {
    let preliminary = (|| -> Result<_> {
        original
            .pidfd()
            .context("selected preparation requires original pidfd")?;
        original.open_proc_dir().map_err(anyhow::Error::msg)?;
        ensure!(
            !original.original_exited().map_err(anyhow::Error::msg)?,
            "selected original exited"
        );
        let _ = crate::process::raise_nofile();
        super::select_session_backend(
            selection,
            true,
            super::multi_functional_probe,
            super::kernel_multi_pid_filter,
        )
    })()
    .map_err(SelectedPreparationFailure::before_links)?;
    let super::SessionBackend { backend, fallback } = preliminary;
    let mut session = match start_selected_attempt(plan, objects, parent, original, backend) {
        Ok(session) => session,
        Err(mut failure)
            if selection == super::BackendSelection::Auto
                && backend == super::AttachBackend::Multi
                && failure.requires_backend_fallback() =>
        {
            let mut quiet = std::io::sink();
            loop {
                match failure.poll_cleanup(&mut quiet) {
                    SelectedCleanupStatus::Settled => break,
                    SelectedCleanupStatus::Unproved => return Err(failure),
                    SelectedCleanupStatus::Pending => {
                        if std::time::Instant::now() >= window.deadline() {
                            return Err(failure);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
            let mut session = start_selected_attempt(
                plan,
                objects,
                parent,
                original,
                super::AttachBackend::Singles,
            )?;
            session.backend_fallback = Some(
                "the uprobe-multi attach failed; its original cleanup settled before Singles"
                    .into(),
            );
            session
        }
        Err(failure) => return Err(failure),
    };
    session.selection = selection;
    if session.backend_fallback.is_none() {
        session.backend_fallback = fallback;
    }
    Ok(session)
}

#[allow(clippy::result_large_err)] // Cold preparation path: the failure retains the native owner for joined cleanup.
fn start_selected_attempt(
    plan: &super::AttachPlan,
    objects: &crate::discovery::identity::PinnedObjects,
    parent: &super::Scope,
    original: &std::sync::Arc<crate::process::PidPin>,
    backend: super::AttachBackend,
) -> std::result::Result<super::Session, SelectedPreparationFailure> {
    let (mut session, prepared_instance) = (|| -> Result<_> {
        ensure!(
            objects.check_unchanged().map_err(anyhow::Error::msg)?,
            "selected pinned provider changed before attach"
        );
        super::Session::prepare_inner_unlinked(
            parent,
            super::CapturePolicy::Allowlisted,
            None,
            None,
            None,
            backend,
            Some(original),
        )
    })()
    .map_err(SelectedPreparationFailure::before_links)?;
    let native = session
        .native_selection
        .as_mut()
        .expect("selected preparation published native owner");
    native.original = Some(std::sync::Arc::clone(original));
    native.parent = Some(parent.clone());
    let attached = (|| -> Result<()> {
        session
            .cleanup_worker
            .as_ref()
            .context("selected cleanup worker absent")?
            .live_admission()
            .map_err(anyhow::Error::msg)?;
        lifecycle::attach_retained_with(&mut session.links, |program| {
            super::Session::attach_lifecycle_program(&mut session.ebpf, program)
                .with_context(|| format!("attaching required selected {program}"))
        })?;
        session.trace_coverage = super::detailed_identity::TraceCoverage::after_activation(
            parent,
            super::monotonic_ns(),
        );
        session.instance = super::InstanceTracking::start_selected(
            &mut session.ebpf,
            &session.image_coverage,
            prepared_instance,
        );
        session
            .audit_image_continuity()
            .map_err(|error| anyhow::anyhow!("selected image hooks: {error:?}"))?;
        session
            .attach_plan(plan, objects)
            .map_err(super::unsupported_environment_context)?;
        session.stage_discovery(crate::discovery::engine::LIVE_DISCOVERY_DRAIN_QUANTUM, 0)?;
        ensure!(
            objects.check_unchanged().map_err(anyhow::Error::msg)?,
            "selected pinned provider changed while attaching"
        );
        Ok(())
    })();
    match attached {
        Ok(()) => Ok(session),
        Err(error) => Err(SelectedPreparationFailure::retaining(session, error)),
    }
}
