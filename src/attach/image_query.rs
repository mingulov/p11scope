//! SPDX-License-Identifier: GPL-3.0-or-later
//! Same-object fresh image queries and the only full-image scan seal.

use super::capture::{NativeDomainId, ReadWindow};
use crate::discovery::instances::MapRange;
use p11scope_ebpf_common::ImageIdentity;
use std::collections::BTreeMap;
use std::mem::size_of_val;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
struct QueryRequest {
    generation: u64,
    cookie: u64,
    slot: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct QueryControl {
    generation: u64,
    deadline_ns: u64,
    visit_limit: u64,
    count: u64,
    visits: u64,
    emitted: u64,
    failed: u64,
}
// SAFETY: C-layout integer-only wire values admit all byte patterns.
unsafe impl aya::Pod for QueryRequest {}
unsafe impl aya::Pod for QueryControl {}
const _: () = assert!(size_of::<QueryRequest>() == 24);
const _: () = assert!(size_of::<QueryControl>() == 56);

/// One retained same-object query program. Requests are immutable while a
/// run is open; the exclusive Session borrow serializes configuration/runs.
pub(super) struct ImageQueryOwner {
    domain: NativeDomainId,
    generation: u64,
    pidfd_selector: bool,
}
impl ImageQueryOwner {
    pub(super) fn load(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        domain: NativeDomainId,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let program: &mut aya::programs::Iter = ebpf
            .program_mut("p11_image_query")
            .context("same-object image query program missing")?
            .try_into()?;
        program
            .load("task", btf)
            .context("load same-object p11_image_query task iterator")?;
        let pidfd_selector = btf
            .id_by_type_name_kind("bpf_iter_attach_task", aya_obj::btf::BtfKind::Func)
            .is_ok();
        Ok(Self {
            domain,
            generation: 0,
            pidfd_selector,
        })
    }

    pub(super) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(super) fn query(
        &mut self,
        ebpf: &mut aya::Ebpf,
        pins: &[&crate::process::PidPin],
        window: ReadWindow,
    ) -> Result<ImageQueryBatch, ImageQueryRefusal> {
        use aya::maps::{Array, HashMap};
        if pins.is_empty() || pins.len() > window.max_rows().min(QUERY_LIMIT) {
            return Err(ImageQueryRefusal::Capacity);
        }
        check_deadline(window.deadline())?;
        if !crate::pidns::numbering().agrees() {
            return Err(ImageQueryRefusal::Custody);
        }
        let mut requested = Vec::with_capacity(pins.len());
        for pin in pins {
            pin.open_proc_dir()
                .map_err(|_| ImageQueryRefusal::Custody)?;
            let pidfd = pin.pidfd().map_err(|_| ImageQueryRefusal::Custody)?;
            let cookie = super::InstanceMaps { ebpf }
                .cookie(pidfd)
                .map_err(|_| ImageQueryRefusal::Custody)?
                .ok_or(ImageQueryRefusal::Unknown)?;
            if cookie == 0
                || cookie > p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT
                || requested.contains(&cookie)
            {
                return Err(ImageQueryRefusal::Stream);
            }
            requested.push(cookie);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ImageQueryRefusal::Exhausted)?;
        let generation = self.generation;
        {
            let map = ebpf
                .map_mut("IMAGE_QUERY_REQUESTS")
                .ok_or(ImageQueryRefusal::Stream)?;
            let mut requests: HashMap<_, u64, QueryRequest> =
                HashMap::try_from(map).map_err(|_| ImageQueryRefusal::Stream)?;
            let old = requests
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ImageQueryRefusal::Stream)?;
            for key in old {
                requests
                    .remove(&key)
                    .map_err(|_| ImageQueryRefusal::Stream)?;
            }
            for (slot, cookie) in requested.iter().enumerate() {
                requests
                    .insert(
                        cookie,
                        QueryRequest {
                            generation,
                            cookie: *cookie,
                            slot: slot as u64,
                        },
                        1,
                    )
                    .map_err(|_| ImageQueryRefusal::Stream)?;
            }
        }
        let control = QueryControl {
            generation,
            deadline_ns: conservative_deadline(window.deadline())?,
            visit_limit: VISIT_LIMIT,
            count: pins.len() as u64,
            ..QueryControl::default()
        };
        let mut bytes = Vec::new();
        /* Each selected run has exactly one requested cookie. Older kernels
         * perform one explicitly bounded walk for the complete request set. */
        if self.pidfd_selector && pins.len() > 1 {
            // Batch requests need one END, not one terminal row per link.
            // The unparameterized walk is bounded on all qualified kernels.
            bytes = self.run(
                ebpf,
                None,
                &control,
                window.deadline(),
                (pins.len() + 1) * ROW_LEN,
            )?;
        } else {
            let selector = if self.pidfd_selector {
                Some(pins[0].pidfd().map_err(|_| ImageQueryRefusal::Custody)?)
            } else {
                None
            };
            bytes.extend(self.run(
                ebpf,
                selector,
                &control,
                window.deadline(),
                (pins.len() + 1) * ROW_LEN,
            )?);
        }
        for (pin, cookie) in pins.iter().zip(&requested) {
            if pin
                .original_exited()
                .map_err(|_| ImageQueryRefusal::Custody)?
            {
                return Err(ImageQueryRefusal::Custody);
            }
            let after = super::InstanceMaps { ebpf }
                .cookie(pin.pidfd().map_err(|_| ImageQueryRefusal::Custody)?)
                .map_err(|_| ImageQueryRefusal::Custody)?;
            if after != Some(*cookie) {
                return Err(ImageQueryRefusal::Custody);
            }
        }
        check_deadline(window.deadline())?;
        let ctl: Array<_, QueryControl> = Array::try_from(
            ebpf.map("IMAGE_QUERY_CTL")
                .ok_or(ImageQueryRefusal::Stream)?,
        )
        .map_err(|_| ImageQueryRefusal::Stream)?;
        let done = ctl.get(&0, 0).map_err(|_| ImageQueryRefusal::Stream)?;
        if done.generation != generation
            || done.count != control.count
            || done.deadline_ns != control.deadline_ns
            || done.visit_limit != control.visit_limit
            || done.failed != 0
            || done.emitted != pins.len() as u64
            || done.visits < pins.len() as u64 + 1
            || done.visits > VISIT_LIMIT
        {
            return Err(ImageQueryRefusal::Stream);
        }
        parse_batch(self.domain, generation, &requested, &bytes)
    }

    fn run(
        &self,
        ebpf: &mut aya::Ebpf,
        pidfd: Option<BorrowedFd<'_>>,
        control: &QueryControl,
        deadline: Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ImageQueryRefusal> {
        let mut ctl: aya::maps::Array<_, QueryControl> = aya::maps::Array::try_from(
            ebpf.map_mut("IMAGE_QUERY_CTL")
                .ok_or(ImageQueryRefusal::Stream)?,
        )
        .map_err(|_| ImageQueryRefusal::Stream)?;
        ctl.set(0, control, 0)
            .map_err(|_| ImageQueryRefusal::Stream)?;
        check_deadline(deadline)?;
        let fd = ebpf
            .program("p11_image_query")
            .ok_or(ImageQueryRefusal::Stream)?
            .fd()
            .map_err(|_| ImageQueryRefusal::Stream)?;
        let link = task_link(fd.as_fd(), pidfd)?;
        check_deadline(deadline)?;
        let iterator = super::identity_iter::iter_create(link.as_fd())
            .map_err(|_| ImageQueryRefusal::Stream)?;
        read_iterator(iterator.as_fd(), deadline, max_bytes)
    }
}

pub(super) fn check_deadline(deadline: Instant) -> Result<(), ImageQueryRefusal> {
    if Instant::now() >= deadline {
        Err(ImageQueryRefusal::Deadline)
    } else {
        Ok(())
    }
}

/// The CLOCK sample precedes the remaining-Instant sample: adding that later
/// remaining duration to the earlier clock cannot extend the original budget.
pub(super) fn conservative_deadline(deadline: Instant) -> Result<u64, ImageQueryRefusal> {
    let clock = super::monotonic_ns().ok_or(ImageQueryRefusal::Deadline)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ImageQueryRefusal::Deadline)?;
    clock
        .checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| ImageQueryRefusal::Deadline)?)
        .ok_or(ImageQueryRefusal::Deadline)
}

pub(super) fn task_link(
    program: BorrowedFd<'_>,
    pidfd: Option<BorrowedFd<'_>>,
) -> Result<OwnedFd, ImageQueryRefusal> {
    let info = super::identity_iter::IterLinkInfo {
        tid: 0,
        pid: 0,
        pid_fd: match pidfd {
            Some(fd) => selector_pidfd(fd.as_raw_fd())?,
            None => 0,
        },
        reserved: 0,
    };
    let attr = super::identity_iter::LinkCreateAttr {
        prog_fd: program.as_raw_fd() as u32,
        target_fd: 0,
        attach_type: 28,
        flags: 0,
        iter_info: if pidfd.is_some() {
            (&info as *const super::identity_iter::IterLinkInfo) as u64
        } else {
            0
        },
        iter_info_len: if pidfd.is_some() {
            size_of_val(&info) as u32
        } else {
            0
        },
        reserved: 0,
    };
    // SAFETY: live program/pidfd selector and complete syscall layout.
    let fd = unsafe { libc::syscall(libc::SYS_bpf, 28u32, &attr, size_of_val(&attr)) };
    if fd < 0 {
        return Err(ImageQueryRefusal::Stream);
    }
    // SAFETY: successful link-create returns a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub(super) fn read_iterator(
    fd: BorrowedFd<'_>,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Vec<u8>, ImageQueryRefusal> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        check_deadline(deadline)?;
        // SAFETY: live iterator fd and writable bounded byte buffer.
        let count = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        check_deadline(deadline)?;
        if count < 0 {
            return Err(ImageQueryRefusal::Stream);
        } // Includes EAGAIN: incomplete, never retry.
        if count == 0 {
            return Ok(bytes);
        }
        let count = count as usize;
        if count > max_bytes.saturating_sub(bytes.len()) {
            return Err(ImageQueryRefusal::Stream);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

impl super::Session {
    pub(crate) fn native_domain(&self) -> Option<NativeDomainId> {
        self.image_query.as_ref().map(ImageQueryOwner::domain)
    }

    /// Called after collection and before routing each later cached-proof batch.
    /// A failed audit is permanent for this Session; ordinary fault resets
    /// never clear the image failure cell.
    pub(crate) fn audit_image_continuity(&self) -> Result<(), ImageQueryRefusal> {
        if !self.policy.wants_instance_hooks() {
            return Err(ImageQueryRefusal::Policy);
        }
        self.instance
            .audit(&self.ebpf, &self.image_coverage)
            .map_err(|_| ImageQueryRefusal::Coverage)
    }

    pub(crate) fn query_images(
        &mut self,
        pins: &[&crate::process::PidPin],
        window: ReadWindow,
    ) -> Result<ImageQueryBatch, ImageQueryRefusal> {
        if !self.policy.wants_instance_hooks() {
            return Err(ImageQueryRefusal::Policy);
        }
        check_deadline(window.deadline())?;
        self.audit_image_continuity()?;
        let result = self
            .image_query
            .as_mut()
            .ok_or(ImageQueryRefusal::Coverage)?
            .query(&mut self.ebpf, pins, window);
        self.audit_image_continuity()?;
        check_deadline(window.deadline())?;
        result
    }

    /// Acquire one watched file through retained proc custody and complete
    /// full-image/epoch/health brackets. `original_fence` is preserved exactly;
    /// the consumer must still compare it to its real current router fence.
    /// The callback lets that owner reject a change before this seal is issued.
    pub(crate) fn scan_image(
        &mut self,
        pin: &crate::process::PidPin,
        object: crate::discovery::identity::PinnedObjectId,
        window: ReadWindow,
        original_fence: u64,
        current_fence: impl Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        if !self.policy.wants_instance_hooks() {
            return Err(ImageQueryRefusal::Policy);
        }
        check_deadline(window.deadline())?;
        let watched = self
            .instance
            .watched(object)
            .cloned()
            .ok_or(ImageQueryRefusal::Coverage)?;
        let domain = self.native_domain().ok_or(ImageQueryRefusal::Coverage)?;
        let proc = pin
            .open_proc_dir()
            .map_err(|_| ImageQueryRefusal::Custody)?;
        check_deadline(window.deadline())?;
        let file_slot = watched.file_slot;
        let mut source = LiveImageScan {
            session: self,
            pin,
            proc,
            watched,
            window,
            current_fence,
        };
        scan_with(&mut source, domain, file_slot, original_fence)
    }

    /// Seal one provider-free interval for one watched file through
    /// retained proc custody and the same complete
    /// full-image/epoch/health brackets as [`Session::scan_image`],
    /// plus the live attach cell. `original_fence` is preserved
    /// exactly; the consumer must still compare it to its real
    /// current router fence. UNRUN: live acquisition stays out of
    /// tests; the birth tests seal through `acquire_test_absence`.
    #[allow(dead_code)] // No Session-loop wire until live activation.
    pub(crate) fn prove_image_absence(
        &mut self,
        pin: &crate::process::PidPin,
        object: crate::discovery::identity::PinnedObjectId,
        window: ReadWindow,
        original_fence: u64,
        current_fence: impl Fn() -> u64,
    ) -> Result<ImageAbsenceProof, ImageQueryRefusal> {
        if !self.policy.wants_instance_hooks() {
            return Err(ImageQueryRefusal::Policy);
        }
        check_deadline(window.deadline())?;
        let watched = self
            .instance
            .watched(object)
            .cloned()
            .ok_or(ImageQueryRefusal::Coverage)?;
        let domain = self.native_domain().ok_or(ImageQueryRefusal::Coverage)?;
        let proc = pin
            .open_proc_dir()
            .map_err(|_| ImageQueryRefusal::Custody)?;
        check_deadline(window.deadline())?;
        let file_slot = watched.file_slot;
        let mut source = LiveImageScan {
            session: self,
            pin,
            proc,
            watched,
            window,
            current_fence,
        };
        prove_absence_with(&mut source, domain, file_slot, original_fence)
    }
}

struct LiveImageScan<'a, F> {
    session: &'a mut super::Session,
    pin: &'a crate::process::PidPin,
    proc: crate::process::ProcPin<'a>,
    watched: super::WatchedFile,
    window: ReadWindow,
    current_fence: F,
}
impl<F: Fn() -> u64> ScanSource for LiveImageScan<'_, F> {
    fn budget(&self) -> Result<(), ImageQueryRefusal> {
        check_deadline(self.window.deadline())
    }
    fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
        self.budget()?;
        if !self
            .watched
            .check_unchanged()
            .map_err(|_| ImageQueryRefusal::Custody)?
        {
            return Err(ImageQueryRefusal::Custody);
        }
        self.session.audit_image_continuity()?;
        self.budget()
    }
    fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
        let batch = self.session.query_images(&[self.pin], self.window)?;
        if Some(batch.domain()) != self.session.native_domain() {
            return Err(ImageQueryRefusal::Stream);
        }
        batch
            .images
            .values()
            .next()
            .copied()
            .ok_or(ImageQueryRefusal::Unknown)
    }
    fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
        self.budget()?;
        let maps = self.session.instance_maps();
        let record = maps
            .record(self.pin.pidfd().map_err(|_| ImageQueryRefusal::Custody)?)
            .map_err(|_| ImageQueryRefusal::Coverage)?;
        let (local, record_flags) = record.map_or((0, 0), |record| {
            (
                record
                    .slot_plus1
                    .iter()
                    .position(|slot| *slot == u64::from(self.watched.file_slot) + 1)
                    .map_or(0, |index| record.epoch[index]),
                record.flags,
            )
        });
        let reading = CompleteEpochs {
            local,
            record_flags,
            global: maps
                .global(self.watched.file_slot)
                .map_err(|_| ImageQueryRefusal::Coverage)?,
            fault: maps.fault().map_err(|_| ImageQueryRefusal::Coverage)?,
            sticky: maps.sticky().map_err(|_| ImageQueryRefusal::Coverage)?,
        };
        self.budget()?;
        Ok(reading)
    }
    fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
        read_confirmed_ranges_with(
            &self.proc,
            &self.watched.maps_keys,
            self.watched.identity,
            self.window.deadline(),
            8 * 1024 * 1024,
            || {},
        )
    }

    fn fence(&self, original: u64) -> bool {
        (self.current_fence)() == original
    }
}

impl<F: Fn() -> u64> AbsenceScanSource for LiveImageScan<'_, F> {
    fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey] {
        &self.watched.maps_keys
    }
    fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity {
        self.watched.identity
    }
    fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
        read_parsed_maps_with(&self.proc, self.window.deadline(), 8 * 1024 * 1024, || {})
    }
    fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal> {
        self.budget()?;
        self.session
            .instance_maps()
            .attach_cell()
            .map_err(|_| ImageQueryRefusal::Coverage)
    }
    fn confirm(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal> {
        // The positive path's exact confirmation: the VMA's own file
        // through its map_files link.
        self.proc
            .mapped_file_identity(start, end, self.window.deadline())
            .map_err(|_| ImageQueryRefusal::Custody)
    }
}

/// The complete retained maps read plus full parse, shared by the
/// positive scan and the absence enumeration. No identity decision:
/// both seals select/confirm from these entries through the same
/// `ranges_for`/`confirm_identity` functions.
fn read_parsed_maps_with(
    proc: &crate::process::ProcPin<'_>,
    deadline: Instant,
    max_bytes: usize,
    after_maps: impl FnOnce(),
) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
    let bytes = proc
        .read_maps(deadline, max_bytes)
        .map_err(|_| ImageQueryRefusal::Custody)?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err(ImageQueryRefusal::Stream);
    }
    let entries =
        p11scope_manifest::maps::parse_maps(&bytes).map_err(|_| ImageQueryRefusal::Stream)?;
    after_maps();
    Ok(entries)
}

/// Actual retained maps/read/relative-stat path shared by LiveImageScan and
/// bounded I/O controls. No parser or identity decision is reimplemented.
fn read_confirmed_ranges_with(
    proc: &crate::process::ProcPin<'_>,
    maps_keys: &[p11scope_manifest::maps::ObjectKey],
    identity: crate::discovery::instances::MappedFileIdentity,
    deadline: Instant,
    max_bytes: usize,
    after_maps: impl FnOnce(),
) -> Result<Vec<MapRange>, ImageQueryRefusal> {
    let entries = read_parsed_maps_with(proc, deadline, max_bytes, after_maps)?;
    let mut ranges = Vec::new();
    for key in maps_keys {
        ranges.extend(crate::discovery::instances::ranges_for(
            &entries,
            key.device.major,
            key.device.minor,
            key.inode,
        ));
    }
    if ranges.len() > 16_384 {
        return Err(ImageQueryRefusal::Capacity);
    }
    // Maps selection and map_files stat are different device domains.
    crate::discovery::instances::confirm_identity(ranges, identity, |start, end| {
        proc.mapped_file_identity(start, end, deadline)
    })
    .map_err(|_| ImageQueryRefusal::Custody)
}

pub(crate) const QUERY_LIMIT: usize = 1_024;
const ROW_LEN: usize = 40;
const VISIT_LIMIT: u64 = 65_536;

pub(super) struct CoverageControl {
    address: std::ptr::NonNull<std::sync::atomic::AtomicU64>,
}
impl CoverageControl {
    pub(super) fn new(ebpf: &aya::Ebpf) -> anyhow::Result<Self> {
        use anyhow::{Context as _, ensure};
        let map = super::policy_map_data(
            "INSTANCE_GEN",
            ebpf.map("INSTANCE_GEN").context("INSTANCE_GEN")?,
        )?;
        // SAFETY: exact mmapable array checked before construction; one page
        // contains all four aligned u64 cells and lives until this owner drops.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map.fd().as_fd().as_raw_fd(),
                0,
            )
        };
        ensure!(
            address != libc::MAP_FAILED,
            "mapping image coverage: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self {
            address: std::ptr::NonNull::new(address.cast())
                .context("null image coverage mapping")?,
        })
    }
    fn cell(&self) -> &std::sync::atomic::AtomicU64 {
        // SAFETY: coverage is cell 3 in the retained page mapping.
        unsafe { &*self.address.as_ptr().add(3) }
    }
    pub(super) fn enabled(&self) -> bool {
        self.cell().load(std::sync::atomic::Ordering::SeqCst) == 1
    }
    pub(super) fn enable(&self) -> anyhow::Result<()> {
        self.cell()
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("image continuity could not enable from Disabled"))
    }
    pub(super) fn fail(&self) {
        fail_coverage_with(self.cell(), || {});
    }

    #[cfg(test)]
    pub(super) fn test_owner(enabled: bool) -> Self {
        // SAFETY: anonymous private page, owned until the normal Drop unmaps it.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        let owner = Self {
            address: std::ptr::NonNull::new(address.cast()).unwrap(),
        };
        if enabled {
            owner.enable().unwrap();
        }
        owner
    }
}

fn fail_coverage_with(cell: &std::sync::atomic::AtomicU64, between: impl FnOnce()) {
    let _ = cell.compare_exchange(
        0,
        2,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    );
    between();
    let _ = cell.compare_exchange(
        1,
        2,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    );
}
impl Drop for CoverageControl {
    fn drop(&mut self) {
        self.fail();
        // SAFETY: exactly the retained page mapping created in new.
        unsafe { libc::munmap(self.address.as_ptr().cast(), 4096) };
    }
}

fn read_fd_access_mode(fd: std::os::fd::RawFd) -> std::io::Result<libc::c_int> {
    // SAFETY: F_GETFL takes no pointer argument; an invalid FD returns EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags & libc::O_ACCMODE)
}

fn validate_image_map_contract(
    name: &str,
    actual: super::ExactMapMetadata,
    expected: super::ExactMapMetadata,
    original_fd: BorrowedFd<'_>,
) -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};
    super::compare_map_metadata(name, actual, expected)?;
    if matches!(name, "IMAGE_CONTINUITY" | "IMAGE_TGID_INDEX") {
        // Linux retains NO_PREALLOC on the map object but moves WRONLY to
        // the created FD. Check the original owned FD, without reopening it.
        let mode = read_fd_access_mode(original_fd.as_raw_fd())
            .with_context(|| format!("reading {name} map FD access mode"))?;
        ensure!(mode == libc::O_WRONLY, "{name} map FD must be write-only");
    }
    Ok(())
}

pub(super) fn prepare_maps(ebpf: &aya::Ebpf, full: bool) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let hashes = if full { 16_384 } else { 1 };
    for (name, kind, key, value, count, flags) in [
        (
            "IMAGE_CONTINUITY",
            aya::maps::MapType::Hash,
            8,
            24,
            hashes,
            1,
        ),
        (
            "IMAGE_TGID_INDEX",
            aya::maps::MapType::Hash,
            8,
            8,
            hashes,
            1,
        ),
        (
            "IMAGE_QUERY_REQUESTS",
            aya::maps::MapType::Hash,
            8,
            24,
            if full { QUERY_LIMIT as u32 } else { 1 },
            129,
        ),
        ("IMAGE_QUERY_CTL", aya::maps::MapType::Array, 4, 56, 1, 0),
        ("INSTANCE_GEN", aya::maps::MapType::Array, 4, 8, 4, 1024),
    ] {
        let map = ebpf.map(name).with_context(|| format!("{name} map"))?;
        let data = super::policy_map_data(name, map)?;
        validate_image_map_contract(
            name,
            super::read_map_metadata(name, data)?,
            super::map_metadata(kind, key, value, count, flags),
            data.fd().as_fd(),
        )?;
        if matches!(name, "IMAGE_CONTINUITY" | "IMAGE_TGID_INDEX") {
            super::freeze_map(name, map)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageQueryRefusal {
    Policy,
    Coverage,
    Custody,
    Deadline,
    Capacity,
    Exhausted,
    Stream,
    Unknown,
    Unstable,
    Empty,
    Fence,
    /// The absence seal found a confirmed watched-provider mapping:
    /// the interval is not provider-free.
    Present,
}

/// Private map results; equality is meaningful only in the owning domain.
pub(crate) struct ImageQueryBatch {
    domain: NativeDomainId,
    images: BTreeMap<u64, ImageIdentity>,
}
impl ImageQueryBatch {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self, cookie: u64) -> Option<ImageIdentity> {
        self.images.get(&cookie).copied()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompleteEpochs {
    pub(crate) local: u64,
    pub(crate) global: u64,
    pub(crate) fault: u64,
    pub(crate) sticky: u64,
    pub(crate) record_flags: u64,
}

/// Constructor remains private to the acquisition owner. Consumers must
/// compare the retained original fence against their still-current router.
pub(crate) struct ImageScanProof {
    domain: NativeDomainId,
    image: ImageIdentity,
    file_slot: u32,
    epochs: CompleteEpochs,
    ranges: Vec<MapRange>,
    fence: u64,
}
impl ImageScanProof {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    pub(crate) fn file_slot(&self) -> u32 {
        self.file_slot
    }
    pub(crate) fn epochs(&self) -> CompleteEpochs {
        self.epochs
    }
    pub(crate) fn ranges(&self) -> &[MapRange] {
        &self.ranges
    }
    pub(crate) fn fence(&self) -> u64 {
        self.fence
    }
}

/// A sealed provider-free interval: a COMPLETE process-maps
/// enumeration (bracketed exactly like a positive scan: custody,
/// stable image, stable epochs, audits, fence) that contains ZERO
/// confirmed watched-provider mappings, plus the attach-cell
/// generation observed live inside the brackets (which ties the
/// enumeration to after that closure's publication). The negative
/// absence witness: distinct from the positive [`ImageScanProof`],
/// which cannot represent absence (the acquisition protocol refuses
/// empty positives). Constructor remains private to the acquisition
/// owner; only [`prove_absence_with`] seals one.
pub(crate) struct ImageAbsenceProof {
    domain: NativeDomainId,
    image: ImageIdentity,
    file_slot: u32,
    epochs: CompleteEpochs,
    attach_generation: u64,
    total_entries: usize,
    fence: u64,
}
impl ImageAbsenceProof {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    pub(crate) fn file_slot(&self) -> u32 {
        self.file_slot
    }
    pub(crate) fn epochs(&self) -> CompleteEpochs {
        self.epochs
    }
    pub(crate) fn attach_generation(&self) -> u64 {
        self.attach_generation
    }
    pub(crate) fn total_entries(&self) -> usize {
        self.total_entries
    }
    pub(crate) fn fence(&self) -> u64 {
        self.fence
    }
}

trait ScanSource {
    fn budget(&self) -> Result<(), ImageQueryRefusal>;
    fn audit(&mut self) -> Result<(), ImageQueryRefusal>;
    fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal>;
    fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal>;
    fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal>;
    fn fence(&self, original: u64) -> bool;
}

/// The absence seal's I/O beneath the same bracket protocol: the
/// watched identity the enumeration must be free of, the complete
/// parsed maps entries, the live attach cell, and the per-candidate
/// map_files confirmation (mirroring the positive path exactly: a
/// colliding file's ranges drop, an unreadable identity refuses the
/// whole seal).
trait AbsenceScanSource: ScanSource {
    fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey];
    fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity;
    fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal>;
    fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal>;
    fn confirm(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal>;
}

fn scan_with(
    source: &mut impl ScanSource,
    domain: NativeDomainId,
    file_slot: u32,
    fence: u64,
) -> Result<ImageScanProof, ImageQueryRefusal> {
    for _ in 0..3 {
        source.budget()?;
        source.audit()?;
        let image = source.query()?;
        if image.task_cookie == 0 {
            return Err(ImageQueryRefusal::Unknown);
        }
        let epochs = source.epochs()?;
        let mut ranges = source.ranges()?;
        let after_epochs = source.epochs()?;
        let after_image = source.query()?;
        source.audit()?;
        source.budget()?;
        if !source.fence(fence) {
            return Err(ImageQueryRefusal::Fence);
        }
        if image != after_image || epochs != after_epochs {
            continue;
        }
        if epochs.sticky != 0
            || epochs.record_flags != 0
            || [epochs.local, epochs.global, epochs.fault]
                .into_iter()
                .any(|cell| cell > u64::from(u32::MAX))
        {
            return Err(ImageQueryRefusal::Coverage);
        }
        if ranges.is_empty() {
            return Err(ImageQueryRefusal::Empty);
        }
        if ranges.len() > 16_384 {
            return Err(ImageQueryRefusal::Capacity);
        }
        ranges.sort();
        ranges.dedup();
        return Ok(ImageScanProof {
            domain,
            image,
            file_slot,
            epochs,
            ranges,
            fence,
        });
    }
    Err(ImageQueryRefusal::Unstable)
}

/// Seal one provider-free interval: the same bracket protocol as
/// [`scan_with`] (budget/audit, image query, epoch brackets, audits,
/// fence, stability, coverage) over a COMPLETE maps enumeration, then
/// the negative rule — zero CONFIRMED watched-provider mappings —
/// instead of the positive non-empty rule. Candidate selection
/// (`ranges_for` per watched key) and map_files confirmation are the
/// positive path's exact functions: a moved mapping (same identity,
/// disjoint addresses) still confirms, so an `mremap`'d provider
/// refuses here with [`ImageQueryRefusal::Present`]; a colliding
/// file's ranges drop; an unreadable identity refuses the whole seal.
/// The live attach cell read inside the brackets ties the enumeration
/// to after that closure's publication (the observer compares it to
/// the claimed closure). A deliberately separate mirror of
/// `scan_with`, not a shared flag: absence is a different statement,
/// and the positive seal stays byte-identical.
fn prove_absence_with(
    source: &mut impl AbsenceScanSource,
    domain: NativeDomainId,
    file_slot: u32,
    fence: u64,
) -> Result<ImageAbsenceProof, ImageQueryRefusal> {
    for _ in 0..3 {
        source.budget()?;
        source.audit()?;
        let image = source.query()?;
        if image.task_cookie == 0 {
            return Err(ImageQueryRefusal::Unknown);
        }
        let epochs = source.epochs()?;
        let entries = source.entries()?;
        let attach_generation = source.attach_generation()?;
        let after_epochs = source.epochs()?;
        let after_image = source.query()?;
        source.audit()?;
        source.budget()?;
        if !source.fence(fence) {
            return Err(ImageQueryRefusal::Fence);
        }
        if image != after_image || epochs != after_epochs {
            continue;
        }
        if epochs.sticky != 0
            || epochs.record_flags != 0
            || [epochs.local, epochs.global, epochs.fault]
                .into_iter()
                .any(|cell| cell > u64::from(u32::MAX))
        {
            return Err(ImageQueryRefusal::Coverage);
        }
        // The enumeration itself must be complete and non-trivial: a
        // live process always maps something, so an empty listing is a
        // corrupt read, never a witness. (The ban on empty POSITIVES
        // is untouched: this type carries provider-freedom of a
        // complete scan, never an empty scan as absence.)
        if entries.is_empty() {
            return Err(ImageQueryRefusal::Stream);
        }
        let mut candidates = Vec::new();
        for key in source.watched_keys() {
            candidates.extend(crate::discovery::instances::ranges_for(
                &entries,
                key.device.major,
                key.device.minor,
                key.inode,
            ));
        }
        if candidates.len() > 16_384 {
            return Err(ImageQueryRefusal::Capacity);
        }
        let confirmed = crate::discovery::instances::confirm_identity(
            candidates,
            source.watched_identity(),
            |start, end| {
                source
                    .confirm(start, end)
                    .map_err(|refusal| format!("{refusal:?}"))
            },
        )
        .map_err(|_| ImageQueryRefusal::Custody)?;
        if !confirmed.is_empty() {
            return Err(ImageQueryRefusal::Present);
        }
        // N14: confirmation performed I/O after the maps snapshot —
        // a mapping can move while its old address is replaced by a
        // foreign file between the enumeration and its stat, which
        // drops the old candidate as foreign and manufactures a
        // provider-free interval from stale brackets. Close the
        // brackets AGAIN after every identity confirmation: the
        // sealed epochs/image must still be current and the audits,
        // budget and fence must still hold. Anything that moved
        // retries with a fresh enumeration; exhaustion refuses with
        // Unstable, never a stale seal. (A closure that advanced
        // during confirmation needs no re-read here: the sealed
        // attach cell then mismatches the live closure and the birth
        // refuses on generation.)
        let verify_epochs = source.epochs()?;
        let verify_image = source.query()?;
        source.audit()?;
        source.budget()?;
        if !source.fence(fence) {
            return Err(ImageQueryRefusal::Fence);
        }
        if image != verify_image || epochs != verify_epochs {
            continue;
        }
        return Ok(ImageAbsenceProof {
            domain,
            image,
            file_slot,
            epochs,
            attach_generation,
            total_entries: entries.len(),
            fence,
        });
    }
    Err(ImageQueryRefusal::Unstable)
}

/// Script only the I/O beneath the owning acquisition protocol. Router
/// regressions still obtain their seal through all of `scan_with`'s checks;
/// they cannot construct a proof or replace its fence after acquisition.
#[cfg(test)]
pub(crate) fn acquire_test_scan(
    domain: NativeDomainId,
    image: ImageIdentity,
    file_slot: u32,
    epochs: CompleteEpochs,
    ranges: Vec<MapRange>,
    fence: u64,
) -> Result<ImageScanProof, ImageQueryRefusal> {
    struct Reads {
        image: ImageIdentity,
        epochs: CompleteEpochs,
        ranges: Vec<MapRange>,
        fence: u64,
    }
    impl ScanSource for Reads {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            Ok(self.image)
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            Ok(self.epochs)
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            Ok(self.ranges.clone())
        }
        fn fence(&self, original: u64) -> bool {
            original == self.fence
        }
    }
    scan_with(
        &mut Reads {
            image,
            epochs,
            ranges,
            fence,
        },
        domain,
        file_slot,
        fence,
    )
}

/// Script only the I/O beneath the owning absence protocol: the full
/// maps enumeration, the attach cell and the per-candidate
/// confirmation. Absence tests still obtain their witness through all
/// of `prove_absence_with`'s checks; they cannot construct a proof or
/// replace its fence after acquisition. (Many arguments is the honest
/// shape: every sealed input is injected, none supplied.)
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn acquire_test_absence(
    domain: NativeDomainId,
    image: ImageIdentity,
    file_slot: u32,
    epochs: CompleteEpochs,
    entries: Vec<p11scope_manifest::maps::MapEntry>,
    attach_generation: u64,
    keys: Vec<p11scope_manifest::maps::ObjectKey>,
    identity: crate::discovery::instances::MappedFileIdentity,
    mut confirm: impl FnMut(
        u64,
        u64,
    ) -> Result<
        crate::discovery::instances::MappedFileIdentity,
        ImageQueryRefusal,
    >,
    fence: u64,
) -> Result<ImageAbsenceProof, ImageQueryRefusal> {
    struct Reads<F> {
        image: ImageIdentity,
        epochs: CompleteEpochs,
        entries: Vec<p11scope_manifest::maps::MapEntry>,
        attach_generation: u64,
        keys: Vec<p11scope_manifest::maps::ObjectKey>,
        identity: crate::discovery::instances::MappedFileIdentity,
        confirm: F,
        fence: u64,
    }
    impl<
        F: FnMut(
            u64,
            u64,
        )
            -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal>,
    > ScanSource for Reads<F>
    {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            Ok(self.image)
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            Ok(self.epochs)
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            Ok(Vec::new())
        }
        fn fence(&self, original: u64) -> bool {
            original == self.fence
        }
    }
    impl<
        F: FnMut(
            u64,
            u64,
        )
            -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal>,
    > AbsenceScanSource for Reads<F>
    {
        fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey] {
            &self.keys
        }
        fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity {
            self.identity
        }
        fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
            Ok(self.entries.clone())
        }
        fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal> {
            Ok(self.attach_generation)
        }
        fn confirm(
            &mut self,
            start: u64,
            end: u64,
        ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal> {
            (self.confirm)(start, end)
        }
    }
    prove_absence_with(
        &mut Reads {
            image,
            epochs,
            entries,
            attach_generation,
            keys,
            identity,
            confirm: &mut confirm,
            fence,
        },
        domain,
        file_slot,
        fence,
    )
}

fn parse_batch(
    domain: NativeDomainId,
    generation: u64,
    requested: &[u64],
    bytes: &[u8],
) -> Result<ImageQueryBatch, ImageQueryRefusal> {
    if generation == 0
        || requested.is_empty()
        || requested.len() > QUERY_LIMIT
        || requested.iter().any(|cookie| {
            *cookie == 0 || *cookie > p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT
        })
        || requested
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != requested.len()
        || bytes.len() != (requested.len() + 1) * ROW_LEN
    {
        return Err(ImageQueryRefusal::Stream);
    }
    let mut images = BTreeMap::new();
    for (position, row) in bytes.as_chunks::<ROW_LEN>().0.iter().enumerate() {
        let word = |offset: usize| u64::from_le_bytes(row[offset..offset + 8].try_into().unwrap());
        let slot = u32::from_le_bytes(row[32..36].try_into().unwrap()) as usize;
        let status = u32::from_le_bytes(row[36..40].try_into().unwrap());
        if word(0) != generation {
            return Err(ImageQueryRefusal::Stream);
        }
        if position == requested.len() {
            if status != 3
                || word(8) != 0
                || word(16) != requested.len() as u64
                || slot != requested.len()
                || word(24) < requested.len() as u64 + 1
                || word(24) > VISIT_LIMIT
            {
                return Err(ImageQueryRefusal::Stream);
            }
        } else {
            if status != 1 {
                return Err(ImageQueryRefusal::Unknown);
            }
            if requested.get(slot) != Some(&word(8))
                || word(24) == 0
                || word(24) & 1 != 0
                || images
                    .insert(
                        word(8),
                        ImageIdentity {
                            task_cookie: word(8),
                            exec_id: word(16),
                        },
                    )
                    .is_some()
            {
                return Err(ImageQueryRefusal::Stream);
            }
        }
    }
    Ok(ImageQueryBatch { domain, images })
}

fn selector_pidfd(raw: i32) -> Result<u32, ImageQueryRefusal> {
    if raw <= 0 {
        return Err(ImageQueryRefusal::Custody);
    }
    u32::try_from(raw).map_err(|_| ImageQueryRefusal::Custody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    fn domain() -> NativeDomainId {
        NativeDomainId::mint()
    }
    fn row(
        generation: u64,
        cookie: u64,
        exec_id: u64,
        sequence: u64,
        slot: u32,
        status: u32,
    ) -> Vec<u8> {
        [
            generation.to_le_bytes().as_slice(),
            cookie.to_le_bytes().as_slice(),
            exec_id.to_le_bytes().as_slice(),
            sequence.to_le_bytes().as_slice(),
            slot.to_le_bytes().as_slice(),
            status.to_le_bytes().as_slice(),
        ]
        .concat()
    }
    fn valid_stream() -> Vec<u8> {
        [row(3, 7, 0, 2, 0, 1), row(3, 0, 1, 2, 1, 3)].concat()
    }
    #[test]
    fn pidfd_zero_selector_never_means_all_tasks() {
        assert_eq!(selector_pidfd(0), Err(ImageQueryRefusal::Custody));
        assert_eq!(selector_pidfd(1), Ok(1));
    }
    #[test]
    fn private_image_hash_requires_permanent_flags_and_original_write_only_fd() {
        use std::fs::{File, OpenOptions};
        let file = tempfile::NamedTempFile::new().unwrap();
        let write_only = OpenOptions::new().write(true).open(file.path()).unwrap();
        let read_only = File::open(file.path()).unwrap();
        let read_write = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file.path())
            .unwrap();
        assert_eq!(
            read_fd_access_mode(write_only.as_raw_fd()).unwrap(),
            libc::O_WRONLY
        );
        assert!(read_fd_access_mode(-1).is_err());
        for (name, value) in [("IMAGE_CONTINUITY", 24), ("IMAGE_TGID_INDEX", 8)] {
            for count in [1, 16_384] {
                let expected =
                    super::super::map_metadata(aya::maps::MapType::Hash, 8, value, count, 1);
                validate_image_map_contract(name, expected, expected, write_only.as_fd()).unwrap();
                for fd in [read_only.as_fd(), read_write.as_fd()] {
                    assert!(validate_image_map_contract(name, expected, expected, fd).is_err());
                }
                for actual in [
                    super::super::ExactMapMetadata {
                        flags: 0,
                        ..expected
                    },
                    super::super::ExactMapMetadata {
                        flags: 17,
                        ..expected
                    },
                    super::super::ExactMapMetadata {
                        key_size: 9,
                        ..expected
                    },
                    super::super::ExactMapMetadata {
                        value_size: value + 1,
                        ..expected
                    },
                    super::super::ExactMapMetadata {
                        max_entries: count + 1,
                        ..expected
                    },
                    super::super::ExactMapMetadata {
                        map_type: aya::maps::MapType::Array,
                        ..expected
                    },
                ] {
                    assert!(
                        validate_image_map_contract(name, actual, expected, write_only.as_fd())
                            .is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn image_query_rejects_foreign_cookie_duplicate_and_stale_generation() {
        for bytes in [
            [row(3, 8, 0, 2, 0, 1), row(3, 0, 1, 2, 1, 3)].concat(),
            [row(2, 7, 0, 2, 0, 1), row(3, 0, 1, 2, 1, 3)].concat(),
        ] {
            assert!(parse_batch(domain(), 3, &[7], &bytes).is_err());
        }
        let duplicate = [
            row(3, 7, 0, 2, 0, 1),
            row(3, 7, 0, 2, 0, 1),
            row(3, 0, 2, 3, 2, 3),
        ]
        .concat();
        assert!(parse_batch(domain(), 3, &[7, 8], &duplicate).is_err());
        let owner = domain();
        let batch = parse_batch(owner, 3, &[7], &valid_stream()).unwrap();
        assert_eq!(batch.domain(), owner);
        assert_eq!(batch.image(7).unwrap().exec_id, 0);
    }
    struct Script {
        images: VecDeque<ImageIdentity>,
        epoch: CompleteEpochs,
        deadline: Instant,
        fence: u64,
        audits: usize,
        audit_failure: Option<usize>,
        epoch_changes: VecDeque<CompleteEpochs>,
        empty_ranges: bool,
        expire_on_ranges: bool,
        audit_reader: Option<Box<dyn FnMut() -> Result<(), ImageQueryRefusal>>>,
    }
    impl ScanSource for Script {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            if Instant::now() >= self.deadline {
                Err(ImageQueryRefusal::Deadline)
            } else {
                Ok(())
            }
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            self.audits += 1;
            if let Some(read) = &mut self.audit_reader {
                read()?;
            }
            if Some(self.audits) == self.audit_failure {
                return Err(ImageQueryRefusal::Coverage);
            }
            Ok(())
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            self.images.pop_front().ok_or(ImageQueryRefusal::Unstable)
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            Ok(self.epoch_changes.pop_front().unwrap_or(self.epoch))
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            if self.expire_on_ranges {
                self.deadline = Instant::now();
            }
            Ok(if self.empty_ranges {
                Vec::new()
            } else {
                vec![MapRange::new(0x1000, 0x2000, 0, true)]
            })
        }
        fn fence(&self, original: u64) -> bool {
            original == self.fence
        }
    }
    fn script(exec_after: u64) -> Script {
        Script {
            // A third closing read: the positive seal consumes two
            // image reads per attempt; the absence seal consumes one
            // more after its identity confirmation (N14).
            images: VecDeque::from([
                ImageIdentity {
                    task_cookie: 7,
                    exec_id: 0,
                },
                ImageIdentity {
                    task_cookie: 7,
                    exec_id: exec_after,
                },
                ImageIdentity {
                    task_cookie: 7,
                    exec_id: exec_after,
                },
            ]),
            epoch: CompleteEpochs {
                local: 0,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            deadline: Instant::now() + Duration::from_secs(1),
            fence: 4,
            audits: 0,
            audit_failure: None,
            epoch_changes: VecDeque::new(),
            empty_ranges: false,
            expire_on_ranges: false,
            audit_reader: None,
        }
    }
    #[test]
    fn same_cookie_reexec_during_scan_refuses() {
        assert!(scan_with(&mut script(1), domain(), 0, 4).is_err());
    }
    #[test]
    fn stable_full_image_scan_has_nonempty_ranges() {
        let mut source = script(0);
        let proof = scan_with(&mut source, domain(), 0, 4).unwrap();
        assert!(!proof.ranges().is_empty());
        assert_eq!(proof.image().exec_id, 0);
        assert_eq!(proof.fence(), 4);
        assert_eq!(source.audits, 2);
    }
    #[test]
    fn original_fence_change_refuses_the_entire_scan() {
        assert!(scan_with(&mut script(0), domain(), 0, 3).is_err());
    }
    #[test]
    fn image_query_requires_complete_end_and_no_partial_bytes() {
        let valid = valid_stream();
        for bytes in [&valid[..ROW_LEN], &valid[..valid.len() - 1]] {
            assert!(parse_batch(domain(), 3, &[7], bytes).is_err());
        }
        let bad_end = [row(3, 7, 0, 2, 0, 1), row(3, 0, 1, 1, 1, 3)].concat();
        assert!(parse_batch(domain(), 3, &[7], &bad_end).is_err());
    }

    #[test]
    fn post_scan_audit_failure_empty_ranges_and_late_io_never_seal() {
        let mut failed_audit = script(0);
        failed_audit.audit_failure = Some(2);
        assert!(matches!(
            scan_with(&mut failed_audit, domain(), 0, 4),
            Err(ImageQueryRefusal::Coverage)
        ));
        let mut empty = script(0);
        empty.empty_ranges = true;
        assert!(matches!(
            scan_with(&mut empty, domain(), 0, 4),
            Err(ImageQueryRefusal::Empty)
        ));
        let mut late = script(0);
        late.expire_on_ranges = true;
        assert!(matches!(
            scan_with(&mut late, domain(), 0, 4),
            Err(ImageQueryRefusal::Deadline)
        ));
    }

    #[test]
    fn miss_read_after_final_query_prevents_seal_and_permanently_fails() {
        let owner = std::rc::Rc::new(CoverageControl::test_owner(true));
        let audit_owner = owner.clone();
        let mut reads = 0;
        let mut source = script(0);
        source.audit_reader = Some(Box::new(move || {
            reads += 1;
            let mut stats: Vec<_> = super::super::INSTANCE_PROGRAMS
                .iter()
                .enumerate()
                .map(|(index, (name, _))| {
                    (
                        *name,
                        super::super::HookStats {
                            program_id: index as u32 + 1,
                            ..super::super::HookStats::default()
                        },
                    )
                })
                .collect();
            let expected = stats
                .iter()
                .map(|(name, stat)| (*name, stat.program_id))
                .collect();
            if reads == 2 {
                stats[3].1.recursion_misses = 1;
            }
            super::super::instance::audit_image_hooks_with(
                &audit_owner,
                true,
                4,
                &expected,
                || Ok("1".into()),
                || Ok(stats),
                || Ok((0, 0)),
            )
            .map_err(|_| ImageQueryRefusal::Coverage)
        }));
        assert!(matches!(
            scan_with(&mut source, domain(), 0, 4),
            Err(ImageQueryRefusal::Coverage)
        ));
        assert_eq!(source.audits, 2);
        assert!(!owner.enabled());
        assert!(owner.enable().is_err());
    }

    #[test]
    fn complete_epoch_changes_retry_three_whole_attempts_and_exhaustion_refuses() {
        let mut source = script(0);
        source.images = VecDeque::from(vec![source.images[0]; 6]);
        let mut changed = source.epoch;
        changed.global = 1;
        source.epoch_changes = VecDeque::from([source.epoch, changed].repeat(3));
        assert!(matches!(
            scan_with(&mut source, domain(), 0, 4),
            Err(ImageQueryRefusal::Unstable)
        ));
        assert_eq!(source.audits, 6);
        for cell in 0..5 {
            let mut exhausted = script(0);
            match cell {
                0 => exhausted.epoch.local = u64::from(u32::MAX) + 1,
                1 => exhausted.epoch.global = u64::from(u32::MAX) + 1,
                2 => exhausted.epoch.fault = u64::from(u32::MAX) + 1,
                3 => exhausted.epoch.sticky = 1,
                _ => exhausted.epoch.record_flags = 1,
            }
            assert!(matches!(
                scan_with(&mut exhausted, domain(), 0, 4),
                Err(ImageQueryRefusal::Coverage)
            ));
        }
    }

    #[test]
    fn actual_iterator_reader_rejects_eagain_and_accepts_only_eof() {
        use std::io::Write as _;
        let mut raw = [0; 2];
        // SAFETY: valid two-element output buffer; pipe2 returns two owned fds.
        assert_eq!(
            unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        // SAFETY: pipe2 succeeded and these are its distinct newly owned fds.
        let read = unsafe { OwnedFd::from_raw_fd(raw[0]) };
        let mut write = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw[1]) });
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(matches!(
            read_iterator(read.as_fd(), deadline, 128),
            Err(ImageQueryRefusal::Stream)
        ));
        write.write_all(b"complete bytes").unwrap();
        drop(write);
        assert_eq!(
            read_iterator(read.as_fd(), deadline, 128).unwrap(),
            b"complete bytes"
        );
        assert!(matches!(
            read_iterator(read.as_fd(), Instant::now(), 128),
            Err(ImageQueryRefusal::Deadline)
        ));
    }

    #[test]
    fn permanent_failure_wins_enable_between_its_two_cas_operations() {
        use std::sync::atomic::{AtomicU64, Ordering};
        for initial in [0, 1] {
            let cell = AtomicU64::new(initial);
            fail_coverage_with(&cell, || {
                std::thread::scope(|scope| {
                    scope.spawn(|| {
                        assert!(
                            cell.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                                .is_err()
                        );
                    });
                });
            });
            assert_eq!(cell.load(Ordering::SeqCst), 2);
        }
        // The other race ordering: activation wins first, then failure revokes it.
        let cell = AtomicU64::new(0);
        assert!(
            cell.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        );
        fail_coverage_with(&cell, || {});
        assert_eq!(cell.load(Ordering::SeqCst), 2);
    }

    struct ProcFixture {
        directory: tempfile::TempDir,
        pin: crate::process::PidPin,
        original: std::path::PathBuf,
        successor: std::path::PathBuf,
        key: p11scope_manifest::maps::ObjectKey,
        identity: crate::discovery::instances::MappedFileIdentity,
    }
    impl ProcFixture {
        fn new() -> Self {
            use std::os::unix::fs::MetadataExt as _;
            let directory = tempfile::tempdir().unwrap();
            let pin = crate::process::PidPin::open(std::process::id()).unwrap();
            let birth = pin.start_time().unwrap();
            std::fs::write(
                directory.path().join("stat"),
                format!(
                    "{} (fixture) S {} {birth}\n",
                    pin.pid(),
                    ["0"; 18].join(" ")
                ),
            )
            .unwrap();
            let original = directory.path().join("original");
            let successor = directory.path().join("successor");
            std::fs::write(&original, b"original file").unwrap();
            std::fs::write(&successor, b"successor file").unwrap();
            std::fs::create_dir(directory.path().join("map_files")).unwrap();
            std::os::unix::fs::symlink(&original, directory.path().join("map_files/1000-2000"))
                .unwrap();
            // A maps key may collide across subvolumes; map_files resolves
            // another device domain. Neither is reconstructed from pathname.
            let key = p11scope_manifest::maps::ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: 0,
                    minor: 99,
                },
                inode: 7,
            };
            std::fs::write(
                directory.path().join("maps"),
                b"1000-2000 r-xp 00000000 00:63 7 /provider\n",
            )
            .unwrap();
            let metadata = std::fs::metadata(&successor).unwrap();
            let identity = crate::discovery::instances::MappedFileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            };
            assert_ne!(identity.dev, libc::makedev(0, 99));
            Self {
                directory,
                pin,
                original,
                successor,
                key,
                identity,
            }
        }
        fn replace_map_file(&self) {
            let link = self.directory.path().join("map_files/1000-2000");
            std::fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&self.successor, link).unwrap();
        }
    }

    #[test]
    fn actual_proc_ranges_reject_truncation_over_budget_and_calibration_collision() {
        let fixture = ProcFixture::new();
        let proc =
            crate::process::ProcPin::test_open_at(&fixture.pin, fixture.directory.path()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let keys = [fixture.key];
        // Same maps key is insufficient: the original link resolves another file.
        assert!(
            read_confirmed_ranges_with(&proc, &keys, fixture.identity, deadline, 1024, || {})
                .unwrap()
                .is_empty()
        );
        fixture.replace_map_file();
        assert!(
            !read_confirmed_ranges_with(&proc, &keys, fixture.identity, deadline, 1024, || {})
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            read_confirmed_ranges_with(&proc, &keys, fixture.identity, deadline, 8, || {}),
            Err(ImageQueryRefusal::Custody)
        ));
        std::fs::write(
            fixture.directory.path().join("maps"),
            b"1000-2000 r-xp 00000000 00:63 7 /truncated",
        )
        .unwrap();
        assert!(matches!(
            read_confirmed_ranges_with(&proc, &keys, fixture.identity, deadline, 1024, || {}),
            Err(ImageQueryRefusal::Stream)
        ));
        assert!(
            read_confirmed_ranges_with(&proc, &keys, fixture.identity, Instant::now(), 1024, || {})
                .is_err()
        );
    }

    struct ProcScript<'a> {
        script: Script,
        fixture: &'a ProcFixture,
        proc: crate::process::ProcPin<'a>,
        replaced: bool,
    }
    impl ScanSource for ProcScript<'_> {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            self.script.budget()
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            self.script.audit()
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            self.script.query()
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            self.script.epochs()
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            let replace = !self.replaced;
            self.replaced = true;
            read_confirmed_ranges_with(
                &self.proc,
                &[self.fixture.key],
                self.fixture.identity,
                self.script.deadline,
                1024,
                || {
                    if replace {
                        self.fixture.replace_map_file();
                    }
                },
            )
        }
        fn fence(&self, original: u64) -> bool {
            self.script.fence(original)
        }
    }

    #[test]
    fn equal_birth_nonleader_shape_rejects_mixed_ranges_and_allows_stable_successor() {
        let old = ImageIdentity {
            task_cookie: 7,
            exec_id: 3,
        };
        let new = ImageIdentity {
            task_cookie: 8,
            exec_id: 4,
        };
        for retry in [false, true] {
            let fixture = ProcFixture::new();
            assert!(fixture.original.exists());
            // Exact same admission birth and original pidfd can acquire the
            // retained directory; de_thread is detected by full image brackets.
            let proc =
                crate::process::ProcPin::test_open_at(&fixture.pin, fixture.directory.path())
                    .unwrap();
            let mut scripted = script(0);
            scripted.images = if retry {
                VecDeque::from([old, new, new, new])
            } else {
                VecDeque::from([old, new])
            };
            let mut source = ProcScript {
                script: scripted,
                fixture: &fixture,
                proc,
                replaced: false,
            };
            let result = scan_with(&mut source, domain(), 0, 4);
            if retry {
                let proof = result.unwrap();
                assert!(proof.image() == new);
                assert!(!proof.ranges().is_empty());
                assert_eq!(source.script.audits, 4);
            } else {
                assert!(result.is_err(), "mixed old maps/new map_files sealed");
            }
        }
    }

    fn absence_entry(
        start: u64,
        end: u64,
        major: u64,
        minor: u64,
        inode: u64,
    ) -> p11scope_manifest::maps::MapEntry {
        p11scope_manifest::maps::MapEntry {
            start,
            end,
            file_offset: 0,
            permissions: *b"r-xp",
            device: p11scope_manifest::maps::Device { major, minor },
            inode,
            raw_path: None,
        }
    }
    fn absence_free_entries() -> Vec<p11scope_manifest::maps::MapEntry> {
        // A complete process enumeration with no watched-provider
        // mapping: exe/libc/stack-style entries under unrelated
        // identities.
        vec![
            absence_entry(0x400000, 0x401000, 8, 2, 1001),
            absence_entry(0x7f00_0000, 0x7f00_1000, 8, 2, 2002),
            absence_entry(0x7fff_0000, 0x7fff_1000, 0, 0, 0),
        ]
    }
    fn watched_key() -> p11scope_manifest::maps::ObjectKey {
        p11scope_manifest::maps::ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 999,
        }
    }
    fn watched_identity() -> crate::discovery::instances::MappedFileIdentity {
        crate::discovery::instances::MappedFileIdentity {
            dev: 0x801,
            ino: 999,
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ConfirmMode {
        Match,
        Mismatch,
        Error,
    }
    struct AbsenceScript {
        script: Script,
        keys: Vec<p11scope_manifest::maps::ObjectKey>,
        identity: crate::discovery::instances::MappedFileIdentity,
        entries: Vec<p11scope_manifest::maps::MapEntry>,
        attach: u64,
        confirm_mode: ConfirmMode,
        confirms: usize,
    }
    impl ScanSource for AbsenceScript {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            self.script.budget()
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            self.script.audit()
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            self.script.query()
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            self.script.epochs()
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            Ok(Vec::new())
        }
        fn fence(&self, original: u64) -> bool {
            self.script.fence(original)
        }
    }
    impl AbsenceScanSource for AbsenceScript {
        fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey] {
            &self.keys
        }
        fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity {
            self.identity
        }
        fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
            Ok(self.entries.clone())
        }
        fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal> {
            Ok(self.attach)
        }
        fn confirm(
            &mut self,
            _start: u64,
            _end: u64,
        ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal> {
            self.confirms += 1;
            match self.confirm_mode {
                ConfirmMode::Match => Ok(self.identity),
                ConfirmMode::Mismatch => Ok(crate::discovery::instances::MappedFileIdentity {
                    dev: 0x802,
                    ino: 1001,
                }),
                ConfirmMode::Error => Err(ImageQueryRefusal::Custody),
            }
        }
    }
    fn absence_script() -> AbsenceScript {
        AbsenceScript {
            script: script(0),
            keys: vec![watched_key()],
            identity: watched_identity(),
            entries: absence_free_entries(),
            attach: 7,
            confirm_mode: ConfirmMode::Match,
            confirms: 0,
        }
    }

    #[test]
    fn absence_seal_requires_provider_free_complete_enumeration() {
        // C1a(b): a complete enumeration with zero watched mappings
        // seals, carrying the bracketed attach cell; the seal
        // consulted no candidate at all.
        let owner = domain();
        let mut source = absence_script();
        let proof = prove_absence_with(&mut source, owner, 3, 4).unwrap();
        assert_eq!(proof.domain(), owner);
        assert_eq!(
            proof.image(),
            ImageIdentity {
                task_cookie: 7,
                exec_id: 0
            }
        );
        assert_eq!(proof.file_slot(), 3);
        assert!(proof.epochs() == source.script.epoch);
        assert_eq!(proof.attach_generation(), 7);
        assert_eq!(proof.total_entries(), 3);
        assert_eq!(proof.fence(), 4);
        assert_eq!(source.confirms, 0, "no candidate consulted");
        // Three audits per sealed attempt: opening, closing, and the
        // post-confirmation bracket (N14).
        assert_eq!(source.script.audits, 3);
    }

    #[test]
    fn absence_seal_refuses_moved_mapping_by_identity() {
        // C1a(b): the mremap shape — the SAME file-backed watched
        // mapping moved to disjoint addresses — refuses with Present.
        // Identity decides, never addresses: the moved range confirms
        // as the watched file.
        let mut source = absence_script();
        source
            .entries
            .push(absence_entry(0x9000_0000, 0x9000_1000, 8, 1, 999));
        assert!(matches!(
            prove_absence_with(&mut source, domain(), 3, 4),
            Err(ImageQueryRefusal::Present)
        ));
        assert_eq!(source.confirms, 1, "the moved range was confirmed");
    }

    #[test]
    fn absence_seal_drops_collisions_but_refuses_unreadable() {
        // C1a(b): the positive path's exact confirmation rule — a
        // colliding file's ranges drop (absence still seals), while an
        // unreadable identity refuses the whole seal.
        let mut dropped = absence_script();
        dropped
            .entries
            .push(absence_entry(0xa000_0000, 0xa000_1000, 8, 1, 999));
        dropped.confirm_mode = ConfirmMode::Mismatch;
        let proof = prove_absence_with(&mut dropped, domain(), 3, 4).unwrap();
        assert_eq!(proof.total_entries(), 4);
        assert_eq!(dropped.confirms, 1, "the collision was confirmed away");
        let mut unreadable = absence_script();
        unreadable
            .entries
            .push(absence_entry(0xa000_0000, 0xa000_1000, 8, 1, 999));
        unreadable.confirm_mode = ConfirmMode::Error;
        assert!(matches!(
            prove_absence_with(&mut unreadable, domain(), 3, 4),
            Err(ImageQueryRefusal::Custody)
        ));
    }

    #[test]
    fn absence_seal_rejects_empty_unstable_and_fence() {
        // C1a(b): the negative seal keeps every bracket — an empty
        // listing is a corrupt read (never a witness), moved epochs
        // refuse, and a changed fence refuses the entire seal.
        let mut empty = absence_script();
        empty.entries.clear();
        assert!(matches!(
            prove_absence_with(&mut empty, domain(), 3, 4),
            Err(ImageQueryRefusal::Stream)
        ));
        let mut moved = absence_script();
        moved.script.images = VecDeque::from(vec![moved.script.images[0]; 6]);
        let mut changed = moved.script.epoch;
        changed.global = 1;
        moved.script.epoch_changes = VecDeque::from([moved.script.epoch, changed].repeat(3));
        assert!(matches!(
            prove_absence_with(&mut moved, domain(), 3, 4),
            Err(ImageQueryRefusal::Unstable)
        ));
        assert!(prove_absence_with(&mut absence_script(), domain(), 3, 9).is_err());
        let mut sticky = absence_script();
        sticky.script.epoch.sticky = 1;
        assert!(matches!(
            prove_absence_with(&mut sticky, domain(), 3, 4),
            Err(ImageQueryRefusal::Coverage)
        ));
    }

    /// N14: the move-and-replace race DURING confirmation. The first
    /// `confirm` advances the epoch cell (the watched mapping moved
    /// and its old address now maps a foreign file) and reports the
    /// old candidate as foreign; enumerations offered on later
    /// attempts carry the moved watched mapping at its new address.
    /// A seal that closes its brackets before confirmation seals the
    /// stale epoch; the fixed seal re-checks after every identity
    /// confirmation and refuses.
    struct ConfirmRace {
        image: ImageIdentity,
        epoch: CompleteEpochs,
        before: Vec<p11scope_manifest::maps::MapEntry>,
        after: Vec<p11scope_manifest::maps::MapEntry>,
        attach: u64,
        keys: Vec<p11scope_manifest::maps::ObjectKey>,
        identity: crate::discovery::instances::MappedFileIdentity,
        foreign: crate::discovery::instances::MappedFileIdentity,
        advance_epoch: bool,
        flip_fence: bool,
        fence_cell: u64,
        raced: bool,
        confirms: usize,
    }
    impl ScanSource for ConfirmRace {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            Ok(self.image)
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            Ok(self.epoch)
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            Ok(Vec::new())
        }
        fn fence(&self, original: u64) -> bool {
            original == self.fence_cell
        }
    }
    impl AbsenceScanSource for ConfirmRace {
        fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey] {
            &self.keys
        }
        fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity {
            self.identity
        }
        fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
            Ok(if self.raced {
                self.after.clone()
            } else {
                self.before.clone()
            })
        }
        fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal> {
            Ok(self.attach)
        }
        fn confirm(
            &mut self,
            _start: u64,
            _end: u64,
        ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal> {
            self.confirms += 1;
            if !self.raced {
                self.raced = true;
                if self.advance_epoch {
                    self.epoch.global = 1;
                }
                if self.flip_fence {
                    self.fence_cell = 9;
                }
                return Ok(self.foreign);
            }
            Ok(self.identity)
        }
    }
    fn confirm_race(advance_epoch: bool, flip_fence: bool) -> ConfirmRace {
        let mut before = absence_free_entries();
        before.push(absence_entry(0x7000_0000, 0x7000_1000, 8, 1, 999));
        let mut after = absence_free_entries();
        after.push(absence_entry(0x9000_0000, 0x9000_1000, 8, 1, 999));
        ConfirmRace {
            image: ImageIdentity {
                task_cookie: 7,
                exec_id: 0,
            },
            epoch: CompleteEpochs {
                local: 0,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            before,
            after,
            attach: 7,
            keys: vec![watched_key()],
            identity: watched_identity(),
            foreign: crate::discovery::instances::MappedFileIdentity {
                dev: 0x802,
                ino: 1001,
            },
            advance_epoch,
            flip_fence,
            fence_cell: 4,
            raced: false,
            confirms: 0,
        }
    }

    #[test]
    fn absence_seal_refuses_move_and_replace_during_confirmation() {
        // N14: the old candidate drops as foreign DURING confirmation
        // while the epoch advances (the watched mapping moved and its
        // old address was replaced). The first attempt's brackets are
        // stale; the retry re-enumerates, confirms the moved mapping
        // by identity, and refuses Present. Sealing the stale epoch
        // here is the defect.
        let mut source = confirm_race(true, false);
        let result = prove_absence_with(&mut source, domain(), 3, 4);
        assert!(
            matches!(result, Err(ImageQueryRefusal::Present)),
            "move-and-replace during confirmation sealed: {:?}",
            result
                .as_ref()
                .map(|proof| (proof.epochs().global, proof.total_entries()))
        );
        assert!(source.raced, "the race hook never fired");
        assert_eq!(source.confirms, 2, "old candidate plus moved mapping");
    }

    #[test]
    fn absence_seal_checks_fence_after_confirmation() {
        // N14: the fence half of the post-confirmation bracket — a
        // fence that moves during confirmation refuses the whole seal
        // even though the dropped candidate looks foreign.
        let mut source = confirm_race(false, true);
        assert!(matches!(
            prove_absence_with(&mut source, domain(), 3, 4),
            Err(ImageQueryRefusal::Fence)
        ));
        assert!(source.raced, "the race hook never fired");
        assert_eq!(source.confirms, 1, "fence refuses before any retry");
    }

    fn live_race_identity(fd: i32) -> crate::discovery::instances::MappedFileIdentity {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
        crate::discovery::instances::MappedFileIdentity {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        }
    }

    fn live_race_maps() -> Vec<p11scope_manifest::maps::MapEntry> {
        let bytes = std::fs::read("/proc/self/maps").expect("read own maps");
        p11scope_manifest::maps::parse_maps(&bytes).expect("parse own maps")
    }

    /// N14 with real mappings: the reviewer's probe shape — a watched
    /// memfd mapped in this process, a complete LIVE /proc/self/maps
    /// listing on every enumeration read, and a REAL mremap plus a
    /// foreign replacement mapping performed DURING the first
    /// confirmation. Identity comes from each VMA's own file
    /// (resolved through its map_files link, fstat'd by fd because
    /// Yama denies stat on the link itself). Only the
    /// epoch/audit/image source is injected: stable except for the
    /// raced advance; the fence never moves.
    struct LiveConfirmRace {
        image: ImageIdentity,
        epoch: CompleteEpochs,
        attach: u64,
        keys: Vec<p11scope_manifest::maps::ObjectKey>,
        identity: crate::discovery::instances::MappedFileIdentity,
        watched_fd: i32,
        replacement_fd: i32,
        old: u64,
        moved: u64,
        raced: bool,
        first_was_foreign: bool,
        confirms: usize,
        /// N17: rendezvous with the racing unhinted allocation. The
        /// confirm hook waits after the move (competitor allocates and
        /// writes its sentinel), waits again (sentinel written), then
        /// replaces the old address and waits a third time (competitor
        /// reads its byte back). Three waits each side, same order.
        barrier: std::sync::Arc<std::sync::Barrier>,
    }
    impl ScanSource for LiveConfirmRace {
        fn budget(&self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn audit(&mut self) -> Result<(), ImageQueryRefusal> {
            Ok(())
        }
        fn query(&mut self) -> Result<ImageIdentity, ImageQueryRefusal> {
            Ok(self.image)
        }
        fn epochs(&mut self) -> Result<CompleteEpochs, ImageQueryRefusal> {
            Ok(self.epoch)
        }
        fn ranges(&mut self) -> Result<Vec<MapRange>, ImageQueryRefusal> {
            Ok(Vec::new())
        }
        fn fence(&self, original: u64) -> bool {
            original == 4
        }
    }
    impl AbsenceScanSource for LiveConfirmRace {
        fn watched_keys(&self) -> &[p11scope_manifest::maps::ObjectKey] {
            &self.keys
        }
        fn watched_identity(&self) -> crate::discovery::instances::MappedFileIdentity {
            self.identity
        }
        fn entries(&mut self) -> Result<Vec<p11scope_manifest::maps::MapEntry>, ImageQueryRefusal> {
            Ok(live_race_maps())
        }
        fn attach_generation(&mut self) -> Result<u64, ImageQueryRefusal> {
            Ok(self.attach)
        }
        fn confirm(
            &mut self,
            start: u64,
            end: u64,
        ) -> Result<crate::discovery::instances::MappedFileIdentity, ImageQueryRefusal> {
            self.confirms += 1;
            // The VMA's own file, resolved through its map_files link.
            let link = format!("/proc/self/map_files/{start:x}-{end:x}");
            if !self.raced {
                self.raced = true;
                // Move the watched mapping elsewhere, replace its old
                // address with the foreign file, and advance the epoch
                // — all between the enumeration and its stat.
                let target = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(target, libc::MAP_FAILED, "reserve the move target");
                // MREMAP_FIXED over the HELD reservation plus
                // DONTUNMAP: the old address stays owned by this
                // fixture until the MAP_FIXED replacement below, so
                // no racing allocation in this shared test process
                // can land there in between (N17). The observable
                // race is unchanged: afterwards the old address
                // holds the foreign file and the moved address the
                // watched one.
                let moved = unsafe {
                    libc::mremap(
                        self.old as *mut libc::c_void,
                        4096,
                        4096,
                        libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED | libc::MREMAP_DONTUNMAP,
                        target,
                    )
                };
                assert_ne!(moved, libc::MAP_FAILED, "move the watched mapping");
                assert_eq!(moved, target, "the move must really relocate");
                // N17: let a racing unhinted allocation land in the
                // move/replacement window; it must take another
                // address and its sentinel must survive below.
                self.barrier.wait();
                self.barrier.wait();
                let replaced = unsafe {
                    libc::mmap(
                        self.old as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        self.replacement_fd,
                        0,
                    )
                };
                assert_eq!(
                    replaced, self.old as *mut libc::c_void,
                    "replace the old address"
                );
                self.barrier.wait();
                self.moved = target as u64;
                self.epoch.global = 1;
                let target_name =
                    std::fs::read_link(&link).expect("the replaced VMA keeps a map_files link");
                assert!(
                    target_name.to_string_lossy().contains("n14-repl"),
                    "the kernel must agree the old address is replaced: {target_name:?}"
                );
                let identity = live_race_identity(self.replacement_fd);
                self.first_was_foreign = identity != self.identity;
                return Ok(identity);
            }
            let target_name = std::fs::read_link(&link).map_err(|_| ImageQueryRefusal::Custody)?;
            if target_name.to_string_lossy().contains("n14-watched") {
                Ok(live_race_identity(self.watched_fd))
            } else if target_name.to_string_lossy().contains("n14-repl") {
                Ok(live_race_identity(self.replacement_fd))
            } else {
                Err(ImageQueryRefusal::Custody)
            }
        }
    }

    #[test]
    fn absence_seal_refuses_move_and_replace_during_confirmation_live_maps() {
        // N14, reviewer probe shape with real mappings (see above).
        // Pre-fix this seals the stale epoch while the watched
        // provider stays mapped; post-fix the retry confirms the
        // moved mapping by identity and refuses Present.
        fn memfd(name: &std::ffi::CStr) -> i32 {
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            assert_ne!(fd, -1, "create {name:?}");
            assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
            fd
        }
        let watched = memfd(c"n14-watched");
        let replacement = memfd(c"n14-repl");
        let old = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                watched,
                0,
            )
        };
        assert_ne!(old, libc::MAP_FAILED, "map the watched file");
        let old_addr = old as u64;
        let watched_key = live_race_maps()
            .into_iter()
            .find(|entry| entry.start <= old_addr && old_addr < entry.end)
            .map(|entry| p11scope_manifest::maps::ObjectKey {
                device: entry.device,
                inode: entry.inode,
            })
            .expect("the watched mapping is listed");
        assert_ne!(watched_key.inode, 0, "the watched key must select");
        // N17 competing-allocation control: a thread racing an
        // ordinary unhinted mmap plus sentinel byte 165 into the
        // move/replacement window (the reviewer's probe shape). The
        // rendezvous is barrier-deterministic, not timing luck.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let competitor_addr = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let competitor_byte = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        let competitor = std::thread::spawn({
            let barrier = std::sync::Arc::clone(&barrier);
            let competitor_addr = std::sync::Arc::clone(&competitor_addr);
            let competitor_byte = std::sync::Arc::clone(&competitor_byte);
            move || {
                barrier.wait();
                let raced = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(raced, libc::MAP_FAILED, "competitor maps");
                competitor_addr.store(raced as u64, std::sync::atomic::Ordering::SeqCst);
                unsafe { std::ptr::write_bytes(raced, 165, 1) };
                barrier.wait();
                barrier.wait();
                let back = unsafe { std::ptr::read(raced as *const u8) };
                competitor_byte.store(back, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let mut source = LiveConfirmRace {
            image: ImageIdentity {
                task_cookie: 7,
                exec_id: 0,
            },
            epoch: CompleteEpochs {
                local: 0,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            attach: 7,
            keys: vec![watched_key],
            identity: live_race_identity(watched),
            watched_fd: watched,
            replacement_fd: replacement,
            old: old_addr,
            moved: 0,
            raced: false,
            first_was_foreign: false,
            confirms: 0,
            barrier,
        };
        let result = prove_absence_with(&mut source, domain(), 3, 4);
        // The watched provider never stopped being mapped (the
        // reviewer's `watched_still_mapped` control), checked before
        // teardown unmaps anything.
        let still_mapped = source.moved != 0
            && std::fs::read_link(format!(
                "/proc/self/map_files/{:x}-{:x}",
                source.moved,
                source.moved + 4096
            ))
            .is_ok_and(|target| target.to_string_lossy().contains("n14-watched"));
        unsafe {
            if source.moved != 0 {
                libc::munmap(source.moved as *mut libc::c_void, 4096);
            }
            libc::munmap(old, 4096);
            libc::close(watched);
            libc::close(replacement);
        }
        competitor.join().expect("the competitor thread finishes");
        let landed = competitor_addr.load(std::sync::atomic::Ordering::SeqCst);
        let survived = competitor_byte.load(std::sync::atomic::Ordering::SeqCst);
        if landed != 0 && landed != old_addr {
            unsafe {
                libc::munmap(landed as *mut libc::c_void, 4096);
            }
        }
        assert!(source.raced, "the race hook never fired");
        assert_ne!(
            landed, old_addr,
            "the racing allocation must not take the fixture's address"
        );
        assert_eq!(
            survived, 165,
            "the racing allocation's sentinel must survive the replacement"
        );
        assert!(
            source.first_was_foreign,
            "the old candidate must drop as foreign during the race"
        );
        assert!(still_mapped, "the watched provider must stay mapped");
        assert!(
            matches!(result, Err(ImageQueryRefusal::Present)),
            "move-and-replace during confirmation sealed: {:?}",
            result
                .as_ref()
                .map(|proof| (proof.epochs().global, proof.total_entries()))
        );
        assert_eq!(source.confirms, 2, "old candidate plus moved mapping");
    }
}
