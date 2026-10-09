//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, retained-root cgroup candidate discovery and fresh leaf sampling.
//! Candidates never authorize admission. Samples are endpoints, not continuous
//! residency, process/image identity, scope absence, or call-time authority.
//! Cancellation is cooperative: an in-flight filesystem syscall must return.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Instant;

const CHUNK: usize = 4096;
const DIRECTORY_FLAGS: u64 = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionStop {
    OperatorStop,
    Deadline,
}

/// Cloneable per-collection control, also usable by later scan/commit stages.
/// The first stop reason is sticky and shared by every clone.
#[derive(Clone)]
pub(crate) struct CollectionControl {
    deadline: Option<Instant>,
    stop: Arc<AtomicU8>,
    operator_stop_source: Option<Arc<AtomicUsize>>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}
impl CollectionControl {
    pub(crate) fn new(deadline: Option<Instant>) -> Self {
        Self::with_clock(deadline, Instant::now)
    }
    pub(crate) fn with_clock(
        deadline: Option<Instant>,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            deadline,
            stop: Arc::new(AtomicU8::new(0)),
            operator_stop_source: None,
            clock: Arc::new(clock),
        }
    }
    pub(crate) fn with_operator_stop_source(mut self, source: Arc<AtomicUsize>) -> Self {
        self.operator_stop_source = Some(source);
        self
    }
    pub(crate) fn cancel(&self) {
        let _ = self
            .stop
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }
    pub(crate) fn check(&self) -> Result<(), CollectionStop> {
        if self.stop.load(Ordering::Acquire) == 0
            && self
                .operator_stop_source
                .as_ref()
                .is_some_and(|source| source.load(Ordering::Acquire) != 0)
        {
            self.cancel();
        }
        if self.stop.load(Ordering::Acquire) == 0
            && self
                .deadline
                .is_some_and(|deadline| (self.clock)() >= deadline)
        {
            let _ = self
                .stop
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.stop.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(CollectionStop::OperatorStop),
            _ => Err(CollectionStop::Deadline),
        }
    }
}

/// Private safety ceilings, not a qualified release workload envelope.
#[derive(Clone, Debug)]
pub(crate) struct CgroupWalkLimits {
    pub(crate) directories: usize,
    pub(crate) depth: usize,
    pub(crate) members: usize,
    pub(crate) file_bytes: usize,
    pub(crate) total_bytes: usize,
    pub(crate) path_bytes: usize,
    pub(crate) work_units: usize,
    pub(crate) open_fds: usize,
}
impl Default for CgroupWalkLimits {
    fn default() -> Self {
        Self {
            directories: 4096,
            depth: 64,
            members: 65536,
            file_bytes: 1 << 20,
            total_bytes: 8 << 20,
            path_bytes: 1 << 20,
            work_units: 1 << 20,
            open_fds: 70,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct CandidateQuota {
    pub(crate) candidates: usize,
    pub(crate) work_units: usize,
}
impl Default for CandidateQuota {
    fn default() -> Self {
        Self {
            candidates: 256,
            work_units: 1 << 16,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CgroupWork {
    pub(crate) directories: usize,
    pub(crate) members: usize,
    pub(crate) membership_bytes: usize,
    pub(crate) path_bytes: usize,
    pub(crate) units: usize,
    pub(crate) peak_open_fds: usize,
}
/// One transaction allowance for discovery, grouped begin/end samples, and
/// caller-charged sweep/scan/confirmation work. Sample answers reuse candidate
/// slots, but all grouping/output allocation and nonmatching parse work counts.
/// Begin each collection with next_candidates to account its live continuation.
pub(crate) struct CgroupWalkBudget {
    limits: CgroupWalkLimits,
    pub(crate) used: CgroupWork,
    file_reads: BTreeMap<(u64, u64), usize>,
    candidate_pids: BTreeSet<u32>,
    retained_fds: usize,
    slice_end: Option<usize>,
}
impl CgroupWalkBudget {
    pub(crate) fn new(limits: CgroupWalkLimits) -> Self {
        Self {
            limits,
            used: CgroupWork::default(),
            file_reads: BTreeMap::new(),
            candidate_pids: BTreeSet::new(),
            retained_fds: 0,
            slice_end: None,
        }
    }
    pub(crate) fn charge_work(
        &mut self,
        control: &CollectionControl,
        units: usize,
    ) -> Result<(), CollectionOutcome> {
        checkpoint(control)?;
        if units > self.limits.work_units.saturating_sub(self.used.units) {
            return Err(incomplete(CgroupIncomplete::WorkLimit));
        }
        if self
            .slice_end
            .is_some_and(|end| units > end.saturating_sub(self.used.units))
        {
            return Err(incomplete(CgroupIncomplete::DiscoverySlice));
        }
        self.used.units += units;
        Ok(())
    }
    fn directory(&mut self) -> Result<(), CollectionOutcome> {
        charge(
            &mut self.used.directories,
            1,
            self.limits.directories,
            CgroupIncomplete::DirectoryLimit,
        )
    }
    fn path(&mut self, bytes: usize) -> Result<(), CollectionOutcome> {
        charge(
            &mut self.used.path_bytes,
            bytes,
            self.limits.path_bytes,
            CgroupIncomplete::PathBytesLimit,
        )
    }
    fn candidate(
        &mut self,
        pid: u32,
        control: &CollectionControl,
    ) -> Result<(), CollectionOutcome> {
        if !self.candidate_pids.contains(&pid) {
            self.charge_work(control, 1)?;
            charge(
                &mut self.used.members,
                1,
                self.limits.members,
                CgroupIncomplete::MemberLimit,
            )?;
            self.candidate_pids.insert(pid);
        }
        Ok(())
    }
    fn fds(&mut self, count: usize) -> Result<(), CollectionOutcome> {
        if count > self.limits.open_fds {
            return Err(incomplete(CgroupIncomplete::FdLimit));
        }
        self.used.peak_open_fds = self.used.peak_open_fds.max(count);
        Ok(())
    }
    fn read_len(&self, key: (u64, u64)) -> Result<usize, CollectionOutcome> {
        let file_left = self
            .limits
            .file_bytes
            .saturating_sub(self.file_reads.get(&key).copied().unwrap_or(0));
        if file_left == 0 {
            return Err(incomplete(CgroupIncomplete::FileBytesLimit));
        }
        let total_left = self
            .limits
            .total_bytes
            .saturating_sub(self.used.membership_bytes);
        if total_left == 0 {
            return Err(incomplete(CgroupIncomplete::TotalBytesLimit));
        }
        Ok(CHUNK.min(file_left).min(total_left))
    }
    fn read_bytes(&mut self, key: (u64, u64), bytes: usize) {
        self.used.membership_bytes += bytes;
        *self.file_reads.entry(key).or_default() += bytes;
    }
}
fn charge(
    used: &mut usize,
    amount: usize,
    limit: usize,
    reason: CgroupIncomplete,
) -> Result<(), CollectionOutcome> {
    if amount > limit.saturating_sub(*used) {
        return Err(incomplete(reason));
    }
    *used += amount;
    Ok(())
}
/// Finite reasons never carry descendant names, paths, or malformed PID text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CgroupIncomplete {
    DirectoryLimit,
    DepthLimit,
    MemberLimit,
    FileBytesLimit,
    TotalBytesLimit,
    PathBytesLimit,
    WorkLimit,
    FdLimit,
    MalformedMembership,
    UnreadableMembership,
    UnreadableDirectory,
    ReplacedDirectory,
    UnsupportedMembership,
    ChangedMembership,
    Continuation,
    DiscoverySlice,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionOutcome {
    Complete,
    Incomplete(CgroupIncomplete),
    Cancelled(CollectionStop),
}
fn incomplete(reason: CgroupIncomplete) -> CollectionOutcome {
    CollectionOutcome::Incomplete(reason)
}
fn checkpoint(control: &CollectionControl) -> Result<(), CollectionOutcome> {
    control.check().map_err(CollectionOutcome::Cancelled)
}
/// Bounded root-relative scheduling hint; not current membership evidence.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct MemberLocator {
    relative: PathBuf,
    device: u64,
    inode: u64,
}
impl MemberLocator {
    fn key(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
    fn bytes(&self) -> usize {
        self.relative.as_os_str().as_bytes().len()
    }
}
pub(crate) struct CandidateBatch {
    pub(crate) candidates: BTreeMap<u32, MemberLocator>,
    /// A complete traversal still supplies only candidates, never scope absence.
    pub(crate) outcome: CollectionOutcome,
    pub(crate) work: CgroupWork,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MembershipOutcome {
    Present,
    AbsentAtLeaf,
    Unknown(CgroupIncomplete),
    Cancelled(CollectionStop),
}
pub(crate) struct MembershipSamples {
    observations: BTreeMap<u32, MembershipOutcome>,
    request_groups: BTreeMap<u32, usize>,
    groups: Vec<SampleGroup>,
    /// Completion of these requests only, not a census or residency receipt.
    pub(crate) outcome: CollectionOutcome,
    pub(crate) work: CgroupWork,
}
impl MembershipSamples {
    /// Resolve one requested PID without materializing a bulk fallback after
    /// exhaustion. Missing/unstarted requests remain unknown; group replacement
    /// invalidates that group's observations without rewriting every entry.
    pub(crate) fn answer(&self, pid: u32) -> MembershipOutcome {
        if let Some(index) = self.request_groups.get(&pid) {
            let group = &self.groups[*index];
            if !group.invalidated
                && let Some(answer) = self.observations.get(&pid)
            {
                return *answer;
            }
            if let Some(fallback) = group.fallback {
                return fallback;
            }
        }
        match self.outcome {
            CollectionOutcome::Incomplete(reason) => MembershipOutcome::Unknown(reason),
            CollectionOutcome::Cancelled(reason) => MembershipOutcome::Cancelled(reason),
            CollectionOutcome::Complete => {
                MembershipOutcome::Unknown(CgroupIncomplete::Continuation)
            }
        }
    }
}
#[derive(Default)]
struct SampleGroup {
    fallback: Option<MembershipOutcome>,
    invalidated: bool,
}
#[derive(Clone, Copy)]
enum Record {
    Pid(u32),
    Malformed,
    Eof,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct ContentStamp {
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl ContentStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}
struct MemberStream {
    file: File,
    stamp: ContentStamp,
    buffer: [u8; CHUNK],
    available: usize,
    cursor: usize,
    number: u32,
    digits: usize,
    bad: bool,
    eof: bool,
    pending: Option<Record>,
}
struct ReadContext<'a> {
    root: &'a File,
    locator: &'a MemberLocator,
    budget: &'a mut CgroupWalkBudget,
    control: &'a CollectionControl,
    live_fds: usize,
}
impl MemberStream {
    fn new(file: File, stamp: ContentStamp) -> Self {
        Self {
            file,
            stamp,
            buffer: [0; CHUNK],
            available: 0,
            cursor: 0,
            number: 0,
            digits: 0,
            bad: false,
            eof: false,
            pending: None,
        }
    }
    fn finish_line(&mut self) -> Record {
        let result = if self.digits != 0 && !self.bad && self.number != 0 {
            Record::Pid(self.number)
        } else {
            Record::Malformed
        };
        self.number = 0;
        self.digits = 0;
        self.bad = false;
        result
    }
    fn peek(&mut self, context: &mut ReadContext<'_>) -> Result<Record, CollectionOutcome> {
        checkpoint(context.control)?;
        if let Some(record) = self.pending {
            return Ok(record);
        }
        loop {
            if self.cursor == self.available {
                if self.eof {
                    let record = if self.digits != 0 || self.bad {
                        self.finish_line()
                    } else {
                        Record::Eof
                    };
                    self.pending = Some(record);
                    return Ok(record);
                }
                context.budget.charge_work(context.control, 1)?;
                let metadata = self
                    .file
                    .metadata()
                    .map_err(|_| incomplete(CgroupIncomplete::UnreadableMembership))?;
                checkpoint(context.control)?;
                // Not a freshness proof. Detectable rewrites invalidate the
                // stream before new bytes can be stitched onto old parser state.
                if ContentStamp::from_metadata(&metadata) != self.stamp {
                    return Err(incomplete(CgroupIncomplete::ChangedMembership));
                }
                let len = context.budget.read_len(context.locator.key())?;
                // Sequential read retains the kernel's seq_file iterator. No
                // lseek/pread or reopened nonzero offset can replay its prefix.
                // SAFETY: file and fixed writable buffer are valid, len bounded.
                let amount = unsafe {
                    libc::read(self.file.as_raw_fd(), self.buffer.as_mut_ptr().cast(), len)
                };
                if amount < 0 {
                    checkpoint(context.control)?;
                    return Err(incomplete(CgroupIncomplete::UnreadableMembership));
                }
                self.available = amount as usize;
                self.cursor = 0;
                self.eof = amount == 0;
                context
                    .budget
                    .read_bytes(context.locator.key(), self.available);
                checkpoint(context.control)?;
                validate(
                    context.root,
                    context.locator,
                    context.budget,
                    context.control,
                    context.live_fds,
                )?;
                continue;
            }
            context.budget.charge_work(context.control, 1)?;
            let byte = self.buffer[self.cursor];
            self.cursor += 1;
            if byte == b'\n' {
                let record = self.finish_line();
                self.pending = Some(record);
                return Ok(record);
            }
            if byte.is_ascii_digit() {
                self.digits = self.digits.saturating_add(1);
                if let Some(next) = self
                    .number
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                {
                    self.number = next;
                } else {
                    self.bad = true;
                }
                if self.digits > 10 {
                    self.bad = true;
                }
            } else {
                self.bad = true;
            }
        }
    }
    fn accept(&mut self) {
        self.pending = None;
    }
}
struct WalkFrame {
    directory: File,
    locator: MemberLocator,
    stream: Option<MemberStream>,
    members_done: bool,
    entries: [u8; CHUNK],
    available: usize,
    cursor: usize,
}
impl WalkFrame {
    fn new(directory: File, locator: MemberLocator) -> Self {
        Self {
            directory,
            locator,
            stream: None,
            members_done: false,
            entries: [0; CHUNK],
            available: 0,
            cursor: 0,
        }
    }
}
/// Per-run DFS scheduling state: depth-bounded directory descriptors and exactly
/// one active membership stream with fixed unread/parser storage. Cached records
/// remain candidates; a resumed batch can never establish complete absence.
#[derive(Default)]
pub(crate) struct CgroupWalkState {
    root: Option<(u64, u64)>,
    frames: Vec<WalkFrame>,
    path_bytes: usize,
}
impl CgroupWalkState {
    fn pop(&mut self) {
        if let Some(frame) = self.frames.pop() {
            self.path_bytes -= frame.locator.bytes();
        }
    }
    fn fd_count(&self) -> usize {
        self.frames.len()
            + self
                .frames
                .iter()
                .filter(|frame| frame.stream.is_some())
                .count()
    }
}

/// Opens only paths relative to the retained root. NO_XDEV also refuses a bind
/// mount that would make an outside cgroup appear beneath this path. If the
/// kernel/security policy refuses constrained lookup, discovery fails closed.
fn open_relative(
    root: &File,
    relative: &Path,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    live_fds: usize,
) -> Result<File, CollectionOutcome> {
    budget.charge_work(control, 1)?;
    budget.fds(live_fds + 1)?;
    let bytes = if relative.as_os_str().is_empty() {
        b".".as_slice()
    } else {
        relative.as_os_str().as_bytes()
    };
    let path =
        CString::new(bytes).map_err(|_| incomplete(CgroupIncomplete::UnreadableDirectory))?;
    // SAFETY: zero initializes every current/future field of this plain kernel
    // input structure; libc marks it non-exhaustive.
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = DIRECTORY_FLAGS;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // SAFETY: root is retained, path is NUL-terminated, and how is a complete
    // kernel input structure with the specified length.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        checkpoint(control)?;
        return Err(incomplete(CgroupIncomplete::UnreadableDirectory));
    }
    // SAFETY: a successful openat2 returned a new, owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd as _) };
    checkpoint(control)?;
    Ok(directory)
}
fn locator(
    directory: &File,
    relative: PathBuf,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
) -> Result<MemberLocator, CollectionOutcome> {
    budget.charge_work(control, 1)?;
    let metadata = directory
        .metadata()
        .map_err(|_| incomplete(CgroupIncomplete::UnreadableDirectory))?;
    checkpoint(control)?;
    if !metadata.is_dir() {
        return Err(incomplete(CgroupIncomplete::UnreadableDirectory));
    }
    Ok(MemberLocator {
        relative,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
fn validate(
    root: &File,
    member: &MemberLocator,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    live_fds: usize,
) -> Result<(), CollectionOutcome> {
    let directory =
        open_relative(root, &member.relative, budget, control, live_fds).map_err(|outcome| {
            if outcome == incomplete(CgroupIncomplete::UnreadableDirectory) {
                incomplete(CgroupIncomplete::ReplacedDirectory)
            } else {
                outcome
            }
        })?;
    budget.charge_work(control, 1)?;
    let metadata = directory
        .metadata()
        .map_err(|_| incomplete(CgroupIncomplete::ReplacedDirectory))?;
    checkpoint(control)?;
    if (metadata.dev(), metadata.ino()) != member.key() {
        return Err(incomplete(CgroupIncomplete::ReplacedDirectory));
    }
    Ok(())
}
fn open_members(
    directory: &File,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    live_fds: usize,
) -> Result<(File, ContentStamp), CollectionOutcome> {
    budget.charge_work(control, 1)?;
    budget.fds(live_fds + 1)?;
    let path = c"cgroup.procs";
    // SAFETY: open_how is a plain kernel input; initialize future fields too.
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // SAFETY: the retained directory and terminated constant path are valid.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        checkpoint(control)?;
        return Err(incomplete(CgroupIncomplete::UnreadableMembership));
    }
    // SAFETY: successful openat2 returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd as _) };
    budget.charge_work(control, 1)?;
    let metadata = file
        .metadata()
        .map_err(|_| incomplete(CgroupIncomplete::UnreadableMembership))?;
    checkpoint(control)?;
    if !metadata.is_file() {
        return Err(incomplete(CgroupIncomplete::UnsupportedMembership));
    }
    let stamp = ContentStamp::from_metadata(&metadata);
    Ok((file, stamp))
}

/// Selects scheduling hints within a slice of the SAME collection allowance.
/// Its result, including a fresh complete traversal, never authorizes admission.
pub(crate) fn next_candidates(
    root: &Arc<File>,
    state: &mut CgroupWalkState,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    quota: CandidateQuota,
) -> CandidateBatch {
    let mut candidates = BTreeMap::new();
    let previous = budget.slice_end;
    let end = budget.used.units.saturating_add(quota.work_units);
    budget.slice_end = Some(previous.map_or(end, |old| old.min(end)));
    let outcome = walk_inner(
        root,
        state,
        budget,
        control,
        quota.candidates,
        &mut candidates,
    )
    .unwrap_or_else(|outcome| outcome);
    budget.slice_end = previous;
    budget.retained_fds = state.fd_count();
    CandidateBatch {
        candidates,
        outcome,
        work: budget.used,
    }
}
fn walk_inner(
    root: &File,
    state: &mut CgroupWalkState,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    quota: usize,
    candidates: &mut BTreeMap<u32, MemberLocator>,
) -> Result<CollectionOutcome, CollectionOutcome> {
    checkpoint(control)?;
    let mut reason = None;
    budget.charge_work(control, 1)?;
    let metadata = root
        .metadata()
        .map_err(|_| incomplete(CgroupIncomplete::UnreadableDirectory))?;
    let key = (metadata.dev(), metadata.ino());
    if state.root.is_some_and(|original| original != key) {
        state.frames.clear();
        state.path_bytes = 0;
        reason = Some(CgroupIncomplete::ReplacedDirectory);
    }
    state.root = Some(key);
    let resumed = !state.frames.is_empty();
    budget.path(state.path_bytes)?;
    budget.fds(state.fd_count() + 1)?;
    if state.frames.is_empty() {
        budget.directory()?;
        let directory = open_relative(root, Path::new(""), budget, control, 1)?;
        let member = locator(&directory, PathBuf::new(), budget, control)?;
        state.frames.push(WalkFrame::new(directory, member));
    } else if !state.frames.last().expect("nonempty").members_done {
        budget.directory()?;
    }
    while !state.frames.is_empty() {
        checkpoint(control)?;
        if candidates.len() >= quota {
            return Err(incomplete(CgroupIncomplete::DiscoverySlice));
        }
        let live_fds = state.fd_count() + 1;
        let frame = state.frames.last_mut().expect("nonempty");
        if let Err(outcome) = validate(root, &frame.locator, budget, control, live_fds) {
            if outcome == incomplete(CgroupIncomplete::ReplacedDirectory) {
                reason.get_or_insert(CgroupIncomplete::ReplacedDirectory);
                state.pop();
                continue;
            }
            return Err(outcome);
        }
        if !frame.members_done {
            let stream_live = if frame.stream.is_none() {
                let (file, stamp) = match open_members(&frame.directory, budget, control, live_fds)
                {
                    Ok(opened) => opened,
                    Err(CollectionOutcome::Incomplete(
                        issue @ (CgroupIncomplete::UnreadableMembership
                        | CgroupIncomplete::UnsupportedMembership),
                    )) => {
                        reason.get_or_insert(issue);
                        frame.members_done = true;
                        continue;
                    }
                    Err(outcome) => return Err(outcome),
                };
                frame.stream = Some(MemberStream::new(file, stamp));
                live_fds + 1
            } else {
                live_fds
            };
            let stream = frame.stream.as_mut().expect("opened stream");
            let mut context = ReadContext {
                root,
                locator: &frame.locator,
                budget,
                control,
                live_fds: stream_live,
            };
            match stream.peek(&mut context) {
                Ok(Record::Pid(pid)) => {
                    if let std::collections::btree_map::Entry::Vacant(entry) = candidates.entry(pid)
                    {
                        if frame.locator.bytes()
                            > context
                                .budget
                                .limits
                                .path_bytes
                                .saturating_sub(state.path_bytes)
                        {
                            reason.get_or_insert(CgroupIncomplete::PathBytesLimit);
                            stream.accept();
                            continue;
                        }
                        context.budget.candidate(pid, control)?;
                        context.budget.path(frame.locator.bytes())?;
                        context.budget.charge_work(control, 1)?;
                        entry.insert(frame.locator.clone());
                    }
                    stream.accept();
                    continue;
                }
                Ok(Record::Malformed) => {
                    reason.get_or_insert(CgroupIncomplete::MalformedMembership);
                    stream.accept();
                    continue;
                }
                Ok(Record::Eof) => {
                    frame.stream = None;
                    frame.members_done = true;
                    continue;
                }
                Err(CollectionOutcome::Incomplete(
                    issue @ (CgroupIncomplete::UnreadableMembership
                    | CgroupIncomplete::UnsupportedMembership
                    | CgroupIncomplete::ChangedMembership),
                )) => {
                    reason.get_or_insert(issue);
                    frame.stream = None;
                    frame.members_done = true;
                    continue;
                }
                Err(CollectionOutcome::Incomplete(CgroupIncomplete::ReplacedDirectory)) => {
                    reason.get_or_insert(CgroupIncomplete::ReplacedDirectory);
                    state.pop();
                    continue;
                }
                Err(outcome) => return Err(outcome),
            }
        }
        budget.charge_work(control, 1)?;
        if frame.cursor == frame.available {
            // SAFETY: retained directory and bounded writable buffer are valid.
            let amount = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    frame.directory.as_raw_fd(),
                    frame.entries.as_mut_ptr(),
                    CHUNK,
                )
            };
            if amount > 0 {
                frame.available = amount as usize;
                frame.cursor = 0;
            }
            checkpoint(control)?;
            if amount < 0 {
                reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
                state.pop();
                continue;
            }
            match validate(root, &frame.locator, budget, control, live_fds) {
                Ok(()) => {}
                Err(CollectionOutcome::Incomplete(CgroupIncomplete::ReplacedDirectory)) => {
                    reason.get_or_insert(CgroupIncomplete::ReplacedDirectory);
                    state.pop();
                    continue;
                }
                Err(outcome) => return Err(outcome),
            }
            if amount == 0 {
                state.pop();
                continue;
            }
        }
        let record = &frame.entries[frame.cursor..frame.available];
        if record.len() < 20 {
            reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
            state.pop();
            continue;
        }
        let length = usize::from(u16::from_ne_bytes([record[16], record[17]]));
        if length < 20 || length > record.len() {
            reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
            state.pop();
            continue;
        }
        let inode = u64::from_ne_bytes(record[..8].try_into().expect("fixed inode"));
        let kind = record[18];
        let Some(end) = record[19..length].iter().position(|byte| *byte == 0) else {
            reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
            state.pop();
            continue;
        };
        let name = &record[19..19 + end];
        if name == b"." || name == b".." || name == b"cgroup.procs" || name.is_empty() {
            frame.cursor += length;
            continue;
        }
        let is_directory = if kind == libc::DT_UNKNOWN {
            budget.charge_work(control, 1)?;
            let name = CString::new(name)
                .map_err(|_| incomplete(CgroupIncomplete::UnreadableDirectory))?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstatat fills stat on success; the final symlink is not followed.
            if unsafe {
                libc::fstatat(
                    frame.directory.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                checkpoint(control)?;
                reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
                frame.cursor += length;
                continue;
            }
            // SAFETY: the successful fstatat initialized the structure.
            let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
            if mode == libc::S_IFLNK {
                reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
            }
            mode == libc::S_IFDIR
        } else {
            if kind == libc::DT_LNK {
                reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
            }
            kind == libc::DT_DIR
        };
        if !is_directory {
            frame.cursor += length;
            continue;
        }
        // Permanent barriers are skipped, not retried at the same entry forever.
        let parent_len = frame.locator.bytes();
        let path_len = parent_len + usize::from(parent_len != 0) + name.len();
        let barrier = if live_fds - 1 > budget.limits.depth {
            Some(CgroupIncomplete::DepthLimit)
        } else if path_len > budget.limits.path_bytes.saturating_sub(state.path_bytes) {
            Some(CgroupIncomplete::PathBytesLimit)
        } else if live_fds + 3 > budget.limits.open_fds {
            Some(CgroupIncomplete::FdLimit)
        } else {
            None
        };
        if let Some(issue) = barrier {
            reason.get_or_insert(issue);
            frame.cursor += length;
            continue;
        }
        budget.directory()?;
        budget.path(path_len)?;
        let path = frame
            .locator
            .relative
            .join(std::ffi::OsStr::from_bytes(name));
        match open_relative(root, &path, budget, control, live_fds) {
            Ok(directory) => {
                let member = locator(&directory, path, budget, control)?;
                frame.cursor += length;
                if member.inode != inode || member.device != key.0 {
                    reason.get_or_insert(CgroupIncomplete::ReplacedDirectory);
                    continue;
                }
                state.path_bytes += member.bytes();
                state.frames.push(WalkFrame::new(directory, member));
            }
            Err(CollectionOutcome::Incomplete(CgroupIncomplete::UnreadableDirectory)) => {
                reason.get_or_insert(CgroupIncomplete::UnreadableDirectory);
                frame.cursor += length;
            }
            Err(outcome) => return Err(outcome),
        }
    }
    checkpoint(control)?;
    Ok(reason.map_or(
        if resumed {
            incomplete(CgroupIncomplete::Continuation)
        } else {
            CollectionOutcome::Complete
        },
        incomplete,
    ))
}

/// Fresh grouped samples from newly opened zero-origin sequential streams. Every
/// leaf is read once per call, including nonmatching records. Requested positives
/// survive later read exhaustion; only valid EOF can answer AbsentAtLeaf.
pub(crate) fn sample_members(
    root: &Arc<File>,
    requests: &BTreeMap<u32, MemberLocator>,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
) -> MembershipSamples {
    let mut samples = MembershipSamples {
        observations: BTreeMap::new(),
        request_groups: BTreeMap::new(),
        groups: Vec::new(),
        outcome: incomplete(CgroupIncomplete::Continuation),
        work: budget.used,
    };
    samples.outcome = sample_inner(root, requests, budget, control, &mut samples)
        .unwrap_or_else(|outcome| outcome);
    samples.work = budget.used;
    samples
}
fn sample_inner(
    root: &File,
    requests: &BTreeMap<u32, MemberLocator>,
    budget: &mut CgroupWalkBudget,
    control: &CollectionControl,
    samples: &mut MembershipSamples,
) -> Result<CollectionOutcome, CollectionOutcome> {
    checkpoint(control)?;
    let mut groups: BTreeMap<&MemberLocator, (usize, BTreeSet<u32>)> = BTreeMap::new();
    for (pid, member) in requests {
        budget.candidate(*pid, control)?;
        // Charge before growing the request index, group/set and fallback
        // storage. Locators are borrowed; the result retains no path copies.
        budget.charge_work(control, 2)?;
        let (index, requested) = groups.entry(member).or_insert_with(|| {
            let index = samples.groups.len();
            samples.groups.push(SampleGroup::default());
            (index, BTreeSet::new())
        });
        samples.request_groups.insert(*pid, *index);
        requested.insert(*pid);
    }
    let mut first_issue = None;
    for (member, (index, requested)) in groups {
        budget.charge_work(control, 1)?;
        let retained = budget.retained_fds;
        let result = (|| {
            budget.directory()?;
            let directory = open_relative(root, &member.relative, budget, control, retained + 1)
                .map_err(|outcome| {
                    if outcome == incomplete(CgroupIncomplete::UnreadableDirectory) {
                        incomplete(CgroupIncomplete::ReplacedDirectory)
                    } else {
                        outcome
                    }
                })?;
            budget.charge_work(control, 1)?;
            let metadata = directory
                .metadata()
                .map_err(|_| incomplete(CgroupIncomplete::ReplacedDirectory))?;
            if (metadata.dev(), metadata.ino()) != member.key() {
                return Err(incomplete(CgroupIncomplete::ReplacedDirectory));
            }
            let (file, stamp) = open_members(&directory, budget, control, retained + 2)?;
            let mut stream = MemberStream::new(file, stamp);
            let mut context = ReadContext {
                root,
                locator: member,
                budget,
                control,
                live_fds: retained + 3,
            };
            let mut remaining = requested.len();
            let mut malformed = false;
            loop {
                match stream.peek(&mut context)? {
                    Record::Pid(pid) => {
                        if requested.contains(&pid)
                            && samples.observations.get(&pid) != Some(&MembershipOutcome::Present)
                        {
                            context.budget.charge_work(control, 1)?;
                            samples.observations.insert(pid, MembershipOutcome::Present);
                            remaining -= 1;
                        }
                        stream.accept();
                        if remaining == 0 {
                            validate(root, member, context.budget, control, context.live_fds)?;
                            checkpoint(control)?;
                            return Ok(());
                        }
                    }
                    Record::Malformed => {
                        malformed = true;
                        stream.accept();
                    }
                    Record::Eof => {
                        validate(root, member, context.budget, control, context.live_fds)?;
                        checkpoint(control)?;
                        if malformed {
                            return Err(incomplete(CgroupIncomplete::MalformedMembership));
                        }
                        for pid in &requested {
                            context.budget.charge_work(control, 1)?;
                            if samples.observations.get(pid) != Some(&MembershipOutcome::Present) {
                                samples
                                    .observations
                                    .insert(*pid, MembershipOutcome::AbsentAtLeaf);
                            }
                        }
                        return Ok(());
                    }
                }
            }
        })();
        if let Err(outcome) = result {
            let group = &mut samples.groups[index];
            group.invalidated = outcome == incomplete(CgroupIncomplete::ReplacedDirectory);
            group.fallback = Some(match outcome {
                CollectionOutcome::Incomplete(reason) => MembershipOutcome::Unknown(reason),
                CollectionOutcome::Cancelled(reason) => MembershipOutcome::Cancelled(reason),
                CollectionOutcome::Complete => unreachable!("errors only"),
            });
            match outcome {
                CollectionOutcome::Cancelled(_) => return Err(outcome),
                CollectionOutcome::Incomplete(
                    CgroupIncomplete::WorkLimit
                    | CgroupIncomplete::TotalBytesLimit
                    | CgroupIncomplete::DirectoryLimit
                    | CgroupIncomplete::FdLimit,
                ) => return Err(outcome),
                CollectionOutcome::Incomplete(issue) => {
                    first_issue.get_or_insert(issue);
                }
                CollectionOutcome::Complete => unreachable!("errors only"),
            }
        }
    }
    checkpoint(control)?;
    Ok(first_issue.map_or(CollectionOutcome::Complete, incomplete))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn tree() -> (tempfile::TempDir, Arc<File>) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cgroup.procs"), "").unwrap();
        let root = Arc::new(File::open(dir.path()).unwrap());
        (dir, root)
    }
    fn child(dir: &std::path::Path, name: &str, pids: &str) {
        fs::create_dir_all(dir.join(name)).unwrap();
        fs::write(dir.join(name).join("cgroup.procs"), pids).unwrap();
    }
    fn run(
        root: &Arc<File>,
        state: &mut CgroupWalkState,
        limits: CgroupWalkLimits,
    ) -> CandidateBatch {
        next_candidates_unlimited(
            root,
            state,
            &mut CgroupWalkBudget::new(limits),
            &CollectionControl::new(None),
        )
    }
    fn next_candidates_unlimited(
        root: &Arc<File>,
        state: &mut CgroupWalkState,
        budget: &mut CgroupWalkBudget,
        control: &CollectionControl,
    ) -> CandidateBatch {
        next_candidates(
            root,
            state,
            budget,
            control,
            CandidateQuota {
                candidates: usize::MAX,
                work_units: usize::MAX,
            },
        )
    }
    fn sample_one(
        root: &Arc<File>,
        locator: &MemberLocator,
        pid: u32,
        budget: &mut CgroupWalkBudget,
        control: &CollectionControl,
    ) -> MembershipOutcome {
        let samples = sample_members(
            root,
            &BTreeMap::from([(pid, locator.clone())]),
            budget,
            control,
        );
        samples.answer(pid)
    }
    fn pids(result: &CandidateBatch) -> Vec<u32> {
        result.candidates.keys().copied().collect()
    }

    #[test]
    fn nested_members_are_sorted_and_deduplicated_without_siblings() {
        let (dir, _) = tree();
        child(dir.path(), "selected", "13\n11\n11\n");
        child(dir.path(), "selected/leaf", "12\n13\n");
        child(dir.path(), "sibling", "99\n");
        let root = Arc::new(File::open(dir.path().join("selected")).unwrap());
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert_eq!(pids(&result), [11, 12, 13]);
        assert_eq!(result.outcome, CollectionOutcome::Complete);
    }
    #[test]
    fn retained_root_survives_operator_path_replacement() {
        let (dir, _) = tree();
        child(dir.path(), "selected", "11\n");
        let root = Arc::new(File::open(dir.path().join("selected")).unwrap());
        fs::rename(dir.path().join("selected"), dir.path().join("old")).unwrap();
        child(dir.path(), "selected", "99\n");
        assert_eq!(
            pids(&run(
                &root,
                &mut CgroupWalkState::default(),
                CgroupWalkLimits::default()
            )),
            [11]
        );
    }
    #[test]
    fn directory_and_membership_symlinks_never_escape() {
        let (dir, root) = tree();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("cgroup.procs"), "99\n").unwrap();
        symlink(outside.path(), dir.path().join("escape")).unwrap();
        child(dir.path(), "bad", "");
        fs::remove_file(dir.path().join("bad/cgroup.procs")).unwrap();
        symlink(
            outside.path().join("cgroup.procs"),
            dir.path().join("bad/cgroup.procs"),
        )
        .unwrap();
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert!(result.candidates.is_empty());
        assert!(matches!(result.outcome, CollectionOutcome::Incomplete(_)));
    }
    #[test]
    fn malformed_member_lines_withhold_completeness_and_keep_valid_pids() {
        let (dir, root) = tree();
        fs::write(
            dir.path().join("cgroup.procs"),
            "23\n0\n-1\nx\n4294967296\n23\n24",
        )
        .unwrap();
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert_eq!(pids(&result), [23, 24]);
        assert_eq!(
            result.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::MalformedMembership)
        );
    }
    #[test]
    fn stable_member_list_above_cap_eventually_reaches_later_pids() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n13\n14\n15\n").unwrap();
        let mut state = CgroupWalkState::default();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..4 {
            let result = run(
                &root,
                &mut state,
                CgroupWalkLimits {
                    members: 2,
                    ..CgroupWalkLimits::default()
                },
            );
            assert!(matches!(result.outcome, CollectionOutcome::Incomplete(_)));
            assert!(result.candidates.len() <= 2);
            seen.extend(pids(&result));
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), [11, 12, 13, 14, 15]);
    }
    #[test]
    fn changing_prefix_cannot_turn_continuation_into_a_partial_pid() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n").unwrap();
        let mut state = CgroupWalkState::default();
        let first = run(
            &root,
            &mut state,
            CgroupWalkLimits {
                members: 1,
                ..CgroupWalkLimits::default()
            },
        );
        assert_eq!(pids(&first), [11]);
        fs::write(dir.path().join("cgroup.procs"), "1234\n12\n").unwrap();
        let next = run(&root, &mut state, CgroupWalkLimits::default());
        assert!(
            !next.candidates.contains_key(&4),
            "offset 3 must not fabricate PID 4 from PID 1234"
        );
        assert!(matches!(next.outcome, CollectionOutcome::Incomplete(_)));
    }
    #[test]
    fn continuation_keeps_a_sequential_membership_description_instead_of_replaying_a_reopened_prefix()
     {
        let (dir, root) = tree();
        fs::write(
            dir.path().join("cgroup.procs"),
            (11..5000).map(|pid| format!("{pid}\n")).collect::<String>(),
        )
        .unwrap();
        let position = || {
            let entry = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .find(|entry| {
                    fs::read_link(entry.path()).ok().as_deref()
                        == Some(dir.path().join("cgroup.procs").as_path())
                })?;
            let info =
                fs::read_to_string(Path::new("/proc/self/fdinfo").join(entry.file_name())).ok()?;
            let pos = info
                .lines()
                .find_map(|line| line.strip_prefix("pos:\t"))?
                .parse::<u64>()
                .ok()?;
            Some((entry.file_name(), pos))
        };
        let mut state = CgroupWalkState::default();
        let limits = CgroupWalkLimits {
            members: 1,
            ..CgroupWalkLimits::default()
        };
        let first = run(&root, &mut state, limits.clone());
        assert_eq!(pids(&first), [11]);
        let retained =
            position().expect("a paused sequence must retain its open membership description");
        assert!(
            retained.1 > 0,
            "sequential reads must advance the retained description"
        );
        let next = run(&root, &mut state, limits);
        assert_eq!(pids(&next), [12]);
        let resumed = position().expect("the sequence remains paused");
        assert_eq!(resumed.0, retained.0);
        assert!(resumed.1 >= retained.1);
    }
    #[test]
    fn permanent_overdepth_branch_does_not_block_later_shallow_sibling() {
        let (dir, root) = tree();
        child(dir.path(), "a", "");
        child(dir.path(), "b", "");
        let branches = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().unwrap().is_dir())
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        child(&branches[0], "blocked", "11\n");
        fs::write(branches[1].join("cgroup.procs"), "99\n").unwrap();
        let mut state = CgroupWalkState::default();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..5 {
            let result = run(
                &root,
                &mut state,
                CgroupWalkLimits {
                    depth: 1,
                    directories: 2,
                    ..CgroupWalkLimits::default()
                },
            );
            assert!(matches!(result.outcome, CollectionOutcome::Incomplete(_)));
            assert!(!result.candidates.contains_key(&11));
            seen.extend(pids(&result));
        }
        assert!(
            seen.contains(&99),
            "the rejected deep child must not pin traversal before a valid sibling"
        );
    }
    #[test]
    fn stable_tree_above_directory_cap_eventually_reaches_later_branches() {
        let (dir, root) = tree();
        child(dir.path(), "a", "11\n");
        child(dir.path(), "b", "12\n");
        child(dir.path(), "c", "13\n");
        let mut state = CgroupWalkState::default();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let result = run(
                &root,
                &mut state,
                CgroupWalkLimits {
                    directories: 1,
                    ..CgroupWalkLimits::default()
                },
            );
            assert!(matches!(result.outcome, CollectionOutcome::Incomplete(_)));
            seen.extend(pids(&result));
            assert!(result.work.directories <= 1);
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), [11, 12, 13]);
    }
    #[test]
    fn replaced_resumed_directory_does_not_supply_stale_members() {
        let (dir, root) = tree();
        child(dir.path(), "leaf", "11\n12\n13\n");
        let mut state = CgroupWalkState::default();
        let first = run(
            &root,
            &mut state,
            CgroupWalkLimits {
                members: 1,
                ..CgroupWalkLimits::default()
            },
        );
        assert_eq!(pids(&first), [11]);
        let outside = tempfile::tempdir().unwrap();
        fs::rename(dir.path().join("leaf"), outside.path().join("old")).unwrap();
        child(dir.path(), "leaf", "99\n");
        let next = run(&root, &mut state, CgroupWalkLimits::default());
        assert!(!next.candidates.contains_key(&12));
        assert!(!next.candidates.contains_key(&13));
        assert!(matches!(next.outcome, CollectionOutcome::Incomplete(_)));
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits::default());
        assert_eq!(
            sample_one(
                &root,
                &first.candidates[&11],
                11,
                &mut budget,
                &CollectionControl::new(None)
            ),
            MembershipOutcome::Unknown(CgroupIncomplete::ReplacedDirectory)
        );
    }
    #[test]
    fn already_cancelled_control_performs_no_work_and_cancel_is_shared() {
        let (_, root) = tree();
        let control = CollectionControl::new(None);
        control.clone().cancel();
        let result = next_candidates_unlimited(
            &root,
            &mut CgroupWalkState::default(),
            &mut CgroupWalkBudget::new(CgroupWalkLimits::default()),
            &control,
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Cancelled(CollectionStop::OperatorStop)
        );
        assert_eq!(result.work, CgroupWork::default());
    }
    #[test]
    fn injected_deadline_interrupts_during_traversal_and_stays_latched() {
        let (dir, root) = tree();
        child(dir.path(), "leaf", "11\n");
        let start = Instant::now();
        let calls = Arc::new(AtomicUsize::new(0));
        let clock_calls = Arc::clone(&calls);
        let control =
            CollectionControl::with_clock(Some(start + Duration::from_secs(1)), move || {
                if clock_calls.fetch_add(1, Ordering::Relaxed) < 8 {
                    start
                } else {
                    start + Duration::from_secs(2)
                }
            });
        let result = next_candidates_unlimited(
            &root,
            &mut CgroupWalkState::default(),
            &mut CgroupWalkBudget::new(CgroupWalkLimits::default()),
            &control,
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
        assert_eq!(control.check(), Err(CollectionStop::Deadline));
        assert!(calls.load(Ordering::Relaxed) < 20);
    }
    #[test]
    fn deadline_after_last_directory_close_cannot_mint_complete_receipt() {
        let (dir, root) = tree();
        let path = dir.path().to_path_buf();
        let started = std::sync::atomic::AtomicBool::new(false);
        let start = Instant::now();
        let control =
            CollectionControl::with_clock(Some(start + Duration::from_secs(1)), move || {
                let owned = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                    .filter(|fd_path| fd_path.starts_with(&path))
                    .count();
                if owned > 1 {
                    started.store(true, Ordering::Relaxed);
                }
                if owned == 1 && started.load(Ordering::Relaxed) {
                    start + Duration::from_secs(2)
                } else {
                    start
                }
            });
        let result = next_candidates_unlimited(
            &root,
            &mut CgroupWalkState::default(),
            &mut CgroupWalkBudget::new(CgroupWalkLimits::default()),
            &control,
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
    }
    #[test]
    fn deadline_during_member_parse_keeps_only_completed_observations() {
        let (dir, root) = tree();
        fs::write(
            dir.path().join("cgroup.procs"),
            (11..100).map(|pid| format!("{pid}\n")).collect::<String>(),
        )
        .unwrap();
        let calls = AtomicUsize::new(0);
        let start = Instant::now();
        let control =
            CollectionControl::with_clock(Some(start + Duration::from_secs(1)), move || {
                if calls.fetch_add(1, Ordering::Relaxed) < 40 {
                    start
                } else {
                    start + Duration::from_secs(2)
                }
            });
        let result = next_candidates_unlimited(
            &root,
            &mut CgroupWalkState::default(),
            &mut CgroupWalkBudget::new(CgroupWalkLimits::default()),
            &control,
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
        assert!(!result.candidates.is_empty());
        assert!(result.candidates.len() < 89);
    }
    #[test]
    fn begin_end_and_leaf_revalidation_consume_one_budget() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n").unwrap();
        let control = CollectionControl::new(None);
        let mut state = CgroupWalkState::default();
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            total_bytes: 6,
            ..CgroupWalkLimits::default()
        });
        let begin = next_candidates_unlimited(&root, &mut state, &mut budget, &control);
        assert_eq!(begin.outcome, CollectionOutcome::Complete);
        assert_eq!(
            sample_one(&root, &begin.candidates[&11], 11, &mut budget, &control),
            MembershipOutcome::Present
        );
        let end = next_candidates_unlimited(&root, &mut state, &mut budget, &control);
        assert_eq!(
            end.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::TotalBytesLimit)
        );
        assert!(budget.used.membership_bytes <= 6);
    }
    #[test]
    fn unsupported_or_missing_membership_is_not_complete_empty() {
        let (dir, root) = tree();
        fs::remove_file(dir.path().join("cgroup.procs")).unwrap();
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::UnreadableMembership)
        );
        fs::create_dir(dir.path().join("cgroup.procs")).unwrap();
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert_eq!(
            result.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::UnsupportedMembership)
        );
    }
    #[test]
    fn valid_empty_scope_and_no_deadline_produce_one_complete_snapshot() {
        let (_dir, root) = tree();
        let result = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        assert!(result.candidates.is_empty());
        assert_eq!(result.outcome, CollectionOutcome::Complete);
        assert_eq!(result.work.directories, 1);
    }
    #[test]
    fn leaf_revalidation_is_a_current_sample_after_migration() {
        let (dir, root) = tree();
        child(dir.path(), "leaf", "11\n");
        let first = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits::default());
        let control = CollectionControl::new(None);
        assert_eq!(
            sample_one(&root, &first.candidates[&11], 11, &mut budget, &control),
            MembershipOutcome::Present
        );
        fs::write(dir.path().join("leaf/cgroup.procs"), "12\n").unwrap();
        assert_eq!(
            sample_one(&root, &first.candidates[&11], 11, &mut budget, &control),
            MembershipOutcome::AbsentAtLeaf
        );
        control.cancel();
        assert_eq!(
            sample_one(&root, &first.candidates[&11], 11, &mut budget, &control),
            MembershipOutcome::Cancelled(CollectionStop::OperatorStop)
        );
    }
    #[test]
    fn many_absent_requests_charge_work_during_eof_materialization() {
        let (_dir, root) = tree();
        let member = MemberLocator {
            relative: PathBuf::new(),
            device: root.metadata().unwrap().dev(),
            inode: root.metadata().unwrap().ino(),
        };
        let requests = (1..=256).map(|pid| (pid, member.clone())).collect();
        // Grouping and the tiny empty-file sample fit. Finalizing all 256
        // absent answers must spend additional work from the same allowance.
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            work_units: 3 * 256 + 64,
            ..CgroupWalkLimits::default()
        });
        let samples = sample_members(&root, &requests, &mut budget, &CollectionControl::new(None));
        assert_eq!(
            samples.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::WorkLimit)
        );
        let absent = (1..=256)
            .filter(|pid| samples.answer(*pid) == MembershipOutcome::AbsentAtLeaf)
            .count();
        assert!(absent > 0 && absent < 256);
        assert!(budget.used.units <= 3 * 256 + 64);
    }
    #[test]
    fn many_absent_requests_poll_deadline_during_eof_materialization() {
        let (dir, root) = tree();
        let member = MemberLocator {
            relative: PathBuf::new(),
            device: root.metadata().unwrap().dev(),
            inode: root.metadata().unwrap().ino(),
        };
        let requests = (1..=256).map(|pid| (pid, member.clone())).collect();
        let fixture = dir.path().to_path_buf();
        let post_open_checks = AtomicUsize::new(0);
        let now = Instant::now();
        let control =
            CollectionControl::with_clock(Some(now + Duration::from_secs(1)), move || {
                let has_membership_stream = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                    .any(|path| path == fixture.join("cgroup.procs"));
                if has_membership_stream && post_open_checks.fetch_add(1, Ordering::Relaxed) >= 64 {
                    now + Duration::from_secs(2)
                } else {
                    now
                }
            });
        let samples = sample_members(
            &root,
            &requests,
            &mut CgroupWalkBudget::new(CgroupWalkLimits::default()),
            &control,
        );
        assert_eq!(
            samples.outcome,
            CollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
        let absent = (1..=256)
            .filter(|pid| samples.answer(*pid) == MembershipOutcome::AbsentAtLeaf)
            .count();
        assert!(absent > 0 && absent < 256);
    }
    #[test]
    fn deep_continuation_retains_only_depth_bounded_directory_fds() {
        let (dir, root) = tree();
        child(dir.path(), "a/b/c/d", "11\n12\n13\n");
        let owned_fds = || {
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                .filter(|path| path.starts_with(dir.path()))
                .count()
        };
        let baseline = owned_fds();
        let mut state = CgroupWalkState::default();
        for _ in 0..4 {
            let result = run(
                &root,
                &mut state,
                CgroupWalkLimits {
                    members: 1,
                    depth: 4,
                    open_fds: 8,
                    ..CgroupWalkLimits::default()
                },
            );
            assert!(matches!(result.outcome, CollectionOutcome::Incomplete(_)));
            assert!(result.work.peak_open_fds <= 8);
            assert!(owned_fds() <= baseline + 6);
        }
        drop(state);
        assert_eq!(owned_fds(), baseline);
    }
    #[test]
    fn leaf_fd_allowance_includes_retained_traversal_continuation() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n").unwrap();
        let control = CollectionControl::new(None);
        let mut state = CgroupWalkState::default();
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            members: 1,
            open_fds: 4,
            ..CgroupWalkLimits::default()
        });
        let first = next_candidates_unlimited(&root, &mut state, &mut budget, &control);
        assert_eq!(pids(&first), [11]);
        assert_eq!(
            first.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::MemberLimit)
        );
        assert_eq!(
            sample_one(&root, &first.candidates[&11], 11, &mut budget, &control),
            MembershipOutcome::Unknown(CgroupIncomplete::FdLimit)
        );
        assert!(budget.used.peak_open_fds <= 4);
    }
    #[test]
    fn depth64_sampling_counts_temporary_fds_at_the_actual_seventy_fd_boundary() {
        let (dir, root) = tree();
        let mut leaf = dir.path().to_path_buf();
        for _ in 0..64 {
            child(&leaf, "d", "");
            leaf = leaf.join("d");
        }
        fs::write(leaf.join("cgroup.procs"), "11\n12\n").unwrap();
        let control_for_peak = |peak: Arc<AtomicUsize>| {
            let fixture = dir.path().to_path_buf();
            let now = Instant::now();
            CollectionControl::with_clock(Some(now + Duration::from_secs(60)), move || {
                let owned = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                    .filter(|path| path.starts_with(&fixture))
                    .count();
                peak.fetch_max(owned, Ordering::Relaxed);
                now
            })
        };
        let mut state = CgroupWalkState::default();
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits::default());
        let peak = Arc::new(AtomicUsize::new(0));
        let control = control_for_peak(Arc::clone(&peak));
        let candidates = next_candidates(
            &root,
            &mut state,
            &mut budget,
            &control,
            CandidateQuota {
                candidates: 1,
                work_units: 10000,
            },
        );
        assert_eq!(pids(&candidates), [11]);
        let sampled = sample_members(&root, &candidates.candidates, &mut budget, &control);
        assert_eq!(sampled.answer(11), MembershipOutcome::Present);
        assert_eq!(peak.load(Ordering::Relaxed), 70);
        assert_eq!(budget.used.peak_open_fds, 70);

        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            open_fds: 69,
            ..CgroupWalkLimits::default()
        });
        let peak = Arc::new(AtomicUsize::new(0));
        let control = control_for_peak(Arc::clone(&peak));
        let candidates = next_candidates(
            &root,
            &mut state,
            &mut budget,
            &control,
            CandidateQuota {
                candidates: 1,
                work_units: 10000,
            },
        );
        assert_eq!(pids(&candidates), [12]);
        let sampled = sample_members(&root, &candidates.candidates, &mut budget, &control);
        assert_eq!(
            sampled.answer(12),
            MembershipOutcome::Unknown(CgroupIncomplete::FdLimit)
        );
        assert!(peak.load(Ordering::Relaxed) <= 69);
        assert!(budget.used.peak_open_fds <= 69);
    }
    #[test]
    fn continuation_candidates_need_a_fresh_sample_after_leaving() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n").unwrap();
        let mut state = CgroupWalkState::default();
        run(
            &root,
            &mut state,
            CgroupWalkLimits {
                members: 1,
                ..CgroupWalkLimits::default()
            },
        );
        fs::write(dir.path().join("cgroup.procs"), "11\n99\n").unwrap();
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits::default());
        let control = CollectionControl::new(None);
        let next = next_candidates(
            &root,
            &mut state,
            &mut budget,
            &control,
            CandidateQuota {
                candidates: 1,
                work_units: 1000,
            },
        );
        assert_eq!(pids(&next), [12]);
        let samples = sample_members(&root, &next.candidates, &mut budget, &control);
        assert_eq!(samples.answer(12), MembershipOutcome::AbsentAtLeaf);
    }
    #[test]
    fn grouped_begin_end_sampling_reaches_later_candidates_without_spending_discovery_budget_again()
    {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n13\n14\n").unwrap();
        let mut state = CgroupWalkState::default();
        let control = CollectionControl::new(None);
        for expected in [vec![11, 12], vec![13, 14]] {
            let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
                members: 2,
                total_bytes: 40,
                ..CgroupWalkLimits::default()
            });
            let candidates = next_candidates(
                &root,
                &mut state,
                &mut budget,
                &control,
                CandidateQuota {
                    candidates: 2,
                    work_units: 1000,
                },
            );
            assert_eq!(pids(&candidates), expected);
            for _ in 0..2 {
                let samples = sample_members(&root, &candidates.candidates, &mut budget, &control);
                assert_eq!(samples.outcome, CollectionOutcome::Complete);
                assert!(
                    candidates
                        .candidates
                        .keys()
                        .all(|pid| samples.answer(*pid) == MembershipOutcome::Present)
                );
            }
            assert_eq!(budget.used.members, 2);
            assert!(budget.used.membership_bytes <= 40);
        }
    }
    #[test]
    fn unreachable_suffix_is_unknown_but_prior_matched_sample_is_preserved() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n13\n14\n").unwrap();
        let candidates = run(
            &root,
            &mut CgroupWalkState::default(),
            CgroupWalkLimits::default(),
        );
        let requests = BTreeMap::from([
            (11, candidates.candidates[&11].clone()),
            (14, candidates.candidates[&14].clone()),
        ]);
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            total_bytes: 6,
            ..CgroupWalkLimits::default()
        });
        let samples = sample_members(&root, &requests, &mut budget, &CollectionControl::new(None));
        assert_eq!(samples.answer(11), MembershipOutcome::Present);
        assert_eq!(
            samples.answer(14),
            MembershipOutcome::Unknown(CgroupIncomplete::TotalBytesLimit)
        );
        assert_eq!(
            samples.outcome,
            CollectionOutcome::Incomplete(CgroupIncomplete::TotalBytesLimit)
        );
    }
    #[test]
    fn discovery_work_slice_leaves_shared_work_for_fresh_validation() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n13\n").unwrap();
        let mut budget = CgroupWalkBudget::new(CgroupWalkLimits {
            work_units: 200,
            ..CgroupWalkLimits::default()
        });
        let control = CollectionControl::new(None);
        let candidates = next_candidates(
            &root,
            &mut CgroupWalkState::default(),
            &mut budget,
            &control,
            CandidateQuota {
                candidates: 1,
                work_units: 60,
            },
        );
        assert_eq!(pids(&candidates), [11]);
        assert!(candidates.work.units <= 60);
        let samples = sample_members(&root, &candidates.candidates, &mut budget, &control);
        assert_eq!(samples.answer(11), MembershipOutcome::Present);
        assert!(budget.used.units <= 200);
    }
    #[test]
    fn each_injected_cap_is_explicit_and_fd_peak_is_bounded() {
        let (dir, root) = tree();
        fs::write(dir.path().join("cgroup.procs"), "11\n12\n").unwrap();
        child(dir.path(), "leaf", "13\n");
        let cases = [
            (
                CgroupWalkLimits {
                    directories: 0,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::DirectoryLimit,
            ),
            (
                CgroupWalkLimits {
                    depth: 0,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::DepthLimit,
            ),
            (
                CgroupWalkLimits {
                    members: 0,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::MemberLimit,
            ),
            (
                CgroupWalkLimits {
                    file_bytes: 2,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::FileBytesLimit,
            ),
            (
                CgroupWalkLimits {
                    total_bytes: 2,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::TotalBytesLimit,
            ),
            (
                CgroupWalkLimits {
                    path_bytes: 0,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::PathBytesLimit,
            ),
            (
                CgroupWalkLimits {
                    work_units: 0,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::WorkLimit,
            ),
            (
                CgroupWalkLimits {
                    open_fds: 1,
                    ..CgroupWalkLimits::default()
                },
                CgroupIncomplete::FdLimit,
            ),
        ];
        for (limits, reason) in cases {
            let fd_cap = limits.open_fds;
            let result = run(&root, &mut CgroupWalkState::default(), limits);
            assert_eq!(result.outcome, CollectionOutcome::Incomplete(reason));
            assert!(result.work.peak_open_fds <= fd_cap);
        }
    }
}
