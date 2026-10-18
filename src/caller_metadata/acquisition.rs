// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded two-read acquisition of cgroup membership for caller metadata.
//!
//! This engine performs no process I/O itself: a narrow [`MembershipSource`]
//! supplies fixed-membership opens, cancellation, a cooperative deadline and
//! original-task liveness. The engine reads the complete membership twice
//! with a 16 KiB + 1 probe, requires byte-identical endpoints, and parses
//! them with the actual [`parse_cgroup_membership`](crate::caller_metadata::parse_cgroup_membership).
//!
//! Equal endpoints are an [`SampleValidity::EndpointSampleOnly`] sample for
//! the recorded read interval. They never prove continuous residence or the
//! absence of an ABA excursion between the reads.
//!
//! The returned [`UncommittedSample`] is explicitly uncommitted private data:
//! original-proc custody alone does not prove an unchanged full execution
//! image. A real outer coordinator must still validate capture, caller,
//! incarnation, sample sequence, original custody and the actual image fence
//! before publication. This packet creates no Presentation metadata.
//!
//! Numeric cgroup provenance is absent at this boundary ([`NumericAbsence`]).
//! Named dependency, not implemented here: mount-proofed cgroup2 directory
//! resolution under a held, verified root with proved namespace-coordinate
//! agreement. Nothing here fabricates an inode or maps a hardcoded
//! `/sys/fs/cgroup` coordinate.

#![forbid(unsafe_code)]

use crate::caller_metadata::{CgroupMembership, MAX_CGROUP_BYTES, parse_cgroup_membership};
use std::io::Read;
use std::time::Instant;

/// Maximum membership bytes the parser accepts; the probe adds one byte so a
/// truncated prefix can never be mistaken for the whole file.
pub(crate) const MEMBERSHIP_MAX_BYTES: usize = 16 * 1024;
/// Per-read probe capacity: [`MEMBERSHIP_MAX_BYTES`] plus the EOF witness byte.
pub(crate) const MEMBERSHIP_PROBE_BYTES: usize = MEMBERSHIP_MAX_BYTES + 1;
/// Complete membership reads per sample.
pub(crate) const MEMBERSHIP_READS_PER_SAMPLE: usize = 2;
/// Heap scratch owned by one sample: two probe buffers, freed on completion.
pub(crate) const SAMPLE_SCRATCH_HEAP_BYTES: usize =
    MEMBERSHIP_READS_PER_SAMPLE * MEMBERSHIP_PROBE_BYTES;
/// Stack footprint of the owned scratch value itself (two heap pointers);
/// the frame otherwise holds only small locals, never variable buffers.
pub(crate) const SAMPLE_SCRATCH_STACK_BYTES: usize = std::mem::size_of::<SampleScratch>();
/// Membership handles open at once: the first read is fully consumed and
/// dropped before the second open.
pub(crate) const MAX_OPEN_MEMBERSHIP_HANDLES: usize = 1;

/// Fixed-membership acquisition and original-task liveness for one sample.
///
/// The source opens only the fixed membership member it was constructed for;
/// it never resolves numeric PIDs, arbitrary paths, or fresh task identity.
/// All failures surface as finite [`SampleRefusal`] values.
pub(crate) trait MembershipSource {
    /// One complete membership stream, from open to EOF.
    type Handle: Read;

    /// Cooperative cancellation requested.
    fn is_cancelled(&self) -> bool;
    /// Cooperative deadline; a blocked kernel read is not preempted by it.
    fn deadline(&self) -> Instant;
    /// Original task still current: `Ok(())` when alive, a finite refusal
    /// when exited or unprovable. Never defaults to alive on error.
    fn check_original(&mut self) -> Result<(), SampleRefusal>;
    /// Open one fresh membership stream for a single complete read.
    fn open_membership(&mut self) -> Result<Self::Handle, SampleRefusal>;
}

/// Why a sample was withheld. Finite by construction: no paths, no errno
/// text, no error chains cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SampleRefusal {
    /// Cancellation was observed before or during acquisition.
    Cancelled,
    /// The cooperative deadline expired before or during acquisition.
    DeadlineExceeded,
    /// The original task exited (or its pin no longer proves it current).
    OriginalExited,
    /// Original liveness could not be established; fail closed.
    OriginalUnknown,
    /// Opening one membership stream failed.
    MembershipOpenFailed,
    /// A membership read failed before EOF, including interruption.
    /// Interrupted reads are refused, never silently retried.
    MembershipReadFailed,
    /// Membership exceeded the 16 KiB probe without EOF; no prefix accepted.
    MembershipOversized,
    /// The two endpoint reads disagreed; all hints are withheld, no retry.
    ChangedDuringSample,
}

/// Validity carried by every uncommitted sample. There is exactly one variant:
/// equal endpoints never become a continuous-residence or ABA-freedom claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SampleValidity {
    EndpointSampleOnly,
}

/// Numeric cgroup provenance at this boundary: always absent. Resolving the
/// sampled membership under a held, coordinate-verified cgroup2 root is the
/// named mount-proof dependency and is not part of this packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NumericAbsence {
    NamespaceUnresolved,
}

/// An explicitly uncommitted private sample: finite parser hints/statuses,
/// validity, numeric absence, and the bracketing read interval only. Raw
/// membership bytes are discarded on completion and never retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UncommittedSample {
    pub membership: CgroupMembership,
    pub validity: SampleValidity,
    pub numeric: NumericAbsence,
    pub started: Instant,
    pub ended: Instant,
}

/// Owned finite scratch for one sample. Dropping zeroes both probe buffers,
/// so raw bytes are discarded on every completion path.
struct SampleScratch {
    first: Box<[u8; MEMBERSHIP_PROBE_BYTES]>,
    second: Box<[u8; MEMBERSHIP_PROBE_BYTES]>,
}

impl SampleScratch {
    fn new() -> Self {
        Self {
            first: Box::new([0u8; MEMBERSHIP_PROBE_BYTES]),
            second: Box::new([0u8; MEMBERSHIP_PROBE_BYTES]),
        }
    }
}

impl Drop for SampleScratch {
    fn drop(&mut self) {
        self.first.fill(0);
        self.second.fill(0);
    }
}

/// Cancellation, then deadline, then original liveness. Order is load-bearing:
/// a cancelled job reports cancellation even past its deadline.
fn gate<S: MembershipSource>(source: &mut S) -> Result<(), SampleRefusal> {
    if source.is_cancelled() {
        return Err(SampleRefusal::Cancelled);
    }
    if Instant::now() >= source.deadline() {
        return Err(SampleRefusal::DeadlineExceeded);
    }
    source.check_original()
}

/// Read one complete membership into `buf`. Only an EOF-terminated read at or
/// below [`MEMBERSHIP_MAX_BYTES`] is accepted; oversize, errors and partial
/// reads are refused without accepting a prefix.
fn read_complete_membership<S: MembershipSource>(
    source: &mut S,
    buf: &mut [u8; MEMBERSHIP_PROBE_BYTES],
) -> Result<usize, SampleRefusal> {
    gate(source)?;
    let mut handle = source.open_membership()?;
    gate(source)?;
    let mut len = 0usize;
    loop {
        gate(source)?;
        let count = handle
            .read(&mut buf[len..])
            .map_err(|_| SampleRefusal::MembershipReadFailed)?;
        gate(source)?;
        if count == 0 {
            return Ok(len);
        }
        len += count;
        if len >= MEMBERSHIP_PROBE_BYTES {
            return Err(SampleRefusal::MembershipOversized);
        }
    }
}

/// Acquire one uncommitted endpoint sample: gate, read twice, require
/// identical endpoints, parse with the actual membership parser.
///
/// There is no retry loop: any refusal or endpoint disagreement withholds the
/// sample and returns. Raw bytes never escape in the result or the refusal.
pub(crate) fn acquire_endpoint_sample<S: MembershipSource>(
    source: &mut S,
) -> Result<UncommittedSample, SampleRefusal> {
    let started = Instant::now();
    let mut scratch = SampleScratch::new();
    let first_len = read_complete_membership(source, &mut scratch.first)?;
    let second_len = read_complete_membership(source, &mut scratch.second)?;
    let ended = Instant::now();
    if scratch.first[..first_len] != scratch.second[..second_len] {
        return Err(SampleRefusal::ChangedDuringSample);
    }
    let membership = parse_cgroup_membership(&scratch.first[..first_len]);
    Ok(UncommittedSample {
        membership,
        validity: SampleValidity::EndpointSampleOnly,
        numeric: NumericAbsence::NamespaceUnresolved,
        started,
        ended,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller_metadata::{ParseReason, ParseStatus, RuntimeHint};
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::ErrorKind;
    use std::rc::Rc;
    use std::time::Duration;

    const DOCKER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const POD_UID: &str = "12345678-1234-abcd-9876-1234567890ab";

    fn docker_membership() -> Vec<u8> {
        format!("0::/docker/{DOCKER_ID}\n").into_bytes()
    }

    fn k8s_membership() -> Vec<u8> {
        format!("0::/kubepods/burstable/pod{POD_UID}/{DOCKER_ID}\n").into_bytes()
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Liveness {
        Alive,
        Exited,
        Unknown,
    }

    #[derive(Clone)]
    struct Shared {
        cancelled: Rc<Cell<bool>>,
        deadline: Rc<Cell<Instant>>,
        liveness: Rc<Cell<Liveness>>,
        live: Rc<Cell<usize>>,
        peak: Rc<Cell<usize>>,
        reads: Rc<Cell<usize>>,
    }

    impl Shared {
        fn new(deadline: Instant) -> Self {
            Self {
                cancelled: Rc::new(Cell::new(false)),
                deadline: Rc::new(Cell::new(deadline)),
                liveness: Rc::new(Cell::new(Liveness::Alive)),
                live: Rc::new(Cell::new(0)),
                peak: Rc::new(Cell::new(0)),
                reads: Rc::new(Cell::new(0)),
            }
        }

        fn note_read(&self) {
            self.reads.set(self.reads.get() + 1);
        }
    }

    enum ReadStep {
        Data(usize),
        Eof,
        Err(ErrorKind),
        Sleep(Duration),
        Cancel,
        KillOriginal,
        PoisonLiveness,
    }

    struct ScriptedHandle {
        shared: Shared,
        data: Vec<u8>,
        cursor: usize,
        steps: VecDeque<ReadStep>,
    }

    impl Drop for ScriptedHandle {
        fn drop(&mut self) {
            self.shared.live.set(self.shared.live.get() - 1);
        }
    }

    impl Read for ScriptedHandle {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            loop {
                match self.steps.pop_front() {
                    None => panic!("scripted handle read past its steps"),
                    Some(ReadStep::Sleep(d)) => std::thread::sleep(d),
                    Some(ReadStep::Cancel) => self.shared.cancelled.set(true),
                    Some(ReadStep::KillOriginal) => self.shared.liveness.set(Liveness::Exited),
                    Some(ReadStep::PoisonLiveness) => {
                        self.shared.liveness.set(Liveness::Unknown);
                    }
                    Some(ReadStep::Err(kind)) => {
                        self.shared.note_read();
                        return Err(std::io::Error::new(kind, "scripted read error"));
                    }
                    Some(ReadStep::Eof) => {
                        self.shared.note_read();
                        return Ok(0);
                    }
                    Some(ReadStep::Data(n)) => {
                        self.shared.note_read();
                        let end = (self.cursor + n).min(self.data.len());
                        let count = end.saturating_sub(self.cursor).min(out.len());
                        out[..count].copy_from_slice(&self.data[self.cursor..self.cursor + count]);
                        self.cursor += count;
                        return Ok(count);
                    }
                }
            }
        }
    }

    struct HandleScript {
        data: Vec<u8>,
        steps: Vec<ReadStep>,
    }

    impl HandleScript {
        fn whole(data: Vec<u8>) -> Self {
            let len = data.len();
            Self {
                data,
                steps: vec![ReadStep::Data(len), ReadStep::Eof],
            }
        }

        fn one_byte_chunks(data: Vec<u8>) -> Self {
            let mut steps: Vec<ReadStep> = (0..data.len()).map(|_| ReadStep::Data(1)).collect();
            steps.push(ReadStep::Eof);
            Self { data, steps }
        }
    }

    enum OpenOutcome {
        Script(HandleScript),
        Fail,
    }

    struct ScriptedSource {
        shared: Shared,
        opens: VecDeque<OpenOutcome>,
        open_count: usize,
        check_count: usize,
    }

    impl ScriptedSource {
        fn new(deadline: Instant) -> Self {
            Self {
                shared: Shared::new(deadline),
                opens: VecDeque::new(),
                open_count: 0,
                check_count: 0,
            }
        }

        fn healthy(data: Vec<u8>) -> Self {
            Self::agree(data, Instant::now() + Duration::from_secs(30))
        }

        fn agree(data: Vec<u8>, deadline: Instant) -> Self {
            let mut source = Self::new(deadline);
            source
                .opens
                .push_back(OpenOutcome::Script(HandleScript::whole(data.clone())));
            source
                .opens
                .push_back(OpenOutcome::Script(HandleScript::whole(data)));
            source
        }

        fn shared(&self) -> &Shared {
            &self.shared
        }
    }

    impl MembershipSource for ScriptedSource {
        type Handle = ScriptedHandle;

        fn is_cancelled(&self) -> bool {
            self.shared.cancelled.get()
        }

        fn deadline(&self) -> Instant {
            self.shared.deadline.get()
        }

        fn check_original(&mut self) -> Result<(), SampleRefusal> {
            self.check_count += 1;
            match self.shared.liveness.get() {
                Liveness::Alive => Ok(()),
                Liveness::Exited => Err(SampleRefusal::OriginalExited),
                Liveness::Unknown => Err(SampleRefusal::OriginalUnknown),
            }
        }

        fn open_membership(&mut self) -> Result<Self::Handle, SampleRefusal> {
            self.open_count += 1;
            match self.opens.pop_front() {
                Some(OpenOutcome::Script(script)) => {
                    self.shared.live.set(self.shared.live.get() + 1);
                    let live = self.shared.live.get();
                    if live > self.shared.peak.get() {
                        self.shared.peak.set(live);
                    }
                    Ok(ScriptedHandle {
                        shared: self.shared.clone(),
                        data: script.data,
                        cursor: 0,
                        steps: script.steps.into(),
                    })
                }
                Some(OpenOutcome::Fail) => Err(SampleRefusal::MembershipOpenFailed),
                None => panic!("engine opened membership more often than scripted"),
            }
        }
    }

    fn generous_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn healthy_two_reads_agree_and_parse() {
        let mut source = ScriptedSource::healthy(docker_membership());
        let sample = acquire_endpoint_sample(&mut source).expect("healthy sample");
        assert_eq!(sample.membership.status, ParseStatus::Recognized);
        let container = sample.membership.container.expect("container hint");
        assert_eq!(container.id.as_str(), DOCKER_ID);
        assert_eq!(container.runtime, RuntimeHint::Docker);
        assert_eq!(sample.membership.pod, None);
        assert_eq!(sample.validity, SampleValidity::EndpointSampleOnly);
        assert_eq!(sample.numeric, NumericAbsence::NamespaceUnresolved);
        assert!(sample.started <= sample.ended);
        assert_eq!(source.open_count, 2);
        assert_eq!(source.shared().peak.get(), 1);
        assert_eq!(source.shared().live.get(), 0);
    }

    #[test]
    fn kubernetes_hints_parse_from_both_reads() {
        let mut source = ScriptedSource::healthy(k8s_membership());
        let sample = acquire_endpoint_sample(&mut source).expect("healthy sample");
        assert_eq!(sample.membership.status, ParseStatus::Recognized);
        assert_eq!(
            sample.membership.pod.expect("pod hint").uid.as_str(),
            POD_UID
        );
        assert_eq!(
            sample
                .membership
                .container
                .expect("container hint")
                .id
                .as_str(),
            DOCKER_ID
        );
    }

    /// Real `File` boundary: the engine drives an actual file read, not only
    /// scripted in-memory handles.
    #[test]
    fn real_file_boundary_reads_twice() {
        struct FileSource {
            path: std::path::PathBuf,
            deadline: Instant,
            opens: usize,
        }

        impl MembershipSource for FileSource {
            type Handle = std::fs::File;

            fn is_cancelled(&self) -> bool {
                false
            }

            fn deadline(&self) -> Instant {
                self.deadline
            }

            fn check_original(&mut self) -> Result<(), SampleRefusal> {
                Ok(())
            }

            fn open_membership(&mut self) -> Result<std::fs::File, SampleRefusal> {
                self.opens += 1;
                std::fs::File::open(&self.path).map_err(|_| SampleRefusal::MembershipOpenFailed)
            }
        }

        let dir = std::env::temp_dir().join(format!("p11scope-acq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cgroup");
        std::fs::write(&path, k8s_membership()).unwrap();
        let mut source = FileSource {
            path,
            deadline: generous_deadline(),
            opens: 0,
        };
        let sample = acquire_endpoint_sample(&mut source).expect("file sample");
        assert_eq!(sample.membership.status, ParseStatus::Recognized);
        assert_eq!(source.opens, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Real current-process membership bytes through the actual `Read`
    /// boundary. Any stable finite parser outcome is accepted; the point is
    /// exact EOF handling on a live proc file.
    #[test]
    fn real_proc_self_cgroup_reads_to_eof() {
        struct ProcSelfSource {
            deadline: Instant,
        }

        impl MembershipSource for ProcSelfSource {
            type Handle = std::fs::File;

            fn is_cancelled(&self) -> bool {
                false
            }

            fn deadline(&self) -> Instant {
                self.deadline
            }

            fn check_original(&mut self) -> Result<(), SampleRefusal> {
                Ok(())
            }

            fn open_membership(&mut self) -> Result<std::fs::File, SampleRefusal> {
                std::fs::File::open("/proc/self/cgroup")
                    .map_err(|_| SampleRefusal::MembershipOpenFailed)
            }
        }

        let mut source = ProcSelfSource {
            deadline: generous_deadline(),
        };
        let sample = acquire_endpoint_sample(&mut source).expect("self cgroup sample");
        assert_eq!(sample.validity, SampleValidity::EndpointSampleOnly);
        assert!(sample.started <= sample.ended);
    }

    #[test]
    fn short_reads_are_completed_not_prefixes() {
        let data = docker_membership();
        let mut source = ScriptedSource::new(generous_deadline());
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::one_byte_chunks(
                data.clone(),
            )));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::one_byte_chunks(data)));
        let sample = acquire_endpoint_sample(&mut source).expect("short reads complete");
        assert_eq!(sample.membership.status, ParseStatus::Recognized);
        assert_eq!(
            sample.membership.container.expect("hint").id.as_str(),
            DOCKER_ID
        );
    }

    #[test]
    fn exact_16kib_is_accepted_at_the_probe_boundary() {
        // 4-byte "0::/" prefix plus a single overlong component: the engine
        // accepts exactly 16 KiB and the parser reports the component limit.
        let mut data = b"0::/".to_vec();
        data.extend(std::iter::repeat_n(b'a', MEMBERSHIP_MAX_BYTES - data.len()));
        assert_eq!(data.len(), MEMBERSHIP_MAX_BYTES);
        let mut source = ScriptedSource::agree(data, generous_deadline());
        let sample = acquire_endpoint_sample(&mut source).expect("exact 16 KiB accepted");
        assert_eq!(sample.membership.status, ParseStatus::Refused);
        assert_eq!(
            sample.membership.reason,
            Some(ParseReason::ComponentTooLong)
        );
    }

    #[test]
    fn plus_one_byte_is_oversized_without_accepting_a_prefix() {
        for chunked in [false, true] {
            let data = vec![b'a'; MEMBERSHIP_PROBE_BYTES];
            let mut source = ScriptedSource::new(generous_deadline());
            for _ in 0..2 {
                let script = if chunked {
                    HandleScript::one_byte_chunks(data.clone())
                } else {
                    HandleScript::whole(data.clone())
                };
                source.opens.push_back(OpenOutcome::Script(script));
            }
            // One extra EOF step is unreachable: the probe fills first.
            assert_eq!(
                acquire_endpoint_sample(&mut source),
                Err(SampleRefusal::MembershipOversized),
                "chunked={chunked}"
            );
        }
    }

    #[test]
    fn oversized_second_read_withholds_despite_healthy_first() {
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(
            HandleScript::whole(docker_membership()),
        ));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(vec![
            b'a';
            MEMBERSHIP_PROBE_BYTES
        ])));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::MembershipOversized)
        );
    }

    #[test]
    fn zero_length_is_parser_malformed_not_acquisition_failure() {
        let mut source = ScriptedSource::agree(Vec::new(), generous_deadline());
        let sample = acquire_endpoint_sample(&mut source).expect("empty input still samples");
        assert_eq!(sample.membership.status, ParseStatus::Refused);
        assert_eq!(sample.membership.reason, Some(ParseReason::Malformed));
    }

    #[test]
    fn changed_bytes_withhold_all_hints() {
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(
            HandleScript::whole(docker_membership()),
        ));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(k8s_membership())));
        let refusal = acquire_endpoint_sample(&mut source).expect_err("A->B must withhold");
        assert_eq!(refusal, SampleRefusal::ChangedDuringSample);
        let rendered = format!("{refusal:?}");
        assert!(!rendered.contains(DOCKER_ID));
        assert!(!rendered.contains(POD_UID));
    }

    #[test]
    fn changed_length_withholds() {
        let mut longer = docker_membership();
        longer.extend_from_slice(b"#");
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(
            HandleScript::whole(docker_membership()),
        ));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(longer)));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::ChangedDuringSample)
        );
    }

    #[test]
    fn equal_endpoints_remain_endpoint_only_without_reread() {
        // A->B->A excursions between the reads are unobservable by design:
        // equal endpoints never claim more than the two endpoints.
        let mut source = ScriptedSource::healthy(docker_membership());
        let sample = acquire_endpoint_sample(&mut source).expect("equal endpoints sample");
        assert_eq!(sample.validity, SampleValidity::EndpointSampleOnly);
        assert_eq!(
            source.open_count, MEMBERSHIP_READS_PER_SAMPLE,
            "no third read may upgrade endpoints into residence proof"
        );
    }

    #[test]
    fn cancelled_before_acquisition_opens_nothing() {
        let mut source = ScriptedSource::healthy(docker_membership());
        source.shared().cancelled.set(true);
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::Cancelled)
        );
        assert_eq!(source.open_count, 0);
        assert_eq!(
            source.check_count, 0,
            "cancellation short-circuits before liveness"
        );
    }

    #[test]
    fn deadline_before_acquisition_opens_nothing() {
        let mut source = ScriptedSource::healthy(docker_membership());
        source.shared().deadline.set(Instant::now());
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::DeadlineExceeded)
        );
        assert_eq!(source.open_count, 0);
    }

    #[test]
    fn cancellation_wins_over_deadline_and_exit() {
        let mut source = ScriptedSource::healthy(docker_membership());
        source.shared().cancelled.set(true);
        source.shared().deadline.set(Instant::now());
        source.shared().liveness.set(Liveness::Exited);
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::Cancelled)
        );
    }

    #[test]
    fn cancel_during_first_read_withholds() {
        let data = docker_membership();
        let len = data.len();
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(HandleScript {
            data: data.clone(),
            steps: vec![ReadStep::Data(len), ReadStep::Cancel, ReadStep::Eof],
        }));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(data)));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::Cancelled)
        );
        assert_eq!(source.open_count, 1);
    }

    #[test]
    fn cancel_during_second_read_withholds() {
        let data = docker_membership();
        let len = data.len();
        let mut source = ScriptedSource::new(generous_deadline());
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(data.clone())));
        source.opens.push_back(OpenOutcome::Script(HandleScript {
            data,
            steps: vec![ReadStep::Data(len), ReadStep::Cancel, ReadStep::Eof],
        }));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::Cancelled)
        );
        assert_eq!(source.open_count, 2);
    }

    #[test]
    fn deadline_during_read_withholds() {
        let data = docker_membership();
        let mut source = ScriptedSource::new(Instant::now() + Duration::from_millis(50));
        for _ in 0..2 {
            source.opens.push_back(OpenOutcome::Script(HandleScript {
                data: data.clone(),
                steps: vec![
                    ReadStep::Sleep(Duration::from_millis(150)),
                    ReadStep::Data(data.len()),
                    ReadStep::Eof,
                ],
            }));
        }
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::DeadlineExceeded)
        );
    }

    #[test]
    fn exited_original_before_acquisition_opens_nothing() {
        let mut source = ScriptedSource::healthy(docker_membership());
        source.shared().liveness.set(Liveness::Exited);
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::OriginalExited)
        );
        assert_eq!(source.open_count, 0);
    }

    #[test]
    fn exited_original_during_read_withholds() {
        let data = docker_membership();
        let len = data.len();
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(HandleScript {
            data: data.clone(),
            steps: vec![ReadStep::Data(len), ReadStep::KillOriginal, ReadStep::Eof],
        }));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(data)));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::OriginalExited)
        );
    }

    #[test]
    fn unprovable_original_liveness_withholds() {
        let mut source = ScriptedSource::healthy(docker_membership());
        source.shared().liveness.set(Liveness::Unknown);
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::OriginalUnknown)
        );
        assert_eq!(source.open_count, 0);
    }

    #[test]
    fn unprovable_original_during_read_withholds() {
        let data = docker_membership();
        let len = data.len();
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(HandleScript {
            data: data.clone(),
            steps: vec![ReadStep::Data(len), ReadStep::PoisonLiveness, ReadStep::Eof],
        }));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(data)));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::OriginalUnknown)
        );
    }

    #[test]
    fn open_failure_is_finite() {
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Fail);
        source.opens.push_back(OpenOutcome::Script(
            HandleScript::whole(docker_membership()),
        ));
        let refusal = acquire_endpoint_sample(&mut source).expect_err("open must refuse");
        assert_eq!(refusal, SampleRefusal::MembershipOpenFailed);
        assert!(!format!("{refusal:?}").contains("cgroup"));
    }

    #[test]
    fn read_errors_are_refusals_and_only_eof_is_eof() {
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::PermissionDenied,
            ErrorKind::UnexpectedEof,
            ErrorKind::Other,
        ] {
            let data = docker_membership();
            let mut source = ScriptedSource::new(generous_deadline());
            source.opens.push_back(OpenOutcome::Script(HandleScript {
                data: data.clone(),
                steps: vec![ReadStep::Data(4), ReadStep::Err(kind)],
            }));
            source
                .opens
                .push_back(OpenOutcome::Script(HandleScript::whole(data)));
            assert_eq!(
                acquire_endpoint_sample(&mut source),
                Err(SampleRefusal::MembershipReadFailed),
                "kind={kind:?}"
            );
        }
    }

    #[test]
    fn interrupted_read_is_refused_without_retry() {
        // A retrying engine would consume the trailing EOF, complete the
        // first read as empty, and proceed to the second open; asserting the
        // refusal plus a single open proves the interruption stopped the job.
        let data = docker_membership();
        let mut source = ScriptedSource::new(generous_deadline());
        source.opens.push_back(OpenOutcome::Script(HandleScript {
            data: data.clone(),
            steps: vec![ReadStep::Err(ErrorKind::Interrupted), ReadStep::Eof],
        }));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::whole(data)));
        assert_eq!(
            acquire_endpoint_sample(&mut source),
            Err(SampleRefusal::MembershipReadFailed)
        );
        assert_eq!(source.open_count, 1);
        assert_eq!(
            source.shared().reads.get(),
            1,
            "the interrupted read was not retried"
        );
        assert_eq!(source.shared().live.get(), 0);
    }

    #[test]
    fn parser_statuses_forward_verbatim() {
        for (input, status, reason) in [
            (
                b"2:cpu:/legacy\n".as_slice(),
                ParseStatus::Refused,
                Some(ParseReason::HierarchyUnsupported),
            ),
            (
                b"0::/a\n0::/b\n".as_slice(),
                ParseStatus::Refused,
                Some(ParseReason::MembershipAmbiguous),
            ),
            (
                b"0::/user.slice/workload\n".as_slice(),
                ParseStatus::Unrecognized,
                Some(ParseReason::Unrecognized),
            ),
            (
                b"not a membership\n".as_slice(),
                ParseStatus::Refused,
                Some(ParseReason::Malformed),
            ),
        ] {
            let mut source = ScriptedSource::healthy(input.to_vec());
            let sample = acquire_endpoint_sample(&mut source).expect("parser status samples");
            assert_eq!(sample.membership.status, status, "{input:?}");
            assert_eq!(sample.membership.reason, reason, "{input:?}");
            assert_eq!(sample.membership.container, None, "{input:?}");
            assert_eq!(sample.membership.pod, None, "{input:?}");
        }
    }

    #[test]
    fn conflicting_pods_are_parser_refusal_not_acquisition_error() {
        let p1 = "12345678-1234-abcd-9876-1234567890ab";
        let p2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        let input = format!("0::/kubepods/pod{p1}/{outer}/kubepods/pod{p2}/{inner}\n").into_bytes();
        let mut source = ScriptedSource::healthy(input);
        let sample = acquire_endpoint_sample(&mut source).expect("ambiguous pattern samples");
        assert_eq!(sample.membership.status, ParseStatus::Refused);
        assert_eq!(
            sample.membership.reason,
            Some(ParseReason::AmbiguousPattern)
        );
    }

    #[test]
    fn no_raw_bytes_are_retained_in_sample_or_refusal() {
        let canary = "canary-component-9f8e7d6c5b4a";
        let input = format!("0::/user.slice/{canary}\n").into_bytes();
        let mut source = ScriptedSource::healthy(input);
        let sample = acquire_endpoint_sample(&mut source).expect("canary sample");
        assert_eq!(sample.membership.status, ParseStatus::Unrecognized);
        let rendered = format!("{sample:?}");
        assert!(!rendered.contains(canary), "{rendered}");
        assert!(
            std::mem::size_of::<UncommittedSample>() <= 512,
            "sample must stay finite, got {} bytes",
            std::mem::size_of::<UncommittedSample>()
        );
        // Copy by construction: using the value twice must compile.
        let again = sample;
        let _ = (sample, again);
    }

    #[test]
    fn transient_bounds_are_exposed_for_job_accounting() {
        assert_eq!(MEMBERSHIP_MAX_BYTES, MAX_CGROUP_BYTES);
        assert_eq!(MEMBERSHIP_PROBE_BYTES, MAX_CGROUP_BYTES + 1);
        assert_eq!(MEMBERSHIP_READS_PER_SAMPLE, 2);
        assert_eq!(SAMPLE_SCRATCH_HEAP_BYTES, 2 * (16 * 1024 + 1));
        assert_eq!(SAMPLE_SCRATCH_HEAP_BYTES, 32_770);
        assert_eq!(SAMPLE_SCRATCH_STACK_BYTES, 2 * std::mem::size_of::<usize>());
        assert_eq!(MAX_OPEN_MEMBERSHIP_HANDLES, 1);
        // Defense in depth: the parser itself refuses anything past the bound.
        let oversized = vec![b'a'; MEMBERSHIP_MAX_BYTES + 1];
        assert_eq!(
            parse_cgroup_membership(&oversized).reason,
            Some(ParseReason::ByteLimit)
        );
    }

    #[test]
    fn single_handle_open_at_a_time() {
        let data = docker_membership();
        let mut source = ScriptedSource::new(generous_deadline());
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::one_byte_chunks(
                data.clone(),
            )));
        source
            .opens
            .push_back(OpenOutcome::Script(HandleScript::one_byte_chunks(data)));
        acquire_endpoint_sample(&mut source).expect("healthy sample");
        assert_eq!(source.shared().peak.get(), MAX_OPEN_MEMBERSHIP_HANDLES);
        assert_eq!(source.shared().live.get(), 0);
    }
}
