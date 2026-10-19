//! SPDX-License-Identifier: GPL-3.0-or-later
//! Retained-[`ProcPin`](super::ProcPin) backend for caller cgroup sampling.
//!
//! This backend borrows already-held custody — the caller's [`ProcPin`] over
//! the original [`PidPin`](super::PidPin) — and implements the acquisition
//! engine's [`MembershipSource`](crate::caller_metadata::acquisition::MembershipSource).
//! It never opens a numeric PID, never reads an arbitrary path, and never
//! constructs fresh task identity: the only member opened is the internally
//! selected `cgroup` file, via the parent's [`relative_proc_open`](super::relative_proc_open),
//! and liveness reuses the original [`original_exited`](super::PidPin::original_exited)
//! check. Bundling these borrows is not admission or attestation.
//!
//! Original proc custody alone does not prove an unchanged full execution
//! image. The real outer coordinator must validate capture, caller,
//! incarnation, sample sequence, original custody and the actual image fence
//! before publication; this packet only returns an explicitly uncommitted
//! private sample with numeric provenance absent.

use super::{ProcPin, relative_proc_open};
use crate::caller_metadata::acquisition::{
    MembershipSource, SampleRefusal, UncommittedSample, acquire_endpoint_sample,
};
use std::os::fd::AsFd as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Fixed-membership source over a held proc directory and its original pin.
///
/// The transient footprint per sample is one membership FD at a time; the
/// proc directory FD and the original pidfd stay owned by the caller.
pub(crate) struct RetainedCgroupSource<'a> {
    proc_pin: &'a ProcPin<'a>,
    cancelled: &'a AtomicBool,
    deadline: Instant,
}

impl<'a> RetainedCgroupSource<'a> {
    /// Borrow held custody for one sample. This bundles borrows only; it
    /// grants no identity, image-fence, or publication authority.
    pub(crate) fn new(
        proc_pin: &'a ProcPin<'a>,
        cancelled: &'a AtomicBool,
        deadline: Instant,
    ) -> Self {
        Self {
            proc_pin,
            cancelled,
            deadline,
        }
    }
}

impl MembershipSource for RetainedCgroupSource<'_> {
    type Handle = std::fs::File;

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn check_original(&mut self) -> Result<(), SampleRefusal> {
        match self.proc_pin.pin.original_exited() {
            Ok(false) => Ok(()),
            Ok(true) => Err(SampleRefusal::OriginalExited),
            Err(_) => Err(SampleRefusal::OriginalUnknown),
        }
    }

    fn open_membership(&mut self) -> Result<std::fs::File, SampleRefusal> {
        let fd = relative_proc_open(self.proc_pin.directory.as_fd(), c"cgroup")
            .map_err(|_| SampleRefusal::MembershipOpenFailed)?;
        Ok(std::fs::File::from(fd))
    }
}

/// Acquire one uncommitted endpoint sample from held proc custody.
///
/// The caller retains the [`ProcPin`], the cancellation flag, and the
/// deadline; only finite refusals escape, never paths or error chains.
pub(crate) fn acquire_retained_cgroup_sample(
    proc_pin: &ProcPin<'_>,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<UncommittedSample, SampleRefusal> {
    let mut source = RetainedCgroupSource::new(proc_pin, cancelled, deadline);
    acquire_endpoint_sample(&mut source)
}

#[cfg(test)]
mod tests {
    use super::super::PidPin;
    use super::*;
    use crate::caller_metadata::acquisition::{NumericAbsence, SampleValidity};
    use std::time::Duration;

    fn generous_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// QUEUED: needs the controller's parent module declarations plus one
    /// Cargo build lane. Real current-process pin, real proc dir, real reads.
    #[test]
    fn retained_self_sample_is_endpoint_only() {
        let pin = PidPin::open(std::process::id()).expect("self pin");
        let proc = pin.open_proc_dir().expect("self proc dir");
        let cancelled = AtomicBool::new(false);
        let sample = acquire_retained_cgroup_sample(&proc, &cancelled, generous_deadline())
            .expect("self cgroup sample");
        assert_eq!(sample.validity, SampleValidity::EndpointSampleOnly);
        assert_eq!(sample.numeric, NumericAbsence::NamespaceUnresolved);
        assert!(sample.started <= sample.ended);
    }

    /// QUEUED: cancellation withholds before any membership open.
    #[test]
    fn retained_cancelled_before_open_withholds() {
        let pin = PidPin::open(std::process::id()).expect("self pin");
        let proc = pin.open_proc_dir().expect("self proc dir");
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            acquire_retained_cgroup_sample(&proc, &cancelled, generous_deadline()),
            Err(SampleRefusal::Cancelled)
        );
    }

    /// QUEUED: an expired cooperative deadline withholds the sample.
    #[test]
    fn retained_expired_deadline_withholds() {
        let pin = PidPin::open(std::process::id()).expect("self pin");
        let proc = pin.open_proc_dir().expect("self proc dir");
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            acquire_retained_cgroup_sample(&proc, &cancelled, Instant::now()),
            Err(SampleRefusal::DeadlineExceeded)
        );
    }

    /// QUEUED: a reaped original is refused through the real pidfd check,
    /// never re-read as a numeric-PID successor.
    #[test]
    fn retained_exited_original_withholds() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep child");
        let pin = PidPin::open(child.id()).expect("child pin");
        let proc = pin.open_proc_dir().expect("child proc dir");
        child.kill().expect("kill child");
        child.wait().expect("reap child");
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            acquire_retained_cgroup_sample(&proc, &cancelled, generous_deadline()),
            Err(SampleRefusal::OriginalExited)
        );
    }
}
