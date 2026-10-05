//! SPDX-License-Identifier: GPL-3.0-or-later
//! C7 A5: the confirmation reads (`map_files` proofs, pins, exe and maps
//! re-reads) of the unselected pids, sharded by contiguous pid ranges.
//!
//! The same record-and-replay shape as the sharded sweep
//! ([`sweep_shards`](crate::discovery::sweep_shards)):
//!
//! - Each shard runs [`attribute_one`] for its pids against a private
//!   [`CaptureWorkBudget::shard_shadow`] and a recording probe. Every
//!   operating-system answer the code asks for (the pin and its checks,
//!   both exe reads, the maps re-read with its clock readings, every
//!   `map_files` proof and every `gone` check) is read there, in the order
//!   and at the moment the serial code reads it, and recorded. The proofs
//!   are read inside the shard's own pin, exactly as serially; nothing
//!   recorded outlives this stage (R-C56-1).
//! - The calling thread then runs [`attribute_one`] again for every pid,
//!   in pid order, against the capture budget, answered from the record.
//!   So every decision, charge (work units first, in order, then I/O),
//!   ceiling and loss is made where the serial path makes it, given the
//!   same answers.
//!
//! Why the record always has the answer the replay asks for: a shard's
//! shadow starts from the capture budget as it stands before any shard
//! runs, and only its own pids spend from it, so at every point it has at
//! least what the capture budget has at the same point of the replay. A
//! replay can therefore only stop earlier (a ceiling, a stop), never go
//! further: it asks for a prefix of the recorded answers. The one branch
//! that reads more answers after an earlier one (a stale examined range
//! escalating to a confirmation) depends only on answers both runs share.
//! An answer the record does not have would be a bug; it is refused
//! (fail closed: unproven, unreadable) rather than read late.

use crate::discovery::caller_registry::ExeIdentity;
use crate::discovery::identity::FileIdentity;
use crate::discovery::scan::{CaptureWorkBudget, MapsReadBuffers, MapsReadLimits};
use crate::discovery::sweep_attribution::{
    ConfirmIo, Confirmation, KnownKeyIndex, MappedIdentities, MemberProbe, SweepAttribution,
    attribute_one, confirm_with, stat_unpinned,
};
use crate::discovery::sweep_shards::{
    Transcript, record_read, replay_one, run_shards, shard_ranges,
};
use p11scope_manifest::maps::{MapEntry, ObjectKey};
use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::io::Read;

/// A [`ConfirmIo`] whose maps re-read can be recorded: the opened maps
/// file and the clock its read polls, which [`ConfirmIo::maps`] must be
/// exactly `read_maps_or_refuse(open_maps(pid)?, budget, maps_now)`.
pub(crate) trait ShardableIo: ConfirmIo {
    type Maps: Read;
    fn open_maps(&mut self, pid: u32) -> std::io::Result<Self::Maps>;
    fn maps_now(&self) -> Option<u64>;
}

/// The refusal a replay gives an answer its record lacks (unreachable).
const DIVERGED: &str = "sharded confirmation replay diverged from its read";

/// One recorded answer.
enum Answer {
    Open(Result<(), String>),
    StartTime(Option<u64>),
    StillTheSame(bool),
    Exe(Option<ExeIdentity>),
    /// `Err`: the maps file did not open.
    Maps(Result<Transcript, String>),
    Mapped(Vec<((u64, u64), Result<FileIdentity, String>)>),
    Gone(bool),
}

/// [`attribute_unselected`](crate::discovery::sweep_attribution::attribute_unselected)
/// over `shards` contiguous pid ranges of `sweep`: the same attribution and
/// the same final budget, given the same answers. `make_io` makes one fresh
/// [`ShardableIo`] per probe call, as the production probe does.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_sharded<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    shards: usize,
    make_io: &F,
) -> SweepAttribution
where
    Io: ShardableIo,
    F: Fn() -> Io + Sync,
{
    let prove = index.map_files_keys();
    let ranges = shard_ranges(sweep.len(), shards);
    let template: &CaptureWorkBudget = budget;
    let records = run_shards(&ranges, &|range: &std::ops::Range<usize>| {
        let mut shadow = template.shard_shadow();
        let mut scratch = SweepAttribution::default();
        sweep[range.clone()]
            .iter()
            .map(|(pid, phase_one)| {
                let mut probe = RecordingProbe {
                    make_io,
                    answers: RefCell::new(Vec::new()),
                    bufs: MapsReadBuffers::default(),
                };
                attribute_one(
                    &mut scratch,
                    *pid,
                    phase_one,
                    unavailable,
                    selected,
                    index,
                    &prove,
                    &mut probe,
                    &mut shadow,
                );
                Record(probe.answers.into_inner())
            })
            .collect::<Vec<_>>()
    });
    let mut out = SweepAttribution::default();
    let mut bufs = MapsReadBuffers::default();
    for ((pid, phase_one), record) in sweep.iter().zip(records.into_iter().flatten()) {
        let mut probe = ReplayProbe {
            answers: RefCell::new(record.0.into()),
            bufs: &mut bufs,
        };
        attribute_one(
            &mut out,
            *pid,
            phase_one,
            unavailable,
            selected,
            index,
            &prove,
            &mut probe,
            budget,
        );
    }
    out
}

/// One pid's answers, in the order they were read.
struct Record(Vec<Answer>);

/// The shard's probe: the production probe's calls, recorded.
struct RecordingProbe<'f, F> {
    make_io: &'f F,
    answers: RefCell<Vec<Answer>>,
    bufs: MapsReadBuffers,
}

impl<Io: ShardableIo, F: Fn() -> Io> MemberProbe for RecordingProbe<'_, F> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        let mut io = RecordingIo {
            inner: (self.make_io)(),
            answers: &self.answers,
            bufs: &mut self.bufs,
        };
        confirm_with(&mut io, pid, prove, budget)
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        let mut io = RecordingIo {
            inner: (self.make_io)(),
            answers: &self.answers,
            bufs: &mut self.bufs,
        };
        stat_unpinned(&mut io, pid, ranges, budget)
    }
}

struct RecordingIo<'a, Io> {
    inner: Io,
    answers: &'a RefCell<Vec<Answer>>,
    bufs: &'a mut MapsReadBuffers,
}

impl<Io: ShardableIo> RecordingIo<'_, Io> {
    fn note(&self, answer: Answer) {
        self.answers.borrow_mut().push(answer);
    }
}

impl<Io: ShardableIo> ConfirmIo for RecordingIo<'_, Io> {
    type Pin = Io::Pin;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        let result = self.inner.mapped_file(pid, start, end);
        self.note(Answer::Mapped(vec![((start, end), result.clone())]));
        result
    }

    fn mapped_files(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        let results = self.inner.mapped_files(pid, ranges);
        self.note(Answer::Mapped(
            ranges
                .iter()
                .copied()
                .zip(results.iter().cloned())
                .collect(),
        ));
        results
    }

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        let pin = self.inner.open(pid);
        self.note(Answer::Open(pin.as_ref().map(|_| ()).map_err(Clone::clone)));
        pin
    }

    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        let start = self.inner.start_time(pin);
        self.note(Answer::StartTime(start));
        start
    }

    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        let same = self.inner.still_the_same(pin);
        self.note(Answer::StillTheSame(same));
        same
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        let exe = self.inner.exe(pid);
        self.note(Answer::Exe(exe.clone()));
        exe
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        let file = match self.inner.open_maps(pid) {
            Ok(file) => file,
            Err(error) => {
                let error = error.to_string();
                self.note(Answer::Maps(Err(error.clone())));
                return Err(error);
            }
        };
        let inner = &self.inner;
        let (transcript, unclean) = record_read(
            file,
            budget,
            MapsReadLimits::LIVE,
            &|| inner.maps_now(),
            self.bufs,
        );
        let result = match unclean {
            Some(result) => result,
            None => transcript
                .clean_result()
                .cloned()
                .unwrap_or_else(|| Err(DIVERGED.into())),
        };
        self.note(Answer::Maps(Ok(transcript)));
        result
    }

    fn gone(&self, pid: u32) -> bool {
        let gone = self.inner.gone(pid);
        self.note(Answer::Gone(gone));
        gone
    }
}

/// The replay's probe: the same calls, answered from one pid's record.
struct ReplayProbe<'b> {
    answers: RefCell<VecDeque<Answer>>,
    bufs: &'b mut MapsReadBuffers,
}

impl MemberProbe for ReplayProbe<'_> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        let mut io = ReplayIo {
            answers: &self.answers,
            bufs: self.bufs,
        };
        confirm_with(&mut io, pid, prove, budget)
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        let mut io = ReplayIo {
            answers: &self.answers,
            bufs: self.bufs,
        };
        stat_unpinned(&mut io, pid, ranges, budget)
    }
}

struct ReplayIo<'a> {
    answers: &'a RefCell<VecDeque<Answer>>,
    bufs: &'a mut MapsReadBuffers,
}

impl ReplayIo<'_> {
    fn next(&self) -> Option<Answer> {
        let answer = self.answers.borrow_mut().pop_front();
        debug_assert!(answer.is_some(), "{DIVERGED}: no answer left");
        answer
    }

    fn diverged<T>(&self, what: &str, refusal: T) -> T {
        debug_assert!(false, "{DIVERGED}: expected {what}");
        refusal
    }

    /// The recorded proofs for `ranges`, which must be a prefix of the
    /// recorded ranges.
    fn mapped(&self, ranges: &[(u64, u64)]) -> Vec<Result<FileIdentity, String>> {
        match self.next() {
            Some(Answer::Mapped(recorded))
                if recorded.len() >= ranges.len()
                    && recorded
                        .iter()
                        .zip(ranges)
                        .all(|((range, _), want)| range == want) =>
            {
                recorded
                    .into_iter()
                    .take(ranges.len())
                    .map(|(_, result)| result)
                    .collect()
            }
            _ => self.diverged("map_files proofs", vec![Err(DIVERGED.into()); ranges.len()]),
        }
    }
}

impl ConfirmIo for ReplayIo<'_> {
    type Pin = ();

    fn mapped_file(&mut self, _pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.mapped(&[(start, end)])
            .pop()
            .unwrap_or_else(|| Err(DIVERGED.into()))
    }

    fn mapped_files(
        &mut self,
        _pid: u32,
        ranges: &[(u64, u64)],
    ) -> Vec<Result<FileIdentity, String>> {
        self.mapped(ranges)
    }

    fn open(&mut self, _pid: u32) -> Result<Self::Pin, String> {
        match self.next() {
            Some(Answer::Open(pin)) => pin,
            _ => self.diverged("a pin", Err(DIVERGED.into())),
        }
    }

    fn start_time(&self, _pin: &Self::Pin) -> Option<u64> {
        match self.next() {
            Some(Answer::StartTime(start)) => start,
            _ => self.diverged("a start time", None),
        }
    }

    fn still_the_same(&self, _pin: &Self::Pin) -> bool {
        match self.next() {
            Some(Answer::StillTheSame(same)) => same,
            _ => self.diverged("a pin check", false),
        }
    }

    fn exe(&self, _pid: u32) -> Option<ExeIdentity> {
        match self.next() {
            Some(Answer::Exe(exe)) => exe,
            _ => self.diverged("an exe read", None),
        }
    }

    fn maps(&mut self, _pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        match self.next() {
            Some(Answer::Maps(Ok(transcript))) => replay_one(
                transcript,
                budget,
                MapsReadLimits::LIVE,
                &crate::attach::monotonic_ns,
                self.bufs,
            ),
            Some(Answer::Maps(Err(error))) => Err(error),
            _ => self.diverged("a maps read", Err(DIVERGED.into())),
        }
    }

    fn gone(&self, _pid: u32) -> bool {
        match self.next() {
            Some(Answer::Gone(gone)) => gone,
            _ => self.diverged("a gone check", false),
        }
    }
}

#[cfg(test)]
#[path = "confirm_shards_tests.rs"]
mod tests;
