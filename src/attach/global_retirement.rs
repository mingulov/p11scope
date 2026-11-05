//! SPDX-License-Identifier: GPL-3.0-or-later
//! Physical retirement and reselection of global static points.

use super::pid_continuity::{AttachRound, PhysicalGapSummary, RegistrationId, current_pair};
use super::{RegisteredLink, RetainedStaticTarget, StaticEndpoint, current_static_sides_from};
use crate::discovery::identity::PinnedObjects;
use crate::plan::Slot;
use aya::programs::uprobe::UProbeScope;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct Retirements {
    summary: PhysicalGapSummary,
    // The index is bounded storage custody, never cross-store identity.
    points: BTreeMap<u32, RetiredPoint>,
    last_completed_ns: Option<u64>,
    exhausted: bool,
}

struct RetiredPoint {
    target: RetainedStaticTarget,
    pair: Option<(RegistrationId, RegistrationId)>,
    started_ns: Option<u64>,
    selected: Option<Selection>,
}

struct Selection {
    target: RetainedStaticTarget,
    completed_ns: Option<u64>,
    completed_pair: Option<(RegistrationId, RegistrationId)>,
}

fn held_target_valid(target: &RetainedStaticTarget) -> bool {
    target.held.as_ref().is_some_and(|held| {
        held.abi() == target.abi
            && held.attach_path() == target.path
            && held.check_unchanged() == Ok(true)
    })
}

fn same_retained_point(left: &RetainedStaticTarget, right: &RetainedStaticTarget) -> bool {
    left.slot.file_offset == right.slot.file_offset
        && left.abi == right.abi
        && held_target_valid(left)
        && held_target_valid(right)
        && left
            .held
            .as_ref()
            .zip(right.held.as_ref())
            .is_some_and(|(left, right)| {
                Arc::ptr_eq(&left.retirement_lease(), &right.retirement_lease())
            })
}

pub(super) fn merge_summaries(
    pid: PhysicalGapSummary,
    global: PhysicalGapSummary,
) -> PhysicalGapSummary {
    let episodes = pid.episodes.checked_add(global.episodes);
    PhysicalGapSummary {
        episodes: episodes.unwrap_or(u64::MAX),
        max_gap_ns: pid.max_gap_ns.into_iter().chain(global.max_gap_ns).max(),
        open: pid.open || global.open,
        unknown: pid.unknown || global.unknown || episodes.is_none(),
    }
}

impl Retirements {
    pub(super) fn summary(&self) -> PhysicalGapSummary {
        self.summary
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn retire_selected(
        &mut self,
        scope: UProbeScope,
        stopped: bool,
        links: &[RegisteredLink],
        choices: &[bool],
        excluded: &BTreeSet<u32>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        clock: impl FnOnce() -> Option<u64>,
    ) {
        if !matches!(scope, UProbeScope::AllProcesses) || stopped || self.exhausted {
            return;
        }
        if choices.len() != links.len() {
            self.summary.unknown = true;
            return;
        }
        let affected: BTreeSet<_> = links
            .iter()
            .zip(choices)
            .filter(|(link, chosen)| {
                **chosen
                    && matches!(
                        link,
                        RegisteredLink::UProbe { .. } | RegisteredLink::MultiUProbe { .. }
                    )
            })
            .flat_map(|(link, _)| link.slots().iter().copied())
            .filter(|slot| !excluded.contains(slot))
            .collect();
        if affected.is_empty() {
            return;
        }
        let started_ns = clock().filter(|time| {
            *time != 0
                && self
                    .last_completed_ns
                    .is_none_or(|previous| *time > previous)
        });
        self.summary.unknown |= started_ns.is_none();
        let sides = current_static_sides_from(links);
        for index in affected {
            let Some(target) = retained
                .get(&index)
                .filter(|target| target.slot.index == index)
            else {
                self.summary.unknown = true;
                continue;
            };
            let pair = current_pair(index, links, &sides);
            self.summary.unknown |= pair.is_none() || !held_target_valid(target);
            if let Some(previous) = self.points.get_mut(&index) {
                // A pending point may be touched again, but must keep its
                // earliest retirement time and the original physical authority.
                if !same_retained_point(&previous.target, target) {
                    self.summary.unknown = true;
                }
                if let Some(selected) = &mut previous.selected {
                    selected.completed_ns = None;
                    selected.completed_pair = None;
                }
                continue;
            }
            if self.points.len() >= p11scope_ebpf_common::MAX_SLOTS as usize {
                self.summary.unknown = true;
                self.exhausted = true;
                return;
            }
            self.points.insert(
                index,
                RetiredPoint {
                    target: target.clone(),
                    pair,
                    started_ns,
                    selected: None,
                },
            );
        }
    }

    /// Reselection across pin stores requires opened-file identity. Slot IDs,
    /// descriptor cookies, raw maps keys and path spellings do not participate.
    pub(super) fn select(&mut self, slots: &[Slot], objects: &PinnedObjects) {
        if self.exhausted || self.points.is_empty() {
            return;
        }
        let mut selected = Vec::new();
        for (&index, retired) in &self.points {
            let Some(held) = &retired.target.held else {
                self.summary.unknown = true;
                continue;
            };
            if held.check_unchanged() != Ok(true) {
                self.summary.unknown = true;
                continue;
            }
            let matches: Vec<_> = slots
                .iter()
                .filter(|slot| {
                    slot.file_offset == retired.target.slot.file_offset
                        && objects.abi_for(slot.object) == Some(retired.target.abi)
                })
                .filter(|slot| {
                    if held.same_kernel_file_as(objects, slot.object)
                        && (held.check_unchanged() != Ok(true)
                            || !held.same_object_as(objects, slot.object))
                    {
                        self.summary.unknown = true;
                    }
                    held.check_unchanged() == Ok(true) && held.same_object_as(objects, slot.object)
                })
                .collect();
            if matches.len() > 1 {
                self.summary.unknown = true;
                continue;
            }
            let Some(slot) = matches.first() else {
                continue;
            };
            let Ok(held) = objects.retain_inventory_target(slot.object) else {
                self.summary.unknown = true;
                continue;
            };
            let target = RetainedStaticTarget {
                slot: (*slot).clone(),
                path: held.attach_path(),
                abi: held.abi(),
                held: Some(held),
            };
            if !held_target_valid(&target) {
                self.summary.unknown = true;
                continue;
            }
            selected.push((index, target));
        }
        self.publish_selection(selected);
    }

    /// A Multi rebuild has no new pin store: its surviving targets share the
    /// exact retained opened file. Arc custody plus unchanged metadata proves
    /// this special case; a proc-fd path comparison alone would not.
    pub(super) fn select_retained(&mut self, targets: &[RetainedStaticTarget]) {
        if self.exhausted {
            return;
        }
        let mut selected = Vec::new();
        for (&index, retired) in &self.points {
            let matches: Vec<_> = targets
                .iter()
                .filter(|target| same_retained_point(&retired.target, target))
                .collect();
            if matches.len() > 1 {
                self.summary.unknown = true;
            } else if let Some(target) = matches.first() {
                selected.push((index, (*target).clone()));
            } else if targets.iter().any(|target| target.slot.index == index) {
                // An affected survivor whose held authority cannot be proved
                // must not disappear from the rebuild's coverage accounting.
                self.summary.unknown = true;
            }
        }
        self.publish_selection(selected);
    }

    fn publish_selection(&mut self, selected: Vec<(u32, RetainedStaticTarget)>) {
        if selected.is_empty() {
            return;
        }
        let unique: BTreeSet<_> = selected
            .iter()
            .map(|(_, target)| target.slot.index)
            .collect();
        if unique.len() != selected.len() {
            self.summary.unknown = true;
            return;
        }
        if !self.summary.open {
            let Some(episodes) = self.summary.episodes.checked_add(1) else {
                self.summary.unknown = true;
                self.summary.open = true;
                self.exhausted = true;
                return;
            };
            self.summary.episodes = episodes;
            self.summary.open = true;
        }
        for (index, target) in selected {
            self.points
                .get_mut(&index)
                .expect("selected retained point")
                .selected = Some(Selection {
                target,
                completed_ns: None,
                completed_pair: None,
            });
        }
    }

    pub(super) fn seal(
        &mut self,
        rounds: &[AttachRound],
        links: &[RegisteredLink],
        sides: &BTreeSet<StaticEndpoint>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        mut clock: impl FnMut() -> Option<u64>,
    ) {
        if !self.summary.open || self.exhausted {
            return;
        }
        for round in rounds {
            let round_slots: BTreeSet<_> = round.slots.iter().copied().collect();
            let affected: Vec<_> = self
                .points
                .iter()
                .filter_map(|(&index, point)| {
                    point
                        .selected
                        .as_ref()
                        .filter(|selected| round_slots.contains(&selected.target.slot.index))
                        .map(|_| index)
                })
                .collect();
            if affected.is_empty() {
                continue;
            }
            let completed = clock();
            let timing = round
                .started_ns
                .zip(round.last_call_ns)
                .zip(completed)
                .filter(|((start, last), end)| {
                    *start > 0 && *last >= *start && *end > *start && *end >= *last
                });
            if timing.is_none() || round_slots.len() != round.slots.len() {
                self.summary.unknown = true;
                continue;
            }
            let ((start, _last), completed) = timing.expect("validated native attempt clocks");
            for index in affected {
                let point = self
                    .points
                    .get_mut(&index)
                    .expect("affected retained point");
                let selected = point.selected.as_mut().expect("affected selected point");
                let Some(retired_ns) = point.started_ns.filter(|retired| start > *retired) else {
                    self.summary.unknown = true;
                    continue;
                };
                let Some(actual) = retained.get(&selected.target.slot.index) else {
                    continue;
                };
                if actual.slot != selected.target.slot
                    || !same_retained_point(&selected.target, actual)
                    || !held_target_valid(&point.target)
                {
                    self.summary.unknown = true;
                    continue;
                }
                let Some((entry, return_)) = current_pair(actual.slot.index, links, sides) else {
                    continue;
                };
                let Some((old_entry, old_return)) = point.pair else {
                    self.summary.unknown = true;
                    continue;
                };
                if [entry, return_]
                    .iter()
                    .any(|id| *id == old_entry || *id == old_return)
                {
                    self.summary.unknown = true;
                    continue;
                }
                if completed.checked_sub(retired_ns).is_none() {
                    self.summary.unknown = true;
                    continue;
                }
                selected.completed_ns = Some(completed);
                selected.completed_pair = Some((entry, return_));
            }
        }
        // A completed point may have been withdrawn while another point was
        // pending. Only the same concrete current pair can retain its endpoint.
        for point in self.points.values_mut() {
            let Some(selected) = point.selected.as_mut() else {
                continue;
            };
            if selected.completed_ns.is_none() {
                continue;
            }
            let actual = retained.get(&selected.target.slot.index);
            let valid_target = actual.is_some_and(|actual| {
                actual.slot == selected.target.slot
                    && same_retained_point(&selected.target, actual)
                    && held_target_valid(&point.target)
            });
            if !valid_target
                || current_pair(selected.target.slot.index, links, sides) != selected.completed_pair
            {
                self.summary.unknown |= actual.is_some() && !valid_target;
                selected.completed_ns = None;
                selected.completed_pair = None;
            }
        }
        let selected: Vec<_> = self
            .points
            .values()
            .filter(|point| point.selected.is_some())
            .collect();
        if selected.is_empty()
            || selected
                .iter()
                .any(|point| point.selected.as_ref().unwrap().completed_ns.is_none())
        {
            return;
        }
        let started = selected.iter().filter_map(|point| point.started_ns).min();
        let completed = selected
            .iter()
            .filter_map(|point| point.selected.as_ref().unwrap().completed_ns)
            .max();
        let Some((completed, gap)) = started.zip(completed).and_then(|(start, end)| {
            end.checked_sub(start)
                .filter(|gap| *gap > 0)
                .map(|gap| (end, gap))
        }) else {
            self.summary.unknown = true;
            return;
        };
        self.summary.max_gap_ns = Some(
            self.summary
                .max_gap_ns
                .map_or(gap, |previous| previous.max(gap)),
        );
        self.last_completed_ns = Some(completed);
        self.summary.open = false;
        self.points.retain(|_, point| point.selected.is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::pid_continuity::{NativeAttempt, PairBook, tests::fixture};
    use crate::attach::{
        CapturePolicy, attach_targets_observed_with, current_static_sides_from,
        extract_selected_links, prune_linkless_retained, retain_from_successful,
    };
    use std::collections::VecDeque;
    use std::fs::File;

    /// The production static-attachment reducer, extraction boundary and held
    /// file proof are real. Only native attachment handles and clocks are scripted.
    #[derive(Default)]
    struct GlobalSession {
        retirements: Retirements,
        pairs: PairBook,
        links: Vec<RegisteredLink>,
        retained: BTreeMap<u32, RetainedStaticTarget>,
    }

    impl GlobalSession {
        fn attach(&mut self, targets: &[RetainedStaticTarget], clocks: &[u64], fail_entry: bool) {
            let slots: Vec<_> = targets.iter().map(|target| target.slot.clone()).collect();
            let paths = targets
                .iter()
                .map(|target| (target.slot.index, (target.path.clone(), target.abi)))
                .collect();
            let reported_completion = clocks.last().copied();
            let mut clocks: VecDeque<_> = clocks.iter().copied().collect();
            let outcome = attach_targets_observed_with(
                &slots,
                CapturePolicy::Allowlisted,
                false,
                |_| Ok(p11scope_manifest::elf::ElfAbi::Lp64),
                |program, slot, _point| {
                    NativeAttempt::run(
                        || clocks.pop_front(),
                        || {
                            if fail_entry && program != "p11_return" {
                                anyhow::bail!("scripted native entry attach failure");
                            }
                            self.links.push(RegisteredLink::MultiUProbe {
                                program,
                                slots: vec![slot.index],
                                fds: vec![File::open("/dev/null").unwrap().into()],
                                registration: self.pairs.register(),
                            });
                            Ok(())
                        },
                    )
                },
                |_| reported_completion,
            )
            .unwrap();
            retain_from_successful(&mut self.retained, &slots, &paths, &outcome.successful);
            for target in targets {
                if let Some(actual) = self.retained.get_mut(&target.slot.index) {
                    actual.held = target.held.as_ref().map(|held| held.share());
                }
            }
            self.retirements.seal(
                &outcome.continuity_rounds,
                &self.links,
                &current_static_sides_from(&self.links),
                &self.retained,
                || clocks.pop_front(),
            );
        }

        fn retire(&mut self, scope: UProbeScope, stopped: bool, excluded: BTreeSet<u32>) {
            let choices = vec![true; self.links.len()];
            self.retirements.retire_selected(
                scope,
                stopped,
                &self.links,
                &choices,
                &excluded,
                &self.retained,
                || Some(40),
            );
            drop(extract_selected_links(
                &mut self.links,
                &mut self.pairs,
                |_| true,
            ));
            prune_linkless_retained(&mut self.retained, &self.links);
        }
    }

    #[test]
    fn global_retirement_session_detach_reselect_records_actual_interval_without_pid_baseline() {
        let (_dir, pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        assert_eq!(session.retirements.summary(), PhysicalGapSummary::default());
        let mut replacement = target;
        replacement.slot.index = 7;
        replacement.slot.descriptor_index = 9;
        session
            .retirements
            .select(std::slice::from_ref(&replacement.slot), &pins);
        assert_eq!(session.retirements.summary().episodes, 1);
        assert!(session.retirements.summary().open);
        session.attach(&[replacement], &[60, 70, 100], false);
        assert_eq!(
            session.retirements.summary(),
            PhysicalGapSummary {
                episodes: 1,
                max_gap_ns: Some(60),
                open: false,
                unknown: false,
            }
        );
    }

    #[test]
    fn global_retirement_session_failed_pair_stays_open() {
        let (_dir, pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        session
            .retirements
            .select(std::slice::from_ref(&target.slot), &pins);
        session.attach(&[target], &[60, 70, 100], true);
        assert!(session.retirements.summary().open);
        assert_eq!(session.retirements.summary().max_gap_ns, None);
        assert_eq!(session.retirements.summary().episodes, 1);
    }

    #[test]
    fn global_retirement_session_stop_failed_slot_and_pid_are_excluded() {
        for (scope, stopped, excluded) in [
            (UProbeScope::AllProcesses, true, BTreeSet::new()),
            (UProbeScope::AllProcesses, false, BTreeSet::from([0])),
            (
                UProbeScope::OneProcess(std::num::NonZeroU32::new(123).unwrap()),
                false,
                BTreeSet::new(),
            ),
        ] {
            let (_dir, pins, target) = fixture();
            let mut session = GlobalSession::default();
            session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
            session.retire(scope, stopped, excluded);
            session.retirements.select(&[target.slot], &pins);
            assert_eq!(session.retirements.summary(), PhysicalGapSummary::default());
        }
    }

    #[test]
    fn global_retirement_session_cross_store_uses_held_file_not_ids_keys_or_cookie() {
        use crate::discovery::identity::test_fixture;
        use p11scope_manifest::maps::{Device, ObjectKey};
        let (dir, _pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        let later = test_fixture::real_scan_pin(
            &dir.path().join("provider"),
            Some(ObjectKey {
                device: Device {
                    major: 90,
                    minor: 91,
                },
                inode: 4242,
            }),
            77,
            test_fixture::SHA,
        );
        let mut replacement = target;
        replacement.slot.index = 9;
        replacement.slot.descriptor_index = 23;
        replacement.slot.names = vec!["C_GetInfo".into()];
        replacement.slot.object = later.pinned().next().unwrap().id;
        replacement.path = later.attach_path_for(replacement.slot.object).unwrap();
        replacement.held = Some(
            later
                .retain_inventory_target(replacement.slot.object)
                .unwrap(),
        );
        session
            .retirements
            .select(std::slice::from_ref(&replacement.slot), &later);
        drop(later);
        session.attach(&[replacement], &[60, 70, 100], false);
        assert_eq!(
            session.retirements.summary(),
            PhysicalGapSummary {
                episodes: 1,
                max_gap_ns: Some(60),
                open: false,
                unknown: false,
            }
        );
    }

    #[test]
    fn global_retirement_session_reused_local_id_raw_key_path_and_offset_are_not_identity() {
        use crate::discovery::identity::test_fixture;
        let (dir, _pins, target) = fixture();
        let key = target.held.as_ref().unwrap().object_key();
        let other_path = dir.path().join("other-provider");
        std::fs::write(&other_path, b"held provider bytes").unwrap();
        let other = test_fixture::real_scan_pin(&other_path, Some(key), 1, test_fixture::SHA);
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        // Identical capture-local object ID, descriptor, slot and path spellings;
        // the new pin actually holds another kernel file.
        let mut candidate = target.slot;
        candidate.object = other.pinned().next().unwrap().id;
        session.retirements.select(&[candidate], &other);
        assert_eq!(session.retirements.summary(), PhysicalGapSummary::default());
    }

    #[test]
    fn global_retirement_session_new_inode_at_same_path_never_closes_retired_point() {
        use crate::discovery::identity::test_fixture;
        let (dir, _pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        let path = dir.path().join("provider");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"held provider bytes").unwrap();
        let later = test_fixture::real_scan_pin(&path, None, 1, test_fixture::SHA);
        let mut candidate = target.slot;
        candidate.object = later.pinned().next().unwrap().id;
        session.retirements.select(&[candidate], &later);
        assert_eq!(session.retirements.summary().episodes, 0);
        assert_eq!(session.retirements.summary().max_gap_ns, None);
    }

    #[test]
    fn global_retirement_session_changed_held_file_cannot_publish_recovery() {
        use crate::discovery::identity::test_fixture;
        let (dir, _pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        let path = dir.path().join("provider");
        std::fs::write(&path, b"rewritten provider bytes of another size").unwrap();
        let later = test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        session.retirements.select(&[target.slot], &later);
        assert!(session.retirements.summary().unknown);
        assert_eq!(session.retirements.summary().max_gap_ns, None);
    }

    #[test]
    fn global_retirement_session_other_offset_is_new_admission() {
        let (_dir, pins, target) = fixture();
        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        let mut candidate = target.slot;
        candidate.index = 7;
        candidate.file_offset += 8;
        session.retirements.select(&[candidate], &pins);
        assert_eq!(session.retirements.summary(), PhysicalGapSummary::default());
    }

    #[test]
    fn global_retirement_session_clock_and_abi_refusals_are_unknown() {
        for (retirement_clock, wrong_abi) in [(None, false), (Some(0), false), (Some(40), true)] {
            let (_dir, pins, target) = fixture();
            let mut session = GlobalSession::default();
            session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
            if wrong_abi {
                session.retained.get_mut(&0).unwrap().abi = p11scope_manifest::elf::ElfAbi::Ilp32;
            }
            session.retirements.retire_selected(
                UProbeScope::AllProcesses,
                false,
                &session.links,
                &vec![true; session.links.len()],
                &BTreeSet::new(),
                &session.retained,
                || retirement_clock,
            );
            session.retirements.select(&[target.slot], &pins);
            assert!(session.retirements.summary().unknown);
            assert_eq!(session.retirements.summary().max_gap_ns, None);
        }
    }

    #[test]
    fn global_retirement_session_stale_pair_and_invalid_attempt_clock_stay_open() {
        for rounds in [
            vec![],
            vec![AttachRound {
                slots: vec![0],
                started_ns: Some(60),
                last_call_ns: Some(70),
            }],
            vec![AttachRound {
                slots: vec![0],
                started_ns: None,
                last_call_ns: Some(70),
            }],
            vec![AttachRound {
                slots: vec![0],
                started_ns: Some(39),
                last_call_ns: Some(70),
            }],
            vec![AttachRound {
                slots: vec![0],
                started_ns: Some(70),
                last_call_ns: Some(60),
            }],
        ] {
            let (_dir, pins, target) = fixture();
            let mut session = GlobalSession::default();
            session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
            // Keep old handles for a deliberate replay at the sealing boundary:
            // neither current sides nor an invented attach round makes them fresh.
            session.retirements.retire_selected(
                UProbeScope::AllProcesses,
                false,
                &session.links,
                &vec![true; session.links.len()],
                &BTreeSet::new(),
                &session.retained,
                || Some(40),
            );
            session.retirements.select(&[target.slot], &pins);
            session.retirements.seal(
                &rounds,
                &session.links,
                &current_static_sides_from(&session.links),
                &session.retained,
                || Some(100),
            );
            assert!(session.retirements.summary().open);
            assert_eq!(session.retirements.summary().max_gap_ns, None);
        }
    }

    #[test]
    fn global_retirement_session_fresh_pair_invalid_completion_clock_stays_unknown_open() {
        for clocks in [vec![60, 70], vec![60, 70, 50], vec![70, 60, 100]] {
            let (_dir, pins, target) = fixture();
            let mut session = GlobalSession::default();
            session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
            session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
            session
                .retirements
                .select(std::slice::from_ref(&target.slot), &pins);
            session.attach(&[target], &clocks, false);
            assert!(session.retirements.summary().unknown);
            assert!(session.retirements.summary().open);
            assert_eq!(session.retirements.summary().max_gap_ns, None);
        }
    }

    #[test]
    fn global_retirement_session_bound_and_episode_overflow_are_explicitly_unknown() {
        let (_dir, pins, target) = fixture();
        let targets: Vec<_> = (0..=p11scope_ebpf_common::MAX_SLOTS)
            .map(|index| {
                let mut target = target.clone();
                target.slot.index = index;
                target.slot.file_offset += u64::from(index) * 8;
                target
            })
            .collect();
        let mut session = GlobalSession::default();
        let clocks: Vec<_> = (1..=targets.len() as u64 * 2 + 1).collect();
        session.attach(&targets, &clocks, false);
        session.retirements.retire_selected(
            UProbeScope::AllProcesses,
            false,
            &session.links,
            &vec![true; session.links.len()],
            &BTreeSet::new(),
            &session.retained,
            || Some(10_000),
        );
        assert!(session.retirements.summary().unknown);
        assert_eq!(session.retirements.summary().episodes, 0);
        assert!(session.retirements.points.len() <= p11scope_ebpf_common::MAX_SLOTS as usize);

        let mut session = GlobalSession::default();
        session.attach(std::slice::from_ref(&target), &[10, 20, 30], false);
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        session.retirements.summary.episodes = u64::MAX;
        session.retirements.select(&[target.slot], &pins);
        assert!(session.retirements.summary().unknown);
        assert!(session.retirements.summary().open);
        assert_eq!(session.retirements.summary().episodes, u64::MAX);
    }

    #[test]
    fn global_retirement_summary_merge_preserves_unknown_open_and_checked_counts() {
        let pid = PhysicalGapSummary {
            episodes: 2,
            max_gap_ns: Some(40),
            open: true,
            unknown: false,
        };
        let global = PhysicalGapSummary {
            episodes: 3,
            max_gap_ns: Some(60),
            open: false,
            unknown: true,
        };
        assert_eq!(
            merge_summaries(pid, global),
            PhysicalGapSummary {
                episodes: 5,
                max_gap_ns: Some(60),
                open: true,
                unknown: true,
            }
        );
        assert!(
            merge_summaries(
                PhysicalGapSummary {
                    episodes: u64::MAX,
                    ..pid
                },
                global
            )
            .unknown
        );
    }

    #[test]
    fn global_retirement_session_partial_multi_rebuild_accounts_healthy_survivor_in_cleanup() {
        use crate::attach::{
            group_static_slots, publish_kept_multi_bundles, reattach_rebuilt_groups_observed_with,
        };
        let (_dir, _pins, target) = fixture();
        let mut sibling = target.clone();
        sibling.slot.index = 1;
        sibling.slot.file_offset += 8;
        let mut session = GlobalSession::default();
        session.attach(
            &[target.clone(), sibling.clone()],
            &[10, 20, 21, 22, 30],
            false,
        );
        // Represent the actual old full Multi group's two owned sides.
        session.links.clear();
        for program in ["p11_return", "p11_entry"] {
            session.links.push(RegisteredLink::MultiUProbe {
                program,
                slots: vec![0, 1],
                fds: vec![File::open("/dev/null").unwrap().into()],
                registration: session.pairs.register(),
            });
        }
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::from([0]));
        session
            .retirements
            .select_retained(std::slice::from_ref(&sibling));
        assert!(session.retirements.summary().open);
        let groups = group_static_slots(
            std::slice::from_ref(&sibling.slot),
            CapturePolicy::Allowlisted,
            false,
            &BTreeMap::from([(1, (sibling.path.clone(), sibling.abi))]),
        );
        let mut times = VecDeque::from([60, 70]);
        let (bundles, outcome) = reattach_rebuilt_groups_observed_with(
            &groups,
            |_| Some(90),
            |_, _, _, _| {
                NativeAttempt::run(
                    || times.pop_front(),
                    || Ok(File::open("/dev/null").unwrap().into()),
                )
            },
            drop,
        );
        publish_kept_multi_bundles(
            &mut session.links,
            &mut session.retained,
            bundles,
            &[sibling],
            &mut session.pairs,
        );
        session.retirements.seal(
            &outcome.continuity_rounds,
            &session.links,
            &current_static_sides_from(&session.links),
            &session.retained,
            || Some(100),
        );
        assert_eq!(
            session.retirements.summary(),
            PhysicalGapSummary {
                episodes: 1,
                max_gap_ns: Some(60),
                open: false,
                unknown: false,
            }
        );
        assert_eq!(
            session.retirements.points.len(),
            0,
            "failed requested point must not be ledgered"
        );
    }

    #[test]
    fn global_retirement_session_aggregate_close_revalidates_earlier_completed_pair() {
        let (_dir, pins, target) = fixture();
        let mut sibling = target.clone();
        sibling.slot.index = 1;
        sibling.slot.file_offset += 8;
        let mut session = GlobalSession::default();
        session.attach(
            &[target.clone(), sibling.clone()],
            &[10, 20, 21, 22, 30],
            false,
        );
        session.retire(UProbeScope::AllProcesses, false, BTreeSet::new());
        session
            .retirements
            .select(&[target.slot.clone(), sibling.slot.clone()], &pins);
        session.attach(&[target], &[60, 70, 100], false);
        assert!(session.retirements.summary().open);
        // Actual failed-manifest prefix cleanup can withdraw an earlier completed
        // pair while another required point is pending. Cached completion timing
        // must not become a final exact endpoint after that pair disappears.
        session.retirements.retire_selected(
            UProbeScope::AllProcesses,
            false,
            &session.links,
            &vec![true; session.links.len()],
            &BTreeSet::from([0]),
            &session.retained,
            || Some(105),
        );
        drop(extract_selected_links(
            &mut session.links,
            &mut session.pairs,
            |link| link.slots().contains(&0),
        ));
        prune_linkless_retained(&mut session.retained, &session.links);
        session.attach(&[sibling], &[110, 120, 130], false);
        assert!(session.retirements.summary().open);
        assert_eq!(session.retirements.summary().max_gap_ns, None);
    }
}
