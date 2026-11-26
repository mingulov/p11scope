//! Mid-capture counting-coverage retirement ledger.
//!
//! A live global retire detaches attached counting probes. Whether that
//! loses calls depends on who still maps the object:
//!
//! - Some process still maps it (or the retire has no exit proof): calls
//!   can happen while the probes are down. The ledger opens a lossy
//!   window for each retired module, from the detach instant until the
//!   module has live cover again.
//! - Every mapper provably exited and none remains: no call is possible,
//!   so nothing is lost and nothing is disclosed. The retire is parked.
//!   If a mapper of that module is seen again before cover returns, the
//!   parked retire turns into a lossy window from its detach instant
//!   (calls of the new mapper before the re-attach were not observed);
//!   otherwise it never surfaces.
//!
//! Bounds: windows are kept per module, at most
//! [`MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE`] each; past the cap the
//! newest retire folds into the module's last window (its conservative
//! outer hull) and counts in `folded`. Retired slots count distinct
//! endpoints (exact opened identity plus offset), never retirements, so
//! repeated retire/re-attach cycles of one provider count its slots once.

use std::collections::{BTreeMap, BTreeSet};

use crate::discovery::identity::{PinnedObjectId, PinnedTimingKey};
use crate::plan::ModuleId;

/// Explicit windows one module keeps before later retires fold into its
/// last window. An engineering bound on memory and JSON size.
pub(crate) const MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE: usize = 8;

/// One retired counting endpoint, identified across re-pins of the same
/// file: the exact opened identity when the object has one, else the
/// capture-local pin (which can only over-count, never merge two files).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RetiredEndpoint {
    Keyed {
        object: PinnedTimingKey,
        file_offset: u64,
    },
    Pinned {
        object: PinnedObjectId,
        file_offset: u64,
    },
}

/// One retire interval on a module. `end_ns: None` reads open-ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetireInterval {
    pub(crate) start_ns: u64,
    pub(crate) end_ns: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ModuleWindows {
    /// Chronological; at most the per-module cap. Only the last can be open.
    windows: Vec<RetireInterval>,
    /// Retires folded into the last window past the cap.
    folded: u64,
    /// Distinct lossy endpoints of this module.
    endpoints: BTreeSet<RetiredEndpoint>,
}

/// A proof-backed retire with zero remaining mappers, waiting to see
/// whether a mapper of the module returns before cover does.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parked {
    start_ns: u64,
    endpoints: BTreeSet<RetiredEndpoint>,
}

/// Test view of one module's window (the projection's shape).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoverageRetireWindowView {
    pub(crate) modules: BTreeSet<ModuleId>,
    pub(crate) start_ns: u64,
    pub(crate) end_ns: Option<u64>,
    /// Distinct lossy endpoints of the module.
    pub(crate) slots: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CoverageRetireLedger {
    modules: BTreeMap<ModuleId, ModuleWindows>,
    /// Distinct lossy endpoints across all modules.
    endpoints: BTreeSet<RetiredEndpoint>,
    parked: BTreeMap<ModuleId, Parked>,
}

impl CoverageRetireLedger {
    /// File one lossy retire: every module of the endpoint gets (or keeps)
    /// an open window from `start_ns`. Returns the number of modules whose
    /// window was opened or reopened by this call.
    pub(crate) fn open(
        &mut self,
        modules: &BTreeSet<ModuleId>,
        endpoint: RetiredEndpoint,
        start_ns: u64,
    ) -> usize {
        let mut opened = 0;
        for module in modules {
            if self.open_module(*module, start_ns) {
                opened += 1;
            }
            self.modules
                .entry(*module)
                .or_default()
                .endpoints
                .insert(endpoint.clone());
        }
        if !modules.is_empty() {
            self.endpoints.insert(endpoint);
        }
        opened
    }

    /// Park one proof-backed zero-mapper retire: no window, no count,
    /// until a mapper of a module is seen again (`promote_seen`).
    pub(crate) fn park(
        &mut self,
        modules: &BTreeSet<ModuleId>,
        endpoint: RetiredEndpoint,
        start_ns: u64,
    ) -> usize {
        for module in modules {
            let parked = self.parked.entry(*module).or_insert(Parked {
                start_ns,
                endpoints: BTreeSet::new(),
            });
            parked.start_ns = parked.start_ns.min(start_ns);
            parked.endpoints.insert(endpoint.clone());
        }
        modules.len()
    }

    /// Turn every parked module the caller sees mapped again into a lossy
    /// window from its parked detach instant. Returns how many modules
    /// were promoted (the caller files the disclosure row when nonzero).
    pub(crate) fn promote_seen(&mut self, mut seen: impl FnMut(ModuleId) -> bool) -> usize {
        let promoted: Vec<ModuleId> = self
            .parked
            .keys()
            .copied()
            .filter(|module| seen(*module))
            .collect();
        for module in &promoted {
            let Some(parked) = self.parked.remove(module) else {
                continue;
            };
            self.open_module(*module, parked.start_ns);
            let windows = self.modules.entry(*module).or_default();
            for endpoint in parked.endpoints {
                windows.endpoints.insert(endpoint.clone());
                self.endpoints.insert(endpoint);
            }
        }
        promoted.len()
    }

    /// Close the open window of every module that has live cover again.
    pub(crate) fn close_revived(&mut self, active: &BTreeSet<ModuleId>, now_ns: u64) {
        for (module, windows) in &mut self.modules {
            if !active.contains(module) {
                continue;
            }
            if let Some(last) = windows.windows.last_mut()
                && last.end_ns.is_none()
            {
                last.end_ns = Some(now_ns.max(last.start_ns));
            }
        }
    }

    pub(crate) fn has_open(&self) -> bool {
        self.modules.values().any(|windows| {
            windows
                .windows
                .last()
                .is_some_and(|last| last.end_ns.is_none())
        })
    }

    pub(crate) fn has_parked(&self) -> bool {
        !self.parked.is_empty()
    }

    pub(crate) fn parked_ids(&self) -> BTreeSet<ModuleId> {
        self.parked.keys().copied().collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Distinct live counting endpoints retired with possible loss.
    pub(crate) fn retired_slots(&self) -> u64 {
        self.endpoints.len() as u64
    }

    /// The windows one module projects, oldest first.
    pub(crate) fn windows_for(&self, module: ModuleId) -> &[RetireInterval] {
        self.modules
            .get(&module)
            .map_or(&[], |windows| windows.windows.as_slice())
    }

    #[cfg(test)]
    pub(crate) fn folded_for(&self, module: ModuleId) -> u64 {
        self.modules
            .get(&module)
            .map_or(0, |windows| windows.folded)
    }

    #[cfg(test)]
    pub(crate) fn parked_modules(&self) -> BTreeSet<ModuleId> {
        self.parked_ids()
    }

    #[cfg(test)]
    pub(crate) fn views(&self) -> Vec<CoverageRetireWindowView> {
        let mut views = Vec::new();
        for (module, windows) in &self.modules {
            for interval in &windows.windows {
                views.push(CoverageRetireWindowView {
                    modules: BTreeSet::from([*module]),
                    start_ns: interval.start_ns,
                    end_ns: interval.end_ns,
                    slots: windows.endpoints.len() as u64,
                });
            }
        }
        views
    }

    /// Open (or keep open) one module's window from `start_ns`. Returns
    /// whether a window was opened or reopened.
    fn open_module(&mut self, module: ModuleId, start_ns: u64) -> bool {
        let windows = self.modules.entry(module).or_default();
        let full = windows.windows.len() >= MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE;
        match windows.windows.last_mut() {
            // Already open from an earlier instant: that window covers
            // this retire's whole interval.
            Some(last) if last.end_ns.is_none() => {
                last.start_ns = last.start_ns.min(start_ns);
                false
            }
            Some(last) if full => {
                // Fold: the last window becomes the conservative hull of
                // itself and this retire, open until cover returns.
                last.start_ns = last.start_ns.min(start_ns);
                last.end_ns = None;
                windows.folded = windows.folded.saturating_add(1);
                true
            }
            _ => {
                windows.windows.push(RetireInterval {
                    start_ns,
                    end_ns: None,
                });
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(offset: u64) -> RetiredEndpoint {
        RetiredEndpoint::Pinned {
            object: PinnedObjectId(7),
            file_offset: offset,
        }
    }

    fn set(ids: &[u32]) -> BTreeSet<ModuleId> {
        ids.iter().copied().map(ModuleId).collect()
    }

    #[test]
    fn parked_retire_files_nothing_until_a_mapper_is_seen() {
        let mut ledger = CoverageRetireLedger::default();
        assert_eq!(ledger.park(&set(&[0]), endpoint(16), 100), 1);
        assert!(ledger.is_empty(), "a parked retire opens no window");
        assert_eq!(ledger.retired_slots(), 0, "a parked retire counts nothing");
        assert!(!ledger.has_open());
        assert_eq!(ledger.promote_seen(|_| false), 0);
        assert!(ledger.is_empty());
        assert_eq!(ledger.parked_modules(), set(&[0]));
        assert_eq!(ledger.promote_seen(|module| module == ModuleId(0)), 1);
        assert_eq!(
            ledger.windows_for(ModuleId(0)),
            &[RetireInterval {
                start_ns: 100,
                end_ns: None
            }],
            "the promoted window starts at the parked detach instant"
        );
        assert_eq!(ledger.retired_slots(), 1);
        assert!(ledger.parked_modules().is_empty());
    }

    #[test]
    fn promotion_only_touches_the_seen_module() {
        let mut ledger = CoverageRetireLedger::default();
        ledger.park(&set(&[0, 1]), endpoint(16), 100);
        assert_eq!(ledger.promote_seen(|module| module == ModuleId(1)), 1);
        assert!(ledger.windows_for(ModuleId(0)).is_empty());
        assert_eq!(ledger.windows_for(ModuleId(1)).len(), 1);
        assert_eq!(ledger.parked_modules(), set(&[0]));
    }

    #[test]
    fn park_keeps_the_earliest_start() {
        let mut ledger = CoverageRetireLedger::default();
        ledger.park(&set(&[0]), endpoint(16), 200);
        ledger.park(&set(&[0]), endpoint(32), 100);
        ledger.promote_seen(|_| true);
        assert_eq!(ledger.windows_for(ModuleId(0))[0].start_ns, 100);
        assert_eq!(ledger.retired_slots(), 2);
    }

    #[test]
    fn open_window_absorbs_a_later_retire_of_the_same_module() {
        let mut ledger = CoverageRetireLedger::default();
        assert_eq!(ledger.open(&set(&[0]), endpoint(16), 100), 1);
        assert_eq!(ledger.open(&set(&[0]), endpoint(32), 150), 0);
        assert_eq!(ledger.windows_for(ModuleId(0)).len(), 1);
        assert_eq!(ledger.retired_slots(), 2);
    }

    #[test]
    fn close_revived_closes_only_active_modules() {
        let mut ledger = CoverageRetireLedger::default();
        ledger.open(&set(&[0, 1]), endpoint(16), 100);
        ledger.close_revived(&set(&[0]), 300);
        assert_eq!(ledger.windows_for(ModuleId(0))[0].end_ns, Some(300));
        assert_eq!(ledger.windows_for(ModuleId(1))[0].end_ns, None);
        assert!(ledger.has_open());
        ledger.close_revived(&set(&[1]), 400);
        assert_eq!(ledger.windows_for(ModuleId(1))[0].end_ns, Some(400));
        assert!(!ledger.has_open());
    }

    #[test]
    fn close_never_ends_before_the_start() {
        let mut ledger = CoverageRetireLedger::default();
        ledger.open(&set(&[0]), endpoint(16), 500);
        ledger.close_revived(&set(&[0]), 400);
        assert_eq!(ledger.windows_for(ModuleId(0))[0].end_ns, Some(500));
    }

    /// F2: a thousand retire/re-attach cycles of one provider keep at
    /// most the per-module cap of windows, fold the rest into a counted
    /// hull, and count the provider's distinct slots once.
    #[test]
    fn thousand_cycles_stay_bounded_with_an_exact_slot_count() {
        let mut ledger = CoverageRetireLedger::default();
        let slots = [16u64, 32, 48];
        for cycle in 0..1000u64 {
            let start = 1_000 + cycle * 10;
            for offset in slots {
                ledger.open(&set(&[3]), endpoint(offset), start);
            }
            ledger.close_revived(&set(&[3]), start + 5);
        }
        let windows = ledger.windows_for(ModuleId(3));
        // The literal bound (N = 8): a change of the cap is a reviewed
        // budget decision, never a silent drift of the public window list.
        assert_eq!(windows.len(), 8);
        assert_eq!(windows.len(), MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE);
        assert_eq!(ledger.folded_for(ModuleId(3)), 992);
        assert_eq!(ledger.retired_slots(), slots.len() as u64);
        let last = windows.last().unwrap();
        assert_eq!(
            last.start_ns,
            1_000 + (MAX_COVERAGE_RETIRE_WINDOWS_PER_MODULE as u64 - 1) * 10,
            "the hull starts at the last explicit window"
        );
        assert_eq!(
            last.end_ns,
            Some(1_000 + 999 * 10 + 5),
            "the hull ends at the last revival"
        );
        for pair in windows.windows(2) {
            assert!(
                pair[0].end_ns.unwrap() <= pair[1].start_ns,
                "explicit windows stay disjoint"
            );
        }
    }

    #[test]
    fn keyed_endpoints_count_once_across_pins() {
        let mut ledger = CoverageRetireLedger::default();
        let first = RetiredEndpoint::Pinned {
            object: PinnedObjectId(1),
            file_offset: 16,
        };
        let second = RetiredEndpoint::Pinned {
            object: PinnedObjectId(2),
            file_offset: 16,
        };
        ledger.open(&set(&[0]), first.clone(), 1);
        ledger.open(&set(&[0]), first, 2);
        assert_eq!(ledger.retired_slots(), 1);
        ledger.open(&set(&[0]), second, 3);
        assert_eq!(ledger.retired_slots(), 2, "distinct pins never merge");
    }

    #[test]
    fn empty_module_set_files_nothing() {
        let mut ledger = CoverageRetireLedger::default();
        assert_eq!(ledger.open(&BTreeSet::new(), endpoint(16), 1), 0);
        assert_eq!(ledger.retired_slots(), 0);
        assert!(ledger.is_empty());
        assert_eq!(ledger.park(&BTreeSet::new(), endpoint(16), 1), 0);
        assert!(!ledger.has_parked());
    }
}
