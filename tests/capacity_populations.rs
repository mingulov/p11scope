//! SPDX-License-Identifier: GPL-3.0-or-later
//! Independent capacity workload populations and demand accounting.
//!
//! Pure, deterministic population math for the Inventory capacity cells:
//! exact boundary composition, N/N+1 refusal pairs, growth-phase demands,
//! owner-population sizing, and the independently ledgered physical-demand
//! union. This module never executes or inspects an observer: every value
//! derives from target-side facts (mapped object identity plus published
//! table offsets), so the oracle and the Rust harness cross-check each
//! other instead of sharing one implementation.

use std::collections::{BTreeMap, BTreeSet};

/// Distinct physical endpoints on one full canonical 2.40 fixture table
/// (`version_matrix.c` with `CAPACITY_UNIQUE=68`).
pub const FULL_SURFACE: usize = 68;

/// Exact Inventory boundary demands: one past the default budget, one past
/// the historical 6,530 union, and the 8,192 candidate ceiling.
pub const BOUNDARY_DEMANDS: [usize; 3] = [4097, 6531, 8192];

/// N/N+1 refusal pairs: (selected budget, independent demand). The demand
/// exceeds the selected budget by exactly one physical endpoint.
pub const REFUSAL_PAIRS: [(usize, usize); 3] = [(4096, 4097), (6530, 6531), (8191, 8192)];

/// Growth-population provider counts per phase: 32 initial, 61 by the
/// middle snapshot, 97 late, plus one changed-inode path replacement.
pub const GROWTH_PHASE_PROVIDERS: [usize; 4] = [32, 61, 97, 98];

/// The owner cell needs 257 distinct provider-bearing process views.
pub const OWNER_DEMAND: usize = 257;

/// Endpoints per owner-cell provider: one tiny canonical table each, so the
/// owner population fits the endpoint budget it is not testing.
pub const OWNER_SURFACE: usize = 1;

/// Compose an exact demand from full 68-endpoint copies plus one smaller
/// physical tail. Returns `(full_copies, tail_endpoints)`.
pub fn compose(demand: usize) -> (usize, usize) {
    (demand / FULL_SURFACE, demand % FULL_SURFACE)
}

/// Provider count for an exact demand: one object per full copy plus one
/// for a nonzero tail.
pub fn provider_count(demand: usize) -> usize {
    let (full, tail) = compose(demand);
    full + if tail > 0 { 1 } else { 0 }
}

/// One target-side physical endpoint: a mapped object identity plus a
/// file offset into its executable mapping. Paths never participate:
/// aliases share an endpoint, distinct inodes never do.
pub type PhysicalEndpoint = (u64, u64, u64, u64);

/// Target-produced facts for one provider copy: its held-FD mapped
/// identity and its independently enumerated table surface. Built only
/// from the test application's own provider calls and its own mappings;
/// observer output cannot construct one.
#[derive(Debug, Clone)]
pub struct TargetFact {
    pub dev_major: u64,
    pub dev_minor: u64,
    pub ino: u64,
    pub offsets: Vec<u64>,
}

/// The independent demand union: deduplicated physical endpoints across
/// every owned provider copy. Duplicate offsets collapse, hardlink
/// aliases share, same-bytes/distinct-inode copies stay distinct, and a
/// path replacement under a new inode adds fresh endpoints.
#[derive(Debug, Default)]
pub struct DemandUnion {
    endpoints: BTreeSet<PhysicalEndpoint>,
    per_object: BTreeMap<(u64, u64, u64), BTreeSet<u64>>,
}

impl DemandUnion {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one target-produced provider surface into the union. Returns
    /// the count of endpoints this provider added beyond earlier copies.
    pub fn insert_provider(&mut self, fact: &TargetFact) -> usize {
        let identity = (fact.dev_major, fact.dev_minor, fact.ino);
        let mut fresh = 0;
        for offset in &fact.offsets {
            if self
                .endpoints
                .insert((identity.0, identity.1, identity.2, *offset))
            {
                fresh += 1;
            }
            self.per_object.entry(identity).or_default().insert(*offset);
        }
        fresh
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn object_count(&self) -> usize {
        self.per_object.len()
    }

    /// Exact whole demand the observer must account for: every admitted
    /// endpoint plus every refused whole-module surface sums to this.
    pub fn demand(&self) -> usize {
        self.len()
    }
}

/// Exact N+1 accounting for a selected budget: the demand exceeds the
/// budget by one endpoint, so at most `limit` endpoints can be admitted
/// and at least one endpoint of whole-module demand is refused.
pub fn refusal_accounting(limit: usize, demand: usize) -> Option<(usize, usize)> {
    if demand == limit + 1 {
        Some((limit, 1))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(ino: u64, offsets: &[u64]) -> TargetFact {
        TargetFact {
            dev_major: 0,
            dev_minor: 35,
            ino,
            offsets: offsets.to_vec(),
        }
    }

    #[test]
    fn boundary_composition_is_exact() {
        assert_eq!(compose(4097), (60, 17));
        assert_eq!(compose(6531), (96, 3));
        assert_eq!(compose(8192), (120, 32));
        for demand in BOUNDARY_DEMANDS {
            let (full, tail) = compose(demand);
            assert_eq!(full * FULL_SURFACE + tail, demand);
            assert!(tail < FULL_SURFACE, "tail is a smaller physical surface");
            assert_eq!(
                provider_count(demand),
                full + 1,
                "one object per full copy plus the tail"
            );
        }
        assert_eq!(provider_count(4097), 61);
        assert_eq!(provider_count(6531), 97);
        assert_eq!(provider_count(8192), 121);
    }

    #[test]
    fn refusal_pairs_differ_by_exactly_one_fresh_endpoint() {
        for (limit, demand) in REFUSAL_PAIRS {
            assert_eq!(demand, limit + 1, "N+1 demand for budget {limit}");
            let (max_occupied, min_refused) =
                refusal_accounting(limit, demand).expect("exact N+1 pair");
            assert_eq!(max_occupied, limit);
            assert_eq!(min_refused, 1);
            // The N+1 population extends the N population by one fresh
            // (object, offset): the same prefix plus one new endpoint.
            let mut prefix = DemandUnion::new();
            for ino in 0..limit as u64 {
                prefix.insert_provider(&fact(100 + ino, &[4096]));
            }
            assert_eq!(prefix.demand(), limit);
            let fresh = prefix.insert_provider(&fact(100 + limit as u64, &[4096]));
            assert_eq!(fresh, 1, "one fresh endpoint past the budget");
            assert_eq!(prefix.demand(), demand);
            assert_eq!(prefix.object_count(), demand);
        }
        assert!(refusal_accounting(4096, 4096).is_none());
        assert!(refusal_accounting(4096, 4098).is_none());
    }

    #[test]
    fn growth_phase_demands_cross_both_boundaries() {
        let demands: Vec<usize> = GROWTH_PHASE_PROVIDERS
            .iter()
            .map(|providers| providers * FULL_SURFACE)
            .collect();
        assert_eq!(demands, vec![2176, 4148, 6596, 6664]);
        assert!(demands[0] < 4096, "initial union below the default");
        assert!(
            demands[1] > 4096 && demands[1] <= 6530,
            "middle union between the boundaries"
        );
        assert!(demands[2] > 6530, "late union past the historical union");
        assert!(demands[3] > demands[2], "path replacement adds demand");
        assert!(demands[3] <= 8192, "one lifetime stays in the envelope");
    }

    #[test]
    fn owner_population_fits_the_budgets_it_does_not_test() {
        let tiny = OWNER_DEMAND * OWNER_SURFACE;
        let full_tables = OWNER_DEMAND * FULL_SURFACE;
        assert_eq!(tiny, 257);
        assert!(tiny <= 4096);
        assert!(
            full_tables > 8192,
            "full tables would test the endpoint budget instead of owners"
        );
    }

    #[test]
    fn demand_union_dedupes_aliases_not_inodes() {
        let mut union = DemandUnion::new();
        let surface: Vec<u64> = (0..68).map(|index| 4096 + 16 * index).collect();
        // Same bytes at distinct inodes stay distinct demand.
        assert_eq!(union.insert_provider(&fact(101, &surface)), 68);
        assert_eq!(union.insert_provider(&fact(102, &surface)), 68);
        assert_eq!(union.demand(), 136);
        // A hardlink alias of the first copy adds no demand.
        assert_eq!(union.insert_provider(&fact(101, &surface)), 0);
        assert_eq!(union.demand(), 136);
        assert_eq!(union.object_count(), 2);
        // Duplicate offsets inside one surface collapse.
        let mut doubled = surface.clone();
        doubled.extend(surface.iter().copied());
        assert_eq!(union.insert_provider(&fact(103, &doubled)), 68);
        assert_eq!(union.demand(), 204);
        // Same path under a new inode (replacement) is fresh demand.
        assert_eq!(union.insert_provider(&fact(104, &surface)), 68);
        assert_eq!(union.demand(), 272);
    }

    #[test]
    fn ledger_union_never_reads_observer_output() {
        // The union API takes only target facts: there is no constructor
        // from verdicts, budgets, gaps, edges, or callers. This test pins
        // that by building the exact 4,097 boundary union from synthetic
        // target facts alone and checking the composition agrees with the
        // oracle-side accounting inputs (61 objects, 4,097 endpoints).
        let (full, tail) = compose(4097);
        let mut union = DemandUnion::new();
        for index in 0..full {
            let surface: Vec<u64> = (0..FULL_SURFACE as u64)
                .map(|offset| 4096 + 16 * offset)
                .collect();
            assert_eq!(
                union.insert_provider(&fact(1000 + index as u64, &surface)),
                68
            );
        }
        let tail_surface: Vec<u64> = (0..tail as u64).map(|offset| 4096 + 16 * offset).collect();
        assert_eq!(union.insert_provider(&fact(2000, &tail_surface)), tail);
        assert_eq!(union.demand(), 4097);
        assert_eq!(union.object_count(), 61);
    }
}
