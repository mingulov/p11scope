//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pure comparison of independent inventory observation windows.

use super::{
    input::{self, Snapshot},
    model::*,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

// Large facts are encoded once per source record/category, never per edge.
// Ranks span both sides and denote exact normalized values, not entities.
#[derive(Clone, Copy)]
struct CallerRanks {
    population: usize,
    lifecycle: usize,
    full: usize,
}
#[derive(Clone, Copy)]
struct ModuleRanks {
    physical: usize,
    paths: usize,
    admission: usize,
    lifecycle: usize,
    full: usize,
}
#[derive(Clone, Copy)]
struct EdgeRanks {
    mapping: usize,
    entries: usize,
    coverage: usize,
    semantics: usize,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeFact {
    caller: usize,
    module: usize,
    mapping: usize,
    entries: usize,
    coverage: usize,
    semantics: usize,
}
struct Ranks {
    callers: Vec<CallerRanks>,
    modules: Vec<ModuleRanks>,
    edges: Vec<EdgeRanks>,
}
struct Prepared {
    summary: SnapshotSummary,
    callers: Vec<CallerRef>,
    modules: Vec<ModuleRef>,
    edges: Vec<EdgeRef>,
}
#[derive(Default)]
struct Group {
    edges: Vec<usize>,
    callers: BTreeSet<usize>,
    modules: BTreeSet<usize>,
}
struct Projection<'a> {
    contents: BTreeMap<&'a str, Vec<usize>>,
    paths: BTreeMap<&'a str, BTreeSet<Option<&'a str>>>,
    applications: BTreeMap<(usize, &'a str), Group>,
}

pub(super) fn compare(before: &Snapshot, after: &Snapshot) -> DiffReport {
    let paths: Vec<String> = [before, after]
        .into_iter()
        .flat_map(|s| {
            s.edges.iter().filter_map(|e| {
                s.modules[e.module].sha256.as_ref()?;
                exe_path(&s.callers[e.caller])
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let path_indexes: BTreeMap<&str, usize> = paths
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), i))
        .collect();
    let (br, ar) = ranks(before, after);
    let b = prepare(before, &br);
    let a = prepare(after, &ar);
    let bp = project(before, &path_indexes);
    let ap = project(after, &path_indexes);
    let mut summary = Summary {
        application_groups_compared: paths.len(),
        application_groups_changed: 0,
        content_both: 0,
        content_before_only: 0,
        content_after_only: 0,
        module_paths_changed: 0,
        unresolved_observations: 0,
    };
    let mut module_contents = Vec::new();
    for digest in bp
        .contents
        .keys()
        .chain(ap.contents.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let bi = bp
            .contents
            .get(digest)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let ai = ap
            .contents
            .get(digest)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let presence = presence(bi.is_empty(), ai.is_empty());
        match presence {
            Presence::Both => summary.content_both += 1,
            Presence::BeforeOnly => summary.content_before_only += 1,
            Presence::AfterOnly => summary.content_after_only += 1,
        }
        let mut changes = BTreeSet::new();
        if presence != Presence::Both {
            changes.insert("content_presence");
        } else {
            changes.extend(content_changes_for(bi, ai, &br, &ar));
        }
        module_contents.push(ContentRow {
            key: ContentKey {
                sha256: digest.to_owned(),
            },
            presence,
            changes: changes.into_iter().collect(),
            before: mapped(bi, &b.modules),
            after: mapped(ai, &a.modules),
        });
    }
    let mut application_changes = Vec::new();
    let mut changed_paths = BTreeSet::new();
    let empty = Group::default();
    for key in bp
        .applications
        .keys()
        .chain(ap.applications.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let bg = bp.applications.get(&key).unwrap_or(&empty);
        let ag = ap.applications.get(&key).unwrap_or(&empty);
        let changes = application_changes_for(before, after, bg, ag, &br, &ar);
        if changes.is_empty() {
            continue;
        }
        changed_paths.insert(key.0);
        application_changes.push(ApplicationChange {
            key: ApplicationKey {
                exe_path_ref: ApplicationPathRef(key.0),
                sha256: key.1.to_owned(),
            },
            presence: presence(bg.edges.is_empty(), ag.edges.is_empty()),
            changes,
            before: mapped(&bg.edges, &b.edges),
            after: mapped(&ag.edges, &a.edges),
            before_population: population(bg, &b),
            after_population: population(ag, &a),
        });
    }
    summary.application_groups_changed = changed_paths.len();
    let mut module_path_changes = Vec::new();
    let empty_paths = BTreeSet::new();
    for path in bp
        .paths
        .keys()
        .chain(ap.paths.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let bv = bp.paths.get(path).unwrap_or(&empty_paths);
        let av = ap.paths.get(path).unwrap_or(&empty_paths);
        if bv == av {
            continue;
        }
        module_path_changes.push(ModulePathChange {
            key: PathKey {
                path: path.to_owned(),
            },
            presence: presence(bv.is_empty(), av.is_empty()),
            changes: vec!["content_presence"],
            before: bv
                .iter()
                .map(|s| PathEvidence {
                    sha256: s.map(str::to_owned),
                })
                .collect(),
            after: av
                .iter()
                .map(|s| PathEvidence {
                    sha256: s.map(str::to_owned),
                })
                .collect(),
        });
    }
    summary.module_paths_changed = module_path_changes.len();
    let mut unresolved = unresolved_rows(before, &b, Side::Before);
    unresolved.extend(unresolved_rows(after, &a, Side::After));
    sort_full(&mut unresolved);
    summary.unresolved_observations = unresolved.len();
    let limitations = before
        .limitations
        .iter()
        .chain(&after.limitations)
        .cloned()
        .chain(
            [
                "absence_is_not_removal",
                "application_groups_use_recorded_paths",
                "counts_are_independent_windows",
                "host_boot_continuity_unknown",
                "physical_continuity_unknown",
                "process_continuity_unknown",
                "scope_completeness_unknown",
                "semantic_details_not_compared",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    DiffReport {
        schema: "p11scope/inventory-diff/v1",
        before: b.summary,
        after: a.summary,
        comparison: Comparison {
            host_relation: "unknown",
            boot_relation: "unknown",
            process_continuity: "unknown",
            physical_continuity: "unknown",
            counter_relation: "independent_windows",
            scope_relation: if before.scope == after.scope {
                "same_recorded_label"
            } else {
                "different_recorded_labels"
            },
            application_paths: paths,
        },
        summary,
        module_contents,
        application_changes,
        module_path_changes,
        unresolved,
        limitations,
    }
}

fn exe_path(c: &input::Caller) -> Option<&str> {
    c.image
        .exe
        .as_ref()?
        .path
        .as_deref()
        .filter(|p| !p.is_empty())
}
fn presence(before_empty: bool, after_empty: bool) -> Presence {
    if before_empty {
        Presence::AfterOnly
    } else if after_empty {
        Presence::BeforeOnly
    } else {
        Presence::Both
    }
}
fn encoded<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("typed inventory evidence is serializable")
}
fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v
}
fn mapped<T: Copy + Ord>(indexes: &[usize], map: &[T]) -> Vec<T> {
    sorted(indexes.iter().map(|&i| map[i]).collect())
}
fn sort_full<T: Serialize>(rows: &mut Vec<T>) {
    let mut indexed: Vec<_> = std::mem::take(rows)
        .into_iter()
        .map(|r| (encoded(&r), r))
        .collect();
    indexed.sort_by(|a, b| a.0.cmp(&b.0));
    *rows = indexed.into_iter().map(|(_, r)| r).collect();
}
fn caller_evidence(c: &input::Caller) -> CallerEvidence {
    CallerEvidence {
        pid: c.pid,
        start_time: c.start_time,
        start_time_unit: c.start_time_unit.clone(),
        image: ImageEvidence {
            authority: c.image.authority.clone(),
            exe: c.image.exe.clone(),
            exec_observed: c.image.exec_observed,
        },
        lifecycle: c.lifecycle.clone(),
        lifecycle_reason: c.lifecycle_reason.clone(),
        first_seen_ns: c.first_seen_ns,
        last_seen_ns: c.last_seen_ns,
        retired: c.retired,
    }
}
fn module_evidence(m: &input::Module) -> ModuleEvidence {
    let mut paths = m.paths.clone();
    paths.sort();
    paths.dedup();
    let mut admission = m.admission.clone();
    admission.reasons.sort();
    admission.reasons.dedup();
    ModuleEvidence {
        paths,
        identity: PhysicalIdentity {
            device: Device {
                major: m.device_major,
                minor: m.device_minor,
            },
            inode: m.inode,
            sha256: m.sha256.clone(),
            build_id: m.build_id.clone(),
            source: m.identity_source.clone(),
        },
        admission,
        lifecycle: m.lifecycle.clone(),
        unloaded_observed: m.unloaded_observed,
        unbound_use: m.unbound_use.clone(),
    }
}
fn caller_keys(c: &input::Caller) -> Vec<Vec<u8>> {
    let mut full = caller_evidence(c);
    full.first_seen_ns = 0;
    full.last_seen_ns = 0;
    vec![
        encoded(&(
            full.pid,
            full.start_time,
            &full.start_time_unit,
            &full.image,
        )),
        encoded(&(&full.lifecycle, &full.lifecycle_reason, full.retired)),
        encoded(&full),
    ]
}
fn module_keys(m: &input::Module) -> Vec<Vec<u8>> {
    let mut full = module_evidence(m);
    if let Some(h) = &mut full.admission.history {
        for a in h {
            a.at_ns = 0;
        }
    }
    if let Some(u) = &mut full.unbound_use {
        u.first_ns = 0;
    }
    vec![
        encoded(&full.identity),
        encoded(&full.paths),
        encoded(&full.admission),
        encoded(&(&full.lifecycle, full.unloaded_observed, &full.unbound_use)),
        encoded(&(
            &full.identity,
            &full.paths,
            &full.admission,
            &full.lifecycle,
            full.unloaded_observed,
            &full.unbound_use,
        )),
    ]
}
fn edge_keys(e: &input::Edge) -> Vec<Vec<u8>> {
    let mut mapping = e.mapping.clone();
    mapping.first_seen_ns = 0;
    mapping.last_seen_ns = 0;
    let mut entries = e.entries.clone();
    entries.first_seen_ns = None;
    entries.last_seen_ns = None;
    let mut coverage = e.coverage.clone();
    if let Some(c) = &mut coverage {
        c.since_ns = None;
        c.first_ns = None;
        c.until_ns = c.until_ns.map(|_| 0);
    }
    vec![
        encoded(&mapping),
        encoded(&entries),
        encoded(&coverage),
        encoded(&e.semantics),
    ]
}
fn ranks(before: &Snapshot, after: &Snapshot) -> (Ranks, Ranks) {
    let keys: Vec<_> = [before, after]
        .into_iter()
        .map(|s| {
            s.callers
                .iter()
                .map(caller_keys)
                .chain(s.modules.iter().map(module_keys))
                .chain(s.edges.iter().map(edge_keys))
                .collect::<Vec<_>>()
        })
        .collect();
    let rank: BTreeMap<&[u8], usize> = keys
        .iter()
        .flatten()
        .flatten()
        .map(Vec::as_slice)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(i, k)| (k, i))
        .collect();
    let mut outputs = Vec::new();
    for (s, keys) in [before, after].into_iter().zip(&keys) {
        let values: Vec<Vec<usize>> = keys
            .iter()
            .map(|row| row.iter().map(|k| rank[k.as_slice()]).collect())
            .collect();
        let callers = values[..s.callers.len()]
            .iter()
            .map(|r| CallerRanks {
                population: r[0],
                lifecycle: r[1],
                full: r[2],
            })
            .collect();
        let modules = values[s.callers.len()..s.callers.len() + s.modules.len()]
            .iter()
            .map(|r| ModuleRanks {
                physical: r[0],
                paths: r[1],
                admission: r[2],
                lifecycle: r[3],
                full: r[4],
            })
            .collect();
        let edges = values[s.callers.len() + s.modules.len()..]
            .iter()
            .map(|r| EdgeRanks {
                mapping: r[0],
                entries: r[1],
                coverage: r[2],
                semantics: r[3],
            })
            .collect();
        outputs.push(Ranks {
            callers,
            modules,
            edges,
        });
    }
    let mut iter = outputs.into_iter();
    (iter.next().unwrap(), iter.next().unwrap())
}
// Normalize-first/full-fact-tie sorting; identical facts reuse a value ref while
// the source-index map and sorted occurrences keep every source row.
fn pool<T: Serialize + Eq, K: Ord>(rows: Vec<T>, keys: Vec<K>) -> (Vec<T>, Vec<usize>) {
    let mut ordered: Vec<_> = rows
        .into_iter()
        .zip(keys)
        .enumerate()
        .map(|(i, (row, key))| {
            let full = encoded(&row);
            (key, full, i, row)
        })
        .collect();
    ordered.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let mut source = vec![0; ordered.len()];
    let mut facts = Vec::new();
    for (_, _, i, row) in ordered {
        if facts.last() != Some(&row) {
            facts.push(row);
        }
        source[i] = facts.len() - 1;
    }
    (facts, source)
}
fn edge_fact(s: &Snapshot, r: &Ranks, i: usize) -> EdgeFact {
    let e = &s.edges[i];
    let v = r.edges[i];
    EdgeFact {
        caller: r.callers[e.caller].full,
        module: r.modules[e.module].full,
        mapping: v.mapping,
        entries: v.entries,
        coverage: v.coverage,
        semantics: v.semantics,
    }
}
fn prepare(s: &Snapshot, r: &Ranks) -> Prepared {
    let callers: Vec<_> = s.callers.iter().map(caller_evidence).collect();
    let caller_order = s
        .callers
        .iter()
        .zip(&r.callers)
        .map(|(c, r)| (c.pid, c.start_time, r.full))
        .collect();
    let (callers, ci) = pool(callers, caller_order);
    let ci: Vec<_> = ci.into_iter().map(CallerRef).collect();
    let modules: Vec<_> = s.modules.iter().map(module_evidence).collect();
    let module_order = modules
        .iter()
        .zip(&r.modules)
        .map(|(m, r)| (m.identity.clone(), r.full))
        .collect();
    let (modules, mi) = pool(modules, module_order);
    let mi: Vec<_> = mi.into_iter().map(ModuleRef).collect();
    let edges: Vec<_> = s
        .edges
        .iter()
        .map(|e| EdgeEvidence {
            caller: ci[e.caller],
            module: mi[e.module],
            mapping: e.mapping.clone(),
            entries: e.entries.clone(),
            coverage: e.coverage.clone(),
            semantics: e.semantics.clone(),
        })
        .collect();
    let edge_order = (0..s.edges.len()).map(|i| edge_fact(s, r, i)).collect();
    let (edges, ei) = pool(edges, edge_order);
    let ei: Vec<_> = ei.into_iter().map(EdgeRef).collect();
    let evidence = SideEvidence {
        callers,
        modules,
        edges,
        caller_occurrences: sorted(ci.clone()),
        module_occurrences: sorted(mi.clone()),
        edge_occurrences: sorted(ei.clone()),
    };
    let mut gaps: Vec<_> = s
        .gaps
        .iter()
        .map(|g| GapEvidence {
            caller: g.caller.map(|i| ci[i]),
            module: g.module.map(|i| mi[i]),
            pid: g.pid,
            subject: g.subject.clone(),
            reason: g.reason.clone(),
            budget: g.budget.clone(),
            repeats: g.repeats,
        })
        .collect();
    sort_full(&mut gaps);
    let mut counters = BTreeMap::from([
        ("callers".into(), Some(s.budgets.callers.refused)),
        ("modules".into(), Some(s.budgets.modules.refused)),
        ("edges".into(), Some(s.budgets.edges.refused)),
        ("endpoints".into(), Some(s.budgets.endpoints.refused)),
        (
            "semantic_state".into(),
            Some(s.budgets.semantic_state.refused),
        ),
    ]);
    counters.insert(
        "inventory_endpoints".into(),
        s.budgets
            .inventory_endpoints
            .as_ref()
            .and_then(|b| b.refused),
    );
    counters.insert(
        "inventory_attach_modules".into(),
        s.budgets
            .inventory_attach_modules
            .as_ref()
            .map(|b| b.refused),
    );
    counters.insert(
        "native_preadmission".into(),
        s.budgets.native_preadmission.as_ref().map(|b| b.refused),
    );
    Prepared {
        summary: SnapshotSummary {
            scope: s.scope.clone(),
            clock: s.clock.clone(),
            observation: s.observation.clone(),
            pid_namespace: s.pid_namespace.clone(),
            scope_completeness: "unknown",
            reported_gaps: s.gaps.len(),
            suppressed_gaps: s.gaps_suppressed,
            refusals: Refusals {
                reported_budget_gaps: s.gaps.iter().filter(|g| g.budget.is_some()).count(),
                budget_counters: counters,
            },
            budgets: s.budgets.clone(),
            loss_evidence: LossEvidence {
                lifecycle: s.observation.lifecycle.clone(),
                native_witnesses: s.observation.native_witnesses.clone(),
            },
            gaps,
            evidence,
        },
        callers: ci,
        modules: mi,
        edges: ei,
    }
}
fn project<'a>(s: &'a Snapshot, paths: &BTreeMap<&str, usize>) -> Projection<'a> {
    let mut p = Projection {
        contents: BTreeMap::new(),
        paths: BTreeMap::new(),
        applications: BTreeMap::new(),
    };
    for (i, m) in s.modules.iter().enumerate() {
        if let Some(digest) = m.sha256.as_deref() {
            p.contents.entry(digest).or_default().push(i);
        }
        for path in &m.paths {
            p.paths
                .entry(path.as_str())
                .or_default()
                .insert(m.sha256.as_deref());
        }
    }
    for (i, e) in s.edges.iter().enumerate() {
        let (Some(path), Some(digest)) = (
            exe_path(&s.callers[e.caller]),
            s.modules[e.module].sha256.as_deref(),
        ) else {
            continue;
        };
        let g = p.applications.entry((paths[path], digest)).or_default();
        g.edges.push(i);
        g.callers.insert(e.caller);
        g.modules.insert(e.module);
    }
    p
}
fn population(g: &Group, p: &Prepared) -> PopulationEvidence {
    PopulationEvidence {
        callers: sorted(g.callers.iter().map(|&i| p.callers[i]).collect()),
        modules: sorted(g.modules.iter().map(|&i| p.modules[i]).collect()),
    }
}
fn module_value(m: ModuleRanks, facet: usize) -> usize {
    match facet {
        0 => m.physical,
        1 => m.paths,
        2 => m.admission,
        _ => m.lifecycle,
    }
}
fn module_values(indexes: &[usize], r: &Ranks, facet: usize) -> Vec<usize> {
    sorted(
        indexes
            .iter()
            .map(|&i| module_value(r.modules[i], facet))
            .collect(),
    )
}
fn module_category_values(
    indexes: &[usize],
    r: &Ranks,
    facet: usize,
    anchored: bool,
) -> Vec<(usize, usize)> {
    sorted(
        indexes
            .iter()
            .map(|&i| {
                let m = r.modules[i];
                (
                    if anchored { m.physical } else { 0 },
                    module_value(m, facet),
                )
            })
            .collect(),
    )
}
fn module_without_category(indexes: &[usize], r: &Ranks, facet: usize) -> Vec<[usize; 4]> {
    sorted(
        indexes
            .iter()
            .map(|&i| {
                let m = r.modules[i];
                let mut key = [m.physical, m.paths, m.admission, m.lifecycle];
                key[facet] = 0;
                key
            })
            .collect(),
    )
}
fn content_changes_for(bi: &[usize], ai: &[usize], br: &Ranks, ar: &Ranks) -> Vec<&'static str> {
    let full_equal = sorted(bi.iter().map(|&i| br.modules[i].full).collect())
        == sorted(ai.iter().map(|&i| ar.modules[i].full).collect());
    if full_equal {
        return Vec::new();
    }
    let mut changes = BTreeSet::new();
    let physical_equal = module_values(bi, br, 0) == module_values(ai, ar, 0);
    if !physical_equal {
        changes.insert("physical_records");
    }
    for (facet, code) in [(1, "paths"), (2, "admission"), (3, "lifecycle")] {
        if module_category_values(bi, br, facet, physical_equal)
            != module_category_values(ai, ar, facet, physical_equal)
            || module_without_category(bi, br, facet) == module_without_category(ai, ar, facet)
        {
            changes.insert(code);
        }
    }
    // Preserve complete module associations even without edges or an equal
    // complement. These reasons describe variation, never paired records.
    if changes.is_empty() {
        for (facet, code) in [(1, "paths"), (2, "admission"), (3, "lifecycle")] {
            let values: BTreeSet<_> = bi
                .iter()
                .map(|&i| module_value(br.modules[i], facet))
                .chain(ai.iter().map(|&i| module_value(ar.modules[i], facet)))
                .collect();
            if values.len() > 1 {
                changes.insert(code);
            }
        }
    }
    changes.into_iter().collect()
}
fn caller_population(g: &Group, r: &Ranks) -> Vec<usize> {
    sorted(g.callers.iter().map(|&i| r.callers[i].population).collect())
}
fn physical_population(g: &Group, r: &Ranks) -> Vec<usize> {
    sorted(g.modules.iter().map(|&i| r.modules[i].physical).collect())
}
fn full_caller_population(g: &Group, r: &Ranks) -> Vec<usize> {
    sorted(g.callers.iter().map(|&i| r.callers[i].full).collect())
}
fn full_module_population(g: &Group, r: &Ranks) -> Vec<usize> {
    sorted(g.modules.iter().map(|&i| r.modules[i].full).collect())
}
fn category(s: &Snapshot, r: &Ranks, i: usize, facet: usize) -> (usize, usize) {
    let e = &s.edges[i];
    let c = r.callers[e.caller];
    let m = r.modules[e.module];
    let v = r.edges[i];
    match facet {
        0 => (m.paths, 0),
        1 => (m.admission, 0),
        2 => (c.lifecycle, m.lifecycle),
        3 => (v.mapping, 0),
        4 => (v.coverage, 0),
        5 => (v.entries, 0),
        _ => (v.semantics, 0),
    }
}
fn category_values(
    s: &Snapshot,
    g: &Group,
    r: &Ranks,
    facet: usize,
    anchored: bool,
) -> Vec<(usize, usize, usize, usize)> {
    sorted(
        g.edges
            .iter()
            .map(|&i| {
                let e = &s.edges[i];
                let value = category(s, r, i, facet);
                (
                    if anchored {
                        r.callers[e.caller].population
                    } else {
                        0
                    },
                    if anchored {
                        r.modules[e.module].physical
                    } else {
                        0
                    },
                    value.0,
                    value.1,
                )
            })
            .collect(),
    )
}
// Removing one category keeps every other association intact. Equal
// complements with unequal full facts identify a category whose conditional
// observations changed, even when all of its marginal values are unchanged.
fn without_category(s: &Snapshot, g: &Group, r: &Ranks, facet: usize) -> Vec<[usize; 10]> {
    sorted(
        g.edges
            .iter()
            .map(|&i| {
                let e = &s.edges[i];
                let c = r.callers[e.caller];
                let m = r.modules[e.module];
                let v = r.edges[i];
                let mut key = [
                    c.population,
                    c.lifecycle,
                    m.physical,
                    m.paths,
                    m.admission,
                    m.lifecycle,
                    v.mapping,
                    v.entries,
                    v.coverage,
                    v.semantics,
                ];
                match facet {
                    0 => key[3] = 0,
                    1 => key[4] = 0,
                    2 => {
                        key[1] = 0;
                        key[5] = 0;
                    }
                    3 => key[6] = 0,
                    4 => key[8] = 0,
                    5 => key[7] = 0,
                    _ => key[9] = 0,
                };
                key
            })
            .collect(),
    )
}
fn application_changes_for(
    b: &Snapshot,
    a: &Snapshot,
    bg: &Group,
    ag: &Group,
    br: &Ranks,
    ar: &Ranks,
) -> Vec<&'static str> {
    if bg.edges.is_empty() || ag.edges.is_empty() {
        return vec!["content_presence"];
    }
    let mut changes = BTreeSet::new();
    let caller_equal = caller_population(bg, br) == caller_population(ag, ar);
    let physical_equal = physical_population(bg, br) == physical_population(ag, ar);
    let caller_facts_equal = full_caller_population(bg, br) == full_caller_population(ag, ar);
    let module_facts_equal = full_module_population(bg, br) == full_module_population(ag, ar);
    if !caller_equal {
        changes.insert("caller_population");
    }
    if !physical_equal {
        changes.insert("physical_records");
    }
    let full_equal = sorted(bg.edges.iter().map(|&i| edge_fact(b, br, i)).collect())
        == sorted(ag.edges.iter().map(|&i| edge_fact(a, ar, i)).collect());
    if !full_equal {
        for (facet, code) in [
            "paths",
            "admission",
            "lifecycle",
            "mapping",
            "coverage",
            "entries",
            "semantics",
        ]
        .into_iter()
        .enumerate()
        {
            if category_values(b, bg, br, facet, caller_equal && physical_equal)
                != category_values(a, ag, ar, facet, caller_equal && physical_equal)
                || without_category(b, bg, br, facet) == without_category(a, ag, ar, facet)
            {
                changes.insert(code);
            }
        }
        // Some joint distributions change without an equal complement or a
        // changed marginal. There is no justified pairing of these records:
        // name their varying categories instead of hiding the full-fact change.
        if changes.is_empty() {
            for (facet, code) in [
                "paths",
                "admission",
                "lifecycle",
                "mapping",
                "coverage",
                "entries",
                "semantics",
            ]
            .into_iter()
            .enumerate()
            {
                let values: BTreeSet<_> = bg
                    .edges
                    .iter()
                    .map(|&i| category(b, br, i, facet))
                    .chain(ag.edges.iter().map(|&i| category(a, ar, i, facet)))
                    .collect();
                if values.len() > 1 {
                    changes.insert(code);
                }
            }
        }
    }
    // Edge fanout can compensate for changed distinct-source composition.
    // Compare complete population facts independently of edge equality, and
    // append source reasons after edge classification so neither hides the other.
    if !caller_facts_equal && caller_equal {
        // The caller description is equal; only its supported lifecycle
        // component can make the complete normalized source facts differ.
        changes.insert("lifecycle");
    }
    if !module_facts_equal && physical_equal {
        let bi: Vec<_> = bg.modules.iter().copied().collect();
        let ai: Vec<_> = ag.modules.iter().copied().collect();
        changes.extend(content_changes_for(&bi, &ai, br, ar));
    }
    changes.into_iter().collect()
}
fn unresolved_rows(s: &Snapshot, p: &Prepared, side: Side) -> Vec<Unresolved> {
    let mut rows = Vec::new();
    let mut referenced = vec![false; s.callers.len()];
    for (i, m) in s.modules.iter().enumerate() {
        if m.sha256.is_none() {
            rows.push(Unresolved {
                side,
                kind: UnresolvedKind::Module,
                reasons: vec!["missing_module_digest"],
                caller: None,
                module: Some(p.modules[i]),
                observation: None,
            });
        }
    }
    for (i, e) in s.edges.iter().enumerate() {
        referenced[e.caller] = true;
        let mut reasons = Vec::new();
        if exe_path(&s.callers[e.caller]).is_none() {
            reasons.push("missing_executable_path");
        }
        if s.modules[e.module].sha256.is_none() {
            reasons.push("missing_module_digest");
        }
        if !reasons.is_empty() {
            rows.push(Unresolved {
                side,
                kind: UnresolvedKind::Edge,
                reasons,
                caller: None,
                module: None,
                observation: Some(p.edges[i]),
            });
        }
    }
    for (i, used) in referenced.into_iter().enumerate() {
        if !used {
            rows.push(Unresolved {
                side,
                kind: UnresolvedKind::Caller,
                reasons: vec!["no_module_observation"],
                caller: Some(p.callers[i]),
                module: None,
                observation: None,
            });
        }
    }
    rows
}
