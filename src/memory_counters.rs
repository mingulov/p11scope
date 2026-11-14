//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Per-structure memory counters (v0.8.0 Phase A0, measure only).
//!
//! Every growing structure reports `len` x approx bytes on the `-v`
//! stderr channel as `p11scope: memory {json}`: one line every 60 s
//! plus one at end of capture. Production behavior, caps, and reports
//! are unchanged; rows a command does not own read `null` (N/A).

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Stderr channel: `-v` only (or `P11SCOPE_CAPTURE_DIAGNOSTICS=1`),
/// one line every [`MEMORY_EMIT_INTERVAL_SECS`] plus one at end of
/// capture. Reports stay byte-identical: nothing here reaches stdout
/// or the `-o` document.
pub(crate) const MEMORY_LINE_PREFIX: &str = "p11scope: memory ";
/// Periodic emit cadence in seconds (Opus residual F1: once per drain
/// would be thousands of lines; the soak sampler is 60 s too).
pub(crate) const MEMORY_EMIT_INTERVAL_SECS: u64 = 60;
const MEMORY_EMIT_INTERVAL: Duration = Duration::from_secs(MEMORY_EMIT_INTERVAL_SECS);

// Per-entry heap factors: preliminary A0 pins from the design's
// round-1 probe notes. The A1 soak cross-checks
// sum(structure bytes) + floor against smaps_rollup Private_Dirty and
// recalibrates these; the residual row reopens the inventory rather
// than absorbing a miss.
//
// `HEAP_MAP_ENTRY` is the amortized B-tree node share for entries
// whose key and value own no heap; entries with `String`/`Vec`/nested
// maps carry their own factor below.
pub(crate) const HEAP_MAP_ENTRY: usize = 64;
/// Admitted caller record: exe identity, launcher chain, app hint.
pub(crate) const HEAP_CALLER_RECORD: usize = 1536;
/// Registry edge record through the production mapping + semantic
/// feed, with a materialized reducer and one observed session:
/// 3561 heap bytes/edge measured over 256 edges (round 4, exceeding
/// the round-1 2304 estimate from a test-only edge without a reducer).
/// Pinned at 3584; the A1 smaps cross-check recalibrates.
pub(crate) const HEAP_EDGE_RECORD: usize = 3584;
/// Registry module record: paths, digests, linkage summaries.
pub(crate) const HEAP_MODULE_RECORD: usize = 1024;
/// Mechanism row shells: op-name set plus combo-map nodes (combos
/// themselves are counted in R7).
pub(crate) const HEAP_MECH_ROW: usize = 320;
/// Template row shells: name list plus attribute-type set nodes.
pub(crate) const HEAP_TEMPLATE_ROW: usize = 160;
/// Discovery history values: module summaries, skip/loss records.
pub(crate) const HEAP_HISTORY_VALUE: usize = 256;
/// Object-model records: views, pending calls, deferred origins.
pub(crate) const HEAP_MODEL_RECORD: usize = 192;
/// Registry key/index strings: module-key paths/digests, gap
/// subject/reason strings.
pub(crate) const HEAP_MODULE_KEY: usize = 192;
/// Deferred-origin records: frozen inputs and pruned-domain memory.
pub(crate) const HEAP_DEFERRED_RECORD: usize = 128;
/// R11 caller key: exe path string plus the inner row-map shell.
pub(crate) const HEAP_R11_CALLER: usize = 192;
/// R11 (function, rv) row: function-name string.
pub(crate) const HEAP_R11_ROW: usize = 96;

/// One counter row: entry count and estimated bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CounterRow {
    pub len: u64,
    pub bytes: u64,
}

/// `len * (entry + heap)`, saturating. `entry_bytes` is the owner's
/// `size_of::<(Key, Value)>()` (or `size_of::<Value>()` for sets);
/// `heap_bytes_per_entry` is one of the `HEAP_*` factors above.
pub(crate) fn counter_row(
    len: usize,
    entry_bytes: usize,
    heap_bytes_per_entry: usize,
) -> CounterRow {
    CounterRow {
        len: len as u64,
        bytes: (len as u64).saturating_mul(entry_bytes.saturating_add(heap_bytes_per_entry) as u64),
    }
}

/// R1 lens: the adapter's caller and incarnation tables, plus the
/// live-pid index (spec §3.1 siblings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterLens {
    pub callers: CounterRow,
    pub incarnations: CounterRow,
    pub live_by_pid: CounterRow,
}

/// R3 lens: per-edge session/operation/mechanism maps, summed over
/// the registry's materialized edges (O(edges), emit path only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EdgeLens {
    pub open: CounterRow,
    pub active: CounterRow,
    pub mechs: CounterRow,
    pub pending: CounterRow,
    pub detached: CounterRow,
}

/// R2 lens: registry caller/module/edge tables plus R3, the key/gap
/// sibling indexes, and the shared semantic-pool charge against the
/// 160 MiB pool. Minor 2: this is the WHOLE pool (custody pins, joint
/// grants, instance input, and mechanism cells all charge it), not
/// mechanism cells alone — the name stays for wire stability, the
/// meaning is documented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryLens {
    pub callers: CounterRow,
    pub retired: CounterRow,
    pub modules: CounterRow,
    pub edges: CounterRow,
    pub modules_by_key: CounterRow,
    pub gap_index: CounterRow,
    pub edge: EdgeLens,
    pub mech_pool_used_bytes: u64,
}

/// R4 lens: the object model's session/object/pending tables, the
/// domain/instance maps, the deferred-origin tables, the
/// pruned-domain memory, and the gap counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelLens {
    pub sessions: CounterRow,
    pub objects: CounterRow,
    pub pending: CounterRow,
    pub pruned_sessions: u64,
    pub pruned_objects: u64,
    pub domains: CounterRow,
    pub instances: CounterRow,
    pub deferred_pending: CounterRow,
    pub deferred_detached: CounterRow,
    pub deferred_releases: CounterRow,
    pub recently_pruned: CounterRow,
    pub gaps: CounterRow,
}

/// R6 rows: every `CaptureHistory` per-ever set. No set is skipped:
/// an omitted set would hide growth the soak must attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HistoryRows {
    pub modules: CounterRow,
    pub decoded: CounterRow,
    pub surfaces: CounterRow,
    pub tables: CounterRow,
    pub skips: CounterRow,
    pub losses: CounterRow,
    pub refusals: CounterRow,
    pub fallbacks: CounterRow,
    pub recorroborated: CounterRow,
    pub conflicted: CounterRow,
    pub scan_gap_tombstones: CounterRow,
    pub corroboration_tombstones: CounterRow,
    pub fallback_tombstones: CounterRow,
    pub selection_inventory: CounterRow,
    pub selection_surfaces: CounterRow,
    pub manifest_selection_ordinals: CounterRow,
    pub selections: CounterRow,
    pub standard_exports: CounterRow,
}

/// R6 lens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistoryLens {
    pub rows: HistoryRows,
}

/// R7/R8/R10/R12 lens over `semantics::State`. The tail totals
/// (`param_combos`, `attr_types`) sum per-row lens: O(rows) on the
/// emit path, never on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateLens {
    pub param_combos: CounterRow,
    pub attr_types: CounterRow,
    pub by_module: CounterRow,
    pub cgroup_mechanisms: CounterRow,
    pub cgroup_retained_paths: CounterRow,
    pub mechanisms: CounterRow,
    pub templates: CounterRow,
    pub logins: CounterRow,
    pub cgroups: CounterRow,
    pub mech_shapes: CounterRow,
    pub reduced: CounterRow,
    pub open: CounterRow,
    pub active_ops: CounterRow,
    pub next_pseudonym: CounterRow,
    pub find_active: CounterRow,
    pub pending: CounterRow,
    pub detached: CounterRow,
    pub inherited_ambiguous: CounterRow,
}

/// Dead-owned ROW counts per R10/R12 map (Blocker 2): rows whose
/// owning process is gone but whose state is retained — the number
/// B1 exit routing would free. Bytes reuse the same entry + heap
/// factors as the totals above. Built from one live-pid set per
/// 60 s pass (see `semantics::State::memory_sample`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateDeadLens {
    pub reduced_dead: CounterRow,
    pub open_dead: CounterRow,
    pub active_ops_dead: CounterRow,
    pub next_pseudonym_dead: CounterRow,
    pub find_active_dead: CounterRow,
    pub pending_dead: CounterRow,
    pub detached_dead: CounterRow,
    pub inherited_ambiguous_dead: CounterRow,
}

/// R11 lens: the trace `CallerReasons` sizes, read only through the
/// size accessors B0 adds (`trace.rs`: `caller_entries`, `row_entries`,
/// `overflowed`, `folded_lines`, `folded_rows`). Entry shapes mirror
/// B0's private aliases (`CallerKey = (u32, Option<String>)`,
/// `FunctionRv = (String, u64)`); A0 never touches `trace.rs`
/// internals (spec §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TracerLens {
    pub outer: CounterRow,
    pub rows: CounterRow,
    pub overflowed: bool,
    pub folded_lines: u64,
    pub folded_rows: u64,
}

impl TracerLens {
    pub(crate) fn from_sizes(
        outer: usize,
        rows: usize,
        overflowed: bool,
        folded_lines: u64,
        folded_rows: usize,
    ) -> Self {
        // Minor 5: entry sizes include the map VALUES, not just the
        // keys — the outer value is the inner row-map shell (BTreeMap,
        // 24 B) and each row value is its u64 count (8 B).
        Self {
            outer: counter_row(
                outer,
                std::mem::size_of::<(u32, Option<String>)>()
                    .saturating_add(std::mem::size_of::<BTreeMap<(String, u64), u64>>()),
                HEAP_R11_CALLER,
            ),
            rows: counter_row(
                rows,
                std::mem::size_of::<((String, u64), u64)>(),
                HEAP_R11_ROW,
            ),
            overflowed,
            folded_lines,
            folded_rows: folded_rows as u64,
        }
    }
}

/// Profile/trace capture lens: engine history, semantic state
/// totals, the dead-owned ROW split from one live-pid set, the
/// live/dead process counts over R10+R12 owners, the sample cost,
/// the pre-sample RSS/HWM, history tasks, and the capture-start RSS
/// baseline for the floor row. The RSS is read BEFORE the sample is
/// built (Important 3), so the sample's own allocations never skew
/// the line it reports on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileLens {
    pub history: HistoryLens,
    pub state: StateLens,
    pub dead: StateDeadLens,
    pub live_processes: u64,
    pub dead_processes: u64,
    pub sample_us: u64,
    pub self_rss_kb: Option<u64>,
    pub self_hwm_kb: Option<u64>,
    pub tasks: CounterRow,
    pub baseline_rss_kb: Option<u64>,
}

/// Inventory capture lens: adapter, registry (+R3), history, object
/// model, the metadata frame row count if the lane is active, and the
/// capture-start RSS baseline for the floor row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryLens {
    pub adapter: AdapterLens,
    pub registry: RegistryLens,
    pub history: HistoryLens,
    pub model: ModelLens,
    pub metadata_rows: Option<CounterRow>,
    pub baseline_rss_kb: Option<u64>,
}

/// One capture's memory snapshot. `None` rows are N/A: the command
/// owns no such structure. Field order is the JSON key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemorySnapshot {
    command: String,
    elapsed_secs: u64,
    r1_adapter_callers: Option<CounterRow>,
    r1_adapter_incarnations: Option<CounterRow>,
    r1_adapter_live_by_pid: Option<CounterRow>,
    r2_registry_callers: Option<CounterRow>,
    r2_registry_retired: Option<CounterRow>,
    r2_registry_modules: Option<CounterRow>,
    r2_registry_edges: Option<CounterRow>,
    r2_modules_by_key: Option<CounterRow>,
    r2_gap_index: Option<CounterRow>,
    r3_edge_open: Option<CounterRow>,
    r3_edge_active: Option<CounterRow>,
    r3_edge_mechs: Option<CounterRow>,
    r3_edge_pending: Option<CounterRow>,
    r3_edge_detached: Option<CounterRow>,
    r3_mech_pool_bytes: Option<u64>,
    r3_mech_pool_used_bytes: Option<u64>,
    r4_model_sessions: Option<CounterRow>,
    r4_model_objects: Option<CounterRow>,
    r4_model_pending: Option<CounterRow>,
    r4_pruned_sessions: Option<u64>,
    r4_pruned_objects: Option<u64>,
    r4_domains: Option<CounterRow>,
    r4_instances: Option<CounterRow>,
    r4_deferred_pending: Option<CounterRow>,
    r4_deferred_detached: Option<CounterRow>,
    r4_deferred_releases: Option<CounterRow>,
    r4_recently_pruned: Option<CounterRow>,
    r4_gaps: Option<CounterRow>,
    r5_seal_value_bytes: Option<u64>,
    r6: Option<HistoryRows>,
    r7_param_combos: Option<CounterRow>,
    r7_attr_types: Option<CounterRow>,
    r7_by_module: Option<CounterRow>,
    r7_cgroup_mechanisms: Option<CounterRow>,
    r7_cgroup_retained_paths: Option<CounterRow>,
    r8_mechanisms: Option<CounterRow>,
    r8_templates: Option<CounterRow>,
    r8_logins: Option<CounterRow>,
    r8_cgroups: Option<CounterRow>,
    r8_mech_shapes: Option<CounterRow>,
    r9_tasks: Option<CounterRow>,
    r10_reduced: Option<CounterRow>,
    r11_caller_reasons_outer: Option<CounterRow>,
    r11_caller_reasons_rows: Option<CounterRow>,
    r11_overflowed: bool,
    r11_folded_lines: u64,
    r11_folded_rows: u64,
    r12_open: Option<CounterRow>,
    r12_active_ops: Option<CounterRow>,
    r12_next_pseudonym: Option<CounterRow>,
    r12_find_active: Option<CounterRow>,
    r12_pending: Option<CounterRow>,
    r12_detached: Option<CounterRow>,
    r12_inherited_ambiguous: Option<CounterRow>,
    r10_r12_live_processes: Option<u64>,
    r10_r12_dead_processes: Option<u64>,
    r10_reduced_dead: Option<CounterRow>,
    r12_open_dead: Option<CounterRow>,
    r12_active_ops_dead: Option<CounterRow>,
    r12_next_pseudonym_dead: Option<CounterRow>,
    r12_find_active_dead: Option<CounterRow>,
    r12_pending_dead: Option<CounterRow>,
    r12_detached_dead: Option<CounterRow>,
    r12_inherited_ambiguous_dead: Option<CounterRow>,
    sample_us: Option<u64>,
    caller_metadata_rows: Option<CounterRow>,
    floor_discovery_baseline_kb: Option<u64>,
    floor_staging_bytes: u64,
    floor_ring_bytes: u64,
    self_rss_kb: Option<u64>,
    self_hwm_kb: Option<u64>,
}

impl MemorySnapshot {
    /// The stderr line: prefix plus compact JSON, no trailing newline
    /// (the sink adds it).
    pub(crate) fn format_line(&self) -> String {
        format!(
            "{MEMORY_LINE_PREFIX}{}",
            serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
        )
    }

    /// The A0 step-4 parser twin: parses exactly what [`format_line`]
    /// emits, and nothing else. Test-only: production formats lines,
    /// the soak sampler parses them externally.
    #[cfg(test)]
    pub(crate) fn parse_line(line: &str) -> Option<Self> {
        let json = line.strip_prefix(MEMORY_LINE_PREFIX)?;
        if json.is_empty() {
            return None;
        }
        serde_json::from_str(json).ok()
    }

    fn floor_staging_ring(ring_bytes: u32) -> (u64, u64) {
        (crate::events::EVENTS_STAGE_BYTES as u64, ring_bytes as u64)
    }

    /// Profile snapshot: R5 (seal only), R6-R10, R12, floor.
    /// R1-R4, R11 and metadata are N/A on this path. The lens carries
    /// the pre-sample RSS and the one-pass live/dead + dead-row split
    /// (see `capture_memory_lens`); the snapshot copies, never probes.
    pub(crate) fn for_profile(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
    ) -> Self {
        Self::for_event_capture(
            "profile",
            elapsed_secs,
            lens,
            ring_bytes,
            seal_value_bytes,
            None,
        )
    }

    /// Trace snapshot: like profile, but R5 is always N/A (the trace
    /// path streams lines; it seals no `Value` tree) and R11 rides the
    /// B0 accessors through `tracer` (trace only).
    pub(crate) fn for_trace(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
        tracer: &TracerLens,
    ) -> Self {
        Self::for_event_capture(
            "trace",
            elapsed_secs,
            lens,
            ring_bytes,
            seal_value_bytes,
            Some(tracer),
        )
    }

    fn for_event_capture(
        command: &str,
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
        r11: Option<&TracerLens>,
    ) -> Self {
        let (staging, ring) = Self::floor_staging_ring(ring_bytes);
        let state = lens.state;
        let dead = lens.dead;
        Self {
            command: command.to_string(),
            elapsed_secs,
            r1_adapter_callers: None,
            r1_adapter_incarnations: None,
            r1_adapter_live_by_pid: None,
            r2_registry_callers: None,
            r2_registry_retired: None,
            r2_registry_modules: None,
            r2_registry_edges: None,
            r2_modules_by_key: None,
            r2_gap_index: None,
            r3_edge_open: None,
            r3_edge_active: None,
            r3_edge_mechs: None,
            r3_edge_pending: None,
            r3_edge_detached: None,
            r3_mech_pool_bytes: None,
            r3_mech_pool_used_bytes: None,
            r4_model_sessions: None,
            r4_model_objects: None,
            r4_model_pending: None,
            r4_pruned_sessions: None,
            r4_pruned_objects: None,
            r4_domains: None,
            r4_instances: None,
            r4_deferred_pending: None,
            r4_deferred_detached: None,
            r4_deferred_releases: None,
            r4_recently_pruned: None,
            r4_gaps: None,
            r5_seal_value_bytes: seal_value_bytes,
            r6: Some(lens.history.rows),
            r7_param_combos: Some(state.param_combos),
            r7_attr_types: Some(state.attr_types),
            r7_by_module: Some(state.by_module),
            r7_cgroup_mechanisms: Some(state.cgroup_mechanisms),
            r7_cgroup_retained_paths: Some(state.cgroup_retained_paths),
            r8_mechanisms: Some(state.mechanisms),
            r8_templates: Some(state.templates),
            r8_logins: Some(state.logins),
            r8_cgroups: Some(state.cgroups),
            r8_mech_shapes: Some(state.mech_shapes),
            r9_tasks: Some(lens.tasks),
            r10_reduced: Some(state.reduced),
            r11_caller_reasons_outer: r11.map(|t| t.outer),
            r11_caller_reasons_rows: r11.map(|t| t.rows),
            r11_overflowed: r11.is_some_and(|t| t.overflowed),
            r11_folded_lines: r11.map_or(0, |t| t.folded_lines),
            r11_folded_rows: r11.map_or(0, |t| t.folded_rows),
            r12_open: Some(state.open),
            r12_active_ops: Some(state.active_ops),
            r12_next_pseudonym: Some(state.next_pseudonym),
            r12_find_active: Some(state.find_active),
            r12_pending: Some(state.pending),
            r12_detached: Some(state.detached),
            r12_inherited_ambiguous: Some(state.inherited_ambiguous),
            r10_r12_live_processes: Some(lens.live_processes),
            r10_r12_dead_processes: Some(lens.dead_processes),
            r10_reduced_dead: Some(dead.reduced_dead),
            r12_open_dead: Some(dead.open_dead),
            r12_active_ops_dead: Some(dead.active_ops_dead),
            r12_next_pseudonym_dead: Some(dead.next_pseudonym_dead),
            r12_find_active_dead: Some(dead.find_active_dead),
            r12_pending_dead: Some(dead.pending_dead),
            r12_detached_dead: Some(dead.detached_dead),
            r12_inherited_ambiguous_dead: Some(dead.inherited_ambiguous_dead),
            sample_us: Some(lens.sample_us),
            caller_metadata_rows: None,
            floor_discovery_baseline_kb: lens.baseline_rss_kb,
            floor_staging_bytes: staging,
            floor_ring_bytes: ring,
            self_rss_kb: lens.self_rss_kb,
            self_hwm_kb: lens.self_hwm_kb,
        }
    }

    /// Inventory snapshot: R1-R4, R6, metadata, floor.
    /// R5, R7-R12 are N/A on this path.
    pub(crate) fn for_inventory(elapsed_secs: u64, lens: InventoryLens, ring_bytes: u32) -> Self {
        let (staging, ring) = Self::floor_staging_ring(ring_bytes);
        let (rss, hwm) = self_rss_hwm_kb().unzip();
        Self {
            command: "inventory".to_string(),
            elapsed_secs,
            r1_adapter_callers: Some(lens.adapter.callers),
            r1_adapter_incarnations: Some(lens.adapter.incarnations),
            r1_adapter_live_by_pid: Some(lens.adapter.live_by_pid),
            r2_registry_callers: Some(lens.registry.callers),
            r2_registry_retired: Some(lens.registry.retired),
            r2_registry_modules: Some(lens.registry.modules),
            r2_registry_edges: Some(lens.registry.edges),
            r2_modules_by_key: Some(lens.registry.modules_by_key),
            r2_gap_index: Some(lens.registry.gap_index),
            r3_edge_open: Some(lens.registry.edge.open),
            r3_edge_active: Some(lens.registry.edge.active),
            r3_edge_mechs: Some(lens.registry.edge.mechs),
            r3_edge_pending: Some(lens.registry.edge.pending),
            r3_edge_detached: Some(lens.registry.edge.detached),
            r3_mech_pool_bytes: Some(
                crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT as u64,
            ),
            r3_mech_pool_used_bytes: Some(lens.registry.mech_pool_used_bytes),
            r4_model_sessions: Some(lens.model.sessions),
            r4_model_objects: Some(lens.model.objects),
            r4_model_pending: Some(lens.model.pending),
            r4_pruned_sessions: Some(lens.model.pruned_sessions),
            r4_pruned_objects: Some(lens.model.pruned_objects),
            r4_domains: Some(lens.model.domains),
            r4_instances: Some(lens.model.instances),
            r4_deferred_pending: Some(lens.model.deferred_pending),
            r4_deferred_detached: Some(lens.model.deferred_detached),
            r4_deferred_releases: Some(lens.model.deferred_releases),
            r4_recently_pruned: Some(lens.model.recently_pruned),
            r4_gaps: Some(lens.model.gaps),
            r5_seal_value_bytes: None,
            r6: Some(lens.history.rows),
            r7_param_combos: None,
            r7_attr_types: None,
            r7_by_module: None,
            r7_cgroup_mechanisms: None,
            r7_cgroup_retained_paths: None,
            r8_mechanisms: None,
            r8_templates: None,
            r8_logins: None,
            r8_cgroups: None,
            r8_mech_shapes: None,
            r9_tasks: None,
            r10_reduced: None,
            r11_caller_reasons_outer: None,
            r11_caller_reasons_rows: None,
            r11_overflowed: false,
            r11_folded_lines: 0,
            r11_folded_rows: 0,
            r12_open: None,
            r12_active_ops: None,
            r12_next_pseudonym: None,
            r12_find_active: None,
            r12_pending: None,
            r12_detached: None,
            r12_inherited_ambiguous: None,
            r10_r12_live_processes: None,
            r10_r12_dead_processes: None,
            r10_reduced_dead: None,
            r12_open_dead: None,
            r12_active_ops_dead: None,
            r12_next_pseudonym_dead: None,
            r12_find_active_dead: None,
            r12_pending_dead: None,
            r12_detached_dead: None,
            r12_inherited_ambiguous_dead: None,
            sample_us: None,
            caller_metadata_rows: lens.metadata_rows,
            floor_discovery_baseline_kb: lens.baseline_rss_kb,
            floor_staging_bytes: staging,
            floor_ring_bytes: ring,
            self_rss_kb: rss,
            self_hwm_kb: hwm,
        }
    }
}

/// Emit cadence: first line at 60 s, then every 60 s; the end line is
/// emitted unconditionally by the caller. O(1); the snapshot it gates
/// does the O(structures)/sampled work.
#[derive(Debug)]
pub(crate) struct MemoryCadence {
    start: Instant,
    last_emit: Option<Instant>,
    interval: Duration,
}

impl MemoryCadence {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            last_emit: None,
            interval: MEMORY_EMIT_INTERVAL,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_interval_for_test(start: Instant, interval: Duration) -> Self {
        Self {
            start,
            last_emit: None,
            interval,
        }
    }

    pub(crate) fn due(&self, now: Instant) -> bool {
        now.duration_since(self.start) >= self.interval
            && self
                .last_emit
                .is_none_or(|last| now.duration_since(last) >= self.interval)
    }

    pub(crate) fn mark(&mut self, now: Instant) {
        self.last_emit = Some(now);
    }

    pub(crate) fn elapsed_secs(&self, now: Instant) -> u64 {
        now.duration_since(self.start).as_secs()
    }
}

/// Split distinct pids into live vs dead by the probe. The caller
/// collects pids straight into a `BTreeSet<u32>` (no intermediate
/// `Vec<ProcessKey>`); several R10/R12 rows (or generations) may name
/// one pid. PID reuse undercounts dead processes (a recycled pid
/// reads live); the B1 exit routing replaces this sample with an
/// incremental split and keeps it as the cross-check. Test-only: the
/// production sample (`semantics::State::memory_sample`) builds its
/// live set inline to reuse it for the dead-row counts.
#[cfg(test)]
pub(crate) fn split_live_dead(pids: &BTreeSet<u32>, probe: &dyn Fn(u32) -> bool) -> (u64, u64) {
    let mut live = 0u64;
    let mut dead = 0u64;
    for pid in pids {
        if probe(*pid) {
            live += 1;
        } else {
            dead += 1;
        }
    }
    (live, dead)
}

/// Best-effort /proc presence probe for the R12 sample.
pub(crate) fn proc_pid_live(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// The capture-start RSS baseline for the floor row, read only when
/// diagnostics are on (Minor 1): the off path pays no
/// `/proc/self/status` read. Bool-gated (like
/// `seal_value_bytes_if_diagnostics`), never env-toggled in tests.
pub(crate) fn baseline_rss_if_diagnostics(on: bool) -> Option<u64> {
    if on {
        self_rss_hwm_kb().map(|(rss, _)| rss)
    } else {
        None
    }
}

/// The observer's own VmRSS/VmHWM in KiB, for the attribution table's
/// floor/residual cross-check. `None` when `/proc/self/status` is
/// unreadable (never fatal: the counters stand alone).
pub(crate) fn self_rss_hwm_kb() -> Option<(u64, u64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = None;
    let mut hwm = None;
    for line in status.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "VmRSS" => rss = Some(value),
            "VmHWM" => hwm = Some(value),
            _ => {}
        }
    }
    Some((rss?, hwm?))
}

/// R5 estimate: heap bytes of one report section `Value` (envelope or
/// largest section). One node counts `size_of::<Value>()`, strings
/// count their bytes, and map entries carry a node-share allowance. A
/// documented approximation, pinned by the twin below; the seal reports
/// envelope + largest section, never the whole tree. The stdout rescue
/// holds one full compact buffer on top (see
/// `fallback_streamed_report_to_stdout`); R5 pins the healthy bound.
pub(crate) fn json_value_bytes(value: &serde_json::Value) -> u64 {
    const NODE: u64 = 32;
    debug_assert_eq!(NODE as usize, std::mem::size_of::<serde_json::Value>());
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => NODE,
        serde_json::Value::String(s) => NODE + s.len() as u64,
        serde_json::Value::Array(items) => {
            NODE + items.iter().map(|v| 32 + json_value_bytes(v)).sum::<u64>()
        }
        serde_json::Value::Object(map) => {
            NODE + map
                .iter()
                .map(|(k, v)| 64 + k.len() as u64 + json_value_bytes(v))
                .sum::<u64>()
        }
    }
}

/// Emit one snapshot line on stderr (best-effort, like every capture
/// diagnostic: a closed stderr never fails the capture).
pub(crate) fn emit_line(snapshot: &MemorySnapshot) {
    let _ = crate::sink::try_stderr_line(&snapshot.format_line());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(len: u64) -> CounterRow {
        CounterRow {
            len,
            bytes: len * 64,
        }
    }

    fn full_history() -> HistoryLens {
        HistoryLens {
            rows: HistoryRows {
                modules: row(1),
                decoded: row(2),
                surfaces: row(3),
                tables: row(4),
                skips: row(5),
                losses: row(6),
                refusals: row(7),
                fallbacks: row(8),
                recorroborated: row(9),
                conflicted: row(10),
                scan_gap_tombstones: row(11),
                corroboration_tombstones: row(12),
                fallback_tombstones: row(13),
                selection_inventory: row(14),
                selection_surfaces: row(15),
                manifest_selection_ordinals: row(16),
                selections: row(17),
                standard_exports: row(18),
            },
        }
    }

    fn full_state() -> StateLens {
        StateLens {
            param_combos: row(1),
            attr_types: row(2),
            by_module: row(16),
            cgroup_mechanisms: row(17),
            cgroup_retained_paths: row(18),
            mechanisms: row(3),
            templates: row(4),
            logins: row(5),
            cgroups: row(6),
            mech_shapes: row(7),
            reduced: row(8),
            open: row(9),
            active_ops: row(10),
            next_pseudonym: row(11),
            find_active: row(12),
            pending: row(13),
            detached: row(14),
            inherited_ambiguous: row(15),
        }
    }

    fn full_dead() -> StateDeadLens {
        StateDeadLens {
            reduced_dead: row(19),
            open_dead: row(20),
            active_ops_dead: row(21),
            next_pseudonym_dead: row(22),
            find_active_dead: row(23),
            pending_dead: row(24),
            detached_dead: row(25),
            inherited_ambiguous_dead: row(26),
        }
    }

    fn full_profile_lens() -> ProfileLens {
        ProfileLens {
            history: full_history(),
            state: full_state(),
            dead: full_dead(),
            live_processes: 1,
            dead_processes: 1,
            sample_us: 123,
            self_rss_kb: Some(1111),
            self_hwm_kb: Some(2222),
            tasks: row(3),
            baseline_rss_kb: Some(4321),
        }
    }

    fn full_inventory_lens() -> InventoryLens {
        InventoryLens {
            adapter: AdapterLens {
                callers: row(1),
                incarnations: row(2),
                live_by_pid: row(3),
            },
            registry: RegistryLens {
                callers: row(3),
                retired: row(4),
                modules: row(5),
                edges: row(6),
                modules_by_key: row(7),
                gap_index: row(8),
                edge: EdgeLens {
                    open: row(7),
                    active: row(8),
                    mechs: row(9),
                    pending: row(10),
                    detached: row(11),
                },
                mech_pool_used_bytes: 999,
            },
            history: full_history(),
            model: ModelLens {
                sessions: row(11),
                objects: row(12),
                pending: row(13),
                pruned_sessions: 14,
                pruned_objects: 15,
                domains: row(17),
                instances: row(18),
                deferred_pending: row(19),
                deferred_detached: row(20),
                deferred_releases: row(21),
                recently_pruned: row(22),
                gaps: row(23),
            },
            metadata_rows: Some(row(16)),
            baseline_rss_kb: Some(4321),
        }
    }

    /// A0 step 1 (corrected per command): the snapshot carries every
    /// owned grower row, and rows the command does not own read N/A.
    #[test]
    fn memory_counters_cover_every_grower() {
        let profile =
            MemorySnapshot::for_profile(60, full_profile_lens(), 32 * 1024 * 1024, Some(100));
        assert_eq!(profile.command, "profile");
        // Owned: R5-R10 + R12 + floor.
        assert_eq!(profile.r5_seal_value_bytes, Some(100));
        let r6 = profile.r6.as_ref().expect("profile owns R6");
        assert_eq!(r6.modules.len, 1);
        assert_eq!(r6.fallback_tombstones.len, 13);
        assert_eq!(profile.r7_param_combos.expect("R7").len, 1);
        assert_eq!(profile.r8_mech_shapes.expect("R8").len, 7);
        assert_eq!(profile.r9_tasks.expect("R9").len, 3);
        assert_eq!(profile.r10_reduced.expect("R10").len, 8);
        assert_eq!(profile.r12_open.expect("R12").len, 9);
        assert_eq!(profile.r12_inherited_ambiguous.expect("R12").len, 15);
        assert_eq!(profile.r10_r12_live_processes, Some(1));
        assert_eq!(profile.r10_r12_dead_processes, Some(1));
        assert_eq!(profile.r10_reduced_dead.expect("R10 dead").len, 19);
        assert_eq!(profile.r12_open_dead.expect("R12 dead").len, 20);
        assert_eq!(
            profile.r12_inherited_ambiguous_dead.expect("R12 dead").len,
            26
        );
        assert_eq!(profile.sample_us, Some(123));
        assert_eq!(profile.self_rss_kb, Some(1111));
        assert_eq!(profile.self_hwm_kb, Some(2222));
        assert_eq!(profile.floor_staging_bytes, 48 * 1024 * 1024);
        assert_eq!(profile.floor_ring_bytes, 32 * 1024 * 1024);
        // Not owned: R1-R4, R11, metadata.
        assert!(profile.r1_adapter_callers.is_none());
        assert!(profile.r1_adapter_incarnations.is_none());
        assert!(profile.r2_registry_callers.is_none());
        assert!(profile.r2_registry_retired.is_none());
        assert!(profile.r2_registry_modules.is_none());
        assert!(profile.r2_registry_edges.is_none());
        assert!(profile.r3_edge_open.is_none());
        assert!(profile.r3_edge_active.is_none());
        assert!(profile.r3_edge_mechs.is_none());
        assert!(profile.r3_edge_pending.is_none());
        assert!(profile.r4_model_sessions.is_none());
        assert!(profile.r4_model_objects.is_none());
        assert!(profile.r4_model_pending.is_none());
        assert!(profile.r11_caller_reasons_outer.is_none());
        assert!(profile.r11_caller_reasons_rows.is_none());
        assert!(!profile.r11_overflowed);
        assert_eq!(profile.r11_folded_lines, 0);
        assert_eq!(profile.r11_folded_rows, 0);
        assert!(profile.caller_metadata_rows.is_none());
        // Full §3.1 list (round 2): N/A rows for structures the
        // profile path does not own, owned rows present.
        assert!(profile.r1_adapter_live_by_pid.is_none());
        assert!(profile.r2_modules_by_key.is_none());
        assert!(profile.r2_gap_index.is_none());
        assert!(profile.r3_edge_detached.is_none());
        assert_eq!(profile.r3_mech_pool_bytes, None);
        assert_eq!(profile.r3_mech_pool_used_bytes, None);
        assert!(profile.r4_domains.is_none());
        assert!(profile.r4_instances.is_none());
        assert!(profile.r4_deferred_pending.is_none());
        assert!(profile.r4_deferred_detached.is_none());
        assert!(profile.r4_deferred_releases.is_none());
        assert!(profile.r4_recently_pruned.is_none());
        assert!(profile.r4_gaps.is_none());
        assert_eq!(r6.selection_inventory.len, 14);
        assert_eq!(r6.selection_surfaces.len, 15);
        assert_eq!(r6.manifest_selection_ordinals.len, 16);
        assert_eq!(r6.selections.len, 17);
        assert_eq!(r6.standard_exports.len, 18);
        assert_eq!(profile.r7_by_module.expect("R7").len, 16);
        assert_eq!(profile.r7_cgroup_mechanisms.expect("R7").len, 17);
        assert_eq!(profile.r7_cgroup_retained_paths.expect("R7").len, 18);
        assert_eq!(profile.floor_discovery_baseline_kb, Some(4321));

        let trace = MemorySnapshot::for_trace(
            60,
            full_profile_lens(),
            32 * 1024 * 1024,
            None,
            &TracerLens::from_sizes(2, 5, true, 7, 3),
        );
        assert_eq!(trace.command, "trace");
        assert_eq!(trace.r9_tasks.expect("trace owns R9").len, 3);
        assert_eq!(trace.r10_r12_live_processes, Some(1));
        assert_eq!(trace.r10_r12_dead_processes, Some(1));
        assert_eq!(trace.r3_mech_pool_bytes, None);
        // R11 rides B0's accessors (round 2): no pending hook remains.
        assert_eq!(trace.r11_caller_reasons_outer.expect("R11").len, 2);
        assert_eq!(trace.r11_caller_reasons_rows.expect("R11").len, 5);
        assert!(trace.r11_overflowed);
        assert_eq!(trace.r11_folded_lines, 7);
        assert_eq!(trace.r11_folded_rows, 3);

        let inventory = MemorySnapshot::for_inventory(60, full_inventory_lens(), 32 * 1024 * 1024);
        assert_eq!(inventory.command, "inventory");
        // Owned: R1-R4 + R6 + metadata.
        assert_eq!(inventory.r1_adapter_callers.expect("R1").len, 1);
        assert_eq!(inventory.r1_adapter_incarnations.expect("R1").len, 2);
        assert_eq!(inventory.r2_registry_edges.expect("R2").len, 6);
        assert_eq!(inventory.r3_edge_pending.expect("R3").len, 10);
        assert_eq!(inventory.r3_mech_pool_bytes, Some(160 * 1024 * 1024));
        assert_eq!(inventory.r4_model_pending.expect("R4").len, 13);
        assert_eq!(inventory.r4_pruned_sessions, Some(14));
        assert_eq!(inventory.r4_pruned_objects, Some(15));
        assert_eq!(inventory.r1_adapter_live_by_pid.expect("R1").len, 3);
        assert_eq!(inventory.r2_modules_by_key.expect("R2").len, 7);
        assert_eq!(inventory.r2_gap_index.expect("R2").len, 8);
        assert_eq!(inventory.r3_edge_detached.expect("R3").len, 11);
        assert_eq!(inventory.r3_mech_pool_used_bytes, Some(999));
        assert_eq!(inventory.r4_domains.expect("R4").len, 17);
        assert_eq!(inventory.r4_instances.expect("R4").len, 18);
        assert_eq!(inventory.r4_deferred_pending.expect("R4").len, 19);
        assert_eq!(inventory.r4_deferred_detached.expect("R4").len, 20);
        assert_eq!(inventory.r4_deferred_releases.expect("R4").len, 21);
        assert_eq!(inventory.r4_recently_pruned.expect("R4").len, 22);
        assert_eq!(inventory.r4_gaps.expect("R4").len, 23);
        assert!(inventory.r6.is_some());
        assert_eq!(
            inventory.r6.as_ref().expect("R6").selection_inventory.len,
            14
        );
        assert_eq!(inventory.caller_metadata_rows.expect("metadata").len, 16);
        assert_eq!(inventory.r11_folded_lines, 0);
        assert_eq!(inventory.r11_folded_rows, 0);
        assert_eq!(inventory.floor_discovery_baseline_kb, Some(4321));
        // Not owned: R5, R7-R12.
        assert!(inventory.r5_seal_value_bytes.is_none());
        assert!(inventory.r7_param_combos.is_none());
        assert!(inventory.r7_attr_types.is_none());
        assert!(inventory.r7_by_module.is_none());
        assert!(inventory.r7_cgroup_mechanisms.is_none());
        assert!(inventory.r7_cgroup_retained_paths.is_none());
        assert!(inventory.r8_mechanisms.is_none());
        assert!(inventory.r8_templates.is_none());
        assert!(inventory.r8_logins.is_none());
        assert!(inventory.r8_cgroups.is_none());
        assert!(inventory.r8_mech_shapes.is_none());
        assert!(inventory.r9_tasks.is_none());
        assert!(inventory.r10_reduced.is_none());
        assert!(inventory.r11_caller_reasons_outer.is_none());
        assert!(inventory.r11_caller_reasons_rows.is_none());
        assert!(!inventory.r11_overflowed);
        assert!(inventory.r12_open.is_none());
        assert!(inventory.r12_active_ops.is_none());
        assert!(inventory.r12_next_pseudonym.is_none());
        assert!(inventory.r12_find_active.is_none());
        assert!(inventory.r12_pending.is_none());
        assert!(inventory.r12_detached.is_none());
        assert!(inventory.r12_inherited_ambiguous.is_none());
        assert!(inventory.r10_r12_live_processes.is_none());
        assert!(inventory.r10_r12_dead_processes.is_none());
        assert!(inventory.r10_reduced_dead.is_none());
        assert!(inventory.r12_open_dead.is_none());
        assert!(inventory.r12_next_pseudonym_dead.is_none());
        assert!(inventory.sample_us.is_none());
    }

    /// A0 step 4 (corrected): the stderr line parses back to the same
    /// snapshot it was formatted from.
    #[test]
    fn memory_line_roundtrip_matches_snapshot() {
        for snapshot in [
            MemorySnapshot::for_profile(60, full_profile_lens(), 32 * 1024 * 1024, Some(100)),
            MemorySnapshot::for_trace(
                120,
                full_profile_lens(),
                32 * 1024 * 1024,
                None,
                &TracerLens::from_sizes(1, 2, false, 0, 0),
            ),
            MemorySnapshot::for_inventory(60, full_inventory_lens(), 32 * 1024 * 1024),
        ] {
            let line = snapshot.format_line();
            assert!(line.starts_with(MEMORY_LINE_PREFIX), "{line}");
            assert!(!line.ends_with('\n'), "one line, no trailing newline");
            let parsed = MemorySnapshot::parse_line(&line).expect("line parses");
            assert_eq!(parsed, snapshot);
        }
    }

    /// R11 sizes ride B0's accessors (spec §3.5): the outer/rows byte
    /// math pins the (pid, path) and (function, rv) entry shapes from
    /// `trace.rs` (`CallerKey`/`FunctionRv`), plus the fold diagnostics.
    #[test]
    fn tracer_lens_bytes_cover_caller_and_row() {
        let lens = TracerLens::from_sizes(2, 5, true, 7, 3);
        assert_eq!(lens.outer.len, 2);
        assert_eq!(lens.rows.len, 5);
        assert!(lens.overflowed);
        assert_eq!(lens.folded_lines, 7);
        assert_eq!(lens.folded_rows, 3);
        assert!(lens.outer.bytes > 0);
        assert!(lens.rows.bytes > 0);
        let clean = TracerLens::from_sizes(0, 0, false, 0, 0);
        assert_eq!(clean.outer.bytes, 0);
        assert_eq!(clean.rows.bytes, 0);
        assert!(!clean.overflowed);
    }

    #[test]
    fn memory_line_rejects_non_memory_lines() {
        assert!(MemorySnapshot::parse_line("p11scope: capturing: waiting").is_none());
        assert!(MemorySnapshot::parse_line("p11scope: memory ").is_none());
        assert!(MemorySnapshot::parse_line("p11scope: memory {not json}").is_none());
        assert!(MemorySnapshot::parse_line("").is_none());
    }

    #[test]
    fn memory_cadence_emits_every_sixty_seconds() {
        assert_eq!(MEMORY_EMIT_INTERVAL_SECS, 60);
        let start = std::time::Instant::now();
        let mut cadence =
            MemoryCadence::with_interval_for_test(start, std::time::Duration::from_secs(60));
        assert!(!cadence.due(start + std::time::Duration::from_secs(59)));
        assert!(cadence.due(start + std::time::Duration::from_secs(60)));
        cadence.mark(start + std::time::Duration::from_secs(60));
        assert!(!cadence.due(start + std::time::Duration::from_secs(119)));
        assert!(cadence.due(start + std::time::Duration::from_secs(120)));
        assert_eq!(
            cadence.elapsed_secs(start + std::time::Duration::from_secs(61)),
            61
        );
    }

    #[test]
    fn memory_live_dead_split_counts_probe_results() {
        let pids = BTreeSet::from([1, 2, 3]);
        let (live, dead) = split_live_dead(&pids, &|pid| pid != 2);
        assert_eq!((live, dead), (2, 1));
        let empty = BTreeSet::new();
        let (live, dead) = split_live_dead(&empty, &|_| true);
        assert_eq!((live, dead), (0, 0));
    }

    /// Minor 7: the stderr line stays well below the 4096-byte atomic
    /// pipe-write limit, even at large counter values. Future keys
    /// must keep this margin (split or trim before growing past it).
    #[test]
    fn memory_line_stays_well_below_pipe_atomic_limit() {
        fn big(len: u64) -> CounterRow {
            CounterRow {
                len,
                bytes: len.saturating_mul(4096),
            }
        }
        // Large but realistic soak values (tens of thousands of rows,
        // multi-GB byte totals), not u64::MAX extremes.
        let mut lens = full_profile_lens();
        lens.state.reduced = big(25_000);
        lens.state.open = big(25_000);
        lens.state.next_pseudonym = big(25_000);
        lens.dead.reduced_dead = big(20_000);
        lens.dead.open_dead = big(20_000);
        lens.dead.next_pseudonym_dead = big(20_000);
        lens.live_processes = 100;
        lens.dead_processes = 25_000;
        lens.sample_us = 999_999;
        for snapshot in [
            MemorySnapshot::for_profile(3600, lens.clone(), 64 * 1024 * 1024, Some(u64::MAX)),
            MemorySnapshot::for_trace(
                3600,
                lens.clone(),
                64 * 1024 * 1024,
                None,
                &TracerLens::from_sizes(4096, 10_000, true, 1_000_000, 500),
            ),
            MemorySnapshot::for_inventory(3600, full_inventory_lens(), 64 * 1024 * 1024),
        ] {
            let line = snapshot.format_line();
            assert!(
                line.len() < 4096,
                "memory line {} bytes, must stay well below 4096: {line:.200}",
                line.len()
            );
        }
    }

    #[test]
    fn json_value_bytes_counts_nodes_and_strings() {
        let empty = serde_json::json!({});
        assert_eq!(json_value_bytes(&empty), 32);
        let value = serde_json::json!({"ab": [1, "cde"]});
        let bytes = json_value_bytes(&value);
        // One object node + key + one array node + two element nodes +
        // string bytes: strictly more than the empty object, and the
        // string payload is counted exactly.
        assert!(bytes > 32 + 2 + 3, "{bytes}");
        assert_eq!(
            json_value_bytes(&serde_json::json!({"k": "v"})),
            32 + 64 + 1 + 32 + 1
        );
    }

    #[test]
    fn self_rss_reads_current_process() {
        let (rss, hwm) = self_rss_hwm_kb().expect("test host has /proc/self/status");
        assert!(rss > 0 && hwm >= rss, "rss={rss} hwm={hwm}");
    }

    /// Minor 1 twin: the baseline reads only when diagnostics are on;
    /// the off path pays no `/proc` read (returns None without touching
    /// the filesystem).
    #[test]
    fn baseline_rss_gated_on_capture_diagnostics() {
        assert_eq!(baseline_rss_if_diagnostics(false), None);
        let on = baseline_rss_if_diagnostics(true).expect("test host has /proc/self/status");
        assert!(on > 0);
    }
}
