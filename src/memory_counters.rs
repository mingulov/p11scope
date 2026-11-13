//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Per-structure memory counters (v0.8.0 Phase A0, measure only).
//!
//! Every growing structure reports `len` x approx bytes on the `-v`
//! stderr channel as `p11scope: memory {json}`: one line every 60 s
//! plus one at end of capture. Production behavior, caps, and reports
//! are unchanged; rows a command does not own read `null` (N/A).

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
/// Registry edge record: mapping evidence, entry strings, gaps.
pub(crate) const HEAP_EDGE_RECORD: usize = 2304;
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

/// R1 lens: the adapter's caller and incarnation tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterLens {
    pub callers: CounterRow,
    pub incarnations: CounterRow,
}

/// R3 lens: per-edge session/operation/mechanism maps, summed over
/// the registry's materialized edges (O(edges), emit path only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EdgeLens {
    pub open: CounterRow,
    pub active: CounterRow,
    pub mechs: CounterRow,
    pub pending: CounterRow,
}

/// R2 lens: registry caller/module/edge tables plus R3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryLens {
    pub callers: CounterRow,
    pub retired: CounterRow,
    pub modules: CounterRow,
    pub edges: CounterRow,
    pub edge: EdgeLens,
}

/// R4 lens: the object model's session/object/pending tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelLens {
    pub sessions: CounterRow,
    pub objects: CounterRow,
    pub pending: CounterRow,
    pub pruned_sessions: u64,
    pub pruned_objects: u64,
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

/// Profile/trace capture lens: engine history, semantic state,
/// distinct R12 pids for the live/dead sample, and history tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileLens {
    pub history: HistoryLens,
    pub state: StateLens,
    pub process_pids: Vec<u32>,
    pub tasks: CounterRow,
}

/// Inventory capture lens: adapter, registry (+R3), history, object
/// model, and the metadata frame row count if the lane is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryLens {
    pub adapter: AdapterLens,
    pub registry: RegistryLens,
    pub history: HistoryLens,
    pub model: ModelLens,
    pub metadata_rows: Option<CounterRow>,
}

/// One capture's memory snapshot. `None` rows are N/A: the command
/// owns no such structure. Field order is the JSON key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemorySnapshot {
    command: String,
    elapsed_secs: u64,
    r1_adapter_callers: Option<CounterRow>,
    r1_adapter_incarnations: Option<CounterRow>,
    r2_registry_callers: Option<CounterRow>,
    r2_registry_retired: Option<CounterRow>,
    r2_registry_modules: Option<CounterRow>,
    r2_registry_edges: Option<CounterRow>,
    r3_edge_open: Option<CounterRow>,
    r3_edge_active: Option<CounterRow>,
    r3_edge_mechs: Option<CounterRow>,
    r3_edge_pending: Option<CounterRow>,
    r3_mech_pool_bytes: u64,
    r4_model_sessions: Option<CounterRow>,
    r4_model_objects: Option<CounterRow>,
    r4_model_pending: Option<CounterRow>,
    r4_pruned_sessions: Option<u64>,
    r4_pruned_objects: Option<u64>,
    r5_seal_value_bytes: Option<u64>,
    r6: Option<HistoryRows>,
    r7_param_combos: Option<CounterRow>,
    r7_attr_types: Option<CounterRow>,
    r8_mechanisms: Option<CounterRow>,
    r8_templates: Option<CounterRow>,
    r8_logins: Option<CounterRow>,
    r8_cgroups: Option<CounterRow>,
    r8_mech_shapes: Option<CounterRow>,
    r9_tasks: Option<CounterRow>,
    r10_reduced: Option<CounterRow>,
    r11_caller_reasons_outer: Option<CounterRow>,
    r11_caller_reasons_rows: Option<CounterRow>,
    r11_pending_b0: bool,
    r12_open: Option<CounterRow>,
    r12_active_ops: Option<CounterRow>,
    r12_next_pseudonym: Option<CounterRow>,
    r12_find_active: Option<CounterRow>,
    r12_pending: Option<CounterRow>,
    r12_detached: Option<CounterRow>,
    r12_inherited_ambiguous: Option<CounterRow>,
    r12_live_processes: Option<u64>,
    r12_dead_processes: Option<u64>,
    caller_metadata_rows: Option<CounterRow>,
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

    fn floor(ring_bytes: u32) -> (u64, u64, Option<u64>, Option<u64>) {
        let (rss, hwm) = self_rss_hwm_kb().unzip();
        (
            crate::events::EVENTS_STAGE_BYTES as u64,
            ring_bytes as u64,
            rss,
            hwm,
        )
    }

    /// Profile snapshot: R5 (seal only), R6-R10, R12, floor.
    /// R1-R4, R11 and metadata are N/A on this path.
    pub(crate) fn for_profile(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
    ) -> Self {
        Self::for_profile_with_probe(
            elapsed_secs,
            lens,
            ring_bytes,
            seal_value_bytes,
            &proc_pid_live,
        )
    }

    /// [`for_profile`] with an injectable liveness probe (tests).
    pub(crate) fn for_profile_with_probe(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
        probe: &dyn Fn(u32) -> bool,
    ) -> Self {
        Self::for_event_capture(
            "profile",
            elapsed_secs,
            lens,
            ring_bytes,
            seal_value_bytes,
            false,
            probe,
        )
    }

    /// Trace snapshot: like profile, but R5 is always N/A (the trace
    /// path streams lines; it seals no `Value` tree) and R11 is
    /// pending on the B0 accessors (TODO hook, trace only).
    pub(crate) fn for_trace(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
    ) -> Self {
        Self::for_event_capture(
            "trace",
            elapsed_secs,
            lens,
            ring_bytes,
            seal_value_bytes,
            true,
            &proc_pid_live,
        )
    }

    /// [`for_trace`] with an injectable liveness probe (tests).
    #[cfg(test)]
    fn for_trace_with_probe(
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        probe: &dyn Fn(u32) -> bool,
    ) -> Self {
        Self::for_event_capture("trace", elapsed_secs, lens, ring_bytes, None, true, probe)
    }

    #[allow(clippy::too_many_arguments)]
    fn for_event_capture(
        command: &str,
        elapsed_secs: u64,
        lens: ProfileLens,
        ring_bytes: u32,
        seal_value_bytes: Option<u64>,
        r11_pending_b0: bool,
        probe: &dyn Fn(u32) -> bool,
    ) -> Self {
        let (live, dead) = split_live_dead(&lens.process_pids, probe);
        let (staging, ring, rss, hwm) = Self::floor(ring_bytes);
        let state = lens.state;
        Self {
            command: command.to_string(),
            elapsed_secs,
            r1_adapter_callers: None,
            r1_adapter_incarnations: None,
            r2_registry_callers: None,
            r2_registry_retired: None,
            r2_registry_modules: None,
            r2_registry_edges: None,
            r3_edge_open: None,
            r3_edge_active: None,
            r3_edge_mechs: None,
            r3_edge_pending: None,
            r3_mech_pool_bytes: crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT as u64,
            r4_model_sessions: None,
            r4_model_objects: None,
            r4_model_pending: None,
            r4_pruned_sessions: None,
            r4_pruned_objects: None,
            r5_seal_value_bytes: seal_value_bytes,
            r6: Some(lens.history.rows),
            r7_param_combos: Some(state.param_combos),
            r7_attr_types: Some(state.attr_types),
            r8_mechanisms: Some(state.mechanisms),
            r8_templates: Some(state.templates),
            r8_logins: Some(state.logins),
            r8_cgroups: Some(state.cgroups),
            r8_mech_shapes: Some(state.mech_shapes),
            r9_tasks: Some(lens.tasks),
            r10_reduced: Some(state.reduced),
            r11_caller_reasons_outer: None,
            r11_caller_reasons_rows: None,
            r11_pending_b0,
            r12_open: Some(state.open),
            r12_active_ops: Some(state.active_ops),
            r12_next_pseudonym: Some(state.next_pseudonym),
            r12_find_active: Some(state.find_active),
            r12_pending: Some(state.pending),
            r12_detached: Some(state.detached),
            r12_inherited_ambiguous: Some(state.inherited_ambiguous),
            r12_live_processes: Some(live),
            r12_dead_processes: Some(dead),
            caller_metadata_rows: None,
            floor_staging_bytes: staging,
            floor_ring_bytes: ring,
            self_rss_kb: rss,
            self_hwm_kb: hwm,
        }
    }

    /// Inventory snapshot: R1-R4, R6, metadata, floor.
    /// R5, R7-R12 are N/A on this path.
    pub(crate) fn for_inventory(elapsed_secs: u64, lens: InventoryLens, ring_bytes: u32) -> Self {
        let (staging, ring, rss, hwm) = Self::floor(ring_bytes);
        Self {
            command: "inventory".to_string(),
            elapsed_secs,
            r1_adapter_callers: Some(lens.adapter.callers),
            r1_adapter_incarnations: Some(lens.adapter.incarnations),
            r2_registry_callers: Some(lens.registry.callers),
            r2_registry_retired: Some(lens.registry.retired),
            r2_registry_modules: Some(lens.registry.modules),
            r2_registry_edges: Some(lens.registry.edges),
            r3_edge_open: Some(lens.registry.edge.open),
            r3_edge_active: Some(lens.registry.edge.active),
            r3_edge_mechs: Some(lens.registry.edge.mechs),
            r3_edge_pending: Some(lens.registry.edge.pending),
            r3_mech_pool_bytes: crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT as u64,
            r4_model_sessions: Some(lens.model.sessions),
            r4_model_objects: Some(lens.model.objects),
            r4_model_pending: Some(lens.model.pending),
            r4_pruned_sessions: Some(lens.model.pruned_sessions),
            r4_pruned_objects: Some(lens.model.pruned_objects),
            r5_seal_value_bytes: None,
            r6: Some(lens.history.rows),
            r7_param_combos: None,
            r7_attr_types: None,
            r8_mechanisms: None,
            r8_templates: None,
            r8_logins: None,
            r8_cgroups: None,
            r8_mech_shapes: None,
            r9_tasks: None,
            r10_reduced: None,
            r11_caller_reasons_outer: None,
            r11_caller_reasons_rows: None,
            r11_pending_b0: false,
            r12_open: None,
            r12_active_ops: None,
            r12_next_pseudonym: None,
            r12_find_active: None,
            r12_pending: None,
            r12_detached: None,
            r12_inherited_ambiguous: None,
            r12_live_processes: None,
            r12_dead_processes: None,
            caller_metadata_rows: lens.metadata_rows,
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

/// Split distinct pids into live vs dead by the probe. Pids are
/// deduplicated: several R12 rows (or generations) may name one pid.
/// PID reuse undercounts dead processes (a recycled pid reads live);
/// the B1 exit routing replaces this sample with an incremental
/// split and keeps it as the cross-check.
pub(crate) fn split_live_dead(pids: &[u32], probe: &dyn Fn(u32) -> bool) -> (u64, u64) {
    let mut live = 0u64;
    let mut dead = 0u64;
    for pid in pids.iter().collect::<BTreeSet<_>>() {
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

/// R5 estimate: the sealed report `Value`'s heap in bytes. One node
/// counts `size_of::<Value>()`, strings count their bytes, and map
/// entries carry a node-share allowance. A documented approximation,
/// pinned by the twin below; Phase B removes the tree it measures.
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
            },
        }
    }

    fn full_state() -> StateLens {
        StateLens {
            param_combos: row(1),
            attr_types: row(2),
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

    fn full_profile_lens() -> ProfileLens {
        ProfileLens {
            history: full_history(),
            state: full_state(),
            process_pids: vec![1, 2],
            tasks: row(3),
        }
    }

    fn full_inventory_lens() -> InventoryLens {
        InventoryLens {
            adapter: AdapterLens {
                callers: row(1),
                incarnations: row(2),
            },
            registry: RegistryLens {
                callers: row(3),
                retired: row(4),
                modules: row(5),
                edges: row(6),
                edge: EdgeLens {
                    open: row(7),
                    active: row(8),
                    mechs: row(9),
                    pending: row(10),
                },
            },
            history: full_history(),
            model: ModelLens {
                sessions: row(11),
                objects: row(12),
                pending: row(13),
                pruned_sessions: 14,
                pruned_objects: 15,
            },
            metadata_rows: Some(row(16)),
        }
    }

    /// A0 step 1 (corrected per command): the snapshot carries every
    /// owned grower row, and rows the command does not own read N/A.
    #[test]
    fn memory_counters_cover_every_grower() {
        let profile = MemorySnapshot::for_profile_with_probe(
            60,
            full_profile_lens(),
            32 * 1024 * 1024,
            Some(100),
            &|pid| pid == 1,
        );
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
        assert_eq!(profile.r12_live_processes, Some(1));
        assert_eq!(profile.r12_dead_processes, Some(1));
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
        assert!(!profile.r11_pending_b0);
        assert!(profile.caller_metadata_rows.is_none());

        let trace = MemorySnapshot::for_trace_with_probe(
            60,
            full_profile_lens(),
            32 * 1024 * 1024,
            &|_| true,
        );
        assert_eq!(trace.command, "trace");
        assert_eq!(trace.r9_tasks.expect("trace owns R9").len, 3);
        assert_eq!(trace.r12_live_processes, Some(2));
        assert_eq!(trace.r12_dead_processes, Some(0));
        // R11 sizes arrive with the B0 accessors; until then the row is
        // N/A with the pending marker set (trace only).
        assert!(trace.r11_caller_reasons_outer.is_none());
        assert!(trace.r11_caller_reasons_rows.is_none());
        assert!(trace.r11_pending_b0);

        let inventory = MemorySnapshot::for_inventory(60, full_inventory_lens(), 32 * 1024 * 1024);
        assert_eq!(inventory.command, "inventory");
        // Owned: R1-R4 + R6 + metadata.
        assert_eq!(inventory.r1_adapter_callers.expect("R1").len, 1);
        assert_eq!(inventory.r1_adapter_incarnations.expect("R1").len, 2);
        assert_eq!(inventory.r2_registry_edges.expect("R2").len, 6);
        assert_eq!(inventory.r3_edge_pending.expect("R3").len, 10);
        assert_eq!(inventory.r3_mech_pool_bytes, 160 * 1024 * 1024);
        assert_eq!(inventory.r4_model_pending.expect("R4").len, 13);
        assert_eq!(inventory.r4_pruned_sessions, Some(14));
        assert_eq!(inventory.r4_pruned_objects, Some(15));
        assert!(inventory.r6.is_some());
        assert_eq!(inventory.caller_metadata_rows.expect("metadata").len, 16);
        // Not owned: R5, R7-R12.
        assert!(inventory.r5_seal_value_bytes.is_none());
        assert!(inventory.r7_param_combos.is_none());
        assert!(inventory.r7_attr_types.is_none());
        assert!(inventory.r8_mechanisms.is_none());
        assert!(inventory.r8_templates.is_none());
        assert!(inventory.r8_logins.is_none());
        assert!(inventory.r8_cgroups.is_none());
        assert!(inventory.r8_mech_shapes.is_none());
        assert!(inventory.r9_tasks.is_none());
        assert!(inventory.r10_reduced.is_none());
        assert!(inventory.r11_caller_reasons_outer.is_none());
        assert!(inventory.r11_caller_reasons_rows.is_none());
        assert!(!inventory.r11_pending_b0);
        assert!(inventory.r12_open.is_none());
        assert!(inventory.r12_active_ops.is_none());
        assert!(inventory.r12_next_pseudonym.is_none());
        assert!(inventory.r12_find_active.is_none());
        assert!(inventory.r12_pending.is_none());
        assert!(inventory.r12_detached.is_none());
        assert!(inventory.r12_inherited_ambiguous.is_none());
        assert!(inventory.r12_live_processes.is_none());
        assert!(inventory.r12_dead_processes.is_none());
    }

    /// A0 step 4 (corrected): the stderr line parses back to the same
    /// snapshot it was formatted from.
    #[test]
    fn memory_line_roundtrip_matches_snapshot() {
        for snapshot in [
            MemorySnapshot::for_profile(60, full_profile_lens(), 32 * 1024 * 1024, Some(100)),
            MemorySnapshot::for_trace(120, full_profile_lens(), 32 * 1024 * 1024, None),
            MemorySnapshot::for_inventory(60, full_inventory_lens(), 32 * 1024 * 1024),
        ] {
            let line = snapshot.format_line();
            assert!(line.starts_with(MEMORY_LINE_PREFIX), "{line}");
            assert!(!line.ends_with('\n'), "one line, no trailing newline");
            let parsed = MemorySnapshot::parse_line(&line).expect("line parses");
            assert_eq!(parsed, snapshot);
        }
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
        let (live, dead) = split_live_dead(&[1, 2, 3], &|pid| pid != 2);
        assert_eq!((live, dead), (2, 1));
        let (live, dead) = split_live_dead(&[], &|_| true);
        assert_eq!((live, dead), (0, 0));
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
}
