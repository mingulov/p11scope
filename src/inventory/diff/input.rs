//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, exact-v1 input. Local references are resolved inside each snapshot.

use anyhow::{Context, Result, ensure};
use serde::{
    Serialize, Serializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[derive(Debug)]
pub(super) struct LoadedSnapshot {
    pub snapshot: Snapshot,
    pub source: File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Snapshot {
    pub scope: String,
    pub clock: Clock,
    pub observation: Observation,
    pub budgets: Budgets,
    pub pid_namespace: Option<PidNamespace>,
    pub callers: Vec<Caller>,
    pub modules: Vec<Module>,
    pub edges: Vec<Edge>,
    pub gaps: Vec<Gap>,
    pub gaps_suppressed: u64,
    pub limitations: Vec<String>,
}

/// Unknown enum labels remain available for diagnostics without becoming an
/// admission, coverage or activity assertion. Serialization preserves the label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Label {
    pub raw: String,
    pub known: bool,
}
impl Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Clock {
    pub basis: String,
    pub unit: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct PidNamespace {
    pub observer: Label,
    pub kernel_pids: Label,
    pub proc_pids: Label,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Observation {
    pub started_ns: u64,
    pub ended_ns: u64,
    pub passes: u64,
    pub usage_feed: bool,
    pub lane: Option<Label>,
    pub settlement: Option<Label>,
    pub retirement: Option<Label>,
    pub attach: Option<Attach>,
    pub lifecycle: Option<Lifecycle>,
    pub native_witnesses: Option<NativeWitnesses>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Attach {
    pub selection: Label,
    pub mechanism: Label,
    pub fallback: Option<String>,
    pub scope_filter: Option<Label>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Lifecycle {
    pub records: u64,
    pub ring_loss: u64,
    pub malformed: u64,
    pub failed_quanta: u64,
    pub recovery_rescans: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct NativeWitnesses {
    pub rows: u64,
    pub bound: u64,
    pub unbound: u64,
    pub pending: u64,
    pub integrity: u64,
    pub unbound_reasons: BTreeMap<String, u64>,
    pub placement: Placement,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Placement {
    pub edge: u64,
    pub module: u64,
    pub ambiguous: u64,
    pub unresolved: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Budget {
    pub limit: u64,
    pub occupied: u64,
    pub refused: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct InventoryEndpoints {
    pub limit: u64,
    pub occupied: u64,
    pub refused: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Counters {
    pub cap: u64,
    pub observed_edges: u64,
    pub saturated_edges: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct SemanticBudget {
    pub limit: u64,
    pub occupied: u64,
    pub status: Label,
    pub unknown_edges: u64,
    pub refused: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct RetainedHistory {
    pub limit: u64,
    pub retained: u64,
    pub suppressed: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Preadmission {
    pub limit: u64,
    pub occupied: u64,
    pub refused: u64,
    pub pruned: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Budgets {
    pub callers: Budget,
    pub modules: Budget,
    pub edges: Budget,
    pub endpoints: Budget,
    pub inventory_endpoints: Option<InventoryEndpoints>,
    pub inventory_attach_modules: Option<Budget>,
    pub counters: Counters,
    pub semantic_state: SemanticBudget,
    pub retained_history: RetainedHistory,
    pub native_preadmission: Option<Preadmission>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct Exe {
    pub dev: u64,
    pub ino: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub path: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Image {
    pub authority: Label,
    pub task_cookie: Option<u64>,
    pub exec_id: Option<u64>,
    pub exe: Option<Exe>,
    pub exec_observed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Caller {
    pub pid: u32,
    pub start_time: Option<u64>,
    pub start_time_unit: String,
    pub incarnation: u64,
    pub image: Image,
    pub lifecycle: Label,
    pub lifecycle_reason: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub retired: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Admission {
    pub state: Label,
    pub class: Option<String>,
    pub endpoints: Option<u64>,
    pub reasons: Vec<String>,
    pub note: String,
    pub history: Option<Vec<AdmissionChange>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct AdmissionChange {
    pub from: Label,
    pub to: Label,
    pub at_ns: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct UnboundUse {
    pub first_ns: u64,
    pub rows: u64,
    pub reasons: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Module {
    pub paths: Vec<String>,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub identity_source: Option<String>,
    pub admission: Admission,
    pub lifecycle: Label,
    pub unloaded_observed: bool,
    pub unbound_use: Option<UnboundUse>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Mapping {
    pub state: Label,
    pub evidence: Option<Label>,
    pub reason: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub interruptions: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Coverage {
    pub state: Label,
    pub since_ns: Option<u64>,
    pub until_ns: Option<u64>,
    pub first_ns: Option<u64>,
    pub lossy: Option<bool>,
    pub reason: Option<Label>,
    pub detail: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Entries {
    pub count: u64,
    pub saturated: bool,
    pub cap: u64,
    pub first_seen_ns: Option<u64>,
    pub last_seen_ns: Option<u64>,
    pub in_flight: bool,
    pub observation: Label,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Edge {
    pub caller: usize,
    pub module: usize,
    pub mapping: Mapping,
    pub entries: Entries,
    pub coverage: Option<Coverage>,
    pub semantics: Label,
    pub mechanisms: Option<Vec<Mechanism>>,
    pub operations: Option<Operations>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Mechanism {
    pub mechanism: u64,
    pub mechanism_hex: String,
    pub name: Option<String>,
    pub operations: Vec<String>,
    pub calls: u64,
    pub errors: u64,
    pub last_seen_ns: u64,
    pub evidence: MechanismEvidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct MechanismEvidence {
    pub functions: Vec<String>,
    pub returns: Vec<Return>,
    pub truncated: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Return {
    pub rv: u64,
    pub rv_hex: String,
    pub name: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Operations {
    pub calls: u64,
    pub started: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub failed: u64,
    pub unknown: u64,
    pub orphans: u64,
    pub dropped: u64,
    pub last_seen_ns: u64,
    pub active: Vec<ActiveOperation>,
    pub evidence: OperationEvidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ActiveOperation {
    pub category: String,
    pub state: Label,
    pub count: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct OperationEvidence {
    pub state_reconciliations: u64,
    pub session_cancel_ambiguities: u64,
    pub session_cancel_unknown_flags: u64,
    pub operation_state_imports: u64,
    pub auth_state_ambiguities: u64,
    pub semantic_capture_failures: u64,
    pub async_duplicates: u64,
    pub async_evictions: u64,
    pub unmatched_closes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Refusal {
    pub resource: String,
    pub limit: u64,
    pub requested: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Gap {
    pub caller: Option<usize>,
    pub module: Option<usize>,
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    pub budget: Option<Refusal>,
    pub repeats: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InputLimits {
    pub bytes: usize,
    pub rows: usize,
    pub string_bytes: usize,
    pub depth: usize,
    pub nodes: usize,
}
impl Default for InputLimits {
    fn default() -> Self {
        Self {
            bytes: 67_108_864,
            rows: 250_000,
            string_bytes: 16_384,
            depth: 64,
            nodes: 2_000_000,
        }
    }
}

pub(super) fn read_snapshot(path: &Path) -> Result<LoadedSnapshot> {
    read_with_limits(path, InputLimits::default())
}
pub(super) fn read_with_limits(path: &Path, limits: InputLimits) -> Result<LoadedSnapshot> {
    let context = || {
        format!(
            "inventory input {}",
            crate::render::escape_controls(&path.to_string_lossy())
        )
    };
    // O_NONBLOCK is set before opening, not after a FIFO could already hang.
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(context)?;
    ensure!(
        source
            .metadata()
            .with_context(context)?
            .file_type()
            .is_file(),
        "{}: expected regular file",
        context()
    );
    let bytes = read_bounded(&mut source, limits.bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e:#}", context()))?;
    let snapshot =
        parse_with_limits(&bytes, limits).map_err(|e| anyhow::anyhow!("{}: {e:#}", context()))?;
    Ok(LoadedSnapshot { snapshot, source })
}
pub(super) fn read_bounded(source: impl Read, limit: usize) -> Result<Vec<u8>> {
    let maximum = u64::try_from(limit)?
        .checked_add(1)
        .context("byte limit overflow")?;
    let mut bytes = Vec::new();
    source
        .take(maximum)
        .read_to_end(&mut bytes)
        .context("reading inventory bytes")?;
    ensure!(
        bytes.len() <= limit,
        "inventory byte limit exceeded ({limit})"
    );
    Ok(bytes)
}
pub(super) fn parse_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    parse_with_limits(bytes, InputLimits::default())
}
pub(super) fn parse_with_limits(bytes: &[u8], limits: InputLimits) -> Result<Snapshot> {
    ensure!(
        bytes.len() <= limits.bytes,
        "inventory byte limit exceeded ({})",
        limits.bytes
    );
    let mut budget = ParseBudget { limits, nodes: 0 };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed {
        budget: &mut budget,
        depth: 1,
    }
    .deserialize(&mut deserializer)
    .map_err(|e| anyhow::anyhow!("inventory JSON: {e}"))?;
    deserializer
        .end()
        .map_err(|e| anyhow::anyhow!("inventory JSON trailing input: {e}"))?;
    // The bounded temporary JSON tree is released once conversion returns.
    convert_snapshot(&value, limits)
}

struct ParseBudget {
    limits: InputLimits,
    nodes: usize,
}
impl ParseBudget {
    fn node<E: de::Error>(&mut self) -> std::result::Result<(), E> {
        if self.nodes >= self.limits.nodes {
            return Err(E::custom("inventory node limit exceeded"));
        }
        self.nodes += 1;
        Ok(())
    }
    fn string<E: de::Error>(&self, value: &str) -> std::result::Result<(), E> {
        if value.len() > self.limits.string_bytes {
            return Err(E::custom("inventory string limit exceeded"));
        }
        Ok(())
    }
}
struct JsonSeed<'a> {
    budget: &'a mut ParseBudget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.depth > self.budget.limits.depth {
            return Err(de::Error::custom("inventory depth limit exceeded"));
        }
        self.budget.node()?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonSeed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON value")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        self.budget.string(value)?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        self.budget.string(&value)?;
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key_seed(KeySeed {
            budget: self.budget,
        })? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("inventory duplicate key"));
            }
            let value = object.next_value_seed(JsonSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
struct KeySeed<'a> {
    budget: &'a mut ParseBudget,
}
impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = String;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<String, D::Error> {
        self.budget.node()?;
        deserializer.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for KeySeed<'_> {
    type Value = String;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON key")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<String, E> {
        self.budget.string(value)?;
        Ok(value.to_owned())
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<String, E> {
        self.budget.string(&value)?;
        Ok(value)
    }
}

/// Typed conversion deliberately names fields in errors and never includes
/// untrusted field contents. Unknown bounded fields are discarded here.
struct Object<'a> {
    fields: &'a Map<String, Value>,
    path: String,
}
impl<'a> Object<'a> {
    fn new(value: &'a Value, path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let fields = value
            .as_object()
            .with_context(|| format!("{path}: expected object"))?;
        Ok(Self { fields, path })
    }
    fn field(&self, key: &str) -> String {
        format!("{}.{key}", self.path)
    }
    fn value(&self, key: &str) -> Result<&'a Value> {
        self.fields
            .get(key)
            .with_context(|| format!("{}: missing required field", self.field(key)))
    }
    fn object(&self, key: &str) -> Result<Object<'a>> {
        Object::new(self.value(key)?, self.field(key))
    }
    fn optional_object(&self, key: &str, nullable: bool) -> Result<Option<Object<'a>>> {
        match self.fields.get(key) {
            None => Ok(None),
            Some(Value::Null) if nullable => Ok(None),
            Some(v) => Object::new(v, self.field(key)).map(Some),
        }
    }
    fn text(&self, key: &str) -> Result<String> {
        self.value(key)?
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("{}: expected string", self.field(key)))
    }
    fn text_null(&self, key: &str) -> Result<Option<String>> {
        if self.value(key)?.is_null() {
            Ok(None)
        } else {
            self.text(key).map(Some)
        }
    }
    fn uint(&self, key: &str) -> Result<u64> {
        self.value(key)?
            .as_u64()
            .with_context(|| format!("{}: expected u64", self.field(key)))
    }
    fn uint32(&self, key: &str) -> Result<u32> {
        u32::try_from(self.uint(key)?).with_context(|| format!("{}: u32 overflow", self.field(key)))
    }
    fn int(&self, key: &str) -> Result<i64> {
        self.value(key)?
            .as_i64()
            .with_context(|| format!("{}: expected i64", self.field(key)))
    }
    fn uint_null(&self, key: &str) -> Result<Option<u64>> {
        if self.value(key)?.is_null() {
            Ok(None)
        } else {
            self.uint(key).map(Some)
        }
    }
    fn boolean(&self, key: &str) -> Result<bool> {
        self.value(key)?
            .as_bool()
            .with_context(|| format!("{}: expected boolean", self.field(key)))
    }
    fn bool_null(&self, key: &str) -> Result<Option<bool>> {
        if self.value(key)?.is_null() {
            Ok(None)
        } else {
            self.boolean(key).map(Some)
        }
    }
    fn array(&self, key: &str) -> Result<&'a Vec<Value>> {
        self.value(key)?
            .as_array()
            .with_context(|| format!("{}: expected array", self.field(key)))
    }
    fn strings(&self, key: &str) -> Result<Vec<String>> {
        self.array(key)?
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("{}[{i}]: expected string", self.field(key)))
            })
            .collect()
    }
    fn label(&self, key: &str, known: &[&str]) -> Result<Label> {
        let raw = self.text(key)?;
        Ok(Label {
            known: known.contains(&raw.as_str()),
            raw,
        })
    }
    fn label_null(&self, key: &str, known: &[&str]) -> Result<Option<Label>> {
        if self.value(key)?.is_null() {
            Ok(None)
        } else {
            self.label(key, known).map(Some)
        }
    }
    fn optional_label(&self, key: &str, known: &[&str]) -> Result<Option<Label>> {
        if self.fields.contains_key(key) {
            self.label(key, known).map(Some)
        } else {
            Ok(None)
        }
    }
    fn u64_map(&self, key: &str) -> Result<BTreeMap<String, u64>> {
        let o = self.object(key)?;
        o.fields
            .iter()
            .map(|(k, v)| {
                v.as_u64()
                    .map(|n| (k.clone(), n))
                    .with_context(|| format!("{}: expected u64 values", o.path))
            })
            .collect()
    }
}

const ADMISSION: &[&str] = &["admitted", "refused", "unresolved"];
const UNKNOWN_REASONS: &[&str] = &[
    "scan_only",
    "not_admitted",
    "not_attached",
    "attach_failed",
    "identity_unavailable",
    "capacity_limited",
    "loss",
    "retired_before_coverage",
    "use_before_admission",
    "pending_first_use",
    "uncounted",
    "scope_membership_unproven",
];
const SEMANTICS: &[&str] = &[
    "observed",
    "unknown (semantic capture withheld)",
    "unknown (unauthoritative module)",
    "unknown (ambiguous descriptor)",
    "unknown (count-only slot)",
    "unknown (no operation evidence)",
    "unknown (same-file double-load)",
];

fn convert_snapshot(value: &Value, limits: InputLimits) -> Result<Snapshot> {
    let root = Object::new(value, "root")?;
    ensure!(
        root.text("schema")? == "p11scope/inventory/v1",
        "root.schema: unsupported schema"
    );
    let mut rows = 0usize;
    for key in ["callers", "modules", "edges", "gaps"] {
        rows = rows
            .checked_add(root.array(key)?.len())
            .context("inventory row limit overflow")?;
    }
    ensure!(
        rows <= limits.rows,
        "inventory row limit exceeded ({})",
        limits.rows
    );
    let mut caller_ids = BTreeMap::new();
    let mut callers = Vec::new();
    for (i, v) in root.array("callers")?.iter().enumerate() {
        let o = Object::new(v, format!("callers[{i}]"))?;
        ensure!(
            caller_ids.insert(o.text("id")?, i).is_none(),
            "callers[{i}]: duplicate caller id"
        );
        callers.push(parse_caller(&o)?);
    }
    let mut module_ids = BTreeMap::new();
    let mut modules = Vec::new();
    for (i, v) in root.array("modules")?.iter().enumerate() {
        let o = Object::new(v, format!("modules[{i}]"))?;
        ensure!(
            module_ids.insert(o.text("id")?, i).is_none(),
            "modules[{i}]: duplicate module id"
        );
        modules.push(parse_module(&o)?);
    }
    let mut pairs = BTreeSet::new();
    let mut edges = Vec::new();
    for (i, v) in root.array("edges")?.iter().enumerate() {
        let o = Object::new(v, format!("edges[{i}]"))?;
        let caller = resolve(&o, "caller", &caller_ids)?;
        let module = resolve(&o, "module", &module_ids)?;
        ensure!(
            pairs.insert((caller, module)),
            "edges[{i}]: duplicate edge pair"
        );
        edges.push(parse_edge(&o, caller, module)?);
    }
    let mut gaps = Vec::new();
    for (i, v) in root.array("gaps")?.iter().enumerate() {
        let o = Object::new(v, format!("gaps[{i}]"))?;
        let repeats = if o.fields.contains_key("repeats") {
            o.uint("repeats")?
        } else {
            1
        };
        ensure!(repeats >= 1, "gaps[{i}].repeats: expected positive count");
        let budget = if o.value("budget")?.is_null() {
            None
        } else {
            let b = o.object("budget")?;
            Some(Refusal {
                resource: b.text("resource")?,
                limit: b.uint("limit")?,
                requested: b.uint("requested")?,
            })
        };
        let pid = o
            .uint_null("pid")?
            .map(u32::try_from)
            .transpose()
            .with_context(|| format!("gaps[{i}].pid: u32 overflow"))?;
        gaps.push(Gap {
            caller: resolve_null(&o, "caller", &caller_ids)?,
            module: resolve_null(&o, "module", &module_ids)?,
            pid,
            subject: o.text("subject")?,
            reason: o.text("reason")?,
            budget,
            repeats,
        });
    }
    let c = root.object("clock")?;
    let clock = Clock {
        basis: c.text("basis")?,
        unit: c.text("unit")?,
    };
    let mut limitations = Vec::new();
    if clock.basis != "CLOCK_MONOTONIC" {
        limitations.push("unknown_clock_basis".to_owned());
    }
    if clock.unit != "ns" {
        limitations.push("unknown_clock_unit".to_owned());
    }
    if callers
        .iter()
        .any(|c| c.start_time_unit != "clock_ticks_since_boot")
    {
        limitations.push("unknown_start_time_unit".to_owned());
    }
    let pid_namespace = root
        .optional_object("pid_namespace", false)?
        .map(|p| {
            Ok::<_, anyhow::Error>(PidNamespace {
                observer: p.label("observer", &["initial", "nested", "unknown"])?,
                kernel_pids: p.label("kernel_pids", &["initial"])?,
                proc_pids: p.label("proc_pids", &["observer", "foreign"])?,
            })
        })
        .transpose()?;
    Ok(Snapshot {
        scope: root.text("scope")?,
        clock,
        observation: parse_observation(&root.object("observation")?)?,
        budgets: parse_budgets(&root.object("budgets")?)?,
        pid_namespace,
        callers,
        modules,
        edges,
        gaps,
        gaps_suppressed: root.uint("gaps_suppressed")?,
        limitations,
    })
}
fn resolve(o: &Object<'_>, key: &str, ids: &BTreeMap<String, usize>) -> Result<usize> {
    ids.get(&o.text(key)?)
        .copied()
        .with_context(|| format!("{}: dangling reference", o.field(key)))
}
fn resolve_null(o: &Object<'_>, key: &str, ids: &BTreeMap<String, usize>) -> Result<Option<usize>> {
    if o.value(key)?.is_null() {
        Ok(None)
    } else {
        resolve(o, key, ids).map(Some)
    }
}
fn parse_caller(o: &Object<'_>) -> Result<Caller> {
    let image = o.object("image")?;
    let exe = if image.value("exe")?.is_null() {
        None
    } else {
        let e = image.object("exe")?;
        Some(Exe {
            dev: e.uint("dev")?,
            ino: e.uint("ino")?,
            mtime_secs: e.int("mtime_secs")?,
            mtime_nanos: e.int("mtime_nanos")?,
            path: e.text_null("path")?,
        })
    };
    Ok(Caller {
        pid: o.uint32("pid")?,
        start_time: o.uint_null("start_time")?,
        start_time_unit: o.text("start_time_unit")?,
        incarnation: o.uint("incarnation")?,
        image: Image {
            authority: image.label("authority", &["native_exact", "scan_pinned"])?,
            task_cookie: image.uint_null("task_cookie")?,
            exec_id: image.uint_null("exec_id")?,
            exe,
            exec_observed: image.boolean("exec_observed")?,
        },
        lifecycle: o.label(
            "lifecycle",
            &["mapped", "exited", "exec_retired", "unknown"],
        )?,
        lifecycle_reason: o.text_null("lifecycle_reason")?,
        first_seen_ns: o.uint("first_seen_ns")?,
        last_seen_ns: o.uint("last_seen_ns")?,
        retired: o.boolean("retired")?,
    })
}
fn parse_module(o: &Object<'_>) -> Result<Module> {
    let identity = o.object("identity")?;
    let device = identity.object("device")?;
    let sha256 = identity
        .text_null("sha256")?
        .map(|digest| {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "{}.sha256: expected 64 ASCII hex digits",
                identity.path
            );
            Ok(digest.to_ascii_lowercase())
        })
        .transpose()?;
    let a = o.object("admission")?;
    let history = if a.fields.contains_key("history") {
        Some(
            a.array("history")?
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let h = Object::new(v, format!("{}.history[{i}]", a.path))?;
                    Ok(AdmissionChange {
                        from: h.label("from", ADMISSION)?,
                        to: h.label("to", ADMISSION)?,
                        at_ns: h.uint("at_ns")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )
    } else {
        None
    };
    let admission_details = Admission {
        state: a.label("state", ADMISSION)?,
        class: a.text_null("class")?,
        endpoints: a.uint_null("endpoints")?,
        reasons: a.strings("reasons")?,
        note: a.text("note")?,
        history,
    };
    let unbound_use = o
        .optional_object("unbound_use", true)?
        .map(|u| {
            Ok::<_, anyhow::Error>(UnboundUse {
                first_ns: u.uint("first_ns")?,
                rows: u.uint("rows")?,
                reasons: u.u64_map("reasons")?,
            })
        })
        .transpose()?;
    Ok(Module {
        paths: o.strings("paths")?,
        device_major: device.uint32("major")?,
        device_minor: device.uint32("minor")?,
        inode: identity.uint("inode")?,
        sha256,
        build_id: identity.text_null("build_id")?,
        identity_source: identity.text_null("source")?,
        admission: admission_details,
        lifecycle: o.label("lifecycle", &["mapped", "unloaded", "unknown"])?,
        unloaded_observed: o.boolean("unloaded_observed")?,
        unbound_use,
    })
}
fn parse_edge(o: &Object<'_>, caller: usize, module: usize) -> Result<Edge> {
    let m = o.object("mapping")?;
    let e = o.object("entries")?;
    let coverage_details = e
        .optional_object("coverage", false)?
        .map(|c| {
            Ok::<_, anyhow::Error>(Coverage {
                state: c.label(
                    "state",
                    &["counted", "witnessed", "watched_no_use", "unknown"],
                )?,
                since_ns: c.uint_null("since_ns")?,
                until_ns: c.uint_null("until_ns")?,
                first_ns: c.uint_null("first_ns")?,
                lossy: c.bool_null("lossy")?,
                reason: c.label_null("reason", UNKNOWN_REASONS)?,
                detail: c.text_null("detail")?,
            })
        })
        .transpose()?;
    let mechanisms = match o.fields.get("mechanisms") {
        None | Some(Value::Null) => None,
        Some(_) => Some(
            o.array("mechanisms")?
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    parse_mechanism(&Object::new(v, format!("{}.mechanisms[{i}]", o.path))?)
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };
    let operations = o
        .optional_object("operations", true)?
        .map(|p| parse_operations(&p))
        .transpose()?;
    Ok(Edge {
        caller,
        module,
        mapping: Mapping {
            state: m.label("state", &["mapped", "ended", "uncertain"])?,
            evidence: m.optional_label("evidence", &["deep_scan", "maps_match"])?,
            reason: m.text_null("reason")?,
            first_seen_ns: m.uint("first_seen_ns")?,
            last_seen_ns: m.uint("last_seen_ns")?,
            interruptions: m.uint("interruptions")?,
        },
        entries: Entries {
            count: e.uint("count")?,
            saturated: e.boolean("saturated")?,
            cap: e.uint("cap")?,
            first_seen_ns: e.uint_null("first_seen_ns")?,
            last_seen_ns: e.uint_null("last_seen_ns")?,
            in_flight: e.boolean("in_flight")?,
            observation: e.label(
                "observation",
                &[
                    "observed",
                    "unknown (not admitted)",
                    "unknown (usage observation unavailable)",
                    "unknown (count unavailable; use witnessed)",
                    "unknown (usage observation lossy)",
                ],
            )?,
        },
        coverage: coverage_details,
        semantics: o.label("semantics", SEMANTICS)?,
        mechanisms,
        operations,
    })
}
fn parse_observation(o: &Object<'_>) -> Result<Observation> {
    let attach = o
        .optional_object("attach", false)?
        .map(|a| {
            Ok::<_, anyhow::Error>(Attach {
                selection: a.label("selection", &["auto", "multi", "singles"])?,
                mechanism: a.label("mechanism", &["uprobe-multi", "per-offset"])?,
                fallback: a.text_null("fallback")?,
                scope_filter: a.label_null(
                    "scope_filter",
                    &["kernel-pid+bpf", "perf-task+bpf", "bpf-cgroup"],
                )?,
            })
        })
        .transpose()?;
    let lifecycle = o
        .optional_object("lifecycle", false)?
        .map(|l| {
            Ok::<_, anyhow::Error>(Lifecycle {
                records: l.uint("records")?,
                ring_loss: l.uint("ring_loss")?,
                malformed: l.uint("malformed")?,
                failed_quanta: l.uint("failed_quanta")?,
                recovery_rescans: l.uint("recovery_rescans")?,
            })
        })
        .transpose()?;
    let native_witnesses = o
        .optional_object("native_witnesses", false)?
        .map(|n| {
            let p = n.object("placement")?;
            Ok::<_, anyhow::Error>(NativeWitnesses {
                rows: n.uint("rows")?,
                bound: n.uint("bound")?,
                unbound: n.uint("unbound")?,
                pending: n.uint("pending")?,
                integrity: n.uint("integrity")?,
                unbound_reasons: n.u64_map("unbound_reasons")?,
                placement: Placement {
                    edge: p.uint("edge")?,
                    module: p.uint("module")?,
                    ambiguous: p.uint("ambiguous")?,
                    unresolved: p.uint("unresolved")?,
                },
            })
        })
        .transpose()?;
    Ok(Observation {
        started_ns: o.uint("started_ns")?,
        ended_ns: o.uint("ended_ns")?,
        passes: o.uint("passes")?,
        usage_feed: o.boolean("usage_feed")?,
        lane: o.optional_label("lane", &["native"])?,
        settlement: o.optional_label("settlement", &["unsettled"])?,
        retirement: o.optional_label("retirement", &["closed", "unsettled"])?,
        attach,
        lifecycle,
        native_witnesses,
    })
}
fn parse_budget(o: &Object<'_>) -> Result<Budget> {
    Ok(Budget {
        limit: o.uint("limit")?,
        occupied: o.uint("occupied")?,
        refused: o.uint("refused")?,
    })
}
fn parse_budgets(o: &Object<'_>) -> Result<Budgets> {
    let c = o.object("counters")?;
    let s = o.object("semantic_state")?;
    let r = o.object("retained_history")?;
    let inventory_endpoints = o
        .optional_object("inventory_endpoints", false)?
        .map(|b| {
            Ok::<_, anyhow::Error>(InventoryEndpoints {
                limit: b.uint("limit")?,
                occupied: b.uint("occupied")?,
                refused: if b.fields.contains_key("refused") {
                    Some(b.uint("refused")?)
                } else {
                    None
                },
            })
        })
        .transpose()?;
    let inventory_attach_modules = o
        .optional_object("inventory_attach_modules", false)?
        .map(|b| parse_budget(&b))
        .transpose()?;
    let native_preadmission = o
        .optional_object("native_preadmission", true)?
        .map(|b| {
            Ok::<_, anyhow::Error>(Preadmission {
                limit: b.uint("limit")?,
                occupied: b.uint("occupied")?,
                refused: b.uint("refused")?,
                pruned: b.uint("pruned")?,
            })
        })
        .transpose()?;
    Ok(Budgets {
        callers: parse_budget(&o.object("callers")?)?,
        modules: parse_budget(&o.object("modules")?)?,
        edges: parse_budget(&o.object("edges")?)?,
        endpoints: parse_budget(&o.object("endpoints")?)?,
        inventory_endpoints,
        inventory_attach_modules,
        counters: Counters {
            cap: c.uint("cap")?,
            observed_edges: c.uint("observed_edges")?,
            saturated_edges: c.uint("saturated_edges")?,
        },
        semantic_state: SemanticBudget {
            limit: s.uint("limit")?,
            occupied: s.uint("occupied")?,
            status: s.label("status", &["withheld", "observed"])?,
            unknown_edges: s.uint("unknown_edges")?,
            refused: s.uint("refused")?,
        },
        retained_history: RetainedHistory {
            limit: r.uint("limit")?,
            retained: r.uint("retained")?,
            suppressed: r.uint("suppressed")?,
        },
        native_preadmission,
    })
}
fn parse_mechanism(o: &Object<'_>) -> Result<Mechanism> {
    let e = o.object("evidence")?;
    let returns = e
        .array("returns")?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let r = Object::new(v, format!("{}.returns[{i}]", e.path))?;
            Ok(Return {
                rv: r.uint("rv")?,
                rv_hex: r.text("rv_hex")?,
                name: r.text_null("name")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Mechanism {
        mechanism: o.uint("mechanism")?,
        mechanism_hex: o.text("mechanism_hex")?,
        name: o.text_null("name")?,
        operations: o.strings("operations")?,
        calls: o.uint("calls")?,
        errors: o.uint("errors")?,
        last_seen_ns: o.uint("last_seen_ns")?,
        evidence: MechanismEvidence {
            functions: e.strings("functions")?,
            returns,
            truncated: e.boolean("truncated")?,
        },
    })
}
fn parse_operations(o: &Object<'_>) -> Result<Operations> {
    let e = o.object("evidence")?;
    let active = o
        .array("active")?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let a = Object::new(v, format!("{}.active[{i}]", o.path))?;
            Ok(ActiveOperation {
                category: a.text("category")?,
                state: a.label("state", &["initialized", "in_progress"])?,
                count: a.uint("count")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Operations {
        calls: o.uint("calls")?,
        started: o.uint("started")?,
        completed: o.uint("completed")?,
        cancelled: o.uint("cancelled")?,
        failed: o.uint("failed")?,
        unknown: o.uint("unknown")?,
        orphans: o.uint("orphans")?,
        dropped: o.uint("dropped")?,
        last_seen_ns: o.uint("last_seen_ns")?,
        active,
        evidence: OperationEvidence {
            state_reconciliations: e.uint("state_reconciliations")?,
            session_cancel_ambiguities: e.uint("session_cancel_ambiguities")?,
            session_cancel_unknown_flags: e.uint("session_cancel_unknown_flags")?,
            operation_state_imports: e.uint("operation_state_imports")?,
            auth_state_ambiguities: e.uint("auth_state_ambiguities")?,
            semantic_capture_failures: e.uint("semantic_capture_failures")?,
            async_duplicates: e.uint("async_duplicates")?,
            async_evictions: e.uint("async_evictions")?,
            unmatched_closes: e.uint("unmatched_closes")?,
        },
    })
}
