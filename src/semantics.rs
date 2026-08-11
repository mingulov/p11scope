//! Semantic state machine: turns a stream of completed `Event`s into
//! meaning — mechanisms, session lifecycle, logins, per-function counts —
//! while pseudonymizing every session handle as it is consumed. Raw
//! handles live only in the in-memory maps below; no accessor on `State`
//! returns one.

use crate::plan::AttachPlan;
use p11scope_ebpf_common::{
    Event, LATENCY_BUCKETS, MECH_NONE, SESSION_NONE, USER_TYPE_NONE, bucket_of, fnkind, shape,
};
use std::collections::{BTreeMap, BTreeSet};

/// Aggregate stats for one mechanism id, kept **verbatim** as `u64` —
/// vendor ids like `0x80001042` must survive unchanged.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MechStat {
    pub calls: u64,
    pub errors: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
    pub total_ns: u64,
    pub max_ns: u64,
    /// Operation categories (`"sign"`, `"encrypt"`, ...) this mechanism id
    /// was seen initializing, derived from the `*Init` function name(s)
    /// at the slot that recorded it. A set, not a scalar: the same
    /// mechanism id can legally serve more than one operation kind.
    pub ops: BTreeSet<String>,
    /// Distinct decoded parameter combinations observed on `*Init` calls
    /// for this mechanism, keyed by `(shape code, p0, p1, p2)` with each
    /// combination's occurrence count. A map, not a single "latest" or
    /// averaged value: migration assessment needs the actual combos a
    /// mechanism was driven with, not a summary that could hide a
    /// weaker one. Only entries whose decode applied (`shape !=
    /// shape::NONE`) are recorded here.
    pub param_combos: BTreeMap<(u32, u64, u64, u64), u64>,
    /// `*Init` calls for this mechanism whose parameter decode did not
    /// apply (`Event::shape == shape::NONE`). Combined with
    /// `param_combos` being non-empty (this mechanism id *did* decode
    /// successfully at least once this capture), a nonzero count here is
    /// evidence of an inconsistent/failed decode on some calls — see
    /// `State::shape_decode_failures`. When `param_combos` is empty this
    /// mechanism simply has no decodable shape (or none observed), which
    /// is not a failure.
    pub init_no_shape: u64,
}

/// Aggregate stats for one template-bearing operation (`C_FindObjectsInit`,
/// `C_CreateObject`, `C_GenerateKey`, ...), keyed by attach slot — the same
/// grouping `functions[]` uses, so an aliased slot's calls stay one entry.
/// Carries only what the application *asked for*: attribute types and the
/// policy-boolean allowlist observed on those templates, never a value
/// beyond the allowlisted booleans, and never the key's effective policy
/// (see module docs on the requested-vs-effective distinction).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TemplateStat {
    /// Every distinct function name resolving to this slot.
    pub names: Vec<String>,
    pub aliased: bool,
    /// Union of attribute *types* requested across every observed call.
    pub attr_types: BTreeSet<u32>,
    /// Bit set (`attr_bool` positions) => this policy-boolean attribute
    /// was observed present-and-true on at least one call.
    pub bools_true: u32,
    /// Bit set => observed present-and-false on at least one call.
    /// Independent of `bools_true`: a bit can be set in both when
    /// different calls asked for different values, and that is
    /// legitimate, distinguishable evidence, not an error.
    pub bools_false: u32,
    /// True when any observed call had `attr_total > attr_count`: either
    /// the template had more entries than the capture's per-event cap
    /// (`MAX_ATTRS`), or the in-kernel walk stopped early on a
    /// `bpf_probe_read_user` failure (an unreadable `pTemplate`/entry) —
    /// both leave `attr_count` short of `attr_total`, and this field does
    /// not distinguish which. Either way it is lost evidence: some
    /// attribute types the application requested were not captured.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionStats {
    pub opened: u64,
    pub closed: u64,
    pub peak_concurrent: u64,
}

/// Per-slot facts `observe` needs on every event, resolved once from the
/// `AttachPlan` so the hot path never re-scans it.
struct SlotMeta {
    /// Every distinct function name resolving to this slot.
    names: Vec<String>,
    /// True for the slot that resolves `C_CloseSession` — the one
    /// `SESSION_ARG0` call that ends a session rather than operating on
    /// one.
    is_close_session: bool,
    /// True when any name at this slot is a `*Final` call: it still
    /// attributes latency to the active operation, but also ends it.
    is_final: bool,
    /// Operation categories named by this slot's `*Init` function(s), if
    /// any — empty for slots that are not `INIT_WITH_MECH`.
    ops: Vec<String>,
    /// True when >= 2 distinct names share this slot.
    aliased: bool,
}

/// Maps a `*Init` function name to the operation category it starts.
/// Anything not recognized (including non-`*Init` names, reached only if
/// a caller passes one) is dropped rather than guessed.
fn op_of_init_name(name: &str) -> Option<&'static str> {
    match name {
        "C_DigestInit" => Some("digest"),
        "C_SignInit" => Some("sign"),
        "C_VerifyInit" => Some("verify"),
        "C_EncryptInit" => Some("encrypt"),
        "C_DecryptInit" => Some("decrypt"),
        "C_SignRecoverInit" => Some("sign_recover"),
        "C_VerifyRecoverInit" => Some("verify_recover"),
        _ => None,
    }
}

/// Turns raw `Event`s into pseudonymized, semantic state. Construct once
/// per capture from the `AttachPlan`, then feed it every completed event.
pub struct State {
    slots: Vec<Option<SlotMeta>>,

    /// pid -> next pseudonym to allocate. Pseudonyms are 1-based and
    /// allocated in first-seen order, independently per pid.
    next_pseudonym: BTreeMap<u32, u64>,
    /// (pid, raw handle) -> pseudonym currently naming that handle. Never
    /// serialized; exists only so a later event on the same handle
    /// resolves to the same session identity.
    pseudonym_of: BTreeMap<(u32, u64), u64>,
    /// (pid, raw handle) currently open.
    open: BTreeSet<(u32, u64)>,
    /// (pid, raw handle) -> mechanism bound by the session's last *Init,
    /// if any operation is currently active.
    active_op: BTreeMap<(u32, u64), u64>,

    mechanisms: BTreeMap<u64, MechStat>,
    /// Template-bearing operations, keyed by attach slot.
    templates: BTreeMap<u32, TemplateStat>,
    logins: BTreeMap<u32, u64>,
    sessions: SessionStats,
    orphan_ops: u64,
    unmatched_closes: u64,
}

fn pid_of(ev: &Event) -> u32 {
    // bpf_get_current_pid_tgid(): tgid (the process id) in the high
    // 32 bits, thread id in the low 32 — matches PID_FILTER's scoping.
    (ev.pid_tgid >> 32) as u32
}

impl State {
    pub fn new(plan: &AttachPlan) -> Self {
        let mut slots: Vec<Option<SlotMeta>> = Vec::new();
        for slot in &plan.slots {
            let idx = slot.index as usize;
            if idx >= slots.len() {
                slots.resize_with(idx + 1, || None);
            }
            slots[idx] = Some(SlotMeta {
                names: slot.names.clone(),
                is_close_session: slot.names.iter().any(|n| n == "C_CloseSession"),
                is_final: slot.names.iter().any(|n| n.ends_with("Final")),
                ops: slot.names.iter().filter_map(|n| op_of_init_name(n)).map(String::from).collect(),
                aliased: slot.aliased,
            });
        }
        Self {
            slots,
            next_pseudonym: BTreeMap::new(),
            pseudonym_of: BTreeMap::new(),
            open: BTreeSet::new(),
            active_op: BTreeMap::new(),
            mechanisms: BTreeMap::new(),
            templates: BTreeMap::new(),
            logins: BTreeMap::new(),
            sessions: SessionStats::default(),
            orphan_ops: 0,
            unmatched_closes: 0,
        }
    }

    pub fn observe(&mut self, ev: &Event) {
        let pid = pid_of(ev);
        let meta = self.slots.get(ev.slot as usize).and_then(|s| s.as_ref());
        // Copy out the bits `observe_*` need up front: holding a `&SlotMeta`
        // borrowed from `self.slots` across a `&mut self` call doesn't
        // typecheck, and these are cheap enough to not warrant an index.
        let is_close_session = meta.map(|m| m.is_close_session).unwrap_or(false);
        let is_final = meta.map(|m| m.is_final).unwrap_or(false);

        match ev.kind {
            fnkind::OPEN_SESSION => self.observe_open_session(pid, ev),
            fnkind::INIT_WITH_MECH => self.observe_init(pid, ev),
            fnkind::SESSION_ARG0 => self.observe_session_arg0(pid, ev, is_close_session, is_final),
            fnkind::LOGIN => self.observe_login(ev),
            fnkind::TEMPLATE_ARG1 | fnkind::TEMPLATE_ARG2 => self.observe_template(ev),
            _ => {}
        }
    }

    fn observe_open_session(&mut self, pid: u32, ev: &Event) {
        if ev.rv != 0 || ev.session == SESSION_NONE {
            return;
        }
        let key = (pid, ev.session);
        let counter = self.next_pseudonym.entry(pid).or_insert(0);
        *counter += 1;
        self.pseudonym_of.insert(key, *counter);
        // A raw handle can be reused for a new logical session once the
        // old one closes; drop any stale binding so it can't leak in.
        self.active_op.remove(&key);
        self.open.insert(key);
        self.sessions.opened += 1;
        self.sessions.peak_concurrent = self.sessions.peak_concurrent.max(self.open.len() as u64);
    }

    fn observe_init(&mut self, pid: u32, ev: &Event) {
        // A new *Init always clears whatever was bound before, whether or
        // not it names a mechanism. Without this, an Init whose pMechanism
        // read failed (MECH_NONE — null pointer, unfaulted page, an
        // anticipated capture-failure mode, not hypothetical) would leave
        // the *previous* mechanism bound, and the next operational call
        // would be silently attributed to it instead of surfacing as an
        // orphan — the capture would look more complete than it was.
        if ev.session != SESSION_NONE {
            self.active_op.remove(&(pid, ev.session));
        }
        if ev.mechanism == MECH_NONE {
            return;
        }
        let ops = self.slots.get(ev.slot as usize).and_then(|s| s.as_ref()).map(|m| m.ops.clone());
        let stat = self.mechanisms.entry(ev.mechanism).or_default();
        record_call(stat, ev);
        if let Some(ops) = ops {
            stat.ops.extend(ops);
        }
        // Decoded parameters are requested-values evidence, same as the
        // mechanism id itself: recorded regardless of `rv`. Only a
        // successful decode (`shape != NONE`) adds a combo; everything
        // else is counted as a no-decode `*Init`, which only becomes
        // interesting evidence (`State::shape_decode_failures`) once this
        // mechanism id has decoded successfully at least once elsewhere.
        if ev.shape != shape::NONE {
            *stat.param_combos.entry((ev.shape, ev.p0, ev.p1, ev.p2)).or_insert(0) += 1;
        } else {
            stat.init_no_shape += 1;
        }
        // The application genuinely requested this mechanism, so it is
        // recorded above regardless of outcome — but a failed Init starts
        // no operation, so only a successful one binds the session.
        if ev.rv == 0 && ev.session != SESSION_NONE {
            self.active_op.insert((pid, ev.session), ev.mechanism);
        }
    }

    fn observe_session_arg0(&mut self, pid: u32, ev: &Event, is_close: bool, is_final: bool) {
        let key = (pid, ev.session);
        if is_close {
            if ev.rv != 0 {
                return;
            }
            if self.open.remove(&key) {
                self.sessions.closed += 1;
            } else {
                self.unmatched_closes += 1;
            }
            self.pseudonym_of.remove(&key);
            self.active_op.remove(&key);
            return;
        }
        // Operational call: attribute to the session's active mechanism,
        // or count as an orphan — evidence capture started mid-operation.
        match self.active_op.get(&key).copied() {
            Some(mech) => {
                record_call(self.mechanisms.entry(mech).or_default(), ev);
                if is_final {
                    self.active_op.remove(&key);
                }
            }
            None => self.orphan_ops += 1,
        }
    }

    fn observe_login(&mut self, ev: &Event) {
        if ev.user_type != USER_TYPE_NONE {
            *self.logins.entry(ev.user_type).or_insert(0) += 1;
        }
    }

    /// `C_FindObjectsInit` / `C_CreateObject` / `C_GenerateKey` — templates
    /// are recorded regardless of `rv`, same rationale as mechanisms: the
    /// application asked for these attributes, and that is the evidence,
    /// independent of whether the call succeeded.
    fn observe_template(&mut self, ev: &Event) {
        let Some(meta) = self.slots.get(ev.slot as usize).and_then(|s| s.as_ref()) else {
            return;
        };
        let stat = self.templates.entry(ev.slot).or_insert_with(|| TemplateStat {
            names: meta.names.clone(),
            aliased: meta.aliased,
            ..Default::default()
        });
        let count = (ev.attr_count as usize).min(ev.attr_types.len());
        for &attr_type in &ev.attr_types[..count] {
            stat.attr_types.insert(attr_type);
        }
        stat.bools_true |= ev.attr_bools & ev.attr_bools_seen;
        stat.bools_false |= ev.attr_bools_seen & !ev.attr_bools;
        if ev.attr_total > ev.attr_count {
            stat.truncated = true;
        }
    }

    pub fn mechanisms(&self) -> &BTreeMap<u64, MechStat> {
        &self.mechanisms
    }

    pub fn templates(&self) -> &BTreeMap<u32, TemplateStat> {
        &self.templates
    }

    pub fn sessions(&self) -> SessionStats {
        self.sessions
    }

    pub fn logins(&self) -> &BTreeMap<u32, u64> {
        &self.logins
    }

    pub fn orphan_ops(&self) -> u64 {
        self.orphan_ops
    }

    pub fn unmatched_closes(&self) -> u64 {
        self.unmatched_closes
    }

    /// True when any template-bearing operation observed `attr_total >
    /// attr_count` in this capture — either a template longer than the
    /// per-event cap, or the in-kernel walk stopping early on a read
    /// failure (see `TemplateStat::truncated`); both are lost evidence.
    /// Feeds `evidence.templates_truncated`, a `completeness` gap.
    pub fn templates_truncated(&self) -> bool {
        self.templates.values().any(|t| t.truncated)
    }

    /// `*Init` calls whose parameter decode did not apply, for mechanism
    /// ids that decoded successfully **at least once** elsewhere in this
    /// capture — an inconsistent-decode signal, not a completeness gap
    /// (see `MechStat::init_no_shape`). A mechanism id that never decoded
    /// **at all** — including one whose *every* decode attempt failed —
    /// contributes nothing here: distinguishing "no decodable shape" from
    /// "a decodable shape that failed on every single call" needs the
    /// registry (which id→shape mapping was published), and this
    /// accessor only has the event stream. This is a deliberate, disclosed
    /// blind spot, not an oversight — see `docs/schema/observed-profile-v1.md`
    /// ("`params` in v1.1" and the `shape_decode_failures` evidence row).
    pub fn shape_decode_failures(&self) -> u64 {
        self.mechanisms
            .values()
            .filter(|m| !m.param_combos.is_empty())
            .map(|m| m.init_no_shape)
            .sum()
    }
}

fn record_call(stat: &mut MechStat, ev: &Event) {
    stat.calls += 1;
    if ev.rv != 0 {
        stat.errors += 1;
    }
    stat.buckets[bucket_of(ev.duration_ns) as usize] += 1;
    stat.total_ns += ev.duration_ns;
    stat.max_ns = stat.max_ns.max(ev.duration_ns);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Slot;

    fn pid_tgid(pid: u32) -> u64 {
        ((pid as u64) << 32) | 0xABCD
    }

    fn ev(pid: u32, slot: u32, kind: u32, session: u64, mechanism: u64, rv: u64, duration_ns: u64) -> Event {
        Event {
            ts_ns: 0,
            duration_ns,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session,
            mechanism,
            rv,
            p0: 0,
            p1: 0,
            p2: 0,
            slot,
            kind,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
        }
    }

    fn login_ev(pid: u32, user_type: u32) -> Event {
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session: SESSION_NONE,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 5,
            kind: fnkind::LOGIN,
            user_type,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
        }
    }

    fn slot(index: u32, names: &[&str], kind: u32) -> Slot {
        Slot {
            index,
            object: "/opt/p11.so".into(),
            file_offset: index as u64 * 0x10,
            names: names.iter().map(|s| s.to_string()).collect(),
            aliased: names.len() >= 2,
            kind,
        }
    }

    // Slot layout shared by the tests below:
    // 0 C_OpenSession   1 C_CloseSession   2 C_SignInit
    // 3 C_Sign          4 C_SignFinal      5 C_Login
    // 6 C_FindObjectsInit (template)
    fn test_plan() -> AttachPlan {
        AttachPlan {
            slots: vec![
                slot(0, &["C_OpenSession"], fnkind::OPEN_SESSION),
                slot(1, &["C_CloseSession"], fnkind::SESSION_ARG0),
                slot(2, &["C_SignInit"], fnkind::INIT_WITH_MECH),
                slot(3, &["C_Sign"], fnkind::SESSION_ARG0),
                slot(4, &["C_SignFinal"], fnkind::SESSION_ARG0),
                slot(5, &["C_Login"], fnkind::LOGIN),
                slot(6, &["C_FindObjectsInit"], fnkind::TEMPLATE_ARG1),
            ],
            skipped: vec![],
            entries_seen: 7,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
        }
    }

    /// An `*Init` event carrying a decoded (or not-decoded) parameter shape.
    fn ev_shape(
        pid: u32,
        session: u64,
        mechanism: u64,
        rv: u64,
        shape_code: u32,
        params: (u64, u64, u64),
    ) -> Event {
        let (p0, p1, p2) = params;
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session,
            mechanism,
            rv,
            p0,
            p1,
            p2,
            slot: 2,
            kind: fnkind::INIT_WITH_MECH,
            user_type: USER_TYPE_NONE,
            shape: shape_code,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
        }
    }

    /// A `C_FindObjectsInit`-shaped template event on slot 6.
    fn ev_template(
        pid: u32,
        attr_types: &[u32],
        attr_total: u32,
        attr_bools: u32,
        attr_bools_seen: u32,
    ) -> Event {
        let mut types = [0u32; 8];
        for (i, &t) in attr_types.iter().enumerate() {
            types[i] = t;
        }
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session: 10,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 6,
            kind: fnkind::TEMPLATE_ARG1,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: types,
            attr_count: attr_types.len() as u32,
            attr_total,
            attr_bools,
            attr_bools_seen,
        }
    }

    #[test]
    fn open_close_balance_and_peak_concurrent() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5)); // open A
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 20, MECH_NONE, 0, 5)); // open B
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 5)); // close A

        let stats = s.sessions();
        assert_eq!(stats.opened, 2);
        assert_eq!(stats.closed, 1);
        assert_eq!(stats.peak_concurrent, 2, "both sessions were open at once");
        assert_eq!(s.unmatched_closes(), 0);
    }

    #[test]
    fn close_without_matching_open_is_unmatched_evidence() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 99, MECH_NONE, 0, 5)); // close, never opened

        assert_eq!(s.unmatched_closes(), 1);
        assert_eq!(s.sessions().closed, 0, "an unmatched close must not inflate the balance");
    }

    #[test]
    fn init_then_operational_call_attributes_to_same_mechanism() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 200)); // C_Sign

        let m = s.mechanisms().get(&0x250).expect("mechanism recorded");
        assert_eq!(m.calls, 2, "the init call and the following op both count");
        assert_eq!(m.errors, 0);
        assert_eq!(m.buckets.iter().sum::<u64>(), 2);
        assert_eq!(s.orphan_ops(), 0);
    }

    #[test]
    fn operational_call_with_no_active_init_is_orphan() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 200)); // C_Sign, no prior Init

        assert_eq!(s.orphan_ops(), 1);
        assert!(s.mechanisms().is_empty(), "an orphan op names no mechanism — never a guess");
    }

    #[test]
    fn init_records_op_and_exact_latency_totals() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit, 100ns
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 300)); // C_SignInit again, 300ns

        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.ops.iter().collect::<Vec<_>>(), vec!["sign"]);
        assert_eq!(m.total_ns, 400);
        assert_eq!(m.max_ns, 300);
    }

    #[test]
    fn init_with_failed_mechanism_read_clears_the_stale_binding() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit binds 0x250
        // A second Init whose pMechanism read failed (kernel reports
        // MECH_NONE) must drop that binding, not leave 0x250 bound.
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, MECH_NONE, 0, 10));
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        assert_eq!(s.orphan_ops(), 1, "must not inherit the stale 0x250 binding");
        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.calls, 1, "only the first, successful Init is recorded");
    }

    #[test]
    fn failed_init_records_the_mechanism_but_does_not_bind_the_operation() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit succeeds, binds 0x250
        // A second Init with a different mechanism that fails (rv != 0) must
        // drop the 0x250 binding, not leave it bound.
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x251, 7, 10)); // C_SignInit fails, rv=7
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        assert_eq!(s.orphan_ops(), 1, "a failed Init clears the stale binding");
        let m250 = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m250.calls, 1, "only the first, successful Init is recorded");
        let m251 = s.mechanisms().get(&0x251).expect("the failed attempt is still evidence");
        assert_eq!(m251.calls, 1);
        assert_eq!(m251.errors, 1);
    }

    #[test]
    fn vendor_mechanism_id_survives_verbatim() {
        let mut s = State::new(&test_plan());
        let vendor_id: u64 = 0x80001042;
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, vendor_id, 0, 100));

        assert!(s.mechanisms().contains_key(&vendor_id));
        assert_eq!(format!("{:#x}", vendor_id), "0x80001042");
    }

    #[test]
    fn two_pids_do_not_share_pseudonyms_or_session_state() {
        let mut s = State::new(&test_plan());
        // Same raw handle value (5), different pids — must not collide.
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 5, MECH_NONE, 0, 5));
        s.observe(&ev(200, 0, fnkind::OPEN_SESSION, 5, MECH_NONE, 0, 5));

        assert_eq!(s.sessions().opened, 2);
        assert_eq!(s.sessions().peak_concurrent, 2);
        // Each pid gets its own first-seen numbering, independently.
        assert_eq!(s.pseudonym_of.get(&(100, 5)), Some(&1));
        assert_eq!(s.pseudonym_of.get(&(200, 5)), Some(&1));

        // Closing pid 100's session must not touch pid 200's.
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.sessions().closed, 1);
        assert_eq!(s.unmatched_closes(), 0);

        // A second close from pid 100 on the same (already-closed) handle
        // is unmatched — it must not borrow pid 200's still-open session.
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.unmatched_closes(), 1);

        s.observe(&ev(200, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.sessions().closed, 2);
        assert_eq!(s.unmatched_closes(), 1, "pid 200's valid close must not be miscounted");
    }

    #[test]
    fn final_call_clears_the_active_operation() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit
        s.observe(&ev(100, 4, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_SignFinal
        // No Init in between — this must now be an orphan.
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.calls, 2, "init + final, not the post-final orphan");
        assert_eq!(s.orphan_ops(), 1);
    }

    #[test]
    fn login_records_user_type_counts_only() {
        let mut s = State::new(&test_plan());
        s.observe(&login_ev(100, 1));
        s.observe(&login_ev(100, 0));
        s.observe(&login_ev(100, 1));

        assert_eq!(s.logins().get(&1), Some(&2));
        assert_eq!(s.logins().get(&0), Some(&1));
    }

    #[test]
    fn distinct_param_combos_are_recorded_with_their_own_counts() {
        let mut s = State::new(&test_plan());
        // Same mechanism, same combo, twice.
        s.observe(&ev_shape(100, 10, 0x0D, 0, shape::RSA_PKCS_PSS, (0x270, 1, 32)));
        s.observe(&ev_shape(100, 10, 0x0D, 0, shape::RSA_PKCS_PSS, (0x270, 1, 32)));
        // Same mechanism, a different salt length: a distinct combo, not an
        // average or a "latest wins" overwrite.
        s.observe(&ev_shape(100, 10, 0x0D, 0, shape::RSA_PKCS_PSS, (0x270, 1, 64)));

        let m = s.mechanisms().get(&0x0D).unwrap();
        assert_eq!(m.param_combos.len(), 2, "two distinct combos, not merged");
        assert_eq!(m.param_combos.get(&(shape::RSA_PKCS_PSS, 0x270, 1, 32)), Some(&2));
        assert_eq!(m.param_combos.get(&(shape::RSA_PKCS_PSS, 0x270, 1, 64)), Some(&1));
        assert_eq!(m.init_no_shape, 0);
    }

    #[test]
    fn shape_decode_failures_only_count_mechanisms_that_decoded_at_least_once() {
        let mut s = State::new(&test_plan());
        // Mechanism 0x1087 (GCM) decodes once, then fails to decode once —
        // the failure is now interesting evidence.
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::GCM, (12, 0, 128)));
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::NONE, (0, 0, 0)));
        // Mechanism 0x9999 never decodes at all — an ordinary id-only
        // mechanism, not a failure.
        s.observe(&ev_shape(100, 10, 0x9999, 0, shape::NONE, (0, 0, 0)));

        assert_eq!(s.shape_decode_failures(), 1);
        let gcm = s.mechanisms().get(&0x1087).unwrap();
        assert_eq!(gcm.init_no_shape, 1);
        let unshaped = s.mechanisms().get(&0x9999).unwrap();
        assert_eq!(unshaped.init_no_shape, 1);
        assert!(unshaped.param_combos.is_empty());
    }

    #[test]
    fn template_attribute_types_and_policy_booleans_render_the_tristate_unambiguously() {
        use p11scope_ebpf_common::attr_bool;

        let mut s = State::new(&test_plan());
        // Call 1: CKA_TOKEN (0x01) true, CKA_PRIVATE (0x02) present-but-false.
        s.observe(&ev_template(
            100,
            &[0x01, 0x02],
            2,
            attr_bool::TOKEN,
            attr_bool::TOKEN | attr_bool::PRIVATE,
        ));
        // Call 2: CKA_SIGN (0x108) never appears at all — must stay absent
        // from both true and false, not default to false.
        s.observe(&ev_template(100, &[0x01], 1, attr_bool::TOKEN, attr_bool::TOKEN));

        let t = s.templates().get(&6).expect("slot 6 recorded");
        assert_eq!(t.names, vec!["C_FindObjectsInit".to_string()]);
        assert!(!t.aliased);
        assert_eq!(t.attr_types, BTreeSet::from([0x01, 0x02]));
        assert_eq!(t.bools_true & attr_bool::TOKEN, attr_bool::TOKEN, "seen and true");
        assert_eq!(t.bools_false & attr_bool::PRIVATE, attr_bool::PRIVATE, "seen and false");
        assert_eq!(t.bools_true & attr_bool::SIGN, 0, "never present — not true");
        assert_eq!(t.bools_false & attr_bool::SIGN, 0, "never present — not false either");
        assert!(!t.truncated);
    }

    #[test]
    fn template_truncation_is_recorded_per_call_and_surfaced_by_the_aggregate_accessor() {
        let mut s = State::new(&test_plan());
        assert!(!s.templates_truncated(), "nothing observed yet");

        // attr_total (10) > attr_count (8, the MAX_ATTRS cap already applied
        // by ev_template's slice length) — a template longer than the cap.
        s.observe(&ev_template(100, &[0x01; 8], 10, 0, 0));

        assert!(s.templates_truncated());
        let t = s.templates().get(&6).unwrap();
        assert!(t.truncated);
    }
}
