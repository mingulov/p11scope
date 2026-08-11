//! Semantic state machine: turns a stream of completed `Event`s into
//! meaning — mechanisms, session lifecycle, logins, per-function counts —
//! while pseudonymizing every session handle as it is consumed. Raw
//! handles live only in the in-memory maps below; no accessor on `State`
//! returns one.

use crate::plan::AttachPlan;
use p11scope_ebpf_common::{Event, LATENCY_BUCKETS, MECH_NONE, SESSION_NONE, USER_TYPE_NONE, bucket_of, fnkind};
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
}

/// Per function-name call/error counts, derived from the event stream.
/// The aggregate maps in `metrics.rs` remain the authority for totals;
/// this is the event-derived view.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FnStat {
    pub calls: u64,
    pub errors: u64,
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
    /// Joined function name(s) — `"C_Sign"`, or `"C_A|C_B"` for an
    /// aliased slot whose names share a target.
    label: String,
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
    logins: BTreeMap<u32, u64>,
    functions: BTreeMap<String, FnStat>,
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
                label: slot.names.join("|"),
                is_close_session: slot.names.iter().any(|n| n == "C_CloseSession"),
                is_final: slot.names.iter().any(|n| n.ends_with("Final")),
                ops: slot.names.iter().filter_map(|n| op_of_init_name(n)).map(String::from).collect(),
            });
        }
        Self {
            slots,
            next_pseudonym: BTreeMap::new(),
            pseudonym_of: BTreeMap::new(),
            open: BTreeSet::new(),
            active_op: BTreeMap::new(),
            mechanisms: BTreeMap::new(),
            logins: BTreeMap::new(),
            functions: BTreeMap::new(),
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
        let label = meta.map(|m| m.label.clone());
        let is_close_session = meta.map(|m| m.is_close_session).unwrap_or(false);
        let is_final = meta.map(|m| m.is_final).unwrap_or(false);

        if let Some(label) = label {
            let stat = self.functions.entry(label).or_default();
            stat.calls += 1;
            if ev.rv != 0 {
                stat.errors += 1;
            }
        }

        match ev.kind {
            fnkind::OPEN_SESSION => self.observe_open_session(pid, ev),
            fnkind::INIT_WITH_MECH => self.observe_init(pid, ev),
            fnkind::SESSION_ARG0 => self.observe_session_arg0(pid, ev, is_close_session, is_final),
            fnkind::LOGIN => self.observe_login(ev),
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

    pub fn mechanisms(&self) -> &BTreeMap<u64, MechStat> {
        &self.mechanisms
    }

    pub fn sessions(&self) -> SessionStats {
        self.sessions
    }

    pub fn logins(&self) -> &BTreeMap<u32, u64> {
        &self.logins
    }

    pub fn functions(&self) -> &BTreeMap<String, FnStat> {
        &self.functions
    }

    pub fn orphan_ops(&self) -> u64 {
        self.orphan_ops
    }

    pub fn unmatched_closes(&self) -> u64 {
        self.unmatched_closes
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
            slot,
            kind,
            user_type: USER_TYPE_NONE,
            _pad: 0,
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
            slot: 5,
            kind: fnkind::LOGIN,
            user_type,
            _pad: 0,
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
    fn test_plan() -> AttachPlan {
        AttachPlan {
            slots: vec![
                slot(0, &["C_OpenSession"], fnkind::OPEN_SESSION),
                slot(1, &["C_CloseSession"], fnkind::SESSION_ARG0),
                slot(2, &["C_SignInit"], fnkind::INIT_WITH_MECH),
                slot(3, &["C_Sign"], fnkind::SESSION_ARG0),
                slot(4, &["C_SignFinal"], fnkind::SESSION_ARG0),
                slot(5, &["C_Login"], fnkind::LOGIN),
            ],
            skipped: vec![],
            entries_seen: 6,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
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
    fn functions_count_calls_and_errors_by_name() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 5)); // C_Sign ok
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 1, 5)); // C_Sign error
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 5)); // C_SignInit

        let sign = s.functions().get("C_Sign").unwrap();
        assert_eq!(sign.calls, 2);
        assert_eq!(sign.errors, 1);
        assert_eq!(s.functions().get("C_SignInit").unwrap().calls, 1);
    }
}
