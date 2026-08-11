//! `trace` renderer: one line per completed call, in arrival order — the
//! per-investigation counterpart to `profile`'s aggregate report
//! (`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`, "Trace
//! mode"). Reuses `render::param_combo_json` for parameter decoding so
//! the same privacy allowlist governs both renderers by construction,
//! not by two independently-maintained implementations, and reuses
//! `semantics::State`'s session-pseudonym machinery so a raw handle is
//! never rendered.

use crate::plan::AttachPlan;
use crate::render;
use crate::semantics::State;
use p11scope_ebpf_common::{Event, MECH_NONE, SESSION_NONE, fnkind, shape};
use std::time::{SystemTime, UNIX_EPOCH};

/// `pid_tgid` (`bpf_get_current_pid_tgid()`) -> (pid, tid): tgid (process
/// id) in the high 32 bits, thread id in the low 32.
fn pid_tid(pid_tgid: u64) -> (u32, u32) {
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

/// Function name(s) at a slot, from the attach plan — the same grouping
/// `render::label` uses for aliased slots, joined the same way.
fn function_name(plan: &AttachPlan, slot: u32) -> String {
    plan.slots
        .iter()
        .find(|s| s.index == slot)
        .map(|s| s.names.join("|"))
        .unwrap_or_else(|| format!("slot#{slot}"))
}

/// A small, honest name table for the two mechanism ids this capture
/// also decodes parameters for (`render::param_combo_json`'s
/// `rsa_pkcs_pss`/`gcm` shapes) — sourced from the same
/// `pkcs11-proxy-ng-types` crate the rest of this codebase already
/// depends on, not a re-derived literal. No general CKM_* id -> name
/// registry exists anywhere in this codebase or its dependencies to
/// reuse (verified: `pkcs11_proxy_ng_types::mechanism_registry` maps ids
/// to *shape* names like `"gcm"`, never to `CKM_*` display names).
/// Every other mechanism, known or vendor, renders verbatim as `0x…`,
/// same as the "unknown mechanism" case — honest rather than guessed.
/// ponytail: bounded to the two decoded shapes; add a full CKM_* name
/// table if trace readability for non-decoded, non-PSS/GCM mechanisms
/// ever becomes a real ask.
fn mechanism_name(id: u64) -> Option<&'static str> {
    match id {
        _ if id == pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS_PSS.0 => Some("CKM_RSA_PKCS_PSS"),
        _ if id == pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0 => Some("CKM_AES_GCM"),
        _ => None,
    }
}

fn mechanism_label(id: u64) -> String {
    mechanism_name(id).map(str::to_string).unwrap_or_else(|| format!("0x{id:x}"))
}

/// Standard PKCS#11 hash-algorithm mechanism ids that can appear as the
/// `hashAlg` field of `CK_RSA_PKCS_PSS_PARAMS`. Fixed, standardized
/// values (OASIS PKCS#11 v3.02 `pkcs11t.h`), not vendor-specific — safe
/// to hardcode. Unrecognized ids render as `0x…`, never guessed.
fn hash_alg_name(id: u64) -> String {
    match id {
        0x0000_0220 => "SHA1".into(),
        0x0000_0255 => "SHA224".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA256.0 => "SHA256".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA384.0 => "SHA384".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA512.0 => "SHA512".into(),
        _ => format!("0x{id:x}"),
    }
}

/// Standard `CKG_MGF1_*` values (OASIS PKCS#11 v3.02 `pkcs11t.h`).
fn mgf_name(id: u64) -> String {
    match id {
        0x1 => "MGF1_SHA1".into(),
        0x2 => "MGF1_SHA256".into(),
        0x3 => "MGF1_SHA384".into(),
        0x4 => "MGF1_SHA512".into(),
        0x5 => "MGF1_SHA224".into(),
        _ => format!("0x{id:x}"),
    }
}

/// Mechanism + decoded parameters, e.g. `CKM_RSA_PKCS_PSS(hash=SHA256
/// mgf=MGF1_SHA256 salt=32)`. The decode itself is `render::
/// param_combo_json` — the exact function `profile`'s JSON report calls
/// — so a shape this phase does not decode (or ever stops decoding)
/// yields no parameters here either, by construction.
fn render_mechanism(ev: &Event) -> String {
    let label = mechanism_label(ev.mechanism);
    if ev.shape == shape::NONE {
        return label;
    }
    let Some(v) = render::param_combo_json(ev.shape, ev.p0, ev.p1, ev.p2, 1) else {
        return label;
    };
    let params = match v.get("shape").and_then(|s| s.as_str()) {
        Some("rsa_pkcs_pss") => {
            format!("hash={} mgf={} salt={}", hash_alg_name(ev.p0), mgf_name(ev.p1), ev.p2)
        }
        Some("gcm") => format!("iv_len={} aad_len={} tag_bits={}", ev.p0, ev.p1, ev.p2),
        _ => return label,
    };
    format!("{label}({params})")
}

fn rv_name(rv: u64) -> String {
    // Reuses proxy-ng's CKR_* name table (`CkRv`'s `Display`) rather than
    // a second one; its format is "CKR_OK (0x00000000)" — only the name
    // is wanted here, the trace line carries the outcome, not the code.
    let s = pkcs11_proxy_ng_types::CkRv(rv).to_string();
    s.split(" (").next().unwrap_or(&s).to_string()
}

fn fmt_wall_time(wall_ns: u128) -> String {
    let secs_total = (wall_ns / 1_000_000_000) as u64;
    let sub_ns = (wall_ns % 1_000_000_000) as u32;
    let secs_of_day = secs_total % 86_400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    format!("{h:02}:{m:02}:{s:02}.{:06}", sub_ns / 1_000)
}

/// One trace line, in the design spec's shape:
/// `HH:MM:SS.ffffff pid P tid T [sess#N] FUNCTION[ MECHANISM] → CKR_x DURATION`.
/// A pure function — no I/O, no shared state — so it is directly
/// testable: given a known `Event` and its resolved wall-clock time,
/// function name, and session pseudonym, it always renders the same line.
pub fn format_line(ev: &Event, wall_ns: u128, function: &str, session: Option<u64>) -> String {
    let (pid, tid) = pid_tid(ev.pid_tgid);
    let mut line = format!("{} pid {pid} tid {tid}", fmt_wall_time(wall_ns));
    if let Some(n) = session {
        line.push_str(&format!(" sess#{n}"));
    }
    line.push_str(&format!(" {function}"));
    if ev.kind == fnkind::INIT_WITH_MECH && ev.mechanism != MECH_NONE {
        line.push(' ');
        line.push_str(&render_mechanism(ev));
    }
    line.push_str(&format!(" \u{2192} {} {}", rv_name(ev.rv), render::fmt_ns(Some(ev.duration_ns))));
    line
}

/// `LOST n events` when the ring buffer dropped anything — mandatory
/// whenever `n > 0`; a trace that lost events must never end silently.
/// `None` when nothing was lost, so a caller can skip printing rather
/// than testing the string for a sentinel.
pub fn lost_line(n: u64) -> Option<String> {
    (n > 0).then(|| format!("LOST {n} events"))
}

/// Turns completed events into trace lines, tracking the two bits of
/// state a pure per-line formatter cannot carry itself: the wall-clock
/// anchor (kernel timestamps are boot-relative monotonic, not epoch —
/// see `p11scope_ebpf_common::Event::ts_ns`) and the session-pseudonym
/// lookup, which `semantics::State` owns.
pub struct Tracer<'a> {
    plan: &'a AttachPlan,
    /// (first observed event's kernel monotonic ts_ns, wall-clock ns at
    /// that same moment) — every later line's wall time is this anchor
    /// plus the kernel-monotonic delta, so line-to-line spacing tracks
    /// the kernel clock exactly; only the anchor itself carries the
    /// small, constant "poll processing lag" of the first event.
    anchor: Option<(u64, u128)>,
}

impl<'a> Tracer<'a> {
    pub fn new(plan: &'a AttachPlan) -> Self {
        Self { plan, anchor: None }
    }

    fn wall_ns_for(&mut self, ts_ns: u64) -> u128 {
        match self.anchor {
            Some((mono0, wall0)) => wall0 + u128::from(ts_ns.saturating_sub(mono0)),
            None => {
                let wall0 =
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                self.anchor = Some((ts_ns, wall0));
                wall0
            }
        }
    }

    /// Feeds one completed event through the semantic state (session
    /// pseudonym allocation, same as `profile`) and returns its rendered
    /// trace line. The session's pseudonym is resolved *before*
    /// `observe`-ing a `C_CloseSession` event — `State::observe` retires
    /// the mapping on a successful close, and the closing call's own
    /// line must still show which session closed.
    pub fn on_event(&mut self, ev: &Event, state: &mut State) -> String {
        let (pid, _tid) = pid_tid(ev.pid_tgid);
        let pre = (ev.session != SESSION_NONE).then(|| state.session_pseudonym(pid, ev.session)).flatten();
        state.observe(ev);
        let session = pre.or_else(|| {
            (ev.session != SESSION_NONE).then(|| state.session_pseudonym(pid, ev.session)).flatten()
        });
        let wall_ns = self.wall_ns_for(ev.ts_ns);
        let function = function_name(self.plan, ev.slot);
        format_line(ev, wall_ns, &function, session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{USER_TYPE_NONE, shape};

    fn base_event() -> Event {
        Event {
            ts_ns: 0,
            duration_ns: 18_000,
            pid_tgid: (12345u64 << 32) | 12401,
            cgroup_id: 0,
            session: SESSION_NONE,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 0,
            kind: fnkind::SESSION_ARG0,
            user_type: USER_TYPE_NONE,
            shape: shape::NONE,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
        }
    }

    #[test]
    fn known_event_renders_the_documented_line_shape() {
        let mut ev = base_event();
        ev.kind = fnkind::INIT_WITH_MECH;
        ev.mechanism = pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS_PSS.0;
        ev.shape = shape::RSA_PKCS_PSS;
        ev.p0 = 0x0000_0250; // CKM_SHA256
        ev.p1 = 0x2; // CKG_MGF1_SHA256
        ev.p2 = 32;

        // Wall time 12:00:01.123456 UTC.
        let wall_ns = 12u128 * 3_600_000_000_000 + 1_123_456_000;
        let line = format_line(&ev, wall_ns, "C_SignInit", Some(7));

        // Duration formatting is reused verbatim from `render::fmt_ns`
        // (one decimal place at µs scale) rather than a second formatter
        // — "18.0µs", not the spec prose's illustrative "18µs".
        assert_eq!(
            line,
            "12:00:01.123456 pid 12345 tid 12401 sess#7 C_SignInit \
             CKM_RSA_PKCS_PSS(hash=SHA256 mgf=MGF1_SHA256 salt=32) \u{2192} CKR_OK 18.0\u{b5}s"
        );
    }

    #[test]
    fn vendor_mechanism_renders_as_hex() {
        let mut ev = base_event();
        ev.kind = fnkind::INIT_WITH_MECH;
        ev.mechanism = 0x8000_1042;
        ev.shape = shape::NONE;

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(line.contains("0x80001042"), "line: {line}");
        assert!(!line.contains("sess#"), "no session pseudonym must appear when none resolved");
    }

    #[test]
    fn known_mechanism_id_with_no_decoded_shape_still_renders_by_name_only() {
        let mut ev = base_event();
        ev.kind = fnkind::INIT_WITH_MECH;
        ev.mechanism = pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0;
        ev.shape = shape::NONE; // e.g. decode failed this call

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(line.contains("CKM_AES_GCM"), "line: {line}");
        assert!(!line.contains('('), "no parameters rendered without a decoded shape: {line}");
    }

    #[test]
    fn errored_call_shows_its_ck_rv() {
        let mut ev = base_event();
        ev.rv = 0x60; // CKR_KEY_HANDLE_INVALID
        let line = format_line(&ev, 0, "C_Sign", Some(3));
        assert!(line.contains("CKR_KEY_HANDLE_INVALID"), "line: {line}");
        assert!(!line.contains("CKR_OK"));
    }

    #[test]
    fn no_session_pseudonym_omits_the_sess_token() {
        let ev = base_event(); // session == SESSION_NONE
        let line = format_line(&ev, 0, "C_Login", None);
        assert!(!line.contains("sess#"), "line: {line}");
    }

    #[test]
    fn lost_line_is_none_when_nothing_was_lost() {
        assert_eq!(lost_line(0), None);
    }

    #[test]
    fn nonzero_loss_counter_produces_the_lost_line() {
        assert_eq!(lost_line(1), Some("LOST 1 events".to_string()));
        assert_eq!(lost_line(42), Some("LOST 42 events".to_string()));
    }

    fn test_plan() -> AttachPlan {
        AttachPlan {
            slots: vec![
                crate::plan::Slot {
                    index: 0,
                    object: "/opt/p11.so".into(),
                    file_offset: 0x10,
                    names: vec!["C_OpenSession".into()],
                    aliased: false,
                    kind: fnkind::OPEN_SESSION,
                },
                crate::plan::Slot {
                    index: 1,
                    object: "/opt/p11.so".into(),
                    file_offset: 0x20,
                    names: vec!["C_CloseSession".into()],
                    aliased: false,
                    kind: fnkind::SESSION_ARG0,
                },
            ],
            skipped: vec![],
            entries_seen: 2,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
        }
    }

    fn open_event(pid: u32, session: u64) -> Event {
        let mut ev = base_event();
        ev.pid_tgid = (u64::from(pid) << 32) | 1;
        ev.kind = fnkind::OPEN_SESSION;
        ev.session = session;
        ev.slot = 0;
        ev
    }

    fn close_event(pid: u32, session: u64) -> Event {
        let mut ev = base_event();
        ev.pid_tgid = (u64::from(pid) << 32) | 1;
        ev.kind = fnkind::SESSION_ARG0;
        ev.session = session;
        ev.slot = 1;
        ev
    }

    #[test]
    fn tracer_resolves_session_pseudonyms_never_raw_handles() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);

        let open_line = tracer.on_event(&open_event(100, 0xDEAD_BEEF), &mut state);
        assert!(open_line.contains("sess#1"), "line: {open_line}");
        assert!(!open_line.contains("deadbeef"), "raw handle must never appear: {open_line}");

        // The closing call must still show the pseudonym, even though
        // `State::observe` retires the mapping as part of processing it.
        let close_line = tracer.on_event(&close_event(100, 0xDEAD_BEEF), &mut state);
        assert!(close_line.contains("sess#1"), "line: {close_line}");
        assert!(state.session_pseudonym(100, 0xDEAD_BEEF).is_none(), "mapping retired after close");
    }

    #[test]
    fn tracer_wall_clock_tracks_kernel_monotonic_deltas() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);

        let mut first = open_event(100, 1);
        first.ts_ns = 1_000_000_000;
        let first_line = tracer.on_event(&first, &mut state);

        let mut second = open_event(100, 2);
        second.ts_ns = first.ts_ns + 500_000_000; // 500ms later, kernel time
        let second_line = tracer.on_event(&second, &mut state);

        let first_ts = &first_line[..15];
        let second_ts = &second_line[..15];
        assert_ne!(first_ts, second_ts, "distinct kernel timestamps must render distinct wall times");
    }
}
