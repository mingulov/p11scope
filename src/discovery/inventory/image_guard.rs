//! SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh current-image guard for inventory owners: every check acquires a
//! new observation through the retained pin and compares it against the
//! independently supplied expected image. The binder vetoes revoked
//! domains only; it never proves currency.

use super::{ImageCheck, ImageGuard};
use crate::attach::capture::{
    BindingObservation, CallerImageObservation, InventoryCapture, NativeDomainId, ReadWindow,
};
use crate::discovery::native_binding::{BoundImage, NativeBinder};
use crate::process::{PidPin, ProcessView};
use anyhow::Result;
use std::sync::Arc;

/// One genuine current-image acquisition from the guard's own capture
/// domain: the facade operation with its fresh generation and stopping
/// refusal, never a cached observation.
#[cfg_attr(not(test), allow(dead_code))] // Packet 2 preparation consumes this.
pub(crate) trait ImageAcquisition {
    fn acquisition_domain(&self) -> NativeDomainId;
    fn acquire_caller_image(
        &mut self,
        original: &Arc<PidPin>,
        window: ReadWindow,
    ) -> Result<CallerImageObservation>;
}

#[cfg_attr(not(test), allow(dead_code))] // Packet 2 preparation consumes this.
impl ImageAcquisition for InventoryCapture {
    fn acquisition_domain(&self) -> NativeDomainId {
        self.domain()
    }

    fn acquire_caller_image(
        &mut self,
        original: &Arc<PidPin>,
        window: ReadWindow,
    ) -> Result<CallerImageObservation> {
        self.observe_caller_image(original, window)
    }
}

/// The approved inventory-owner image guard: acquires on every check and
/// classifies provenance before mismatch. A foreign domain, foreign
/// allocation, or invalid generation is `Unavailable`, never terminal
/// `Changed`. Neither the observation nor an `Exact` result is stored for
/// the next check. Packet 2 preparation constructs this around its active
/// capture; packet 1 exercises it through scripted acquisition.
#[cfg_attr(not(test), allow(dead_code))] // Packet 2 preparation consumes this.
pub(crate) struct FreshImageGuard<'a, S: ImageAcquisition + ?Sized> {
    source: &'a mut S,
    binder: &'a NativeBinder,
    window: ReadWindow,
    // RED: cached first observation (the forbidden cache); GREEN removes it.
    cached: Option<CallerImageObservation>,
}

#[cfg_attr(not(test), allow(dead_code))] // Packet 2 preparation consumes this.
impl<'a, S: ImageAcquisition + ?Sized> FreshImageGuard<'a, S> {
    /// Borrow the guard's own capture, the binder (a revocation veto
    /// only), and the one-row window built from the operation allowance.
    pub(crate) fn new(source: &'a mut S, binder: &'a NativeBinder, window: ReadWindow) -> Self {
        Self {
            source,
            binder,
            window,
            cached: None,
        }
    }
}

impl<S: ImageAcquisition + ?Sized> ImageGuard for FreshImageGuard<'_, S> {
    fn check(&mut self, view: &ProcessView, expected: BoundImage) -> ImageCheck {
        let domain = self.source.acquisition_domain();
        if !self.binder.domain_active(domain) || !expected.belongs_to(domain) {
            return ImageCheck::Unavailable;
        }
        if !view.still_the_same() {
            return ImageCheck::Unavailable;
        }
        let original = view.retained_pin_arc();
        // RED: reuse the first acquisition forever; GREEN acquires now.
        if self.cached.is_none() {
            match self.source.acquire_caller_image(original, self.window) {
                Ok(observation) => self.cached = Some(observation),
                // RED: fallback-as-Exact; GREEN returns Unavailable here.
                Err(_) => return ImageCheck::Exact,
            }
        }
        let observation = self.cached.as_ref().expect("cached above");
        if !view.still_the_same() {
            return ImageCheck::Unavailable;
        }
        match expected.compare_observation(original, observation) {
            BindingObservation::Match => ImageCheck::Exact,
            BindingObservation::DifferentImage => ImageCheck::Changed,
            BindingObservation::Unavailable => ImageCheck::Unavailable,
        }
    }
}

/// Scripted acquisition for guard tests: observations run through the real
/// baseline decoder, with explicit call counts and generations. Never a
/// production source.
#[cfg(test)]
pub(crate) struct ScriptedAcquisition {
    domain: NativeDomainId,
    script: std::collections::VecDeque<ScriptedOutcome>,
    calls: usize,
    generations: Vec<u64>,
}

/// One scripted acquisition answer. `Observe` decodes an identity row for
/// `cookie`/`exec_id` at `generation`; `on` simulates a misdirected answer
/// built on another allocation (the genuine operation always answers on
/// the passed original, so this entry only exercises provenance refusal).
#[cfg(test)]
pub(crate) enum ScriptedOutcome {
    Observe {
        generation: u64,
        cookie: u64,
        exec_id: u64,
        on: Option<Arc<PidPin>>,
    },
    Fail(&'static str),
}

#[cfg(test)]
impl ScriptedAcquisition {
    pub(crate) fn new(domain: NativeDomainId) -> Self {
        Self {
            domain,
            script: std::collections::VecDeque::new(),
            calls: 0,
            generations: Vec::new(),
        }
    }

    pub(crate) fn script_observe(&mut self, generation: u64, cookie: u64, exec_id: u64) {
        self.script.push_back(ScriptedOutcome::Observe {
            generation,
            cookie,
            exec_id,
            on: None,
        });
    }

    pub(crate) fn script_observe_on(
        &mut self,
        generation: u64,
        cookie: u64,
        exec_id: u64,
        on: Arc<PidPin>,
    ) {
        self.script.push_back(ScriptedOutcome::Observe {
            generation,
            cookie,
            exec_id,
            on: Some(on),
        });
    }

    pub(crate) fn script_fail(&mut self, reason: &'static str) {
        self.script.push_back(ScriptedOutcome::Fail(reason));
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls
    }

    pub(crate) fn generations(&self) -> &[u64] {
        &self.generations
    }
}

#[cfg(test)]
impl ImageAcquisition for ScriptedAcquisition {
    fn acquisition_domain(&self) -> NativeDomainId {
        self.domain
    }

    fn acquire_caller_image(
        &mut self,
        original: &Arc<PidPin>,
        window: ReadWindow,
    ) -> Result<CallerImageObservation> {
        assert_eq!(
            window.max_rows(),
            1,
            "the guard queries one identity row per check"
        );
        self.calls += 1;
        if window.deadline() < std::time::Instant::now() {
            anyhow::bail!("scripted acquisition window expired");
        }
        match self.script.pop_front() {
            Some(ScriptedOutcome::Observe {
                generation,
                cookie,
                exec_id,
                on,
            }) => {
                let built_on = on.as_ref().unwrap_or(original);
                let observation = crate::attach::capture::scripted_observation(
                    self.domain,
                    built_on,
                    generation,
                    cookie,
                    exec_id,
                )?;
                self.generations.push(generation);
                Ok(observation)
            }
            Some(ScriptedOutcome::Fail(reason)) => {
                Err(anyhow::anyhow!("scripted acquisition failed: {reason}"))
            }
            None => panic!(
                "scripted acquisition script exhausted after {} calls",
                self.calls
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::capture::{
        CaptureHealth, CapturePhase, CookieQuery, DiscoveryBatch, DomainCookie, ExecCoverage,
        ScopeCustody, WitnessBatch, WitnessRow,
    };
    use crate::discovery::caller_registry::CallerId;
    use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
    use crate::discovery::native_binding::{
        BinderLimits, Binding, CallerLookup, LiveCaller, NativeIdentity,
    };
    use crate::process::ProcessViewId;
    use p11scope_ebpf_common::{DISCOVERY_KIND_EXEC, DiscoveryRecord};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// A scripted pin: (pid, generation). Two generations of one pid are
    /// two processes.
    type TestPin = (u32, u64);

    /// A binder with scripted live callers and cookie answers, settling
    /// real bindings through the production decision path (no host reads).
    struct BinderScene {
        binder: NativeBinder,
        live: HashMap<u32, (CallerId, u64, TestPin)>,
        answers: HashMap<(TestPin, NativeDomainId), CookieQuery>,
        clock: u64,
    }

    struct SceneLookup<'a>(&'a HashMap<u32, (CallerId, u64, TestPin)>);

    impl CallerLookup<TestPin> for SceneLookup<'_> {
        fn live_caller(&self, pid: u32) -> Option<LiveCaller<'_, TestPin>> {
            self.0.get(&pid).map(|(id, first_seen_ns, pin)| LiveCaller {
                id: *id,
                first_seen_ns: *first_seen_ns,
                pin,
            })
        }
    }

    struct SceneIdentity<'a> {
        answers: &'a HashMap<(TestPin, NativeDomainId), CookieQuery>,
    }

    impl NativeIdentity<TestPin> for SceneIdentity<'_> {
        fn owner_image(&mut self, _: u32) -> Option<BoundImage> {
            None
        }

        fn query_cookie(&mut self, domain: NativeDomainId, pin: &TestPin) -> CookieQuery {
            self.answers
                .get(&(*pin, domain))
                .cloned()
                .unwrap_or(CookieQuery::NoCookie)
        }
    }

    impl BinderScene {
        fn new() -> Self {
            Self {
                binder: NativeBinder::new(BinderLimits::default()),
                live: HashMap::new(),
                answers: HashMap::new(),
                clock: 1_000,
            }
        }

        fn tick(&mut self) -> u64 {
            self.clock += 10;
            self.clock
        }

        fn lookup(&self) -> SceneLookup<'_> {
            SceneLookup(&self.live)
        }

        fn absorb(&mut self, batch: &WitnessBatch) {
            let lookup = SceneLookup(&self.live);
            let mut identity = SceneIdentity {
                answers: &self.answers,
            };
            self.binder.absorb_witnesses(batch, &lookup, &mut identity);
        }

        fn read_rows(&mut self, domain: NativeDomainId, rows: Vec<WitnessRow>) {
            let at = self.tick();
            let batch = WitnessBatch {
                domain,
                phase: CapturePhase::Active,
                rows,
                integrity: Vec::new(),
                integrity_total: 0,
                visited: 0,
                sweep_completed: true,
                sweeps_completed: 1,
                row_bound_reached: false,
                deadline_reached: false,
                read_failures: Vec::new(),
                unrecorded_rows: 0,
                sweep_gaps: false,
                counts: Vec::new(),
                refresh_sweep_completed: true,
                refresh_sweep_gaps: false,
                refresh_deadline_reached: false,
                refresh_sweeps_completed: 1,
                seen_rows: 0,
                pair_limit: 65_536,
                health: CaptureHealth {
                    discovery_counters: Some([0, 0, 0, 0, 0]),
                    ..CaptureHealth::default()
                },
                health_regression: None,
                health_unproven: None,
                health_baseline_ns: 0,
                health_read_ns: at,
                rows_anchor_ns: at + 1,
                rows_read_ns: at + 1,
                counts_read_ns: at + 1,
                changed_objects: Vec::new(),
                custody: ScopeCustody::System,
                custody_proven_ns: None,
                lifecycle_proven_ns: u64::MAX,
                lifecycle_loss: None,
                unsettled: false,
            };
            self.absorb(&batch);
        }

        fn drain(&mut self, domain: NativeDomainId, execs: &[(u32, u64)]) {
            let at = self.tick();
            let batch = DiscoveryBatch::scripted(
                domain,
                execs
                    .iter()
                    .map(|(tgid, ts)| {
                        // SAFETY: `DiscoveryRecord` is a plain `repr(C)`
                        // integer record; all zeroes is a valid value.
                        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
                        record.kind = DISCOVERY_KIND_EXEC;
                        record.pid_tgid = (u64::from(*tgid) << 32) | u64::from(*tgid);
                        record.hook_ts_ns = *ts;
                        record
                    })
                    .collect(),
                at,
            );
            self.binder.absorb_lifecycle(&batch);
        }

        /// Settle one binding through the production path: coverage, one
        /// live caller, one answering cookie, one row, both horizons.
        fn settle(
            &mut self,
            domain: NativeDomainId,
            pid: u32,
            caller: u32,
            ticket: u64,
            exec: u64,
        ) -> CallerId {
            self.binder
                .note_exec_coverage(ExecCoverage::scripted(domain, 0));
            let id = CallerId(caller);
            let first_seen = self.tick();
            self.live.insert(pid, (id, first_seen, (pid, 0)));
            self.answers.insert(
                ((pid, 0), domain),
                CookieQuery::Cookie(DomainCookie::scripted(domain, ticket)),
            );
            let t0 = self.tick();
            self.read_rows(
                domain,
                vec![WitnessRow::scripted(
                    domain,
                    ticket,
                    exec,
                    AttachObjectId::scripted(0),
                    EndpointId(0),
                    pid,
                    t0,
                )],
            );
            self.drain(domain, &[]);
            self.read_rows(domain, Vec::new());
            let verdicts: Vec<Binding> = self
                .binder
                .take_decisions()
                .into_iter()
                .map(|decision| decision.binding)
                .collect();
            assert_eq!(verdicts, [Binding::Bound(id)]);
            id
        }
    }

    fn window() -> ReadWindow {
        ReadWindow::new(1, Instant::now() + Duration::from_secs(30)).unwrap()
    }

    fn self_view() -> ProcessView {
        ProcessView::open_warm_only(ProcessViewId(0), std::process::id()).unwrap()
    }

    #[test]
    fn fresh_guard_queries_each_checkpoint() {
        const TICKET: u64 = 41;
        const EXEC: u64 = 7;
        let domain = NativeDomainId::mint();
        let mut scene = BinderScene::new();
        let caller = scene.settle(domain, 4242, 0, TICKET, EXEC);
        assert!(scene.binder.holds_image(domain, caller));
        let view = self_view();
        let expected = BoundImage::scripted(domain, TICKET, EXEC).unwrap();
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe(1, TICKET, EXEC);
        source.script_observe(2, TICKET, EXEC);
        source.script_fail("the third acquisition fails");
        let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
        assert_eq!(guard.check(&view, expected), ImageCheck::Exact);
        assert_eq!(guard.check(&view, expected), ImageCheck::Exact);
        // A later source error yields Unavailable although the binder
        // still has its old binding: binder state is never currency.
        assert_eq!(guard.check(&view, expected), ImageCheck::Unavailable);
        drop(guard);
        assert_eq!(source.calls(), 3, "one acquisition per check");
        assert_eq!(source.generations(), &[1, 2]);
        assert!(scene.binder.holds_image(domain, caller));
    }

    #[test]
    fn fresh_guard_rejects_cross_domain_and_replacement_original() {
        const TICKET: u64 = 41;
        const EXEC: u64 = 7;
        let domain = NativeDomainId::mint();
        let foreign = NativeDomainId::mint();
        let mut scene = BinderScene::new();
        scene
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        scene
            .binder
            .note_exec_coverage(ExecCoverage::scripted(foreign, 0));
        let view = self_view();
        let expected = BoundImage::scripted(domain, TICKET, EXEC).unwrap();

        // The same original allocation plus the matching source domain
        // succeeds.
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe(1, TICKET, EXEC);
        let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
        assert_eq!(guard.check(&view, expected), ImageCheck::Exact);
        drop(guard);
        assert_eq!(source.calls(), 1);

        // The same PID/start-time in a separately opened allocation is a
        // replacement original, never the retained one.
        let replacement = Arc::new(PidPin::open(std::process::id()).unwrap());
        assert_eq!(replacement.pid(), view.pid());
        assert_eq!(replacement.start_time(), view.start_time());
        assert!(!Arc::ptr_eq(&replacement, view.retained_pin_arc()));
        let mut source = ScriptedAcquisition::new(domain);
        source.script_observe_on(2, TICKET, EXEC, replacement);
        let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
        assert_eq!(guard.check(&view, expected), ImageCheck::Unavailable);
        drop(guard);
        assert_eq!(source.calls(), 1);

        // Equal ticket/exec from another domain refuses before any
        // acquisition, never as a terminal Changed.
        let alien = BoundImage::scripted(foreign, TICKET, EXEC).unwrap();
        let mut source = ScriptedAcquisition::new(domain);
        source.script_fail("must never be consumed");
        let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
        assert_eq!(guard.check(&view, alien), ImageCheck::Unavailable);
        drop(guard);
        assert_eq!(source.calls(), 0);

        // In the proper domain and original, a changed ticket or exec is
        // a genuine Changed.
        for (ticket, exec) in [(TICKET + 1, EXEC), (TICKET, EXEC + 1)] {
            let mut source = ScriptedAcquisition::new(domain);
            source.script_observe(3, ticket, exec);
            let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
            assert_eq!(guard.check(&view, expected), ImageCheck::Changed);
            drop(guard);
            assert_eq!(source.calls(), 1);
        }
    }

    #[test]
    fn finished_domain_cannot_supply_fresh_owner_authority() {
        const TICKET: u64 = 41;
        const EXEC: u64 = 1;
        const T1: u32 = 4242;
        const T2: u32 = 4243;
        let d1 = NativeDomainId::mint();
        let d2 = NativeDomainId::mint();
        let mut scene = BinderScene::new();
        let c1 = scene.settle(d1, T1, 0, TICKET, EXEC);
        let expected1 = scene
            .binder
            .expected_owner_image(d1, c1, T1, &scene.lookup())
            .expect("an active settled binding supplies its expected image");

        // After finish, D1 refuses even though its old binding and token
        // remain for history.
        scene.binder.finish(d1);
        assert!(
            scene
                .binder
                .expected_owner_image(d1, c1, T1, &scene.lookup())
                .is_none()
        );
        assert!(scene.binder.holds_image(d1, c1));

        // Unknown domains and callers supply nothing.
        assert!(
            scene
                .binder
                .expected_owner_image(NativeDomainId::mint(), c1, T1, &scene.lookup())
                .is_none()
        );
        assert!(
            scene
                .binder
                .expected_owner_image(d1, CallerId(99), T1, &scene.lookup())
                .is_none()
        );

        // D2 settles the equal transport numbers as its own image; that
        // does not revive D1.
        let c2 = scene.settle(d2, T2, 1, TICKET, EXEC);
        assert!(
            scene
                .binder
                .expected_owner_image(d1, c1, T1, &scene.lookup())
                .is_none()
        );
        let expected2 = scene
            .binder
            .expected_owner_image(d2, c2, T2, &scene.lookup())
            .expect("D2 supplies its own expected image");
        assert_ne!(expected1, expected2);

        // A live lookup that no longer names the caller refuses.
        scene.live.remove(&T2);
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c2, T2, &scene.lookup())
                .is_none()
        );
        scene.live.insert(T2, (c2, 1_000, (T2, 0)));

        // A newer exec of the ticket, known but undecided, conflicts.
        let t0 = scene.tick();
        scene.read_rows(
            d2,
            vec![WitnessRow::scripted(
                d2,
                TICKET,
                EXEC + 4,
                AttachObjectId::scripted(0),
                EndpointId(0),
                T2,
                t0,
            )],
        );
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c2, T2, &scene.lookup())
                .is_none()
        );

        // Deciding that row proves the old image ended; the factory keeps
        // refusing for the ended caller.
        scene.drain(d2, &[]);
        scene.read_rows(d2, Vec::new());
        let verdicts: Vec<Binding> = scene
            .binder
            .take_decisions()
            .into_iter()
            .map(|decision| decision.binding)
            .collect();
        assert!(
            verdicts.iter().any(|verdict| matches!(
                verdict,
                Binding::Unbound(crate::discovery::native_binding::UnboundReason::ExecTransition)
            )),
            "the newer row ends the old image: {verdicts:?}"
        );
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c2, T2, &scene.lookup())
                .is_none()
        );

        // Fresh D2 bindings still supply; an exec at/after admission and
        // lost lifecycle evidence each invalidate what they touch.
        let c3 = scene.settle(d2, T2, 2, TICKET + 1, EXEC);
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c3, T2, &scene.lookup())
                .is_some()
        );
        scene.drain(d2, &[(T2, scene.clock + 100)]);
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c3, T2, &scene.lookup())
                .is_none(),
            "an exec at or after admission invalidates the binding"
        );
        const T3: u32 = 4244;
        let c4 = scene.settle(d2, T3, 3, TICKET + 2, EXEC);
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c4, T3, &scene.lookup())
                .is_some()
        );
        let lost_at = scene.clock + 50;
        let mut lost = DiscoveryBatch::scripted(d2, Vec::new(), lost_at);
        lost.failure = Some("scripted lifecycle loss".into());
        scene.binder.absorb_lifecycle(&lost);
        assert!(
            scene
                .binder
                .expected_owner_image(d2, c4, T3, &scene.lookup())
                .is_none(),
            "lost lifecycle evidence invalidates the binding"
        );

        // D2's own expected identity still matches its own observation.
        let view = self_view();
        let mut source = ScriptedAcquisition::new(d2);
        source.script_observe(1, TICKET, EXEC);
        let mut guard = FreshImageGuard::new(&mut source, &scene.binder, window());
        assert_eq!(guard.check(&view, expected2), ImageCheck::Exact);
        drop(guard);
        assert_eq!(source.calls(), 1);
    }
}
