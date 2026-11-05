//! SPDX-License-Identifier: GPL-3.0-or-later
//! Production diagnostic hooks over the same real-identity retirement schedules.
use super::demotion_retirement_tests::Scene;
use super::*;
use crate::inventory_diagnostics::{
    CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticOutcome, InitError,
    RetainedIdentityView,
};
use serde_json::Value;

struct IdentityView<'a, Source: ProcessSource>(&'a InventoryCoordinator<Source>);
impl<Source: ProcessSource> RetainedIdentityView for IdentityView<'_, Source> {
    fn application(&self, caller: u32) -> Option<&str> {
        self.0
            .adapter
            .record(CallerId(caller))?
            .exe
            .as_ref()?
            .path
            .as_deref()
    }
    fn module(&self, module: u32) -> Option<&str> {
        self.0
            .registry
            .module(ModuleId(module))?
            .paths
            .first()
            .map(String::as_str)
    }
}

fn export(scene: &mut Scene) -> Vec<Value> {
    let finished = scene
        .native
        .scene
        .coordinator
        .take_diagnostics(DiagnosticOutcome {
            capture_outcome: CaptureOutcome::Completed,
            capture_settlement: CaptureSettlement::Settled,
        })
        .expect("enabled production recorder");
    let mut bytes = Vec::new();
    finished
        .write_jsonl(
            &mut bytes,
            &IdentityView(&scene.native.scene.coordinator),
            || false,
        )
        .unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

type RegistrySnapshot = (Vec<(u32, u64, String, String)>, Vec<(String, String)>, u64);

fn snapshot(scene: &Scene) -> RegistrySnapshot {
    let registry = &scene.native.scene.coordinator.registry;
    (
        registry
            .edges()
            .map(|edge| {
                (
                    edge.module.0,
                    edge.entry_count,
                    format!("{:?}", edge.mapping),
                    format!("{:?}", registry.coverage(edge)),
                )
            })
            .collect(),
        registry
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect(),
        registry.published_revision(),
    )
}

/// Unmodified production output plus independently sampled registry milestones.
/// Scene's real-identity seed issues1 then5; it does not pretend to issue five
/// unit rounds. The live G21 fixture separately requires its32 unit trajectories.
pub(crate) struct G21CountDiagnosticFixture {
    pub(crate) records: Vec<Value>,
    pub(crate) caller: String,
    pub(crate) module_a: String,
    pub(crate) module_b: Option<String>,
    pub(crate) issued_a: Vec<u64>,
    pub(crate) issued_after_a: Vec<u64>,
    pub(crate) committed_a: Vec<(u64, u64)>,
    pub(crate) committed_b: Vec<(u64, u64)>,
}

fn g21_committed_edge(scene: &Scene, suffix: &str) -> Option<(String, u64)> {
    let registry = &scene.native.scene.coordinator.registry;
    registry.edges_of(scene.caller).find_map(|edge| {
        registry
            .module(edge.module)
            .filter(|module| module.paths.iter().any(|path| path.ends_with(suffix)))
            .map(|_| (edge.module.label(), edge.entry_count))
    })
}

type G21CountMilestones = Vec<(u64, u64)>;

fn g21_drive_count_diagnostics(
    scene: &mut Scene,
    recovered: bool,
) -> (G21CountMilestones, G21CountMilestones) {
    let mut a = vec![(5, g21_committed_edge(scene, "a.so").unwrap().1)];
    let mut b = Vec::new();
    if recovered {
        scene.observe(true, true, 200);
        scene.count(6);
        a.push((6, g21_committed_edge(scene, "a.so").unwrap().1));
        b.push((6, g21_committed_edge(scene, "b.so").unwrap().1));
        scene.observe(false, true, 300);
        scene.count(7);
        scene.horizons();
        a.push((7, g21_committed_edge(scene, "a.so").unwrap().1));
        b.push((7, g21_committed_edge(scene, "b.so").unwrap().1));
        scene.count(8);
        scene.horizons();
        a.push((8, g21_committed_edge(scene, "a.so").unwrap().1));
        b.push((8, g21_committed_edge(scene, "b.so").unwrap().1));
    } else {
        for absolute in [6, 7] {
            scene.count(absolute);
            a.push((absolute, g21_committed_edge(scene, "a.so").unwrap().1));
        }
    }
    (a, b)
}

pub(crate) fn genuine_g21_count_diagnostics(recovered: bool) -> G21CountDiagnosticFixture {
    let mut scene = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    let (committed_a, committed_b) = g21_drive_count_diagnostics(&mut scene, recovered);
    G21CountDiagnosticFixture {
        caller: scene.caller.label(),
        module_a: g21_committed_edge(&scene, "a.so").unwrap().0,
        module_b: g21_committed_edge(&scene, "b.so").map(|edge| edge.0),
        issued_a: if recovered {
            vec![1, 5]
        } else {
            vec![1, 5, 6, 7]
        },
        issued_after_a: if recovered { vec![6, 7, 8] } else { Vec::new() },
        committed_a,
        committed_b,
        records: export(&mut scene),
    }
}

#[test]
fn genuine_ordinary_diagnostics_feed_g21_a_oracle() {
    let actual = genuine_g21_count_diagnostics(false);
    let mut disabled = Scene::placed();
    let milestones = g21_drive_count_diagnostics(&mut disabled, false);
    assert_eq!(
        (&actual.committed_a, &actual.committed_b),
        (&milestones.0, &milestones.1)
    );
    assert_eq!(actual.committed_a, vec![(5, 5), (6, 6), (7, 7)]);
    for absolute in [6, 7] {
        assert!(
            actual
                .records
                .iter()
                .any(|row| row["kind"] == "count_decision"
                    && row["decision"] == "staged"
                    && row["absolute"] == absolute
                    && row["pair"].is_string()
                    && row["module_id"] == actual.module_a)
        );
        assert!(actual.records.iter().any(|row| row["kind"] == "publication"
            && row["edge_total"] == absolute
            && row["module_id"] == actual.module_a
            && row["pair"].is_null()
            && row["decision"].is_null()
            && row["absolute"].is_null()
            && row["observation_ref"].is_null()
            && row["context_unavailable"] == true));
    }
}

#[test]
fn dropped_pair_raw_reads_remain_diagnostic_without_becoming_published_counts() {
    for initial in [false, true] {
        let mut disabled = Scene::placed();
        let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
        for scene in [&mut disabled, &mut enabled] {
            scene.count(161950);
            let mut row = scene.native.row(41, 1, 7, 100, 0);
            let key = PairKey::of(&row);
            let coordinator = &mut scene.native.scene.coordinator;
            // Retain an already rejected range and drop its count target
            // through production bookkeeping. The diagnostic read must not
            // replace the retained history or revive this placement.
            coordinator
                .registry
                .note_retirement_count_gap(scene.caller, 161950, 162003);
            coordinator.drop_pair_count(&row, DiagnosticReason::IdentityChanged);
            coordinator.commit_batch(false).unwrap();
            let NativeBatch::Witness(mut read) =
                scene.native.stamps.read(scene.native.domain, Vec::new())
            else {
                unreachable!("a witness read supplies the already acquired rows")
            };
            if initial {
                row.entry_count = 162003;
                read.rows.push(row);
            } else {
                read.counts.push(CallerCountUpdate {
                    image: p11scope_ebpf_common::ImageIdentity {
                        task_cookie: 41,
                        exec_id: 1,
                    },
                    object: scene.native.scene.delta.endpoints[0].object,
                    count: 162003,
                });
            }
            // Drive the real read-consumption seam without replaying an
            // initial row through the independent witness binder again.
            scene.native.scene.coordinator.absorb_pair_counts(&read);
            scene.native.scene.coordinator.commit_batch(false).unwrap();
            assert_eq!(g21_committed_edge(scene, "a.so").unwrap().1, 161950);
            assert!(matches!(
                scene.native.scene.coordinator.pair_targets.get(&key),
                Some(PairTarget::Dropped { .. })
            ));
            assert!(
                !scene
                    .native
                    .scene
                    .coordinator
                    .pair_counts
                    .contains_key(&key)
            );
            assert!(
                scene
                    .native
                    .scene
                    .coordinator
                    .registry
                    .gaps()
                    .iter()
                    .any(|gap| gap.reason.contains("(161950, 162003]")
                        && gap.reason.contains("53 unattributed calls"))
            );
        }
        assert_eq!(snapshot(&enabled), snapshot(&disabled));
        let lines = export(&mut enabled);
        let observation = lines
            .iter()
            .find(|line| line["kind"] == "count_observation" && line["absolute"] == 162003)
            .expect("an already read absolute survives the dropped-placement branch");
        assert_eq!(
            observation["origin"],
            if initial { "initial" } else { "refresh" }
        );
        assert!(observation["pair"].is_string());
        assert!(observation["pre"].is_number() && observation["post"].is_number());
        assert!(
            !lines
                .iter()
                .any(|line| line["kind"] == "publication" && line["edge_total"] == 162003)
        );
        assert_eq!(lines.last().unwrap()["kind"], "footer");
    }
}

#[test]
fn genuine_recovered_diagnostics_feed_g21_a_oracle() {
    let actual = genuine_g21_count_diagnostics(true);
    let mut disabled = Scene::placed();
    let milestones = g21_drive_count_diagnostics(&mut disabled, true);
    assert_eq!(
        (&actual.committed_a, &actual.committed_b),
        (&milestones.0, &milestones.1)
    );
    assert_eq!(actual.committed_a, vec![(5, 5), (6, 5), (7, 5), (8, 5)]);
    assert_eq!(actual.committed_b, vec![(6, 0), (7, 0), (8, 1)]);
    let placed = actual
        .records
        .iter()
        .find(|row| {
            row["kind"] == "publication" && row["decision"] == "placed" && row["absolute"] == 8
        })
        .unwrap();
    assert_eq!(placed["module_id"], actual.module_b.as_deref().unwrap());
    assert_eq!(placed["staged"], 1);
    assert!(placed["pair"].is_string());
    assert_eq!(placed["observation_ref"]["status"], "retained");
}

fn recovered_schedule(scene: &mut Scene) {
    scene.observe(true, true, 200);
    scene.count(7);
    scene.observe(false, true, 300);
    scene.count(8);
    scene.horizons();
    scene.count(10);
    scene.horizons();
    assert_eq!(scene.counts(), (5, 2));
}

#[test]
fn genuine_recovery_diagnostics_preserve_counts_and_explain_fence() {
    let mut disabled = Scene::placed();
    let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    recovered_schedule(&mut disabled);
    recovered_schedule(&mut enabled);
    assert_eq!(snapshot(&enabled), snapshot(&disabled));
    let lines = export(&mut enabled);
    let fence_read = lines
        .iter()
        .find(|line| line["kind"] == "count_observation" && line["absolute"] == 8)
        .unwrap();
    let recovered_stage = lines
        .iter()
        .find(|line| line["decision"] == "staged" && line["absolute"] == 10)
        .unwrap();
    assert_eq!(recovered_stage["baseline_pre"], fence_read["pre"]);
    assert_eq!(recovered_stage["baseline_post"], fence_read["post"]);
    assert!(lines.iter().any(|line| line["decision"] == "staged"
        && line["absolute"] == 1
        && line["base"] == 0
        && line["staged"] == 1));
    assert!(lines.iter().any(|line| line["decision"] == "staged"
        && line["absolute"] == 10
        && line["base"] == 8
        && line["staged"] == 2));
    assert!(lines.iter().any(|line| line["kind"] == "count_observation"
        && line["absolute"] == 8
        && line["origin"] == "refresh"));
    assert!(lines.iter().any(|line| line["decision"] == "withheld"
        && line["after"] == 7
        && line["through"] == 8
        && line["reason"] == "awaiting_fence"));
    assert!(lines.iter().any(|line| line["decision"] == "placed"
        && line["absolute"] == 10
        && line["base"] == 8
        && line["edge_total"] == 2));
    let recovered_placement = lines
        .iter()
        .find(|line| line["decision"] == "placed" && line["absolute"] == 10)
        .unwrap();
    assert_eq!(recovered_placement["staged"], 2);
    assert_eq!(recovered_placement["baseline_pre"], fence_read["pre"]);
    assert_eq!(recovered_placement["baseline_post"], fence_read["post"]);
    assert!(
        enabled
            .native
            .scene
            .coordinator
            .take_diagnostics(DiagnosticOutcome {
                capture_outcome: CaptureOutcome::Completed,
                capture_settlement: CaptureSettlement::Settled
            })
            .is_none()
    );
    assert_eq!(
        enabled.counts(),
        (5, 2),
        "taking diagnostics retains identities and accounting"
    );
}

#[test]
fn stale_original_reads_are_recorded_at_their_actual_bracket() {
    let mut scene = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    scene.bracketed_count(9, 1_500, 1_501, false);
    scene.bracketed_count(6, 900, 901, false);
    scene.bracketed_count(6, 950, 951, false);
    assert_eq!(
        scene
            .native
            .scene
            .coordinator
            .registry
            .edges_of(scene.caller)
            .next()
            .unwrap()
            .entry_count,
        9
    );
    let lines = export(&mut scene);
    let stale: Vec<_> = lines
        .iter()
        .filter(|line| line["kind"] == "count_observation" && line["absolute"] == 6)
        .collect();
    assert_eq!(
        stale.len(),
        1,
        "unchanged stale polling keeps its original reference"
    );
    assert_eq!(stale[0]["pre"], 900);
    assert_eq!(stale[0]["post"], 901);
    assert_eq!(stale[0]["reason"], "stale_observation");
    assert!(
        lines.iter().any(|line| line["kind"] == "publication"
            && line["edge_total"] == 9
            && line["pair"].is_null()
            && line["decision"].is_null()
            && line["context_unavailable"] == true),
        "direct publication reports its actual total without invented pair correlation"
    );
}

#[test]
fn tiny_rings_filter_and_init_failure_cannot_change_accounting() {
    let mut disabled = Scene::placed();
    let mut tiny = Scene::placed_with_diagnostics(Some(DiagnosticConfig {
        ordinary_capacity: 2,
        exceptional_capacity: 2,
        ..DiagnosticConfig::default()
    }));
    let mut filtered = Scene::placed_with_diagnostics(Some(DiagnosticConfig {
        pid_filter: Some(999),
        ..DiagnosticConfig::default()
    }));
    let mut refused = Scene::placed();
    assert_eq!(
        refused
            .native
            .scene
            .coordinator
            .enable_diagnostics(DiagnosticConfig {
                ordinary_capacity: 0,
                ..DiagnosticConfig::default()
            }),
        Err(InitError::InvalidLimits)
    );
    for scene in [&mut disabled, &mut tiny, &mut filtered, &mut refused] {
        recovered_schedule(scene);
    }
    assert_eq!(snapshot(&tiny), snapshot(&disabled));
    assert_eq!(snapshot(&filtered), snapshot(&disabled));
    assert_eq!(snapshot(&refused), snapshot(&disabled));
    let tiny_lines = export(&mut tiny);
    assert!(
        tiny_lines
            .iter()
            .any(|line| line["history_complete"] == false)
    );
    let filtered_lines = export(&mut filtered);
    assert!(
        filtered_lines
            .iter()
            .filter(|line| line["kind"] != "header" && line["kind"] != "footer")
            .all(|line| line["kind"] == "capture_health" || line["kind"] == "publication")
    );
}

#[test]
fn historical_requests_keep_immutable_reads_and_publish_union_once() {
    let mut disabled = Scene::placed();
    let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    for scene in [&mut disabled, &mut enabled] {
        scene.observe(true, true, 200);
        scene.count(7);
        scene.observe(false, true, 300);
        scene.count(8);
        scene.horizons();
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
        scene.native.counts_read(Vec::new(), vec![(41, 1, 0, 12)]);
        scene.native.scene.source.kill(7);
        scene.native.scene.coordinator.observe_empty_pass(
            &mut crate::discovery::engine::inventory::UnavailableImageGuard,
            &mut scene.native.cookies,
            "owned caller ended before publication",
            350,
        );
        scene.native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(scene.counts(), (5, 4));
        scene.count(14);
        scene.horizons();
        assert_eq!(scene.counts(), (5, 4));
    }
    assert_eq!(snapshot(&enabled), snapshot(&disabled));
    let lines = export(&mut enabled);
    let requests: Vec<_> = lines
        .iter()
        .filter(|line| {
            line["decision"] == "staged" && (line["absolute"] == 10 || line["absolute"] == 12)
        })
        .collect();
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[0]["pending"], requests[1]["pending"]);
    assert_ne!(
        requests[0]["observation_ref"]["seq"],
        requests[1]["observation_ref"]["seq"]
    );
    let placements: Vec<_> = lines
        .iter()
        .filter(|line| {
            line["decision"] == "placed" && (line["absolute"] == 10 || line["absolute"] == 12)
        })
        .collect();
    assert_eq!(
        placements.len(),
        2,
        "historical placement remains visible even when current proof is canceled"
    );
    assert!(placements.iter().all(|line| line["edge_total"] == 4));
    assert!(lines.iter().any(|line| line["reason"] == "stale_decision"));
}

#[test]
fn temporarily_unavailable_binding_keeps_the_original_candidate_reference() {
    let mut disabled = Scene::placed();
    let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    for scene in [&mut disabled, &mut enabled] {
        scene.observe(true, true, 200);
        scene.count(7);
        scene.native.unavailable_answer(7, 500);
        scene.observe(false, true, 300);
        scene.count(8);
        scene.count(10);
        scene.horizons();
        assert_eq!(scene.counts(), (5, 0));
        scene.native.answer(7, 500, 41);
        scene.horizons();
        scene.count(12);
        scene.horizons();
        assert_eq!(scene.counts(), (5, 4));
    }
    assert_eq!(snapshot(&enabled), snapshot(&disabled));
    let lines = export(&mut enabled);
    assert!(
        lines
            .iter()
            .any(|line| line["reason"] == "binding_unproven")
    );
    assert!(
        lines.iter().any(|line| line["decision"] == "staged"
            && line["fence"] == 8
            && line["absolute"] == 12)
    );
}

#[test]
fn global_refresh_loss_and_stop_remain_visible_under_pid_filter() {
    let mut disabled = Scene::placed();
    let mut filtered = Scene::placed_with_diagnostics(Some(DiagnosticConfig {
        pid_filter: Some(999),
        ..DiagnosticConfig::default()
    }));
    for scene in [&mut disabled, &mut filtered] {
        scene
            .native
            .scene
            .coordinator
            .begin_capture_coverage(crate::attach::capture::CaptureScopeCoverage::System);
        scene
            .native
            .scene
            .coordinator
            .note_refresh_loss("actual terminal refresh failed".into());
        scene.native.scene.coordinator.end_capture_coverage(2_000);
    }
    assert_eq!(snapshot(&filtered), snapshot(&disabled));
    let lines = export(&mut filtered);
    assert!(
        lines
            .iter()
            .any(|line| line["kind"] == "capture_health" && line["reason"] == "capture_loss")
    );
    assert!(
        lines
            .iter()
            .any(|line| line["kind"] == "capture_health" && line["reason"] == "capture_stopped")
    );
}

#[test]
fn exhausted_actual_pending_handle_refuses_growth_without_changing_history() {
    let mut disabled = Scene::placed();
    let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    for scene in [&mut disabled, &mut enabled] {
        scene.observe(true, true, 200);
        scene.count(7);
        scene.observe(false, true, 300);
        scene.count(8);
        scene.horizons();
        scene.native.scene.coordinator.next_pending_id = u64::MAX;
        scene.count(10);
        scene.horizons();
        scene.count(12);
        scene.horizons();
        assert_eq!(scene.counts(), (5, 0));
    }
    assert_eq!(snapshot(&enabled), snapshot(&disabled));
    let lines = export(&mut enabled);
    assert!(lines.iter().any(|line| line["decision"] == "rejected"
        && line["reason"] == "budget_refused"
        && line["absolute"] == 10));
}

#[test]
fn diagnostic_scalar_layout_is_separate_from_recorder_container_budget() {
    println!(
        "diagnostic fixed layout: pair_read={} held_pair={} pending_projection={} pending_observation={} recovery_projection={} recovery={}",
        std::mem::size_of::<PairCount>(),
        std::mem::size_of::<HeldPairCount>(),
        std::mem::size_of::<PendingDiagnostics>(),
        std::mem::size_of::<PendingCountObservation>(),
        std::mem::size_of::<RecoveryDiagnostics>(),
        std::mem::size_of::<PairRecovery>()
    );
    assert!(std::mem::size_of::<RecoveryDiagnostics>() <= 128);
    assert!(std::mem::size_of::<PendingDiagnostics>() <= 48);
    assert!(std::mem::size_of::<HeldPairCount>() <= 104);
}

#[test]
fn genuine_binding_rejection_withholds_the_candidate_and_keeps_history() {
    let mut disabled = Scene::placed();
    let mut enabled = Scene::placed_with_diagnostics(Some(DiagnosticConfig::default()));
    for scene in [&mut disabled, &mut enabled] {
        scene.observe(true, true, 200);
        scene.count(7);
        scene.native.unavailable_answer(7, 500);
        scene.observe(false, true, 300);
        scene.count(8);
        scene
            .native
            .query_answer(7, 500, crate::attach::capture::CookieQuery::NoCookie);
        scene.horizons();
        scene.native.answer(7, 500, 41);
        scene.count(10);
        scene.horizons();
        assert_eq!(
            scene.counts(),
            (5, 0),
            "a rejected original read cannot authorize later growth"
        );
    }
    assert_eq!(snapshot(&enabled), snapshot(&disabled));
    let lines = export(&mut enabled);
    assert!(
        lines
            .iter()
            .any(|line| line["decision"] == "rejected" && line["reason"] == "identity_changed")
    );
}
