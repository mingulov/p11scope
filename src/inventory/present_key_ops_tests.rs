//! SPDX-License-Identifier: GPL-3.0-or-later
//! Family-28 key-operation text summary: the `key operations:` block
//! `render_snapshot` prints directly after the `coverage:` line — one
//! header line plus one indented line per provider and category. Counts
//! per operation category from the shared `ObjectObservations` — the
//! same tallies the dashboard line shows, never object identity.

use super::*;
use crate::discovery::caller_registry::ModuleId;
use crate::discovery::caller_registry::RegistryLimits;
use crate::discovery::caller_registry::instance_input::{InstanceLifecycle, RegistryInstanceId};
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_dashboard::{DashboardState, DisplayFrame, LogTail, Viewport, render_frame};
use crate::key_operation_projection::{
    KeyAggRow, MetadataBlock, MetadataField, ObjectObservations, ObjectRow, ObsStatus,
    QueriesBlock, SECONDARY_ROLE, SessionRow, UnknownAggRow, object_observations_json,
};

/// A captured scale presentation carrying `observations`, the way the
/// live loop embeds a committed revision (mirrors
/// `key_operation_tests::harness_presentation`, which lives in another
/// test module).
fn key_ops_presentation(observations: ObjectObservations) -> Presentation {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "key-ops-text",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 92_000,
    });
    harness.commit();
    let mut presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    presentation.object_observations = observations;
    presentation
}

fn populated(revision: u64) -> ObjectObservations {
    let mut observations = ObjectObservations::unavailable(revision, "bootstrap_unavailable");
    observations.status = ObsStatus::Populated;
    observations.reason = "none";
    observations
}

fn key_row(
    category: &'static str,
    role: &'static str,
    completed: u64,
    failed: u64,
    active: u64,
    unit: &'static str,
) -> KeyAggRow {
    KeyAggRow {
        instance: "test-instance".to_string(),
        object: 11,
        category,
        role,
        metadata_at_use: "rsa_2048",
        unit,
        started: completed.saturating_add(failed).saturating_add(active),
        completed,
        failed,
        cancelled: 0,
        unknown: 0,
        active,
        key_join_lost: 0,
    }
}

fn unknown_row(
    category: &'static str,
    completed: u64,
    failed: u64,
    active: u64,
    unit: &'static str,
) -> UnknownAggRow {
    UnknownAggRow {
        category,
        reason: "unbound",
        unit,
        completed,
        failed,
        cancelled: 0,
        unknown: 0,
        active,
    }
}

/// Blank-metadata object record (mirrors the N9 `churned` record in
/// `key_operation_tests`, which lives in another test module).
fn object_row(object: u64) -> ObjectRow {
    let blank = MetadataField {
        status: "absent",
        scalar: None,
        curve: None,
    };
    let block = MetadataBlock {
        class: blank,
        key_type: blank,
        token: blank,
        value_len: blank,
        modulus_bits: blank,
        ec_params: blank,
        parameter_set: blank,
    };
    ObjectRow {
        object,
        session: 7,
        origin: "observed",
        creation: None,
        birth: None,
        lifetime: "destroyed",
        lifetime_reason: None,
        attribution: "valid",
        attribution_reason: None,
        requested: block,
        established: block,
        queries: QueriesBlock {
            class: "not_queried",
            key_type: "not_queried",
            token: "not_queried",
            value_len: "not_queried",
            modulus_bits: "not_queried",
            ec_params: "not_queried",
            parameter_set: "not_queried",
        },
        label: None,
        successful_references: 1,
        successful_key_references: 0,
        accessing_sessions: 1,
    }
}

/// The single `key operations:` line of a snapshot.
fn key_ops_line(snapshot: &str) -> &str {
    let lines: Vec<&str> = snapshot
        .lines()
        .filter(|line| line.starts_with("key operations:"))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one key operations line:\n{snapshot}"
    );
    lines[0]
}

/// A proved-key row on one instance and object: the per-provider tests'
/// handle for attributing tallies to providers. Primary role, operation
/// unit — the grouping inputs under test are instance and category.
fn key_row_on(
    instance: &str,
    object: u64,
    category: &'static str,
    completed: u64,
    failed: u64,
    active: u64,
) -> KeyAggRow {
    let mut row = key_row(category, "key", completed, failed, active, "operations");
    row.instance = instance.to_string();
    row.object = object;
    row
}

/// Four keys over two providers: two sessions, four object rows, and
/// proved rows on instances `i0`/`i1` resolving to two provider
/// modules. The per-provider wrap test's fixture.
fn two_provider_presentation() -> Presentation {
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.sessions.push(SessionRow {
        session: 8,
        origin: "opened",
        status: "live",
    });
    for object in [11, 12, 13, 14] {
        observations.objects.push(object_row(object));
    }
    observations
        .key_operations
        .push(key_row_on("i0", 11, "sign", 2, 1, 0));
    observations
        .key_operations
        .push(key_row_on("i0", 12, "sign", 3, 0, 1));
    observations
        .key_operations
        .push(key_row_on("i1", 13, "decrypt", 4, 0, 0));
    observations
        .key_operations
        .push(key_row_on("i1", 14, "decrypt", 1, 2, 0));
    let mut presentation = key_ops_presentation(observations);
    presentation.modules[0].paths = vec!["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so".into()];
    let first_module = presentation.modules[0].id;
    let next_module = presentation
        .modules
        .iter()
        .map(|module| module.id.0)
        .max()
        .unwrap()
        + 1;
    let mut second = presentation.modules[0].clone();
    second.id = ModuleId(next_module);
    second.paths = vec!["/opt/vendor/libfoo-pkcs11.so".into()];
    presentation.modules.push(second);
    let caller = presentation.callers[0].id;
    // Only the fixture's instances resolve, whatever the harness carried.
    presentation.instances.clear();
    for (raw, module) in [(0u32, first_module), (1, ModuleId(next_module))] {
        presentation.instances.push(InstanceView {
            id: RegistryInstanceId::from_raw(raw),
            caller,
            module,
            state: InstanceLifecycle::Observed,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        });
    }
    presentation
}

/// The dashboard H9 projection line at a wide viewport (mirrors
/// `key_operation_tests::dashboard_text`, which lives in another test
/// module).
fn dashboard_projection_line(presentation: &Presentation) -> String {
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 1: key ops text");
    let frame = DisplayFrame {
        presentation: std::sync::Arc::new(presentation.clone()),
        log: tail.snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 300,
            height: 24,
        },
        &DashboardState::new(),
    );
    let text = String::from_utf8(bytes).expect("frames are valid UTF-8");
    text.replace("\x1b[H", "")
        .replace("\x1b[K", "")
        .lines()
        .find(|line| line.starts_with("keys revision"))
        .expect("projection line")
        .to_string()
}

/// Per-category (completed, failed, active) summed over a snapshot's
/// key-operations block: provider lines plus `unknown keys` lines.
/// Anything unexpected fails loudly, never parses silently.
fn snapshot_tallies(snapshot: &str) -> Vec<(&str, u64, u64, u64)> {
    use std::collections::BTreeMap;
    let mut tallies: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
    for line in key_ops_block(snapshot).iter().skip(1) {
        if line.starts_with("  not attributed:")
            || line.starts_with("  type unknown")
            || line.starts_with("  pqc keys:")
            || *line == "  no key operations observed"
        {
            continue;
        }
        // "  <provider>: <category> <completed> completed, <failed> returned
        // an error/errors, <active> active <unit> [(machine)]", or the same
        // shape under "unknown keys". Verbose machine suffixes never reach
        // the tally: the unit suffix gates the parse.
        let (_, segment) = line
            .split_once(": ")
            .unwrap_or_else(|| panic!("key-ops detail line without a tally: {line}"));
        let segment = segment.split_once(" (").map_or(segment, |(tally, _)| tally);
        // "<category> <completed> completed, <failed> returned an error/errors, <active> active <unit>"
        let (category, rest) = segment.split_once(' ').expect("category");
        let rest = rest
            .strip_suffix(" operations")
            .or_else(|| rest.strip_suffix(" message_contexts"))
            .expect("unit");
        let mut words = rest.split(' ');
        let completed: u64 = words.next().expect("completed").parse().expect("digits");
        assert_eq!(words.next(), Some("completed,"));
        let failed: u64 = words.next().expect("failed").parse().expect("digits");
        assert_eq!(words.next(), Some("returned"));
        match words.next() {
            Some("an") => {
                assert_eq!(failed, 1, "singular for one: {line}");
                assert_eq!(words.next(), Some("error,"));
            }
            Some("errors,") => {}
            other => panic!("failed noun: {other:?} in {line}"),
        }
        let active: u64 = words.next().expect("active").parse().expect("digits");
        assert_eq!(words.next(), Some("active"));
        assert_eq!(words.next(), None);
        let slot = tallies.entry(category).or_insert((0, 0, 0));
        slot.0 = slot.0.saturating_add(completed);
        slot.1 = slot.1.saturating_add(failed);
        slot.2 = slot.2.saturating_add(active);
    }
    tallies
        .into_iter()
        .map(|(category, (completed, failed, active))| (category, completed, failed, active))
        .collect()
}

/// Per-category (completed, failed, active) parsed from a dashboard
/// `keys revision` line.
fn dashboard_tallies(line: &str) -> Vec<(&str, u64, u64, u64)> {
    let tail = line.split(" | ").nth(2).expect("tally tail");
    let mut tallies = Vec::new();
    for segment in tail.split(", ") {
        // "<category> <completed>/<failed>/<active> <unit>"
        let (category, rest) = segment.split_once(' ').expect("category");
        let (counts, _unit) = rest.split_once(' ').expect("unit");
        let mut counts = counts.split('/');
        let completed: u64 = counts.next().expect("completed").parse().expect("digits");
        let failed: u64 = counts.next().expect("failed").parse().expect("digits");
        let active: u64 = counts.next().expect("active").parse().expect("digits");
        assert_eq!(counts.next(), None);
        tallies.push((category, completed, failed, active));
    }
    tallies
}

#[test]
fn key_ops_line_unavailable_names_reason() {
    let presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "bootstrap_unavailable"));
    let snapshot = render_snapshot(&presentation);
    let lines: Vec<&str> = snapshot.lines().collect();
    let coverage = lines
        .iter()
        .position(|line| line.starts_with("coverage: "))
        .expect("coverage line");
    assert_eq!(
        lines[coverage + 1],
        "key operations: not available — per-key tracking never started, so no key can be named yet",
        "the unavailable line sits directly after coverage:\n{snapshot}"
    );
    assert_eq!(
        snapshot
            .lines()
            .filter(|line| line.starts_with("key operations:"))
            .count(),
        1,
        "exactly one key operations line:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_counts_not_attributed_beside_exact_rows() {
    let mut observations = populated(9);
    observations.status = ObsStatus::Partial;
    observations.reason = "authority_lost";
    observations
        .key_operations
        .push(key_row("sign", "key", 4, 0, 0, "operations"));
    observations.add_unattributed("record_lost", 2);
    observations.add_unattributed("proof_refused_fallback", 3);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert_eq!(
        block,
        vec![
            "key operations: 0 keys on 1 provider; rev 9 partial; 0 sessions",
            "  per-key tracking lost some calls; exact rows continue",
            "  unidentified provider: sign 4 completed, 0 returned errors, 0 active operations",
            "  not attributed: record_lost 2",
            "  not attributed: proof_refused_fallback 3",
        ],
        "exact rows stay, counts sit beside them in frozen order:\n{snapshot}"
    );
}

/// v0.7.0 issue 2: a partial section whose rows continue never reads
/// "stopped" — the reason names the loss while the exact rows beside
/// it continue. Both key rows and unknown rows count as continuing
/// rows; the machine reason stays `authority_lost` (verbose only).
#[test]
fn key_ops_line_partial_authority_lost_with_rows_names_continuing_rows() {
    for (label, mut observations) in [
        ("key row", {
            let mut observations = populated(9);
            observations.status = ObsStatus::Partial;
            observations.reason = "authority_lost";
            observations
                .key_operations
                .push(key_row("sign", "key", 4, 0, 0, "operations"));
            observations
        }),
        ("unknown row", {
            let mut observations = populated(9);
            observations.status = ObsStatus::Partial;
            observations.reason = "authority_lost";
            observations
                .unknown_key_operations
                .push(unknown_row("sign", 4, 0, 0, "operations"));
            observations
        }),
    ] {
        observations.add_unattributed("record_lost", 2);
        let presentation = key_ops_presentation(observations);
        let snapshot = render_snapshot(&presentation);
        let block = key_ops_block(&snapshot);
        let reason = block
            .iter()
            .find(|line| line.contains("per-key tracking lost some calls"))
            .unwrap_or_else(|| panic!("{label}: the reason line: {snapshot}"));
        assert_eq!(
            *reason, "  per-key tracking lost some calls; exact rows continue",
            "{label}: the reason matches the continuing rows: {snapshot}"
        );
        let text = block.join("\n");
        assert!(
            !text.contains("stopped"),
            "{label}: nothing reads stopped while rows continue: {snapshot}"
        );
        assert!(
            !text.contains("authority_lost"),
            "{label}: concise keeps the machine reason out: {snapshot}"
        );
        let verbose =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
        let verbose_block = key_ops_block(&verbose);
        assert!(
            verbose_block
                .iter()
                .any(|line| line.contains("(reason: authority_lost)")),
            "{label}: verbose keeps the machine reason: {verbose}"
        );
    }
}

/// v0.7.0 issue 2 (pin): a partial `authority_lost` section with no
/// rows at all (counts only) keeps reading "stopped" — nothing
/// continues, so the stopped wording is accurate there, as in the
/// unavailable section.
#[test]
fn key_ops_line_partial_authority_lost_without_rows_keeps_stopped() {
    let mut observations = populated(9);
    observations.status = ObsStatus::Partial;
    observations.reason = "authority_lost";
    observations.add_unattributed("record_lost", 2);
    assert!(observations.key_operations.is_empty());
    assert!(observations.unknown_key_operations.is_empty());
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert!(
        block.contains(&"  per-key tracking stopped; plain counts are unaffected"),
        "counts-only partial keeps stopped: {snapshot}"
    );
}

/// DEMO-4: a first-observed key row under the `unknown` metadata
/// label reads in text as type unknown (not established while
/// observed), beside the exact tallies. The text claims no timing it
/// cannot prove (the key may predate attach or its attribute call may
/// simply be unobserved).
#[test]
fn key_ops_line_names_unknown_type_not_established_while_observed() {
    let mut observations = populated(9);
    let mut row = key_row("sign", "key", 2, 0, 0, "operations");
    row.metadata_at_use = "unknown";
    observations.key_operations.push(row);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert_eq!(
        block,
        vec![
            "key operations: 0 keys on 1 provider; rev 9 populated; 0 sessions",
            "  unidentified provider: sign 2 completed, 0 returned errors, 0 active operations",
            "  type unknown (not established while observed) (1 key row)",
        ],
        "the tallies stay exact, the unknown type is named, never guessed:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_journal_unavailable_names_tracking_off() {
    let presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: not reported (per-key tracking is off)",
        "journal_unavailable names tracking off:\n{snapshot}"
    );
}

/// The remedy gap the seal path notes when `--key-operations` was
/// requested but no semantic subset minted.
fn subset_refused_gap(reason: &str) -> GapView {
    GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "key operations unavailable".into(),
        reason: reason.into(),
        budget: None,
        repeats: 1,
    }
}

#[test]
fn key_ops_line_subset_refused_names_manifest_for_softhsm() {
    // Requested tracking, refused subset, one SoftHSM module: the
    // line names the provider by file name like any other provider,
    // plus the rerun, never tracking-off.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.modules[0].paths = vec!["/usr/lib64/pkcs11/libsofthsm2.so".into()];
    presentation.gaps.push(subset_refused_gap(
        "subset refused (incomplete_provider); provider function tables cannot be verified \
         without operator attestation: rerun with --manifest <manifest.json> for per-key rows; \
         broad inventory continues with S1 mechanisms and API results",
    ));
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: libsofthsm2.so's function table cannot be verified \
         without --manifest; rerun with --manifest",
        "the SoftHSM line names the file and the rerun:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_subset_refused_names_basename_for_other_providers() {
    // Same refusal, an unfamiliar provider file: the line names the
    // file's basename, never a guessed product.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.modules[0].paths = vec!["/opt/vendor/libfoo-pkcs11.so".into()];
    presentation.gaps.push(subset_refused_gap(
        "subset refused (incomplete_provider); rerun with --manifest <manifest.json>",
    ));
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: libfoo-pkcs11.so's function table cannot be verified \
         without --manifest; rerun with --manifest",
        "generic providers read by basename:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_subset_refused_without_single_module_stays_generic() {
    // Same refusal, zero or several modules: no single provider is
    // nameable, so the line stays generic but still remedies.
    for extra in [false, true] {
        let mut presentation =
            key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
        if extra {
            let mut second = presentation.modules[0].clone();
            second.paths = vec!["/opt/vendor/libfoo-pkcs11.so".into()];
            presentation.modules.push(second);
        } else {
            presentation.modules.clear();
        }
        presentation.gaps.push(subset_refused_gap(
            "subset refused (incomplete_provider); rerun with --manifest <manifest.json>",
        ));
        let snapshot = render_snapshot(&presentation);
        assert_eq!(
            key_ops_line(&snapshot),
            "key operations: provider function tables cannot be verified \
             without --manifest; rerun with --manifest",
            "extra={extra}: generic but remedied:\n{snapshot}"
        );
    }
}

#[test]
fn key_ops_line_requested_without_manifest_names_manifest() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.key_operations_requested = true;
    presentation.manifests_present = false;
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: requested, but per-key tracking needs --manifest",
        "requested without a manifest never reads 'off':\n{snapshot}"
    );
}

#[test]
fn key_ops_line_manifest_path_refusal_names_check_remedy() {
    // Manifest-path refusal: the summary names the file but remedies
    // with check-the-manifest, never the rerun.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.modules[0].paths = vec!["/opt/vendor/libfoo-pkcs11.so".into()];
    presentation.gaps.push(subset_refused_gap(
        "subset refused (incomplete_provider); provider function tables cannot be verified \
         from the supplied --manifest inputs: check the manifest inputs for per-key rows; \
         broad inventory continues with S1 mechanisms and API results",
    ));
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: libfoo-pkcs11.so's function table cannot be verified \
         from the supplied --manifest inputs; check the manifest",
        "manifest-path line checks, never reruns:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_requested_with_manifest_and_no_gap_stays_off() {
    // Requested with a manifest but no start was recorded and no gap
    // exists (no start was refused): the conservative fallthrough is
    // "off", and only the manifest-less request names --manifest.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.key_operations_requested = true;
    presentation.manifests_present = true;
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_line(&snapshot),
        "key operations: not reported (per-key tracking is off)",
        "manifested request without a gap stays off:\n{snapshot}"
    );
}

/// Item 6: concise folds a denied live-capture refusal to one short
/// clause; the full host summary stays verbose-only.
#[test]
fn concise_gap_summary_folds_denied_capture_refusal() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    let stored = "live capture refused (live capture needs CAP_BPF (load BPF programs and attach \
        probes); needs CAP_PERFMON (load BPF programs alongside CAP_BPF): the kernel refused to load \
        p11scope's BPF programs (Operation not permitted). Grant the minimal set: sudo setcap \
        'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' \
        /usr/bin/p11scope, or use 'p11scope inspect --pid N' for a scan without capture.); grant \
        the minimal capability set for full capture (see 'p11scope doctor')";
    presentation
        .gaps
        .push(named_gap("native usage feed unavailable", stored));
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    // The group line would run past 100 chars, so the reason gives way
    // (marked) while the short machine-name subject stays whole.
    assert_eq!(
        block,
        vec![
            "gaps: 1",
            "  1 × native usage feed unavailable — live capture refused (missing capabilities); run \
             'p11scope do…",
        ],
        "the concise gaps block:\n{concise}"
    );
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars: {:?}",
        block[1]
    );
    assert!(!concise.contains("Operation not permitted"), "{concise}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains(stored), "{verbose}");
}

/// Item 6: a non-denied refusal (old kernel, verifier) folds without
/// sudo advice; sudo cannot help there.
#[test]
fn concise_gap_summary_folds_unproven_capture_refusal() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    let stored = "live capture refused (live capture did not start: loading p11scope's BPF \
        programs failed (Permission denied); run 'p11scope doctor' for host readiness, or use \
        'p11scope inspect --pid N' for a scan without capture.)";
    presentation
        .gaps
        .push(named_gap("native usage feed unavailable", stored));
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(
        block,
        vec![
            "gaps: 1",
            "  1 × native usage feed unavailable — live capture refused (see 'p11scope doctor')",
        ],
        "the concise gaps block:\n{concise}"
    );
    assert!(!concise.contains("sudo"), "{concise}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(verbose.contains(stored), "{verbose}");
}

#[test]
fn key_ops_line_manifest_path_refusal_without_single_module_stays_generic() {
    // Manifest-path refusal, zero or several modules: no single
    // provider is nameable, so the line stays generic but still
    // names the check remedy.
    for extra in [false, true] {
        let mut presentation =
            key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
        if extra {
            let mut second = presentation.modules[0].clone();
            second.paths = vec!["/opt/vendor/libfoo-pkcs11.so".into()];
            presentation.modules.push(second);
        } else {
            presentation.modules.clear();
        }
        presentation.gaps.push(subset_refused_gap(
            "subset refused (incomplete_provider); provider function tables cannot be verified \
             from the supplied --manifest inputs: check the manifest inputs for per-key rows; \
             broad inventory continues with S1 mechanisms and API results",
        ));
        let snapshot = render_snapshot(&presentation);
        assert_eq!(
            key_ops_line(&snapshot),
            "key operations: provider function tables cannot be verified \
             from the supplied --manifest inputs; check the manifest",
            "extra={extra}: generic but checked:\n{snapshot}"
        );
    }
}

#[test]
fn key_ops_line_requested_but_refused_names_request_not_tracking_off() {
    // The flag was given but the seal refused (subset or journal
    // start): the `key operations unavailable` gap proves tracking was
    // wanted, so the header names the request and the cause, never
    // tracking-off — one wording per state (I1).
    for reason in [
        "subset refused; broad inventory continues with S1 mechanisms and API results",
        "journal-pair-missing: p11scope-journal-btf; broad inventory continues with S1 mechanisms and API results",
    ] {
        let mut presentation =
            key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: "key operations unavailable".into(),
            reason: reason.into(),
            budget: None,
            repeats: 1,
        });
        let snapshot = render_snapshot(&presentation);
        let line = key_ops_line(&snapshot);
        let want = format!(
            "key operations: requested, but per-key tracking did not start ({})",
            reason.split(';').next().unwrap().trim()
        );
        assert_eq!(line, want, "reason={reason:?}:\n{snapshot}");
        assert!(
            !line.contains("tracking is off"),
            "a refused request never reads tracking-off: {line}"
        );
    }
}

#[test]
fn key_ops_line_populated_counts_primary_once() {
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    // The secondary association stands beside the primary's row: its
    // large counts must never leak into the tally (H9 §82).
    observations
        .key_operations
        .push(key_row("sign", SECONDARY_ROLE, 100, 50, 25, "operations"));
    observations
        .unknown_key_operations
        .push(unknown_row("sign", 3, 0, 1, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_block(&snapshot),
        vec![
            "key operations: 1 key on 1 provider; rev 3 populated; 1 session",
            "  unidentified provider: sign 2 completed, 1 returned an error, 0 active operations",
            "  unknown keys: sign 3 completed, 0 returned errors, 1 active operations",
        ],
        "primary + unknown only, secondary never double-counted:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_stale_shows_reason() {
    let mut observations = ObjectObservations::unavailable(9, "bootstrap_unavailable");
    observations.status = ObsStatus::Stale;
    observations.reason = "publication_budget_exhausted";
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    assert_eq!(
        key_ops_block(&snapshot),
        vec![
            "key operations: 0 keys on 0 providers; rev 9 stale; 0 sessions",
            "  key publication hit its budget; plain counts are unaffected",
            "  no key operations observed",
        ],
        "stale names its reason:\n{snapshot}"
    );
}

#[test]
fn key_ops_line_lossless_large_values() {
    let mut observations = populated(5);
    observations.key_operations.push(key_row(
        "sign",
        "key",
        18_446_744_073_709_551_614,
        0,
        0,
        "operations",
    ));
    observations
        .key_operations
        .push(key_row("verify", "key", u64::MAX, 0, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert_eq!(
        block,
        vec![
            "key operations: 0 keys on 1 provider; rev 5 populated; 0 sessions",
            "  unidentified provider: sign 18446744073709551614 completed, 0 returned errors, 0 active operations",
            "  unidentified provider: verify 18446744073709551615 completed, 0 returned errors, 0 active operations",
        ],
        "u64 digits render exactly, categories in order:\n{snapshot}"
    );
    // The documented exception to the 100-char cap: exact digits win,
    // so a pathological tally beside a fixed label exceeds it rather
    // than truncating counts.
    assert!(
        block[2].chars().count() > 100,
        "counts stay exact past the cap: {:?}",
        block[2]
    );
}

#[test]
fn key_ops_line_matches_dashboard_tallies() {
    let mut observations = populated(11);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations.objects.push(object_row(12));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 3, "operations"));
    observations
        .key_operations
        .push(key_row("wrap", "wrapping_key", 4, 0, 1, "operations"));
    observations
        .key_operations
        .push(key_row("wrap", SECONDARY_ROLE, 40, 41, 42, "operations"));
    observations
        .unknown_key_operations
        .push(unknown_row("sign", 5, 6, 7, "operations"));
    let presentation = key_ops_presentation(observations.clone());
    let snapshot = render_snapshot(&presentation);
    let text_tallies = snapshot_tallies(&snapshot);
    let frame_line = dashboard_projection_line(&presentation);
    let frame_tallies = dashboard_tallies(&frame_line);
    assert_eq!(
        text_tallies, frame_tallies,
        "text and dashboard agree per category"
    );
    assert_eq!(
        text_tallies,
        vec![("sign", 7, 7, 10), ("wrap", 4, 0, 1)],
        "primary + unknown only, category order"
    );

    // Negative control: a different projection disagrees.
    let mut other = observations;
    other.key_operations[0].completed = 200;
    let other_presentation = key_ops_presentation(other);
    let other_line = dashboard_projection_line(&other_presentation);
    let other_frame = dashboard_tallies(&other_line);
    assert_ne!(
        text_tallies, other_frame,
        "the comparison is sensitive to the tallies"
    );
}

/// F5: the tally says what happened to the call ("returned an
/// error/errors"), not "failed" (which reads as an observer failure).
/// JSON keys stay `failed`.
#[test]
fn key_ops_tally_says_returned_an_error_not_failed() {
    let mut observations = populated(3);
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    observations
        .key_operations
        .push(key_row("verify", "key", 5, 2, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot).join("\n");
    assert!(
        block.contains("1 returned an error"),
        "singular tally missing: {block}"
    );
    assert!(
        block.contains("2 returned errors"),
        "plural tally missing: {block}"
    );
    assert!(
        !block.contains(" failed"),
        "observer-failure wording leaked: {block}"
    );
}

/// F5: the dashboard projection line spells its fields (sessions,
/// keys, per-key rows, unattributed rows, revision, refused), not
/// `sess/obj/krows/urows/rev`.
#[test]
fn dashboard_projection_line_spells_fields() {
    let mut observations = populated(91);
    observations.status = ObsStatus::Populated;
    observations.reason = "none";
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 1: f5");
    let frame = DisplayFrame {
        presentation: std::sync::Arc::new(presentation),
        log: tail.snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 300,
            height: 24,
        },
        &DashboardState::new(),
    );
    let text = String::from_utf8(bytes).expect("frames are valid UTF-8");
    let line = text
        .replace("\x1b[H", "")
        .replace("\x1b[K", "")
        .lines()
        .find(|line| line.contains("rev"))
        .expect("projection line")
        .to_string();
    for plain in [
        "revision",
        "sessions",
        "per-key rows",
        "unattributed rows",
        "refused",
    ] {
        assert!(line.contains(plain), "{plain} missing: {line}");
    }
    for abbrev in ["sess ", "krows", "urows", " rev "] {
        assert!(!line.contains(abbrev), "{abbrev} leaked: {line}");
    }
}

#[test]
fn key_ops_line_carries_no_object_identity() {
    let mut observations = populated(13);
    observations.sessions.push(SessionRow {
        session: 123_456_789,
        origin: "first_observed",
        status: "live",
    });
    let mut row = object_row(987_654_321_098);
    row.label = Some("label-7X-secret");
    row.requested.value_len = MetadataField {
        status: "value",
        scalar: Some(42421),
        curve: None,
    };
    row.established.ec_params = MetadataField {
        status: "value",
        scalar: None,
        curve: Some("secp384r1"),
    };
    observations.objects.push(row);
    let mut key = key_row("sign", "key", 2, 0, 1, "operations");
    key.instance = "instance-9Z-private".to_string();
    key.object = 987_654_321_098;
    observations.key_operations.push(key);
    let presentation = key_ops_presentation(observations.clone());
    let snapshot = render_snapshot(&presentation);
    // The whole concise block carries counts only, never identity — the
    // header and every provider line, not just the header.
    let block = key_ops_block(&snapshot).join("\n");
    for forbidden in [
        "987654321098",
        "123456789",
        "label-7X-secret",
        "42421",
        "secp384r1",
        "instance-9Z-private",
    ] {
        assert!(
            !block.contains(forbidden),
            "text block carries no object identity ({forbidden}): {block}"
        );
    }
    // Positive control: the JSON section still carries every token.
    let document = serde_json::to_string(&object_observations_json(&observations)).unwrap();
    for token in [
        "987654321098",
        "123456789",
        "label-7X-secret",
        "42421",
        "secp384r1",
        "instance-9Z-private",
    ] {
        assert!(
            document.contains(token),
            "JSON keeps the identity token ({token})"
        );
    }
}

fn named_gap(subject: &str, reason: &str) -> GapView {
    GapView {
        caller: None,
        module: None,
        pid: None,
        subject: subject.into(),
        reason: reason.into(),
        budget: None,
        repeats: 1,
    }
}

/// A linked lane with observed semantic calls and no Joint feed or
/// birth refusal names its `bootstrap_unavailable` once; the twins
/// (no calls, a named refusal, any other reason) add nothing.
#[test]
fn silent_bootstrap_unavailable_is_named_once() {
    let silent = ObjectObservations::unavailable(7, "bootstrap_unavailable");
    let gap = silent_bootstrap_gap(&silent, 1, &[named_gap("semantic input refused", "slot")])
        .expect("observed calls with no birth and no refusal are named");
    assert_eq!(gap.subject, "Joint birth unavailable; retained S1");
    assert_eq!(gap.reason, "joint_birth_unoffered");
    assert_eq!(gap.repeats, 1);
    assert!(
        silent_bootstrap_gap(&silent, 0, &[]).is_none(),
        "no observed calls: nothing owed"
    );
    let refused = [named_gap(
        "Joint birth unavailable; retained S1",
        "joint_birth_native_RowUnreadable",
    )];
    assert!(
        silent_bootstrap_gap(&silent, 1, &refused).is_none(),
        "a refusal already names it"
    );
    for reason in [
        "journal_unavailable",
        "proof_refused_fallback",
        "authority_lost",
    ] {
        let other = ObjectObservations::unavailable(7, reason);
        assert!(
            silent_bootstrap_gap(&other, 1, &[]).is_none(),
            "{reason} carries its own cause"
        );
    }
    assert!(silent_bootstrap_gap(&populated(7), 1, &[]).is_none());
}

/// The wiring's twin: a linked capture without any observed semantic
/// call has nothing to name, so its presentation adds no gap.
#[test]
fn presentation_without_semantic_calls_adds_no_bootstrap_gap() {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "idle-bootstrap",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 93_000,
    });
    harness.commit();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert_eq!(
        presentation.object_observations.reason,
        "bootstrap_unavailable"
    );
    assert!(presentation.semantic_edges.is_empty());
    assert!(
        presentation
            .gaps
            .iter()
            .all(|gap| gap.reason != "joint_birth_unoffered")
    );
}

/// The middle twin: one registered instance with zero reduced calls
/// still yields a semantic row, so its silent `bootstrap_unavailable`
/// is named. The gap fires on registration, not on observed calls.
#[test]
fn presentation_with_registered_instance_and_no_calls_names_bootstrap_gap() {
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::ModuleKey;
    use crate::discovery::caller_registry::instance_input as instance;
    use crate::discovery::instances::InstanceId;
    use p11scope_ebpf_common::ImageIdentity;
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "idle-registered",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 94_000,
    });
    harness.commit();
    let caller = harness
        .coordinator()
        .adapter()
        .live_id(94_000)
        .expect("live caller");
    let module = ModuleKey::physical(8, 1, 100_000, Some("sha000000".into()), "/scale/m0.so");
    let domain = NativeDomainId::mint();
    let key = instance::key(
        domain,
        ImageIdentity {
            task_cookie: 1000,
            exec_id: 0,
        },
        InstanceId::from_raw(1),
        module,
    );
    harness
        .coordinator_mut()
        .registry_mut()
        .note_instance(instance::registration(key, caller, 100, None));
    harness.commit();
    let presentation = Presentation::capture(harness.coordinator(), "workload", 1, 2, 1);
    assert_eq!(
        presentation.object_observations.reason,
        "bootstrap_unavailable"
    );
    assert_eq!(presentation.semantic_edges.len(), 1);
    assert!(
        presentation
            .gaps
            .iter()
            .any(|gap| gap.reason == "joint_birth_unoffered"),
        "a registered instance with no calls is still owed a name"
    );
}

/// CLI-1/KEY-2: an unavailable key-operations section names its reason
/// in plain words; verbose pairs the machine reason beside it.
#[test]
fn unavailable_key_operations_name_plain_reason_with_machine_code() {
    for (reason, plain) in [
        (
            "bootstrap_unavailable",
            "per-key tracking never started, so no key can be named yet",
        ),
        (
            "authority_lost",
            "per-key tracking stopped; plain counts are unaffected",
        ),
        (
            "row_budget_exhausted",
            "per-key rows hit their budget; plain counts are unaffected",
        ),
    ] {
        let presentation = key_ops_presentation(ObjectObservations::unavailable(3, reason));
        let concise =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains(&format!("key operations: not available — {plain}")),
            "{reason}: {concise}"
        );
        assert!(!concise.contains(reason), "{reason} leaked: {concise}");
        let verbose =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains(plain), "{reason}: {verbose}");
        assert!(
            verbose.contains(&format!("(reason: {reason})")),
            "{reason}: {verbose}"
        );
    }
}

/// F3: the unlinked-journal, seal and fallback gaps render in plain
/// words with their machine tokens beside them (verbose); concise
/// must never see the raw `S1` / `joint_*` strings.
#[test]
fn joint_journal_seal_fallback_gaps_render_plain_words_with_machine_tokens() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "per-key tracking is off; this capture keeps S1 mechanisms and API results".into(),
        reason: "joint_journal_unavailable".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_seal_h3_loss_history_loss".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_fallback_staging_full".into(),
        budget: None,
        repeats: 1,
    });
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("per-key tracking is off; function and mechanism counts are unaffected"),
        "keeps-S1 subject needs a plain twin: {verbose}"
    );
    assert!(
        verbose.contains("per-key tracking ended early"),
        "joint_seal_* needs a plain twin: {verbose}"
    );
    assert!(
        verbose.contains("per-key tracking fell back to plain counts"),
        "joint_fallback_* needs a plain twin: {verbose}"
    );
    // The machine tokens stay beside the plain words in verbose text.
    assert!(
        verbose.contains("(joint_seal_h3_loss_history_loss)"),
        "{verbose}"
    );
    assert!(
        verbose.contains("(joint_fallback_staging_full)"),
        "{verbose}"
    );
    assert!(
        verbose.contains(
            "(per-key tracking is off; this capture keeps S1 mechanisms and API results)"
        ),
        "{verbose}"
    );
}

/// CLI-1/KEY-3: the Joint birth gap renders in plain words with the
/// machine subject and reason beside it.
#[test]
fn joint_birth_gap_renders_plain_words_with_machine_reason() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "Joint key operations unavailable; retained S1".into(),
        reason: "joint_birth_unoffered".into(),
        budget: None,
        repeats: 1,
    });
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: JOINT_BIRTH_UNAVAILABLE_SUBJECT.into(),
        reason: "joint_birth_unoffered".into(),
        budget: None,
        repeats: 1,
    });
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("Per-key tracking did not start for this process"),
        "{verbose}"
    );
    assert!(
        verbose.contains("no key session was offered to track"),
        "{verbose}"
    );
    assert!(verbose.contains("(joint_birth_unoffered)"), "{verbose}");
    assert!(
        verbose.contains("(Joint key operations unavailable; retained S1)"),
        "{verbose}"
    );
    assert!(
        verbose.contains("(Joint birth unavailable; retained S1)"),
        "{verbose}"
    );
}

/// A refused image stays S1 with a truthful plain reason: its calls
/// shed (or its records proved unusable) before tracking could cover
/// them, so per-key tracking cannot start from its first call. The
/// old "image changed" wording blamed an exec that never happened.
#[test]
fn joint_refused_image_gap_names_untracked_prefix_not_an_image_change() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
    for reason in ["joint_image_refused", "joint_birth_claim_ImageTainted"] {
        presentation.gaps.push(GapView {
            caller: None,
            module: None,
            pid: None,
            subject: JOINT_BIRTH_UNAVAILABLE_SUBJECT.into(),
            reason: reason.into(),
            budget: None,
            repeats: 1,
        });
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        concise.contains("process was not tracked from its first call"),
        "{concise}"
    );
    assert!(
        !concise.contains("process image changed before tracking could start"),
        "stale exec-blaming text leaked: {concise}"
    );
    assert!(
        !concise.contains("joint_image_refused")
            && !concise.contains("joint_birth_claim_ImageTainted"),
        "machine reasons leaked to concise: {concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("process was not tracked from its first call"),
        "{verbose}"
    );
    assert!(verbose.contains("(joint_image_refused)"), "{verbose}");
    assert!(
        verbose.contains("(joint_birth_claim_ImageTainted)"),
        "{verbose}"
    );
}

/// Item 14: when --key-operations was requested but per-key tracking did
/// not start, the line names the request and the cause; without the
/// request gap it stays "not reported (per-key tracking is off)".
#[test]
fn key_ops_line_requested_but_not_started_names_cause() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.push(GapView {
        caller: None,
        module: None,
        pid: None,
        subject: "key operations unavailable".into(),
        reason:
            "test journal refused; broad inventory continues with S1 mechanisms and API results"
                .into(),
        budget: None,
        repeats: 1,
    });
    let snapshot =
        render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    assert!(
        key_ops_line(&snapshot)
            .starts_with("key operations: requested, but per-key tracking did not start"),
        "{snapshot}"
    );
    assert!(
        !key_ops_line(&snapshot).contains("not reported"),
        "{snapshot}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        key_ops_line(&verbose)
            .starts_with("key operations: requested, but per-key tracking did not start"),
        "{verbose}"
    );
    let plain = key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    assert_eq!(
        key_ops_line(&render_snapshot(&plain)),
        "key operations: not reported (per-key tracking is off)",
    );
}

/// I7: overlay-witness gap reasons render in plain words in text
/// (concise folds, verbose pairs the machine token beside them);
/// JSON keeps the stored reasons unchanged.
#[test]
fn overlay_witness_gap_reasons_render_plain_words_with_machine_tokens() {
    let cases = [
        (
            "original_file_unproven: the kernel witness proved another file",
            "mapping is another file, not the held file",
        ),
        (
            "original_file_unproven: witness query budget exhausted",
            "kernel proof budget exhausted",
        ),
        (
            "original_file_unproven: kernel witness unavailable",
            "kernel proof unavailable",
        ),
        (
            "original_file_unproven: kernel witness unavailable: \
             scoped collection deactivates the kernel proof",
            "kernel proof unavailable",
        ),
        (
            "original_file_unproven: witness anchor binding failed",
            "kernel proof anchor failed",
        ),
    ];
    // Concise: one gap at a time (no folding), plain only.
    for (reason, plain) in cases {
        let mut presentation =
            key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
        presentation.gaps.clear();
        presentation
            .gaps
            .push(named_gap("/provider/lib.so", reason));
        let concise =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
        let block = gaps_block(&concise);
        assert_eq!(block.len(), 2, "header plus one group line: {concise}");
        assert!(block[1].contains(plain), "{reason}: {concise}");
        assert!(
            !concise.contains("original_file_unproven"),
            "{reason}: {concise}"
        );
        assert!(!concise.contains("kernel witness"), "{reason}: {concise}");
    }
    // Verbose: every gap line pairs plain words with the machine token.
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(3, "bootstrap_unavailable"));
    presentation.gaps.clear();
    for (reason, _) in cases {
        presentation
            .gaps
            .push(named_gap("/provider/lib.so", reason));
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    for (reason, plain) in cases {
        assert!(verbose.contains(plain), "{reason}: {verbose}");
        assert!(
            verbose.contains(&format!("({reason})")),
            "{reason}: {verbose}"
        );
    }
    // JSON keeps the stored machine reasons.
    let document = crate::inventory::render_json_from_presentation(&presentation);
    let stored: Vec<&str> = document["gaps"]
        .as_array()
        .expect("gaps array")
        .iter()
        .map(|gap| gap["reason"].as_str().expect("reason"))
        .collect();
    for (reason, _) in cases {
        assert!(stored.contains(&reason), "{reason} missing: {stored:?}");
    }
}

/// The key-operations block: the header plus every indented detail line
/// that follows it, stopping at the next flush-left line.
fn key_ops_block(snapshot: &str) -> Vec<&str> {
    let lines: Vec<&str> = snapshot.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("key operations:"))
        .expect("key operations header");
    let mut block = vec![lines[start]];
    for line in &lines[start + 1..] {
        if line.starts_with(' ') {
            block.push(line);
        } else {
            break;
        }
    }
    block
}

/// The concise gaps block: the `gaps: N` header plus every indented
/// group line that follows it.
fn gaps_block(snapshot: &str) -> Vec<&str> {
    let lines: Vec<&str> = snapshot.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("gaps:"))
        .expect("gaps header");
    let mut block = vec![lines[start]];
    for line in &lines[start + 1..] {
        if line.starts_with(' ') {
            block.push(line);
        } else {
            break;
        }
    }
    block
}

/// Readable key operations: four keys over two providers render one
/// header line plus one line per provider, every line at most 100
/// chars, with no machine instance labels in concise text. The JSON
/// section keeps every per-key row.
#[test]
fn key_operations_line_wraps_per_provider() {
    let presentation = two_provider_presentation();
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert_eq!(
        block,
        vec![
            "key operations: 4 keys on 2 providers; rev 3 populated; 2 sessions",
            "  libfoo-pkcs11.so: decrypt 5 completed, 2 returned errors, 0 active operations",
            "  libsofthsm2.so: sign 5 completed, 1 returned an error, 1 active operations",
        ],
        "header plus one line per provider:\n{concise}"
    );
    for line in &block {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{concise}"
        );
    }
    assert!(!concise.contains("(i0)"), "{concise}");
    assert!(!concise.contains("(i1)"), "{concise}");
    // Positive control: the JSON section still carries every per-key row.
    let document =
        serde_json::to_value(object_observations_json(&presentation.object_observations)).unwrap();
    assert_eq!(
        document
            .get("key_operations")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(4),
        "JSON keeps all four rows"
    );
}

/// Verbose keeps the machine instance labels beside the provider names.
#[test]
fn key_ops_verbose_provider_lines_keep_instance_labels() {
    let presentation = two_provider_presentation();
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(
        block,
        vec![
            "key operations: 4 keys on 2 providers; rev 3 populated; 2 sessions",
            "  libfoo-pkcs11.so: decrypt 5 completed, 2 returned errors, 0 active operations (i1)",
            "  libsofthsm2.so: sign 5 completed, 1 returned an error, 1 active operations (i0)",
        ],
        "verbose keeps instance labels in parentheses:\n{verbose}"
    );
    for line in &block {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{verbose}"
        );
    }
}

/// Rows whose instance resolves to no provider read under a fixed
/// label in concise text (never the raw instance string); verbose
/// names the instance in parentheses.
#[test]
fn key_ops_unresolved_instance_reads_unidentified_provider() {
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .key_operations
        .push(key_row("sign", "key", 2, 1, 0, "operations"));
    let presentation = key_ops_presentation(observations);
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert_eq!(
        block,
        vec![
            "key operations: 1 key on 1 provider; rev 3 populated; 1 session",
            "  unidentified provider: sign 2 completed, 1 returned an error, 0 active operations",
        ],
        "unresolved instances read as unidentified:\n{concise}"
    );
    assert!(
        !block.iter().any(|line| line.contains("test-instance")),
        "raw instance label leaked:\n{concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(
        block[1],
        "  unidentified provider: sign 2 completed, 1 returned an error, 0 active operations \
         (test-instance)",
        "verbose names the instance:\n{verbose}"
    );
}

/// Verbose instance labels are projection strings: controls escape
/// like every other snapshot field, so one row can never forge a
/// second output line.
#[test]
fn key_ops_verbose_instance_labels_escape_controls() {
    let mut observations = populated(3);
    observations
        .key_operations
        .push(key_row_on("i0\nX", 11, "sign", 2, 0, 0));
    let presentation = key_ops_presentation(observations);
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(block.len(), 2, "header plus one provider line:\n{verbose}");
    assert!(
        block[1].contains("(i0\\nX)"),
        "the label escapes: {:?}",
        block[1]
    );
}

/// CLI-1: a provider group with hundreds of instances keeps its
/// verbose line within 100 chars — the instance-label suffix
/// truncates with a mark instead of growing unbounded, while the
/// tally stays exact. Both group shapes (identified and
/// unidentified) bound the suffix; concise stays suffix-free.
#[test]
fn key_ops_verbose_many_instances_stay_within_100_chars() {
    fn observations_with_instances(instances: &[String]) -> ObjectObservations {
        let mut observations = populated(3);
        observations.sessions.push(SessionRow {
            session: 7,
            origin: "opened",
            status: "live",
        });
        observations.objects.push(object_row(11));
        for instance in instances {
            observations
                .key_operations
                .push(key_row_on(instance, 11, "sign", 1, 0, 0));
        }
        observations
    }
    // Unidentified: no fixture instance resolves, so every row shares
    // the one fixed-label group and all labels land on one line.
    let labels: Vec<String> = (0..300).map(|i| format!("instance-{i:03}")).collect();
    let mut presentation = key_ops_presentation(observations_with_instances(&labels));
    presentation.instances.clear();
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(block.len(), 2, "header plus one provider line:\n{verbose}");
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars: {:?}:\n{verbose}",
        block[1]
    );
    assert!(
        block[1].contains('…'),
        "truncation is marked: {:?}",
        block[1]
    );
    assert!(
        block[1].starts_with(
            "  unidentified provider: sign 300 completed, 0 returned errors, 0 active operations ("
        ),
        "the tally stays exact: {:?}",
        block[1]
    );
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert!(
        !block[1].contains("instance-"),
        "raw instance label leaked:\n{concise}"
    );
    // Identified: every label resolves to the one harness module, so
    // the provider-named group carries all 300 labels.
    let labels: Vec<String> = (0..300).map(|i| format!("i{i}")).collect();
    let mut presentation = key_ops_presentation(observations_with_instances(&labels));
    let module = presentation.modules[0].id;
    let caller = presentation.callers[0].id;
    presentation.instances.clear();
    for (raw, label) in labels.iter().enumerate() {
        assert_eq!(
            RegistryInstanceId::from_raw(raw as u32).label(),
            *label,
            "fixture rows resolve to the harness module"
        );
        presentation.instances.push(InstanceView {
            id: RegistryInstanceId::from_raw(raw as u32),
            caller,
            module,
            state: InstanceLifecycle::Observed,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        });
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(block.len(), 2, "header plus one provider line:\n{verbose}");
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars: {:?}:\n{verbose}",
        block[1]
    );
    assert!(
        block[1].contains('…'),
        "truncation is marked: {:?}",
        block[1]
    );
}

/// A long provider file name together with hundreds of instance
/// labels still fits the verbose line within 100 chars: the name
/// and the suffix shrink cooperatively, both marked, while the
/// tally stays exact and the suffix keeps its closing paren.
#[test]
fn key_ops_verbose_long_name_many_instances_stay_within_100_chars() {
    let labels: Vec<String> = (0..300).map(|i| format!("i{i}")).collect();
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    for instance in &labels {
        observations
            .key_operations
            .push(key_row_on(instance, 11, "sign", 1, 0, 0));
    }
    let mut presentation = key_ops_presentation(observations);
    let basename = format!("lib{}.so", "p".repeat(194));
    assert_eq!(basename.chars().count(), 200);
    presentation.modules[0].paths = vec![format!("/opt/vendor/{basename}")];
    let module = presentation.modules[0].id;
    let caller = presentation.callers[0].id;
    presentation.instances.clear();
    for (raw, label) in labels.iter().enumerate() {
        assert_eq!(
            RegistryInstanceId::from_raw(raw as u32).label(),
            *label,
            "fixture rows resolve to the harness module"
        );
        presentation.instances.push(InstanceView {
            id: RegistryInstanceId::from_raw(raw as u32),
            caller,
            module,
            state: InstanceLifecycle::Observed,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        });
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(block.len(), 2, "header plus one provider line:\n{verbose}");
    let tally = "sign 300 completed, 0 returned errors, 0 active operations";
    assert!(
        block[1].contains(tally),
        "the tally stays exact: {:?}",
        block[1].chars().take(160).collect::<String>()
    );
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars ({}): {:?}:\n{verbose}",
        block[1].chars().count(),
        block[1].chars().take(160).collect::<String>()
    );
    assert!(
        block[1].contains('…'),
        "truncation is marked: {:?}",
        block[1].chars().take(160).collect::<String>()
    );
    assert!(
        block[1].starts_with("  lib"),
        "the provider name stays first: {:?}",
        block[1].chars().take(160).collect::<String>()
    );
    assert!(
        block[1].ends_with(')'),
        "the suffix keeps its closing paren: {:?}",
        block[1].chars().take(160).collect::<String>()
    );
}

/// Capture-wide unknown-key rows (no instance) read on their own
/// `unknown keys` lines, never merged into a provider's tallies.
#[test]
fn key_ops_unknown_bucket_reads_unknown_keys_lines() {
    let mut observations = populated(3);
    observations.sessions.push(SessionRow {
        session: 7,
        origin: "opened",
        status: "live",
    });
    observations.objects.push(object_row(11));
    observations
        .unknown_key_operations
        .push(unknown_row("sign", 3, 0, 1, "operations"));
    let presentation = key_ops_presentation(observations);
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert_eq!(
        block,
        vec![
            "key operations: 1 key on 0 providers; rev 3 populated; 1 session",
            "  unknown keys: sign 3 completed, 0 returned errors, 1 active operations",
        ],
        "unknown rows stay separate:\n{concise}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(
        block[1],
        "  unknown keys: sign 3 completed, 0 returned errors, 1 active operations (unbound)",
        "verbose names the machine reason:\n{verbose}"
    );
}

/// A very long provider file name truncates to keep the provider line
/// at most 100 chars; the tally itself is never truncated.
#[test]
fn key_ops_long_provider_name_truncates_line_to_100_chars() {
    let mut observations = populated(3);
    observations
        .key_operations
        .push(key_row_on("i0", 11, "sign", 2, 1, 0));
    let mut presentation = key_ops_presentation(observations);
    let basename = format!("lib{}.so", "p".repeat(110));
    presentation.modules[0].paths = vec![format!("/opt/vendor/{basename}")];
    let caller = presentation.callers[0].id;
    let module = presentation.modules[0].id;
    presentation.instances.clear();
    presentation.instances.push(InstanceView {
        id: RegistryInstanceId::from_raw(0),
        caller,
        module,
        state: InstanceLifecycle::Observed,
        reason: None,
        first_seen_ns: 100,
        last_seen_ns: 200,
    });
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert_eq!(block.len(), 2, "header plus one provider line:\n{concise}");
    let tally = "sign 2 completed, 1 returned an error, 0 active operations";
    assert!(
        block[1].ends_with(tally),
        "the tally stays exact: {:?}",
        block[1]
    );
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars: {:?}",
        block[1]
    );
    assert!(
        block[1].contains('…'),
        "truncation is marked: {:?}",
        block[1]
    );
    assert!(block[1].starts_with("  lib"), "{:?}", block[1]);
}

/// A non-`none` publication reason reads on its own indented line so
/// the header stays short; verbose pairs it with the machine reason.
#[test]
fn key_ops_stale_reason_reads_on_own_line() {
    let mut observations = ObjectObservations::unavailable(9, "bootstrap_unavailable");
    observations.status = ObsStatus::Stale;
    observations.reason = "publication_budget_exhausted";
    let presentation = key_ops_presentation(observations);
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = key_ops_block(&concise);
    assert_eq!(
        block,
        vec![
            "key operations: 0 keys on 0 providers; rev 9 stale; 0 sessions",
            "  key publication hit its budget; plain counts are unaffected",
            "  no key operations observed",
        ],
        "stale names its reason on its own line:\n{concise}"
    );
    for line in &block {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{concise}"
        );
    }
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    assert_eq!(
        block[1],
        "  key publication hit its budget; plain counts are unaffected \
         (reason: publication_budget_exhausted)",
        "verbose pairs the machine reason:\n{verbose}"
    );
}

/// Readable gaps: three gap reasons render `gaps: 3` plus one indented
/// line each, every line at most 100 chars, in plain words; verbose
/// keeps the machine tokens in parentheses.
#[test]
fn gaps_line_lists_one_reason_per_line() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    presentation.gaps.push(named_gap("scope-a", "reason-a"));
    presentation.gaps.push(named_gap("scope-b", "reason-b"));
    presentation
        .gaps
        .push(named_gap("key row", "foreign_or_unproven_caller"));
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(
        block,
        vec![
            "gaps: 3",
            "  1 × key row — caller not confirmed",
            "  1 × scope-a — reason-a",
            "  1 × scope-b — reason-b",
        ],
        "one indented line per reason:\n{concise}"
    );
    for line in &block {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{concise}"
        );
    }
    assert!(
        !block
            .iter()
            .any(|line| line.contains("--json has every item")),
        "no collapsed suffix remains: {block:?}"
    );
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("(foreign_or_unproven_caller)"),
        "verbose keeps the machine reason:\n{verbose}"
    );
}

/// The gaps block lists every group while the group count stays
/// within the fold boundary (twenty; beyond that the block folds,
/// pinned by `gaps_block_folds_beyond_twenty_groups`).
#[test]
fn gaps_block_lists_small_groups_without_fold() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    for (subject, reason) in [
        ("scope-a", "reason-a"),
        ("scope-b", "reason-b"),
        ("scope-c", "reason-c"),
        ("scope-d", "reason-d"),
    ] {
        presentation.gaps.push(named_gap(subject, reason));
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(block.len(), 5, "header plus four group lines: {block:?}");
    assert_eq!(block[0], "gaps: 4");
    assert!(
        !block.iter().any(|line| line.contains("more")),
        "nothing folds: {block:?}"
    );
}

/// A scope gap that explains missing counts reads first in the
/// concise gaps block, ahead of frequent per-object groups: a single
/// `stopped before attach` row must not sink under hundreds of
/// per-object rows or fold out of the block.
#[test]
fn gaps_block_lists_scope_gaps_before_frequent_object_gaps() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    presentation.gaps.push(named_gap(
        "stopped before attach",
        "the completed collection applied scan-only",
    ));
    for index in 0..25 {
        let mut object_gap = named_gap(&format!("object-{index:02}"), "reason-x");
        object_gap.pid = Some(1000 + index);
        presentation.gaps.push(object_gap.clone());
        presentation.gaps.push(object_gap);
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(block[0], "gaps: 51");
    assert!(
        block[1].contains("stopped before attach"),
        "the scope gap reads first: {block:?}"
    );
}

/// A `stopped before attach` gap explains missing counts, so it
/// ranks above pid-less per-object groups (attach-set refusals,
/// catalog skips): with twenty-five refusal groups it still reads
/// first, never folds out of the block.
#[test]
fn gaps_block_ranks_stopped_before_attach_above_pidless_refusals() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    presentation.gaps.push(named_gap(
        "stopped before attach",
        "the completed collection applied scan-only",
    ));
    for index in 0..25 {
        presentation.gaps.push(named_gap(
            "inventory attach set refused module",
            &format!("fixture refusal {index:02}"),
        ));
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(block[0], "gaps: 26");
    assert!(
        block[1].contains("stopped before attach"),
        "the count-explaining gap reads first: {block:?}"
    );
}

/// The stopped-before-attach gap keeps its counts clause in full:
/// "counts not attached" survives the 100-char cap and the internal
/// `pass-0` term stays out of the concise line, while verbose keeps
/// the stored reason beside the plain words.
#[test]
fn concise_gap_line_keeps_counts_clause_for_stopped_before_attach() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    presentation.gaps.push(named_gap(
        "stopped before attach",
        "operator stop during pass-0 collection (5.21s elapsed); the completed collection applied scan-only: modules and callers shown, counts not attached",
    ));
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(block.len(), 2);
    assert!(block[1].contains("counts not attached"), "{block:?}");
    assert!(!block[1].contains("pass-0"), "{block:?}");
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    assert!(
        verbose.contains("operator stop during pass-0 collection"),
        "{verbose}"
    );
}

/// CLI-1: the concise gaps block stays bounded — beyond twenty
/// distinct groups it shows the first twenty (most frequent first)
/// plus one fold line, while the header count stays exact.
#[test]
fn gaps_block_folds_beyond_twenty_groups() {
    fn block_for(groups: usize) -> Vec<String> {
        let mut presentation =
            key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
        presentation.gaps.clear();
        for i in 0..groups {
            let subject = format!("scope-{i:02}");
            presentation.gaps.push(named_gap(&subject, "reason-x"));
        }
        let concise =
            render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
        gaps_block(&concise)
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }
    let at_boundary = block_for(20);
    assert_eq!(
        at_boundary.len(),
        21,
        "twenty groups still list every group: {at_boundary:?}"
    );
    assert!(
        !at_boundary.iter().any(|line| line.contains("more")),
        "nothing folds at the boundary: {at_boundary:?}"
    );
    let one_over = block_for(21);
    assert_eq!(
        one_over.len(),
        22,
        "header plus twenty groups plus the fold line: {one_over:?}"
    );
    assert_eq!(one_over[0], "gaps: 21");
    assert_eq!(
        one_over[21], "  and 1 more group (--json has every item)",
        "the fold line names the remainder: {one_over:?}"
    );
    let many = block_for(25);
    assert_eq!(
        many.len(),
        22,
        "header plus twenty groups plus the fold line: {many:?}"
    );
    assert_eq!(many[0], "gaps: 25", "the header count stays exact");
    assert_eq!(many[1], "  1 × scope-00 — reason-x");
    assert_eq!(many[20], "  1 × scope-19 — reason-x");
    assert_eq!(
        many[21], "  and 5 more groups (--json has every item)",
        "the fold line names the remainder: {many:?}"
    );
    for line in &many {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{}",
            many.join("\n")
        );
    }
}

/// The fold header counts loss rows, not groups: 21 groups where
/// one group holds 3 rows read `gaps: 23` while the fold still
/// shows 20 groups plus `and 1 more group`.
#[test]
fn gaps_block_fold_header_counts_rows_not_groups() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    for _ in 0..3 {
        presentation.gaps.push(named_gap("scope-hot", "reason-x"));
    }
    for i in 0..20 {
        let subject = format!("scope-{i:02}");
        presentation.gaps.push(named_gap(&subject, "reason-x"));
    }
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(
        block.len(),
        22,
        "header plus twenty groups plus the fold line: {block:?}"
    );
    assert_eq!(block[0], "gaps: 23", "the header counts rows, not groups");
    assert_eq!(block[1], "  3 × scope-hot — reason-x");
    assert_eq!(block[20], "  1 × scope-18 — reason-x");
    assert_eq!(
        block[21], "  and 1 more group (--json has every item)",
        "the fold line names the remainder: {block:?}"
    );
    for line in &block {
        assert!(
            line.chars().count() <= 100,
            "over 100 chars: {line:?}:\n{}",
            block.join("\n")
        );
    }
}

/// A very long gap subject truncates to keep the group line at most
/// 100 chars; the count and reason stay intact.
#[test]
fn gaps_long_subject_truncates_line_to_100_chars() {
    let mut presentation =
        key_ops_presentation(ObjectObservations::unavailable(7, "journal_unavailable"));
    presentation.gaps.clear();
    let subject = format!("/proc/11/root/{}_deleted.so", "d".repeat(150));
    presentation.gaps.push(named_gap(&subject, "reason-x"));
    let concise = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Concise);
    let block = gaps_block(&concise);
    assert_eq!(block.len(), 2, "header plus one group line: {block:?}");
    assert_eq!(block[0], "gaps: 1");
    assert!(
        block[1].ends_with(" — reason-x"),
        "the reason stays intact: {:?}",
        block[1]
    );
    assert!(
        block[1].chars().count() <= 100,
        "over 100 chars: {:?}",
        block[1]
    );
    assert!(
        block[1].contains('…'),
        "truncation is marked: {:?}",
        block[1]
    );
}

// ==================== F16 (7.05 PQC): PQC spotlight ====================

/// F16: the concise block spotlights proved PQC uses per parameter
/// set on their own line beside the exact per-provider tallies.
/// Secondary-role rows stand beside (never double-counted), non-PQC
/// rows contribute no segment, and the spotlight sits before the
/// `not attributed` / `type unknown` lines. No object identity anywhere.
#[test]
fn key_ops_line_spotlights_pqc_uses() {
    let mut observations = populated(9);
    let mut sign = key_row("sign", "key", 12, 0, 0, "operations");
    sign.metadata_at_use = "ml_dsa_65";
    observations.key_operations.push(sign);
    let mut verify = key_row("verify", "key", 3, 0, 0, "operations");
    verify.metadata_at_use = "ml_dsa_65";
    observations.key_operations.push(verify);
    observations
        .key_operations
        .push(key_row("sign", "key", 5, 0, 0, "operations"));
    let mut secondary = key_row("sign", SECONDARY_ROLE, 100, 0, 0, "operations");
    secondary.metadata_at_use = "ml_dsa_65";
    observations.key_operations.push(secondary);
    observations.add_unattributed("record_lost", 2);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    // The tallies stay exact (parsed from the provider lines): 12 + 5
    // sign, 3 verify; the secondary 100 excluded.
    assert_eq!(
        snapshot_tallies(&snapshot),
        vec![("sign", 17, 0, 0), ("verify", 3, 0, 0)],
        "tallies intact: {snapshot}"
    );
    let spotlight = block
        .iter()
        .find(|line| line.starts_with("  pqc keys: "))
        .expect("the PQC spotlight line");
    assert_eq!(
        *spotlight, "  pqc keys: ML-DSA-65 sign: 12, ML-DSA-65 verify: 3",
        "one segment per (label, category): {snapshot}"
    );
    let text = block.join("\n");
    assert!(
        !text.contains("100"),
        "the secondary row never double-counts: {snapshot}"
    );
    let pqc = block
        .iter()
        .position(|line| line.starts_with("  pqc keys: "))
        .expect("spotlight");
    let unattributed = block
        .iter()
        .position(|line| line.starts_with("  not attributed:"))
        .expect("suffix");
    assert!(
        pqc < unattributed,
        "the spotlight precedes the suffixes: {snapshot}"
    );
    assert!(
        !text.contains("object#") && !text.contains("test-instance"),
        "counts only, never object identity: {snapshot}"
    );
}

/// F16 negative control: without PQC-labelled proved rows the block
/// shows no spotlight at all.
#[test]
fn key_ops_line_without_pqc_rows_shows_no_spotlight() {
    let mut observations = populated(9);
    observations
        .key_operations
        .push(key_row("sign", "key", 4, 0, 0, "operations"));
    let mut secondary = key_row("sign", SECONDARY_ROLE, 2, 0, 0, "operations");
    secondary.metadata_at_use = "ml_kem_768";
    observations.key_operations.push(secondary);
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert!(
        !block.iter().any(|line| line.starts_with("  pqc keys:")),
        "no spotlight without primary PQC rows: {snapshot}"
    );
    assert_eq!(snapshot_tallies(&snapshot), vec![("sign", 4, 0, 0)]);
}

/// F16: `-v` adds failed/active terminals to the same spotlight
/// segments, with the tallies' singular/plural nouns.
#[test]
fn key_ops_line_pqc_spotlight_verbose_adds_terminals() {
    let mut observations = populated(9);
    let mut sign = key_row("sign", "key", 12, 1, 0, "operations");
    sign.metadata_at_use = "ml_dsa_65";
    observations.key_operations.push(sign);
    let mut encap = key_row("encapsulate", "encapsulation_key", 7, 2, 1, "operations");
    encap.metadata_at_use = "ml_kem_768";
    observations.key_operations.push(encap);
    let presentation = key_ops_presentation(observations);
    let verbose = render_snapshot_with_verbosity(&presentation, crate::cli::TextVerbosity::Verbose);
    let block = key_ops_block(&verbose);
    let spotlight = block
        .iter()
        .find(|line| line.starts_with("  pqc keys: "))
        .expect("the verbose spotlight line");
    assert!(
        spotlight.contains("ML-DSA-65 sign: 12 completed, 1 returned an error, 0 active"),
        "singular noun: {verbose}"
    );
    assert!(
        spotlight.contains("ML-KEM-768 encapsulate: 7 completed, 2 returned errors, 1 active"),
        "plural nouns: {verbose}"
    );
    let concise = render_snapshot(&presentation);
    let short = key_ops_block(&concise);
    let brief = short
        .iter()
        .find(|line| line.starts_with("  pqc keys: "))
        .expect("the concise spotlight line");
    assert_eq!(
        *brief, "  pqc keys: ML-DSA-65 sign: 12, ML-KEM-768 encapsulate: 7",
        "concise shows completions only: {concise}"
    );
}

/// F16: the display map covers exactly the eighteen PQC labels —
/// every `is_pqc_metadata_label` member renders, nothing else does.
#[test]
fn pqc_display_label_covers_all_pqc_labels() {
    use crate::key_operation_projection::contract::METADATA_LABELS_V5;
    use crate::key_operation_projection::is_pqc_metadata_label;
    for label in METADATA_LABELS_V5 {
        assert_eq!(
            pqc_display_label(label).is_some(),
            is_pqc_metadata_label(label),
            "{label}"
        );
    }
    let displays: Vec<&str> = METADATA_LABELS_V5
        .iter()
        .filter_map(|label| pqc_display_label(label))
        .collect();
    assert_eq!(displays.len(), 18, "eighteen display names");
}

/// F16 residual (review item 8): spotlight segments sort by the
/// label's v5 vocabulary rank, not the display string — `ml_kem_512`
/// precedes `ml_kem_1024` even though both the label bytes and the
/// display bytes sort `1024` before `512` lexicographically.
#[test]
fn key_ops_line_pqc_spotlight_sorts_by_label() {
    let mut observations = populated(9);
    let mut wide = key_row("sign", "key", 4, 0, 0, "operations");
    wide.metadata_at_use = "ml_kem_1024";
    observations.key_operations.push(wide);
    let mut narrow = key_row("sign", "key", 6, 0, 0, "operations");
    narrow.metadata_at_use = "ml_kem_512";
    observations.key_operations.push(narrow);
    let segments = pqc_key_breakdown(&observations);
    assert_eq!(
        segments
            .iter()
            .map(|segment| segment.display)
            .collect::<Vec<_>>(),
        vec!["ML-KEM-512", "ML-KEM-1024"],
        "vocabulary order, not display order"
    );
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    let spotlight = block
        .iter()
        .find(|line| line.starts_with("  pqc keys: "))
        .unwrap_or_else(|| panic!("the spotlight line: {snapshot}"));
    assert_eq!(
        *spotlight, "  pqc keys: ML-KEM-512 sign: 6, ML-KEM-1024 sign: 4",
        "the line follows label order: {snapshot}"
    );
}

/// F16 residual (review item 8): the spotlight names segments with
/// proved completions only — a failed-only PQC row contributes no
/// segment, so no `: 0` segment renders.
#[test]
fn key_ops_line_pqc_spotlight_skips_zero_completed_segments() {
    let mut observations = populated(9);
    let mut failed_only = key_row("sign", "key", 0, 2, 0, "operations");
    failed_only.metadata_at_use = "ml_dsa_65";
    observations.key_operations.push(failed_only);
    assert!(
        pqc_key_breakdown(&observations).is_empty(),
        "no segment without a proved completion"
    );
    let presentation = key_ops_presentation(observations);
    let snapshot = render_snapshot(&presentation);
    let block = key_ops_block(&snapshot);
    assert!(
        !block.iter().any(|line| line.starts_with("  pqc keys:")),
        "no spotlight without a proved completion: {snapshot}"
    );
}

/// F16 residual (review item 8): the exact eighteen display strings
/// the concise spotlight renders, pinned label by label against the
/// capture contract's vocabulary table.
#[test]
fn pqc_display_label_pins_all_eighteen_display_strings() {
    for (label, display) in [
        ("ml_dsa_44", "ML-DSA-44"),
        ("ml_dsa_65", "ML-DSA-65"),
        ("ml_dsa_87", "ML-DSA-87"),
        ("ml_kem_512", "ML-KEM-512"),
        ("ml_kem_768", "ML-KEM-768"),
        ("ml_kem_1024", "ML-KEM-1024"),
        ("slh_dsa_sha2_128s", "SLH-DSA-SHA2-128S"),
        ("slh_dsa_shake_128s", "SLH-DSA-SHAKE-128S"),
        ("slh_dsa_sha2_128f", "SLH-DSA-SHA2-128F"),
        ("slh_dsa_shake_128f", "SLH-DSA-SHAKE-128F"),
        ("slh_dsa_sha2_192s", "SLH-DSA-SHA2-192S"),
        ("slh_dsa_shake_192s", "SLH-DSA-SHAKE-192S"),
        ("slh_dsa_sha2_192f", "SLH-DSA-SHA2-192F"),
        ("slh_dsa_shake_192f", "SLH-DSA-SHAKE-192F"),
        ("slh_dsa_sha2_256s", "SLH-DSA-SHA2-256S"),
        ("slh_dsa_shake_256s", "SLH-DSA-SHAKE-256S"),
        ("slh_dsa_sha2_256f", "SLH-DSA-SHA2-256F"),
        ("slh_dsa_shake_256f", "SLH-DSA-SHAKE-256F"),
    ] {
        assert_eq!(pqc_display_label(label), Some(display), "{label}");
    }
}

/// F16 residual (review item 8): the spotlight's rank table follows
/// the v5 vocabulary order exactly — the eighteen PQC labels of
/// `METADATA_LABELS_V5` in table order rank 0..18, and nothing else
/// ranks at all.
#[test]
fn pqc_label_rank_matches_v5_order() {
    use crate::key_operation_projection::contract::METADATA_LABELS_V5;
    use crate::key_operation_projection::is_pqc_metadata_label;
    let v5_pqc: Vec<&&str> = METADATA_LABELS_V5
        .iter()
        .filter(|label| is_pqc_metadata_label(label))
        .collect();
    assert_eq!(v5_pqc.len(), 18, "eighteen PQC labels in v5");
    for (rank, label) in v5_pqc.iter().enumerate() {
        assert_eq!(pqc_label_rank(label), Some(rank as u8), "{label}");
    }
    for label in ["rsa_2048", "unknown", "metadata_unknown", ""] {
        assert_eq!(pqc_label_rank(label), None, "{label}");
    }
}
