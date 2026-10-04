//! SPDX-License-Identifier: GPL-3.0-or-later
//! U1 dashboard tests: deterministic rendering + REAL PTY coverage
//! (scrolling, resize, small terminals, Unicode/control, exit/
//! restoration, large inventories), JSON-vs-dashboard replay
//! agreement, and the dashboard-on/off risk gate.

use super::*;
use crate::discovery::caller_registry::{
    AdmissionState, BudgetRefusal, CallerId, CoverageNote, ImageAuthority, ModuleInfo, ModuleKey,
    RegistryGap, RegistryLimits,
};
use crate::discovery::inventory_workload::{ChurnSpec, Harness, ScaleSpec};
use crate::inventory_present::Presentation;
use crate::semantics_edge::SemanticCall;
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::time::{Duration, Instant};

fn harness() -> Harness {
    Harness::new(RegistryLimits::default_limits()).unwrap()
}

fn refused_module_info(index: usize) -> ModuleInfo {
    let path = format!("/dash/refused{index}.so");
    ModuleInfo {
        path: path.clone(),
        key: ModuleKey::physical(
            8,
            1,
            300_000 + index as u64,
            Some(format!("dsha{index:06}")),
            &path,
        ),
        double_loaded: false,
        build_id: None,
        identity_source: Some("workload".into()),
        admission: AdmissionState::Refused,
        admission_class: Some("refused".into()),
        admission_endpoints: None,
        admission_reasons: vec!["fixture refusal".into()],
    }
}

/// A workload with dashboard-visible variety: admitted + refused
/// edges, an exited caller, gaps, and several passes of history.
fn varied_presentation() -> Presentation {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-varied",
        callers: 6,
        modules: 3,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 80_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness.advance(10);
    let now = harness.now_ns();
    let live = harness.coordinator().adapter().live_id(80_000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        live,
        80_000,
        refused_module_info(0),
        now,
    );
    harness.commit();
    harness.advance(10);
    harness.source().kill(80_001);
    let observed: BTreeSet<u32> = (80_000..80_006).filter(|pid| *pid != 80_001).collect();
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    )
}

fn frame_for(presentation: &Presentation) -> DisplayFrame {
    let mut tail = LogTail::bounded();
    tail.push("p11scope: pass 0: 6 scanned (0 native, 6 scan-pinned)");
    DisplayFrame {
        presentation: Arc::new(presentation.clone()),
        log: tail.snapshot(),
    }
}

/// Strip our own framing (`\x1b[H` head, `\x1b[K` line ends) for
/// content assertions; anything else ESC-shaped fails separately.
fn frame_text(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec()).expect("frames are valid UTF-8");
    assert!(text.starts_with("\x1b[H"), "frames home first");
    text.replace("\x1b[H", "").replace("\x1b[K", "")
}

/// Every ESC byte in a frame is one of ours (cursor-home / clear-line
/// only, monochrome): no injected or stray sequences, ever.
fn assert_own_escapes_only(bytes: &[u8]) {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b {
            assert!(index + 2 < bytes.len(), "truncated escape at byte {index}");
            assert!(
                &bytes[index..index + 3] == b"\x1b[H" || &bytes[index..index + 3] == b"\x1b[K",
                "foreign escape at byte {index}"
            );
            index += 3;
        } else {
            index += 1;
        }
    }
}

#[test]
fn frame_bytes_are_deterministic_and_parseable() {
    let presentation = varied_presentation();
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 80,
        height: 24,
    };
    let state = DashboardState::new();
    let first = render_frame(&frame, viewport, &state);
    let second = render_frame(&frame, viewport, &state);
    assert_eq!(first, second, "same inputs render byte-identical");
    assert_own_escapes_only(&first);
    let text = frame_text(&first);
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines.len(), 24, "full frames fill the viewport");
}

#[test]
fn coverage_stays_prominent_and_totals_ignore_the_scroll() {
    let presentation = varied_presentation();
    let total_edges = presentation.edges.len();
    assert!(total_edges > 6, "varied fixture overflows one screen");
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 80,
        height: 24,
    };
    let top = render_frame(&frame, viewport, &DashboardState::new());
    let top_text = frame_text(&top);
    let top_lines: Vec<&str> = top_text.split('\n').collect();
    // B4: gap/refusal/suppressed counts visible without scrolling on
    // 80×24 — they are header lines 1-3, never in the scroll region.
    assert!(top_lines[0].contains("6 callers"), "{}", top_lines[0]);
    assert!(top_lines[1].contains("gaps"), "{}", top_lines[1]);
    assert!(top_lines[1].contains("refusals"), "{}", top_lines[1]);
    assert!(top_lines[1].contains("suppressed"), "{}", top_lines[1]);
    // Scroll to the bottom: the header totals are byte-identical (the
    // view narrowed, the totals never did).
    let mut scrolled = DashboardState::new();
    for _ in 0..total_edges {
        scrolled.scroll_down(total_edges);
    }
    let bottom = render_frame(&frame, viewport, &scrolled);
    let bottom_text = frame_text(&bottom);
    let bottom_lines: Vec<&str> = bottom_text.split('\n').collect();
    assert_eq!(bottom_lines[0], top_lines[0], "title totals ignore scroll");
    assert_eq!(bottom_lines[1], top_lines[1], "coverage ignores scroll");
    assert_eq!(bottom_lines[2], top_lines[2], "budgets ignore scroll");
    // ... while the window moved (markers both directions).
    assert!(bottom_text.contains("^ +"), "{bottom_text}");
    assert!(top_text.contains("v +"), "{top_text}");
    assert!(bottom_text.contains("scroll "), "{bottom_text}");
}

/// Capture the harness's current registry state as a presentation
/// (same extraction the JSON path uses for its observation block).
fn capture_from_harness(harness: &Harness) -> Presentation {
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    )
}

#[test]
fn dashboard_states_match_the_presentation_edge_for_edge() {
    // E2 (in-crate replay): the SAME scripted workload renders both
    // JSON and dashboard frames; every edge's states agree.
    let presentation = varied_presentation();
    assert_frame_matches_presentation(&presentation);
}

#[test]
fn dashboard_agrees_with_json_on_canonical_churn_storm() {
    // E2 (verbatim Phase-4 replay): the canonical churn-storm spec
    // — 128 pids x 8 generations x 16 modules at first_pid 80_000,
    // the EXACT spec `run_churn_storm` pins — renders both JSON
    // and a dashboard frame with identical states.
    let mut harness = harness();
    let spec = ChurnSpec {
        pids: 128,
        generations: 8,
        modules: 16,
        first_pid: 80_000,
    };
    let (admitted, _events) = harness.run_churn(&spec);
    assert_eq!(admitted, 1024, "canonical storm admits every incarnation");
    let presentation = capture_from_harness(&harness);
    assert_eq!(presentation.edges.len(), 1024);
    assert_frame_matches_presentation(&presentation);
}

fn assert_frame_matches_presentation(presentation: &Presentation) {
    let document = render_json_from_presentation_for(presentation);
    assert_eq!(
        document["edges"].as_array().unwrap().len(),
        presentation.edges.len()
    );
    let frame = frame_for(presentation);
    // A viewport tall enough for every block (8 lines per edge
    // plus header room): the frame must name every edge's exact
    // states.
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 200,
            height: presentation
                .edges
                .len()
                .saturating_mul(8)
                .saturating_add(40),
        },
        &DashboardState::new(),
    );
    let text = frame_text(&bytes);
    for edge in &presentation.edges {
        let identity = format!("{} pid ", edge.caller.label());
        assert!(text.contains(&identity), "edge identity: {identity}");
        assert!(
            text.contains(&format!("presence {}", edge.presence.label())),
            "presence for {}",
            edge.caller.label()
        );
        assert!(
            text.contains(&format!("capture {}", edge.capture.label())),
            "capture for {}",
            edge.caller.label()
        );
        assert!(
            text.contains(&format!("activity {}", edge.activity.label())),
            "activity for {}",
            edge.caller.label()
        );
        assert!(
            text.contains(&format!(
                "entries {}",
                crate::inventory_present::entries_display(edge)
            )),
            "entries for {}",
            edge.caller.label()
        );
    }
    // ... and the withheld semantic column on every block.
    assert!(
        text.contains("unknown (semantic capture withheld)"),
        "{text}"
    );
    // Header totals equal the JSON budgets (full coverage, not the
    // window).
    let first = text.lines().next().unwrap();
    assert!(
        first.contains(&format!("{} callers", presentation.callers.len())),
        "{first}"
    );
    assert!(
        first.contains(&format!("{} edges", presentation.edges.len())),
        "{first}"
    );
}

fn render_json_from_presentation_for(presentation: &Presentation) -> serde_json::Value {
    crate::inventory::render_json_from_presentation(presentation)
}

#[test]
fn handoff_is_bounded_latest_wins_and_never_backpressures() {
    assert_eq!(DisplayHandoff::capacity(), 1, "the enforced bound");
    let handoff = DisplayHandoff::new();
    assert!(handoff.take().is_none(), "empty takes yield nothing");
    let log = LogTail::bounded().snapshot();
    // A stalled terminal: three offers, no takes — the two obsolete
    // frames shed, the latest survives, and offering never blocks.
    for (index, scope) in ["one", "two", "three"].iter().enumerate() {
        let mut presentation = varied_presentation();
        presentation.scope_label = (*scope).to_string();
        presentation.passes = index as u64;
        handoff.offer(Arc::new(presentation), log.clone());
    }
    assert_eq!(handoff.offered(), 3);
    assert_eq!(handoff.dropped_frames(), 2, "shed frames are counted");
    assert_eq!(handoff.consumed(), 0);
    let frame = handoff.take().expect("the latest frame survives");
    assert_eq!(frame.presentation.scope_label, "three");
    assert_eq!(frame.presentation.passes, 2);
    assert_eq!(handoff.consumed(), 1);
    assert!(handoff.take().is_none(), "one take drains the slot");
    // Capture facts are unaffected by shed frames: the presentations
    // offered still exist (Arc-shared, immutable) wherever the
    // capturer retained them.
    assert_eq!(handoff.offered(), 3);
}

#[test]
fn log_tail_sanitizes_truncates_and_accounts() {
    // Line-count overflow drives eviction here (the byte budget fits a
    // truncated line, as in production).
    let mut tail = LogTail::new(4, 4096);
    tail.push("plain line");
    tail.push("\x1b[31mred\x1b[0m \x07bell\x00nul");
    let snapshot = tail.snapshot();
    assert_eq!(snapshot.lines.len(), 2);
    assert!(!snapshot.lines[1].contains('\x1b'), "{}", snapshot.lines[1]);
    assert!(!snapshot.lines[1].contains('\x07'), "{}", snapshot.lines[1]);
    assert!(
        snapshot.lines[1].contains("\\u{1b}"),
        "{}",
        snapshot.lines[1]
    );
    // Overflow evicts oldest-first with exact counts.
    for index in 0..10 {
        tail.push(&format!("overflow line {index}"));
    }
    assert_eq!(tail.snapshot().lines.len(), 4);
    assert!(tail.dropped_lines() > 0);
    assert!(tail.dropped_bytes() > 0);
    // A single overlong line truncates with the marker, bytes counted.
    let before = tail.dropped_bytes();
    tail.push(&"x".repeat(2000));
    assert!(tail.dropped_bytes() > before);
    assert!(
        tail.snapshot().lines.last().unwrap().ends_with("…"),
        "overlong lines truncate with …"
    );
    // Frames surface the accounting (never silent) and carry no raw
    // control bytes from the tail.
    let presentation = varied_presentation();
    let frame = DisplayFrame {
        presentation: Arc::new(presentation),
        log: tail.snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 24,
        },
        &DashboardState::new(),
    );
    let text = frame_text(&bytes);
    assert!(text.contains("dropped lines"), "{text}");
    assert!(text.contains("dropped bytes"), "{text}");
    for byte in bytes.iter() {
        if byte.is_ascii_control() {
            assert!(
                *byte == b'\n' || *byte == 0x1b,
                "raw control byte {byte:#x} in frame"
            );
        }
    }
}

#[test]
fn ansi_stays_on_the_terminal_never_in_json() {
    let presentation = varied_presentation();
    let document = render_json_from_presentation_for(&presentation);
    let pretty = serde_json::to_string_pretty(&document).unwrap();
    assert!(!pretty.contains('\x1b'), "no ANSI in JSON output");
    let snapshot = crate::inventory_present::render_snapshot(&presentation);
    assert!(!snapshot.contains('\x1b'), "no ANSI in snapshots");
    let frame = frame_for(&presentation);
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 24,
        },
        &DashboardState::new(),
    );
    assert!(bytes.contains(&0x1b), "frames are ANSI presentation");
}

#[test]
fn small_terminals_degrade_to_the_stated_minimal_layout() {
    let presentation = varied_presentation();
    let frame = frame_for(&presentation);
    for viewport in [
        Viewport {
            width: 60,
            height: 20,
        },
        Viewport {
            width: 80,
            height: 10,
        },
        Viewport {
            width: 40,
            height: 10,
        },
        Viewport {
            width: 10,
            height: 5,
        },
        Viewport {
            width: 79,
            height: 24,
        },
        Viewport {
            width: 80,
            height: 13,
        },
    ] {
        let bytes = render_frame(&frame, viewport, &DashboardState::new());
        let text = frame_text(&bytes);
        let lines: Vec<&str> = text.split('\n').collect();
        assert!(lines.len() <= viewport.height, "{viewport:?}: {text}");
        for line in &lines {
            assert!(
                line.chars().count() <= viewport.width,
                "{viewport:?}: line overflows: {line:?}"
            );
        }
        // Below ~30 columns even the marker truncates; the layout is
        // still the minimal one (totals/coverage first, bounded).
        if viewport.width >= 30 {
            assert!(text.contains("minimal"), "{viewport:?}: {text}");
        }
        assert!(text.contains("totals:"), "{viewport:?}: {text}");
        assert!(text.contains("coverage:"), "{viewport:?}: {text}");
    }
    // Boundary: 80×14 is full, with the edge table.
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 14,
        },
        &DashboardState::new(),
    );
    let text = frame_text(&bytes);
    assert!(!text.contains("minimal"), "{text}");
    assert!(text.contains("--- edges"), "{text}");
}

#[test]
fn unicode_and_control_paths_render_safely() {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-unicode",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 81_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Poison the rendered strings: controls, CSI, and wide chars.
    let mut presentation = {
        let document = harness.render();
        let started = document["observation"]["started_ns"].as_u64().unwrap();
        let ended = document["observation"]["ended_ns"].as_u64().unwrap();
        Presentation::capture(
            harness.coordinator(),
            "workload",
            started,
            ended,
            1,
            ended,
            1,
        )
    };
    presentation.callers[0].exe.as_mut().unwrap().path =
        Some("/tmp/\x07evil-\x1b[1m-\u{009b}CSI-\u{7f}del".to_string());
    presentation.modules[0].paths = vec!["/lib/日本語プロバイダー\x00.so".to_string()];
    let frame = DisplayFrame {
        presentation: Arc::new(presentation),
        log: LogTail::bounded().snapshot(),
    };
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 24,
        },
        &DashboardState::new(),
    );
    // Valid UTF-8, char-boundary truncation, and no control injection:
    // every ESC is ours, no other C0 survives (outside newlines).
    let text = String::from_utf8(bytes.clone()).expect("frames are valid UTF-8");
    assert_own_escapes_only(&bytes);
    for byte in bytes.iter() {
        if byte.is_ascii_control() {
            assert!(
                *byte == b'\n' || *byte == 0x1b,
                "raw control byte {byte:#x} reached the terminal"
            );
        }
    }
    // Legitimate non-ASCII survives (escaped, never stripped).
    assert!(text.contains("日本語"), "{text}");
    // ... and the same frame crosses a REAL pty unchanged apart
    // from the kernel's \n -> \r\n translation: no control
    // injection, no ESC added or lost, legitimate text intact.
    let mut pty = Pty::open();
    pty.set_winsize(80, 24);
    pty.slave.write_all(&bytes).unwrap();
    pty.slave.flush().unwrap();
    let seen = pty.read_until(b"q quit", Duration::from_secs(5));
    let crossed = String::from_utf8(seen).expect("pty output stays valid UTF-8");
    let crossed = crossed.replace("\r\n", "\n");
    assert_own_escapes_only(crossed.as_bytes());
    for byte in crossed.bytes() {
        if byte.is_ascii_control() {
            assert!(
                byte == b'\n' || byte == 0x1b,
                "raw control byte {byte:#x} crossed the pty"
            );
        }
    }
    assert!(crossed.contains("日本語"), "{crossed}");
    assert_eq!(
        crossed.bytes().filter(|byte| *byte == 0x1b).count(),
        bytes.iter().filter(|byte| **byte == 0x1b).count(),
        "pty traversal adds or drops no escapes"
    );
}

#[test]
fn truncate_cell_never_splits_chars() {
    assert_eq!(truncate_cell("abc", 5), "abc");
    assert_eq!(truncate_cell("abc", 3), "abc");
    assert_eq!(truncate_cell("abcd", 3), "ab…");
    assert_eq!(truncate_cell("日本語", 2), "日…");
    assert_eq!(truncate_cell("a", 0), "");
    assert_eq!(truncate_cell("", 4), "");
}

#[test]
fn key_parsing_maps_arrows_quit_and_nothing_else() {
    fn scripted(bytes: &[u8]) -> Option<Key> {
        let mut remaining = bytes.to_vec();
        poll_key_from(&mut |into: &mut [u8]| {
            if remaining.is_empty() || into.is_empty() {
                return false;
            }
            let take = into.len().min(remaining.len());
            // Split multi-byte arrivals one byte at a time (a slow
            // terminal may deliver ESC [ A across reads).
            into[0] = remaining.remove(0);
            for slot in into.iter_mut().skip(1).take(take.saturating_sub(1)) {
                if remaining.is_empty() {
                    break;
                }
                *slot = remaining.remove(0);
            }
            true
        })
    }
    assert_eq!(scripted(b"q"), Some(Key::Quit));
    assert_eq!(scripted(b"Q"), Some(Key::Quit));
    assert_eq!(scripted(b"\x03"), Some(Key::Quit));
    assert_eq!(scripted(b"\x1b"), Some(Key::Quit));
    assert_eq!(scripted(b"k"), Some(Key::Up));
    assert_eq!(scripted(b"j"), Some(Key::Down));
    assert_eq!(scripted(b"\x1b[A"), Some(Key::Up));
    assert_eq!(scripted(b"\x1b[B"), Some(Key::Down));
    assert_eq!(scripted(b""), None);
    assert_eq!(scripted(b"x"), None);
    assert_eq!(scripted(b"\x1b[C"), None);
    assert_eq!(scripted(b"\t"), Some(Key::Detail));
}

#[test]
fn dashboard_on_off_capture_totals_identical_with_measured_overhead() {
    // E3 RISK GATE (in-crate): matched dashboard-on vs dashboard-off
    // runs over the SAME workload — capture totals identical, overhead
    // measured and reported (no claimed number without its
    // measurement). No time assertion: timing is evidence, and an
    // assertion on wall time would be load-flaky by construction.
    fn run_off() -> (serde_json::Value, Duration) {
        let mut harness = harness();
        let spec = ScaleSpec {
            name: "risk-gate",
            callers: 512,
            modules: 512,
            edges_per_caller: 8,
            endpoints_per_module: 4,
            first_pid: 82_000,
        };
        let start = Instant::now();
        harness.stage_scale(&spec);
        harness.commit();
        let document = harness.render();
        (document, start.elapsed())
    }
    fn run_on() -> (serde_json::Value, Duration, u64) {
        let mut harness = harness();
        let spec = ScaleSpec {
            name: "risk-gate",
            callers: 512,
            modules: 512,
            edges_per_caller: 8,
            endpoints_per_module: 4,
            first_pid: 82_000,
        };
        let start = Instant::now();
        harness.stage_scale(&spec);
        harness.commit();
        let document = harness.render();
        // The dashboard path: immutable capture through the bounded
        // handoff, then frames at several scroll positions.
        let started = document["observation"]["started_ns"].as_u64().unwrap();
        let ended = document["observation"]["ended_ns"].as_u64().unwrap();
        let presentation = Presentation::capture(
            harness.coordinator(),
            "workload",
            started,
            ended,
            1,
            ended,
            ended.saturating_sub(started),
        );
        let handoff = DisplayHandoff::new();
        let mut tail = LogTail::bounded();
        tail.push("p11scope: pass 0: risk-gate run");
        handoff.offer(Arc::new(presentation), tail.snapshot());
        let frame = handoff.take().expect("offered frame");
        let viewport = Viewport {
            width: 80,
            height: 24,
        };
        let mut bytes_total = 0;
        for scroll in 0..10 {
            let mut state = DashboardState::new();
            for _ in 0..scroll {
                state.scroll_down(frame.presentation.edges.len());
            }
            bytes_total += render_frame(&frame, viewport, &state).len();
        }
        // Rendering must not mutate capture: re-render and compare.
        let again = harness.render();
        assert_eq!(document, again, "frames never mutate capture");
        (document, start.elapsed(), bytes_total as u64)
    }
    let (off, off_time) = run_off();
    let (on, on_time, frame_bytes) = run_on();
    // Identical ledgers first (readable diffs), then full-document
    // equality modulo wall-clock readings (the two runs own separate
    // capture clocks; every count, identity, state, and gap is pinned).
    let ledger = ScaleSpec {
        name: "risk-gate",
        callers: 512,
        modules: 512,
        edges_per_caller: 8,
        endpoints_per_module: 4,
        first_pid: 82_000,
    }
    .expected_ledger();
    crate::discovery::inventory_workload::assert_ledger(&off, &ledger);
    crate::discovery::inventory_workload::assert_ledger(&on, &ledger);
    let mut off_norm = off.clone();
    let mut on_norm = on.clone();
    normalize_timestamps(&mut off_norm);
    normalize_timestamps(&mut on_norm);
    assert_eq!(on_norm, off_norm, "dashboard-on/off capture identical");
    let overhead = on_time.saturating_sub(off_time);
    eprintln!(
        "risk gate (512 callers/512 modules/4096 edges, 10 frames): off={off_time:?} on={on_time:?} overhead={overhead:?} frame_bytes={frame_bytes}"
    );
}

/// Null every wall-clock reading so two matched runs compare on
/// counts, identities, states, and gaps — never on clock values.
fn normalize_timestamps(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key.ends_with("_ns") {
                    *child = serde_json::Value::Null;
                } else {
                    normalize_timestamps(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                normalize_timestamps(item);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// REAL PTY tests: frames travel through a kernel pty pair (output
// processing, winsize, restoration sequences included).
// ---------------------------------------------------------------------------

/// A kernel pty pair for dashboard I/O tests.
struct Pty {
    master: File,
    slave: File,
}

impl Pty {
    fn open() -> Self {
        let mut master_fd: RawFd = -1;
        let mut slave_fd: RawFd = -1;
        let outcome = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            outcome,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(master_fd >= 0 && slave_fd >= 0);
        // Nonblocking master: reads poll with a deadline instead of
        // hanging the suite when an expectation fails.
        let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
        unsafe {
            libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            master: unsafe { File::from_raw_fd(master_fd) },
            slave: unsafe { File::from_raw_fd(slave_fd) },
        }
    }

    fn set_winsize(&self, cols: u16, rows: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let outcome = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
        assert_eq!(outcome, 0, "TIOCSWINSZ failed");
    }

    /// Read the master until `needle` appears or the deadline passes;
    /// returns everything read (pty output processing included).
    fn read_until(&mut self, needle: &[u8], timeout: Duration) -> Vec<u8> {
        use std::io::Read as _;
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::new();
        let mut chunk = [0u8; 4096];
        while Instant::now() < deadline {
            match self.master.read(&mut chunk) {
                Ok(0) => std::thread::sleep(Duration::from_millis(10)),
                Ok(n) => {
                    collected.extend_from_slice(&chunk[..n]);
                    if collected.windows(needle.len()).any(|w| w == needle) {
                        return collected;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("pty master read failed: {error}"),
            }
        }
        panic!(
            "pty read timed out waiting for {needle:?}; got {} bytes: {collected:?}",
            collected.len()
        );
    }
}

#[test]
fn pty_frame_roundtrip_resize_and_layout() {
    let mut pty = Pty::open();
    pty.set_winsize(80, 24);
    let queried = Viewport::from_fd(pty.slave.as_raw_fd()).expect("pty winsize queries");
    assert_eq!(
        queried,
        Viewport {
            width: 80,
            height: 24
        }
    );
    let presentation = varied_presentation();
    let frame = frame_for(&presentation);
    let bytes = render_frame(&frame, queried, &DashboardState::new());
    pty.slave.write_all(&bytes).unwrap();
    pty.slave.flush().unwrap();
    // The footer's quit hint proves the whole frame crossed the pty.
    let seen = pty.read_until(b"q quit", Duration::from_secs(5));
    // Pty output processing translates \n to \r\n; normalize and
    // the bytes are exactly the rendered frame.
    let text = String::from_utf8_lossy(&seen).replace("\r\n", "\n");
    let expected = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains(&expected[..expected.len().min(200)]),
        "frame head crossed intact"
    );
    assert!(text.contains("coverage:"), "{text}");
    // Resize to a small terminal: the SAME snapshot degrades.
    pty.set_winsize(60, 20);
    let small = Viewport::from_fd(pty.slave.as_raw_fd()).expect("resized winsize queries");
    assert_eq!(
        small,
        Viewport {
            width: 60,
            height: 20
        }
    );
    let bytes = render_frame(&frame, small, &DashboardState::new());
    pty.slave.write_all(&bytes).unwrap();
    pty.slave.flush().unwrap();
    // The whole minimal frame (its footer is its last row): its header
    // alone can arrive in a read before its coverage line does.
    let seen = pty.read_until(b"enlarge the terminal", Duration::from_secs(5));
    let text = String::from_utf8_lossy(&seen).replace("\r\n", "\n");
    assert!(text.contains("minimal"), "{text}");
    assert!(text.contains("coverage:"), "{text}");
}

#[test]
fn pty_terminal_writer_restores_on_clean_and_error_paths() {
    // Clean path: enter, frame, drop — exit sequences follow content.
    let mut pty = Pty::open();
    pty.set_winsize(80, 24);
    {
        let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
        writer.enter().unwrap();
        let presentation = varied_presentation();
        let frame = frame_for(&presentation);
        let bytes = render_frame(
            &frame,
            Viewport {
                width: 80,
                height: 24,
            },
            &DashboardState::new(),
        );
        writer.frame(&bytes).unwrap();
        assert_eq!(writer.account().frames_written, 1);
    }
    let seen = pty.read_until(b"\x1b[?1049l", Duration::from_secs(5));
    let text = String::from_utf8_lossy(&seen);
    let enter = text.find("\x1b[?1049h").expect("enter sequence");
    let frame_at = text.find("p11scope inventory").expect("frame content");
    let exit = text.find("\x1b[?1049l").expect("exit sequence");
    assert!(enter < frame_at && frame_at < exit, "enter < frame < exit");
    assert!(text.contains("\x1b[?25l"), "cursor hidden");
    assert!(text.contains("\x1b[?25h"), "cursor restored");
    // Error path: a fallible scope returns Err through the writer —
    // restoration still lands (Drop runs on `?`).
    let mut pty = Pty::open();
    let outcome: std::io::Result<()> = (|| {
        let mut writer = TerminalWriter::open(pty.slave.as_raw_fd())?;
        writer.enter()?;
        writer.frame(b"partial")?;
        Err(std::io::Error::other("injected dashboard failure"))
    })();
    assert!(outcome.is_err());
    let seen = pty.read_until(b"\x1b[?1049l", Duration::from_secs(5));
    assert!(seen.windows(b"\x1b[?25h".len()).any(|w| w == b"\x1b[?25h"));
}

/// Fills the pty until its slave refuses more (nobody reads the master).
/// The kernel moves buffered output on asynchronously, which can reopen a
/// little room after a refusal: refill until a pass after a pause takes
/// nothing.
fn fill(pty: &Pty) {
    use std::io::Write as _;
    let mut filler = pty.slave.try_clone().unwrap();
    let flags = unsafe { libc::fcntl(filler.as_raw_fd(), libc::F_GETFL) };
    unsafe {
        libc::fcntl(filler.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    loop {
        let mut took = 0;
        while let Ok(wrote) = filler.write(&[b'.'; 1024]) {
            if wrote == 0 {
                break;
            }
            took += wrote;
        }
        if took == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::fcntl(filler.as_raw_fd(), libc::F_SETFL, flags);
    }
}

/// Reads whatever the master holds now, until it stays empty for `quiet`.
fn drain(pty: &mut Pty, quiet: Duration) -> Vec<u8> {
    use std::io::Read as _;
    let mut collected = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut idle_since = Instant::now();
    while idle_since.elapsed() < quiet {
        match pty.master.read(&mut chunk) {
            Ok(n) if n > 0 => {
                collected.extend_from_slice(&chunk[..n]);
                idle_since = Instant::now();
            }
            _ => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    collected
}

/// C5.3: a terminal that stops reading costs each frame at most the write
/// budget; its frames shed with counters, and the screen is still restored
/// once it reads again.
#[test]
fn pty_a_stalled_terminal_sheds_frames_within_the_write_budget() {
    let mut pty = Pty::open();
    let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
    writer.enter().unwrap();
    fill(&pty);
    let frame = vec![b'F'; 4096];
    for _ in 0..20 {
        let began = Instant::now();
        writer.frame(&frame).unwrap();
        let took = began.elapsed();
        assert!(
            took < FRAME_WRITE_BUDGET + Duration::from_millis(40),
            "a stalled frame write took {took:?}"
        );
    }
    let account = writer.account();
    assert_eq!(account.frames_written, 0, "{account:?}");
    assert_eq!(account.frames_shed, 20, "{account:?}");
    assert_eq!(account.bytes_shed, 20 * 4096, "{account:?}");
    // The reader comes back: the restore reaches it whole.
    let reader = std::thread::spawn(move || {
        let seen = pty.read_until(b"\x1b[?1049l", Duration::from_secs(5));
        (pty, seen)
    });
    assert!(writer.restore(), "{:?}", writer.account());
    let (_pty, seen) = reader.join().unwrap();
    assert!(
        seen.windows(4).any(|w| w == b"\x18\x1b[?"),
        "CAN before the restore"
    );
    assert!(
        !seen.contains(&b'F'),
        "no shed frame byte reached the terminal"
    );
}

/// C5.3: a frame the terminal took only in part is counted cut, and the
/// next frame starts with CAN (aborting the cut escape sequence) before
/// its full repaint.
#[test]
fn pty_a_frame_cut_short_is_repaired_by_the_next() {
    let mut pty = Pty::open();
    let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
    fill(&pty);
    // Free a little room, less than the frame.
    let mut freed = 0;
    let mut chunk = [0u8; 512];
    while freed < 1024 {
        use std::io::Read as _;
        match pty.master.read(&mut chunk) {
            Ok(n) => freed += n,
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    writer.frame(&[b'A'; 32 * 1024]).unwrap();
    let account = writer.account();
    assert_eq!(
        (account.frames_shed, account.frames_cut),
        (1, 1),
        "{account:?}"
    );
    assert!(account.bytes_shed > 0 && account.bytes_shed < 32 * 1024);
    drain(&mut pty, Duration::from_millis(100));
    writer.frame(b"BBBB").unwrap();
    let seen = drain(&mut pty, Duration::from_millis(100));
    assert!(
        seen.ends_with(b"\x18BBBB"),
        "{:?}",
        String::from_utf8_lossy(&seen)
    );
    assert_eq!(writer.account().frames_written, 1);
    // Repaired: the frame after it carries no prefix.
    writer.frame(b"CCCC").unwrap();
    let seen = drain(&mut pty, Duration::from_millis(100));
    assert_eq!(seen, b"CCCC");
}

/// Review N1: a sustained stall cuts a frame, then sheds the next ones
/// whole; the repair is still owed, so the first frame written after the
/// stall starts with CAN.
#[test]
fn pty_a_repair_survives_frames_shed_whole_after_a_cut() {
    let mut pty = Pty::open();
    let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
    fill(&pty);
    let mut freed = 0;
    let mut chunk = [0u8; 512];
    while freed < 1024 {
        use std::io::Read as _;
        match pty.master.read(&mut chunk) {
            Ok(n) => freed += n,
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    writer.frame(&[b'A'; 32 * 1024]).unwrap();
    fill(&pty);
    writer.frame(&[b'X'; 4096]).unwrap();
    writer.frame(&[b'X'; 4096]).unwrap();
    let account = writer.account();
    assert_eq!(
        (
            account.frames_shed,
            account.frames_cut,
            account.frames_written
        ),
        (3, 1, 0),
        "{account:?}"
    );
    drain(&mut pty, Duration::from_millis(100));
    writer.frame(b"BBBB").unwrap();
    let seen = drain(&mut pty, Duration::from_millis(100));
    assert!(
        seen.ends_with(b"\x18BBBB"),
        "{:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// C5.3, the display under its loop: with a terminal that never reads,
/// every service tick still returns within the frame budget (keys never
/// wait either), frames shed with counters, and the display restores the
/// screen once the terminal reads again. The ticks run on their own
/// thread: a blocking write would hang it, and the watchdog fails the
/// test instead of the suite.
#[test]
fn pty_display_ticks_never_wait_on_a_stalled_terminal() {
    let mut pty = Pty::open();
    pty.set_winsize(200, 60);
    let output = pty.slave.as_raw_fd();
    let input = pty.slave.try_clone().unwrap();
    let input_fd = input.as_raw_fd();
    fill(&pty);
    let (done, finished) = std::sync::mpsc::channel();
    let ticker = std::thread::spawn(move || {
        let io = DashboardIo {
            output,
            input: Some(input_fd),
            account: None,
            stderr_fd: 2,
            stderr: StderrRoute::Leave,
        };
        let mut display = Display::open(&io, "pid:1").unwrap();
        let presentation = varied_presentation();
        let mut slowest = Duration::ZERO;
        let began = Instant::now();
        let mut ticks = 0;
        while began.elapsed() < Duration::from_millis(1500) {
            // A pass about every 10 ticks, as the 1 s cadence over 20 ms
            // ticks would offer (scaled down).
            if ticks % 10 == 0 {
                display.offer(presentation.clone());
            }
            ticks += 1;
            let tick = Instant::now();
            display.tick();
            slowest = slowest.max(tick.elapsed());
            std::thread::sleep(Duration::from_millis(20));
        }
        let account = display.account();
        done.send((slowest, account)).unwrap();
        // Restore once the reader is back (the main thread drains).
        display.restore();
        let restored = display.account().terminal.restored;
        drop(input);
        restored
    });
    let (slowest, account) = finished
        .recv_timeout(Duration::from_secs(10))
        .expect("a display tick blocked on the stalled terminal");
    assert!(
        slowest < FRAME_WRITE_BUDGET + Duration::from_millis(40),
        "slowest tick {slowest:?}"
    );
    assert!(account.ticks >= 50, "{account:?}");
    assert!(
        account.longest_gap < Duration::from_millis(100),
        "{account:?}"
    );
    assert!(
        account.longest_pass_gap < Duration::from_millis(100),
        "{account:?}"
    );
    assert!(account.terminal.frames_shed >= 3, "{account:?}");
    assert_eq!(account.terminal.frames_written, 0, "{account:?}");
    let seen = pty.read_until(b"\x1b[?1049l", Duration::from_secs(5));
    assert!(ticker.join().unwrap(), "restore reached the terminal");
    assert!(
        seen.windows(6).any(|w| w == b"\x1b[?25h"),
        "cursor restored"
    );
}

/// C5.3: restoring the screen on a terminal that never reads again waits
/// at most the restore budget, then sheds the sequence and says so.
#[test]
fn pty_a_restore_on_a_terminal_that_never_reads_is_bounded() {
    let pty = Pty::open();
    let fd = pty.slave.as_raw_fd();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut writer = TerminalWriter::open(fd).unwrap();
        writer.enter().unwrap();
        fill(&pty);
        let began = Instant::now();
        let restored = writer.restore();
        done.send((restored, began.elapsed())).unwrap();
        drop(pty);
    });
    // Fixed bounds (not derived from the budget): the documented 1 s.
    let (restored, took) = finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the restore blocked on a terminal that never reads");
    assert!(!restored, "nothing could reach the terminal");
    assert!(took < Duration::from_millis(1250), "{took:?}");
}

/// Review L1: a restore the terminal shed is tried once more (after the
/// report): a terminal that reads again gets the whole sequence, CAN
/// first; a restore that went through is never repeated.
#[test]
fn pty_a_shed_restore_is_retried_once() {
    let pty = Pty::open();
    let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
    writer.enter().unwrap();
    fill(&pty);
    assert!(!writer.restore(), "nothing could reach the terminal");
    let reader = std::thread::spawn(move || {
        let mut pty = pty;
        let seen = pty.read_until(b"\x1b[?1049l", Duration::from_secs(5));
        (pty, seen)
    });
    assert!(
        writer.retry_restore(Duration::from_secs(5)),
        "{:?}",
        writer.account()
    );
    let (mut pty, seen) = reader.join().unwrap();
    assert!(
        seen.ends_with(RESTORE_SCREEN),
        "the whole sequence, CAN first"
    );
    let account = writer.account();
    assert!(account.restored && account.restore_retried, "{account:?}");
    assert!(writer.retry_restore(Duration::from_secs(5)));
    assert!(drain(&mut pty, Duration::from_millis(100)).is_empty());
    // A restore that went through first time is not retried.
    let mut pty = Pty::open();
    let mut writer = TerminalWriter::open(pty.slave.as_raw_fd()).unwrap();
    writer.enter().unwrap();
    assert!(writer.restore());
    drain(&mut pty, Duration::from_millis(100));
    assert!(writer.retry_restore(Duration::from_secs(5)));
    assert!(!writer.account().restore_retried);
    assert!(drain(&mut pty, Duration::from_millis(100)).is_empty());
}

/// C5.3: the stop's closing lines share one budget on a stderr that does
/// not read: past it each line is shed after the floor wait, counted.
#[test]
fn notices_on_a_stalled_stderr_share_one_budget() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (reader, writer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    let mut sink =
        crate::sink::SinkWriter::new(crate::sink::StdoutInner::File(writer.try_clone().unwrap()))
            .unwrap();
    // Fill the pipe through the sink's own nonblocking description.
    {
        use std::io::Write as _;
        let mut filler = writer;
        while filler.write(&[b'.'; 4096]).is_ok() {}
    }
    sink.take_drops();
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut notices = Notices::over(sink, Duration::from_millis(200));
        let began = Instant::now();
        for line in 0..5 {
            notices.line(&format!("notice {line}"));
        }
        done.send((notices.shed(), began.elapsed())).unwrap();
    });
    let (shed, took) = finished
        .recv_timeout(Duration::from_secs(5))
        .expect("a notice blocked on the stalled stderr");
    assert_eq!(shed, 5);
    assert!(took < Duration::from_millis(500), "{took:?}");
    drop(reader);
}

/// Review N2: once the shared budget is spent on a stalled stderr, a
/// later line still gets its floor wait, so a stderr that reads again
/// takes it.
#[test]
fn notices_reach_a_stderr_that_reads_again_after_the_budget_is_spent() {
    use std::io::Read as _;
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (mut reader, writer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    let sink =
        crate::sink::SinkWriter::new(crate::sink::StdoutInner::File(writer.try_clone().unwrap()))
            .unwrap();
    {
        use std::io::Write as _;
        let mut filler = writer;
        while filler.write(&[b'.'; 4096]).is_ok() {}
    }
    let mut notices = Notices::over(sink, Duration::from_millis(20));
    notices.line("shed while stalled");
    assert_eq!(notices.shed(), 1);
    // The reader drains everything it was sent.
    let mut chunk = [0u8; 65536];
    let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
    unsafe {
        libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    while reader.read(&mut chunk).is_ok_and(|read| read > 0) {}
    notices.line("delivered once it reads");
    assert_eq!((notices.written(), notices.shed()), (1, 1));
    let read = reader.read(&mut chunk).unwrap();
    assert_eq!(&chunk[..read], b"delivered once it reads\n");
}

/// C5.3: the loop's last stretch, from its last tick to the stop, counts
/// as a service gap (a pass that held the loop until the stop is not
/// hidden by the missing next tick).
#[test]
fn pty_the_stretch_before_the_stop_counts_as_a_gap() {
    let pty = Pty::open();
    let io = DashboardIo {
        output: pty.slave.as_raw_fd(),
        input: None,
        account: None,
        stderr_fd: 2,
        stderr: StderrRoute::Leave,
    };
    let mut display = Display::open(&io, "pid:1").unwrap();
    display.tick();
    std::thread::sleep(Duration::from_millis(150));
    display.restore();
    let account = display.account();
    assert!(
        account.longest_gap >= Duration::from_millis(150),
        "{account:?}"
    );
}

/// A stand-in for the process's stderr (review M1): a file only this
/// test writes, behind an fd of its own (the test process's fd 2 is
/// never touched).
struct FakeStderr {
    file: File,
    fd: std::os::fd::OwnedFd,
}

impl FakeStderr {
    fn open() -> Self {
        let file = tempfile::tempfile().unwrap();
        let fd = file.try_clone().unwrap().into();
        Self { file, fd }
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// A writer of the process's stderr (a scan diagnostic, a panic).
    fn write(&self, line: &str) {
        let bytes = format!("{line}\n");
        let wrote = unsafe { libc::write(self.raw(), bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(wrote, bytes.len() as isize);
    }

    fn text(&self) -> String {
        use std::io::{Read as _, Seek as _};
        let mut file = &self.file;
        file.rewind().unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        text
    }
}

fn display_over(pty: &Pty, stderr: &FakeStderr, route: StderrRoute) -> Display {
    let io = DashboardIo {
        output: pty.slave.as_raw_fd(),
        input: None,
        account: None,
        stderr_fd: stderr.raw(),
        stderr: route,
    };
    Display::open(&io, "pid:1").unwrap()
}

/// Review M1: a stderr that is the terminal is captured while the screen
/// is up, and at the restore everything it held (also what arrived after
/// the last pass) and every pass warning is replayed on the real stderr,
/// which is then back in place. Progress lines are not replayed.
#[test]
fn pty_a_captured_stderr_is_replayed_on_the_real_stderr_at_the_restore() {
    let pty = Pty::open();
    let stderr = FakeStderr::open();
    let mut display = display_over(&pty, &stderr, StderrRoute::Capture);
    stderr.write("discovery: a stray diagnostic");
    display.warn("p11scope: pass failed, continuing without its scan");
    display.log("p11scope: pass 1: 1 scanned");
    display.offer(varied_presentation());
    stderr.write("discovery: after the last pass");
    assert_eq!(stderr.text(), "", "nothing reached the real stderr yet");
    display.restore();
    let text = stderr.text();
    assert!(
        text.starts_with("p11scope: stderr while the dashboard ran (3 lines):\n"),
        "{text}"
    );
    for kept in [
        "discovery: a stray diagnostic\n",
        "p11scope: pass failed, continuing without its scan\n",
        "discovery: after the last pass\n",
    ] {
        assert!(text.contains(kept), "{kept:?} in {text}");
    }
    assert!(!text.contains("pass 1:"), "{text}");
    let account = display.account().stderr;
    assert_eq!(
        (
            account.route,
            account.replayed,
            account.dropped,
            account.undrained
        ),
        (StderrRoute::Capture, 3, 0, false),
        "{account:?}"
    );
    // The stderr fd is back on the real stderr.
    stderr.write("after the restore");
    assert!(stderr.text().ends_with("after the restore\n"));
}

/// Review M1 (F8): a panic under the dashboard writes its message into the
/// capture; the unwind restores the screen and replays it.
#[test]
fn pty_a_panic_message_survives_the_dashboard() {
    let pty = Pty::open();
    let stderr = FakeStderr::open();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _display = display_over(&pty, &stderr, StderrRoute::Capture);
        // What the panic hook writes to the process's stderr.
        stderr.write("thread 'main' panicked at src/inventory.rs:1:1:");
        stderr.write("an injected invariant failure");
        panic!("an injected invariant failure");
    }));
    assert!(unwound.is_err());
    let text = stderr.text();
    assert!(
        text.contains(
            "thread 'main' panicked at src/inventory.rs:1:1:\nan injected invariant failure\n"
        ),
        "{text}"
    );
}

/// Review M1: a stderr that is not the terminal (`2>file`) is left alone,
/// and the log lines (progress and warnings) are mirrored to it as they
/// come, like the classic path's.
#[test]
fn pty_a_stderr_file_gets_the_log_lines_as_they_come() {
    let pty = Pty::open();
    let stderr = FakeStderr::open();
    let mut display = display_over(&pty, &stderr, StderrRoute::Mirror);
    stderr.write("discovery: a direct diagnostic");
    display.log("p11scope: pass 1: 1 scanned");
    display.warn("p11scope: pass 3: caller c0 exited");
    display.offer(varied_presentation());
    assert_eq!(
        stderr.text(),
        "discovery: a direct diagnostic\np11scope: pass 1: 1 scanned\n\
         p11scope: pass 3: caller c0 exited\n"
    );
    display.restore();
    assert_eq!(stderr.text().lines().count(), 3, "nothing replayed twice");
    let account = display.account().stderr;
    assert_eq!(
        (account.mirrored, account.mirror_shed),
        (2, 0),
        "{account:?}"
    );
}

/// Review M1 (L3): a stderr pipe nobody reads (its reopen fails with
/// ENXIO, a write would be EPIPE) sheds the closing lines with counts and
/// never panics or blocks.
#[test]
fn notices_on_a_readerless_stderr_shed_without_panicking() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (reader, writer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    // Opened while the reader is there; the reader then goes away.
    let mut late = Notices::on_fd(writer.as_raw_fd(), Duration::from_millis(100));
    drop(reader);
    let mut early = Notices::on_fd(writer.as_raw_fd(), Duration::from_millis(100));
    for line in 0..3 {
        late.line(&format!("closing line {line}"));
        early.line(&format!("closing line {line}"));
    }
    assert_eq!((late.written(), late.shed()), (0, 3));
    assert_eq!((early.written(), early.shed()), (0, 3));
}

#[test]
fn pty_raw_mode_roundtrips_without_touching_stdin() {
    let pty = Pty::open();
    let fd = pty.slave.as_raw_fd();
    let mut before: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut before) }, 0);
    {
        let guard = RawModeGuard::enter_fd(fd).unwrap().expect("slave is a tty");
        let mut raw: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut raw) }, 0);
        assert_eq!(raw.c_lflag & libc::ICANON, 0, "canonical off");
        assert_eq!(raw.c_lflag & libc::ECHO, 0, "echo off");
        assert_eq!(raw.c_lflag & libc::ISIG, 0, "signal-chars off");
        assert_ne!(raw.c_oflag & libc::OPOST, 0, "output processing kept");
        drop(guard);
    }
    let mut after: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut after) }, 0);
    assert_eq!(
        (
            before.c_iflag,
            before.c_oflag,
            before.c_cflag,
            before.c_lflag
        ),
        (after.c_iflag, after.c_oflag, after.c_cflag, after.c_lflag),
        "termios restored exactly"
    );
    // Non-terminals decline raw mode instead of failing.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    assert!(RawModeGuard::enter_fd(tmp.as_raw_fd()).unwrap().is_none());
}

#[test]
fn pty_large_inventory_renders_through_bounded_views() {
    // E1 scale: 4096 callers + 4096 modules through an 80×24 window.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-scale",
        callers: 4096,
        modules: 4096,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 90_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let presentation = Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        1,
        ended,
        ended.saturating_sub(started),
    );
    assert_eq!(presentation.callers.len(), 4096);
    assert_eq!(presentation.modules.len(), 4096);
    assert_eq!(presentation.edges.len(), 4096);
    let frame = frame_for(&presentation);
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 24,
        },
        &DashboardState::new(),
    );
    // Bounded: exactly the viewport, however large the capture.
    let text = frame_text(&bytes);
    assert_eq!(text.split('\n').count(), 24);
    assert!(text.contains("4096 callers"), "{text}");
    assert!(text.contains("4096 edges"), "{text}");
    assert!(text.contains("more below"), "{text}");
    // ... and the bounded frame crosses a real pty intact.
    let mut pty = Pty::open();
    pty.set_winsize(80, 24);
    pty.slave.write_all(&bytes).unwrap();
    pty.slave.flush().unwrap();
    let seen = pty.read_until(b"q quit", Duration::from_secs(10));
    let text = String::from_utf8_lossy(&seen).replace("\r\n", "\n");
    assert!(text.contains("4096 callers"), "{text}");
    assert!(text.contains("more below"), "{text}");
    // Scrolling traverses without narrowing totals.
    let mut scrolled = DashboardState::new();
    for _ in 0..4000 {
        scrolled.scroll_down(4096);
    }
    let bytes = render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 24,
        },
        &scrolled,
    );
    let text = frame_text(&bytes);
    assert!(text.contains("4096 edges"), "{text}");
    assert!(text.contains("^ +"), "{text}");
}

#[test]
fn starved_windows_stay_honest_about_showing_nothing() {
    // A room too small for even the minimal block shows the honest
    // line (never bare markers), and the range names 0-0 (never an
    // edge the frame does not show).
    let presentation = varied_presentation();
    assert!(!presentation.edges.is_empty());
    let (lines, shown) = render_edge_window(&presentation, 80, 2, 0, false);
    assert_eq!(shown, 0);
    assert_eq!(
        lines,
        vec!["(no edges fit here; scroll or enlarge the terminal)".to_string()]
    );
    assert_eq!(visible_item_range(0, 13, 3), (0, 0));
    assert_eq!(visible_item_range(0, 0, 0), (0, 0));
    // The normal path is unchanged: counts, not scroll arithmetic.
    assert_eq!(visible_item_range(2, 13, 1), (2, 3));
    // Sanity: the same fixture shows edges once the room suffices.
    let (_, shown) = render_edge_window(&presentation, 80, 7, 0, false);
    assert!(shown > 0);
}

/// Capture the harness state as a presentation (the varied tail,
/// factored for the detail-page fixtures).
fn capture_presentation(harness: &Harness) -> Presentation {
    let document = harness.render();
    let started = document["observation"]["started_ns"].as_u64().unwrap();
    let ended = document["observation"]["ended_ns"].as_u64().unwrap();
    let passes = document["observation"]["passes"].as_u64().unwrap();
    Presentation::capture(
        harness.coordinator(),
        "workload",
        started,
        ended,
        passes,
        ended,
        ended.saturating_sub(started),
    )
}

/// One caller, one edge, one completed sign: the observed edge the
/// detail pages page over. Returns the presentation plus the
/// evidence counters the JSON carries (the pages must match them).
fn observed_presentation() -> Presentation {
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-detail",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 81_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = harness.coordinator().adapter().live_id(81_000).unwrap();
    let key = ModuleKey::physical(8, 1, 100_000, Some("sha000000".into()), "/scale/m0.so");
    let init = SemanticCall {
        function: "C_SignInit".into(),
        rv: 0,
        session: 7,
        mechanism: 0x1087,
        capture: p11scope_ebpf_common::capture::MECHANISM_VALUE
            | p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
        ts_ns: 100,
        ..SemanticCall::default()
    };
    let op = SemanticCall {
        function: "C_Sign".into(),
        rv: 0,
        session: 7,
        capture: p11scope_ebpf_common::capture::MECHANISM_NONE
            | p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
        ts_ns: 110,
        ..SemanticCall::default()
    };
    harness.observe_semantic(caller, &key, init);
    harness.observe_semantic(caller, &key, op);
    harness.coordinator_mut().registry_mut().record_gap(RegistryGap {
        caller: None,
        module: None,
        pid: None,
        subject: "detail probe gap".into(),
        reason: "the gaps page must show this row verbatim even when it wraps across two eighty-column terminal lines".into(),
        budget: None,
    });
    harness.commit();
    capture_presentation(&harness)
}

/// The gaps-page content lines for gap `head` (the `gap i/n …`
/// line), whitespace-normalized the way word-wrap reflows: words in
/// order, single spaces. Equals the snapshot gap line when the page
/// shows the gap whole.
fn normalized_gap_content(text: &str, head: &str) -> String {
    let clean = text.replace("\x1b[K", "");
    let mut lines = clean.lines().skip_while(|line| *line != head);
    assert_eq!(lines.next(), Some(head));
    let content: Vec<&str> = lines.take_while(|line| line.starts_with(' ')).collect();
    assert!(!content.is_empty(), "gap {head} shows its text");
    content
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn detail_pages_keep_shaved_facts_reachable_at_80x14() {
    // F6: the summary shaves counters and gap rows behind explicit
    // markers at 80x14; the evidence page shows all nine counters
    // and the gaps page the wrapped gap row — every fact reachable
    // across frames, every frame honest about its window.
    let presentation = observed_presentation();
    assert_eq!(presentation.edges.len(), 1);
    assert_eq!(presentation.gaps.len(), 1);
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 80,
        height: 14,
    };
    let mut summary = DashboardState::new();
    assert_eq!(summary.detail, DetailPage::Summary);
    let text = frame_text(&render_frame(&frame, viewport, &summary));
    assert!(text.contains("evidence +9 hidden"), "{text}");
    // The gap row fits but truncates mid-reason: the summary names
    // the gap, the gaps page below carries its whole text.
    assert!(text.contains("gap [detail probe gap]"), "{text}");
    assert!(!text.contains("eighty-column terminal lines"), "{text}");
    assert!(text.contains("--- edges 1-1 of 1 [summary]"), "{text}");
    assert!(
        text.contains("scroll 0/0 | showing edges 1-1 of 1 | j/k scroll, tab details, q quit"),
        "{text}"
    );
    summary.next_detail();
    assert_eq!(summary.detail, DetailPage::Evidence);
    let text = frame_text(&render_frame(&frame, viewport, &summary));
    assert!(!text.contains("no edges fit"), "{text}");
    assert_eq!(text.matches("ev ").count(), 9, "{text}");
    for short in [
        "reconc",
        "cancel_amb",
        "cancel_flags",
        "op_imports",
        "auth_amb",
        "cap_fail",
        "async_dup",
        "async_evict",
        "unmatch_close",
    ] {
        assert!(text.contains(&format!("ev {short}=0")), "{text}");
    }
    assert!(!text.contains("hidden"), "{text}");
    // The evidence page carries the edge's full coverage label (the
    // summary shows only the compact entries form).
    assert!(text.contains("coverage unknown (scan only)"), "{text}");
    assert!(text.contains("--- edges 1-1 of 1 [evidence]"), "{text}");
    summary.next_detail();
    assert_eq!(summary.detail, DetailPage::Gaps);
    let text = frame_text(&render_frame(&frame, viewport, &summary));
    assert!(text.contains("gap 1/1 caller * module *"), "{text}");
    assert_eq!(
        normalized_gap_content(&text, "gap 1/1 caller * module *"),
        "gap [detail probe gap] the gaps page must show this row verbatim even when it wraps across two eighty-column terminal lines",
    );
    assert!(text.contains("--- gaps 1-1 of 1 [gaps]"), "{text}");
    assert!(
        text.contains("scroll 0/0 | showing gaps 1-1 of 1 | j/k scroll, tab details, q quit"),
        "{text}"
    );
    summary.next_detail();
    assert_eq!(summary.detail, DetailPage::Summary);
}

#[test]
fn gaps_page_lists_gaps_that_name_no_edge() {
    // F6: a caller-qualified gap for a caller with no edge rides no
    // summary block; the gaps ledger lists it with attribution.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-orphan-gap",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 82_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .record_gap(RegistryGap {
        caller: Some(CallerId(7)),
        module: None,
        pid: Some(82_009),
        subject: "caller capacity exhausted".into(),
        reason:
            "the registry retains at most 3 callers (requested caller 4); the mapping was dropped"
                .into(),
        budget: Some(BudgetRefusal {
            resource: "callers",
            limit: 3,
            requested: 4,
        }),
    });
    harness.commit();
    let presentation = capture_presentation(&harness);
    assert_eq!(presentation.edges.len(), 1);
    assert_eq!(presentation.gaps.len(), 1);
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 80,
        height: 14,
    };
    let summary = DashboardState::new();
    let text = frame_text(&render_frame(&frame, viewport, &summary));
    assert!(
        !text.contains("caller capacity exhausted"),
        "no summary block rides an edgeless gap: {text}"
    );
    let mut gaps = DashboardState::new();
    gaps.next_detail();
    gaps.next_detail();
    assert_eq!(gaps.detail, DetailPage::Gaps);
    let text = frame_text(&render_frame(&frame, viewport, &gaps));
    assert!(
        text.contains("gap 1/1 caller c7 module * pid 82009"),
        "{text}"
    );
    assert_eq!(
        normalized_gap_content(&text, "gap 1/1 caller c7 module * pid 82009"),
        "gap [caller capacity exhausted] the registry retains at most 3 callers (requested caller 4); the mapping was dropped (budget callers: limit 3, requested 4)",
    );
}

#[test]
fn dashboard_gap_scroll_survives_redraw() {
    // F6c: the production redraw clamp runs through the page-aware
    // helper — a gaps-page scroll stays put across redraws even
    // when the edge count is smaller (the old edge-count clamp
    // dragged every such scroll back to gap zero, and stranded
    // every later gap when no edge existed at all).
    for edges_per_caller in [0, 1] {
        let mut harness = harness();
        let spec = ScaleSpec {
            name: "dash-gap-clamp",
            callers: 1,
            modules: 1,
            edges_per_caller,
            endpoints_per_module: 1,
            first_pid: 84_000,
        };
        harness.stage_scale(&spec);
        harness.commit();
        for index in 0..4 {
            harness
                .coordinator_mut()
                .registry_mut()
                .record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: format!("gap probe {index}"),
                    reason: format!("retained gap {index} of the redraw-clamp probe"),
                    budget: None,
                });
        }
        harness.commit();
        let presentation = capture_presentation(&harness);
        assert_eq!(presentation.edges.len(), edges_per_caller);
        assert_eq!(presentation.gaps.len(), 4);
        let frame = frame_for(&presentation);
        let viewport = Viewport {
            width: 80,
            height: 14,
        };
        let mut state = DashboardState::new();
        state.next_detail();
        state.next_detail();
        assert_eq!(state.detail, DetailPage::Gaps);
        // Scroll to the last gap exactly like the production key
        // handler (page total, not the edge count).
        for _ in 0..3 {
            state.scroll_down(state.items_total(&presentation));
        }
        assert_eq!(state.scroll, 3);
        let text = frame_text(&render_frame(&frame, viewport, &state));
        assert!(
            text.contains("gap 4/4"),
            "edges={edges_per_caller} last gap reachable: {text}"
        );
        // The old redraw clamp, for contrast: with fewer edges than
        // gaps it collapses the scroll (the reported defect).
        let mut collapsed = state;
        collapsed.clamp(presentation.edges.len());
        assert_eq!(
            collapsed.scroll, 0,
            "edges={edges_per_caller} the edge-count clamp strands gap 4/4"
        );
        // The production redraw clamp preserves the gaps scroll.
        state.clamp_to_presentation(&presentation);
        assert_eq!(
            state.scroll, 3,
            "edges={edges_per_caller} redraw keeps gap 4/4"
        );
        let text = frame_text(&render_frame(&frame, viewport, &state));
        assert!(
            text.contains("gap 4/4"),
            "edges={edges_per_caller} last gap still shown: {text}"
        );
        assert!(text.contains("--- gaps 4-4 of 4 [gaps]"), "{text}");
    }
}

#[test]
fn gaps_page_exposes_multiframe_gap_at_80x14() {
    // F6d: a 600+ character gap reason exceeds the seven content
    // rows at 80x14 and pages within its record — repeated
    // production Down steps expose every line across frames (the
    // old whole-block fit rejected the record outright behind "no
    // gaps fit"), then reach the next record.
    let words: Vec<String> = (0..100).map(|index| format!("seg{index:03}")).collect();
    let reason = words.join(" ");
    assert!(
        reason.chars().count() >= 600,
        "the probe reason exceeds one frame: {} chars",
        reason.chars().count()
    );
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-tall-gap",
        callers: 1,
        modules: 1,
        edges_per_caller: 0,
        endpoints_per_module: 1,
        first_pid: 85_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "tall probe gap".into(),
            reason: reason.clone(),
            budget: None,
        });
    harness
        .coordinator_mut()
        .registry_mut()
        .record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "short trailer gap".into(),
            reason: "the record after the tall one".into(),
            budget: None,
        });
    harness.commit();
    let presentation = capture_presentation(&harness);
    assert_eq!(presentation.edges.len(), 0);
    assert_eq!(presentation.gaps.len(), 2);
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 80,
        height: 14,
    };
    // Walk the production Down handler to the bottom, one frame per
    // step; the walk must terminate (no paging stall).
    let mut state = DashboardState::new();
    state.next_detail();
    state.next_detail();
    assert_eq!(state.detail, DetailPage::Gaps);
    let mut frames = Vec::new();
    for _ in 0..64 {
        let text = frame_text(&render_frame(&frame, viewport, &state));
        assert_eq!(text.lines().count(), 14, "every frame fills 80x14");
        frames.push((state.scroll, state.gap_line, text));
        let before = (state.scroll, state.gap_line);
        state.scroll_gaps_down(&presentation, viewport.width);
        if (state.scroll, state.gap_line) == before {
            break;
        }
    }
    let last = frames.last().expect("at least one frame");
    assert_eq!(
        (last.0, last.1),
        (1, 0),
        "the walk ends on the last record's head"
    );
    assert!(frames.len() < 64, "the walk terminates far below the bound");
    // The tall record spans frames: more than one frame holds
    // scroll 0, and none of them hides behind "no gaps fit".
    let tall_frames: Vec<&(usize, usize, String)> =
        frames.iter().filter(|frame| frame.0 == 0).collect();
    assert!(
        tall_frames.len() >= 2,
        "the tall record spans frames: {} states",
        frames.len()
    );
    for (_, _, text) in &frames {
        assert!(!text.contains("no gaps fit"), "{text}");
    }
    // The first frame names the record and its continuation; a mid
    // frame names the lines above and the footer its offset.
    assert!(
        tall_frames[0].2.contains("gap 1/2 caller * module *"),
        "{}",
        tall_frames[0].2
    );
    assert!(
        tall_frames[0].2.contains("(continued: +"),
        "{}",
        tall_frames[0].2
    );
    assert!(
        tall_frames
            .iter()
            .any(|frame| frame.2.contains("lines above)")),
        "a mid frame names the skipped lines"
    );
    assert!(
        tall_frames.iter().any(|frame| frame.2.contains("line +")),
        "the footer names the within-record offset"
    );
    // Every word of the reason is readable in some frame.
    for word in &words {
        assert!(
            frames.iter().any(|frame| frame.2.contains(word)),
            "word {word} reachable across {} frames",
            frames.len()
        );
    }
    // Ranges stay honest while paging, and the trailer record
    // follows the tall one whole.
    for (scroll, _, text) in &frames {
        assert!(
            text.contains(&format!(
                "--- gaps {}-{} of 2 [gaps]",
                scroll + 1,
                scroll + 1
            )),
            "{text}"
        );
    }
    assert!(last.2.contains("gap 2/2 caller * module *"), "{}", last.2);
    assert!(
        last.2.contains("the record after the tall one"),
        "{}",
        last.2
    );
    assert!(!last.2.contains("(continued:"), "{}", last.2);
    // Up walks back to the first record's head, line by line.
    for _ in 0..64 {
        if (state.scroll, state.gap_line) == (0, 0) {
            break;
        }
        state.scroll_gaps_up();
    }
    assert_eq!((state.scroll, state.gap_line), (0, 0));
    let text = frame_text(&render_frame(&frame, viewport, &state));
    assert!(text.contains("gap 1/2 caller * module *"), "{text}");
}

#[test]
fn gap_continuation_offset_clamps_after_reflow_or_shrink() {
    // F6e: the footer names the EFFECTIVE within-record offset — the
    // stored offset clamped to the record's wrapped body at the live
    // width — so a stale offset (a wider reflow, or a rescan that
    // shrank the record) can never disagree with the continuation
    // head. The old footer printed the raw stored offset.
    /// Footer offset: the `line +N` in the `scroll …` footer, if any.
    fn footer_offset(text: &str) -> Option<usize> {
        let marker = "line +";
        let at = text.find(marker)?;
        text[at + marker.len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()
    }
    /// Continuation-head offset: the `(+N lines above)` head, if any.
    fn head_offset(text: &str) -> Option<usize> {
        let marker = "(+";
        let at = text.find(marker)?;
        let rest = &text[at + marker.len()..];
        let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        assert!(
            rest[digits.len()..].starts_with(" lines above)"),
            "the `(+` marker always opens a continuation head: {text}"
        );
        digits.parse().ok()
    }
    fn record_reason(harness: &mut Harness, subject: &str, reason: &str) {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: subject.into(),
                reason: reason.into(),
                budget: None,
            });
    }
    let words: Vec<String> = (0..100).map(|index| format!("seg{index:03}")).collect();
    let tall_reason = words.join(" ");
    let mut tall_harness = harness();
    let spec = ScaleSpec {
        name: "dash-stale-offset",
        callers: 1,
        modules: 1,
        edges_per_caller: 0,
        endpoints_per_module: 1,
        first_pid: 86_000,
    };
    tall_harness.stage_scale(&spec);
    tall_harness.commit();
    record_reason(&mut tall_harness, "tall probe gap", &tall_reason);
    tall_harness.commit();
    let tall = capture_presentation(&tall_harness);
    assert_eq!(tall.gaps.len(), 1);
    // A rescan that shrank the record: same ledger position, a short
    // replacement reason.
    let mut rescan = harness();
    let rescan_spec = ScaleSpec {
        name: "dash-shrunk-offset",
        first_pid: 87_000,
        ..spec
    };
    rescan.stage_scale(&rescan_spec);
    rescan.commit();
    record_reason(
        &mut rescan,
        "shrunk probe gap",
        "the replacement record after the rescan is much shorter than the tall probe it replaced",
    );
    rescan.commit();
    let shrunk = capture_presentation(&rescan);
    assert_eq!(shrunk.gaps.len(), 1);
    let narrow = Viewport {
        width: 80,
        height: 14,
    };
    // Baseline: a production Down walk names the same offset in the
    // head and the footer (the fix must not disturb the sane path).
    let mut state = DashboardState::new();
    state.next_detail();
    state.next_detail();
    assert_eq!(state.detail, DetailPage::Gaps);
    for _ in 0..2 {
        state.scroll_gaps_down(&tall, narrow.width);
    }
    assert_eq!((state.scroll, state.gap_line), (0, 2));
    let text = frame_text(&render_frame(&frame_for(&tall), narrow, &state));
    assert_eq!(text.lines().count(), 14, "{text}");
    assert_eq!(head_offset(&text), Some(2), "{text}");
    assert_eq!(footer_offset(&text), Some(2), "{text}");
    // Reflow: the offset was valid at width 80 (the walk above keeps
    // stepping there), but the same stored offset overruns the
    // rewrapped body at width 200. Direct assignment simulates the
    // pre-resize navigation — the production handler can never
    // produce a stale offset by itself.
    state.gap_line = 6;
    let wide = Viewport {
        width: 200,
        height: 14,
    };
    let text = frame_text(&render_frame(&frame_for(&tall), wide, &state));
    assert_eq!(text.lines().count(), 14, "{text}");
    let head = head_offset(&text).expect("a continuation head names the offset");
    assert!(
        head < 6,
        "the reflow clamps the stale offset 6 to {head}: {text}"
    );
    assert_eq!(footer_offset(&text), Some(head), "{text}");
    assert!(!text.contains("line +6"), "{text}");
    // Shrink: the same stale offset against the rescanned short
    // record clamps to its body, head and footer agreeing.
    let text = frame_text(&render_frame(&frame_for(&shrunk), narrow, &state));
    assert_eq!(text.lines().count(), 14, "{text}");
    let head = head_offset(&text).expect("a continuation head names the offset");
    assert!(
        head < 6,
        "the shrinkage clamps the stale offset 6 to {head}: {text}"
    );
    assert_eq!(footer_offset(&text), Some(head), "{text}");
    assert!(!text.contains("line +6"), "{text}");
    // Clamp to zero: a one-body-line record leaves no offset to
    // name — the footer drops `line +` and the head is plain.
    let text = frame_text(&render_frame(&frame_for(&shrunk), wide, &state));
    assert_eq!(text.lines().count(), 14, "{text}");
    assert_eq!(head_offset(&text), None, "{text}");
    assert_eq!(footer_offset(&text), None, "{text}");
    assert!(!text.contains("lines above"), "{text}");
}

#[test]
fn each_detail_page_scrolls_its_own_items_with_clamped_ranges() {
    // Two edges, one gap: the edge pages scroll over two items, the
    // gaps page over one; switching pages clamps the scroll.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-pages",
        callers: 2,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: 83_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    harness
        .coordinator_mut()
        .registry_mut()
        .record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "detail probe gap".into(),
            reason: "one gap".into(),
            budget: None,
        });
    harness.commit();
    let presentation = capture_presentation(&harness);
    assert_eq!(presentation.edges.len(), 2);
    assert_eq!(presentation.gaps.len(), 1);
    let mut state = DashboardState::new();
    assert_eq!(state.items_total(&presentation), 2);
    state.scroll_down(2);
    state.scroll_down(2);
    assert_eq!(state.scroll, 1, "scroll clamps to the last edge");
    state.next_detail();
    assert_eq!(state.items_total(&presentation), 2);
    state.next_detail();
    assert_eq!(state.detail, DetailPage::Gaps);
    assert_eq!(state.items_total(&presentation), 1);
    state.clamp(state.items_total(&presentation));
    assert_eq!(state.scroll, 0, "page switches clamp the scroll");
    let frame = frame_for(&presentation);
    let text = frame_text(&render_frame(
        &frame,
        Viewport {
            width: 80,
            height: 14,
        },
        &state,
    ));
    assert!(text.contains("showing gaps 1-1 of 1"), "{text}");
}

#[test]
fn mixed_coverage_renders_identically_in_json_jsonl_and_dashboard() {
    // Task 6 C2: per-edge coverage — counted, witnessed, watched (and
    // a demoted watch), scan-only unknown, and not-admitted unknown —
    // renders from the ONE presentation into the JSON document, the
    // JSONL edge events, the pager snapshot, and dashboard frames.
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "dash-coverage",
        callers: 1,
        modules: 5,
        edges_per_caller: 5,
        endpoints_per_module: 4,
        first_pid: 82_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let caller = harness.coordinator().adapter().live_id(82_000).unwrap();
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        82_000,
        refused_module_info(1),
        now,
    );
    harness.commit();
    harness.advance(100);
    let at = harness.now_ns();
    let key = |index: u64| {
        let path = format!("/scale/m{index}.so");
        ModuleKey::physical(8, 1, 100_000 + index, Some(format!("sha{index:06}")), &path)
    };
    {
        let registry = harness.coordinator_mut().registry_mut();
        registry.note_coverage(caller, &key(0), CoverageNote::Counted { since_ns: at });
        registry.observe_entries(caller, &key(0), 4, at);
        registry.note_witness(caller, &key(1), at);
        registry.note_coverage(caller, &key(2), CoverageNote::Watched { since_ns: at });
        registry.note_coverage(caller, &key(3), CoverageNote::Watched { since_ns: at });
    }
    harness.commit();
    harness.advance(10);
    harness
        .coordinator_mut()
        .registry_mut()
        .note_health_regression("CALLER_EVIDENCE rose", at + 5, at + 5);
    harness.commit();
    harness.advance(10);
    let at2 = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_coverage(
        caller,
        &key(2),
        CoverageNote::Watched { since_ns: at2 },
    );
    harness.coordinator_mut().registry_mut().note_coverage(
        caller,
        &key(4),
        CoverageNote::Watched { since_ns: at2 },
    );
    harness.commit();
    let presentation = capture_from_harness(&harness);
    let document = render_json_from_presentation_for(&presentation);
    let states: Vec<String> = presentation
        .edges
        .iter()
        .map(|edge| match &edge.coverage {
            crate::discovery::caller_registry::UseCoverage::Unknown(reason) => {
                format!("unknown/{}", reason.code())
            }
            other => other.state().to_string(),
        })
        .collect();
    assert_eq!(
        states,
        [
            "counted",
            "witnessed",
            "watched_no_use",
            "unknown/loss",
            "watched_no_use",
            "unknown/not_admitted",
        ],
        "every coverage shape in one fixture"
    );

    // JSONL: every edge event carries the JSON edge verbatim.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut writer = crate::inventory_events::EventWriter::create(&path, 1 << 20, 5).unwrap();
    crate::inventory_events::emit_snapshot_as_events(&mut writer, &presentation, 1).unwrap();
    drop(writer);
    let body = std::fs::read_to_string(&path).unwrap();
    let edge_events: Vec<serde_json::Value> = body
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| line["event"].clone())
        .collect();
    let edges_json = document["edges"].as_array().unwrap();
    assert_eq!(edge_events.len(), edges_json.len());

    let snapshot = crate::inventory_present::render_snapshot(&presentation);
    let frame = frame_for(&presentation);
    let viewport = Viewport {
        width: 200,
        height: 120,
    };
    let summary = frame_text(&render_frame(&frame, viewport, &DashboardState::new()));
    let mut evidence_state = DashboardState::new();
    evidence_state.next_detail();
    assert_eq!(evidence_state.detail, DetailPage::Evidence);
    let evidence = frame_text(&render_frame(&frame, viewport, &evidence_state));
    for ((edge, edge_json), event) in presentation
        .edges
        .iter()
        .zip(edges_json.iter())
        .zip(edge_events.iter())
    {
        let name = format!("{}->{}", edge.caller.label(), edge.module.label());
        // JSONL == JSON, coverage included; the derived states agree.
        assert_eq!(event["entries"], edge_json["entries"], "{name}");
        assert_eq!(event["capture"], edge.capture.label(), "{name}");
        assert_eq!(event["activity"], edge.activity.label(), "{name}");
        let coverage = &edge_json["entries"]["coverage"];
        assert_eq!(coverage["state"], edge.coverage.state(), "{name}");
        // Snapshot and dashboard: one label, one compact count, one
        // activity — each derived from the same view.
        let label = crate::inventory_present::coverage_label(&edge.coverage);
        let line = snapshot
            .lines()
            .find(|line| {
                line.starts_with(&format!(
                    "edge {} -> {} ",
                    edge.caller.label(),
                    edge.module.label()
                ))
            })
            .unwrap();
        assert!(line.contains(&format!("coverage {label}")), "{line}");
        assert!(
            evidence.contains(&format!("coverage {label}")),
            "{name}: {evidence}"
        );
        // The edge's block: its identity line plus the indented item
        // lines under it.
        let lines: Vec<&str> = summary.lines().collect();
        let head = lines
            .iter()
            .position(|line| line.contains(&format!("-> {} (", edge.module.label())))
            .unwrap_or_else(|| panic!("{name} block: {summary}"));
        let block = lines[head..]
            .iter()
            .enumerate()
            .take_while(|(index, line)| *index == 0 || line.starts_with("  "))
            .map(|(_, line)| *line)
            .collect::<Vec<_>>()
            .join("\n");
        let display = crate::inventory_present::entries_display(edge);
        assert!(
            block.contains(&format!("entries {display}")),
            "{name}: {block}"
        );
        assert!(
            block.contains(&format!("activity {}", edge.activity.label())),
            "{name}: {block}"
        );
        assert!(
            block.contains(&format!("capture {}", edge.capture.label())),
            "{name}: {block}"
        );
        // Quiet only where it is a fact; armed only where covered.
        if edge.activity.label() == "quiet" {
            assert!(
                matches!(edge.coverage.state(), "watched_no_use" | "counted"),
                "{name}"
            );
        }
        if edge.capture.label() == "armed" {
            assert_ne!(edge.coverage.state(), "unknown", "{name}");
        }
        match edge.coverage.state() {
            "counted" => {
                assert_eq!(edge_json["entries"]["count"], 4);
                assert_eq!(display, "4");
                assert_eq!(coverage["since_ns"], at);
                assert_eq!(edge_json["entries"]["observation"], "observed");
            }
            "witnessed" => {
                assert_eq!(display, "?");
                assert_eq!(coverage["first_ns"], at);
                assert_eq!(edge.activity.label(), "used (recency unknown)");
            }
            "watched_no_use" => {
                assert_eq!(display, "0");
                assert_eq!(coverage["since_ns"], at2);
                assert_eq!(edge_json["entries"]["observation"], "observed");
            }
            _ => {
                assert_eq!(display, "?");
                assert_ne!(edge_json["entries"]["observation"], "observed");
                assert!(coverage["since_ns"].is_null() && coverage["first_ns"].is_null());
            }
        }
    }
    // The demotion keeps m3's interval unknown; m2's re-watch is a new
    // interval that starts after the regression, never inside it.
    assert_eq!(edges_json[3]["entries"]["coverage"]["reason"], "loss");
    assert_eq!(
        edges_json[3]["entries"]["coverage"]["detail"],
        "CALLER_EVIDENCE rose"
    );
    assert_eq!(edges_json[2]["entries"]["coverage"]["since_ns"], at2);
    assert!(edges_json[2]["entries"]["coverage"]["until_ns"].is_null());
}
