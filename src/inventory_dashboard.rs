//! SPDX-License-Identifier: GPL-3.0-or-later
//! U1 read-only dashboard: bounded views over unbounded captures.
//!
//! The renderer consumes IMMUTABLE [`Presentation`] snapshots through
//! a BOUNDED [`DisplayHandoff`] and never holds capture/coordinator
//! locks while writing the terminal. Redraws coalesce around 3 Hz
//! (the plan's 2–4 Hz band); dropping obsolete display frames is
//! acceptable, losing capture facts is not. Narrowing the VIEW
//! (scroll position) never narrows the totals shown.
//!
//! Read-only: scrolling and detail paging only — no
//! filtering/selection (U2), no capture control. ANSI stays on the
//! terminal stream; JSON paths
//! never see an escape byte. The log tail holds SANITIZED observer
//! diagnostics with explicit truncation accounting (bytes/lines
//! dropped shown, never silent). Small terminals degrade to a stated
//! minimal layout (never crash, never corrupt); Unicode/control
//! input renders safely via control-escaping plus display-cell
//! truncation.
//!
//! Hand-rolled ANSI handles scrolling and resize; unicode-width measures
//! display cells without adding a terminal widget framework.

use crate::inventory_present::Presentation;
use crate::render::escape_controls;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use unicode_width::UnicodeWidthStr;

/// Coalesced redraw cadence: ~3 Hz inside the plan's 2–4 Hz band.
pub(crate) const REDRAW_INTERVAL: Duration = Duration::from_millis(333);
/// Capture rescan cadence inside the dashboard loop.
pub(crate) const RESCAN_INTERVAL: Duration = Duration::from_secs(1);
/// Bounded handoff capacity in frames: latest-wins, size 1. A stalled
/// terminal sheds display frames here; capture never backpressures.
pub(crate) const HANDOFF_CAPACITY: usize = 1;
/// Full dashboard needs this width (exact state labels are wide) and
/// height; anything smaller degrades to the minimal summary layout.
pub(crate) const MIN_FULL_WIDTH: usize = 80;
pub(crate) const MIN_FULL_HEIGHT: usize = 14;
/// Bounded observer-log tail: at most this many lines / bytes.
pub(crate) const LOG_TAIL_MAX_LINES: usize = 100;
pub(crate) const LOG_TAIL_MAX_BYTES: usize = 8192;
/// One log line is capped here (overlong lines truncate with `…` and
/// the dropped bytes are accounted).
pub(crate) const LOG_LINE_MAX_CHARS: usize = 1024;
/// In-cell truncation marker.
pub(crate) const TRUNCATION_MARK: &str = "…";

/// Truncate to `width` display cells on a character boundary, marking
/// omitted content with `…`. Callers escape controls before layout.
pub(crate) fn truncate_cell(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.width() <= width {
        return text.to_string();
    }
    let mut kept = String::new();
    for ch in text.chars() {
        let previous = kept.len();
        kept.push(ch);
        if kept.width() > width - 1 {
            kept.truncate(previous);
            break;
        }
    }
    kept.push_str(TRUNCATION_MARK);
    kept
}

/// Producer-side bounded observer-log tail. Every push sanitizes
/// (control-escaping, so target-controlled bytes can never inject
/// terminal sequences) and every dropped line/byte is counted —
/// the frame header shows the counts, never silence.
pub(crate) struct LogTail {
    lines: VecDeque<String>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    dropped_lines: u64,
    dropped_bytes: u64,
}

impl LogTail {
    pub(crate) fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            bytes: 0,
            max_lines: max_lines.max(1),
            max_bytes: max_bytes.max(1),
            dropped_lines: 0,
            dropped_bytes: 0,
        }
    }

    pub(crate) fn bounded() -> Self {
        Self::new(LOG_TAIL_MAX_LINES, LOG_TAIL_MAX_BYTES)
    }

    /// Push one sanitized diagnostic line, evicting oldest-first past
    /// the bounds with exact accounting.
    pub(crate) fn push(&mut self, line: &str) {
        let clean = escape_controls(line).into_owned();
        let kept = truncate_cell(&clean, LOG_LINE_MAX_CHARS);
        if kept.len() < clean.len() {
            self.dropped_bytes = self
                .dropped_bytes
                .saturating_add((clean.len() - kept.len()) as u64);
        }
        self.bytes = self.bytes.saturating_add(kept.len());
        self.lines.push_back(kept);
        while self.lines.len() > self.max_lines || self.bytes > self.max_bytes {
            if let Some(evicted) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(evicted.len());
                self.dropped_lines = self.dropped_lines.saturating_add(1);
                self.dropped_bytes = self.dropped_bytes.saturating_add(evicted.len() as u64);
            } else {
                break;
            }
        }
    }

    pub(crate) fn snapshot(&self) -> LogSnapshot {
        LogSnapshot {
            lines: self.lines.iter().cloned().collect(),
            dropped_lines: self.dropped_lines,
            dropped_bytes: self.dropped_bytes,
        }
    }

    /// Dropped counters (tests pin the accounting; frames read them
    /// from the immutable [`LogSnapshot`]).
    #[cfg(test)]
    pub(crate) fn dropped_lines(&self) -> u64 {
        self.dropped_lines
    }

    #[cfg(test)]
    pub(crate) fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }
}

/// Immutable log-tail snapshot paired with a presentation frame.
#[derive(Debug, Clone)]
pub(crate) struct LogSnapshot {
    pub lines: Vec<String>,
    pub dropped_lines: u64,
    pub dropped_bytes: u64,
}

/// One display frame: an immutable presentation plus its paired log
/// tail. Both are immutable snapshots; the renderer never touches
/// capture state.
#[derive(Clone)]
pub(crate) struct DisplayFrame {
    pub presentation: Arc<Presentation>,
    pub log: LogSnapshot,
}

/// Bounded latest-wins handoff from capture to renderer. Capacity is
/// [`HANDOFF_CAPACITY`] (1): offering while a frame is unconsumed
/// drops the OBSOLETE frame (counted in `dropped_frames`) and keeps
/// the latest — a stalled terminal sheds display work, never
/// backpressures capture, and never loses a capture fact (facts live
/// in the coordinator/JSON, not in frames). The mutex guards only the
/// slot swap; neither side holds it across terminal I/O.
pub(crate) struct DisplayHandoff {
    slot: Mutex<VecDeque<DisplayFrame>>,
    offered: AtomicU64,
    dropped_frames: AtomicU64,
    consumed: AtomicU64,
}

impl DisplayHandoff {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(VecDeque::with_capacity(HANDOFF_CAPACITY)),
            offered: AtomicU64::new(0),
            dropped_frames: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
        }
    }

    /// The enforced bound (tests pin it behaviorally: offers past it
    /// shed oldest-first).
    #[cfg(test)]
    pub(crate) fn capacity() -> usize {
        HANDOFF_CAPACITY
    }

    /// Offer one frame; never blocks on the terminal. Past capacity,
    /// the oldest unconsumed frame sheds (counted) and the latest is
    /// kept — coalescing, not queueing.
    pub(crate) fn offer(&self, presentation: Arc<Presentation>, log: LogSnapshot) {
        let mut slot = self.slot.lock().expect("display handoff lock held");
        while slot.len() >= HANDOFF_CAPACITY {
            slot.pop_front();
            self.dropped_frames.fetch_add(1, Ordering::SeqCst);
        }
        slot.push_back(DisplayFrame { presentation, log });
        self.offered.fetch_add(1, Ordering::SeqCst);
    }

    /// Take the latest frame, if any (older queued frames shed with
    /// it — the renderer always shows the newest). Callers must
    /// release the handoff (this returns owned data) BEFORE writing
    /// the terminal.
    pub(crate) fn take(&self) -> Option<DisplayFrame> {
        let mut slot = self.slot.lock().expect("display handoff lock held");
        let mut frame = slot.pop_front()?;
        // Coalesce: skip to the newest queued frame.
        while let Some(newer) = slot.pop_front() {
            self.dropped_frames.fetch_add(1, Ordering::SeqCst);
            frame = newer;
        }
        self.consumed.fetch_add(1, Ordering::SeqCst);
        Some(frame)
    }

    pub(crate) fn offered(&self) -> u64 {
        self.offered.load(Ordering::SeqCst)
    }

    pub(crate) fn dropped_frames(&self) -> u64 {
        self.dropped_frames.load(Ordering::SeqCst)
    }

    pub(crate) fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::SeqCst)
    }
}

impl Default for DisplayHandoff {
    fn default() -> Self {
        Self::new()
    }
}

/// Terminal size in chars. Originates from `TIOCGWINSZ` on the live
/// terminal (re-queried every frame, so resizes apply at the next
/// redraw) or constructed directly in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Viewport {
    pub width: usize,
    pub height: usize,
}

impl Viewport {
    /// Query the terminal size; `None` when the fd is not a terminal
    /// or reports a degenerate size (callers then degrade, never
    /// guess).
    pub(crate) fn from_fd(fd: std::os::fd::RawFd) -> Option<Self> {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } != 0 {
            return None;
        }
        if size.ws_col == 0 || size.ws_row == 0 {
            return None;
        }
        Some(Self {
            width: size.ws_col as usize,
            height: size.ws_row as usize,
        })
    }
}

/// Read-only detail page (F6): which bounded view the edge window
/// shows. Paging is view navigation like scrolling — every page
/// covers all of its items, with no selection or filtering (U2).
/// Tight viewports that shave summary detail keep every fact
/// reachable: evidence counters on the evidence page, gap rows (and
/// the gaps that name no edge) on the gaps page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum DetailPage {
    /// Per-edge summary blocks (identities, states, mechanisms,
    /// operations, riding gaps) with adaptive detail budgets.
    #[default]
    Summary,
    /// Per-edge usage coverage plus the operation-evidence counters
    /// (all nine per observed edge; the bare semantic label
    /// otherwise).
    Evidence,
    /// The coverage ledger: every gap with its caller/module
    /// attribution, including gaps that ride no edge block.
    Gaps,
}

impl DetailPage {
    /// The header tag naming the page (`[summary]` …).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Evidence => "evidence",
            Self::Gaps => "gaps",
        }
    }
}

/// Read-only view state: the scroll position and the detail page.
/// There is no filtering/selection (U2) and no capture control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DashboardState {
    /// Index of the first visible item (edge or gap, per page).
    pub scroll: usize,
    /// Which detail page the window shows.
    pub detail: DetailPage,
    /// Wrapped body-line offset within the scrolled-to gap record
    /// (F6d): tall gap records span frames on the gaps page, one
    /// body line per Down key, before scrolling advances to the
    /// next record. Meaningless (always zero) off the gaps page.
    pub gap_line: usize,
}

impl DashboardState {
    pub(crate) fn new() -> Self {
        Self {
            scroll: 0,
            detail: DetailPage::Summary,
            gap_line: 0,
        }
    }

    /// Items the current page scrolls over: edges, or gaps on the
    /// gaps page.
    pub(crate) fn items_total(&self, presentation: &Presentation) -> usize {
        match self.detail {
            DetailPage::Gaps => presentation.gaps.len(),
            DetailPage::Summary | DetailPage::Evidence => presentation.edges.len(),
        }
    }

    /// Cycle summary → evidence → gaps → summary (the Tab key).
    /// Callers clamp the scroll to the new page's total. The
    /// within-record offset resets: it belongs to one gaps-page
    /// record, never to a page switch.
    pub(crate) fn next_detail(&mut self) {
        self.detail = match self.detail {
            DetailPage::Summary => DetailPage::Evidence,
            DetailPage::Evidence => DetailPage::Gaps,
            DetailPage::Gaps => DetailPage::Summary,
        };
        self.gap_line = 0;
    }

    pub(crate) fn scroll_down(&mut self, total_items: usize) {
        self.scroll = self
            .scroll
            .saturating_add(1)
            .min(total_items.saturating_sub(1));
    }

    pub(crate) fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub(crate) fn clamp(&mut self, total_items: usize) {
        self.scroll = self.scroll.min(total_items.saturating_sub(1));
    }

    /// Clamp the scroll to the CURRENT page's item total (F6c): the
    /// gaps page scrolls over gaps, not edges. Every production
    /// clamp (key-driven page switches, redraws) funnels through
    /// here so a redraw can never drag a gaps-page scroll back to
    /// the edge count and strand later gaps.
    pub(crate) fn clamp_to_presentation(&mut self, presentation: &Presentation) {
        self.clamp(self.items_total(presentation));
    }

    /// Gaps-page Down (F6d): step one wrapped body line deeper into
    /// the scrolled-to record while it has lines below the offset,
    /// else advance to the next record. Line steps can never skip
    /// a line (the renderer shows a multi-line slice per frame),
    /// so repeated Down exposes every line of every record. The
    /// body length comes from the SAME block construction the
    /// renderer uses, at the live viewport width, so paging and
    /// rendering can never disagree about record boundaries.
    pub(crate) fn scroll_gaps_down(&mut self, presentation: &Presentation, width: usize) {
        let total = presentation.gaps.len();
        if total == 0 {
            self.scroll = 0;
            self.gap_line = 0;
            return;
        }
        // A rescan may have shrunk the ledger under the scroll.
        self.scroll = self.scroll.min(total - 1);
        let body_lines =
            gap_block_lines(&presentation.gaps[self.scroll], self.scroll, total, width)
                .len()
                .saturating_sub(1);
        if self.gap_line + 1 < body_lines {
            self.gap_line += 1;
        } else if self.scroll + 1 < total {
            self.scroll += 1;
            self.gap_line = 0;
        }
        // Else the last line of the last record: stay (bottom).
    }

    /// Gaps-page Up (F6d): step one wrapped body line back toward
    /// the record head, else to the previous record. Width-free:
    /// stepping back can never overshoot line zero.
    pub(crate) fn scroll_gaps_up(&mut self) {
        if self.gap_line > 0 {
            self.gap_line -= 1;
        } else {
            self.scroll_up();
        }
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

/// Render one full dashboard frame as ANSI bytes: cursor-home plus
/// content lines, each cleared to end-of-line so shorter redraws
/// never leave ghosts. Pure function of (frame, viewport, state):
/// the same inputs render the same bytes, byte for byte. Monochrome
/// (cursor/clear only, no SGR colors) by U1 design.
///
/// Layout (full, `width >= 80`, `height >= 14`): 3-line header with
/// FULL totals plus coverage (gap/refusal/suppressed counts visible
/// without scrolling on 80×24), a scrollable edge table in whole
/// edge blocks, a bounded log tail, and a footer naming the view
/// window. Scrolling narrows only the visible window; every total
/// still covers the whole capture. Small terminals get the stated
/// compact window instead (totals, coverage and scrollable associations) — never a crash, never corruption.
pub(crate) fn render_frame(
    frame: &DisplayFrame,
    viewport: Viewport,
    state: &DashboardState,
) -> Vec<u8> {
    let width = viewport.width.max(1);
    let height = viewport.height.max(1);
    let mut lines = if width < MIN_FULL_WIDTH || height < MIN_FULL_HEIGHT {
        render_minimal(frame, width, height, state)
    } else {
        render_full(frame, width, height, state)
    };
    // Full repaints only: pad short frames so every row is rewritten
    // (a shorter redraw must never leave a previous taller frame's
    // rows stale on screen).
    while lines.len() < height {
        lines.push(String::new());
    }
    let mut out = Vec::with_capacity(lines.iter().map(|line| line.len() + 8).sum());
    out.extend_from_slice(b"\x1b[H");
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\x1b[K");
    }
    out
}

/// Compact terminals prioritize identifiable associations over observer logs.
/// Below the useful window size, only bounded totals and coverage remain.
fn render_minimal(
    frame: &DisplayFrame,
    width: usize,
    height: usize,
    state: &DashboardState,
) -> Vec<String> {
    let presentation = frame.presentation.as_ref();
    let budgets = &presentation.budgets;
    let coverage = if frame.log.dropped_lines > 0 || frame.log.dropped_bytes > 0 {
        format!(
            "coverage: {}g {}r {}s; dropped {}L {}B",
            presentation.gaps.len(),
            budgets.refusals(),
            presentation.gaps_suppressed,
            frame.log.dropped_lines,
            frame.log.dropped_bytes,
        )
    } else {
        format!(
            "coverage: {} gaps {} refusals {} suppressed",
            presentation.gaps.len(),
            budgets.refusals(),
            presentation.gaps_suppressed,
        )
    };
    let mut lines = vec![
        truncate_cell(
            &format!("p11scope inventory {} (minimal)", presentation.scope_label),
            width,
        ),
        truncate_cell(
            &format!(
                "totals: {} callers {} modules {} edges",
                presentation.callers.len(),
                presentation.modules.len(),
                presentation.edges.len()
            ),
            width,
        ),
        truncate_cell(&coverage, width),
    ];
    if width >= 30 && height >= 8 {
        let total = state.items_total(presentation);
        let scroll = state.scroll.min(total.saturating_sub(1));
        let room = height.saturating_sub(4);
        let (mut window, shown) = match state.detail {
            DetailPage::Summary => render_compact_edge_window(presentation, width, room, scroll),
            DetailPage::Evidence => render_edge_window(presentation, width, room, scroll, true),
            DetailPage::Gaps => {
                render_gap_window(presentation, width, room, scroll, state.gap_line)
            }
        };
        let (first, last) = visible_item_range(shown, total, scroll);
        lines.append(&mut window);
        while lines.len() < height - 1 {
            lines.push(String::new());
        }
        let offset = if state.detail == DetailPage::Gaps {
            presentation.gaps.get(scroll).map_or(0, |gap| {
                effective_gap_line(gap, scroll, total, width, state.gap_line)
            })
        } else {
            0
        };
        let continuation = if offset > 0 {
            format!(" +{offset}")
        } else {
            String::new()
        };
        lines.push(truncate_cell(
            &format!(
                "{} {first}-{last}/{total}{continuation} | j/k tab q quit",
                state.detail.label()
            ),
            width,
        ));
    } else {
        lines.push(truncate_cell(
            "enlarge terminal for associations | q quit",
            width,
        ));
    }
    lines.truncate(height);
    lines
}

/// Three lines per complete association, with directional markers when room
/// permits. Visible ranges derive from emitted blocks, never from total rows.
fn render_compact_edge_window(
    presentation: &Presentation,
    width: usize,
    room: usize,
    scroll: usize,
) -> (Vec<String>, usize) {
    let total = presentation.edges.len();
    if total == 0 {
        return (vec![truncate_cell("(no edges captured)", width)], 0);
    }
    let scroll = scroll.min(total - 1);
    let mut lines = Vec::new();
    // At height 8, an above marker takes the one spare line. Markers must
    // never displace the first complete association.
    if scroll > 0 && room >= 4 {
        lines.push(truncate_cell(&format!("^ +{scroll} more above"), width));
    }
    let mut shown = 0;
    for edge in presentation.edges.iter().skip(scroll) {
        if room.saturating_sub(lines.len()) < 3 {
            break;
        }
        lines.push(identity_cell(
            "application ",
            &crate::inventory_present::application_label(presentation, edge.caller),
            &edge.caller.label(),
            width,
        ));
        lines.push(identity_cell(
            "module ",
            &crate::inventory_present::module_label(presentation, edge.module),
            &edge.module.label(),
            width,
        ));
        lines.push(truncate_cell(
            &crate::inventory_present::observation_label(edge),
            width,
        ));
        shown += 1;
        let below = total - scroll - shown;
        if below > 0 && room.saturating_sub(lines.len()) < 4 {
            if lines.len() < room {
                lines.push(truncate_cell(&format!("v +{below} more below"), width));
            }
            break;
        }
    }
    if shown == 0 {
        return (
            vec![truncate_cell("(no edges fit; enlarge terminal)", width)],
            0,
        );
    }
    (lines, shown)
}

fn render_full(
    frame: &DisplayFrame,
    width: usize,
    height: usize,
    state: &DashboardState,
) -> Vec<String> {
    let presentation = frame.presentation.as_ref();
    let budgets = &presentation.budgets;
    let total = state.items_total(presentation);
    let scroll = state.scroll.min(total.saturating_sub(1));
    let mut lines = vec![
        truncate_cell(
            &format!(
                "p11scope inventory {} | {} passes | {} callers {} modules {} edges",
                presentation.scope_label,
                presentation.passes,
                presentation.callers.len(),
                presentation.modules.len(),
                presentation.edges.len(),
            ),
            width,
        ),
        truncate_cell(
            &format!(
                "coverage: {} gaps {} refusals {} suppressed | endpoints {}/{} | attach {}/{} | semantic {} ({} held, {} unknown, {} refused)",
                presentation.gaps.len(),
                budgets.refusals(),
                presentation.gaps_suppressed,
                budgets.endpoints_occupied,
                budgets.endpoints_limit,
                budgets.inventory_endpoints_occupied,
                budgets.inventory_endpoints_limit,
                crate::inventory_present::semantic_status(budgets),
                budgets.semantic_occupied,
                budgets.semantic_unknown_edges,
                budgets.semantic_refused,
            ),
            width,
        ),
        truncate_cell(
            &format!(
                "budgets: callers {}/{} refused {} | modules {}/{} refused {} | edges {}/{} refused {} | counters observed {} saturated {} | retained {}/{} suppressed {}",
                budgets.callers_occupied,
                budgets.callers_limit,
                budgets.callers_refused,
                budgets.modules_occupied,
                budgets.modules_limit,
                budgets.modules_refused,
                budgets.edges_occupied,
                budgets.edges_limit,
                budgets.edges_refused,
                budgets.counters_observed,
                budgets.counters_saturated,
                budgets.retained,
                budgets.retained_limit,
                budgets.retained_suppressed,
            ),
            width,
        ),
    ];
    let edge_room = detail_room(height);
    let log_rows = detail_log_rows(height);
    let kind = match state.detail {
        DetailPage::Gaps => "gaps",
        DetailPage::Summary | DetailPage::Evidence => "edges",
    };
    let (mut edge_lines, shown) = match state.detail {
        DetailPage::Summary => render_edge_window(presentation, width, edge_room, scroll, false),
        DetailPage::Evidence => render_edge_window(presentation, width, edge_room, scroll, true),
        DetailPage::Gaps => {
            render_gap_window(presentation, width, edge_room, scroll, state.gap_line)
        }
    };
    let (first, last) = visible_item_range(shown, total, scroll);
    lines.push(truncate_cell(
        &format!("--- {kind} {first}-{last} of {total} [{}] (scroll narrows this view only; totals above cover everything) ---", state.detail.label()),
        width,
    ));
    lines.append(&mut edge_lines);
    // Pad a short window so the log tail + footer stay pinned to the
    // bottom rows regardless of content.
    while lines.len() < 3 + 1 + edge_room {
        lines.push(String::new());
    }
    let log_header = if frame.log.dropped_lines > 0 || frame.log.dropped_bytes > 0 {
        format!(
            "--- observer log (last {}; +{} dropped lines, +{} dropped bytes) ---",
            frame.log.lines.len().min(log_rows),
            frame.log.dropped_lines,
            frame.log.dropped_bytes
        )
    } else {
        format!(
            "--- observer log (last {}) ---",
            frame.log.lines.len().min(log_rows)
        )
    };
    lines.push(truncate_cell(&log_header, width));
    let tail: Vec<String> = frame
        .log
        .lines
        .iter()
        .rev()
        .take(log_rows)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|line| truncate_cell(line, width))
        .collect();
    // Pad short tails so the footer stays on the last row.
    for _ in tail.len()..log_rows {
        lines.push(String::new());
    }
    lines.extend(tail);
    let max_scroll = total.saturating_sub(1);
    // Within-record paging (F6d) names its line offset: two frames
    // mid-record would otherwise carry identical footers. The footer
    // names the EFFECTIVE offset (F6e) — the stored offset clamped
    // to the record's wrapped body at the live width, the SAME clamp
    // the continuation head uses — so a stale offset (a resize, or a
    // rescan that shrank the record) can never disagree with the
    // head. A clamp to zero drops the suffix: the head is plain.
    let gap_offset = if state.detail == DetailPage::Gaps && state.gap_line > 0 {
        presentation.gaps.get(scroll).map_or(0, |gap| {
            effective_gap_line(gap, scroll, total, width, state.gap_line)
        })
    } else {
        0
    };
    let position = if gap_offset > 0 {
        format!("scroll {scroll}/{max_scroll} line +{gap_offset}")
    } else {
        format!("scroll {scroll}/{max_scroll}")
    };
    lines.push(truncate_cell(
        &format!("{position} | showing {kind} {first}-{last} of {total} | j/k scroll, tab details, q quit"),
        width,
    ));
    lines.truncate(height);
    lines
}

/// Observer-log rows for a full-layout height: the log adapts to
/// short terminals and the detail window takes the rest. At the
/// minimal full height (14) the log yields its second row so the
/// window keeps a 5-row middle budget: one observed edge (identity,
/// states, counts, operations) plus both scroll markers. The log
/// still shows its latest line and the drop counts below.
fn detail_log_rows(height: usize) -> usize {
    if height >= 20 {
        4
    } else if height >= 15 {
        2
    } else {
        1
    }
}

/// Detail-window rows for a full-layout height: header (3) +
/// table header (1) + log header (1) + log rows + footer (1) come
/// off the top, at least two rows remain. Full layout needs
/// height >= 14, so production rooms are always >= 7.
fn detail_room(height: usize) -> usize {
    height
        .saturating_sub(3 + 1 + 1 + detail_log_rows(height) + 1)
        .max(2)
}

/// Per-edge detail budget: how much of an edge's expandable detail
/// (mechanism rows, evidence counters, gap rows) its block may show.
/// [`fit_edge_block`] shaves this budget stage by stage until the
/// block fits the window's remaining room — every hidden fact stays
/// explicitly counted by a marker, never silently dropped.
#[derive(Debug, Clone, Copy)]
struct BlockBudget {
    /// Mechanism rows shown (of the edge's total; the rest collapse
    /// into the `+N more mechs` marker).
    mech_rows: usize,
    /// Whether the nine `ev …` counters render (else an
    /// `evidence +N hidden` marker counts them).
    show_evidence: bool,
    /// Whether riding gap rows render (else a `gaps +N hidden`
    /// marker counts them).
    show_gaps: bool,
    /// Secondary retained PID/incarnation/lifecycle; the evidence page always
    /// carries these when a tight summary yields their rows.
    show_identity: bool,
}

/// Render the visible edge window as whole edge blocks: `^ +K more
/// above` when scrolled, then blocks, then `v +M more below` when the
/// room runs out. Every block carries full exact state labels (items
/// wrap on ` | ` boundaries, never mid-label); summary expandable
/// detail shaves to the remaining room via [`fit_edge_block`], so a
/// short viewport narrows detail — always with explicit markers —
/// instead of rejecting whole edges. The evidence page renders the
/// compact counter blocks instead (shaved summary facts stay
/// reachable there).
/// Returns the window lines plus the count of edge blocks actually
/// emitted (the header range derives from this count, never from
/// re-parsing rendered text).
fn render_edge_window(
    presentation: &Presentation,
    width: usize,
    room: usize,
    scroll: usize,
    evidence: bool,
) -> (Vec<String>, usize) {
    let total = presentation.edges.len();
    let mut lines = Vec::new();
    if total == 0 {
        lines.push(truncate_cell("(no edges captured)", width));
        return (lines, 0);
    }
    let above = scroll.min(total);
    if above > 0 {
        lines.push(truncate_cell(&format!("^ +{above} more above"), width));
    }
    let mut shown = 0;
    for edge in presentation.edges.iter().skip(scroll) {
        let remaining_after = total - scroll - shown - 1;
        // Reserve one line for the `more below` marker when edges
        // remain after this block.
        let reserve = usize::from(remaining_after > 0);
        let budget = room.saturating_sub(lines.len() + reserve);
        let block = if evidence {
            fit_evidence_block(presentation, edge, width, budget)
        } else {
            fit_edge_block(presentation, edge, width, budget)
        };
        let Some(block) = block else {
            break;
        };
        shown += 1;
        lines.extend(block);
    }
    if shown == 0 {
        // Nothing fits at this scroll position (tight room, tall
        // minimal blocks): say so honestly instead of showing bare
        // markers under a range that claims an edge. The footer keeps
        // the scroll position, so this line can never strand a reader.
        return (
            vec![truncate_cell(
                "(no edges fit here; scroll or enlarge the terminal)",
                width,
            )],
            0,
        );
    }
    let hidden_below = total.saturating_sub(scroll + shown);
    if hidden_below > 0 {
        // The reservation above guarantees this fits.
        if lines.len() < room {
            lines.push(truncate_cell(
                &format!("v +{hidden_below} more below (scroll down)"),
                width,
            ));
        }
    }
    (lines, shown)
}

/// Render the visible gaps window as whole gap blocks over the
/// coverage ledger: every gap in presentation order with its
/// caller/module attribution. Same packing and honesty rules as
/// [`render_edge_window`]: directional markers, whole blocks only,
/// and an honest line when nothing fits or no gap exists — except
/// the FIRST visible record, which pages within itself (F6d): when
/// its wrapped block exceeds the budget, or the state holds a
/// within-record offset, the window shows the head (or an explicit
/// continuation head) plus a body slice with an explicit
/// continuation marker, consuming the window for that frame. Tall
/// records thus span frames instead of vanishing behind "no gaps
/// fit", and every line stays reachable by repeated Down.
fn render_gap_window(
    presentation: &Presentation,
    width: usize,
    room: usize,
    scroll: usize,
    gap_line: usize,
) -> (Vec<String>, usize) {
    let total = presentation.gaps.len();
    let mut lines = Vec::new();
    if total == 0 {
        lines.push(truncate_cell("(no coverage gaps)", width));
        return (lines, 0);
    }
    let above = scroll.min(total);
    if above > 0 {
        lines.push(truncate_cell(&format!("^ +{above} more above"), width));
    }
    let mut shown = 0;
    let mut first = true;
    for (index, gap) in presentation.gaps.iter().enumerate().skip(scroll) {
        let remaining_after = total - scroll - shown - 1;
        // Reserve one line for the `more below` marker when gaps
        // remain after this block.
        let reserve = usize::from(remaining_after > 0);
        let budget = room.saturating_sub(lines.len() + reserve);
        if first {
            first = false;
            // A paged record consumes the window: the next frame (or
            // the next record) comes from scrolling. Only a record
            // shown whole lets later records pack behind it.
            match render_first_gap_record(&mut lines, gap, index, total, width, budget, gap_line) {
                FirstGapOutcome::Whole => {
                    shown += 1;
                }
                FirstGapOutcome::Paged => {
                    shown += 1;
                    break;
                }
                FirstGapOutcome::Unshown => break,
            }
            continue;
        }
        let Some(block) = fit_gap_block(gap, index, total, width, budget) else {
            break;
        };
        shown += 1;
        lines.extend(block);
    }
    if shown == 0 {
        return (
            vec![truncate_cell(
                "(no gaps fit here; scroll or enlarge the terminal)",
                width,
            )],
            0,
        );
    }
    let hidden_below = total.saturating_sub(scroll + shown);
    if hidden_below > 0 {
        // The reservation above guarantees this fits.
        if lines.len() < room {
            lines.push(truncate_cell(
                &format!("v +{hidden_below} more below (scroll down)"),
                width,
            ));
        }
    }
    (lines, shown)
}

/// Render one edge's block within `budget` rows, shaving expandable
/// detail until it fits: mechanism rows shrink 8→0 first (the longest,
/// least dense rows), then evidence hides, then gaps hide — each
/// stage with explicit markers. Secondary identity yields last to the
/// evidence page. `None` when even the established minimal block
/// (identity, states, counts, operations, markers) exceeds the budget;
/// the window then stops honestly instead of cropping a block.
/// The full-detail stage renders first, so roomy viewports pay
/// exactly one render; only tight rooms walk the shave stages.
fn fit_edge_block(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
    budget: usize,
) -> Option<Vec<String>> {
    let full = BlockBudget {
        mech_rows: DASHBOARD_MAX_MECHS,
        show_evidence: true,
        show_gaps: true,
        show_identity: true,
    };
    let block = render_edge_block(presentation, edge, width, full);
    if block.len() <= budget {
        return Some(block);
    }
    for mech_rows in (0..DASHBOARD_MAX_MECHS).rev() {
        let stage = BlockBudget {
            mech_rows,
            show_evidence: true,
            show_gaps: true,
            show_identity: true,
        };
        let block = render_edge_block(presentation, edge, width, stage);
        if block.len() <= budget {
            return Some(block);
        }
    }
    for (show_evidence, show_gaps) in [(false, true), (false, false)] {
        let stage = BlockBudget {
            mech_rows: 0,
            show_evidence,
            show_gaps,
            show_identity: true,
        };
        let block = render_edge_block(presentation, edge, width, stage);
        if block.len() <= budget {
            return Some(block);
        }
    }
    // New secondary identity details must not increase the established
    // minimum whole-edge summary block. They remain on the evidence page.
    let compact = BlockBudget {
        mech_rows: 0,
        show_evidence: false,
        show_gaps: false,
        show_identity: false,
    };
    let block = render_edge_block(presentation, edge, width, compact);
    (block.len() <= budget).then_some(block)
}

/// Dashboard mechanism facts: the count plus one item per mechanism
/// (bounded by the block budget — full detail shows
/// [`DASHBOARD_MAX_MECHS`], tight rooms shave toward zero — with an
/// explicit `+N more mechs` marker past the shown rows: bounded,
/// never silent). Each shown mech mirrors its snapshot segment —
/// verbatim id, name, operation categories, counts, recency,
/// provenance — so every dashboard edge's facts compare against its
/// JSON edge (F6/C1).
pub(crate) const DASHBOARD_MAX_MECHS: usize = 8;

fn semantic_mech_items(
    mechanisms: &[crate::inventory_present::MechanismView],
    mech_rows: usize,
) -> Vec<String> {
    let mut items = vec![if mechanisms.is_empty() {
        "mechs 0: none".to_string()
    } else {
        format!("mechs {}", mechanisms.len())
    }];
    for mech in mechanisms.iter().take(mech_rows) {
        let id = match mech.name {
            Some(name) => format!("{name}/0x{:x}", mech.id),
            None => format!("0x{:x}", mech.id),
        };
        let by = escape_controls(&mech.functions.join(",")).into_owned();
        let rv = mech
            .returns
            .iter()
            .map(|rv| format!("0x{rv:x}"))
            .collect::<Vec<_>>()
            .join(",");
        items.push(format!(
            "mech [{id} {} calls={} errors={} last={} by=[{by}] rv=[{rv}]{}]",
            mech.operations.join(","),
            mech.calls,
            mech.errors,
            mech.last_seen_ns,
            if mech.truncated { " truncated" } else { "" },
        ));
    }
    let hidden = mechanisms.len().saturating_sub(mech_rows);
    if hidden > 0 {
        items.push(format!("+{hidden} more mechs"));
    }
    items
}

/// The nine operation-evidence counters as compact `ev {short}={n}`
/// items — one item per counter so narrow viewports wrap instead of
/// truncating. Short keys (legend; full JSON key → dashboard key):
/// `state_reconciliations` → `reconc`,
/// `session_cancel_ambiguities` → `cancel_amb`,
/// `session_cancel_unknown_flags` → `cancel_flags`,
/// `operation_state_imports` → `op_imports`,
/// `auth_state_ambiguities` → `auth_amb`,
/// `semantic_capture_failures` → `cap_fail`,
/// `async_duplicates` → `async_dup`,
/// `async_evictions` → `async_evict`,
/// `unmatched_closes` → `unmatch_close`.
fn evidence_items(operations: &crate::inventory_present::OperationsView) -> Vec<String> {
    let evidence = operations.evidence;
    [
        ("reconc", evidence.state_reconciliations),
        ("cancel_amb", evidence.session_cancel_ambiguities),
        ("cancel_flags", evidence.session_cancel_unknown_flags),
        ("op_imports", evidence.operation_state_imports),
        ("auth_amb", evidence.auth_state_ambiguities),
        ("cap_fail", evidence.semantic_capture_failures),
        ("async_dup", evidence.async_duplicates),
        ("async_evict", evidence.async_evictions),
        ("unmatch_close", evidence.unmatched_closes),
    ]
    .iter()
    .map(|(short, value)| format!("ev {short}={value}"))
    .collect()
}

/// Gaps that name this edge: global gaps (no caller/module) ride
/// every block, caller gaps ride their caller's blocks, and
/// module-qualified gaps ride exactly their edge. Coverage holes are
/// edge-relevant regardless of semantic state, so unknown edges show
/// them too — the bare semantic label stays bare; gaps are coverage
/// rows, not semantic detail.
fn riding_gaps<'a>(
    presentation: &'a Presentation,
    edge: &crate::inventory_present::EdgeView,
) -> Vec<&'a crate::inventory_present::GapView> {
    presentation
        .gaps
        .iter()
        .filter(|gap| {
            gap.caller.is_none_or(|caller| caller == edge.caller)
                && gap.module.is_none_or(|module| module == edge.module)
        })
        .collect()
}

/// One gap as its snapshot line verbatim (`gap [{subject}] {reason}`
/// plus the budget clause when the gap records a refusal),
/// control-escaped for the terminal.
fn gap_item(gap: &crate::inventory_present::GapView) -> String {
    let subject = escape_controls(&gap.subject);
    let reason = escape_controls(&gap.reason);
    match gap.budget {
        Some(refusal) => format!(
            "gap [{subject}] {reason} (budget {}: limit {}, requested {})",
            refusal.resource, refusal.limit, refusal.requested,
        ),
        None => format!("gap [{subject}] {reason}"),
    }
}

/// Reserve the physical reference before truncating its independent label.
fn identity_cell(prefix: &str, label: &str, id: &str, width: usize) -> String {
    let suffix = format!(" [{id}]");
    let label_width = width.saturating_sub(suffix.width());
    let text = truncate_cell(&format!("{prefix}{label}"), label_width);
    truncate_cell(&format!("{text}{suffix}"), width)
}

/// Independently budget the application and module around the arrow.
fn edge_identity_line(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
) -> String {
    let separator = " -> ";
    let available = width.saturating_sub(separator.width());
    let app_width = available / 2;
    let module_width = available - app_width;
    let app = identity_cell(
        "",
        &crate::inventory_present::application_label(presentation, edge.caller),
        &edge.caller.label(),
        app_width,
    );
    let module = identity_cell(
        "",
        &crate::inventory_present::module_label(presentation, edge.module),
        &edge.module.label(),
        module_width,
    );
    truncate_cell(&format!("{app}{separator}{module}"), width)
}

/// Retained identity details only; a dangling ID never borrows a current PID.
fn secondary_identity_items(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
) -> Vec<String> {
    let Ok(index) = presentation
        .callers
        .binary_search_by_key(&edge.caller, |caller| caller.id)
    else {
        return Vec::new();
    };
    let caller = &presentation.callers[index];
    let mut items = vec![format!(
        "pid {} incarnation {}",
        caller.pid, caller.incarnation
    )];
    if let Some(lifecycle) = crate::inventory_present::caller_lifecycle_label(caller) {
        items.push(lifecycle.into());
    }
    items
}

/// Greedy wrap on item boundaries; no item is split mid-label.
/// Overlong single items truncate with the cell marker (gap text
/// that must survive whole uses [`wrap_words`] on the gaps page).
fn wrap_items(width: usize, items: &[String]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::from("  ");
    for item in items {
        let piece = if current.len() > 2 {
            format!(" | {item}")
        } else {
            item.clone()
        };
        if current.width() + piece.width() <= width {
            current.push_str(&piece);
        } else {
            if current.len() > 2 {
                lines.push(truncate_cell(&current, width));
            }
            current = format!("  {item}");
            if current.width() > width {
                lines.push(truncate_cell(&current, width));
                current = String::from("  ");
            }
        }
    }
    if current.len() > 2 {
        lines.push(truncate_cell(&current, width));
    }
    lines
}

/// One edge as an identity line plus wrapped exact state items.
/// Item order is stable: base states, mechanism facts, evidence
/// counters, riding gaps, operation aggregates, active machines.
/// Expandable detail (mech rows, evidence, gaps) follows `budget`;
/// hidden detail counts itself in a marker in the same slot its rows
/// would occupy, so shaved blocks pack like full ones.
fn render_edge_block(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
    budget: BlockBudget,
) -> Vec<String> {
    let mut lines = vec![edge_identity_line(presentation, edge, width)];
    let mut items = vec![
        format!("mapping {}", edge.mapping.label()),
        format!("presence {}", edge.presence.label()),
        format!("capture {}", edge.capture.label()),
        format!("activity {}", edge.activity.label()),
        // `?` where the count is not a fact; the full coverage label
        // (state, instant, reason) is on the evidence page, so the
        // summary block keeps its 80x14 fit.
        format!(
            "entries {}",
            crate::inventory_present::entries_display(edge)
        ),
        format!("semantics {}", edge.semantics.label),
    ];
    if let Some(operations) = edge.semantics.operations.as_ref() {
        items.extend(semantic_mech_items(
            &edge.semantics.mechanisms,
            budget.mech_rows,
        ));
        let evidence = evidence_items(operations);
        if budget.show_evidence {
            items.extend(evidence);
        } else {
            items.push(format!("evidence +{} hidden", evidence.len()));
        }
    }
    let riding = riding_gaps(presentation, edge);
    if budget.show_gaps {
        items.extend(riding.iter().map(|gap| gap_item(gap)));
    } else if !riding.is_empty() {
        items.push(format!("gaps +{} hidden", riding.len()));
    }
    if let Some(operations) = edge.semantics.operations.as_ref() {
        // Two items (not one long line) so 80-column viewports wrap
        // instead of truncating; each label names its own counter.
        items.push(format!(
            "ops calls={} started={} completed={} cancelled={}",
            operations.calls, operations.started, operations.completed, operations.cancelled,
        ));
        items.push(format!(
            "ops failed={} unknown={} orphans={} dropped={} last={}",
            operations.failed,
            operations.unknown,
            operations.orphans,
            operations.dropped,
            operations.last_seen_ns,
        ));
        let active = if operations.active.is_empty() {
            "active none".to_string()
        } else {
            format!(
                "active {}",
                operations
                    .active
                    .iter()
                    .map(|op| format!("{}:{}x{}", op.category, op.state, op.count))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        items.push(active);
    }
    if budget.show_identity {
        items.extend(secondary_identity_items(presentation, edge));
    }
    lines.extend(wrap_items(width, &items));
    lines
}

/// One edge's evidence block: the identity line, the edge's usage
/// coverage (state, instant, reason — the summary page shows only the
/// compact `entries` form), plus all nine operation-evidence counters
/// (or the bare semantic label when the edge holds no operations).
/// Operation aggregates stay on the summary page, which already shows
/// them at 80x14 — this page answers the counters alone, so its blocks
/// fit tight rooms.
fn render_evidence_block(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
) -> Vec<String> {
    let mut lines = vec![edge_identity_line(presentation, edge, width)];
    let mut items = vec![coverage_item(edge)];
    match edge.semantics.operations.as_ref() {
        Some(operations) => items.extend(evidence_items(operations)),
        None => items.push(format!("semantics {}", edge.semantics.label)),
    }
    items.extend(secondary_identity_items(presentation, edge));
    lines.extend(wrap_items(width, &items));
    lines
}

/// The edge's coverage item (`coverage <label>`), control-escaped: a
/// loss reason may carry producer text.
pub(crate) fn coverage_item(edge: &crate::inventory_present::EdgeView) -> String {
    format!(
        "coverage {}",
        escape_controls(&crate::inventory_present::coverage_label(&edge.coverage))
    )
}

/// One evidence block within `budget` rows, or `None` when even the
/// compact block exceeds it (the window then stops honestly instead
/// of cropping a block).
fn fit_evidence_block(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
    budget: usize,
) -> Option<Vec<String>> {
    let block = render_evidence_block(presentation, edge, width);
    (block.len() <= budget).then_some(block)
}

/// Greedy word-wrap for gap text in display cells; overlong words split
/// on character boundaries. A glyph too wide for the viewport is marked.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    let push_word = |lines: &mut Vec<String>, current: &mut String, word: &str| {
        if current.is_empty() {
            current.push_str(word);
            return;
        }
        if current.width() + 1 + word.width() <= width {
            current.push(' ');
            current.push_str(word);
            return;
        }
        lines.push(std::mem::take(current));
        current.push_str(word);
    };
    for word in text.split_whitespace() {
        if word.width() <= width {
            push_word(&mut lines, &mut current, word);
            continue;
        }
        // An overlong word: flush the line, then split the word on
        // char boundaries.
        if !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        let mut chunk = String::new();
        for ch in word.chars() {
            let mut candidate = chunk.clone();
            candidate.push(ch);
            if candidate.width() > width {
                if !chunk.is_empty() {
                    lines.push(std::mem::take(&mut chunk));
                }
                if ch.to_string().width() > width {
                    // A single glyph cannot fit this degenerate viewport.
                    lines.push(TRUNCATION_MARK.into());
                    continue;
                }
            }
            chunk.push(ch);
        }
        current = chunk;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// How the first visible gap record rendered: whole (later
/// records may pack behind it), paged (a head plus a body slice —
/// the record consumes the window), or unshown (the budget cannot
/// even name the record — the window stops honestly).
enum FirstGapOutcome {
    Whole,
    Paged,
    Unshown,
}

/// Effective within-record offset (F6e): the stored offset clamped
/// to the record's wrapped body at the live width, measured with the
/// SAME block construction the renderer uses. The continuation head
/// AND the footer both use this, so a stale offset — a resize that
/// rewrapped the body shorter, or a rescan that replaced the record
/// under the scroll — renders identically in both places.
fn effective_gap_line(
    gap: &crate::inventory_present::GapView,
    index: usize,
    total: usize,
    width: usize,
    gap_line: usize,
) -> usize {
    let body = gap_block_lines(gap, index, total, width)
        .len()
        .saturating_sub(1);
    gap_line.min(body.saturating_sub(1))
}

/// Render the FIRST visible gap record (F6d): whole when it fits at
/// offset zero (later records pack behind it, exactly as before),
/// else a within-record page — the head (or an explicit
/// continuation head naming the skipped lines) plus a body slice,
/// plus an explicit continuation marker when body remains below.
/// The offset clamps defensively (a rescan may have replaced the
/// record under the scroll). Appends at most `budget` lines.
/// `Unshown` only when the budget holds no head line at all.
fn render_first_gap_record(
    lines: &mut Vec<String>,
    gap: &crate::inventory_present::GapView,
    index: usize,
    total: usize,
    width: usize,
    budget: usize,
    gap_line: usize,
) -> FirstGapOutcome {
    let block = gap_block_lines(gap, index, total, width);
    // The block always holds a head plus at least one body line
    // (`wrap_words` never returns empty).
    let (head, body) = block.split_first().expect("a gap block names its gap");
    if gap_line == 0 && block.len() <= budget {
        lines.extend(block);
        return FirstGapOutcome::Whole;
    }
    if budget < 2 {
        return FirstGapOutcome::Unshown;
    }
    let offset = effective_gap_line(gap, index, total, width, gap_line);
    if offset == 0 {
        lines.push(head.clone());
    } else {
        lines.push(truncate_cell(
            &format!(
                "gap {}/{} (+{offset} lines above) {}",
                index + 1,
                total,
                gap_head_attribution(gap),
            ),
            width,
        ));
    }
    let remaining = body.len() - offset;
    if remaining < budget {
        // Tail page: the head plus every remaining body line.
        lines.extend(body[offset..].iter().cloned());
        return FirstGapOutcome::Paged;
    }
    // Middle page: the head, a body slice, and the continuation
    // marker. Production budgets are always >= 5 here (rooms >= 7
    // minus at most two marker/reserve lines), so the slice always
    // advances; a degenerate budget still terminates (the Down
    // handler steps at least one line per key).
    let take = budget.saturating_sub(2);
    lines.extend(body[offset..offset + take].iter().cloned());
    let below = remaining - take;
    lines.push(truncate_cell(
        &format!("(continued: +{below} more lines below in this gap; scroll down)"),
        width,
    ));
    FirstGapOutcome::Paged
}

/// One gap's full ledger block: a column-0 attribution line
/// (position, caller, module, pid) plus the snapshot gap line
/// verbatim, word-wrapped — never truncated, so every gap's full
/// text stays reachable. Always at least two lines (head + body:
/// `wrap_words` never returns empty). The gaps-page Down handler
/// measures record boundaries with this SAME construction, so
/// paging and rendering always agree.
/// The attribution tail shared by a gap head and its
/// continuation head (`caller … module …[ pid …]`).
fn gap_head_attribution(gap: &crate::inventory_present::GapView) -> String {
    let caller = gap
        .caller
        .map(|caller| caller.label())
        .unwrap_or_else(|| "*".to_string());
    let module = gap
        .module
        .map(|module| module.label())
        .unwrap_or_else(|| "*".to_string());
    let mut attribution = format!("caller {caller} module {module}");
    if let Some(pid) = gap.pid {
        attribution.push_str(&format!(" pid {pid}"));
    }
    attribution
}

fn gap_block_lines(
    gap: &crate::inventory_present::GapView,
    index: usize,
    total: usize,
    width: usize,
) -> Vec<String> {
    let head = format!("gap {}/{} {}", index + 1, total, gap_head_attribution(gap),);
    let mut block = vec![truncate_cell(&head, width)];
    for line in wrap_words(&gap_item(gap), width.saturating_sub(2).max(1)) {
        block.push(truncate_cell(&format!("  {line}"), width));
    }
    block
}

/// One gap's ledger block within `budget` rows. `None` when the
/// wrapped block exceeds `budget` (the window then stops honestly
/// instead of cropping). Only non-first records use this: the
/// first visible record pages within itself (F6d) instead.
fn fit_gap_block(
    gap: &crate::inventory_present::GapView,
    index: usize,
    total: usize,
    width: usize,
    budget: usize,
) -> Option<Vec<String>> {
    let block = gap_block_lines(gap, index, total, width);
    (block.len() <= budget).then_some(block)
}

/// The 1-based visible item range named in the table header/footer
/// (edges, or gaps on the gaps page). Derived from the
/// emitted-block COUNT the window returns, not from arithmetic over
/// the scroll or by re-parsing rendered text — the header can never
/// claim items the frame does not show, and a future reformat cannot
/// silently degrade the range. An empty window names 0-0 (nothing
/// shown) alongside the window's honest message; the footer still
/// carries the scroll position.
fn visible_item_range(shown: usize, total: usize, scroll: usize) -> (usize, usize) {
    if total == 0 || shown == 0 {
        return (0, 0);
    }
    (scroll + 1, scroll + shown)
}

/// How long one redraw may wait for the terminal to take its frame
/// (C5.3). The wait comes out of a service tick, so it is small: past
/// it the rest of the frame is shed and counted, never blocked on.
pub(crate) const FRAME_WRITE_BUDGET: Duration = Duration::from_millis(10);
/// How long entering or restoring the screen may wait for a terminal
/// that does not read (C5.3): past it the sequence is shed and counted,
/// so a stalled terminal never holds the stop or the report.
pub(crate) const RESTORE_BUDGET: Duration = Duration::from_secs(1);

/// Enter the alternate screen, hide the cursor, home.
const ENTER_SCREEN: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[H";
/// Show the cursor and leave the alternate screen, after a CAN that
/// aborts any escape sequence a shed frame cut short.
const RESTORE_SCREEN: &[u8] = b"\x18\x1b[?25h\x1b[?1049l";
/// Prefix of the first frame after one was cut short: CAN aborts the
/// cut escape sequence; the full repaint that follows rewrites every
/// row.
const REPAIR_FRAME: &[u8] = b"\x18";

/// What the terminal writer shed (C5.3): every frame is either written
/// whole or counted here. A frame is shed when the terminal did not take
/// it within [`FRAME_WRITE_BUDGET`]; `frames_cut` counts those whose
/// head already reached the terminal (the next frame repairs the
/// screen).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TerminalAccount {
    pub frames_written: u64,
    pub frames_shed: u64,
    pub frames_cut: u64,
    pub bytes_shed: u64,
    /// Total time frame writes waited for the terminal.
    pub stall_ms: u64,
    /// The restore sequence reached the terminal whole.
    pub restored: bool,
    /// The first restore was shed and tried once more after the report
    /// ([`TerminalWriter::retry_restore`]).
    pub restore_retried: bool,
}

/// The dashboard's terminal output (C5.3): a private nonblocking
/// description of the terminal behind the reused bounded sink
/// ([`SinkWriter`](crate::sink::SinkWriter)), so a terminal that stops
/// reading costs a redraw at most [`FRAME_WRITE_BUDGET`] and its frames
/// shed with counters. Entering takes over the screen; [`restore`]
/// (also on drop, every path) shows the cursor and leaves the alternate
/// screen within [`RESTORE_BUDGET`]. The shared description of the
/// terminal (the shell's) keeps its flags.
///
/// [`restore`]: TerminalWriter::restore
pub(crate) struct TerminalWriter {
    sink: crate::sink::SinkWriter<File>,
    fd: std::os::fd::RawFd,
    entered: bool,
    /// The last frame was cut short: the next one starts with a repair.
    torn: bool,
    /// The last frame reached the terminal whole.
    last_written: bool,
    /// The restore was shed: one retry is left.
    restore_shed: bool,
    account: TerminalAccount,
}

impl TerminalWriter {
    /// Opens the terminal on `fd` as a private description (through
    /// `/proc/self/fd`, `O_NONBLOCK | O_NOCTTY`): `dup` would alias the
    /// shell's description, and nonblocking writes there would leak to
    /// it.
    pub(crate) fn open(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(format!("/proc/self/fd/{fd}"))?;
        let own_fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        Ok(Self {
            sink: crate::sink::SinkWriter::new(file)?,
            fd: own_fd,
            entered: false,
            torn: false,
            last_written: false,
            restore_shed: false,
            account: TerminalAccount::default(),
        })
    }

    /// The terminal's fd (for the window size), owned by the sink.
    pub(crate) fn fd(&self) -> std::os::fd::RawFd {
        self.fd
    }

    /// Takes over the screen (bounded). A terminal that does not take the
    /// sequence still gets the restore at the end.
    pub(crate) fn enter(&mut self) -> std::io::Result<()> {
        self.entered = true;
        self.write_bounded(ENTER_SCREEN, RESTORE_BUDGET).map(|_| ())
    }

    /// Writes one frame within [`FRAME_WRITE_BUDGET`]; what the terminal
    /// did not take is shed and counted. Only a transport error (a hung-up
    /// terminal) is an error.
    pub(crate) fn frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let repair = if self.torn { REPAIR_FRAME } else { b"" };
        let mut bytes = Vec::with_capacity(repair.len() + frame.len());
        bytes.extend_from_slice(repair);
        bytes.extend_from_slice(frame);
        let shed = self.write_bounded(&bytes, FRAME_WRITE_BUDGET)?;
        self.last_written = shed == 0;
        if shed == 0 {
            self.account.frames_written += 1;
            self.torn = false;
        } else {
            self.account.frames_shed += 1;
            self.account.bytes_shed = self.account.bytes_shed.saturating_add(shed);
            if shed < bytes.len() as u64 {
                self.account.frames_cut += 1;
                self.torn = true;
            }
        }
        Ok(())
    }

    /// Shows the cursor and leaves the alternate screen (bounded by
    /// [`RESTORE_BUDGET`]); true when the sequence reached the terminal
    /// whole. Only the first call writes.
    pub(crate) fn restore(&mut self) -> bool {
        if !self.entered {
            return self.account.restored;
        }
        self.entered = false;
        self.account.restored = matches!(self.write_bounded(RESTORE_SCREEN, RESTORE_BUDGET), Ok(0));
        self.restore_shed = !self.account.restored;
        self.account.restored
    }

    /// One more attempt after a shed restore, bounded by `budget` (call it
    /// only once nothing it could hold remains: after the report). The
    /// sequence starts with CAN, which aborts whatever head of the shed one
    /// reached the terminal. True when the terminal is restored.
    pub(crate) fn retry_restore(&mut self, budget: Duration) -> bool {
        if std::mem::take(&mut self.restore_shed) {
            self.account.restore_retried = true;
            self.account.restored = matches!(self.write_bounded(RESTORE_SCREEN, budget), Ok(0));
        }
        self.account.restored
    }

    pub(crate) fn account(&self) -> TerminalAccount {
        self.account
    }

    /// The last frame reached the terminal whole.
    pub(crate) fn last_frame_written(&self) -> bool {
        self.last_written
    }

    /// One bounded write: the bytes shed (0 when all were written).
    fn write_bounded(&mut self, bytes: &[u8], budget: Duration) -> std::io::Result<u64> {
        self.sink.begin_tick(budget);
        self.sink.write_all(bytes)?;
        self.sink.flush()?;
        let drops = self.sink.take_drops();
        self.account.stall_ms = self.account.stall_ms.saturating_add(drops.stall_ms);
        Ok(drops.dropped_bytes)
    }
}

impl Drop for TerminalWriter {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Minimal raw-mode guard for dashboard key input: disables
/// canonical mode, echo, and signal-chars on stdin, keeping output
/// processing (so `\n` still renders). Reads never wait (`VMIN` 0,
/// `VTIME` 0): a key poll must not hold a service tick (C5.3).
/// Dropping restores the saved termios on every path. `None` when
/// stdin is not a terminal (the dashboard then runs without keys until
/// `--duration`/signal).
pub(crate) struct RawModeGuard {
    fd: std::os::fd::RawFd,
    saved: libc::termios,
}

impl RawModeGuard {
    /// Raw mode on any terminal fd (production passes stdin through
    /// [`DashboardIo`]; tests pass a pty slave so the real termios
    /// round-trips without touching the test runner's stdin).
    pub(crate) fn enter_fd(fd: std::os::fd::RawFd) -> std::io::Result<Option<Self>> {
        if unsafe { libc::isatty(fd) } != 1 {
            return Ok(None);
        }
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(Self { fd, saved }))
    }

    /// The terminal input fd keys are read from.
    pub(crate) fn fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

/// Dashboard keys: scrolling, detail paging, plus quit.
/// Everything else is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Detail,
    Quit,
}

/// How long an escape sequence's continuation bytes may take to arrive
/// after its ESC (only then does a key poll wait at all).
const ESCAPE_CONTINUATION_WAIT: Duration = Duration::from_millis(30);

/// Key poll on the terminal input `fd` that never waits for a first byte
/// (C5.3: it runs inside a service tick). Arrow escape sequences parse
/// as scrolling (their continuation waits at most
/// [`ESCAPE_CONTINUATION_WAIT`]); Tab pages the detail views;
/// `q`/`Q`/Ctrl-C/ESC quit.
pub(crate) fn poll_key_fd(fd: std::os::fd::RawFd) -> Option<Key> {
    let mut first = true;
    poll_key_from(&mut |into: &mut [u8]| {
        let wait = if std::mem::take(&mut first) {
            Duration::ZERO
        } else {
            ESCAPE_CONTINUATION_WAIT
        };
        read_key_byte(fd, into, wait)
    })
}

/// Key parsing over an injected byte reader (production reads stdin;
/// tests script byte sequences, including split arrow arrivals).
fn poll_key_from(read: &mut dyn FnMut(&mut [u8]) -> bool) -> Option<Key> {
    let mut first = [0u8; 1];
    if !read(&mut first) {
        return None;
    }
    match first[0] {
        b'q' | b'Q' | 0x03 => Some(Key::Quit),
        b'k' => Some(Key::Up),
        b'j' => Some(Key::Down),
        b'\t' => Some(Key::Detail),
        0x1b => {
            // Arrow keys arrive as ESC [ A/B; a lone ESC quits.
            let mut rest = [0u8; 2];
            if !read(&mut rest[0..1]) {
                return Some(Key::Quit);
            }
            if rest[0] != b'[' {
                return Some(Key::Quit);
            }
            if !read(&mut rest[1..2]) {
                return Some(Key::Quit);
            }
            match rest[1] {
                b'A' => Some(Key::Up),
                b'B' => Some(Key::Down),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Reads `into` from `fd` once it is readable within `wait`.
fn read_key_byte(fd: std::os::fd::RawFd, into: &mut [u8], wait: Duration) -> bool {
    if into.is_empty() {
        return false;
    }
    let mut ready = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = wait.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one valid stack `pollfd`; `poll` writes only its `revents`.
    if unsafe { libc::poll(&mut ready, 1, timeout_ms) } != 1 {
        return false;
    }
    // SAFETY: `into` is a valid writable buffer of `into.len()` bytes.
    let outcome = unsafe {
        libc::read(
            fd,
            into.as_mut_ptr().cast::<libc::c_void>(),
            into.len() as libc::size_t,
        )
    };
    outcome == into.len() as isize
}

/// Cooperative stop flag for the inventory loop (classic or dashboard):
/// SIGINT/SIGTERM/SIGHUP set it (signal-safe atomics only, like the
/// capture loops); the loop polls it every tick and exits through its
/// stop path, so the terminal restores on operator stops and supervisor
/// kills alike.
/// SIGKILL cannot be caught — its terminal needs `reset(1)`.
pub(crate) struct StopFlag {
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Armed once the report is written (R-C51-4): a further stop signal
    /// then ends the process at once (`_exit(128 + signal)`); the kernel
    /// releases whatever the drop was still detaching.
    exit_on_next: Arc<std::sync::atomic::AtomicBool>,
    _hooks: Vec<signal_hook::SigId>,
}

// `signal_hook::low_level::register` is process-global; the dashboard
// runs once per process, so the hooks live for the run.
impl StopFlag {
    pub(crate) fn install() -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exit_on_next = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hooks = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let flag = Arc::clone(&stop);
            let armed = Arc::clone(&exit_on_next);
            // The callback is the signal-safe minimum: atomic loads and a
            // store, or `_exit` (async-signal-safe); no allocation, no
            // I/O, no locks.
            let hook = unsafe {
                signal_hook::low_level::register(signal, move || {
                    if armed.load(Ordering::SeqCst) {
                        libc::_exit(128 + signal);
                    }
                    flag.store(true, Ordering::SeqCst);
                })
            };
            if let Ok(id) = hook {
                hooks.push(id);
            }
        }
        Self {
            stop,
            exit_on_next,
            _hooks: hooks,
        }
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// From now on a stop signal exits the process at once (R-C51-4: the
    /// report is written; only the blocking probe detach may remain).
    pub(crate) fn exit_on_next_signal(&self) {
        self.exit_on_next.store(true, Ordering::SeqCst);
    }
}

/// True when `fd` names a terminal (the dashboard's honesty gate:
/// interactive frames require a TTY; pipes degrade to snapshots).
pub(crate) fn fd_is_tty(fd: std::os::fd::RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Where the interactive dashboard draws and reads keys (C5.3).
/// Production: the terminal on stdout, the keys on stdin and the
/// process's stderr on fd 2; tests pass a pty and their own stderr.
pub(crate) struct DashboardIo {
    /// The terminal frames go to (opened as a private nonblocking
    /// description; the fd itself is never changed or closed).
    pub output: std::os::fd::RawFd,
    /// The key input; keys are live only when it is a terminal.
    pub input: Option<std::os::fd::RawFd>,
    /// Receives the display's account when the dashboard ends (tests).
    pub account: Option<std::rc::Rc<std::cell::Cell<Option<DisplayAccount>>>>,
    /// The process's stderr (production fd 2): where the closing lines
    /// go, and what [`StderrRoute::Capture`] redirects.
    pub stderr_fd: std::os::fd::RawFd,
    /// What the dashboard does with that stderr while it owns the screen.
    pub stderr: StderrRoute,
}

impl DashboardIo {
    pub(crate) fn stdio() -> Self {
        Self {
            output: 1,
            input: Some(0),
            account: None,
            stderr_fd: 2,
            stderr: StderrRoute::for_fd(2),
        }
    }
}

/// What the dashboard does with the process's stderr while it owns the
/// screen (C5.3, review M1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum StderrRoute {
    /// Stderr is a terminal (normally the dashboard's own): every writer
    /// would scribble beside the screen and, on a terminal that stopped
    /// reading, block in a blocking write. It is captured
    /// ([`StderrCapture`]) into the log tail, and what it held, with the
    /// pass warnings, is replayed on the real stderr at the restore.
    Capture,
    /// Stderr is a file or a pipe: left alone, so it keeps every line it
    /// kept on the classic path; the log tail's lines are mirrored to it
    /// (bounded, shed and counted when it stops reading).
    Mirror,
    /// Left alone and nothing mirrored (unit tests running beside others).
    #[default]
    Leave,
}

impl StderrRoute {
    /// Capture only a terminal: a file or a pipe neither scribbles on the
    /// screen nor loses what it is given.
    pub(crate) fn for_fd(fd: std::os::fd::RawFd) -> Self {
        if fd_is_tty(fd) {
            Self::Capture
        } else {
            Self::Mirror
        }
    }
}

/// Captured stderr lines kept for the log tail, at most this many between
/// two ticks (older ones are counted, not kept).
const CAPTURED_LINES_MAX: usize = 256;

/// What the capture's reader thread holds for the next tick.
#[derive(Default)]
struct CapturedLines {
    lines: VecDeque<String>,
    dropped: u64,
}

/// The process's stderr while the dashboard owns the terminal (C5.3): the
/// stderr fd points at a pipe whose reader thread keeps the lines
/// (bounded) for the log tail. Every stderr writer of a pass (warnings
/// deep in a scan, a helper process) would otherwise scribble beside the
/// screen and, on a terminal that stopped reading, block the loop in a
/// blocking write. The reader drains continuously, so a writer never
/// waits on the terminal. [`finish`](Self::finish) puts the saved stderr
/// back and hands over what the reader still held; a drop only puts it
/// back.
pub(crate) struct StderrCapture {
    fd: std::os::fd::RawFd,
    saved: Option<std::os::fd::OwnedFd>,
    captured: Arc<Mutex<CapturedLines>>,
    /// Signalled by the reader once it reached the pipe's end.
    drained: Option<std::sync::mpsc::Receiver<()>>,
    progress_was: bool,
}

/// How long the restore waits for the capture's reader to drain the pipe
/// once the stderr is back. The pipe ends when its last write end closes:
/// at once, unless a helper process that inherited it still runs; past
/// the wait the lines read so far are replayed and the rest stay unread.
const CAPTURE_DRAIN_WAIT: Duration = Duration::from_millis(250);

/// What a [`StderrCapture`] held when it finished.
pub(crate) struct CaptureEnd {
    pub lines: Vec<String>,
    /// Lines the reader dropped before anyone took them.
    pub dropped: u64,
    /// Putting the saved stderr back failed: the stderr fd still names
    /// the pipe (the closing lines use their own description of the real
    /// stderr, opened before the capture).
    pub restore_error: Option<std::io::Error>,
    /// The reader reached the pipe's end within [`CAPTURE_DRAIN_WAIT`].
    pub drained: bool,
}

impl StderrCapture {
    /// Captures the stderr on `fd` (production: 2).
    pub(crate) fn begin(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
        // SAFETY: `F_DUPFD_CLOEXEC` returns a fresh owned fd, or -1.
        let saved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if saved < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor this capture owns.
        let saved = unsafe { OwnedFd::from_raw_fd(saved) };
        let mut ends = [0; 2];
        // SAFETY: `pipe2` writes two fresh fds into `ends`.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both ends are fresh descriptors owned here.
        let (read, write) = unsafe { (File::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // Room for a burst while the reader is descheduled (best effort).
        // SAFETY: a size request on our own pipe.
        unsafe {
            libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, 1 << 20);
        }
        let captured = Arc::new(Mutex::new(CapturedLines::default()));
        let sink = Arc::clone(&captured);
        let (done, drained) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("p11scope-stderr".into())
            .spawn(move || {
                read_captured(read, &sink);
                let _ = done.send(());
            })?;
        // SAFETY: `dup2` onto the stderr fd; the pipe's write end stays
        // owned by `write` until it drops below (the reader then ends).
        if unsafe { libc::dup2(write.as_raw_fd(), fd) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        drop(write);
        Ok(Self {
            fd,
            saved: Some(saved),
            captured,
            drained: Some(drained),
            progress_was: crate::inspect_system::set_progress_lines(false),
        })
    }

    /// The lines captured since the last call, and how many were dropped.
    pub(crate) fn take(&self) -> (Vec<String>, u64) {
        let mut captured = self
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dropped = std::mem::take(&mut captured.dropped);
        (captured.lines.drain(..).collect(), dropped)
    }

    /// Puts the saved stderr back, waits (bounded) for the reader to
    /// drain the pipe, and hands over every line it still held: nothing
    /// written to stderr while the dashboard ran is lost unannounced.
    pub(crate) fn finish(mut self, wait: Duration) -> CaptureEnd {
        let restore_error = self.end().err();
        // With the stderr still on the pipe its end never comes: no wait.
        let drained = restore_error.is_none()
            && self
                .drained
                .take()
                .is_some_and(|drained| drained.recv_timeout(wait).is_ok());
        let (lines, dropped) = self.take();
        CaptureEnd {
            lines,
            dropped,
            restore_error,
            drained,
        }
    }

    /// Puts the saved stderr back (once).
    fn end(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let Some(saved) = self.saved.take() else {
            return Ok(());
        };
        crate::inspect_system::set_progress_lines(self.progress_was);
        loop {
            // SAFETY: `dup2` of our own saved descriptor onto the stderr
            // fd.
            if unsafe { libc::dup2(saved.as_raw_fd(), self.fd) } >= 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Drop for StderrCapture {
    fn drop(&mut self) {
        let _ = self.end();
    }
}

/// The capture's reader: lines, each capped at [`LOG_LINE_MAX_CHARS`]
/// bytes (the tail truncates further), at most [`CAPTURED_LINES_MAX`]
/// held.
fn read_captured(mut pipe: File, captured: &Mutex<CapturedLines>) {
    use std::io::Read as _;
    let mut partial: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let keep = |line: &[u8]| {
        let text = String::from_utf8_lossy(line).into_owned();
        let mut captured = captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        captured.lines.push_back(text);
        while captured.lines.len() > CAPTURED_LINES_MAX {
            captured.lines.pop_front();
            captured.dropped = captured.dropped.saturating_add(1);
        }
    };
    loop {
        let read = match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &byte in &chunk[..read] {
            if byte == b'\n' {
                keep(&partial);
                partial.clear();
            } else if partial.len() < LOG_LINE_MAX_CHARS {
                partial.push(byte);
            }
        }
    }
    if !partial.is_empty() {
        keep(&partial);
    }
}

/// Keys handled in one service tick, at most (a paste cannot hold a tick).
const KEYS_PER_TICK: usize = 64;

/// What the dashboard's display did over a run (C5.3): the frame
/// handoff, the terminal writer's account, and the service ticks the
/// loop gave it. `longest_gap` is the longest time between two
/// consecutive ticks with no pass between them (what the display and the
/// ticks themselves cost); `longest_pass_gap` the longest stretch across
/// a pass (from the takeover to the first tick, between the ticks around
/// a pass, or from the last tick to the stop), which also carries the
/// pass's own work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DisplayAccount {
    pub offered: u64,
    pub consumed: u64,
    pub superseded: u64,
    pub terminal: TerminalAccount,
    pub ticks: u64,
    pub longest_gap: Duration,
    pub longest_pass_gap: Duration,
    pub stderr: StderrAccount,
    /// Closing stderr lines the real stderr did not take within their
    /// budget (or that had no stderr to go to).
    pub notices_shed: u64,
}

/// What became of the stderr lines of a dashboard run (C5.3, review M1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StderrAccount {
    pub route: StderrRoute,
    /// Captured lines and pass warnings replayed at the restore.
    pub replayed: u64,
    /// Captured lines and pass warnings dropped before the replay (the
    /// capture's reader and the replay keep the newest lines only).
    pub dropped: u64,
    /// The capture's reader had not drained the pipe within its wait.
    pub undrained: bool,
    /// Putting the saved stderr back failed.
    pub restore_failed: bool,
    /// Log lines mirrored to a stderr that is not the terminal.
    pub mirrored: u64,
    /// Log lines the mirror shed: that stderr did not take them in time.
    pub mirror_shed: u64,
}

/// Captured lines and pass warnings the replay keeps, at most (the newest;
/// older ones are counted).
const REPLAY_LINES_MAX: usize = 256;

/// What mirroring the log lines may wait on a stderr that stopped reading,
/// per pass; past it the pass's further lines are shed (counted).
const MIRROR_PASS_BUDGET: Duration = Duration::from_millis(5);

/// How long the restore retried after the report may wait for a terminal
/// that shed the first one ([`Display::retry_restore`]); a second signal
/// exits sooner.
pub(crate) const RESTORE_RETRY_BUDGET: Duration = Duration::from_secs(5);

/// The closing stderr lines' shared budget ([`Notices`]).
pub(crate) const NOTICE_BUDGET: Duration = Duration::from_secs(1);

/// The interactive dashboard's display side (C5.3), driven by the
/// inventory loop's service ticks: it never owns the loop. Each tick
/// reads keys without waiting and, at the ~3 Hz cadence (or after a
/// key), renders the newest presentation and hands it to the
/// [`TerminalWriter`], which sheds what the terminal does not take
/// within its budget. A stalled terminal therefore never delays a tick:
/// the capture keeps its cadence and the frames are counted as shed.
pub(crate) struct Display {
    writer: TerminalWriter,
    keys: Option<RawModeGuard>,
    stderr: Option<StderrCapture>,
    /// The closing lines, on the real stderr (opened before the capture).
    notices: Notices,
    /// The log lines' mirror ([`StderrRoute::Mirror`]).
    mirror: Option<Notices>,
    /// What the restore replays ([`StderrRoute::Capture`]).
    replay: VecDeque<String>,
    stderr_account: StderrAccount,
    handoff: DisplayHandoff,
    tail: LogTail,
    state: DashboardState,
    last_frame: Option<DisplayFrame>,
    last_viewport: Viewport,
    next_redraw: std::time::Instant,
    quit: std::rc::Rc<std::cell::Cell<bool>>,
    failure: Option<std::io::Error>,
    restored: bool,
    ticks: u64,
    last_tick: Option<std::time::Instant>,
    /// A pass was offered since the last tick.
    pass_since_tick: bool,
    longest_gap: Duration,
    longest_pass_gap: Duration,
    /// Frames shed already announced in the log tail.
    shed_announced: u64,
}

impl Display {
    /// Takes over the terminal of `io`: the alternate screen (bounded),
    /// and raw key input when its input is a terminal.
    pub(crate) fn open(io: &DashboardIo, scope_label: &str) -> std::io::Result<Self> {
        // Before the capture: the closing lines go to the real stderr.
        let notices = Notices::on_fd(io.stderr_fd, NOTICE_BUDGET);
        let mirror = (io.stderr == StderrRoute::Mirror)
            .then(|| Notices::mirror_on_fd(io.stderr_fd, MIRROR_PASS_BUDGET));
        let mut writer = TerminalWriter::open(io.output)?;
        writer.enter()?;
        let keys = match io.input {
            Some(fd) => RawModeGuard::enter_fd(fd)?,
            None => None,
        };
        let stderr = if io.stderr == StderrRoute::Capture {
            Some(StderrCapture::begin(io.stderr_fd)?)
        } else {
            None
        };
        let mut tail = LogTail::bounded();
        tail.push(&format!(
            "p11scope inventory {scope_label}: dashboard started (rescan 1 Hz, redraw ~3 Hz{})",
            if keys.is_some() {
                ""
            } else {
                "; stdin is not a terminal, keys unavailable"
            }
        ));
        Ok(Self {
            writer,
            keys,
            stderr,
            notices,
            mirror,
            replay: VecDeque::new(),
            stderr_account: StderrAccount {
                route: io.stderr,
                ..StderrAccount::default()
            },
            handoff: DisplayHandoff::new(),
            tail,
            state: DashboardState::new(),
            last_frame: None,
            last_viewport: Viewport {
                width: 80,
                height: 24,
            },
            next_redraw: std::time::Instant::now(),
            quit: std::rc::Rc::new(std::cell::Cell::new(false)),
            failure: None,
            restored: false,
            ticks: 0,
            // The first gap runs from the takeover (the first pass in it).
            last_tick: Some(std::time::Instant::now()),
            pass_since_tick: true,
            longest_gap: Duration::ZERO,
            longest_pass_gap: Duration::ZERO,
            shed_announced: 0,
        })
    }

    /// Set by `q`/ESC/Ctrl-C, or by a terminal transport error: the loop
    /// polls it with its stop signals.
    pub(crate) fn quit_flag(&self) -> std::rc::Rc<std::cell::Cell<bool>> {
        std::rc::Rc::clone(&self.quit)
    }

    /// One line for the log tail (sanitized there), mirrored to a stderr
    /// that is not the terminal: a progress line.
    pub(crate) fn log(&mut self, line: &str) {
        self.tail.push(line);
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.line(&crate::render::escape_controls(line));
        }
    }

    /// A line that must outlive the screen (a pass warning, a caller
    /// event): logged, and kept for the replay when stderr is captured.
    /// After the restore it goes straight to the closing lines.
    pub(crate) fn warn(&mut self, line: &str) {
        if self.restored {
            self.notice(line);
            return;
        }
        self.log(line);
        if self.stderr.is_some() {
            self.keep(line.to_string());
        }
    }

    /// One closing line on the real stderr, within the shared notice
    /// budget (shed and counted past it).
    pub(crate) fn notice(&mut self, line: &str) {
        self.notices.line(line);
    }

    fn keep(&mut self, line: String) {
        self.replay.push_back(line);
        while self.replay.len() > REPLAY_LINES_MAX {
            self.replay.pop_front();
            self.stderr_account.dropped += 1;
        }
    }

    /// Offers the pass's presentation (latest wins, never blocks), with
    /// the log tail including what stderr captured since the last pass.
    pub(crate) fn offer(&mut self, presentation: Presentation) {
        self.pass_since_tick = true;
        self.take_stderr();
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.refill(MIRROR_PASS_BUDGET);
        }
        self.handoff
            .offer(Arc::new(presentation), self.tail.snapshot());
    }

    /// Moves the captured stderr lines into the log tail (sanitized there)
    /// and the replay.
    fn take_stderr(&mut self) {
        let Some(capture) = self.stderr.as_ref() else {
            return;
        };
        let (lines, dropped) = capture.take();
        self.captured(lines, dropped);
    }

    fn captured(&mut self, lines: Vec<String>, dropped: u64) {
        if dropped > 0 {
            self.stderr_account.dropped += dropped;
            self.tail.push(&format!(
                "p11scope: {dropped} stderr lines dropped before the log tail took them"
            ));
        }
        for line in lines {
            self.tail.push(&line);
            self.keep(line);
        }
    }

    /// One service tick: keys, then the frame when one is due. Never
    /// waits on the terminal past [`FRAME_WRITE_BUDGET`].
    pub(crate) fn tick(&mut self) {
        let now = std::time::Instant::now();
        self.note_gap(now);
        self.ticks += 1;
        if self.restored || self.quit.get() {
            return;
        }
        let mut redraw = now >= self.next_redraw;
        if let Some(fd) = self.keys.as_ref().map(RawModeGuard::fd) {
            for _ in 0..KEYS_PER_TICK {
                let Some(key) = poll_key_fd(fd) else {
                    break;
                };
                // Keys redraw at once (scrolling stays responsive inside
                // the coalesced cadence).
                redraw = true;
                match key {
                    Key::Quit => {
                        self.tail.push("p11scope: quit requested");
                        self.quit.set(true);
                        return;
                    }
                    Key::Up => {
                        if self.state.detail == DetailPage::Gaps {
                            self.state.scroll_gaps_up();
                        } else {
                            self.state.scroll_up();
                        }
                    }
                    Key::Down => {
                        if let Some(frame) = self.last_frame.as_ref() {
                            if self.state.detail == DetailPage::Gaps {
                                // Within-record paging (F6d) wraps at the
                                // live viewport width, exactly like the
                                // renderer.
                                self.state.scroll_gaps_down(
                                    &frame.presentation,
                                    self.last_viewport.width,
                                );
                            } else {
                                let total = self.state.items_total(&frame.presentation);
                                self.state.scroll_down(total);
                            }
                        } else if self.state.detail != DetailPage::Gaps {
                            self.state.scroll_down(0);
                        }
                    }
                    Key::Detail => {
                        self.state.next_detail();
                        if let Some(frame) = self.last_frame.as_ref() {
                            self.state.clamp_to_presentation(&frame.presentation);
                        }
                    }
                }
            }
        }
        if redraw {
            self.next_redraw = now + REDRAW_INTERVAL;
            self.draw();
        }
    }

    fn draw(&mut self) {
        if let Some(frame) = self.handoff.take() {
            self.last_frame = Some(frame);
        }
        let Some(frame) = self.last_frame.as_ref() else {
            return;
        };
        self.state.clamp_to_presentation(&frame.presentation);
        let viewport = Viewport::from_fd(self.writer.fd()).unwrap_or(Viewport {
            width: 80,
            height: 24,
        });
        self.last_viewport = viewport;
        let bytes = render_frame(frame, viewport, &self.state);
        if let Err(error) = self.writer.frame(&bytes) {
            // A transport error (a hung-up terminal): stop drawing and end
            // the run through its stop path, so the report is written.
            self.failure = Some(error);
            self.quit.set(true);
            return;
        }
        let account = self.writer.account();
        if account.frames_shed > self.shed_announced && self.writer.last_frame_written() {
            self.tail.push(&format!(
                "p11scope: the terminal did not keep up: {} frames shed so far ({} bytes); \
                 the capture was not delayed",
                account.frames_shed, account.bytes_shed
            ));
            self.shed_announced = account.frames_shed;
        }
    }

    fn note_gap(&mut self, now: std::time::Instant) {
        if let Some(last) = self.last_tick.replace(now) {
            let gap = now.saturating_duration_since(last);
            if std::mem::take(&mut self.pass_since_tick) {
                self.longest_pass_gap = self.longest_pass_gap.max(gap);
            } else {
                self.longest_gap = self.longest_gap.max(gap);
            }
        }
    }

    /// Gives the terminal back: raw input off, cursor shown, alternate
    /// screen left (bounded by [`RESTORE_BUDGET`]), stderr restored, then
    /// what stderr captured and the pass warnings replayed on it (within
    /// the notice budget), so nothing the screen alone showed is lost
    /// with it. Idempotent; ticks after it draw nothing. The loop's last
    /// stretch (from its last tick to the stop) counts as a gap.
    pub(crate) fn restore(&mut self) {
        if std::mem::replace(&mut self.restored, true) {
            return;
        }
        self.note_gap(std::time::Instant::now());
        self.last_tick = None;
        drop(self.keys.take());
        self.writer.restore();
        let Some(capture) = self.stderr.take() else {
            return;
        };
        let end = capture.finish(CAPTURE_DRAIN_WAIT);
        self.captured(end.lines, end.dropped);
        self.stderr_account.undrained = !end.drained;
        if let Some(error) = end.restore_error {
            self.stderr_account.restore_failed = true;
            self.notice(&format!(
                "p11scope: could not put stderr back after the dashboard ({error}); \
                 later stderr lines are lost"
            ));
        }
        self.replay_kept();
    }

    /// Replays the kept lines on the real stderr, oldest first.
    fn replay_kept(&mut self) {
        let dropped = self.stderr_account.dropped;
        if self.replay.is_empty() && dropped == 0 {
            return;
        }
        self.notice(&format!(
            "p11scope: stderr while the dashboard ran ({} lines{}):",
            self.replay.len(),
            if dropped > 0 {
                format!(", {dropped} older dropped")
            } else {
                String::new()
            }
        ));
        while let Some(line) = self.replay.pop_front() {
            self.notices.line(&crate::render::escape_controls(&line));
            self.stderr_account.replayed += 1;
        }
    }

    /// After a restore the terminal did not take whole (one still stalled
    /// at the stop, e.g. Ctrl-S then `q`): one more attempt, bounded by
    /// `budget`, once the report is written. Says how it went (on the
    /// closing lines) when it was needed; true when the terminal is
    /// restored.
    pub(crate) fn retry_restore(&mut self, budget: Duration) -> bool {
        let before = self.writer.account();
        let restored = self.writer.retry_restore(budget);
        if !before.restored && self.writer.account().restore_retried {
            self.notice(if restored {
                "p11scope: dashboard screen restored (the terminal read again)"
            } else {
                "p11scope: dashboard screen restore shed: the terminal did not read; run `reset`"
            });
        }
        restored
    }

    /// A terminal transport error that ended the run, once.
    pub(crate) fn take_failure(&mut self) -> Option<std::io::Error> {
        self.failure.take()
    }

    pub(crate) fn account(&self) -> DisplayAccount {
        DisplayAccount {
            offered: self.handoff.offered(),
            consumed: self.handoff.consumed(),
            superseded: self.handoff.dropped_frames(),
            terminal: self.writer.account(),
            ticks: self.ticks,
            longest_gap: self.longest_gap,
            longest_pass_gap: self.longest_pass_gap,
            stderr: StderrAccount {
                mirrored: self.mirror.as_ref().map_or(0, Notices::written),
                mirror_shed: self.mirror.as_ref().map_or(0, Notices::shed),
                ..self.stderr_account
            },
            notices_shed: self.notices.shed(),
        }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Bounded stderr lines (C5.3): the closing lines a dashboard run ends
/// with, and the mirror of its log lines. Their stderr may be the stalled
/// terminal or a pipe nobody reads, so every line waits only within one
/// shared budget and is shed past it (counted), never holding a pass, the
/// stop or the report. A stderr that cannot be opened sheds every line:
/// nothing here ever falls back to a blocking (or panicking) write.
pub(crate) struct Notices {
    sink: Option<crate::sink::SinkWriter<crate::sink::StdoutInner>>,
    left: Duration,
    /// The least wait a line gets once the budget is spent.
    floor: Duration,
    /// After a shed the further lines shed at once (until a refill).
    pause_after_shed: bool,
    stalled: bool,
    written: u64,
    shed: u64,
}

/// The least wait a closing line gets once the shared budget is spent: a
/// terminal that recovered still takes it.
const NOTICE_FLOOR: Duration = Duration::from_millis(5);

/// The least wait a mirrored line gets: a regular file or a pipe with
/// room takes it at once.
const MIRROR_FLOOR: Duration = Duration::from_millis(1);

impl Notices {
    /// The closing lines, on the stderr `fd` names now: open them before
    /// a [`StderrCapture`] begins, so they reach the real stderr.
    pub(crate) fn on_fd(fd: std::os::fd::RawFd, budget: Duration) -> Self {
        Self::over_sink(crate::sink::sink_on_fd(fd).ok(), budget)
    }

    /// The mirror of the log lines on `fd`, with `budget` per pass
    /// ([`refill`](Self::refill)).
    fn mirror_on_fd(fd: std::os::fd::RawFd, budget: Duration) -> Self {
        Self {
            floor: MIRROR_FLOOR,
            pause_after_shed: true,
            ..Self::over_sink(crate::sink::sink_on_fd(fd).ok(), budget)
        }
    }

    fn over_sink(
        sink: Option<crate::sink::SinkWriter<crate::sink::StdoutInner>>,
        budget: Duration,
    ) -> Self {
        Self {
            sink,
            left: budget,
            floor: NOTICE_FLOOR,
            pause_after_shed: false,
            stalled: false,
            written: 0,
            shed: 0,
        }
    }

    pub(crate) fn line(&mut self, line: &str) {
        let Some(sink) = self
            .sink
            .as_mut()
            .filter(|_| !(self.pause_after_shed && self.stalled))
        else {
            self.shed += 1;
            return;
        };
        let started = std::time::Instant::now();
        sink.begin_tick(self.left.max(self.floor));
        let written = writeln!(sink, "{line}").and_then(|()| sink.flush());
        self.left = self.left.saturating_sub(started.elapsed());
        if written.is_err() || sink.take_drops().dropped_bytes > 0 {
            self.shed += 1;
            self.stalled = true;
        } else {
            self.written += 1;
        }
    }

    /// A fresh budget (the mirror's, per pass).
    fn refill(&mut self, budget: Duration) {
        self.left = budget;
        self.stalled = false;
    }

    /// Notices over an explicit sink (tests).
    #[cfg(test)]
    pub(crate) fn over(
        sink: crate::sink::SinkWriter<crate::sink::StdoutInner>,
        budget: Duration,
    ) -> Self {
        Self::over_sink(Some(sink), budget)
    }

    /// Lines written whole so far.
    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    /// Lines shed so far.
    pub(crate) fn shed(&self) -> u64 {
        self.shed
    }
}

#[cfg(test)]
#[path = "inventory_dashboard_tests.rs"]
mod tests;
