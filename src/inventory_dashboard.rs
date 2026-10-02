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
//! input renders safely via control-escaping plus char-boundary
//! truncation.
//!
//! No new dependencies: the widget needs (scroll/resize/degrade) are
//! modest and hand-rolled ANSI suffices; the locked workspace
//! qualifies without Ratatui.

use crate::inventory_present::Presentation;
use crate::render::escape_controls;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// Truncate to `width` chars on a char boundary, marking with `…`.
/// Never panics (zero width yields empty); never splits a char or an
/// escape (callers escape before truncating, and markers carry no
/// ANSI).
pub(crate) fn truncate_cell(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}{TRUNCATION_MARK}")
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
/// minimal summary instead (totals, coverage, log tail, no edge
/// table) — never a crash, never corruption.
pub(crate) fn render_frame(
    frame: &DisplayFrame,
    viewport: Viewport,
    state: &DashboardState,
) -> Vec<u8> {
    let width = viewport.width.max(1);
    let height = viewport.height.max(1);
    let mut lines = if width < MIN_FULL_WIDTH || height < MIN_FULL_HEIGHT {
        render_minimal(frame, width, height)
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

/// Stated minimal layout for small terminals: totals, coverage, and
/// the log tail fit; the edge table does not and says so honestly.
fn render_minimal(frame: &DisplayFrame, width: usize, height: usize) -> Vec<String> {
    let presentation = frame.presentation.as_ref();
    let budgets = &presentation.budgets;
    let mut lines = vec![
        truncate_cell(
            &format!(
                "p11scope inventory {} (minimal: terminal {}x{}, full dashboard needs {}x{})",
                presentation.scope_label, width, height, MIN_FULL_WIDTH, MIN_FULL_HEIGHT,
            ),
            width,
        ),
        truncate_cell(
            &format!(
                "totals: {} callers {} modules {} edges | {} passes",
                presentation.callers.len(),
                presentation.modules.len(),
                presentation.edges.len(),
                presentation.passes,
            ),
            width,
        ),
        truncate_cell(
            &format!(
                "coverage: {} gaps {} refusals {} suppressed | endpoints {}/{} | attach {}/{}",
                presentation.gaps.len(),
                budgets.refusals(),
                presentation.gaps_suppressed,
                budgets.endpoints_occupied,
                budgets.endpoints_limit,
                budgets.inventory_endpoints_occupied,
                budgets.inventory_endpoints_limit,
            ),
            width,
        ),
        truncate_cell(
            &format!(
                "semantic: {} ({} held, {} unknown, {} refused) | retained {}/{}",
                crate::inventory_present::semantic_status(budgets),
                budgets.semantic_occupied,
                budgets.semantic_unknown_edges,
                budgets.semantic_refused,
                budgets.retained,
                budgets.retained_limit,
            ),
            width,
        ),
    ];
    if !presentation.edges.is_empty() {
        lines.push(truncate_cell(
            &format!(
                "{} edges hidden; enlarge the terminal for the edge table",
                presentation.edges.len()
            ),
            width,
        ));
    }
    let log_header = if frame.log.dropped_lines > 0 || frame.log.dropped_bytes > 0 {
        format!(
            "--- observer log ({} lines; +{} dropped lines, +{} dropped bytes) ---",
            frame.log.lines.len(),
            frame.log.dropped_lines,
            frame.log.dropped_bytes
        )
    } else {
        format!("--- observer log ({} lines) ---", frame.log.lines.len())
    };
    lines.push(truncate_cell(&log_header, width));
    // The log tail fills what the terminal has left after the footer.
    let room = height.saturating_sub(lines.len() + 1);
    let tail: Vec<String> = frame
        .log
        .lines
        .iter()
        .rev()
        .take(room)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|line| truncate_cell(line, width))
        .collect();
    lines.extend(tail);
    lines.push(truncate_cell(
        "enlarge the terminal for details | q quit",
        width,
    ));
    lines.truncate(height);
    lines
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
/// stage with explicit markers. `None` when even the minimal block
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
        };
        let block = render_edge_block(presentation, edge, width, stage);
        if block.len() <= budget {
            return Some(block);
        }
    }
    None
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

/// One edge's column-0 identity line, shared by the summary and
/// evidence pages so blocks attribute identically on both.
fn edge_identity_line(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
) -> String {
    let caller_exe = presentation
        .callers
        .iter()
        .find(|caller| caller.id == edge.caller)
        .and_then(|caller| caller.exe.as_ref())
        .and_then(|exe| exe.path.as_deref())
        .unwrap_or("?");
    let module_path = presentation
        .modules
        .iter()
        .find(|module| module.id == edge.module)
        .and_then(|module| module.paths.first())
        .map(String::as_str)
        .unwrap_or("?");
    truncate_cell(
        &format!(
            "{} pid {} ({}) -> {} ({})",
            edge.caller.label(),
            presentation
                .callers
                .iter()
                .find(|caller| caller.id == edge.caller)
                .map(|caller| caller.pid)
                .unwrap_or(0),
            escape_controls(caller_exe),
            edge.module.label(),
            escape_controls(module_path),
        ),
        width,
    )
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
        if current.len() + piece.len() <= width {
            current.push_str(&piece);
        } else {
            if current.len() > 2 {
                lines.push(truncate_cell(&current, width));
            }
            current = format!("  {item}");
            if current.len() > width {
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

/// Greedy word-wrap for gap text: words pack to `width` chars,
/// overlong words split on char boundaries. Always returns at
/// least one line; every line fits `width` chars.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    let push_word = |lines: &mut Vec<String>, current: &mut String, word: &str| {
        if current.is_empty() {
            current.push_str(word);
            return;
        }
        if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
            return;
        }
        lines.push(std::mem::take(current));
        current.push_str(word);
    };
    for word in text.split_whitespace() {
        if word.chars().count() <= width {
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
            if chunk.chars().count() >= width {
                lines.push(std::mem::take(&mut chunk));
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

/// Alternate-screen + cursor guard: entering takes over the terminal;
/// dropping (all paths: return, error, `?`) restores cursor, screen,
/// and mode. Best-effort writes — restoration must never panic.
pub(crate) struct TerminalGuard {
    restore_to: File,
}

impl TerminalGuard {
    /// Enter the dashboard screen on `term` (the live terminal file).
    pub(crate) fn enter(term: &File) -> std::io::Result<Self> {
        let mut out = term.try_clone()?;
        out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[H")?;
        out.flush()?;
        Ok(Self {
            restore_to: term.try_clone()?,
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore_to.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = self.restore_to.flush();
    }
}

/// Minimal raw-mode guard for dashboard key input: disables
/// canonical mode, echo, and signal-chars on stdin, keeping output
/// processing (so `\n` still renders). Dropping restores the saved
/// termios on every path. `None` when stdin is not a terminal (the
/// dashboard then runs without keys until `--duration`/signal).
pub(crate) struct RawModeGuard {
    fd: std::os::fd::RawFd,
    saved: libc::termios,
}

impl RawModeGuard {
    pub(crate) fn enter_stdin() -> std::io::Result<Option<Self>> {
        Self::enter_fd(0)
    }

    /// Raw mode on any terminal fd (production passes stdin; tests pass
    /// a pty slave so the real termios round-trips without touching the
    /// test runner's stdin).
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
        raw.c_cc[libc::VTIME] = 1;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(Self { fd, saved }))
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

/// Non-blocking key poll on stdin (100 ms VTIME slices when raw;
/// immediate EOF/absence otherwise). Arrow escape sequences parse as
/// scrolling; Tab pages the detail views; `q`/`Q`/Ctrl-C/ESC quit.
pub(crate) fn poll_key() -> Option<Key> {
    poll_key_from(&mut read_stdin_byte)
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

fn read_stdin_byte(into: &mut [u8]) -> bool {
    if into.is_empty() {
        return false;
    }
    let outcome = unsafe {
        libc::read(
            0,
            into.as_mut_ptr().cast::<libc::c_void>(),
            into.len() as libc::size_t,
        )
    };
    outcome == into.len() as isize
}

/// Cooperative stop flag for the dashboard loop: SIGINT/SIGTERM/
/// SIGHUP set it (signal-safe atomics only, like the capture loops);
/// the loop polls it every tick and exits through the guards, so the
/// terminal restores on operator stops and supervisor kills alike.
/// SIGKILL cannot be caught — its terminal needs `reset(1)`.
pub(crate) struct StopFlag {
    stop: Arc<std::sync::atomic::AtomicBool>,
    _hooks: Vec<signal_hook::SigId>,
}

// `signal_hook::low_level::register` is process-global; the dashboard
// runs once per process, so the hooks live for the run.
impl StopFlag {
    pub(crate) fn install() -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hooks = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let flag = Arc::clone(&stop);
            // The callback is the signal-safe minimum: one atomic
            // store, no allocation, no I/O, no locks.
            let hook = unsafe {
                signal_hook::low_level::register(signal, move || {
                    flag.store(true, Ordering::SeqCst);
                })
            };
            if let Ok(id) = hook {
                hooks.push(id);
            }
        }
        Self {
            stop,
            _hooks: hooks,
        }
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// True when `fd` names a terminal (the dashboard's honesty gate:
/// interactive frames require a TTY; pipes degrade to snapshots).
pub(crate) fn fd_is_tty(fd: std::os::fd::RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Open stdout (fd 1) as a terminal file for frame writes + guard
/// restoration. The fd is never closed here (`try_clone` owns a
/// duplicate; the original stays the process's stdout).
pub(crate) fn stdout_terminal() -> std::io::Result<File> {
    use std::os::fd::FromRawFd as _;
    // Check BEFORE wrapping: from_raw_fd(-1) on dup failure would
    // violate the ownership contract (Drop would close an fd we
    // never owned).
    let duped = unsafe { libc::dup(1) };
    if duped < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(duped) })
}

#[cfg(test)]
#[path = "inventory_dashboard_tests.rs"]
mod tests;
