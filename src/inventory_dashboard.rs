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
//! Read-only: scrolling only — no filtering/selection (U2), no
//! capture control. ANSI stays on the terminal stream; JSON paths
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

/// Read-only view state: the scroll position only. There is no
/// filtering/selection (U2) and no capture control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DashboardState {
    /// Index of the first visible edge.
    pub scroll: usize,
}

impl DashboardState {
    pub(crate) fn new() -> Self {
        Self { scroll: 0 }
    }

    pub(crate) fn scroll_down(&mut self, total_edges: usize) {
        self.scroll = self
            .scroll
            .saturating_add(1)
            .min(total_edges.saturating_sub(1));
    }

    pub(crate) fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub(crate) fn clamp(&mut self, total_edges: usize) {
        self.scroll = self.scroll.min(total_edges.saturating_sub(1));
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
                "coverage: {} gaps {} refusals {} suppressed | endpoints {}/{}",
                presentation.gaps.len(),
                budgets.refusals(),
                presentation.gaps_suppressed,
                budgets.endpoints_occupied,
                budgets.endpoints_limit,
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
    let total = presentation.edges.len();
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
                "coverage: {} gaps {} refusals {} suppressed | endpoints {}/{} | semantic {} ({} held, {} unknown, {} refused)",
                presentation.gaps.len(),
                budgets.refusals(),
                presentation.gaps_suppressed,
                budgets.endpoints_occupied,
                budgets.endpoints_limit,
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
    // Log rows adapt to short terminals; the edge table takes the rest.
    let log_rows: usize = if height >= 20 { 4 } else { 2 };
    // Header (3) + edge-table header (1) + log header (1) + log rows + footer (1).
    let edge_room = height.saturating_sub(3 + 1 + 1 + log_rows + 1).max(2);
    let (mut edge_lines, shown) = render_edge_window(presentation, width, edge_room, scroll);
    let (first, last) = visible_edge_range(shown, total, scroll);
    lines.push(truncate_cell(
        &format!("--- edges {first}-{last} of {total} (scroll narrows this view only; totals above cover everything) ---"),
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
    lines.push(truncate_cell(
        &format!(
            "scroll {scroll}/{max_scroll} | showing edges {first}-{last} of {total} | up/down j/k scroll, q quit"
        ),
        width,
    ));
    lines.truncate(height);
    lines
}

/// Render the visible edge window as whole edge blocks: `^ +K more
/// above` when scrolled, then blocks, then `v +M more below` when the
/// room runs out. Every block carries full exact state labels (items
/// wrap on ` | ` boundaries, never mid-label).
/// Returns the window lines plus the count of edge blocks actually
/// emitted (the header range derives from this count, never from
/// re-parsing rendered text).
fn render_edge_window(
    presentation: &Presentation,
    width: usize,
    room: usize,
    scroll: usize,
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
        let block = render_edge_block(presentation, edge, width);
        // Reserve one line for the `more below` marker when edges
        // remain after this block.
        let remaining_after = total - scroll - shown - 1;
        let need = block.len() + usize::from(remaining_after > 0);
        if lines.len() + need > room {
            break;
        }
        shown += 1;
        lines.extend(block);
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
    if lines.is_empty() {
        lines.push(truncate_cell("(no edges fit; enlarge the terminal)", width));
    }
    (lines, shown)
}

/// Dashboard mechanism summary: the count plus up to
/// [`DASHBOARD_MAX_MECH_NAMES`] registered names (verbatim hex for
/// unregistered ids), with an explicit `+N more` marker past the cap —
/// bounded, never silent.
pub(crate) const DASHBOARD_MAX_MECH_NAMES: usize = 8;

fn semantic_mechs_item(mechanisms: &[crate::inventory_present::MechanismView]) -> String {
    if mechanisms.is_empty() {
        return "mechs 0: none".to_string();
    }
    let mut names: Vec<String> = mechanisms
        .iter()
        .take(DASHBOARD_MAX_MECH_NAMES)
        .map(|mech| {
            mech.name
                .map(str::to_string)
                .unwrap_or_else(|| format!("0x{:x}", mech.id))
        })
        .collect();
    let hidden = mechanisms.len().saturating_sub(names.len());
    if hidden > 0 {
        names.push(format!("+{hidden} more"));
    }
    format!("mechs {}: {}", mechanisms.len(), names.join(", "))
}

/// One edge as an identity line plus wrapped exact state items.
fn render_edge_block(
    presentation: &Presentation,
    edge: &crate::inventory_present::EdgeView,
    width: usize,
) -> Vec<String> {
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
    let mut lines = vec![truncate_cell(
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
    )];
    let mut items = vec![
        format!("presence {}", edge.presence.label()),
        format!("capture {}", edge.capture.label()),
        format!("activity {}", edge.activity.label()),
        format!("entries {}", edge.entry_count),
        format!("semantics {}", edge.semantics.label),
    ];
    if let Some(operations) = edge.semantics.operations.as_ref() {
        items.push(semantic_mechs_item(&edge.semantics.mechanisms));
        items.push(format!(
            "ops {} calls {} started {} completed {} cancelled {} failed {} unknown {} orphans {} dropped",
            operations.calls,
            operations.started,
            operations.completed,
            operations.cancelled,
            operations.failed,
            operations.unknown,
            operations.orphans,
            operations.dropped,
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
    // Greedy wrap on item boundaries; no item is split mid-label.
    let mut current = String::from("  ");
    for item in &items {
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

/// The 1-based visible edge range named in the table header/footer.
/// Derived from the emitted-block COUNT the window returns, not from
/// arithmetic over the scroll or by re-parsing rendered text — the
/// header can never claim edges the frame does not show, and a
/// future reformat cannot silently degrade the range.
fn visible_edge_range(shown: usize, total: usize, scroll: usize) -> (usize, usize) {
    if total == 0 {
        return (0, 0);
    }
    if shown == 0 {
        let at = scroll.min(total.saturating_sub(1)) + 1;
        return (at, at);
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

/// Dashboard keys: scrolling plus quit. Everything else is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Key {
    Up,
    Down,
    Quit,
}

/// Non-blocking key poll on stdin (100 ms VTIME slices when raw;
/// immediate EOF/absence otherwise). Arrow escape sequences parse as
/// scrolling; `q`/`Q`/Ctrl-C/ESC quit.
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
