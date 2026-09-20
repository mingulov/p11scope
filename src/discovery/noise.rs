//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery-noise aggregation (Task 3.2, S1).
//!
//! Live `--system` discovery emits one stderr line per skipped object view
//! (~380-514 lines/run pre-Phase-1: 231 ESRCH, 122 maps-snapshot, 20 ENOENT,
//! plus refusals). This module collapses that repetition into per-class
//! summaries with counts: the first full sample per class plus `… ×N`,
//! categorical.
//!
//! Classes are finite and PID-free; first samples are scrubbed of raw PIDs
//! (`/proc/<pid>`, `pid <n>`) and addresses (`0x…`) so the operator channel
//! never leaks target layout.

use std::collections::BTreeMap;

/// Finite categorical classes for discovery stderr noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoveryNoiseClass {
    /// The process ended mid-scan (ESRCH / generation changed).
    ProcessEnded,
    /// The `/proc/<pid>/maps` snapshot was refused whole.
    MapsSnapshot,
    /// A mapped object file went missing (ENOENT).
    ObjectMissing,
    /// A scope member could not be retained or scanned (unproven loss).
    ProcessView,
    /// An accepted generation changed during attach preparation.
    StaleView,
    /// Anything else discovery skipped.
    Other,
}

impl DiscoveryNoiseClass {
    /// Categorical label for the operator channel. Finite, stable, PID-free.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ProcessEnded => "process-ended",
            Self::MapsSnapshot => "maps-snapshot",
            Self::ObjectMissing => "object-missing",
            Self::ProcessView => "process-view",
            Self::StaleView => "stale-view",
            Self::Other => "other",
        }
    }
}

/// Classify one `(subject, reason)` skip into its noise class. Pure: no I/O,
/// no allocation beyond the returned enum. Order matters: the maps-snapshot
/// and stale-view checks precede the process-ended check because their reasons
/// contain overlapping substrings (`generation changed`).
pub fn classify_discovery_noise(subject: &str, reason: &str) -> DiscoveryNoiseClass {
    if reason.contains("mapping validation unavailable")
        || reason.contains("empty or truncated")
        || reason.contains("empty /proc maps")
        || reason.contains("reversed or overlapping")
        || reason.contains("maps snapshot was refused")
    {
        DiscoveryNoiseClass::MapsSnapshot
    } else if reason.contains("accepted process generation changed") {
        DiscoveryNoiseClass::StaleView
    } else if reason.contains("No such process")
        || reason.contains("os error 3")
        || reason.contains("exited before discovery")
        || reason.contains("generation changed")
        || reason.contains("ESRCH")
    {
        DiscoveryNoiseClass::ProcessEnded
    } else if reason.contains("No such file or directory")
        || reason.contains("os error 2")
        || reason.contains("ENOENT")
    {
        DiscoveryNoiseClass::ObjectMissing
    } else if subject == "process view"
        || reason.contains("could not be retained")
        || reason.contains("could not be scanned")
        || reason.contains("could not be pinned")
        || reason.contains("process-view capacity")
    {
        DiscoveryNoiseClass::ProcessView
    } else {
        DiscoveryNoiseClass::Other
    }
}

/// Scrub raw PIDs and addresses from operator-channel text: `/proc/<digits>`
/// becomes `/proc/<pid>`, `pid <digits>` (any ASCII case) becomes
/// `pid <pid>`, and `0x<hex>` becomes `0x<addr>`. Byte-scans ASCII patterns
/// only, so non-ASCII path bytes pass through untouched. Idempotent.
pub fn scrub_discovery_noise_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if text[index..].starts_with("/proc/") {
            let mut end = index + "/proc/".len();
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > index + "/proc/".len() {
                out.push_str("/proc/<pid>");
                index = end;
                continue;
            }
        }
        if index + 3 <= bytes.len()
            && bytes[index..index + 3].eq_ignore_ascii_case(b"pid")
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
        {
            let mut space_end = index + 3;
            while space_end < bytes.len() && bytes[space_end] == b' ' {
                space_end += 1;
            }
            if space_end > index + 3 && space_end < bytes.len() && bytes[space_end].is_ascii_digit()
            {
                out.push_str(&text[index..space_end]);
                out.push_str("<pid>");
                let mut digit_end = space_end;
                while digit_end < bytes.len() && bytes[digit_end].is_ascii_digit() {
                    digit_end += 1;
                }
                index = digit_end;
                continue;
            }
        }
        if index + 2 < bytes.len()
            && bytes[index] == b'0'
            && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X')
            && bytes[index + 2].is_ascii_hexdigit()
        {
            out.push_str(&text[index..index + 2]);
            out.push_str("<addr>");
            let mut end = index + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            index = end;
            continue;
        }
        let ch = text[index..].chars().next().expect("non-empty remainder");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

#[derive(Debug, Clone)]
struct ClassEntry {
    count: u64,
    first_sample: String,
}

/// Per-class discovery-noise accumulator: counts plus the first full sample.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryNoiseAggregator {
    entries: BTreeMap<DiscoveryNoiseClass, ClassEntry>,
}

impl DiscoveryNoiseAggregator {
    /// Record one `discovery skipped` pair.
    pub fn note_skip(&mut self, subject: &str, reason: &str) {
        let class = classify_discovery_noise(subject, reason);
        let entry = self.entries.entry(class).or_insert_with(|| {
            let scrubbed_subject = scrub_discovery_noise_text(subject);
            let scrubbed_reason = scrub_discovery_noise_text(reason);
            let sample = format!(
                "discovery skipped {} — {}",
                crate::render::escape_controls(&scrubbed_subject),
                crate::render::escape_controls(&scrubbed_reason)
            );
            ClassEntry {
                count: 0,
                first_sample: sample,
            }
        });
        entry.count = entry.count.saturating_add(1);
    }

    /// Record one unreadable scope member. `detail` may name `pid`; the stored
    /// sample never does. Bare-pid replacement applies only to multi-digit pids
    /// so small errnos (`os error 2`) are never rewritten.
    pub fn note_unreadable(&mut self, pid: u32, detail: &str) {
        let mut scrubbed = detail.to_string();
        if pid >= 100 {
            let needle = pid.to_string();
            if scrubbed.contains(&needle) {
                scrubbed = scrubbed.replace(&needle, "<pid>");
            }
        }
        scrubbed = scrub_discovery_noise_text(&scrubbed);
        self.note_skip("process view", &scrubbed);
    }

    /// Exact count for one class (0 when unseen).
    pub fn count(&self, class: DiscoveryNoiseClass) -> u64 {
        self.entries.get(&class).map_or(0, |entry| entry.count)
    }

    /// Total notes across all classes.
    pub fn total(&self) -> u64 {
        self.entries
            .values()
            .fold(0u64, |acc, entry| acc.saturating_add(entry.count))
    }

    /// True when nothing has been noted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merge another accumulator in: counts sum, earliest first sample wins.
    pub fn merge(&mut self, other: &Self) {
        for (class, other_entry) in &other.entries {
            match self.entries.get_mut(class) {
                Some(entry) => {
                    entry.count = entry.count.saturating_add(other_entry.count);
                }
                None => {
                    self.entries.insert(*class, other_entry.clone());
                }
            }
        }
    }

    /// One categorical summary line per class, ordered by class. A lone sample
    /// renders bare; repeats render the first full sample plus `… ×N` with the
    /// exact class count.
    pub fn lines(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(class, entry)| {
                if entry.count <= 1 {
                    format!(
                        "p11scope: discovery: {}: {}",
                        class.label(),
                        entry.first_sample
                    )
                } else {
                    format!(
                        "p11scope: discovery: {} ×{}: {} … ×{}",
                        class.label(),
                        entry.count,
                        entry.first_sample,
                        entry.count
                    )
                }
            })
            .collect()
    }

    /// Emit the summaries to stderr, one line per class.
    pub fn report(&self) {
        for line in self.lines() {
            eprintln!("{line}");
        }
    }

    /// Drop all accumulated notes (after reporting).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESRCH_REASON: &str = "open failed: No such process (os error 3)";
    const MAPS_REASON: &str = "memory scan refused: initial mapping validation unavailable: empty or truncated /proc maps snapshot";
    const ENOENT_REASON: &str = "open failed: No such file or directory (os error 2)";

    #[test]
    fn aggregates_live_reference_classes_with_exact_counts() {
        let mut noise = DiscoveryNoiseAggregator::default();
        for index in 0..231 {
            noise.note_skip(
                &format!("/snap/firefox/8929/usr/lib/firefox/libsoftokn3-{index}.so"),
                ESRCH_REASON,
            );
        }
        for _ in 0..122 {
            noise.note_skip("capture discovery", MAPS_REASON);
        }
        for index in 0..20 {
            noise.note_skip(
                &format!("/usr/lib/x86_64-linux-gnu/libnss-{index}.so"),
                ENOENT_REASON,
            );
        }
        assert_eq!(
            noise.count(DiscoveryNoiseClass::ProcessEnded),
            231,
            "ESRCH class must count exactly"
        );
        assert_eq!(
            noise.count(DiscoveryNoiseClass::MapsSnapshot),
            122,
            "maps-snapshot class must count exactly"
        );
        assert_eq!(
            noise.count(DiscoveryNoiseClass::ObjectMissing),
            20,
            "ENOENT class must count exactly"
        );
        assert_eq!(noise.total(), 373, "total must be the exact sum");
        let lines = noise.lines();
        assert_eq!(lines.len(), 3, "one summary line per class: {lines:#?}");
        let joined = lines.join("\n");
        assert!(
            joined.contains("… \u{00d7}231"),
            "ESRCH summary carries its exact count: {joined:?}"
        );
        assert!(
            joined.contains("… \u{00d7}122"),
            "maps summary carries its exact count: {joined:?}"
        );
        assert!(
            joined.contains("… \u{00d7}20"),
            "ENOENT summary carries its exact count: {joined:?}"
        );
        assert!(
            joined.contains("libsoftokn3-0.so") && joined.contains(ESRCH_REASON),
            "first ESRCH sample is preserved full: {joined:?}"
        );
        assert!(
            joined.contains(MAPS_REASON),
            "first maps sample is preserved full: {joined:?}"
        );
    }

    #[test]
    fn aggregated_output_contains_no_pids_or_addresses() {
        let mut noise = DiscoveryNoiseAggregator::default();
        noise.note_skip("/proc/4242/mem", ESRCH_REASON);
        noise.note_skip(
            "/proc/9999/root/usr/lib/libnss.so",
            "open failed: No such file or directory (os error 2)",
        );
        noise.note_skip(
            "capture discovery",
            "partial snapshot of one data mapping: read 3 of 9 bytes at 0x7f8b12345678",
        );
        noise.note_unreadable(
            4242,
            "the process generation could not be pinned: pid 4242 exited",
        );
        noise.note_unreadable(
            7777,
            "the process could not be scanned: open /proc/7777/mem failed at 0xdeadBEEF",
        );
        let joined = noise.lines().join("\n");
        assert!(!joined.is_empty(), "noise must render summaries");
        for leaked in [
            "4242",
            "9999",
            "7777",
            "0x7f8b12345678",
            "0xdeadBEEF",
            "0xDEADBEEF",
        ] {
            assert!(
                !joined.contains(leaked),
                "aggregated output must not leak {leaked:?}: {joined:?}"
            );
        }
        assert!(
            joined.contains("process-ended")
                || joined.contains("object-missing")
                || joined.contains("process-view")
                || joined.contains("other"),
            "summaries stay categorical: {joined:?}"
        );
    }

    #[test]
    fn single_occurrence_has_no_ellipsis_suffix() {
        let mut noise = DiscoveryNoiseAggregator::default();
        noise.note_skip("capture discovery", MAPS_REASON);
        let lines = noise.lines();
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(
            lines[0].contains(MAPS_REASON),
            "single sample is preserved: {:?}",
            lines[0]
        );
        assert!(
            !lines[0].contains("… \u{00d7}"),
            "a single occurrence needs no repetition suffix: {:?}",
            lines[0]
        );
    }

    #[test]
    fn merge_sums_counts_and_keeps_earliest_sample() {
        let mut left = DiscoveryNoiseAggregator::default();
        left.note_skip("/snap/a.so", ESRCH_REASON);
        left.note_skip("/snap/b.so", ESRCH_REASON);
        let mut right = DiscoveryNoiseAggregator::default();
        right.note_skip("/snap/c.so", ESRCH_REASON);
        right.note_skip("capture discovery", MAPS_REASON);
        left.merge(&right);
        assert_eq!(left.count(DiscoveryNoiseClass::ProcessEnded), 3);
        assert_eq!(left.count(DiscoveryNoiseClass::MapsSnapshot), 1);
        let joined = left.lines().join("\n");
        assert!(
            joined.contains("/snap/a.so"),
            "merge keeps the earliest first sample: {joined:?}"
        );
        assert!(
            !joined.contains("/snap/c.so"),
            "later samples collapse into the count: {joined:?}"
        );
    }

    #[test]
    fn classification_is_categorical_and_stable() {
        assert_eq!(
            classify_discovery_noise("/snap/x.so", ESRCH_REASON),
            DiscoveryNoiseClass::ProcessEnded
        );
        assert_eq!(
            classify_discovery_noise("capture discovery", MAPS_REASON),
            DiscoveryNoiseClass::MapsSnapshot
        );
        assert_eq!(
            classify_discovery_noise("/usr/lib/y.so", ENOENT_REASON),
            DiscoveryNoiseClass::ObjectMissing
        );
        assert_eq!(
            classify_discovery_noise(
                "process view",
                "accepted process generation changed during attach preparation; its discovery claims were removed"
            ),
            DiscoveryNoiseClass::StaleView
        );
        for class in [
            DiscoveryNoiseClass::ProcessEnded,
            DiscoveryNoiseClass::MapsSnapshot,
            DiscoveryNoiseClass::ObjectMissing,
            DiscoveryNoiseClass::ProcessView,
            DiscoveryNoiseClass::StaleView,
            DiscoveryNoiseClass::Other,
        ] {
            let label = class.label();
            assert!(
                !label.contains("4242") && !label.contains("0x"),
                "labels are categorical, never data: {label:?}"
            );
        }
    }
}
