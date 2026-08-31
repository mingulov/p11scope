//! Internal-only attribution for published discovery skips.
//!
//! `render::capture_skipped_out` deliberately flattens every internal loss to
//! one of a handful of categorical public reasons, and the plan deduplicates
//! per exact `(subject, reason)` pair. Both are required — the public document
//! must not name paths, pids or error chains, and one provider ten processes
//! map is one loss — but together they make a published record impossible to
//! trace back to the code that raised it, and impossible to tell "34 contexts
//! collapsed to one record" from "one context raised one record".
//!
//! This facility records, for every internal skip, the site that raised it
//! (`file:line`, via `#[track_caller]`) and how many times that site raised
//! that exact pair before deduplication. It is compiled in only with the
//! `skip-attribution` Cargo feature — the same build-feature gate the
//! `unsafe-unvalidated-metadata` diagnostic surface uses — and it writes to
//! stderr only. Nothing here reaches the capture document, its schema, or the
//! privacy allowlist: `report` is the only emitter and it is never consulted
//! by any renderer.

use super::scan::Skipped;

#[cfg(feature = "skip-attribution")]
mod imp {
    use super::Skipped;
    use crate::render;
    use std::collections::BTreeMap;
    use std::panic::Location;
    use std::sync::{Mutex, OnceLock};

    /// `(subject, reason)` → `file:line` → times raised before deduplication.
    type Ledger = BTreeMap<(String, String), BTreeMap<String, u64>>;

    // ponytail: process-global. One p11scope process is one capture, and the
    // alternative is threading a diagnostic through every `DiscoveryCounters`
    // clone and merge in the engine. Move it onto `Engine` if the binary ever
    // runs two captures at once.
    fn ledger() -> &'static Mutex<Ledger> {
        static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
        LEDGER.get_or_init(Mutex::default)
    }

    fn record(site: String, skip: &Skipped) {
        let mut ledger = ledger().lock().unwrap_or_else(|e| e.into_inner());
        *ledger
            .entry((skip.subject.clone(), skip.reason.clone()))
            .or_default()
            .entry(site)
            .or_default() += 1;
    }

    #[track_caller]
    pub fn note(skip: &Skipped) {
        record(site_of(Location::caller()), skip);
    }

    #[track_caller]
    pub fn note_all(skips: &[Skipped]) {
        let site = site_of(Location::caller());
        for skip in skips {
            record(site.clone(), skip);
        }
    }

    fn site_of(location: &Location<'static>) -> String {
        format!("{}:{}", location.file(), location.line())
    }

    fn sites_of(skip: &Skipped) -> String {
        let ledger = ledger().lock().unwrap_or_else(|e| e.into_inner());
        match ledger.get(&(skip.subject.clone(), skip.reason.clone())) {
            None => "<unattributed>".into(),
            Some(sites) => sites
                .iter()
                .map(|(site, count)| format!("{site} x{count}"))
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    /// One line per published record, then one per internal pair that never
    /// reached the document (deduplicated away, filtered, or rebuilt out).
    pub fn lines(published: &[Skipped]) -> Vec<String> {
        let mut out = vec![format!("{} published record(s)", published.len())];
        for (index, skip) in published.iter().enumerate() {
            out.push(format!(
                "[{index}] {:?} <- {} :: subject={:?} reason={:?}",
                render::capture_skipped_out(skip).reason,
                sites_of(skip),
                skip.subject,
                skip.reason,
            ));
        }
        let ledger = ledger().lock().unwrap_or_else(|e| e.into_inner());
        for ((subject, reason), sites) in ledger.iter() {
            let published = published
                .iter()
                .any(|s| &s.subject == subject && &s.reason == reason);
            if published {
                continue;
            }
            let sites = sites
                .iter()
                .map(|(site, count)| format!("{site} x{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(format!(
                "[not published] {sites} :: subject={subject:?} reason={reason:?}"
            ));
        }
        out
    }
}

#[cfg(not(feature = "skip-attribution"))]
mod imp {
    use super::Skipped;

    #[track_caller]
    pub fn note(_skip: &Skipped) {}

    #[track_caller]
    pub fn note_all(_skips: &[Skipped]) {}

    pub fn lines(_published: &[Skipped]) -> Vec<String> {
        Vec::new()
    }
}

pub use imp::{note, note_all};

/// Stderr only, once per capture, right where the public `skipped` array is
/// assembled. A no-op without the `skip-attribution` feature.
pub fn report(published: &[Skipped]) {
    for line in imp::lines(published) {
        eprintln!("p11scope: skip-attribution: {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render;

    fn skip(subject: &str, reason: &str) -> Skipped {
        Skipped {
            subject: subject.into(),
            reason: reason.into(),
        }
    }

    /// The seam: the facility observes, it never feeds. Whatever the ledger
    /// holds — empty (feature off) or fully populated (feature on) — the
    /// public records rendered from the same internal skips are byte-identical.
    #[test]
    fn attribution_leaves_the_public_records_byte_identical() {
        let internal = vec![
            skip(
                "owned initial-set discovery",
                "the child had not mapped it yet",
            ),
            skip(
                "live loader discovery",
                "a loader hit named a retired context",
            ),
        ];
        let render_public = |skips: &[Skipped]| {
            serde_json::to_string(
                &skips
                    .iter()
                    .map(render::capture_skipped_out)
                    .collect::<Vec<_>>(),
            )
            .expect("public records serialize")
        };

        let before = render_public(&internal);
        note_all(&internal);
        note(&internal[0]);
        note(&skip("process view", "never published"));
        report(&internal);
        let after = render_public(&internal);

        assert_eq!(
            before, after,
            "recording attribution must not change the published records"
        );
    }

    /// …and with the feature on it must actually attribute: the site that
    /// raised the pair, its pre-deduplication count, and the pairs that never
    /// reached the document.
    #[cfg(feature = "skip-attribution")]
    #[test]
    fn attribution_names_the_site_its_count_and_the_unpublished_pairs() {
        // Unique to this test: the ledger is process-global and shared with
        // every sibling test in this binary.
        let internal = vec![skip(
            "live loader discovery",
            "attribution self-test: context never bound",
        )];
        for _ in 0..2 {
            note(&internal[0]);
        }
        note(&skip(
            "process view",
            "attribution self-test: deduplicated away",
        ));

        // The ledger is process-global and the sibling test shares it, so
        // assert on content, not on position.
        let lines = imp::lines(&internal);
        assert_eq!(lines[0], "1 published record(s)", "{lines:#?}");
        assert!(
            lines[1].contains("attribution.rs:")
                && lines[1].contains(" x2")
                && lines[1].contains("\"discovery unavailable\""),
            "the published record names its site, pre-dedup count and public reason: {lines:#?}"
        );
        assert!(
            lines.iter().any(|line| line.starts_with("[not published]")
                && line.contains("attribution self-test: deduplicated away")
                && line.contains("attribution.rs:")),
            "internal pairs that never reached the document are listed: {lines:#?}"
        );
    }
}
