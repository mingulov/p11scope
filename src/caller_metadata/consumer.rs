//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pure consumers of the one immutable metadata frame. No acquisition here.

use super::presentation::CallerMetadata;
use super::runtime::MetadataFrame;
use crate::inventory_events::EventWriter;
use crate::inventory_present::Presentation;

/// Compact detail text. IDs come only from fixed canonical parser values.
pub(crate) fn detail(metadata: CallerMetadata, at_ns: u64) -> String {
    let mut parts = vec![format!("caller context {}", metadata.status.label())];
    if let Some(uid) = metadata.pod.uid {
        parts.push(format!("pod {} (hint)", uid.as_str()));
    }
    if let Some(id) = metadata.container.id {
        parts.push(format!("container {} (hint)", id.as_str()));
    }
    if let Some(ended) = metadata.sample_ended_ns {
        parts.push(format!(
            "sampled at {ended} ns; age {} ms; endpoint sample only",
            at_ns.saturating_sub(ended) / 1_000_000
        ));
    }
    if let Some(reason) = metadata.reason {
        parts.push(reason.label().into());
    }
    parts.join(" / ")
}

/// Semantic payload equality excludes only observation time and sample serial.
/// Migration, failed refresh, stale, retirement and every component cause count.
fn same_payload(mut left: CallerMetadata, mut right: CallerMetadata) -> bool {
    for value in [&mut left, &mut right] {
        value.revision = 0;
        value.sample_started_ns = None;
        value.sample_ended_ns = None;
    }
    left == right
}

/// Keep one charged immutable frame, rather than another4096-DTO digest table.
/// A pass emits at most the existing4096 retained caller bound. Rotation and
/// write failures use the existing event transport; this adds no lossless claim.
#[derive(Default)]
pub(crate) struct MetadataEmitter {
    previous: MetadataFrame,
}
impl MetadataEmitter {
    pub(crate) fn emit(
        &mut self,
        writer: &mut EventWriter,
        presentation: &Presentation,
        at_ns: u64,
        force: bool,
    ) -> Result<usize, String> {
        if !presentation.caller_metadata.summary.enabled {
            return Ok(0);
        }
        let mut emitted = 0;
        for caller in presentation
            .callers
            .iter()
            .take(super::presentation::MAX_CALLER_METADATA_RECORDS)
        {
            let Some(metadata) = presentation.caller_metadata.metadata(caller.id) else {
                continue;
            };
            let old = self.previous.metadata(caller.id);
            if !force
                && self.previous.contains(caller.id)
                && old.is_some_and(|old| same_payload(old, metadata))
            {
                continue;
            }
            writer.append("caller_metadata_changed", serde_json::json!({
                "caller": caller.id.label(), "revision": metadata.revision.to_string(), "metadata": metadata,
            }), at_ns)?;
            emitted += 1;
        }
        self.previous = presentation.caller_metadata.clone();
        Ok(emitted)
    }
}

#[cfg(test)]
mod tests {
    use super::super::acquisition::{NumericAbsence, SampleValidity, UncommittedSample};
    use super::super::presentation::{MetadataReason, MetadataStatus};
    use super::*;

    fn healthy() -> CallerMetadata {
        let now = std::time::Instant::now();
        let sample = UncommittedSample {
            membership: super::super::parse_cgroup_membership(
                format!("0::/docker/{}\n", "a".repeat(64)).as_bytes(),
            ),
            validity: SampleValidity::EndpointSampleOnly,
            numeric: NumericAbsence::NamespaceUnresolved,
            started: now,
            ended: now,
        };
        CallerMetadata::sampled(1, 10, 20, &sample)
    }

    #[test]
    fn unchanged_refresh_ignores_time_but_migration_failure_stale_retirement_change() {
        let first = healthy();
        let mut refresh = first;
        refresh.revision = 2;
        refresh.sample_started_ns = Some(100);
        refresh.sample_ended_ns = Some(110);
        assert!(same_payload(first, refresh));
        assert!(!same_payload(first, first.to_stale()));
        assert!(!same_payload(first, first.to_historical()));
        assert!(!same_payload(
            first,
            CallerMetadata::unknown(MetadataReason::ReadFailed, 2)
        ));
        let mut migrated = first;
        migrated.container.id = None;
        assert!(!same_payload(first, migrated));
    }

    #[test]
    fn detail_labels_hint_age_endpoint_only_and_cause_without_paths() {
        let label = detail(healthy(), 2_000_020);
        assert!(label.contains(&"a".repeat(64)));
        assert!(label.contains("(hint)"));
        assert!(label.contains("age 2 ms"));
        assert!(label.contains("endpoint sample only"));
        assert!(!label.contains("/docker/"));
        assert!(
            detail(CallerMetadata::unknown(MetadataReason::ReadFailed, 3), 0)
                .contains("read_failed")
        );
        assert_eq!(healthy().to_stale().status, MetadataStatus::Stale);
    }
}
