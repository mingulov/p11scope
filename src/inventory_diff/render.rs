//! SPDX-License-Identifier: GPL-3.0-or-later
//! Readable rendering of the offline report.

use super::model::{
    CallerEvidence, CallerRef, DiffReport, EdgeEvidence, EdgeRef, ModuleEvidence, ModuleRef,
    Presence, Side, SnapshotSummary,
};
use crate::render::escape_controls;
use std::collections::BTreeMap;
use std::io::{self, Write};
use unicode_width::UnicodeWidthChar as _;

/// Rendering only borrows the pooled report. References never reach the human
/// output: labels, physical descriptions and separate observations do.
pub(super) fn render_text(report: &DiffReport, out: &mut dyn Write) -> io::Result<()> {
    let mut human = Human(out);
    let summary = &report.summary;
    human.line(
        0,
        &format!(
            "Inventory comparison: {} application group{} changed",
            summary.application_groups_changed,
            plural(summary.application_groups_changed)
        ),
    )?;
    human.line(
        2,
        &format!(
            "{} application group{} compared; {} common module content{}",
            summary.application_groups_compared,
            plural(summary.application_groups_compared),
            summary.content_both,
            plural(summary.content_both)
        ),
    )?;
    human.line(
        2,
        &format!(
            "{} new module content{} observed; {} content{} not observed after",
            summary.content_after_only,
            plural(summary.content_after_only),
            summary.content_before_only,
            plural(summary.content_before_only)
        ),
    )?;
    human.line(
        2,
        &format!(
            "{} module path{} changed; {} unresolved observation{}",
            summary.module_paths_changed,
            plural(summary.module_paths_changed),
            summary.unresolved_observations,
            plural(summary.unresolved_observations)
        ),
    )?;
    if report.application_changes.is_empty()
        && report.module_path_changes.is_empty()
        && report
            .module_contents
            .iter()
            .all(|row| row.changes.is_empty())
    {
        human.line(0, "No differences in the compared inventory observations")?;
    }
    let mut previous_path = None;
    for row in &report.application_changes {
        if previous_path != Some(row.key.exe_path_ref) {
            human.blank()?;
            human.identity(
                0,
                "Application",
                &report.comparison.application_paths[row.key.exe_path_ref.0],
            )?;
            previous_path = Some(row.key.exe_path_ref);
        }
        human.line(2, &format!("Module content: {}", presence(row.presence)))?;
        human.line(4, &row.key.sha256)?;
        human.line(
            2,
            &format!("Changed observations: {}", row.changes.join(", ")),
        )?;
        for (name, side, population, edges) in [
            (
                "Before",
                &report.before,
                &row.before_population,
                &row.before,
            ),
            ("After", &report.after, &row.after_population, &row.after),
        ] {
            human.line(
                2,
                &format!(
                    "{name}: {} caller records; {} physical module records; {} edge observations",
                    population.callers.len(),
                    population.modules.len(),
                    edges.len()
                ),
            )?;
            let mut modules = BTreeMap::new();
            for module in &population.modules {
                *modules.entry(*module).or_insert(0usize) += 1;
            }
            for (module, count) in modules {
                human.module_label(4, &side.evidence.modules[module.0], count)?;
            }
        }
    }
    for row in &report.module_path_changes {
        human.blank()?;
        human.line(
            0,
            match row.presence {
                Presence::Both => "Different module content observed at this path:",
                Presence::BeforeOnly => "Recorded module path not observed after:",
                Presence::AfterOnly => "Recorded module path observed after only:",
            },
        )?;
        human.line(2, &row.key.path)?;
        for (name, values) in [("Before", &row.before), ("After", &row.after)] {
            human.line(2, &format!("{name} content descriptions: {}", values.len()))?;
            for value in values {
                human.line(
                    4,
                    value.sha256.as_deref().unwrap_or("Content digest unknown"),
                )?;
            }
        }
    }
    for row in &report.module_contents {
        if row.presence == Presence::Both && row.changes.is_empty() {
            continue;
        }
        human.blank()?;
        human.line(0, &format!("Module content: {}", presence(row.presence)))?;
        human.line(2, &row.key.sha256)?;
        human.line(
            2,
            &format!("Changed observations: {}", row.changes.join(", ")),
        )?;
        for (name, side, records) in [
            ("Before", &report.before, &row.before),
            ("After", &report.after, &row.after),
        ] {
            human.line(
                2,
                &format!(
                    "{name}: {} physical module record{}",
                    records.len(),
                    plural(records.len())
                ),
            )?;
            let mut occurrences = BTreeMap::<ModuleRef, usize>::new();
            for reference in records {
                *occurrences.entry(*reference).or_default() += 1;
            }
            for (reference, count) in occurrences {
                human.module_label(4, &side.evidence.modules[reference.0], count)?;
            }
        }
    }
    // Full shared module details appear once per side, including unchanged and
    // missing-digest records. Fanout edges never repeat admission payloads.
    for (name, side) in [("Before", &report.before), ("After", &report.after)] {
        let mut occurrences = BTreeMap::<ModuleRef, usize>::new();
        for module in &side.evidence.module_occurrences {
            *occurrences.entry(*module).or_default() += 1;
        }
        for (module, count) in occurrences {
            human.blank()?;
            human.line(0, &format!("{name} recorded module details"))?;
            human.module(
                &side.evidence.modules[module.0],
                count,
                side.clock.unit == "ns",
            )?;
        }
    }
    for (name, side) in [("Before", &report.before), ("After", &report.after)] {
        human.blank()?;
        human.snapshot(name, side)?;
    }
    let mut unresolved_groups = BTreeMap::new();
    for row in &report.unresolved {
        let side = match row.side {
            Side::Before => &report.before,
            Side::After => &report.after,
        };
        let caller = row.caller.or_else(|| {
            row.observation
                .map(|reference| side.evidence.edges[reference.0].caller)
        });
        let path = caller
            .and_then(|reference| side.evidence.callers[reference.0].image.exe.as_ref())
            .and_then(|exe| exe.path.as_deref())
            .filter(|path| !path.is_empty());
        unresolved_groups
            .entry((row.side, path))
            .or_insert_with(Vec::new)
            .push(row);
    }
    for ((which, path), group) in unresolved_groups {
        let name = match which {
            Side::Before => "Before",
            Side::After => "After",
        };
        human.blank()?;
        human.line(0, &format!("{name} unresolved observations"))?;
        if let Some(path) = path {
            human.identity(2, "Recorded application", path)?;
        }
        for rows in group.chunk_by(|left, right| left == right) {
            let row = &rows[0];
            let (name, side) = match row.side {
                Side::Before => ("Before", &report.before),
                Side::After => ("After", &report.after),
            };
            human.line(
                2,
                &format!(
                    "{name} unresolved: {} source observation{}",
                    rows.len(),
                    plural(rows.len())
                ),
            )?;
            if let Some(reference) = row.caller {
                let caller = &side.evidence.callers[reference.0];
                human.caller(side, reference.0)?;
                human.line(2, &format!("PID {}: no module observation", caller.pid))?;
            }
            if let Some(reference) = row.module {
                human.line(2, "Content digest unknown")?;
                human.module_label(2, &side.evidence.modules[reference.0], 1)?;
            }
            if let Some(reference) = row.observation {
                let edge = &side.evidence.edges[reference.0];
                human.caller(side, edge.caller.0)?;
                if side.evidence.modules[edge.module.0]
                    .identity
                    .sha256
                    .is_none()
                {
                    human.line(2, "Content digest unknown")?;
                }
                human.module_label(2, &side.evidence.modules[edge.module.0], 1)?;
            }
            human.line(2, &format!("Reasons: {}", row.reasons.join(", ")))?;
        }
    }
    human.blank()?;
    human.line(
        0,
        "Coverage/identity: scope completeness and host/boot continuity are unknown.",
    )?;
    human.line(
        0,
        "Cross-snapshot process and physical continuity are unknown.",
    )?;
    human.line(
        0,
        "Counts describe independent observation windows; no count delta is computed.",
    )?;
    human.line(0, "Not observed after does not prove removal.")?;
    human.line(0, "Application groups use recorded paths.")?;
    human.line(
        0,
        "Instance and detailed semantic changes are not compared.",
    )?;
    for limitation in &report.limitations {
        human.line(2, &format!("Limitation: {limitation}"))?;
    }
    Ok(())
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn presence(value: Presence) -> &'static str {
    match value {
        Presence::Both => "observed in both snapshots",
        Presence::BeforeOnly => "not observed after",
        Presence::AfterOnly => "observed after only",
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|name| !name.is_empty())
        .unwrap_or(path)
}

fn short_label(label: &str) -> String {
    let mut characters = label.chars();
    let prefix: String = characters.by_ref().take(40).collect();
    if characters.next().is_some() {
        format!("{prefix}… (full paths in module details)")
    } else {
        prefix
    }
}

struct Human<'a>(&'a mut dyn Write);

impl Human<'_> {
    /// Width uses the existing Unicode-width dependency; hard wrapping preserves
    /// every character of long path identities rather than truncating them.
    fn line(&mut self, indent: usize, raw: &str) -> io::Result<()> {
        let escaped = escape_controls(raw);
        let prefix = " ".repeat(indent);
        let mut chunk = String::new();
        let mut width = indent;
        for character in escaped.chars() {
            let next = character.width().unwrap_or(0);
            if width + next > 80 && !chunk.is_empty() {
                writeln!(self.0, "{prefix}{chunk}")?;
                chunk.clear();
                width = indent;
            }
            chunk.push(character);
            width += next;
        }
        writeln!(self.0, "{prefix}{chunk}")
    }

    fn blank(&mut self) -> io::Result<()> {
        self.0.write_all(b"\n")
    }

    fn identity(&mut self, indent: usize, kind: &str, path: &str) -> io::Result<()> {
        self.line(indent, &format!("{kind}: {}", basename(path)))?;
        self.line(indent + 2, "Recorded path:")?;
        self.line(indent + 4, path)
    }

    fn module_label(
        &mut self,
        indent: usize,
        module: &ModuleEvidence,
        count: usize,
    ) -> io::Result<()> {
        self.line(
            indent,
            &format!(
                "Module: {}",
                module
                    .paths
                    .first()
                    .map(|path| short_label(basename(path)))
                    .unwrap_or_else(|| "Unknown module path".to_owned())
            ),
        )?;
        self.line(
            indent + 2,
            &format!(
                "device {}:{}; inode {}; {} source record{}",
                module.identity.device.major,
                module.identity.device.minor,
                module.identity.inode,
                count,
                plural(count)
            ),
        )
    }

    fn module(
        &mut self,
        module: &ModuleEvidence,
        count: usize,
        clock_unit_is_ns: bool,
    ) -> io::Result<()> {
        self.module_label(2, module, count)?;
        for path in &module.paths {
            self.line(4, path)?;
        }
        self.line(2, "Content SHA-256:")?;
        self.line(
            4,
            module
                .identity
                .sha256
                .as_deref()
                .unwrap_or("Content digest unknown"),
        )?;
        self.line(
            2,
            &format!(
                "Admission: {}{}",
                module.admission.state.raw,
                if module.admission.state.known {
                    ""
                } else {
                    " (unknown label)"
                }
            ),
        )?;
        if let Some(class) = &module.admission.class {
            self.line(4, &format!("Class: {class}"))?;
        }
        match module.admission.endpoints {
            Some(count) => self.line(4, &format!("Endpoints: {count}"))?,
            None => self.line(4, "Endpoints: unknown (not reported)")?,
        }
        self.line(4, &module.admission.note)?;
        for reason in &module.admission.reasons {
            self.line(4, &format!("Reason: {reason}"))?;
        }
        match &module.admission.history {
            Some(history) => {
                self.line(
                    4,
                    &format!(
                        "Admission history: {} recorded transition{}",
                        history.len(),
                        plural(history.len())
                    ),
                )?;
                // The field name is historical. Unknown snapshot units keep
                // raw values and a finite qualifier; their full string is
                // already available once in the corresponding side metadata.
                let timestamp_unit = if clock_unit_is_ns {
                    "ns"
                } else {
                    "(clock unit unknown)"
                };
                for transition in history {
                    self.line(
                        4,
                        &format!(
                            "{}{} -> {}{} at {} {}",
                            transition.from.raw,
                            if transition.from.known {
                                ""
                            } else {
                                " (unknown label)"
                            },
                            transition.to.raw,
                            if transition.to.known {
                                ""
                            } else {
                                " (unknown label)"
                            },
                            transition.at_ns,
                            timestamp_unit
                        ),
                    )?;
                }
            }
            None => self.line(4, "Admission history: not published")?,
        }
        self.line(
            2,
            &format!(
                "Recorded module lifecycle: {}; unload observed: {}",
                module.lifecycle.raw, module.unloaded_observed
            ),
        )?;
        if let Some(unbound) = &module.unbound_use {
            self.line(
                2,
                &format!(
                    "Unbound use: {} rows; first {}",
                    unbound.rows, unbound.first_ns
                ),
            )?;
            for (reason, rows) in &unbound.reasons {
                self.line(4, &format!("{reason}: {rows}"))?;
            }
        }
        Ok(())
    }

    fn caller(&mut self, side: &SnapshotSummary, reference: usize) -> io::Result<()> {
        let caller = &side.evidence.callers[reference];
        match caller
            .image
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_deref())
            .filter(|path| !path.is_empty())
        {
            Some(_) => self.line(
                2,
                &format!("Recorded application caller PID {}", caller.pid),
            )?,
            None => self.line(2, &format!("Unknown executable (PID {})", caller.pid))?,
        }
        Ok(())
    }

    fn caller_details(&mut self, caller: &CallerEvidence, count: usize) -> io::Result<()> {
        self.line(
            4,
            &format!(
                "Caller PID {}; {} source caller record{}",
                caller.pid,
                count,
                plural(count)
            ),
        )?;
        self.line(4, &format!("Recorded start: {:?}", caller.start_time))?;
        self.line(4, &format!("Start time unit: {}", caller.start_time_unit))?;
        self.line(
            4,
            &format!(
                "Recorded caller lifecycle: {}{}; retired: {}",
                caller.lifecycle.raw,
                if caller.lifecycle.known {
                    ""
                } else {
                    " (unknown label)"
                },
                caller.retired
            ),
        )?;
        if let Some(reason) = &caller.lifecycle_reason {
            self.line(4, &format!("Caller reason: {reason}"))?;
        }
        self.line(
            4,
            &format!(
                "Caller observation window: first {}; last {}",
                caller.first_seen_ns, caller.last_seen_ns
            ),
        )?;
        self.line(
            4,
            &format!(
                "Image authority: {}{}; exec observed: {}",
                caller.image.authority.raw,
                if caller.image.authority.known {
                    ""
                } else {
                    " (unknown label)"
                },
                caller.image.exec_observed
            ),
        )?;
        if let Some(exe) = &caller.image.exe {
            self.line(
                4,
                &format!(
                    "Executable device {}; inode {}; recorded mtime {}:{}",
                    exe.dev, exe.ino, exe.mtime_secs, exe.mtime_nanos
                ),
            )?;
        }
        Ok(())
    }

    fn activity(&mut self, edge: &EdgeEvidence) -> io::Result<()> {
        let coverage = edge.coverage.as_ref();
        if coverage.is_some_and(|c| c.state.known && c.state.raw == "witnessed") {
            self.line(6, "Use witnessed; entry count unavailable")?;
        } else if coverage.is_some_and(|c| c.state.known && c.state.raw == "watched_no_use") {
            self.line(6, "No use observed during recorded watch coverage")?;
        } else if edge.entries.observation.known && edge.entries.observation.raw == "observed" {
            self.line(
                6,
                &format!("at least {} entries observed", edge.entries.count),
            )?;
        } else {
            self.line(
                6,
                &format!("Entry activity unknown: {}", edge.entries.observation.raw),
            )?;
            self.line(
                6,
                &format!(
                    "Reported count {}; coverage limits its interpretation",
                    edge.entries.count
                ),
            )?;
        }
        match coverage {
            Some(c) if c.state.known && c.state.raw != "unknown" => {
                self.line(6, &format!("Coverage: {}", c.state.raw))?
            }
            Some(c) => self.line(
                6,
                &format!("Coverage unknown (reported label: {})", c.state.raw),
            )?,
            None => self.line(6, "Coverage unknown (not published)")?,
        }
        if let Some(c) = coverage {
            if c.lossy == Some(true) {
                self.line(6, "Coverage lossy; observations are lower bounds")?;
            }
            if let Some(reason) = &c.reason {
                self.line(6, &format!("Coverage reason: {}", reason.raw))?;
            }
            if let Some(detail) = &c.detail {
                self.line(6, &format!("Coverage detail: {detail}"))?;
            }
            self.line(
                6,
                &format!(
                    "Coverage window: since {:?}; until {:?}; first {:?}",
                    c.since_ns, c.until_ns, c.first_ns
                ),
            )?;
        }
        if edge.entries.saturated {
            self.line(
                6,
                &format!(
                    "Entry counter saturated (reported cap {})",
                    edge.entries.cap
                ),
            )?;
        }
        if edge.entries.in_flight {
            self.line(
                6,
                "Entry in flight; completed operations are not established",
            )?;
        }
        self.line(6, &format!("Mapping: {}", edge.mapping.state.raw))?;
        if let Some(reason) = &edge.mapping.reason {
            self.line(6, &format!("Mapping reason: {reason}"))?;
        }
        self.line(
            6,
            &if edge.semantics.known {
                format!("Semantic availability: {}", edge.semantics.raw)
            } else {
                format!(
                    "Semantic availability unknown (reported label: {})",
                    edge.semantics.raw
                )
            },
        )
    }

    fn snapshot(&mut self, name: &str, side: &SnapshotSummary) -> io::Result<()> {
        self.line(
            0,
            &format!(
                "{name} observation window: {}..{} {} ({})",
                side.observation.started_ns,
                side.observation.ended_ns,
                side.clock.unit,
                side.clock.basis
            ),
        )?;
        self.line(
            2,
            &format!(
                "Recorded scope: {}; scope completeness {} (PARTIAL interpretation)",
                side.scope, side.scope_completeness
            ),
        )?;
        self.line(
            2,
            &format!(
                "Reported gaps {}; suppressed gaps {}",
                side.reported_gaps, side.suppressed_gaps
            ),
        )?;
        for (resource, refused) in &side.refusals.budget_counters {
            match refused {
                Some(value) if *value > 0 => {
                    self.line(2, &format!("Reported refusals - {resource}: {value}"))?
                }
                None => self.line(2, &format!("Refusals for {resource}: unknown"))?,
                _ => {}
            }
        }
        if let Some(loss) = &side.loss_evidence.lifecycle {
            self.line(
                2,
                &format!(
                    "Lifecycle evidence: ring loss {}; malformed {}; failed quanta {}",
                    loss.ring_loss, loss.malformed, loss.failed_quanta
                ),
            )?;
        }
        if let Some(witnesses) = &side.loss_evidence.native_witnesses {
            self.line(
                2,
                &format!(
                    "Native witnesses: bound {}; unbound {}; pending {}; integrity {}",
                    witnesses.bound, witnesses.unbound, witnesses.pending, witnesses.integrity
                ),
            )?;
        }
        for gap in &side.gaps {
            self.line(2, &format!("Gap: {}; repeats {}", gap.subject, gap.repeats))?;
            self.line(4, &gap.reason)?;
        }
        // Each pooled full caller fact owns its associations. Large caller
        // labels occur once here, while all edge occurrences stay adjacent to
        // that description without a human join through machine references.
        let mut callers = BTreeMap::<CallerRef, usize>::new();
        for reference in &side.evidence.caller_occurrences {
            *callers.entry(*reference).or_default() += 1;
        }
        let mut associations = BTreeMap::<CallerRef, Vec<EdgeRef>>::new();
        for reference in &side.evidence.edge_occurrences {
            associations
                .entry(side.evidence.edges[reference.0].caller)
                .or_default()
                .push(*reference);
        }
        let mut applications = BTreeMap::new();
        for (reference, count) in callers {
            let path = side.evidence.callers[reference.0]
                .image
                .exe
                .as_ref()
                .and_then(|exe| exe.path.as_deref())
                .filter(|path| !path.is_empty());
            applications
                .entry(path)
                .or_insert_with(Vec::new)
                .push((reference, count));
        }
        for (path, callers) in applications {
            match path {
                Some(path) => self.identity(2, "Recorded application", path)?,
                None => self.line(2, "Unknown executable observations")?,
            }
            for (reference, count) in callers {
                self.caller_details(&side.evidence.callers[reference.0], count)?;
                let edges = associations.remove(&reference).unwrap_or_default();
                for references in edges.chunk_by(|left, right| left == right) {
                    let edge = &side.evidence.edges[references[0].0];
                    self.line(
                        6,
                        &format!(
                            "{} source edge observation{}",
                            references.len(),
                            plural(references.len())
                        ),
                    )?;
                    self.module_label(6, &side.evidence.modules[edge.module.0], 1)?;
                    self.activity(edge)?;
                }
            }
        }
        Ok(())
    }
}
