<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Inspect application presentation — v1 additive fields

`p11scope inspect --pid PID --json` retains document ID
`p11scope/inspect/v1`. Existing `pid`, `scan`, `modules` and `skipped` fields
keep their meanings. The additive root fields are `application` and
`application_status`; consumers that ignore unknown fields remain compatible.

An observed application has exactly:

```json
{
  "application": {
    "path": "/usr/bin/python3",
    "dev": 2049,
    "ino": 12345,
    "mtime_secs": 1780000000,
    "mtime_nanos": 0,
    "start_time": 54321,
    "status": "observed"
  },
  "application_status": "observed"
}
```

This is an illustrative shape, not captured evidence. `dev`, `ino`,
`mtime_secs` and `mtime_nanos` are executable-file metadata;
`start_time` is the retained process start time in Linux clock ticks since boot.
`path` is the observed executable-link path, including any deleted marker.
It identifies a scan-local label, not a package, script, service or trust claim.
An interpreter remains `python3`, `java`, or the observed interpreter basename.
PID remains in the observer's existing `/proc` numbering.

When naming is withheld, `application` is `null`. The finite status is:

| application_status | Meaning |
| --- | --- |
| observed | The producer completed the application receipt around the scan and provider pinning. |
| unavailable | A required executable, path or start-time sample could not be read. A later read cannot repair a missing initial sample. |
| changed | The before/after executable metadata, path or start time differed. |
| lost | The original process pin could no longer validate the sampled generation. |
| not_examined | No completed application receipt was produced, including failed or unexamined diagnoses. |

The producer reads executable identity and fresh start time before scanning,
then re-reads after scanning and provider pinning using the same held
ProcessView. The fresh start time is checked against the original retained
pin identity. A live pidfd or unchanged start time alone cannot establish
executable identity. Renderers use the immutable receipt and perform no
`/proc` reads or later PID lookup.

A failed application receipt changes only the name/null/status. It does not
remove physical provider evidence, reclassify mapping results, create a gap in
call counts, or change the existing command's exit status. An unavailable memory
scan can still retain provider mappings and an observed application if its
mapping scan completed and the identity receipt succeeded. Failed initial
mapping reads never become a successful empty inventory.

Text shows the escaped executable basename before PID, then the full observed
path and identity detail. Unknown text is `Unknown executable (PID N)`.
Equal basenames or paths do not merge process or provider objects; physical
identity remains available to distinguish them. Mapping and decoded table
entries describe scan evidence. **Activity was not captured by inspect.**

Unchanged-image re-exec, including A-to-B-to-A between samples, is a documented
snapshot limitation. This receipt cannot establish the image of a historical
call event and grants no trace, profile or metrics executable-name authority.

The system projection adds the same fields to every `processes[]` row in
`p11scope/inspect-system/v1`; process/object references retain their existing
meanings. Scanned/MemoryUnavailable rows require the completed deep-scan
receipt. The sample encloses both mapping scans and provider pinning under the
original ProcessView. Failed initial/final mapping validation or a rejected
scan-generation check stays `not_examined`, even with a stable executable.
Successfully empty scans and completed mapping scans with unavailable memory
can retain an observed receipt. This presentation completion gate grants no
absence authority and does not change the physical mapping result or gap.
MapsMatched rows instead consume the separate retained SweptMember confirmation,
which checks executable identity around maps and physical proof reads. A missing
retained path still withholds the name. Unreadable, Exited and NotSelected rows
remain visible with unknown application identity.

System text uses the same retained receipts for mapped-by labels and the process
table, which also shows full executable paths and physical identity detail.
Rendering never repairs a missing identity using current process state. Host
adapter tests and installed system-scope qualification remain distinct checks;
the schema alone does not establish installed scope coverage.

Field authority is the narrow
[inspect presentation identity amendment](../privacy/allowlist-v3.md#inspect-presentation-identity-p5u-2026-10-09).
No `cmdline`, `environ`, `comm`, argument, payload or new provider-memory field
is authorized. Privacy allowlists v1 and v2 remain unchanged.
