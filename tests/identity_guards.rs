//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Identity guard rails: held-descriptor hashing, device-domain separation,
//! no new `makedev` bridges, and file learning never arming outside system
//! scope. Tests only; this packet touches no product file.
//!
//! Each guard pins its production function and carries an executed negative
//! control proving it can fail:
//!
//! - `held_fd_pin_survives_ancestor_swap` pins the held-fd rule behind
//!   [`KernelSelfMappingProbe::kernel_maps_key`] and
//!   `scripts/mapped-provider-pin.py` (hash and privately map the same
//!   held fd, never reopen by pathname). Control: the swapped pathname
//!   pins a different digest, so a path-reopening implementation fails.
//! - `device_domains_*` pins [`Device::to_kdev`] over recorded live btrfs
//!   pairs (maps device vs fstat device). Controls: the major-0 layout
//!   coincidence and the ext4 same-pairs control.
//! - `no_new_production_makedev_bridge` pins the single reviewed bridge
//!   (`MappedFile::key_is_identity`) and fails on any new production
//!   `makedev(` site. Control: the matcher self-test flags a bridge
//!   sample and clears comment/test samples.
//! - `non_system_scopes_never_arm_file_learning` pins the scope gate in
//!   `Engine::start_file_learning` (first, before any arming step) and
//!   its single production call site. Control: the gate predicate fails
//!   a gate-less sample.

use p11scope_manifest::identity::{KernelSelfMappingProbe, SelfMappingProbe, UnboundedProbeBudget};
use p11scope_manifest::maps::Device;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Package root under test, independent of the runner's working directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `text` with every comment, string and char literal blanked to spaces.
/// Newlines are kept, so line numbers and byte offsets still line up with
/// the original. Block comments are non-nested; lifetimes (`'a`) are not
/// chars. Blanked regions are replaced byte-for-byte with spaces, so no
/// partial UTF-8 sequence survives; code bytes pass through untouched.
fn strip_code(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] != b'\n' {
                    out[i] = b' ';
                }
                i += 1;
            }
            for j in [i, i + 1] {
                if j < bytes.len() {
                    out[j] = b' ';
                }
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if let Some(end) = raw_string_end(bytes, i) {
            for j in i..end {
                if bytes[j] != b'\n' {
                    out[j] = b' ';
                }
            }
            i = end;
            continue;
        }
        if bytes[i] == b'"' || (bytes[i] == b'b' && bytes.get(i + 1) == Some(&b'"')) {
            let quote = if bytes[i] == b'b' { i + 1 } else { i };
            out[i] = b' ';
            if quote != i {
                out[quote] = b' ';
            }
            i = quote + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    out[i] = b' ';
                    if i + 1 < bytes.len() && bytes[i + 1] != b'\n' {
                        out[i + 1] = b' ';
                    }
                    i += 2;
                    continue;
                }
                let is_quote = bytes[i] == b'"';
                if bytes[i] != b'\n' {
                    out[i] = b' ';
                }
                i += 1;
                if is_quote {
                    break;
                }
            }
            continue;
        }
        if let Some(end) = char_end(bytes, i) {
            for slot in &mut out[i..end] {
                *slot = b' ';
            }
            i = end;
            continue;
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanked regions keep valid UTF-8")
}

/// End offset (exclusive) of the raw string starting at `i`, if any:
/// `r"..."`, `r#"..."#`, with an optional `b`/`br` prefix.
fn raw_string_end(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    if bytes.get(j) == Some(&b'b') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    // A bare `r` in code (identifier character) is not a raw string.
    if bytes.get(j) != Some(&b'"') && bytes.get(j) != Some(&b'#') {
        return None;
    }
    // Avoid matching identifiers ending in `r` (e.g. `super`, `bar`):
    // the `r` must start the token.
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    if bytes[i] == b'b' && i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    let mut hashes = 0;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' && bytes[j + 1..].starts_with(&vec![b'#'; hashes]) {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    None
}

/// End offset (exclusive) of the char literal starting at `i`, if any.
/// Lifetimes (`'a`, `'static`) are not chars and return `None`.
fn char_end(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    if bytes.get(j) == Some(&b'b') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'\'') {
        return None;
    }
    if i > 0 && is_ident_byte(bytes[i - 1]) {
        return None;
    }
    j += 1;
    if bytes.get(j) == Some(&b'\\') {
        // Escaped char: scan to the closing quote on the same line.
        j += 1;
        while j < bytes.len() && bytes[j] != b'\'' && bytes[j] != b'\n' {
            j += 1;
        }
        return (bytes.get(j) == Some(&b'\'')).then(|| j + 1);
    }
    // Plain char: exactly one Unicode scalar, then the closing quote on
    // the same line. A bare lifetime (`'a`) has no closing quote.
    let mut k = j;
    while k < bytes.len() && bytes[k] != b'\'' && bytes[k] != b'\n' {
        k += 1;
    }
    if bytes.get(k) != Some(&b'\'') {
        return None;
    }
    let span = std::str::from_utf8(&bytes[j..k]).ok()?;
    (span.chars().count() == 1).then(|| k + 1)
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Offset of the `}` matching the `{` at `open` in stripped text.
fn match_brace(stripped: &str, open: usize) -> Option<usize> {
    let bytes = stripped.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0u32;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        if *b == b'{' {
            depth += 1;
        } else if *b == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// One scanned file: original and stripped lines side by side, sharing
/// line numbers and byte offsets.
struct ScanFile {
    rel: String,
    lines: Vec<String>,
    stripped_lines: Vec<String>,
    stripped: String,
    line_starts: Vec<usize>,
}

fn scan_text(rel: &str, text: &str) -> ScanFile {
    let stripped = strip_code(text);
    let mut line_starts = vec![0];
    for (i, b) in stripped.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let stripped_lines: Vec<String> = stripped.split('\n').map(str::to_string).collect();
    assert_eq!(
        lines.len(),
        stripped_lines.len(),
        "stripping keeps line counts in {rel}"
    );
    ScanFile {
        rel: rel.to_string(),
        lines,
        stripped_lines,
        stripped,
        line_starts,
    }
}

fn scan_path(root: &Path, path: &Path) -> ScanFile {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("guard reads {}: {error}", path.display()));
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    scan_text(&rel, &text)
}

/// Byte ranges of test-only code: `#[cfg(test)]` items, `#[test]` function
/// bodies, and `mod tests` bodies. A range that cannot be resolved exactly
/// is left out (fail closed: suspicious code gets flagged, never hidden).
fn test_ranges(file: &ScanFile) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for (i, line) in file.lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            if let Some(range) = gated_item_range(file, i) {
                ranges.push(range);
            }
        } else if trimmed.starts_with("#[test]") {
            if let Some(range) = test_fn_range(file, i) {
                ranges.push(range);
            }
        } else if is_mod_tests_line(&file.stripped_lines[i])
            && let Some(range) = brace_range_from(file, i)
        {
            ranges.push(range);
        }
    }
    ranges
}

/// First line after `from` that carries code beyond attributes: skips blank
/// lines, attribute lines, and lines the stripper emptied (comments).
fn next_significant(file: &ScanFile, from: usize) -> Option<usize> {
    ((from + 1)..file.lines.len()).find(|j| {
        let original = file.lines[*j].trim_start();
        !original.starts_with('#') && !file.stripped_lines[*j].trim().is_empty()
    })
}

/// Range of the item a `#[cfg(test)]` line gates: a brace-matched block
/// for block items, or the declaration line for `;` items. Unknown item
/// shapes get a minimal range (fail closed).
fn gated_item_range(file: &ScanFile, attr: usize) -> Option<(usize, usize)> {
    let item = next_significant(file, attr)?;
    let head = item_head_kind(&file.stripped_lines[item])?;
    let start = file.line_starts[attr];
    match head {
        ItemHead::Block => brace_range_from(file, item).map(|(_, end)| (start, end)),
        ItemHead::Decl => {
            // Through the terminating `;`, bounded to the item's own lines.
            let base = file.line_starts[item];
            let tail = &file.stripped[base..];
            let semi = tail.find(';')?;
            if tail[..semi].lines().count() > 25 {
                return None;
            }
            Some((start, base + semi + 1))
        }
    }
}

/// Whether the item head opens a block or ends at `;`. `None` for shapes
/// this guard does not classify (fields, variants, statements): those get
/// no range and stay visible.
fn item_head_kind(stripped: &str) -> Option<ItemHead> {
    let head = stripped.trim_start();
    // Strip visibility and qualifiers to the item keyword.
    let mut words = head.split(|c: char| !c.is_ascii_alphanumeric() && c != '_');
    let mut keyword = words.next()?;
    if keyword == "pub" {
        // Skip a `(...)` scope, then take the next word.
        let mut rest = head.split_once("pub")?.1.trim_start();
        if rest.starts_with('(') {
            rest = rest.split(')').nth(1)?.trim_start();
        }
        keyword = rest
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()?;
    }
    if matches!(keyword, "unsafe" | "async" | "extern") {
        let rest = head.split_once(keyword)?.1;
        keyword = rest
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .find(|word| !word.is_empty())?;
    }
    match keyword {
        "mod" | "fn" | "struct" | "enum" | "union" | "trait" | "impl" => {
            if head.contains('{') || !head.contains(';') {
                Some(ItemHead::Block)
            } else {
                // `mod foo;` / `fn foo();`: declaration only.
                Some(ItemHead::Decl)
            }
        }
        "const" | "static" | "type" | "use" => Some(ItemHead::Decl),
        _ => None,
    }
}

#[derive(PartialEq, Eq)]
enum ItemHead {
    Block,
    Decl,
}

/// Range of the `#[test]` function: the attribute through the matched body.
fn test_fn_range(file: &ScanFile, attr: usize) -> Option<(usize, usize)> {
    let item = next_significant(file, attr)?;
    fn_defined_on(&file.stripped_lines[item])?;
    brace_range_from(file, item).map(|(_, end)| (file.line_starts[attr], end))
}

fn is_mod_tests_line(stripped: &str) -> bool {
    let mut search = stripped;
    while let Some(pos) = search.find("mod") {
        let before = pos == 0 || !is_ident_byte(search.as_bytes()[pos - 1]);
        let after_mod = &search[pos + 3..];
        let spaced = after_mod.starts_with(|c: char| c.is_whitespace());
        if before && spaced {
            let rest = after_mod.trim_start();
            if let Some(after) = rest.strip_prefix("tests")
                && (after.is_empty() || !is_ident_byte(after.as_bytes()[0]))
            {
                return rest.contains('{');
            }
        }
        search = after_mod;
    }
    false
}

/// Brace-matched range starting at the first `{` on or after `line`.
/// Bounded to 25 lines past `line` for the opening brace; the body itself
/// is matched exactly.
fn brace_range_from(file: &ScanFile, line: usize) -> Option<(usize, usize)> {
    let base = file.line_starts[line];
    let tail = &file.stripped[base..];
    let open = tail.find('{')?;
    if tail[..open].lines().count() > 25 {
        return None;
    }
    let close = match_brace(&file.stripped, base + open)?;
    Some((base, close + 1))
}

/// `Some(name)` when the stripped line defines `fn name` (not a pointer).
/// Byte-oriented: never slices at a non-boundary, so multibyte content
/// elsewhere on the line cannot panic the scan.
fn fn_defined_on(stripped: &str) -> Option<String> {
    let bytes = stripped.as_bytes();
    let mut found = None;
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if bytes[i..].starts_with(b"fn ")
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && let Some(name) = fn_name_after(stripped, i + 3)
        {
            found = Some(name);
        }
        i += 1;
    }
    found
}

fn fn_name_after(line: &str, mut i: usize) -> Option<String> {
    let bytes = line.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && is_ident_byte(bytes[i]) {
        i += 1;
    }
    if start == i {
        return None;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    match bytes.get(i) {
        // Byte indices span ASCII only (identifier plus whitespace), so the
        // slice always lands on char boundaries.
        Some(b'(') | Some(b'<') => Some(line[start..i].trim_end().to_string()),
        _ => None,
    }
}

/// Nearest enclosing `fn` at or above `line_no` (0-based): a candidate
/// only counts when the line sits inside its brace-matched body, so a hit
/// past a nested function's close still attributes to the outer function.
fn enclosing_fn(file: &ScanFile, line_no: usize) -> Option<String> {
    let offset = file.line_starts[line_no];
    for l in (0..=line_no).rev() {
        let Some(name) = fn_defined_on(&file.stripped_lines[l]) else {
            continue;
        };
        if l == line_no {
            return Some(name);
        }
        if let Some((_, end)) = brace_range_from(file, l)
            && offset < end
        {
            return Some(name);
        }
    }
    None
}

/// Every `.rs` file under `src/` and `crates/`, minus test-only files:
/// anything under a `tests/` directory, `tests.rs` file-modules, and
/// `*_tests.rs` files (all `#[cfg(test)]`-wired). Sorted for stable output.
fn scanned_rust_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut out = Vec::new();
    for top in ["src", "crates"] {
        walk_rust(&root.join(top), &mut out);
    }
    out.sort();
    out
}

fn walk_rust(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("guard scans {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("guard reads every directory entry");
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                continue;
            }
            walk_rust(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "tests.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            out.push(path);
        }
    }
}

struct Hit {
    rel: String,
    line_no: usize,
    func: String,
    text: String,
}

/// Hits of `needle` in one scanned file: comment- and string-free (via
/// [`strip_code`]) and outside [`test_ranges`].
fn hits_in_file(file: &ScanFile, needle: &str) -> Vec<Hit> {
    let ranges = test_ranges(file);
    let mut hits = Vec::new();
    for (idx, stripped) in file.stripped_lines.iter().enumerate() {
        if !stripped.contains(needle) {
            continue;
        }
        let offset = file.line_starts[idx];
        if ranges.iter().any(|(s, e)| *s <= offset && offset < *e) {
            continue;
        }
        hits.push(Hit {
            rel: file.rel.clone(),
            line_no: idx + 1,
            func: enclosing_fn(file, idx).unwrap_or_else(|| "<top-level>".to_string()),
            text: file.lines[idx].trim().to_string(),
        });
    }
    hits
}

/// Every `needle` occurrence in production code. Sorted by file, line.
fn production_hits(needle: &str) -> Vec<Hit> {
    let root = repo_root();
    let mut hits = Vec::new();
    for path in scanned_rust_files() {
        hits.extend(hits_in_file(&scan_path(&root, &path), needle));
    }
    hits.sort_by(|a, b| (&a.rel, a.line_no).cmp(&(&b.rel, b.line_no)));
    hits
}

/// Every `fn name` definition of `name` in scanned production code.
fn fn_definitions(name: &str) -> Vec<(String, usize, String)> {
    let root = repo_root();
    let mut out = Vec::new();
    for path in scanned_rust_files() {
        let file = scan_path(&root, &path);
        let ranges = test_ranges(&file);
        for (idx, stripped) in file.stripped_lines.iter().enumerate() {
            if fn_defined_on(stripped).as_deref() != Some(name) {
                continue;
            }
            let offset = file.line_starts[idx];
            if ranges.iter().any(|(s, e)| *s <= offset && offset < *e) {
                continue;
            }
            let base = file.line_starts[idx];
            let Some((_, end)) = brace_range_from(&file, idx) else {
                continue;
            };
            out.push((
                file.rel.clone(),
                idx + 1,
                file.stripped[base..end].to_string(),
            ));
        }
    }
    out.sort();
    out
}

/// The single production definition body of `fn name` in one file; fails
/// otherwise. Same-named methods on other types (e.g. the membership
/// check also called `key_is_identity`) live in other files and never
/// collide here.
fn single_fn_body_in_file(rel: &str, name: &str) -> (usize, String) {
    let defs: Vec<(usize, String)> = fn_definitions(name)
        .into_iter()
        .filter(|(def_rel, _, _)| def_rel == rel)
        .map(|(_, line, body)| (line, body))
        .collect();
    assert_eq!(
        defs.len(),
        1,
        "expected exactly one production `fn {name}` in {rel}: {:?}",
        defs.iter().map(|(line, _)| line).collect::<Vec<_>>(),
    );
    defs.into_iter().next().expect("checked above")
}

/// The no-new-bridge guard: every production `makedev(` site must be the
/// one reviewed bridge below. `makedev` builds the userspace `st_dev`
/// layout, so any new production use either compares across device
/// domains (the btrfs trap in `crates/manifest/src/maps.rs`) or needs a
/// reviewed same-domain justification in the allowlist. Test fixtures may
/// build `st_dev` values freely; they are excluded by [`test_ranges`] and
/// the test-file rules, never by name.
///
/// Pins `MappedFile::key_is_identity` (`src/discovery/identity.rs`): the
/// single reviewed bridge, which compares a `makedev`-rebuilt maps pair
/// with fstat identity only on `KEY_IS_IDENTITY_FILESYSTEMS`.
#[test]
fn no_new_production_makedev_bridge() {
    const ALLOWED: [(&str, &str); 1] = [("src/discovery/identity.rs", "key_is_identity")];
    let hits = production_hits("makedev(");
    let unexpected: Vec<String> = hits
        .iter()
        .filter(|hit| !ALLOWED.contains(&(hit.rel.as_str(), hit.func.as_str())))
        .map(|hit| {
            format!(
                "{}:{} in `{}`: {}",
                hit.rel, hit.line_no, hit.func, hit.text
            )
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "new production `makedev(` site(s); a maps/fstat comparison here is a device-domain \
         bridge (see the `Device::from_kdev` docs). Same-domain uses need a reviewed allowlist \
         entry with justification:\n{}",
        unexpected.join("\n"),
    );
    assert_eq!(
        hits.len(),
        ALLOWED.len(),
        "the reviewed bridge moved; re-pin file and function, keeping the filesystem gate: {:?}",
        hits.iter()
            .map(|hit| format!("{}:{}", hit.rel, hit.func))
            .collect::<Vec<_>>(),
    );
    let (_, body) = single_fn_body_in_file("src/discovery/identity.rs", "key_is_identity");
    assert!(
        body.contains("KEY_IS_IDENTITY_FILESYSTEMS"),
        "the reviewed bridge lost its filesystem gate; without it the `makedev` comparison \
         runs on btrfs/overlay too",
    );
}

/// The non-member privacy guard: file learning arms for system scope only,
/// so a non-member opening a provider during a `run` (cgroup scope) is
/// never staged. The unit twin `learned_unavailable_files_a_named_gap`
/// pins the Pid behaviour; this guard pins the structural gate, which
/// covers every non-System scope including run's, plus the single
/// production call site behind the Detailed-only switch.
///
/// Pins `Engine::start_file_learning` (`src/discovery/engine.rs`) and its
/// call in `capture_with_host` (`src/run.rs`).
#[test]
fn non_system_scopes_never_arm_file_learning() {
    let (_, body) = single_fn_body_in_file("src/discovery/engine.rs", "start_file_learning");
    assert!(
        gate_returns_before_arm(&body),
        "`Engine::start_file_learning` must return for non-System scopes before any arming \
         step (learner start, `*_rx = Some`, gap filing)",
    );
    let calls: Vec<Hit> = production_hits("start_file_learning")
        .into_iter()
        .filter(|hit| !hit.text.contains("fn start_file_learning"))
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "expected the single production arming call; a new call site arms learning from a \
         new flow and must be reviewed: {:?}",
        calls
            .iter()
            .map(|hit| format!("{}:{} in `{}`", hit.rel, hit.line_no, hit.func))
            .collect::<Vec<_>>(),
    );
    assert_eq!(calls[0].rel, "src/run.rs");
    assert_eq!(
        calls[0].func, "capture_with_host",
        "the arming call moved; re-pin file and function, keeping the Detailed-only switch",
    );
    let root = repo_root();
    let run_text =
        std::fs::read_to_string(root.join("src/run.rs")).expect("guard reads src/run.rs");
    let run_lines: Vec<&str> = run_text.lines().collect();
    let call = calls[0].line_no;
    let context = run_lines[call.saturating_sub(9)..call.min(run_lines.len())].join("\n");
    assert!(
        context.contains("file_learning_armed"),
        "the arming call left its `file_learning_armed(policy)` (Detailed-only) switch:\n{context}",
    );
}

/// True when `body` (of `start_file_learning`) gates on the System-only
/// scope check and returns before any arming step. `return` must be the
/// keyword, not part of a longer identifier.
fn gate_returns_before_arm(body: &str) -> bool {
    const GATE: &str = "!matches!(self.scope, Scope::System)";
    const ARM_MARKERS: [&str; 4] = [
        "FileLearner::start",
        "file_learner = Some",
        "learned_rx = Some",
        "mark_partial",
    ];
    let Some(gate) = body.find(GATE) else {
        return false;
    };
    let Some(first_arm) = ARM_MARKERS
        .iter()
        .filter_map(|marker| body.find(marker))
        .min()
    else {
        return false;
    };
    if first_arm < gate {
        return false;
    }
    has_return_keyword(&body[gate..first_arm])
}

fn has_return_keyword(span: &str) -> bool {
    let bytes = span.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if bytes[i..].starts_with(b"return")
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && bytes.get(i + 6).is_none_or(|next| !is_ident_byte(*next))
        {
            return true;
        }
        i += 1;
    }
    false
}

struct PinOutput {
    sha256: String,
    maps_major: u64,
    maps_minor: u64,
    ino: u64,
}

fn pin_script() -> PathBuf {
    repo_root().join("scripts/mapped-provider-pin.py")
}

fn parse_pin_json(stdout: &[u8]) -> PinOutput {
    let value: serde_json::Value =
        serde_json::from_slice(stdout).expect("the pin script prints one JSON object");
    PinOutput {
        sha256: value["sha256"].as_str().expect("sha256 field").to_string(),
        maps_major: value["mapping"]["dev"][0].as_u64().expect("maps major"),
        maps_minor: value["mapping"]["dev"][1].as_u64().expect("maps minor"),
        ino: value["ino"].as_u64().expect("ino field"),
    }
}

fn run_pin_script(cmd: &mut Command) -> PinOutput {
    let output = cmd.output().expect("python3 runs the pin script");
    assert!(
        output.status.success(),
        "the pin script failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    parse_pin_json(&output.stdout)
}

/// Pin through a pathname (the script's ordinary interface).
fn pin_path(path: &Path) -> PinOutput {
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg(pin_script()).arg(path);
    run_pin_script(&mut cmd)
}

/// Pin through the held descriptor itself: the child inherits only this
/// fd (its `CLOEXEC` cleared in `pre_exec`) and the script opens it as
/// `/dev/fd/N`, so every byte hashed and every mapping anchored comes
/// from the held file, never from a pathname re-resolution.
fn pin_held_fd(held: &std::fs::File) -> PinOutput {
    let fd = held.as_raw_fd();
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg(pin_script()).arg(format!("/dev/fd/{fd}"));
    unsafe {
        cmd.pre_exec(move || {
            // SAFETY: runs after `fork`, before `exec`; `fcntl` is
            // async-signal-safe; touches only our own fd.
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    run_pin_script(&mut cmd)
}

/// Held-fd hashing vs path reopen across an ancestor swap. Pins the
/// production rule: hash and privately map the same held fd
/// (`KernelSelfMappingProbe::kernel_maps_key` plus the pin script's rule),
/// never reopen a held object by its pathname. Fixture shape follows the
/// fanotify ancestor-swap twin: the ancestor directory is renamed away
/// and its name is symlinked at a decoy, so the pathname now spells a
/// different live file.
///
/// Negative control (executed below): the swapped pathname pins a
/// different digest, so pointed at `File::open(path)` this guard reports
/// the wrong file and fails.
#[test]
fn held_fd_pin_survives_ancestor_swap() {
    let dir = tempfile::tempdir().expect("fixture tempdir creates");
    let ancestor = dir.path().join("real");
    let decoy = dir.path().join("evil");
    std::fs::create_dir(&ancestor).expect("ancestor creates");
    std::fs::create_dir(&decoy).expect("decoy creates");
    let path = ancestor.join("provider.so");
    let original: Vec<u8> = [&b"held-provider-original-v1\n"[..]; 64].concat();
    let swapped: Vec<u8> = [&b"swapped-provider-evil-v2\n"[..]; 200].concat();
    std::fs::write(&path, &original).expect("original writes");
    std::fs::write(decoy.join("provider.so"), &swapped).expect("decoy writes");
    let expected = std::fs::metadata(&path).expect("original stats");

    // Baseline through the production rule, before the swap. The probe
    // and the script must agree: both read the same held file.
    let baseline = pin_path(&path);
    let held = std::fs::File::open(&path).expect("held fd opens");
    let probe = KernelSelfMappingProbe;
    let mut budget = UnboundedProbeBudget;
    let key = probe
        .kernel_maps_key(&held, &mut budget)
        .expect("the probe maps the held fd");
    assert_eq!(
        (key.device.major, key.device.minor, key.inode),
        (baseline.maps_major, baseline.maps_minor, expected.ino()),
        "probe and script agree on the held file before the swap",
    );

    // The swap: rename the ancestor away, symlink its name at the decoy.
    let moved = dir.path().join("real.moved");
    std::fs::rename(&ancestor, &moved).expect("ancestor renames away");
    std::os::unix::fs::symlink(&decoy, &ancestor).expect("decoy symlinks in");
    let swapped_meta = std::fs::metadata(&path).expect("swapped pathname stats");
    assert_ne!(
        swapped_meta.ino(),
        expected.ino(),
        "the fixture really swapped the pathname onto another file",
    );

    // Held-fd facts still describe the ORIGINAL file.
    let held_pin = pin_held_fd(&held);
    assert_eq!(
        held_pin.sha256, baseline.sha256,
        "held-fd hash is swap-immune",
    );
    assert_eq!(
        (held_pin.maps_major, held_pin.maps_minor, held_pin.ino),
        (baseline.maps_major, baseline.maps_minor, expected.ino()),
        "held-fd maps anchor is swap-immune",
    );
    assert_eq!(
        probe.kernel_maps_key(&held, &mut budget),
        Some(key),
        "held-fd probe key is swap-immune",
    );

    // A path reopen sees the swapped bytes instead.
    let swapped_pin = pin_path(&path);
    assert_ne!(
        swapped_pin.sha256, baseline.sha256,
        "control: the swapped pathname pins different bytes, proving the fixture swaps",
    );
    assert_eq!(
        swapped_pin.ino,
        swapped_meta.ino(),
        "control: the path pin follows the pathname to the decoy",
    );
}

/// Recorded live device pairs `(maps_major, maps_minor, fstat_major,
/// fstat_minor)`, captured 2026-11-14 on host `lu26` (kernel
/// 7.0.0-43-generic) via `scripts/mapped-provider-pin.py`: the `mapping`
/// device is what `/proc/self/maps` renders for a private mapping of the
/// file, the `file_identity` device is its fstat `st_dev` decoded with
/// `os.major`/`os.minor`. Full outputs are filed with the packet evidence
/// (`device-pairs-provenance.log`). Both rows are btrfs (subvolumes `@`
/// and `@home`); no overlay mount was obtainable from this unprivileged
/// lane (user namespaces are AppArmor-restricted, no container access),
/// and the anonymous `0:N` shape below is exactly the overlay/btrfs
/// shape: the maps device is filesystem-level (same `0:35` on both
/// subvolumes) while fstat carries the per-subvolume anonymous device.
const BTRFS_RECORDED: [(u64, u64, u32, u32); 2] = [(0, 35, 0, 37), (0, 35, 0, 47)];

/// Maps identity and fstat identity are separate device domains: on the
/// recorded btrfs pairs the rendered pairs differ, so the kernel word
/// and the fstat word differ too. A domain-mixing comparison (treating
/// one as the other) fails here.
///
/// Pins `Device::to_kdev` (`crates/manifest/src/maps.rs`).
#[test]
fn device_domains_recorded_btrfs_pairs_differ() {
    for (maps_major, maps_minor, fstat_major, fstat_minor) in BTRFS_RECORDED {
        let st_dev = libc::makedev(fstat_major, fstat_minor);
        assert_eq!(
            (libc::major(st_dev), libc::minor(st_dev)),
            (fstat_major, fstat_minor),
            "the recorded userspace decode is faithful",
        );
        let maps = Device {
            major: maps_major,
            minor: maps_minor,
        };
        assert_ne!(
            (maps.major, maps.minor),
            (u64::from(fstat_major), u64::from(fstat_minor)),
            "maps and fstat render different pairs on btrfs",
        );
        assert_ne!(
            maps.to_kdev(),
            st_dev,
            "the kernel word and the fstat word differ across domains",
        );
    }
}

/// Why the btrfs trap is silent: on major-0/minor<256 devices the two
/// layouts agree numerically (see the `Device::from_kdev` docs), so a
/// domain-mixing comparison passes on btrfs-shaped devices and fails
/// everywhere else. Pin the coincidence so the row above is read as
/// structure (different minors), never as layout.
#[test]
fn device_domains_major_zero_layout_coincidence_is_pinned() {
    assert_eq!(
        Device {
            major: 0,
            minor: 35
        }
        .to_kdev(),
        35
    );
    assert_eq!(libc::makedev(0, 35), 35);
}

/// Same-shape control on an identity-filesystem device: the rendered
/// pairs agree (which is why `key_is_identity` may compare them there),
/// but the raw words still differ (kernel word vs userspace word), so a
/// raw-word comparison is wrong even where pairs agree.
#[test]
fn device_domains_ext4_control_agrees_pairs_only() {
    let st_dev = libc::makedev(8, 1);
    assert_eq!((libc::major(st_dev), libc::minor(st_dev)), (8, 1));
    assert_eq!(Device { major: 8, minor: 1 }.to_kdev(), (8 << 20) | 1);
    assert_ne!(
        Device { major: 8, minor: 1 }.to_kdev(),
        st_dev,
        "raw words differ even where the pairs agree",
    );
}

/// [`production_hits`] over inline text, for the matcher self-tests.
fn production_hits_on_text(text: &str, needle: &str) -> Vec<(usize, String, String)> {
    hits_in_file(&scan_text("sample.rs", text), needle)
        .into_iter()
        .map(|hit| (hit.line_no, hit.func, hit.text))
        .collect()
}

#[test]
fn scan_machinery_strips_comments_strings_and_chars() {
    let text = r##"fn prod() -> u64 {
// a `makedev(` mention in a line comment
/// a `makedev(` mention in a doc comment
/* a `makedev(` mention
   in a block comment */
    let open = "a brace { and makedev( in a string";
    let raw = r#"another { and makedev( in a raw string"#;
    let tick: char = '{';
    let wide: char = '界';
    let _ = (tick, wide);
    0x801
}
fn with_lifetime<'a>(x: &'a u64) -> u64 {
    *x
}
"##;
    let stripped = strip_code(text);
    assert!(
        !stripped.contains("makedev("),
        "comments and strings hide nothing:\n{stripped}"
    );
    assert!(
        stripped.contains("let open"),
        "code lines survive:\n{stripped}"
    );
    assert!(
        stripped.contains("with_lifetime"),
        "lifetimes are not chars:\n{stripped}"
    );
    assert!(
        !stripped.contains('界'),
        "multibyte chars are stripped too:\n{stripped}"
    );
    assert_eq!(
        stripped.lines().count(),
        text.lines().count(),
        "line numbers still line up"
    );
    // The braces left are the real ones: both function bodies match.
    let file = scan_text("sample.rs", text);
    let first_open = file.stripped.find('{').expect("first body opens");
    let first_close = match_brace(&file.stripped, first_open).expect("first body closes");
    assert!(
        file.stripped[first_open..=first_close].contains("let open"),
        "string braces never join the depth count"
    );
}

#[test]
fn scan_machinery_ranges_cover_test_items_only() {
    let text = r#"fn prod_bridge() -> u64 {
    libc::makedev(8, 1)
}
#[cfg(test)]
mod tests {
    fn helper() -> u64 {
        libc::makedev(0, 1)
    }
    #[test]
    fn twin() {
        assert_eq!(libc::makedev(0, 1), 1);
    }
}
#[test]
fn loose_twin() {
    let _ = libc::makedev(0, 2);
}
"#;
    assert_eq!(
        production_hits_on_text(text, "makedev(")
            .iter()
            .map(|(line, func, _)| (*line, func.clone()))
            .collect::<Vec<_>>(),
        vec![(2, "prod_bridge".to_string())],
        "only the production site is visible",
    );
    // Negative control: without the `mod tests` wrapper the helper is
    // production code, and the matcher sees it.
    let unwrapped = text.replace("#[cfg(test)]\nmod tests {\n", "").replace(
        "    #[test]\n    fn twin() {\n        assert_eq!(libc::makedev(0, 1), 1);\n    }\n}\n",
        "#[test]\nfn twin() {\n    assert_eq!(libc::makedev(0, 1), 1);\n}\n",
    );
    let funcs: Vec<String> = production_hits_on_text(&unwrapped, "makedev(")
        .iter()
        .map(|(_, func, _)| func.clone())
        .collect();
    assert_eq!(funcs, vec!["prod_bridge".to_string(), "helper".to_string()]);
}

#[test]
fn scan_machinery_finds_enclosing_fn() {
    assert_eq!(
        fn_defined_on("    pub(crate) fn gated() {"),
        Some("gated".to_string())
    );
    assert_eq!(
        fn_defined_on("async unsafe fn mixed() {"),
        Some("mixed".to_string())
    );
    assert_eq!(
        fn_defined_on("fn generic<T>(x: T) {"),
        Some("generic".to_string())
    );
    assert_eq!(fn_defined_on("    let callback: fn(u32);"), None);
    assert_eq!(fn_defined_on(&strip_code("    // fn commented() {")), None);
    let file = scan_text(
        "sample.rs",
        "fn outer() {\n    let x = 1;\n    fn inner() {\n        let y = 2;\n    }\n}\n",
    );
    // The sample has no comments, so stripped lines equal the originals.
    assert_eq!(enclosing_fn(&file, 1), Some("outer".to_string()));
    assert_eq!(enclosing_fn(&file, 3), Some("inner".to_string()));
    assert_eq!(enclosing_fn(&file, 5), Some("outer".to_string()));
}

#[test]
fn arming_gate_predicate_fires_only_on_gated_bodies() {
    let gated = "fn start_file_learning(&mut self) {\n    if !matches!(self.scope, Scope::System) {\n        return;\n    }\n    \
         match FileLearner::start() {\n        Ok((learner, rx)) => {\n            self.file_learner = Some(learner);\n        }\n    }\n}\n";
    assert!(gate_returns_before_arm(gated), "the gated shape passes");
    // Negative controls: no gate, a gate after the arming step, and a
    // `return` that is only part of an identifier.
    let ungated = gated.replace(
        "    if !matches!(self.scope, Scope::System) {\n        return;\n    }\n",
        "",
    );
    assert_ne!(ungated, gated, "the control really removes the gate");
    assert!(!gate_returns_before_arm(&ungated), "a gate-less body fails");
    let late_gate = "fn start_file_learning(&mut self) {\n    self.file_learner = Some(learner);\n    \
         if !matches!(self.scope, Scope::System) {\n        return;\n    }\n}\n";
    assert!(!gate_returns_before_arm(late_gate), "a late gate fails");
    let fake_return = "fn start_file_learning(&mut self) {\n    if !matches!(self.scope, Scope::System) {\n        self.return_probe_flag = true;\n    }\n    \
         self.file_learner = Some(learner);\n}\n";
    assert!(
        !gate_returns_before_arm(fake_return),
        "a `return` inside an identifier is not a return"
    );
}
