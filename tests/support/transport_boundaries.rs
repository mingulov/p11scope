//! SPDX-License-Identifier: GPL-3.0-or-later
//! Source sentinels shared with a standalone, dependency-free regression seam.

const JOURNAL: &str = "src/semantics_objects/journal.rs";
const INPUT: &str = "src/discovery/caller_registry/instance_input.rs";
const CORROBORATION: &str = "    if base.continuity.entry_ip != begin.entry_ip() {\n        return false;\n    }\n    if !stamp_agrees(&base.continuity.entry_stamp, &begin.entry_stamp()) {\n        return false;\n    }";
const MODEL_PARAMETER: &str = "model: &crate::semantics_objects::ObjectSemantics,";
const PRODUCER_TEST_MODULE: &str = "#[cfg(test)]\npub(crate) mod tests {";
const PRODUCER_INITIALIZERS: &str = "        base.continuity.entry_ip = ENTRY_IP;\n        base.continuity.entry_stamp = InstanceStamp {\n            epoch: 7,\n            global: 8,\n            fault: 9,\n            file_slot_plus1: 3,\n            flags: STAMP_VALID,\n        };\n        base.continuity.return_stamp = base.continuity.entry_stamp;";

pub fn uses_private_record_fields(path: &str, source: &str) -> bool {
    let mut scan = source.as_bytes().to_vec();
    if path == JOURNAL
        && let Some((_, body)) = function(source, "end_agrees_with_begin", None)
        && source.matches(CORROBORATION).count() == 1
        && let Some(offset) = source[body.clone()].find(CORROBORATION)
    {
        let start = body.start + offset;
        let code = code_only(source);
        // Only the two direct, consecutive equality guards. No other part of
        // this function (or the journal) is exempt from the privacy scan.
        if balanced(&code[body.start..start], b'{', b'}')
            && code[start..start + CORROBORATION.len()] == *CORROBORATION.as_bytes()
        {
            scan[start..start + CORROBORATION.len()].fill(b' ');
        }
    }
    if path == JOURNAL
        && let Some(initializers) = producer_fixture_initializers(source)
    {
        scan[initializers].fill(b' ');
    }
    let scan = String::from_utf8(scan)
        .expect("only exact ASCII exceptions were masked")
        .replace("continuity_cuts", "")
        .replace("poll_records_to_position", "");
    [
        "entry_ip",
        "entry_stamp",
        "return_stamp",
        "poll_records",
        "decode_record",
    ]
    .iter()
    .any(|field| scan.contains(field))
        || scan.match_indices(".continuity").any(|(offset, field)| {
            scan[offset + field.len()..]
                .chars()
                .next()
                .is_none_or(|next| !next.is_alphanumeric() && next != '_')
        })
}

fn producer_fixture_initializers(source: &str) -> Option<Span> {
    let code = code_only(source);
    let mut headers = source
        .match_indices(PRODUCER_TEST_MODULE)
        .filter(|(start, _)| {
            code[*start..*start + PRODUCER_TEST_MODULE.len()] == *PRODUCER_TEST_MODULE.as_bytes()
        });
    let (module_start, _) = headers.next()?;
    if headers.next().is_some()
        || !balanced(&code[..module_start], b'{', b'}')
        || !balanced(&code[..module_start], b'(', b')')
        || !balanced(&code[..module_start], b'[', b']')
    {
        return None;
    }
    let module_open = module_start + PRODUCER_TEST_MODULE.len() - 1;
    let module_close = closing(&code, module_open, b'{', b'}')?;
    let (signature, body) = function(
        source,
        "producer_agreement_pair",
        Some("pub(crate) mod tests {"),
    )?;
    // The known tuple/array return belongs to this fixture. A block in a
    // different return type must not be mistaken for the helper's body.
    if body.start <= module_open
        || body.end >= module_close
        || source[signature.end + 1..body.start - 1].trim() != "-> ([u8; 224], [u8; 632])"
        || source.matches(PRODUCER_INITIALIZERS).count() != 1
    {
        return None;
    }
    let start = body.start + source[body.clone()].find(PRODUCER_INITIALIZERS)?;
    let end = start + PRODUCER_INITIALIZERS.len();
    let preceding = &code[body.start..start];
    // Only the exact direct initializer statements following the producer
    // call. Balanced delimiters exclude nested branches/callbacks/macros;
    // the statement boundary also excludes an unbraced closure body.
    (balanced(preceding, b'{', b'}')
        && balanced(preceding, b'(', b')')
        && balanced(preceding, b'[', b']')
        && preceding
            .iter()
            .rev()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(&b';')
        && code[start..end] == *PRODUCER_INITIALIZERS.as_bytes())
    .then_some(start..end)
}

pub fn model_marker(path: &str, source: &str) -> Option<&'static str> {
    let mut scan = source.as_bytes().to_vec();
    if path == INPUT {
        let code = code_only(source);
        for name in [
            "deliver_joint_seal",
            "deliver_joint_failure",
            "after_joint_delivery",
            "deliver_joint_algorithm_failure_for_test",
            "deliver_joint_algorithm_seal_for_test",
        ] {
            let Some((signature, _)) = function(source, name, Some("impl CallerRegistry {")) else {
                continue;
            };
            // The legacy algorithm adapter is permitted only under its real,
            // directly attached test gate. Comments/literals cannot supply it.
            if let Some(header) = match name {
                "deliver_joint_algorithm_failure_for_test" => Some(
                    b"#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_failure_for_test("
                        .as_slice(),
                ),
                "deliver_joint_algorithm_seal_for_test" => Some(
                    b"#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_seal_for_test("
                        .as_slice(),
                ),
                _ => None,
            } {
                let preceding = &code[..signature.start];
                if !preceding.ends_with(header) {
                    continue;
                }
                let before_header = &preceding[..preceding.len() - header.len()];
                // Macro input can look like an item while an expansion strips
                // its attribute; the gate must be at real item depth.
                if !balanced(before_header, b'(', b')') || !balanced(before_header, b'[', b']') {
                    continue;
                }
            }
            let signature_text = &source[signature.clone()];
            if signature_text.matches(MODEL_PARAMETER).count() != 1 {
                continue;
            }
            let start = signature.start + signature_text.find(MODEL_PARAMETER).unwrap();
            // A direct borrowed parameter, not a nested callback type, return
            // type, body annotation or model constructor.
            if balanced(&code[signature.start..start], b'(', b')')
                && code[signature.start..start]
                    .iter()
                    .rev()
                    .find(|b| !b.is_ascii_whitespace())
                    == Some(&b',')
                && code[start..start + MODEL_PARAMETER.len()] == *MODEL_PARAMETER.as_bytes()
            {
                scan[start..start + MODEL_PARAMETER.len()].fill(b' ');
            }
        }
    }
    let scan = String::from_utf8(scan).expect("only ASCII model parameters were masked");
    [
        "ObjectDomain",
        "OriginFact",
        "RefCut",
        "CallToken",
        "CompleteInputPrefix",
        "ObjectSemantics",
    ]
    .into_iter()
    .find(|marker| scan.contains(marker))
}

/// Mask comments and literals for locating code spans; the actual forbidden
/// marker scans still inspect all other original text, as the old sentinels did.
fn code_only(source: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut code = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let mut end = None;
        if bytes[i..].starts_with(b"//") {
            end = Some(
                i + bytes[i..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .unwrap_or(bytes.len() - i),
            );
        } else if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            i += 2;
            while i < bytes.len() && depth != 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            end = Some(i);
        } else if bytes[i] == b'r' {
            let mut quote = i + 1;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let suffix = &bytes[i + 1..quote];
                let mut after = quote + 1;
                while after < bytes.len() {
                    if bytes[after] == b'"' && bytes[after + 1..].starts_with(suffix) {
                        break;
                    }
                    after += 1;
                }
                end = Some((after + 1 + suffix.len()).min(bytes.len()));
            }
        }
        if end.is_none() && bytes[start] == b'"' {
            i = start + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            end = Some(i);
        } else if end.is_none() && bytes[start] == b'\'' {
            // A lifetime has no closing quote after its first character.
            let mut after = start + 1;
            if bytes.get(after) == Some(&b'\\') {
                after += 1;
                after += match bytes.get(after) {
                    Some(b'x') => 3,
                    Some(b'u') => bytes[after..]
                        .iter()
                        .position(|b| *b == b'}')
                        .map_or(1, |n| n + 1),
                    Some(_) => 1,
                    None => 0,
                };
            } else if let Some(ch) = source[after..].chars().next() {
                after += ch.len_utf8();
            }
            if bytes.get(after) == Some(&b'\'') {
                end = Some(after + 1);
            }
        }
        if let Some(end) = end {
            code[start..end].fill(b' ');
            i = end;
        } else {
            i = start + 1;
        }
    }
    code
}

fn balanced(bytes: &[u8], open: u8, close: u8) -> bool {
    let mut depth = 0usize;
    for byte in bytes {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            let Some(left) = depth.checked_sub(1) else {
                return false;
            };
            depth = left;
        }
    }
    depth == 0
}

fn closing(code: &[u8], from: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    for (offset, byte) in code.iter().enumerate().skip(from) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(offset);
            }
        }
    }
    None
}

type Span = std::ops::Range<usize>;

/// Recognize one uniquely named function in its exact top-level owner. This is
/// deliberately a narrow source sentinel, not a permissive Rust parser.
fn function(source: &str, name: &str, owner: Option<&str>) -> Option<(Span, Span)> {
    let code = code_only(source);
    let identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut matches = source.match_indices("fn").filter_map(|(offset, _)| {
        if !code[offset..].starts_with(b"fn")
            || (offset > 0 && identifier(code[offset - 1]))
            || !code.get(offset + 2)?.is_ascii_whitespace()
        {
            return None;
        }
        let mut named = offset + 2;
        while code.get(named).is_some_and(u8::is_ascii_whitespace) {
            named += 1;
        }
        let after = named + name.len();
        (code[named..].starts_with(name.as_bytes())
            && code.get(after).is_none_or(|byte| !identifier(*byte)))
        .then_some((offset, after))
    });
    let (start, mut open) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    // A function-shaped token tree inside a () or [] macro is not an item.
    if !balanced(&code[..start], b'(', b')') || !balanced(&code[..start], b'[', b']') {
        return None;
    }
    let mut outer = Vec::new();
    for (offset, byte) in code[..start].iter().enumerate() {
        match byte {
            b'{' => outer.push(offset),
            b'}' => {
                outer.pop()?;
            }
            _ => {}
        }
    }
    match owner {
        None if !outer.is_empty() => return None,
        Some(owner) => {
            if outer.len() != 1 {
                return None;
            }
            let end = outer[0] + 1;
            let begin = end.checked_sub(owner.len())?;
            if code[begin..end] != *owner.as_bytes() {
                return None;
            }
        }
        None => {}
    }
    while code.get(open).is_some_and(u8::is_ascii_whitespace) {
        open += 1;
    }
    if code.get(open) != Some(&b'(') {
        return None;
    }
    let close = closing(&code, open, b'(', b')')?;
    let mut body_open = close + 1;
    loop {
        // Tuple/array return types can contain semicolons. Only a body or
        // declaration delimiter outside those balanced groups decides here.
        match *code.get(body_open)? {
            b'(' => body_open = closing(&code, body_open, b'(', b')')? + 1,
            b'[' => body_open = closing(&code, body_open, b'[', b']')? + 1,
            b'{' => break,
            b';' | b'}' => return None,
            _ => body_open += 1,
        }
    }
    let body_close = closing(&code, body_open, b'{', b'}')?;
    Some((open + 1..close, body_open + 1..body_close))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOURNAL: &str = "src/semantics_objects/journal.rs";
    const INPUT: &str = "src/discovery/caller_registry/instance_input.rs";
    const GUARDS: &str = "    if base.continuity.entry_ip != begin.entry_ip() {\n        return false;\n    }\n    if !stamp_agrees(&base.continuity.entry_stamp, &begin.entry_stamp()) {\n        return false;\n    }";
    const FIXTURE_INITIALIZERS: &str = "        base.continuity.entry_ip = ENTRY_IP;\n        base.continuity.entry_stamp = InstanceStamp {\n            epoch: 7,\n            global: 8,\n            fault: 9,\n            file_slot_plus1: 3,\n            flags: STAMP_VALID,\n        };\n        base.continuity.return_stamp = base.continuity.entry_stamp;";
    const TEST_MODULE: &str = "#[cfg(test)]\npub(crate) mod tests {";

    fn journal() -> String {
        std::fs::read_to_string(JOURNAL).expect("read real journal")
    }

    fn input() -> String {
        std::fs::read_to_string(INPUT).expect("read real evidence adapter")
    }

    fn producer_fixture_item() -> String {
        let source = journal();
        let start = source.find("    fn producer_agreement_pair(").unwrap();
        let end = start
            + source[start..]
                .find("\n    fn producer_pair_agrees(")
                .unwrap();
        source[start..end].to_owned()
    }

    fn producer_fixture() -> String {
        format!("{TEST_MODULE}\n{}\n}}", producer_fixture_item())
    }

    #[test]
    fn real_journal_failure_is_isolated_to_the_producer_fixture_initializers() {
        let source = journal();
        assert_eq!(source.matches(FIXTURE_INITIALIZERS).count(), 1);
        assert!(!uses_private_record_fields(
            JOURNAL,
            &source.replace(FIXTURE_INITIALIZERS, "")
        ));
    }

    #[test]
    fn exact_real_producer_fixture_is_permitted_in_its_test_module() {
        assert!(!uses_private_record_fields(JOURNAL, &producer_fixture()));
    }

    #[test]
    fn producer_fixture_requires_unique_direct_test_ancestry() {
        let source = producer_fixture();
        let item = producer_fixture_item();
        for path in [
            "src/render.rs",
            "src/output.rs",
            "src/semantics_objects/other.rs",
        ] {
            assert!(uses_private_record_fields(path, &source), "{path}");
        }
        for (case, changed) in [
            ("missing gate", source.replace("#[cfg(test)]\n", "")),
            (
                "production gate",
                source.replace("#[cfg(test)]", "#[cfg(not(test))]"),
            ),
            (
                "comment gate",
                source.replace("#[cfg(test)]", "/* #[cfg(test)] */"),
            ),
            (
                "literal gate",
                source.replace("#[cfg(test)]", "#[doc = \"#[cfg(test)]\"]"),
            ),
            (
                "renamed module",
                source.replace("mod tests {", "mod production {"),
            ),
            (
                "renamed helper",
                source.replace("fn producer_agreement_pair(", "fn other_fixture("),
            ),
            (
                "different fixture return",
                source.replace("-> ([u8; 224], [u8; 632])", "-> ([u8; 225], [u8; 632])"),
            ),
            ("production helper", item.clone()),
            (
                "decoy test gate beside production owner",
                format!(
                    "{TEST_MODULE}\n}}\n{}",
                    source.replace("#[cfg(test)]", "#[cfg(not(test))]")
                ),
            ),
            ("nested module", format!("mod production {{\n{source}\n}}")),
            (
                "nested fake gate",
                format!("fn production() {{\n{source}\n}}"),
            ),
            ("comment source", format!("/* {source} */")),
            (
                "raw literal source",
                format!("const HIDDEN: &str = r####\"{source}\"####;"),
            ),
            (
                "duplicate helper",
                source.replace(
                    TEST_MODULE,
                    &format!("{TEST_MODULE}\nfn producer_agreement_pair() {{}}"),
                ),
            ),
        ] {
            assert!(uses_private_record_fields(JOURNAL, &changed), "{case}");
        }
        for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
            let module_input = format!("strip_test_gate!{open}\n{source}\n{close};");
            assert!(
                uses_private_record_fields(JOURNAL, &module_input),
                "module macro {open}"
            );
            let helper_input = format!("{TEST_MODULE}\nstrip_helper!{open}\n{item}\n{close};\n}}");
            assert!(
                uses_private_record_fields(JOURNAL, &helper_input),
                "helper macro {open}"
            );
        }
    }

    #[test]
    fn producer_fixture_exception_cannot_authorize_other_or_nested_private_uses() {
        let source = producer_fixture();
        for (case, replacement) in [
            (
                "nested branch",
                format!("        if ready {{\n{FIXTURE_INITIALIZERS}\n        }}"),
            ),
            (
                "nested callback",
                format!("        let callback = || {{\n{FIXTURE_INITIALIZERS}\n        }};"),
            ),
            (
                "unbraced callback",
                format!("        let callback = ||\n{FIXTURE_INITIALIZERS}"),
            ),
            (
                "nested helper",
                format!("        fn nested() {{\n{FIXTURE_INITIALIZERS}\n        }}"),
            ),
            (
                "duplicate initializers",
                format!("{FIXTURE_INITIALIZERS}\n{FIXTURE_INITIALIZERS}"),
            ),
            (
                "other initializer",
                FIXTURE_INITIALIZERS.replace("= ENTRY_IP;", "= other_ip;"),
            ),
            (
                "render",
                format!("{FIXTURE_INITIALIZERS}\n        render(base.continuity.entry_ip);"),
            ),
            (
                "private record read",
                format!("{FIXTURE_INITIALIZERS}\n        let value = record.return_stamp;"),
            ),
            (
                "whole continuity read",
                format!("{FIXTURE_INITIALIZERS}\n        let value = base.continuity;"),
            ),
            (
                "comment initializers",
                format!("/*\n{FIXTURE_INITIALIZERS}\n*/"),
            ),
            (
                "literal initializers",
                format!("        let text = r####\"{FIXTURE_INITIALIZERS}\"####;"),
            ),
        ] {
            let changed = source.replace(FIXTURE_INITIALIZERS, &replacement);
            assert!(uses_private_record_fields(JOURNAL, &changed), "{case}");
        }
        for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
            let replacement =
                format!("        initializer!{open}\n{FIXTURE_INITIALIZERS}\n{close};");
            let changed = source.replace(FIXTURE_INITIALIZERS, &replacement);
            assert!(
                uses_private_record_fields(JOURNAL, &changed),
                "initializer macro {open}"
            );
        }
        for added in [
            "fn render(record: Record) { render(record.entry_ip); }",
            "fn other(record: Record) { let raw = record.continuity; }",
        ] {
            assert!(uses_private_record_fields(
                JOURNAL,
                &format!("{source}\n{added}")
            ));
        }
    }

    #[test]
    fn function_locator_handles_the_actual_array_return_without_accepting_declarations() {
        let source = producer_fixture();
        let (_, body) = function(
            &source,
            "producer_agreement_pair",
            Some("pub(crate) mod tests {"),
        )
        .expect("the real array-return helper has a body");
        assert!(source[body].contains(FIXTURE_INITIALIZERS));
        assert!(
            function(
                "fn declaration() -> ([u8; 224], [u8; 632]);",
                "declaration",
                None
            )
            .is_none()
        );
        for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
            let source = format!("item!{open}fn direct() -> bool {{ true }}{close}");
            assert!(function(&source, "direct", None).is_none());
        }
    }

    #[test]
    fn real_journal_has_only_internal_corroboration_reads() {
        assert!(!uses_private_record_fields(JOURNAL, &journal()));
    }

    #[test]
    fn real_transport_has_only_borrowed_joint_callback_parameters() {
        for path in [
            "src/events.rs",
            "src/semantic_capture.rs",
            INPUT,
            "src/discovery/inventory_coordinator/semantics.rs",
        ] {
            let source = std::fs::read_to_string(path).expect("read real transport source");
            assert_eq!(model_marker(path, &source), None, "{path}");
        }
    }

    #[test]
    fn private_guard_exception_cannot_authorize_other_consumers() {
        let source = journal();
        for path in [
            "src/render.rs",
            "src/output.rs",
            "src/semantics_objects/other.rs",
        ] {
            assert!(uses_private_record_fields(path, &source), "{path}");
        }
        for changed in [
            source.replace("fn end_agrees_with_begin(", "fn other_consumer("),
            source.replace(
                GUARDS,
                &format!("{GUARDS}\n    render(base.continuity.entry_ip);"),
            ),
            source.replace(
                "return false;\n    }\n    if !stamp_agrees",
                "return true;\n    }\n    if !stamp_agrees",
            ),
            source.replace("entry_ip != begin", "entry_ip == begin"),
            format!("{source}\nfn leak() {{ render(record.entry_stamp); }}"),
            format!("{source}\nfn leak() {{ render(record.return_stamp); }}"),
            format!("{source}\nfn leak() {{ render(record.continuity); }}"),
            format!("{source}\nfn leak() {{ let _ = decode_record(bytes); }}"),
            format!("{source}\nfn end_agrees_with_begin() {{}}"),
        ] {
            assert!(uses_private_record_fields(JOURNAL, &changed));
        }
    }

    #[test]
    fn borrowed_model_exception_cannot_authorize_bodies_or_other_callbacks() {
        let source = input();
        for path in [
            "src/events.rs",
            "src/semantic_capture.rs",
            "src/discovery/inventory_coordinator/semantics.rs",
        ] {
            assert!(model_marker(path, &source).is_some(), "{path}");
        }
        for changed in [
            source.replace("fn deliver_joint_seal(", "fn another_callback("),
            source.replace("model: &crate::semantics_objects::ObjectSemantics,", "model: crate::semantics_objects::ObjectSemantics,"),
            source.replace("model: &crate::semantics_objects::ObjectSemantics,", "model: &mut crate::semantics_objects::ObjectSemantics,"),
            source.replace("let was_joint =", "let _ = crate::semantics_objects::ObjectSemantics::default();\n        let was_joint ="),
            source.replace("let was_joint =", "let _: Option<crate::semantics_objects::ObjectSemantics> = None;\n        let was_joint ="),
            source.replace("let now_joint = self", "let _: Option<crate::semantics_objects::ObjectSemantics> = None;\n        let now_joint = self"),
            source.replace(
                ") -> crate::semantics_key_use::SealApplyOutcome {",
                ") -> crate::semantics_objects::ObjectSemantics {",
            ),
            format!("{source}\nfn deliver_joint_seal() {{}}"),
            format!("{source}\nfn transport(model: &crate::semantics_objects::ObjectSemantics) {{}}"),
        ] {
            assert!(model_marker(INPUT, &changed).is_some());
        }
        for marker in [
            "ObjectDomain",
            "OriginFact",
            "RefCut",
            "CallToken",
            "CompleteInputPrefix",
        ] {
            let changed = source.replace(
                "let was_joint =",
                &format!("let _ = {marker}::new();\n        let was_joint ="),
            );
            assert_eq!(model_marker(INPUT, &changed), Some(marker));
        }
    }

    #[test]
    fn corroboration_must_be_unique_direct_code_in_the_top_level_function() {
        let source = journal();
        for changed in [
            source.replace(GUARDS, &format!("{GUARDS}\n{GUARDS}")),
            source.replace(GUARDS, &format!("    if false {{\n{GUARDS}\n    }}")),
            format!("fn wrapper() {{\n{source}\n}}"),
            format!("/* {source} */"),
            format!("const HIDDEN: &str = r###\"{source}\"###;"),
            format!("{source}\nfn  end_agrees_with_begin () {{}}"),
        ] {
            assert!(uses_private_record_fields(JOURNAL, &changed));
        }
    }

    #[test]
    fn borrowed_parameters_must_be_unique_direct_code_in_the_registry_impl() {
        let source = input();
        for changed in [
            source.replace("impl CallerRegistry {", "impl Renderer {"),
            format!("mod renderer {{\n{source}\n}}"),
            format!("/* {source} */"),
            format!("const HIDDEN: &str = r###\"{source}\"###;"),
            source.replace(
                "model: &crate::semantics_objects::ObjectSemantics,",
                "callback: fn(model: &crate::semantics_objects::ObjectSemantics,),",
            ),
            format!("{source}\nfn  deliver_joint_seal () {{}}"),
        ] {
            assert!(model_marker(INPUT, &changed).is_some());
        }
    }

    #[test]
    fn algorithm_failure_borrow_requires_the_real_test_only_helper() {
        const NAME: &str = "deliver_joint_algorithm_failure_for_test";
        const HEADER: &str =
            "#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_failure_for_test(";
        let source = input();
        assert_eq!(source.matches(HEADER).count(), 1);
        assert_eq!(model_marker(INPUT, &source), None);

        for changed in [
            source.replace(HEADER, "pub(crate) fn deliver_joint_algorithm_failure_for_test("),
            source.replace("#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm", "#[cfg(not(test))]\n    pub(crate) fn deliver_joint_algorithm"),
            source.replace(HEADER, "/* #[cfg(test)] */\n    pub(crate) fn deliver_joint_algorithm_failure_for_test("),
            source.replace(HEADER, "#[doc = \"#[cfg(test)]\"]\n    pub(crate) fn deliver_joint_algorithm_failure_for_test("),
            source.replace(NAME, "other_algorithm_failure"),
            source.replace("impl CallerRegistry {", "impl Renderer {"),
            format!("{source}\nimpl CallerRegistry {{\n    #[cfg(test)]\n    fn {NAME}() {{}}\n}}"),
        ] {
            assert!(model_marker(INPUT, &changed).is_some());
        }

        let (signature, body) = function(&source, NAME, Some("impl CallerRegistry {")).unwrap();
        for parameter in [
            "model: crate::semantics_objects::ObjectSemantics,",
            "model: &mut crate::semantics_objects::ObjectSemantics,",
            "callback: fn(model: &crate::semantics_objects::ObjectSemantics,),",
        ] {
            let mut changed = source.clone();
            changed.replace_range(
                signature.clone(),
                &source[signature.clone()].replace(MODEL_PARAMETER, parameter),
            );
            assert!(model_marker(INPUT, &changed).is_some());
        }
        for declaration in [
            "let _owned = crate::semantics_objects::ObjectSemantics::new();",
            "let _owned: crate::semantics_objects::ObjectSemantics;",
        ] {
            let mut changed = source.clone();
            changed.insert_str(body.start, declaration);
            assert!(model_marker(INPUT, &changed).is_some());
        }
        let mut changed = source.clone();
        changed.replace_range(
            signature.end + 1..body.start - 1,
            " -> &crate::semantics_objects::ObjectSemantics ",
        );
        assert!(model_marker(INPUT, &changed).is_some());
    }

    #[test]
    fn test_only_helper_cannot_be_input_to_an_attribute_stripping_macro() {
        let source = input();
        let header = "#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_failure_for_test(";
        let begin = source.find(header).unwrap();
        let (_, body) = function(
            &source,
            "deliver_joint_algorithm_failure_for_test",
            Some("impl CallerRegistry {"),
        )
        .unwrap();
        let item = &source[begin..body.end + 1];
        let rejected: Vec<_> = [('(', ')'), ('[', ']')]
            .into_iter()
            .map(|(open, close)| {
                let mut changed = source.clone();
                changed.replace_range(
                    begin..body.end + 1,
                    &format!("strip_test_gate!{open}\n    {item}\n    {close};"),
                );
                model_marker(INPUT, &changed).is_some()
            })
            .collect();
        assert_eq!(rejected, [true, true]);
    }

    #[test]
    fn algorithm_seal_borrow_requires_the_real_test_only_helper() {
        const NAME: &str = "deliver_joint_algorithm_seal_for_test";
        const HEADER: &str =
            "#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_seal_for_test(";
        let source = input();
        assert_eq!(source.matches(HEADER).count(), 1);
        assert_eq!(model_marker(INPUT, &source), None);

        for changed in [
            source.replace(HEADER, "pub(crate) fn deliver_joint_algorithm_seal_for_test("),
            source.replace(HEADER, "#[cfg(not(test))]\n    pub(crate) fn deliver_joint_algorithm_seal_for_test("),
            source.replace(HEADER, "/* #[cfg(test)] */\n    pub(crate) fn deliver_joint_algorithm_seal_for_test("),
            source.replace(HEADER, "#[doc = \"#[cfg(test)]\"]\n    pub(crate) fn deliver_joint_algorithm_seal_for_test("),
            source.replace(NAME, "other_algorithm_seal"),
            source.replace("impl CallerRegistry {", "impl Renderer {"),
            format!("{source}\nimpl CallerRegistry {{\n    #[cfg(test)]\n    fn {NAME}() {{}}\n}}"),
        ] {
            assert!(model_marker(INPUT, &changed).is_some());
        }

        let (signature, body) = function(&source, NAME, Some("impl CallerRegistry {")).unwrap();
        for parameter in [
            "model: crate::semantics_objects::ObjectSemantics,",
            "model: &mut crate::semantics_objects::ObjectSemantics,",
            "callback: fn(model: &crate::semantics_objects::ObjectSemantics,),",
        ] {
            let mut changed = source.clone();
            changed.replace_range(
                signature.clone(),
                &source[signature.clone()].replace(MODEL_PARAMETER, parameter),
            );
            assert!(model_marker(INPUT, &changed).is_some());
        }
        for declaration in [
            "let _owned = crate::semantics_objects::ObjectSemantics::new();",
            "let _owned: crate::semantics_objects::ObjectSemantics;",
        ] {
            let mut changed = source.clone();
            changed.insert_str(body.start, declaration);
            assert!(model_marker(INPUT, &changed).is_some());
        }
        let mut changed = source.clone();
        changed.replace_range(
            signature.end + 1..body.start - 1,
            " -> &crate::semantics_objects::ObjectSemantics ",
        );
        assert!(model_marker(INPUT, &changed).is_some());
    }

    #[test]
    fn algorithm_seal_helper_cannot_be_input_to_an_attribute_stripping_macro() {
        let source = input();
        let header = "#[cfg(test)]\n    pub(crate) fn deliver_joint_algorithm_seal_for_test(";
        let begin = source.find(header).unwrap();
        let (_, body) = function(
            &source,
            "deliver_joint_algorithm_seal_for_test",
            Some("impl CallerRegistry {"),
        )
        .unwrap();
        let item = &source[begin..body.end + 1];
        let rejected: Vec<_> = [('(', ')'), ('[', ']'), ('{', '}')]
            .into_iter()
            .map(|(open, close)| {
                let mut changed = source.clone();
                changed.replace_range(
                    begin..body.end + 1,
                    &format!("strip_test_gate!{open}\n    {item}\n    {close};"),
                );
                model_marker(INPUT, &changed).is_some()
            })
            .collect();
        assert_eq!(rejected, [true, true, true]);
    }

    #[test]
    fn counts_and_same_consumer_drain_keep_their_existing_exemptions() {
        for source in [
            "let rounds = outcome.continuity_rounds;",
            "if engine.continuity_deferred {}",
            "let cuts = report.continuity_cuts;",
            "let events = poll_records_to_position();",
        ] {
            assert!(!uses_private_record_fields("src/render.rs", source));
        }
        assert_eq!(model_marker(INPUT, "fn route() { deliver(tail); }"), None);
    }
}
