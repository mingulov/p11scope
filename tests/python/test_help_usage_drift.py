# SPDX-License-Identifier: GPL-3.0-or-later
"""Help/usage/parser flag agreement (SYSPLAN residual F-30).

Three artifacts name the CLI surface: the parser in src/cli.rs, the USAGE
and scoped help texts, and docs/usage.md. Syntax equality between the help
texts is pinned in Rust (`scoped_help_syntax_lines_are_verbatim_from_global_usage`);
these tests pin the other two directions statically, without building:

- every `--flag` the parser accepts appears in USAGE or a scoped help
  text (a silent flag fails);
- every `--flag` USAGE or a scoped help advertises appears in
  docs/usage.md (undocumented flags like the old
  `--attach-backend`/`--version` gap fail).

CI runs this file (help-drift step). The Rust test
`usage_doc_documents_every_cli_flag` is the same agreement inside
`cargo test`; the two overlap deliberately so neither runner can drift.

Run: python3 -I tests/python/test_help_usage_drift.py -v
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_RS = ROOT / "src" / "cli.rs"
USAGE_MD = ROOT / "docs" / "usage.md"

FLAG = re.compile(r"--[a-z][a-z0-9-]*")


def usage_text():
    """USAGE plus every scoped help const body out of src/cli.rs.

    Lane B shortened the global USAGE into per-command topics: a flag
    named by any scoped `*_HELP` const is advertised, not silent. The
    assembled helps (`trace_help()`, `inventory_diff_help()`) only add
    numeric bound lines, so the const bodies carry every flag.
    """
    text = CLI_RS.read_text(encoding="utf-8")
    bodies = [
        match.group(1)
        for match in re.finditer(
            r'(?:pub )?const (?:USAGE|[A-Z0-9_]*HELP[A-Z0-9_]*)[^=]*= "(.*?)";',
            text,
            re.DOTALL,
        )
    ]
    assert bodies, "no help consts found in src/cli.rs"
    return "\n".join(bodies)


def parser_flags():
    """`--flag` literals the parser accepts.

    String literals in match arms and `require_value` sites. The
    `unknown_arg` refusal table is cut out first: removed flags
    (`--provenance-module`, `--trusted-workload`) and misplaced-option
    hints live there and are refused with a named error, never accepted
    (pinned by `removed_flags_get_a_named_hint`).
    """
    text = CLI_RS.read_text(encoding="utf-8")
    start = text.index("fn unknown_arg(")
    end = text.index("fn run_unknown_arg(")
    text = text[:start] + text[end:]
    # Unit tests name every flag including removed ones; only production
    # code says what the parser accepts.
    text = text[: text.index("mod tests")]
    flags = set()
    for match in re.finditer(r'"(--[a-z][a-z0-9-]*)"', text):
        flags.add(match.group(1))
    return flags


class HelpUsageDrift(unittest.TestCase):
    def test_parser_flags_appear_in_usage(self):
        advertised = set(FLAG.findall(usage_text()))
        for flag in sorted(parser_flags()):
            # `--help` is handled, not advertised: every subcommand accepts
            # it but USAGE stays the surface, not the meta-surface.
            if flag == "--help":
                continue
            self.assertIn(flag, advertised, f"parser accepts {flag}, USAGE never names it")

    def test_usage_flags_appear_in_usage_md(self):
        doc = USAGE_MD.read_text(encoding="utf-8")
        for flag in sorted(set(FLAG.findall(usage_text()))):
            self.assertIn(flag, doc, f"USAGE advertises {flag}, docs/usage.md never documents it")


if __name__ == "__main__":
    unittest.main()
