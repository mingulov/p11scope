# SPDX-License-Identifier: GPL-3.0-or-later
"""Machine-readable v3 schema agrees with the release oracle (F-50, F-12).

docs/schema/observed-profile-v3.schema.json is a consumer aid, not the
enforcement: scripts/check-capture-evidence.py stays the gate. These tests
keep the two in agreement — the closed evidence key sets per lane, the
required enums, and the lane discriminator — so the schema cannot drift
from what the oracle accepts.

Run: python3 -I tests/python/test_schema_json.py -v
"""

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
SCHEMA = json.loads(
    (ROOT / "docs" / "schema" / "observed-profile-v3.schema.json").read_text(
        encoding="utf-8"
    )
)


def evidence_schema():
    return SCHEMA["properties"]["evidence"]


class SchemaOracleAgreement(unittest.TestCase):
    def test_evidence_keys_match_oracle_closed_sets(self):
        """Schema evidence properties are exactly the oracle's closed key
        universe: base keys + profile-only keys + run-only child flag."""
        wanted = (
            set(CHECKER["BASE_EVIDENCE_KEYS"])
            | set(CHECKER["PROFILE_V3_FIELDS"])
            | {"child_still_running"}
        )
        self.assertEqual(set(evidence_schema()["properties"]), wanted)

    def test_metrics_required_is_oracle_base(self):
        """Metrics requires exactly the oracle base key set."""
        self.assertEqual(
            set(evidence_schema()["required"]), set(CHECKER["BASE_EVIDENCE_KEYS"])
        )

    def test_profile_branch_requires_versioned_only_fields(self):
        """The lane==profile branch requires exactly the 4 versioned-only
        fields; the metrics branch forbids them."""
        branches = SCHEMA["allOf"]
        profile = next(
            b
            for b in branches
            if b["if"] == {"properties": {"lane": {"const": "profile"}}}
        )
        self.assertEqual(
            set(profile["then"]["properties"]["evidence"]["required"]),
            set(CHECKER["PROFILE_V3_FIELDS"]),
        )
        metrics = next(
            b
            for b in branches
            if b["if"] == {"properties": {"lane": {"const": "metrics"}}}
        )
        forbidden = {
            req
            for clause in metrics["then"]["properties"]["evidence"]["not"]["anyOf"]
            for req in clause["required"]
        }
        self.assertEqual(forbidden, set(CHECKER["PROFILE_V3_FIELDS"]))

    def test_function_row_identity_matches_oracle(self):
        """`functions[].target` and `.ordinals` keys and bounds match the
        oracle's closed row-identity shape (review answer (c))."""
        row = SCHEMA["properties"]["functions"]["items"]["properties"]
        self.assertEqual(
            set(row["target"]["properties"]), set(CHECKER["FUNCTION_TARGET_KEYS"])
        )
        self.assertEqual(
            set(row["ordinals"]["items"]["properties"]),
            set(CHECKER["FUNCTION_ORDINAL_KEYS"]),
        )
        self.assertEqual(
            row["ordinals"]["items"]["properties"]["ordinal"]["maximum"] + 1,
            CHECKER["MAX_FUNCTION_ORDINALS"],
        )

    def test_enums_match_oracle(self):
        """Closed enums in the schema equal the oracle's vocabularies."""
        props = evidence_schema()["properties"]
        self.assertEqual(
            set(props["verdict_detail"]["enum"]), set(CHECKER["VERDICT_DETAILS"])
        )
        self.assertEqual(
            set(props["pause"]["enum"]), set(CHECKER["PAUSE_VALUES"])
        )
        self.assertEqual(
            set(props["completeness"]["enum"]), {"COMPLETE", "PARTIAL"}
        )
        self.assertEqual(
            set(props["p11scope_env"]["items"]["properties"]["name"]["enum"]),
            set(CHECKER["P11SCOPE_ENV_VARS"]),
        )
        skip_reasons = set(
            props["skipped"]["items"]["properties"]["reason"]["enum"]
        )
        self.assertEqual(
            skip_reasons,
            set(CHECKER["ENTRY_REASONS"]) | set(CHECKER["DISCOVERY_REASONS"]),
        )
        self.assertEqual(
            set(SCHEMA["properties"]["lane"]["enum"]),
            {CHECKER["PROFILE_LANE"], CHECKER["METRICS_LANE"]},
        )

    def test_selection_shape_matches_oracle(self):
        """Selection sub-object keys and bounds match the oracle."""
        selection = evidence_schema()["properties"]["interface_selection"]
        self.assertEqual(
            set(selection["properties"]), set(CHECKER["SELECTION_KEYS"])
        )
        self.assertEqual(
            set(
                selection["properties"]["providers"]["items"]["properties"][
                    "coverage"
                ]["enum"]
            ),
            set(CHECKER["SELECTION_COVERAGE"]),
        )
        self.assertEqual(
            set(
                selection["properties"]["tuples"]["items"]["properties"][
                    "authority"
                ]["enum"]
            ),
            set(CHECKER["SELECTION_AUTHORITIES"]),
        )

    def test_scheduling_shape_matches_oracle(self):
        """Scheduling closed keys match the oracle."""
        scheduling = evidence_schema()["properties"]["scheduling"]
        self.assertEqual(
            set(scheduling["properties"]), set(CHECKER["SCHEDULING_KEYS"])
        )
        self.assertEqual(
            set(scheduling["properties"]["phase_ms"]["properties"]),
            set(CHECKER["SCHEDULING_PHASE_KEYS"]),
        )


if __name__ == "__main__":
    unittest.main()
