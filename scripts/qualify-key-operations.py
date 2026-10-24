#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""STUB: compare the RSA application ledger with observed key operations.

The test commit carries this accepting stub so the twin-refusal tests fail
by assertion; the implementation commit replaces it with the real oracle.
"""


MAX_OBSERVER_BYTES = 8 * 1024 * 1024


class OracleRefusal(ValueError):
    """The observed output does not match the independent ledger."""


def read_observer_file(path):
    """Read an observer JSON document (stub: unbounded plain load)."""
    import json

    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def compare(_application_rows, _observer_doc):
    """Compare ledgers (stub: wrongly accepts every pair)."""
    return {"match": True}


def main(argv=None):
    """STUB CLI: exit 0 without comparing."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("application", help="application JSONL file")
    parser.add_argument("observer", help="observer inventory JSON file")
    parser.parse_args(argv)
    print(json.dumps({"match": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
