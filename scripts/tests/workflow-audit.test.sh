#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Regression guard for the workflow audit's enforcement configuration.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
from pathlib import Path
import re


def enforcing(text):
    # This deliberately accepts only the explicit job/step configuration used
    # here, not arbitrary YAML aliases or inherited defaults. A restructure
    # requires updating this regression guard in the same review.
    match = re.search(r"^  zizmor:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", text, re.M | re.S)
    if not match:
        return False
    job = match[1]
    action = re.search(r"^      - uses: zizmorcore/zizmor-action@[0-9a-f]{40}[^\n]*\n(.*?)(?=^      - |\Z)", job, re.M | re.S)
    if not action:
        return False
    settings = action[1]
    return (
        re.search(r"^        with:\s*$", settings, re.M) is not None
        and re.search(r"^          advanced-security: false\s*$", settings, re.M) is not None
        and re.search(r"^          min-severity: medium\s*$", settings, re.M) is not None
        and re.search(r"^          persona: regular\s*$", settings, re.M) is not None
        and "continue-on-error:" not in job
        and "security-events:" not in job
    )


actual = Path(".github/workflows/ci.yml").read_text()
assert enforcing(actual), "workflow audit must enforce findings without code-scanning upload"
for bad in [
    actual.replace("advanced-security: false", "advanced-security: true"),
    actual.replace("          advanced-security: false\n", ""),
    actual.replace("min-severity: medium", "min-severity: high"),
    actual.replace("persona: regular", "persona: auditor"),
    actual.replace("  zizmor:\n", "  zizmor:\n    continue-on-error: true\n"),
    actual.replace("  zizmor:\n", "  zizmor:\n    security-events: write\n"),
    actual.replace("  zizmor:\n", "  other-audit:\n"),
]:
    assert not enforcing(bad), "regression guard accepted disabled/changed enforcement"
print("workflow audit enforcement: valid job passes; 7 unsafe/changed configurations rejected")
PY
