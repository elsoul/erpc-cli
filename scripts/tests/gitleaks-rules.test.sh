#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the project rules in .gitleaks.toml that have needed fixing.
#
#   scripts/tests/gitleaks-rules.test.sh [path/to/gitleaks]   (default: gitleaks)
#
# onepassword-service-account-token: a service account token is ops_
# followed by base64 (standard or URL-safe) of a JSON object, so it starts
# ops_eyJ. The rule once matched ops_ plus any 40 identifier characters, and
# so reported long Rust test names containing "stops_" as tokens. This checks
# that such names are not reported, and that tokens still are: in either
# alphabet, glued to other text, after an escaped newline, hard-wrapped, and
# cut off at 44 characters (ops_ and 40 more, the old rule's minimum length).
#
# Samples are built when the test runs, never written to a tracked file, so
# the repository holds no token-shaped string. gitleaks reads them on stdin
# with this repository's config, and the test checks which rule fired.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
GITLEAKS="${1:-gitleaks}" python3 - <<'PY'
import base64
import json
import os
import subprocess
import tempfile

GITLEAKS = os.environ["GITLEAKS"]
RULE = "onepassword-service-account-token"


def rules_fired(text):
    with tempfile.TemporaryDirectory() as d:
        report = os.path.join(d, "report.json")
        run = subprocess.run(
            [GITLEAKS, "stdin", "--no-banner", "--redact", "--config", ".gitleaks.toml",
             "--report-format", "json", "--report-path", report, "--exit-code", "0"],
            input=text.encode(), capture_output=True,
        )
        if run.returncode != 0:
            raise SystemExit(f"gitleaks failed ({run.returncode}): {run.stderr.decode()[-400:]}")
        with open(report) as f:
            return {finding["RuleID"] for finding in json.load(f)}


# A made-up token of the real shape: ops_ and base64 of a JSON object. The
# first value is chosen so that the base64 has a + or / (and the URL-safe
# form a - or _) within the first 37 characters after eyJ, the part the
# rule's minimum covers; otherwise a rule missing those characters would
# still match and the alphabet would go untested.
def claims(first):
    return {
        "x": first,
        "signInAddress": "example.1password.com",
        "userAuth": {"method": "SRPg-4096", "alg": "PBES2g-HS256", "iterations": 650000,
                     "salt": "x" * 22},
        "email": "service-account@example.invalid",
        "muk": {"alg": "A256GCM", "k": "y" * 43, "kty": "oct", "kid": "mp"},
        "secretKey": "A3-XXXXXX-XXXXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
        "deviceUuid": "device0device0device0dev",
    }


def encode(first):
    return base64.b64encode(json.dumps(claims(first), separators=(",", ":")).encode()).decode()


for first in ("".join(t) for n in range(1, 4) for t in __import__("itertools").product("?>~ab", repeat=n)):
    std = encode(first)
    if any(c in "+/" for c in std[3:40]):
        break
else:
    raise SystemExit("no sample value puts + or / in the first 37 characters after eyJ")
url = std.replace("+", "-").replace("/", "_").rstrip("=")
token, token_url = "ops_" + std, "ops_" + url
assert token.startswith("ops_eyJ") and len(token) > 300, token[:12]
assert any(c in "-_" for c in url[3:40]), "URL-safe sample has no - or _ early"


def wrap(text, width):
    return "\n".join(text[i:i + width] for i in range(0, len(text), width))


reported = [
    ("an assignment", f"OP_SERVICE_ACCOUNT_TOKEN={token}"),
    ("URL-safe base64 in a JSON string", f'{{"token": "{token_url}"}}'),
    ("a line on its own", token),
    ("glued to a word character", f"TOKEN_{token}"),
    ("after an escaped newline", f'{{"log": "starting\\n{token}"}}'),
    ("hard-wrapped at 76 columns", wrap(token, 76)),
    ("an export wrapped at 80 columns", wrap(f"export OP_SERVICE_ACCOUNT_TOKEN={token}", 80)),
    # ops_ and 40 more: the old rule's minimum length.
    ("cut off at 44 characters", token[:44] + "..."),
]
not_reported = [
    ("the six test names it used to report", "\n".join([
        "    fn a_repoint_that_stops_says_what_is_left_and_when_to_send_it_again() {",
        "    async fn a_line_that_stops_being_active_during_the_build_hands_nothing_over() {",
        "    fn a_deploy_stops_before_anything_at_lists_erpc_would_not_put_on_the_server() {",
        "    async fn a_revoke_drops_trust_under_every_id_the_bytes_were_trusted_by() {",
        "    async fn nobody_to_say_yes_stops_the_move_before_the_account_or_the_server_is_reached() {",
        "    async fn a_move_that_stops_leaves_erpc_toml_and_the_pins_as_they_were() {",
    ])),
    ("a long identifier after stops_", "let stops_" + "and_then_" * 12 + "done = 1;"),
    # Not a service account token's shape, so not this rule's to report.
    ("ops_ followed by something other than eyJ", "ops_" + "abc123" * 10),
]

failed = []
for label, text in reported:
    if RULE not in rules_fired(text):
        failed.append(f"not reported: {label}")
for label, text in not_reported:
    if RULE in rules_fired(text):
        failed.append(f"reported by mistake: {label}")
if failed:
    raise SystemExit("gitleaks rule self-test:\n  " + "\n  ".join(failed))
print(f"gitleaks {RULE}: {len(reported)} token shapes reported, {len(not_reported)} identifier cases not")
PY
