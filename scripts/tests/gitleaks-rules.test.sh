#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Holds the 1Password service-account token rule of .gitleaks.toml to the
# shapes it must and must not report. The rule once had no left boundary, so
# any identifier with "ops_" inside a word (a test name ending a word in
# "dr", "st" or "pr" before it, followed by 40 name characters) was reported
# as a token. The full-history scan cannot be made green again by a later
# commit, so a false positive there is expensive; hence a test.
#
# The token-shaped strings are put together at run time: this file holds
# none for the history scan to find. Needs gitleaks (GITLEAKS, or on PATH)
# and python3.
set -uo pipefail

export LC_ALL=C

gitleaks="${GITLEAKS:-gitleaks}"
command -v "$gitleaks" >/dev/null 2>&1 || { echo "gitleaks not found; set GITLEAKS" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }

repo_root="$(git rev-parse --show-toplevel)"
config="$repo_root/.gitleaks.toml"
rule='onepassword-service-account-token'
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

prefix='op''s_'
body="$(printf 'Ab3-d_9%.0s' 1 2 3 4 5 6 7)"
token="$prefix$body"

findings() {
  rm -f "$work/report.json"
  "$gitleaks" dir --no-banner --config "$config" --report-format json \
    --report-path "$work/report.json" "$work/case.txt" >/dev/null 2>&1
  python3 -c '
import json, sys
try:
    report = json.load(open(sys.argv[1]))
except FileNotFoundError:
    sys.exit("gitleaks wrote no report")
print(sum(1 for finding in report or [] if finding.get("RuleID") == sys.argv[2]))
' "$work/report.json" "$rule"
}

failures=0
check() {
  local expected="$1" label="$2" line="$3" got
  printf '%s\n' "$line" >"$work/case.txt"
  got="$(findings)" || { echo "FAIL: $label: $got"; failures=$((failures + 1)); return; }
  if [ "$got" = "$expected" ]; then
    echo "ok: $label"
  else
    echo "FAIL: $label: expected $expected finding(s), got $got"
    failures=$((failures + 1))
  fi
}

# Where a token is written, it is reported.
check 1 "at the start of a line" "$token"
check 1 "after =" "OP_SERVICE_ACCOUNT_TOKEN=$token"
check 1 "after a double quote" "token = \"$token\""
check 1 "after a single quote" "token = '$token'"
check 1 "after a colon" "token:$token"
check 1 "after a space" "token $token"
check 1 "as a JSON value" "{\"token\": \"$token\"}"
check 1 "as a YAML value" "token: $token"
check 1 "as a quoted Rust value" "let credential = \"$token\";"
check 1 "as a quoted value on the same Rust line as a lookalike function name" "fn st$token() { let credential = \"$token\"; }"
# "ops_" inside a word is not a token.
check 0 "inside a word ending in dr" "def test_firewall_dr$token"
check 0 "inside a word ending in st" "st$token"
check 0 "inside a word ending in pr" "pr$token"

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "all cases passed"
