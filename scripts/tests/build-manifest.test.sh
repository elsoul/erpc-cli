#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/release/build-manifest.sh.
#
# This script runs once per release and had never been executed: it globbed
# .tar.gz while cargo-dist emits .tar.xz, so it would have aborted the signing
# job every time, and the only verifiable release control would never have run.
# These cases feed it realistically named artifacts.
#
#   scripts/tests/build-manifest.test.sh
set -uo pipefail

repo_root="$(git rev-parse --show-toplevel)"
script="$repo_root/scripts/release/build-manifest.sh"
pass=0
fail=0

ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n   %s\n' "$1" "${2:-}"; }

# The targets cargo-dist is configured to build, read from the same file the
# script checks against, so this test cannot drift from the configuration.
targets=$(grep -oE '"[a-z0-9_]+-[a-z0-9_-]+",' "$repo_root/dist-workspace.toml" | tr -d '",')
target_count=$(printf '%s\n' "$targets" | grep -c .)

make_artifacts() {
  local dir="$1" t
  mkdir -p "$dir"
  for t in $targets; do
    case "$t" in
      *windows*) printf 'archive\n' > "$dir/erpc-$t.zip";;
      *) printf 'archive\n' > "$dir/erpc-$t.tar.xz";;
    esac
  done
  printf '{"bomFormat":"CycloneDX"}\n' > "$dir/erpc.cdx.json"
  # Artifacts that are not release targets and must not be counted.
  printf 'src\n' > "$dir/source.tar.gz"
  printf '#!/bin/sh\n' > "$dir/erpc-installer.sh"
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# 1. A realistic artifact directory produces a manifest covering every target.
make_artifacts "$tmp/good"
if out=$("$script" "$tmp/good" v1.2.3 abc123 2>"$tmp/err"); then
  got=$(printf '%s' "$out" | grep -o '"archive"' | grep -c .)
  if [ "$got" -eq "$target_count" ]; then
    ok "covers all $target_count configured targets"
  else
    bad "covers all $target_count configured targets" "manifest has $got"
  fi
  for t in $targets; do
    printf '%s' "$out" | grep -q "\"$t\"" || bad "manifest names $t" "missing"
  done
  printf '%s' "$out" | grep -q '"tag": "v1.2.3"' && ok "carries the tag" || bad "carries the tag"
  printf '%s' "$out" | grep -q '"commit": "abc123"' && ok "carries the commit" || bad "carries the commit"
  printf '%s' "$out" | grep -q '"sbom_sha256": "[0-9a-f]\{64\}"' && ok "carries the SBOM hash" || bad "carries the SBOM hash"
  printf '%s' "$out" | grep -q 'source.tar.gz' && bad "excludes the source archive" "source.tar.gz counted" || ok "excludes the source archive"
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1 \
      && ok "emits valid JSON" || bad "emits valid JSON"
  fi
else
  bad "covers all $target_count configured targets" "script failed: $(cat "$tmp/err")"
fi

# 2. Refuses rather than signing a manifest that vouches for nothing.
mkdir -p "$tmp/empty"
"$script" "$tmp/empty" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses an empty artifact directory" "it emitted a manifest" \
  || ok "refuses an empty artifact directory"

# 3. Refuses when the SBOM is absent.
make_artifacts "$tmp/nosbom"; rm -f "$tmp/nosbom"/*.cdx.json
"$script" "$tmp/nosbom" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses a manifest without an SBOM" "it emitted one" \
  || ok "refuses a manifest without an SBOM"

# 4. Refuses when a target is missing, which is the case the count check exists
#    for and which previously failed open.
make_artifacts "$tmp/partial"
rm -f "$(ls "$tmp"/partial/erpc-*.tar.xz 2>/dev/null | head -1)"
"$script" "$tmp/partial" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses a manifest missing a target" "it emitted one" \
  || ok "refuses a manifest missing a target"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
