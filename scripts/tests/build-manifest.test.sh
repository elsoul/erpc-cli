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

# Run the gate, and this harness's own re-exec below, under the SAME bash
# that was used to start it -- never whatever `#!/usr/bin/env bash` finds on
# PATH. On a machine with a newer bash on PATH the CI job named "gates under
# bash 3.2" ran only this harness under 3.2 while the gate itself ran under
# bash 5, which does not share 3.2's collation behaviour. That is why two
# locale defects passed locally and failed only on the runner.
sh="${BASH:-/bin/bash}"

# A gate must behave the same whatever locale the caller has. Outside the C
# locale a bash range follows collation order: `[A-Z]` matches lowercase too,
# and `[!A-Za-z0-9._-]` stops matching accented letters. That silently turned
# two live rules into no-ops while this suite passed on a developer machine
# with no LANG set and failed only on the runner. So the suite runs itself
# once per locale and every case must pass in both.
if [ -z "${ERPC_TEST_LOCALE:-}" ]; then
  utf8=""
  # Deliberately not `locale -a | grep -q`: under `set -o pipefail` the -q
  # exit closes the pipe, `locale` dies of SIGPIPE and the pipeline reports
  # failure, so every locale looked absent. Match the captured list instead.
  all_locales="$(locale -a 2>/dev/null || true)"
  for cand in en_US.UTF-8 en_GB.UTF-8 en_US.utf8; do
    case "
$all_locales
" in
      *"
$cand
"*) utf8="$cand"; break;;
    esac
  done
  if [ -z "$utf8" ]; then
    echo "no dictionary-collation UTF-8 locale on this machine, so the" >&2
    echo "locale-independence of the gate cannot be verified here." >&2
    exit 1
  fi
  rc=0
  for loc in C "$utf8"; do
    printf '== locale %s ==\n' "$loc"
    ERPC_TEST_LOCALE="$loc" LC_ALL="$loc" LANG="$loc" "$sh" "$0" "$@" || rc=1
  done
  exit "$rc"
fi

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
  # Artifacts that DO reach the glob and must be rejected by the name filter.
  # A name without the erpc- prefix never reaches it, so it proves nothing.
  printf 'src\n' > "$dir/erpc-source.tar.gz"
  printf 'x\n' > "$dir/erpc-installer.tar.gz"
  printf '#!/bin/sh\n' > "$dir/erpc-installer.sh"
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# 1. A realistic artifact directory produces a manifest covering every target.
make_artifacts "$tmp/good"
if out=$("$sh" "$script" "$tmp/good" v1.2.3 abc123 2>"$tmp/err"); then
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
  printf '%s' "$out" | grep -q 'erpc-source' && bad "excludes the source archive" "counted" || ok "excludes the source archive"
  printf '%s' "$out" | grep -q 'erpc-installer' && bad "excludes the installer archive" "counted" || ok "excludes the installer archive"
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1 \
      && ok "emits valid JSON" || bad "emits valid JSON"
  fi
else
  bad "covers all $target_count configured targets" "script failed: $(cat "$tmp/err")"
fi

# 2. Refuses rather than signing a manifest that vouches for nothing.
mkdir -p "$tmp/empty"
"$sh" "$script" "$tmp/empty" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses an empty artifact directory" "it emitted a manifest" \
  || ok "refuses an empty artifact directory"

# 3. Refuses when the SBOM is absent.
make_artifacts "$tmp/nosbom"; rm -f "$tmp/nosbom"/*.cdx.json
"$sh" "$script" "$tmp/nosbom" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses a manifest without an SBOM" "it emitted one" \
  || ok "refuses a manifest without an SBOM"

# 4. Refuses when a target is missing, which is the case the count check exists
#    for and which previously failed open.
make_artifacts "$tmp/partial"
rm -f "$(ls "$tmp"/partial/erpc-*.tar.xz 2>/dev/null | head -1)"
"$sh" "$script" "$tmp/partial" v1.2.3 abc123 >/dev/null 2>&1 \
  && bad "refuses a manifest missing a target" "it emitted one" \
  || ok "refuses a manifest missing a target"

# 5. An artifact name that would need escaping inside the manifest JSON must
# be refused, not written. Under en_US.UTF-8 the name filter's range stopped
# matching accented letters, so this exact file was accepted and its name went
# into the signed manifest unescaped. The release job runs with a UTF-8 LANG.
# The assertion is on the MESSAGE, not the exit code. An extra archive also
# makes the target count disagree, so a non-zero exit proves nothing about
# the name filter: with the locale fix reverted this case still exited 1, for
# the wrong reason. Only the filter emits this line.
mkdir -p "$tmp/badname"
make_artifacts "$tmp/badname"
# $'...' so the name really carries the UTF-8 bytes. Written as "\xc3\xa9"
# inside double quotes bash leaves the backslash in the name, and a backslash
# is refused in every locale, so the case would pass without testing anything.
accented="$tmp/badname/erpc-x86_64-apple-darwin-caf"$'\303\251'".tar.xz"
printf 'archive\n' > "$accented"
name_err="$("$sh" "$script" "$tmp/badname" v1.2.3 abc123 2>&1 >/dev/null)"
case "$name_err" in
  *"unexpected character in artifact name"*)
    ok "refuses an artifact name needing JSON escaping";;
  *)
    bad "refuses an artifact name needing JSON escaping" \
        "the name filter never fired; it said: $name_err";;
esac

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
