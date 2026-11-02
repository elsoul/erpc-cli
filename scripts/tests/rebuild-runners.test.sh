#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Asserts that rebuild-compare in release-publish.yml rebuilds each Linux
# target on the runner image `dist plan` builds it on, with the same system
# packages and without a cross linker.
#
# The rebuild compares binary hashes, so it only means something when both
# builds ran in one environment. It first ran on ubuntu-latest with
# cargo-zigbuild while dist built natively on ubuntu-22.04 (x86_64) and
# ubuntu-22.04-arm (aarch64) with musl-gcc; aws-lc-sys is C, so the hashes
# could not have matched and the first tag would have failed at the
# comparison. The runners are chosen by cargo-dist and can change with a
# dist upgrade, hence a test that asks dist rather than a comment.
#
# Needs `dist` (cargo-dist) and `jq`; CI runs it in the dist-plan job. It is
# not in the gates-bash32 job because that runner has no cargo-dist, and the
# script uses nothing beyond bash 3.2 that the other tests do not.
set -uo pipefail

export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
custom="$repo_root/.github/workflows/release-publish.yml"
[ -f "$custom" ] || { echo "missing $custom" >&2; exit 2; }
command -v dist >/dev/null || { echo "dist (cargo-dist) is not on PATH" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is not on PATH" >&2; exit 2; }

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n   %s\n' "$1" "${2:-}"; }

plan=$(cd "$repo_root" && dist plan --output-format=json 2>/dev/null) || {
  echo "dist plan failed" >&2; exit 2;
}

job=$(awk '
  /^  rebuild-compare:/ { inside = 1; next }
  inside && /^  [a-z]/ { exit }
  inside && /^[[:space:]]*#/ { next }
  inside { print }
' "$custom")
[ -n "$job" ] || { echo "could not find the rebuild-compare job in $custom" >&2; exit 2; }

# "target runner" pairs from the include: matrix.
pairs=$(printf '%s\n' "$job" | awk '
  /- target:/ { t = $NF }
  /runner:/ && t != "" { print t, $NF; t = "" }
')

if [ -z "$pairs" ]; then
  bad "rebuild-compare lists its targets with runners" \
      "no '- target:' / 'runner:' pairs in the job's matrix"
fi

# 1. Every Linux target dist builds is rebuilt, on the same runner.
dist_linux=$(printf '%s' "$plan" | jq -r '
  .ci.github.artifacts_matrix.include[]
  | select(.targets[0] | test("linux"))
  | "\(.targets[0]) \(.runner)"' | sort)
mine=$(printf '%s\n' "$pairs" | sed '/^$/d' | sort)
if [ -n "$dist_linux" ] && [ "$dist_linux" = "$mine" ]; then
  ok "each Linux target is rebuilt on the runner dist builds it on"
else
  bad "each Linux target is rebuilt on the runner dist builds it on" \
      "dist plan: $(printf '%s' "$dist_linux" | tr '\n' ';') rebuild-compare: $(printf '%s' "$mine" | tr '\n' ';')"
fi

# 1b. dist builds them on the bare runner. A container would make the
#     runner name meaningless for this comparison.
in_container=$(printf '%s' "$plan" | jq -r '
  [.ci.github.artifacts_matrix.include[]
   | select(.targets[0] | test("linux"))
   | select(.container != null)
   | .targets[0]] | join(" ")')
if [ -z "$in_container" ]; then
  ok "dist builds the Linux targets on the bare runner, not in a container"
else
  bad "dist builds the Linux targets on the bare runner, not in a container" \
      "built in a container: $in_container; rebuild-compare does not use one"
fi

# 2. The job uses the matrix runner rather than a fixed image.
if printf '%s\n' "$job" | grep -qE '^    runs-on:[[:space:]]*\$\{\{[[:space:]]*matrix\.runner[[:space:]]*\}\}'; then
  ok "rebuild-compare runs on matrix.runner"
else
  bad "rebuild-compare runs on matrix.runner" \
      "runs-on is not \${{ matrix.runner }}, so the pairs above are not what runs"
fi

# 3. The packages dist installs are installed for the rebuild too.
missing=""
for pkg in $(printf '%s' "$plan" | jq -r '
  .ci.github.artifacts_matrix.include[]
  | select(.targets[0] | test("linux"))
  | .packages_install // empty' \
  | grep -oE 'apt-get install( -[a-z]+)* .*' | sed -E 's/^apt-get install( -[a-z]+)* //' | tr ' ' '\n' | sed '/^-/d;/^$/d' | sort -u); do
  printf '%s\n' "$job" | grep -qE "apt-get install.*[[:space:]]$pkg([[:space:]]|\$)" || missing="$missing $pkg"
done
if [ -z "$missing" ]; then
  ok "the rebuild installs the packages dist installs"
else
  bad "the rebuild installs the packages dist installs" "not installed by rebuild-compare:$missing"
fi

# 4. No cross linker: dist builds these natively.
if printf '%s\n' "$job" | grep -q zigbuild; then
  bad "the rebuild does not use cargo-zigbuild" "zig links differently from the native musl-gcc build"
else
  ok "the rebuild does not use cargo-zigbuild"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
