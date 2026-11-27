#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

# These are structural checks of the two pinned workflows. The dist-plan job
# separately checks target coverage against cargo-dist.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/../.." && pwd)"
tagged="$root/.github/workflows/release-publish.yml"
untagged="$root/.github/workflows/release-preflight.yml"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

job() {
  awk -v name="$2" '
    $0 == "  " name ":" { inside = 1; next }
    inside && /^  [a-z]/ { exit }
    inside && !/^[[:space:]]*#/ { print }
  ' "$1"
}

native_runners() {
  local pairs expected
  pairs=$(printf '%s\n' "$1" | awk '
    /^[[:space:]]*- target:/ { target = $NF }
    /^[[:space:]]*runner:/ && target != "" { print target, $NF; target = "" }
  ' | sort)
  expected='aarch64-apple-darwin macos-15
aarch64-unknown-linux-musl ubuntu-22.04-arm
x86_64-apple-darwin macos-15-intel
x86_64-pc-windows-msvc windows-2022
x86_64-unknown-linux-musl ubuntu-22.04'
  # Match the literal workflow expression.
  # shellcheck disable=SC2016
  [ "$pairs" = "$expected" ] && printf '%s\n' "$1" | grep -Fxq '    runs-on: ${{ matrix.runner }}'
}

check_wiring() {
  local smoke archive dependencies
  smoke=$(job "$1" smoke-archives)
  archive=$(job "$2" archive)
  dependencies=$(job "$1" sign | sed -n 's/^    needs:[[:space:]]*//p' | tr '[],' '   ')
  if ! printf '%s\n' "$dependencies" | grep -Eq '(^|[[:space:]])smoke-archives([[:space:]]|$)'; then
    echo "sign must depend on the archive smoke job"
    return 1
  fi
  # shellcheck disable=SC2016
  if ! printf '%s\n' "$smoke" | grep -Fxq '        run: scripts/release/check-security-check-archive.sh "artifacts/erpc-$RELEASE_TARGET"'; then
    echo "tagged smoke job must run the archive check"
    return 1
  fi
  # shellcheck disable=SC2016
  if ! printf '%s\n' "$archive" | grep -Fxq '          scripts/release/check-security-check-archive.sh "target/distrib/erpc-$RELEASE_TARGET"'; then
    echo "untagged preflight must run the archive check"
    return 1
  fi
  if ! native_runners "$smoke"; then
    echo "tagged smoke job must pair each target with its native runner"
    return 1
  fi
  if ! native_runners "$archive"; then
    echo "untagged preflight must pair each target with its native runner"
    return 1
  fi
}

reject() {
  local expected="$1" output
  shift
  if output=$(check_wiring "$@"); then
    echo "accepted invalid wiring: $expected" >&2
    exit 1
  fi
  [ "$output" = "$expected" ] || { echo "unexpected error: $output" >&2; exit 1; }
  echo "ok   rejects invalid wiring: $expected"
}

check_wiring "$tagged" "$untagged"
echo "ok   requires both archive smoke jobs and five native runner pairs"

sed 's/, smoke-archives]/]/' "$tagged" > "$scratch/no-dependency.yml"
reject 'sign must depend on the archive smoke job' "$scratch/no-dependency.yml" "$untagged"

sed '/^[[:space:]]*run: scripts\/release\/check-security-check-archive\.sh/d' "$tagged" > "$scratch/no-tagged-call.yml"
reject 'tagged smoke job must run the archive check' "$scratch/no-tagged-call.yml" "$untagged"

sed '/^[[:space:]]*scripts\/release\/check-security-check-archive\.sh/d' "$untagged" > "$scratch/no-untagged-call.yml"
reject 'untagged preflight must run the archive check' "$tagged" "$scratch/no-untagged-call.yml"

swap_runners() {
  sed -e 's/runner: macos-15-intel$/runner: swapped-macos/' \
      -e 's/runner: macos-15$/runner: macos-15-intel/' \
      -e 's/runner: swapped-macos$/runner: macos-15/' "$1"
}

swap_runners "$tagged" > "$scratch/wrong-tagged-runners.yml"
reject 'tagged smoke job must pair each target with its native runner' "$scratch/wrong-tagged-runners.yml" "$untagged"

swap_runners "$untagged" > "$scratch/wrong-untagged-runners.yml"
reject 'untagged preflight must pair each target with its native runner' "$tagged" "$scratch/wrong-untagged-runners.yml"
