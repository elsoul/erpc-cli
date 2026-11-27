#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

# Exercise the release gate with archives made here from a trusted fixture.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="$root/scripts/release/check-security-check-archive.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

make_archive() {
  local scenario="$1" base="$2" package
  package="$scratch/$scenario/erpc-aarch64-apple-darwin"
  mkdir -p "$package"
  cp "$root/scripts/tests/fixtures/security-check-archive/erpc.sh" "$package/erpc"
  chmod +x "$package/erpc"
  printf '%s\n' "$scenario" > "$package/scenario"
  tar -cJf "$base.tar.xz" -C "$scratch/$scenario" erpc-aarch64-apple-darwin
}

make_archive complete "$scratch/complete-archive"
"$BASH" "$gate" "$scratch/complete-archive"
echo "ok   accepts an archive with help and all five completion scripts"

for scenario in help bash zsh fish powershell elvish decoy-bash decoy-zsh decoy-fish decoy-powershell decoy-elvish; do
  missing="${scenario#decoy-}"
  base="$scratch/without-$scenario"
  make_archive "$scenario" "$base"
  if output=$("$BASH" "$gate" "$base" 2>&1); then
    echo "accepted an archive missing the flag in $missing" >&2
    exit 1
  fi
  if [ "$missing" = help ]; then
    expected='missing --security-check in ai --help'
  else
    expected="missing --security-check in $missing completions"
  fi
  [ "$output" = "$expected" ] || { echo "unexpected error: $output" >&2; exit 1; }
  echo "ok   rejects the archive missing the flag in $scenario"
done
