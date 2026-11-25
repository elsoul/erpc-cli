#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Chain-boundary gate for crates/erpc. Each chain's node commands live in
# crates/erpc/src/chains/<chain>/, and what chains share lives in
# crates/erpc/src/node/. A chain module that names another chain's module
# ties two chains together that should change on their own, so this gate
# fails on one.
#
# What it reads: every .rs file under crates/erpc/src/chains/<chain>/, for
# the text `chains::` followed by a path (as in `crate::chains::eth::rpc`,
# or `chains::eth::rpc` inside a `use crate::{...}` group), and for
# `chains as`, an alias of the chains module. It fails closed: `chains::{`,
# `chains::*`, and a `chains::` it cannot read a path after are refused,
# since none can be attributed to one chain. Comments are read like code.
#
# It reads text, not Rust. It does not resolve `super::` paths, so a path
# that leaves the chain that way is not seen: one `super::` from a chain's
# mod.rs, or more from a file below it. Nor does it follow `#[path]` or
# `include!`.
#
# An exception names the importing chain, the path it may use (and anything
# under it), and why, starting with the date it was written. An exception
# that no longer matches anything fails the gate, so it goes when the
# import does.
#
#   scripts/check-chain-imports.sh
set -uo pipefail
export LC_ALL=C

cd "$(git rev-parse --show-toplevel)" || exit 1
root="crates/erpc/src/chains"

# importer|path|reason, one per line.
exceptions='robinhood|nitro::rpc::admission_session|2026-11-25: Robinhood Chain RPC nodes are Nitro followers that chains/nitro stores; Robinhood admission opens one through this session, which refuses any network outside the robinhood family.'

if [ ! -d "$root" ]; then
  echo "check-chain-imports: $root is missing" >&2
  exit 1
fi

fail=0
used="|"

while IFS='|' read -r who path why; do
  [ -n "$who" ] || continue
  case "$why" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]': '?*) ;;
    *)
      echo "check-chain-imports: the exception for $who -> $path needs a reason starting with its date" >&2
      fail=1
      ;;
  esac
done <<EOF
$exceptions
EOF

allowed() {
  local own="$1" ref="$2" who path why
  while IFS='|' read -r who path why; do
    [ "$who" = "$own" ] || continue
    case "$ref" in
      "$path" | "$path"::*)
        used="$used$who:$path|"
        return 0
        ;;
    esac
  done <<EOF
$exceptions
EOF
  return 1
}

word='(^|[^A-Za-z0-9_])'
after='(\{|\*|[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*)'

for dir in "$root"/*/; do
  own="$(basename "$dir")"
  hits="$(grep -rnE --include='*.rs' "${word}chains(::|[[:space:]]+as[[:space:]])" "$dir")"
  if [ "$?" -gt 1 ]; then
    echo "check-chain-imports: could not read $dir" >&2
    fail=1
    continue
  fi
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    text="${rest#*:}"
    if printf '%s\n' "$text" | grep -qE "${word}chains[[:space:]]+as[[:space:]]"; then
      echo "$file:$line: chains/$own aliases the chains module; name each chain module on its own" >&2
      fail=1
    fi
    seen="$(printf '%s\n' "$text" | grep -oE "${word}chains::" | wc -l)"
    refs="$(printf '%s\n' "$text" | grep -oE "${word}chains::$after" | sed -E 's/^[^c]*chains:://')"
    found=0
    # $refs is split on whitespace, but must not be globbed: `*` is a ref.
    set -f
    for ref in $refs; do
      found=$((found + 1))
      case "$ref" in
        "{" | "*")
          echo "$file:$line: chains/$own imports chains::$ref; name each chain module on its own" >&2
          fail=1
          continue
          ;;
      esac
      [ "${ref%%::*}" = "$own" ] && continue
      allowed "$own" "$ref" && continue
      echo "$file:$line: chains/$own names chains::$ref; share it through crate::node instead" >&2
      fail=1
    done
    set +f
    if [ "$found" -lt "$seen" ]; then
      echo "$file:$line: chains/$own has a chains:: path this gate cannot read; write it as one path" >&2
      fail=1
    fi
  done <<EOF
$hits
EOF
done

while IFS='|' read -r who path why; do
  [ -n "$who" ] || continue
  case "$used" in
    *"|$who:$path|"*) ;;
    *)
      echo "check-chain-imports: the exception for $who -> $path no longer matches anything; remove it" >&2
      fail=1
      ;;
  esac
done <<EOF
$exceptions
EOF

exit "$fail"
