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
# What it reads: every .rs file under crates/erpc/src/chains/<chain>/, as
# text (a NUL byte does not hide a file), for the word `chains`. It allows
# the word only where it starts a path into the file's own chain
# (`chains::<own>`, as in `crate::chains::eth::rpc` from chains/eth) or an
# exception below, and refuses it everywhere else: a path to another chain,
# `chains::{...}`, `chains::*`, an alias (`chains as`), space or a comment or
# a line break between `chains` and `::`, and prose. Comments and string
# literals are read like code. It also refuses a symlink anywhere under
# chains/, which it would not read through, and a .rs file directly in
# chains/ other than mod.rs, such as a chains/<chain>.rs it would not read.
#
# It reads text, not Rust: it sees only the word `chains` as written in a
# chain's own files. Any route to another chain that is not spelled that way
# in the importing file is not seen. Some, and this list is not complete:
# `super::` paths (one `super::` from a chain's mod.rs is the chains module,
# and more leave the chain from a file below it); `#[path]` and `include!`;
# a macro that expands to another chain's path, whether another chain
# exports it or chains/mod.rs (which is not read) or code outside chains/
# defines it; methods another chain adds to a shared type in an impl block;
# and a re-export elsewhere in the crate that makes another chain's module
# reachable by another name. It catches ordinary imports; it does not prove
# that no chain depends on another.
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

# What the scan below would not read: a symlink (grep -r does not follow
# one it meets) and a chain's root written as chains/<chain>.rs.
links="$(find "$root" -type l)"
if [ -n "$links" ]; then
  printf '%s\n' "$links" | while IFS= read -r l; do
    echo "check-chain-imports: $l is a symlink; chain files must be files of their own" >&2
  done
  fail=1
fi
for f in "$root"/*.rs; do
  [ -e "$f" ] || continue
  [ "$(basename "$f")" = "mod.rs" ] && continue
  echo "check-chain-imports: $f is a .rs file directly in chains/; a chain's root is chains/<chain>/mod.rs" >&2
  fail=1
done

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

# Each word `chains` on a line, as the path that follows it (`eth::rpc`
# for `chains::eth::rpc`), or `-` when no path follows it directly.
# shellcheck disable=SC2016 # an awk program: its $0 and $1 are awk's
uses='
{
  s = $0
  while (match(s, /chains/)) {
    before = (RSTART > 1) ? substr(s, RSTART - 1, 1) : ""
    s = substr(s, RSTART + 6)
    if (before ~ /[A-Za-z0-9_]/ || s ~ /^[A-Za-z0-9_]/) continue
    if (match(s, /^::[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*/))
      print substr(s, 3, RLENGTH - 2)
    else
      print "-"
  }
}'

for dir in "$root"/*/; do
  own="$(basename "$dir")"
  # -a: a file with a NUL byte in it is still read, not called binary.
  hits="$(grep -arnE --include='*.rs' '(^|[^A-Za-z0-9_])chains([^A-Za-z0-9_]|$)' "$dir")"
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
    while IFS= read -r ref; do
      if [ "$ref" = "-" ]; then
        echo "$file:$line: chains/$own uses the word chains other than as a path into its own chain; name its own chain module as chains::$own, and share anything else through crate::node" >&2
        fail=1
        continue
      fi
      [ "${ref%%::*}" = "$own" ] && continue
      allowed "$own" "$ref" && continue
      echo "$file:$line: chains/$own names chains::$ref; share it through crate::node instead" >&2
      fail=1
    done <<REFS
$(printf '%s\n' "${rest#*:}" | awk "$uses")
REFS
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
