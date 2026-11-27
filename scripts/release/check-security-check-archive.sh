#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

# Run only against an archive produced by the trusted build being checked.
set -euo pipefail

archive_base="${1:?usage: check-security-check-archive.sh /path/to/erpc-target}"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

case "$archive_base" in
  *-pc-windows-msvc)
    python -m zipfile -e "$archive_base.zip" "$scratch"
    executable=erpc.exe
    ERPC_HOME="$(cygpath -w "$scratch/state")"
    ;;
  *)
    tar -xf "$archive_base.tar.xz" -C "$scratch"
    executable=erpc
    ERPC_HOME="$scratch/state"
    ;;
esac
export ERPC_HOME

binary=$(find "$scratch" -type f -name "$executable")
[ -f "$binary" ] || { echo "expected one $executable in $archive_base" >&2; exit 1; }

# Inspect the pinned clap generator's candidate syntax without sourcing the
# scripts. A comment, description or a candidate for a different command
# cannot prove that erpc ai completes the flag.
has_completion() {
  local generated="$2"
  case "$1" in
    bash)
      awk '
        /^[[:space:]]*erpc__subcmd__ai\)[[:space:]]*$/ { ai = 1; next }
        /^[[:space:]]*;;[[:space:]]*$/ { ai = 0 }
        ai && /^[[:space:]]*opts="[^"]*"[[:space:]]*$/ {
          sub(/^[[:space:]]*opts="/, "")
          sub(/"[[:space:]]*$/, "")
          for (i = 1; i <= NF; i++) if ($i == "--security-check") found = 1
          ai = 0
        }
        END { exit !found }
      ' "$generated"
      ;;
    zsh)
      # The root switch follows the erpc-command context assignment.
      # erpc help has its own switch and another arm named (ai).
      # shellcheck disable=SC2016
      awk -v quote="'" -v context='curcontext="${curcontext%:*:*}:erpc-command-$line[1]:"' '
        {
          sub(/^[[:space:]]*/, "")
          sub(/[[:space:]]*$/, "")
          if (/^case .* in$/) {
            depth++
            if (root_next && $0 == "case $line[1] in") root_depth = depth
          } else if ($0 == "esac") {
            if (depth == root_depth) { root_depth = 0; ai = 0 }
            depth--
          } else if (root_depth && depth == root_depth) {
            if ($0 == "(ai)") ai = 1
            if ($0 == ";;") ai = 0
            if (ai && index($0, quote) == 1) {
              line = substr($0, 2)
              sub(/^\([^)]*\)/, "", line)
              if (index(line, "--security-check[") == 1) found = 1
            }
          }
          root_next = ($0 == context)
        }
        END { exit !found }
      ' "$generated"
      ;;
    fish)
      grep -qE '^complete -c erpc -n "__fish_erpc_using_subcommand ai" -l security-check([[:space:]]|$)' "$generated"
      ;;
    powershell)
      section_candidate "'erpc;ai' {" \
        "[CompletionResult]::new('--security-check', '--security-check', [CompletionResultType]::ParameterName," "$generated"
      ;;
    elvish)
      section_candidate "&'erpc;ai'= {" 'cand --security-check ' "$generated"
      ;;
  esac
}

section_candidate() {
  awk -v section="$1" -v candidate="$2" '
    { sub(/^[[:space:]]*/, "") }
    $0 == section { ai = 1; next }
    $0 == "}" { ai = 0 }
    ai && index($0, candidate) == 1 { found = 1 }
    END { exit !found }
  ' "$3"
}

"$binary" --help > "$scratch/help"
"$binary" ai --help > "$scratch/ai-help"
if ! grep -Eq '^[[:space:]]+--security-check([[:space:]]|$)' "$scratch/ai-help"; then
  echo "missing --security-check in ai --help" >&2
  exit 1
fi
for shell in bash zsh fish powershell elvish; do
  "$binary" completions "$shell" > "$scratch/completions"
  if ! has_completion "$shell" "$scratch/completions"; then
    echo "missing --security-check in $shell completions" >&2
    exit 1
  fi
done
