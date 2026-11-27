#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

archive_base="${1:?usage: check-security-check-archive.sh /path/to/erpc-target}"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

case "$archive_base" in
  *-pc-windows-msvc)
    python -m zipfile -e "$archive_base.zip" "$scratch"
    executable=erpc.exe
    shell=powershell
    ERPC_HOME="$(cygpath -w "$scratch/state")"
    ;;
  *)
    tar -xf "$archive_base.tar.xz" -C "$scratch"
    executable=erpc
    shell=bash
    ERPC_HOME="$scratch/state"
    ;;
esac
export ERPC_HOME

binary=$(find "$scratch" -type f -name "$executable")
[ -f "$binary" ] || { echo "expected one $executable in $archive_base" >&2; exit 1; }

"$binary" --help > "$scratch/help"
"$binary" ai --help > "$scratch/ai-help"
"$binary" completions "$shell" > "$scratch/completions"
grep -Eq '^[[:space:]]+--security-check([[:space:]]|$)' "$scratch/ai-help"
# PowerShell and Bash generators both derive flags from the same command.
grep -Eq '(^|[^[:alnum:]_-])--security-check([^[:alnum:]_-]|$)' "$scratch/completions"
