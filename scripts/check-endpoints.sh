#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Egress allowlist gate.
#
# Every host `erpc` may contact is declared once, in
# crates/erpc-core/src/endpoints.rs. This script extracts that list and refuses
# any other http/https/ws/wss URL in a tracked file.
#
#   scripts/check-endpoints.sh [files...]       # default: all tracked files
#   scripts/check-endpoints.sh --print-exceptions
#
# WHAT IT COVERS, exactly. Every tracked file is scanned for URLs and every
# host is held to the allowlist, with two carve-outs:
#
#   1. Prose files (.md, .txt, NOTICE, CHANGELOG, AUTHORS) may link anywhere,
#      because a documentation link cannot make the program connect. A prose
#      line is still held to the allowlist when it is inside a fenced code
#      block, contains a code span, or carries a download/install/execute
#      command — that is, whenever it is an instruction a reader may run.
#   2. The files listed by --print-exceptions are not scanned at all. Those
#      are generated artifacts, lockfiles, this gate's own fixtures, and the
#      files that name hosts on purpose.
#
# Any claim in the documentation about this gate's coverage must match
# --print-exceptions; a self-test asserts that it does.
#
# This is a text gate over source, not a sandbox. It cannot stop a dependency
# from opening a socket, and it cannot see a host assembled at runtime from
# fragments. It stops a destination from entering this repository unreviewed.
#
# Written for bash 3.2 (macOS /bin/bash): no mapfile, no associative arrays.
# CI exercises bash 3.2 and bash 5.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

allowlist_src="crates/erpc-core/src/endpoints.rs"

# The one list of files this gate does not scan. Kept here so the
# documentation can be checked against it instead of paraphrasing it.
print_exceptions() {
  cat <<'EOF'
.github/workflows/release.yml
THIRD_PARTY_NOTICES.md
crates/erpc-core/src/endpoints.rs
docs/public-hosts.md
scripts/check-endpoints.sh
scripts/tests/check-endpoints.test.sh
scripts/tests/check-oss-hygiene.test.sh
*.lock
*lock.json
LICENSE
LICENSES/*
EOF
}

if [ "${1:-}" = "--print-exceptions" ]; then
  print_exceptions
  exit 0
fi

[ -f "$allowlist_src" ] || { echo "missing $allowlist_src" >&2; exit 2; }

# Read ONLY the `pub const ... = &[ ... ];` arrays, stopping at the test module
# so test fixtures cannot widen the allowlist, and stripping `//` comments so a
# host mentioned in a comment cannot widen it either.
consts=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { line = $0; sub(/\/\/.*/, "", line); print line }
  inside && /\];/ { inside = 0 }
' "$allowlist_src")

[ -n "$consts" ] || { echo "could not read the allowlist from $allowlist_src" >&2; exit 2; }

allowed=$(printf '%s\n' "$consts" | grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)
patterns=$(printf '%s\n' "$consts" | grep -oE '\("[A-Za-z0-9.-]+",[[:space:]]*"[A-Za-z0-9.-]+"\)' \
  | sed -E 's/^\("([^"]+)",[[:space:]]*"([^"]+)"\)$/\1	\2/')

# A broken extraction would make this gate reject everything, which looks
# strict and is useless. Fail loudly instead.
if [ "$(printf '%s\n' "$allowed" | grep -c .)" -lt 5 ]; then
  echo "allowlist extraction produced fewer than 5 hosts; the gate is broken" >&2
  exit 2
fi

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files)
fi

prose_re='(\.(md|txt)$|^(NOTICE|CHANGELOG|AUTHORS)$)'
# Verbs that fetch, install or execute from a URL. Prose lines carrying one of
# these are held to the allowlist even outside a code block.
command_re='(curl|wget|iwr|irm|iex|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|\| *(ba)?sh|cargo +(install|add)|pip +install|pipx +install|npm +(install|i|exec)|pnpm +(add|dlx)|yarn +add|go +(install|get)|gem +install|brew +install|apt-get +install|docker +(run|pull)|nix +(run|shell)|git +clone)'

status=0
report() { printf '%s:%s: %s\n' "$1" "$2" "$3" >&2; status=1; }

is_excepted() {
  local f="$1" pat
  while IFS= read -r pat; do
    [ -n "$pat" ] || continue
    case "$f" in
      $pat) return 0;;
    esac
  done <<EOF
$(print_exceptions)
EOF
  case "$f" in */node_modules/*|target/*) return 0;; esac
  return 1
}

host_allowed() {
  local host prefix suffix mid a
  host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  while [ "${host%.}" != "$host" ]; do host="${host%.}"; done
  while IFS= read -r a; do
    [ -n "$a" ] && [ "$host" = "$a" ] && return 0
  done <<EOF
$allowed
EOF
  while IFS=$'\t' read -r prefix suffix; do
    [ -n "$prefix" ] || continue
    case "$host" in
      "$prefix"*"$suffix")
        mid="${host#"$prefix"}"; mid="${mid%"$suffix"}"
        case "$mid" in *.*|"") ;; *) return 0;; esac
        ;;
    esac
  done <<EOF
$patterns
EOF
  return 1
}

check_url() {
  local f="$1" ln="$2" url="$3" scheme rest hostport host
  scheme="${url%%://*}"
  rest="${url#*://}"
  # A template expression immediately after :// means the host itself is
  # computed, so there is no literal to check. Anywhere else the expression is
  # stripped and the remaining literal host IS checked, because appending an
  # expression must not become a way past this gate.
  case "$rest" in
    '${'*|'{{'*|'$('*) return 0;;
  esac
  hostport="${rest%%/*}"; hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
  hostport="${hostport##*@}"
  # Cut the host at the first template delimiter; what precedes it is literal.
  hostport="${hostport%%\$\{*}"; hostport="${hostport%%\{\{*}"; hostport="${hostport%%\$(*}"
  case "$hostport" in
    \[*\]*) host="${hostport%%\]*}]";;
    *) host="${hostport%%:*}";;
  esac
  # Prose and code wrap URLs in punctuation; it is not part of the host.
  host="${host%%[)\",\';\`]*}"
  [ -n "$host" ] || return 0
  if ! host_allowed "$host"; then
    report "$f" "$ln" "endpoint not in the allowlist: $scheme://$host  (declare it in $allowlist_src if it is intended)"
  fi
}

check_line() {
  local f="$1" ln="$2" line="$3" url
  for url in $(printf '%s' "$line" | grep -oiE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()`-]+'); do
    check_url "$f" "$ln" "$url"
  done
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  is_excepted "$f" && continue

  if [[ "$f" =~ $prose_re ]]; then
    # grep -a so a stray NUL cannot hide the rest of the file.
    ln=0
    fenced=0
    while IFS= read -r line; do
      ln=$((ln + 1))
      case "$line" in
        '```'*|'~~~'*) fenced=$((1 - fenced)); continue;;
      esac
      case "$line" in
        *'://'*) ;;
        *) continue;;
      esac
      # Insecure scheme anywhere in prose. The host must end at a delimiter so
      # that localhost.evil.com is not mistaken for loopback.
      if printf '%s' "$line" | grep -qiE '(http|ws)://' \
        && ! printf '%s' "$line" | grep -qiE '(http|ws)://(127\.0\.0\.1|localhost|\[::1\])([:/?#"'"'"'`)]|$)'; then
        if printf '%s' "$line" | grep -qiE '(http|ws)://[A-Za-z0-9]'; then
          report "$f" "$ln" "insecure URL in documentation: $(printf '%s' "$line" | grep -oiE '(http|ws)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' | head -1)"
        fi
      fi
      # Instructions a reader may run are held to the allowlist: inside a
      # fenced block, inside a code span, or carrying a command verb.
      if [ "$fenced" = 1 ] || printf '%s' "$line" | grep -q '`' \
        || printf '%s' "$line" | grep -qiE "$command_re"; then
        check_line "$f" "$ln" "$line"
      fi
    done < <(grep -a '' "$f" 2>/dev/null)
  else
    while IFS=: read -r ln rest; do
      [ -z "$ln" ] && continue
      check_url "$f" "$ln" "$rest"
    done < <(grep -naoiE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()`-]+' "$f" 2>/dev/null)
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<MSG

check-endpoints: FAILED

Outbound destinations are declared in one place:
  $allowlist_src

Add the host there, with a comment saying what contacts it and whether a
credential is sent, then run this check again. Do not read ERPC service
endpoints from configuration or environment variables.
MSG
fi
exit "$status"
