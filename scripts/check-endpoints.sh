#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Egress allowlist gate.
#
# Every host `erpc` may contact is declared once, in
# crates/erpc-core/src/endpoints.rs. This script extracts that list and refuses
# any other http/https/ws/wss URL in a tracked text file, so a new outbound
# destination cannot be introduced without editing the allowlist, which a
# reviewer sees.
#
#   scripts/check-endpoints.sh [files...]     # default: all tracked files
#
# Coverage: every tracked text file. Prose files (.md, .txt) are the one
# exception, because documentation legitimately links to the wider web and a
# prose link cannot make the program connect anywhere — but a prose line that
# carries a download or execute command (curl, wget, irm, iwr, iex, `| sh`)
# IS held to the allowlist, since that line is an instruction a reader runs.
# Generated files and fixtures are listed in skip_re below.
#
# This is a text gate over source, not a sandbox. It cannot stop a dependency
# from opening its own socket; it stops a destination from entering this
# repository unreviewed.
#
# Written for bash 3.2 (macOS /bin/bash): no mapfile, no associative arrays.
# CI exercises both bash 3.2 and bash 5.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

allowlist_src="crates/erpc-core/src/endpoints.rs"
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

# Exact hosts: a line whose only content is a quoted literal (with optional
# comma), or an inline array of such literals. Anything else is ignored.
allowed=$(printf '%s\n' "$consts" | grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)
# Wildcard entries: ("prefix", ".suffix") -> "prefix<TAB>.suffix"
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

# Vendored, generated and fixture files. release.yml and THIRD_PARTY_NOTICES.md
# are generated (cargo-dist, cargo-about) and reviewed when their generator is
# upgraded; the two self-tests hold deliberately bad samples.
skip_re='(\.lock$|lock\.json$|^LICENSES/|^LICENSE$|/node_modules/|^target/|^scripts/tests/[a-z-]+\.test\.sh$|^\.github/workflows/release\.yml$|^THIRD_PARTY_NOTICES\.md$)'
prose_re='(\.(md|txt)$|^(NOTICE|CHANGELOG|AUTHORS)$)'
# Prose lines that are instructions to run something are held to the allowlist.
command_re='(curl|wget|iwr|irm|iex|Invoke-WebRequest|Invoke-RestMethod|\| *(ba)?sh)'

status=0
report() { printf '%s:%s: %s\n' "$1" "$2" "$3" >&2; status=1; }

host_allowed() {
  local host prefix suffix mid a
  host=$(printf '%s' "${1%.}" | tr '[:upper:]' '[:lower:]')
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

# Emits "line:url" for every URL on lines matching the optional filter.
scan_urls() {
  local file="$1" filter="${2:-}"
  if [ -n "$filter" ]; then
    grep -noiE "$filter[^\"']*((https?|wss?)://[A-Za-z0-9._~:/?#@!\$&*+,;=%\${}()-]+)" "$file" 2>/dev/null \
      | grep -oiE '^[0-9]+:|(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()-]+' \
      | paste -d: - - 2>/dev/null
  else
    grep -noiE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()-]+' "$file" 2>/dev/null
  fi
}

check_url_line() {
  local f="$1" ln="$2" url="$3" scheme hostport host
  scheme="${url%%://*}"
  hostport="${url#*://}"; hostport="${hostport%%/*}"
  hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
  hostport="${hostport##*@}"
  case "$hostport" in
    \[*\]*) host="${hostport%%\]*}]";;
    *) host="${hostport%%:*}";;
  esac
  # Prose and code wrap URLs in punctuation; it is not part of the host.
  host="${host%%[)\",\';]*}"
  while [ "${host%.}" != "$host" ]; do host="${host%.}"; done
  # Template expressions resolve at runtime; there is no literal host here.
  case "$host" in *'${'*|*'{{'*|*'$('*|'') return 0;; esac
  if ! host_allowed "$host"; then
    report "$f" "$ln" "endpoint not in the allowlist: $scheme://$host  (declare it in $allowlist_src if it is intended)"
  fi
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  [[ "$f" =~ $skip_re ]] && continue
  # This script, the allowlist and the published host list name hosts on purpose.
  case "$f" in
    scripts/check-endpoints.sh|"$allowlist_src"|docs/public-hosts.md) continue;;
  esac
  # Skip binary files.
  grep -Iq . "$f" 2>/dev/null || continue

  if [[ "$f" =~ $prose_re ]]; then
    # Insecure schemes anywhere in prose.
    while IFS=: read -r ln url; do
      [ -z "$ln" ] && continue
      report "$f" "$ln" "insecure URL in documentation: $url"
    done < <(grep -noiE '(http|ws)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$f" 2>/dev/null \
      | grep -viE '://(127\.0\.0\.1|localhost|\[::1\])')
    # Lines that instruct the reader to fetch or execute something.
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      ln="${hit%%:*}"; rest="${hit#*:}"
      for url in $(printf '%s' "$rest" | grep -oiE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()-]+'); do
        check_url_line "$f" "$ln" "$url"
      done
    done < <(grep -noiE ".*$command_re.*" "$f" 2>/dev/null | grep -iE '(https?|wss?)://')
  else
    while IFS=: read -r ln url; do
      [ -z "$ln" ] && continue
      check_url_line "$f" "$ln" "$url"
    done < <(grep -noiE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()-]+' "$f" 2>/dev/null)
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
