#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Egress allowlist gate.
#
# Every host `erpc` may contact is declared once, in
# crates/erpc-core/src/endpoints.rs. This script extracts that list and refuses
# any other http/https/ws/wss URL in the source tree, so a new outbound
# destination cannot be introduced without editing the allowlist, which a
# reviewer sees.
#
#   scripts/check-endpoints.sh [files...]     # default: all tracked files
#
# Scope: code, workflows, scripts and configuration, where an egress is
# actually performed or configured. Markdown is checked only for insecure
# schemes, since documentation legitimately links to the wider web and a prose
# link cannot make the program connect anywhere.
#
# Written for bash 3.2 (macOS): no mapfile, no associative arrays.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

allowlist_src="crates/erpc-core/src/endpoints.rs"
[ -f "$allowlist_src" ] || { echo "missing $allowlist_src" >&2; exit 2; }

# Read ONLY the `pub const ... = &[ ... ];` arrays, and stop at the test module
# so that test fixtures (which deliberately contain rejected hosts) can never
# widen the allowlist.
consts=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' "$allowlist_src")

[ -n "$consts" ] || { echo "could not read the allowlist from $allowlist_src" >&2; exit 2; }

# Exact hosts: every quoted string outside the ("prefix", ".suffix") pairs.
# The arrays contain nothing but host literals, so "..." is a safe extraction
# and avoids a bracket expression whose portability differs between greps.
allowed=$(printf '%s\n' "$consts" | grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)
# Wildcard entries: ("prefix", ".suffix") -> "prefix<TAB>.suffix"
patterns=$(printf '%s\n' "$consts" | grep -oE '\("[A-Za-z0-9.-]+",[[:space:]]*"[A-Za-z0-9.-]+"\)' \
  | sed -E 's/^\("([^"]+)",[[:space:]]*"([^"]+)"\)$/\1\t\2/')

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files)
fi

# Vendored, generated and fixture files. release.yml and THIRD_PARTY_NOTICES.md
# are generated (cargo-dist, cargo-about) and reviewed when their generator is
# upgraded; scripts/tests holds deliberately bad samples.
skip_re='(\.lock$|lock\.json$|^LICENSES/|^LICENSE$|/node_modules/|^target/|^scripts/tests/|^\.github/workflows/release\.yml$|^THIRD_PARTY_NOTICES\.md$)'
code_re='\.(rs|ts|js|sh|toml|yml|yaml|json)$'

status=0
report() { printf '%s:%s: %s\n' "$1" "$2" "$3" >&2; status=1; }

host_allowed() {
  local host="${1%.}" a prefix suffix mid
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

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  [[ "$f" =~ $skip_re ]] && continue
  # This script, the allowlist and the published host list name hosts on purpose.
  case "$f" in
    scripts/check-endpoints.sh|"$allowlist_src"|docs/public-hosts.md) continue;;
  esac

  if [[ "$f" =~ $code_re ]]; then
    while IFS=: read -r ln url; do
      [ -z "$ln" ] && continue
      scheme="${url%%://*}"
      hostport="${url#*://}"; hostport="${hostport%%/*}"
      hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
      hostport="${hostport##*@}"
      case "$hostport" in
        \[*\]*) host="${hostport%%\]*}]";;
        *) host="${hostport%%:*}";;
      esac
      # Template expressions resolve at runtime; there is no literal host here.
      case "$host" in *'${'*|*'{{'*|*'$('*|'') continue;; esac
      if ! host_allowed "$host"; then
        report "$f" "$ln" "endpoint not in the allowlist: $scheme://$host  (declare it in $allowlist_src if it is intended)"
      fi
    done < <(grep -noE '(https?|wss?)://[A-Za-z0-9._~:/?#@!$&*+,;=%${}()-]+' "$f" 2>/dev/null)
  else
    while IFS=: read -r ln url; do
      [ -z "$ln" ] && continue
      report "$f" "$ln" "insecure URL in documentation: $url"
    done < <(grep -noE '(http|ws)://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+' "$f" 2>/dev/null \
      | grep -vE '://(127\.0\.0\.1|localhost|\[::1\])')
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
