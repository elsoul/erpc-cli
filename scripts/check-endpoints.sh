#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Egress allowlist gate.
#
#   scripts/check-endpoints.sh [files...]       # default: all tracked files
#   scripts/check-endpoints.sh --print-exceptions
#
# ONE RULE: every http/https/ws/wss URL in a tracked file must name a host
# declared in crates/erpc-core/src/endpoints.rs. Two lists live there:
#
#   * the hosts erpc may contact (service, browser, distribution, tooling,
#     loopback), allowed anywhere;
#   * DOCUMENTATION_HOSTS, allowed only in prose files (.md, .txt, NOTICE,
#     CHANGELOG, AUTHORS) — link targets, never destinations.
#
# Earlier versions of this gate tried to tell a documentation link from an
# instruction a reader might run, using fence tracking, code spans and a list
# of command verbs. Every round of review found both a bypass and a false
# positive in that machinery, because it is a markdown parser written in a
# text matcher. The heuristics are gone. Adding a reference now means adding
# a host to DOCUMENTATION_HOSTS, which is cheap, visible, and has no edge.
#
# Scope and limits, stated exactly:
#   - Files listed by --print-exceptions are not scanned at all.
#   - Plaintext http:// and ws:// are refused outside loopback, per URL.
#   - A URL whose host begins with a shell or template expression (${, {{,
#     $(, backtick) is skipped, because there is no literal to check. An
#     expression anywhere else is stripped and the literal prefix IS checked.
#   - A host that is not plain ASCII, or one that starts with a backslash
#     escape, is reported: both are literals a reviewer should see, and
#     neither may be skipped just because the matcher finds them awkward.
#   - Escaped slashes (\/\/) are normalised before matching, so a URL in a
#     JSON or TypeScript string cannot hide from the pattern.
#   - A host assembled at runtime from fragments is invisible to this gate.
#     This is a text gate over source, not a sandbox, and it does not
#     constrain a dependency.
#
# Written for bash 3.2 (macOS /bin/bash): no mapfile, no associative arrays.
# CI exercises bash 3.2 and bash 5.
set -uo pipefail

# Every pattern below is matched against bytes, so the locale must not decide
# what a character class means. Under en_US.UTF-8 — which is what the GitHub
# runners set — a bash range follows collation order, so `[A-Z]` also matches
# lowercase and `[!A-Za-z0-9._-]` stops matching accented letters. Both turned
# live controls into no-ops that still passed their self-tests on a machine
# with no LANG set. The self-tests run under both locales to keep this honest.
export LC_ALL=C

cd "$(git rev-parse --show-toplevel)"

allowlist_src="crates/erpc-core/src/endpoints.rs"

# The one list of files this gate does not scan. Printed so documentation can
# point at it instead of paraphrasing it. Patterns are matched against the
# whole path, so a leading */ is required to match at any depth.
print_exceptions() {
  cat <<'EOF'
.github/workflows/release.yml
THIRD_PARTY_NOTICES.md
crates/erpc-core/src/endpoints.rs
docs/public-hosts.md
scripts/check-endpoints.sh
scripts/tests/check-endpoints.test.sh
scripts/tests/check-oss-hygiene.test.sh
Cargo.lock
installer/package-lock.json
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
read_consts() {
  awk -v want="$1" '
    /^#\[cfg\(test\)\]/ { exit }
    /^pub const [A-Z_]+: &\[/ {
      inside = (want == "ALL" || index($0, "pub const " want ":") == 1)
    }
    inside { line = $0; sub(/\/\/.*/, "", line); print line }
    inside && /\];/ { inside = 0 }
  ' "$allowlist_src"
}

extract_hosts() { grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u; }

doc_hosts=$(read_consts DOCUMENTATION_HOSTS | extract_hosts)
all_consts=$(read_consts ALL)
# Service hosts are everything declared except the documentation-only list.
# No `|| <fallback>`: grep exits 1 when it selects nothing, and a fallback
# here would quietly make every declared host, documentation hosts included,
# allowed in code. An empty result is caught by the tripwire below instead.
service_hosts=$(printf '%s\n' "$all_consts" | extract_hosts | grep -vxF "$doc_hosts")
patterns=$(printf '%s\n' "$all_consts" | grep -oE '\("[A-Za-z0-9.-]+",[[:space:]]*"[A-Za-z0-9.-]+"\)' \
  | sed -E 's/^\("([^"]+)",[[:space:]]*"([^"]+)"\)$/\1	\2/')

# A broken extraction would make this gate reject everything, which looks
# strict and is useless. Fail loudly instead.
if [ "$(printf '%s\n' "$service_hosts" | grep -c .)" -lt 5 ]; then
  echo "allowlist extraction produced fewer than 5 hosts; the gate is broken" >&2
  exit 2
fi
# And an empty documentation list would make `grep -vxF ""` pass everything
# through, so service_hosts would grow rather than shrink and the tripwire
# above would never fire — the opposite of the intended failure.
if [ "$(printf '%s\n' "$doc_hosts" | grep -c .)" -lt 1 ]; then
  echo "DOCUMENTATION_HOSTS extraction is empty; the gate is broken" >&2
  exit 2
fi

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files)
fi

prose_re='(\.(md|txt)$|^(NOTICE|CHANGELOG|AUTHORS)$)'

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

# $1 host, $2 "prose" or "code"
host_allowed() {
  local host="$1" kind="$2" prefix suffix mid a
  host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
  while [ "${host%.}" != "$host" ]; do host="${host%.}"; done
  while IFS= read -r a; do
    [ -n "$a" ] && [ "$host" = "$a" ] && return 0
  done <<EOF
$service_hosts
EOF
  if [ "$kind" = prose ]; then
    while IFS= read -r a; do
      [ -n "$a" ] && [ "$host" = "$a" ] && return 0
    done <<EOF
$doc_hosts
EOF
  fi
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

is_loopback_host() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    127.0.0.1|localhost|'[::1]') return 0;;
  esac
  return 1
}

# True when a host containing a template is pinned by a declared
# HOST_PATTERNS pair: the literal text before the template starts with the
# pattern's prefix, the literal text after it ends with the pattern's suffix,
# and neither literal part introduces a dot of its own, so the registrable
# domain cannot move. `solana-snapshot-${REGION}.erpc.global` qualifies;
# `github.com${X}.evil.example.net` does not.
template_host_matches_pattern() {
  local host prefix suffix lit_pre lit_suf opener closer after best d c o cl mid tail
  host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')

  # Find the EARLIEST template delimiter and pair it with ITS OWN closer.
  # Pairing matters: a backtick is both a template delimiter and a JavaScript
  # string quote, so "after the last closing delimiter" reads the text after
  # the string's closing backtick and loses the real suffix.
  best=""; opener=""; closer=""
  for d in '${:}' '{{:}}' '$(:)' '`:`'; do
    o="${d%%:*}"; cl="${d##*:}"
    c="${host%%$o*}"
    [ "$c" = "$host" ] && continue
    if [ -z "$opener" ] || [ ${#c} -lt ${#best} ]; then best="$c"; opener="$o"; closer="$cl"; fi
  done
  [ -n "$opener" ] || return 1
  lit_pre="$best"

  after="${host#*$opener}"
  case "$after" in *"$closer"*) lit_suf="${after#*$closer}";; *) return 1;; esac
  # The suffix is literal text, so the same trailing punctuation the caller
  # strips applies here.
  lit_suf="${lit_suf%%[)\",\';\`]*}"
  # A second template in the suffix means the tail is not literal either.
  case "$lit_suf" in *'${'*|*'{{'*|*'$('*|*'`'*) return 1;; esac
  [ -n "$lit_suf" ] || return 1

  while IFS=$'\t' read -r prefix suffix; do
    [ -n "$prefix" ] || continue
    case "$lit_pre" in "$prefix"*) ;; *) continue;; esac
    case "$lit_suf" in *"$suffix") ;; *) continue;; esac
    mid="${lit_pre#"$prefix"}"
    tail="${lit_suf%"$suffix"}"
    # Neither literal part may introduce a dot: the registrable domain has to
    # stay where the declared pattern puts it.
    case "$mid$tail" in *.*) continue;; esac
    return 0
  done <<EOF
$patterns
EOF
  return 1
}

# $1 file, $2 line number, $3 url, $4 kind
check_url() {
  local f="$1" ln="$2" url="$3" kind="$4" scheme rest hostport host
  scheme=$(printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]')
  rest="${url#*://}"
  # The host itself is computed, so there is no literal to check. A backtick
  # command substitution counts: `https://`h`.example.com/` has no literal
  # host either. One appearing after a literal prefix is handled below.
  case "$rest" in
    '${'*|'{{'*|'$('*|'`'*) return 0;;
  esac
  hostport="${rest%%/*}"; hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
  hostport="${hostport##*@}"
  case "$hostport" in
    \[*\]*) host="${hostport%%\]*}]";;
    *) host="${hostport%%:*}";;
  esac

  # A template anywhere but position 0 of the host leaves an allowlisted
  # literal prefix in front of a suffix the author chooses. It is the same
  # mechanism as the backslash below: `https://github.com${""}.evil.example.net`
  # is one string whose prefix is allowlisted and whose registrable domain is
  # not, and cutting at the template to check the prefix passes it.
  #
  # Such a host is allowed only when its literal prefix and literal suffix
  # match a declared HOST_PATTERNS pair, which is exactly what that list is
  # for (`solana-snapshot-${REGION}.erpc.global`). Anything else is reported:
  # the gate cannot know what the expression expands to, and the one thing it
  # must not do is vouch for a host on the strength of its first few bytes.
  # A template AT position 0 was already returned above: there is no literal.
  case "$host" in
    *'${'*|*'{{'*|*'$('*|*'`'*)
      if template_host_matches_pattern "$host"; then
        return 0
      fi
      report "$f" "$ln" "expression in host, so the literal prefix does not fix the destination: $scheme://$host"
      return 0
      ;;
  esac
  # A backslash ANYWHERE in the host hides the rest of it. In Rust,
  # TypeScript and Python alike `https://github.com\x2eevil.example.net` is
  # one compile-time literal under evil.example.net, and trimming at the
  # backslash would leave the allowlisted prefix and pass. Checking only
  # position 0 catches the shape that would have been caught anyway.
  case "$host" in
    *\\*)
      report "$f" "$ln" "escape sequence in host, so the literal is hidden: $scheme://$host"
      return 0
      ;;
  esac
  host="${host%%[)\",\';\`]*}"
  [ -n "$host" ] || return 0

  # A host that is not plain ASCII is a homograph risk and must be seen, not
  # silently skipped because the matcher's character class missed it.
  # Deliberately `tr -d` and not a bracket expression: a class containing
  # `[` and `]` is read differently by different greps, and two attempts at
  # writing one here produced a check that silently matched nothing.
  if [ -n "$(printf '%s' "$host" | LC_ALL=C tr -d 'A-Za-z0-9.:_[]-')" ]; then
    report "$f" "$ln" "non-ASCII or unexpected character in host: $scheme://$host"
    return 0
  fi
  if ! is_loopback_host "$host" && [ "$scheme" = http -o "$scheme" = ws ]; then
    report "$f" "$ln" "plaintext $scheme:// outside loopback: $host"
    return 0
  fi
  if ! host_allowed "$host" "$kind"; then
    report "$f" "$ln" "endpoint not in the allowlist: $scheme://$host  (declare it in $allowlist_src; documentation links go in DOCUMENTATION_HOSTS)"
  fi
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  is_excepted "$f" && continue
  if [[ "$f" =~ $prose_re ]]; then kind=prose; else kind=code; fi

  # -a so a stray NUL cannot hide the rest of the file from either branch.
  # Escaped slashes (\/\/) are normalised so a JSON or TypeScript string
  # cannot hide a URL from the matcher.
  while IFS=: read -r ln url; do
    [ -z "$ln" ] && continue
    check_url "$f" "$ln" "$url" "$kind"
  done < <(grep -a '' "$f" 2>/dev/null | sed 's|\\/|/|g' \
    | grep -naoiE '(https?|wss?)://[^[:space:]"'"'"'<>]+' 2>/dev/null)
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<MSG

check-endpoints: FAILED

Every URL in this repository must name a host declared in
  $allowlist_src

A destination erpc contacts goes in one of the host lists there. A link that
only appears in documentation goes in DOCUMENTATION_HOSTS. Files this gate
does not scan: scripts/check-endpoints.sh --print-exceptions
MSG
fi
exit "$status"
