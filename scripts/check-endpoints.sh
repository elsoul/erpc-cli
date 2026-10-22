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
#   - A host containing a shell or template expression (${, ${{, {{, $(,
#     backtick) is reported, UNLESS the literal text on both sides of the
#     expression matches a declared HOST_PATTERNS pair and neither literal
#     part adds a dot of its own. Where the expression sits does not change
#     this: a leading expression leaves the registrable domain literal, and
#     that is the part that decides the destination. An earlier version
#     stripped the expression and checked the prefix alone, which let an
#     allowlisted prefix vouch for an attacker-chosen suffix.
#   - A host that is ENTIRELY one balanced expression, such as ${MIRROR}, is
#     skipped: there is nothing literal to check. An UNTERMINATED opener is
#     not that case and is reported, because the text after it is literal
#     and is usually the registrable domain.
#   - The matcher reads each line as written and never rewrites it. A URL is
#     a run of non-space characters or whole balanced ${ }, ${{ }}, {{ }} and
#     $( ) expressions, so a space inside one of those does not end it.
#     Backticks are excluded on purpose: a backtick is also a string quote,
#     and pairing them across a space would splice a URL to unrelated text.
#     The cost is the one case this gate does NOT see: a backtick expression
#     containing a space, as in https://`cat host`.evil.example.net, is cut
#     at the space and its domain is never checked.
#   - A host that is not plain ASCII, or one containing a backslash escape
#     anywhere, is reported: both are literals a reviewer should see, and
#     neither may be skipped just because the matcher finds them awkward.
#     These checks, and the plaintext one above, run on every URL before the
#     allowlist question is answered, so no host can reach an "allowed"
#     verdict without passing them first.
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
# The host's literal skeleton: every BALANCED expression removed, so a caller
# can apply character checks to the parts the author actually wrote.
#
# Balanced only, and nothing is cut to end-of-string. An earlier version cut
# from any surviving opener to the end, which emptied the skeleton for
# `https://${x.evil.example.net` and made the caller skip the host on the
# grounds that it had no literal part -- while its literal part was the
# registrable domain. A surviving opener now stays in the skeleton, where
# `$` and `{` fail the character check, which is what the comment above this
# function always claimed happened.
strip_expressions() {
  printf '%s' "$1" \
    | sed -e 's/\${{[^}]*}}//g' -e 's/\${[^}]*}//g' -e 's/{{[^}]*}}//g' \
          -e 's/\$([^)]*)//g' -e 's/`[^`]*`//g'
}

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
  local f="$1" ln="$2" url="$3" kind="$4" scheme rest hostport host has_expr probe
  scheme=$(printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]')
  rest="${url#*://}"
  hostport="${rest%%/*}"; hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
  hostport="${hostport##*@}"
  case "$hostport" in
    \[*\]*) host="${hostport%%\]*}]";;
    *) host="${hostport%%:*}";;
  esac

  # An expression is present when removing the balanced ones changed the
  # host, or when an opener survives that removal. Derived this way rather
  # than by looking for a delimiter, because a lone backtick is far more
  # often a JavaScript string quote than an expression: treating
  # `https://user-api.erpc.global`;` as an expression host would report a
  # host. A removed backtick PAIR does count.
  paired=$(strip_expressions "$host")
  has_expr=no
  [ "$paired" = "$host" ] || has_expr=yes
  case "$paired" in *'${'*|*'{{'*|*'$('*) has_expr=yes;; esac

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

  # `probe` is the host's literal skeleton: the same string with every
  # expression removed, so the checks below read the parts the author wrote
  # and not the parts the expansion decides. With no expression it is just
  # the host. The scheme and character checks run on it BEFORE the allowlist
  # question, because an earlier arrangement answered that question first and
  # returned, which let a host matching a declared pattern carry plaintext
  # http, a Cyrillic label or an escape past checks the gate states as
  # absolute.
  if [ "$has_expr" = yes ]; then
    probe="$paired"
  else
    host="${host%%[)\",\';\`]*}"
    probe="$host"
  fi
  probe="${probe%%[)\",\';\`]*}"
  [ "$has_expr" = yes ] || [ -n "$host" ] || return 0

  # A host that is not plain ASCII is a homograph risk and must be seen, not
  # silently skipped because the matcher's character class missed it.
  # Deliberately `tr -d` and not a bracket expression: a class containing
  # `[` and `]` is read differently by different greps, and two attempts at
  # writing one here produced a check that silently matched nothing.
  if [ -n "$(printf '%s' "$probe" | LC_ALL=C tr -d 'A-Za-z0-9.:_[]-')" ]; then
    report "$f" "$ln" "non-ASCII or unexpected character in host: $scheme://$host"
    return 0
  fi
  if ! is_loopback_host "$host" && [ "$scheme" = http -o "$scheme" = ws ]; then
    report "$f" "$ln" "plaintext $scheme:// outside loopback: $host"
    return 0
  fi

  # An expression in the host means the destination is not fixed by what is
  # written. It is allowed only when the literal text on both sides matches a
  # declared HOST_PATTERNS pair, which is what that list is for
  # (`solana-snapshot-${REGION}.erpc.global`). The one thing this gate must
  # not do is vouch for a host on the strength of its first few bytes -- and
  # that applies just as much when the expression comes FIRST, because the
  # literal that follows it is the registrable domain. A host with no literal
  # part at all is skipped: there is nothing to check, and nothing here
  # builds one.
  if [ "$has_expr" = yes ]; then
    [ -n "$probe" ] || return 0
    template_host_matches_pattern "$host" && return 0
    report "$f" "$ln" "expression in host, so the literal text does not fix the destination: $scheme://$host"
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
  #
  # A URL is a run of non-space characters OR whole balanced expressions,
  # so a space inside `${{ ... }}` or `{{ ... }}` does not end it and
  # `https://{{ host }}.evil.example.net` is seen whole. An earlier version
  # got this by rewriting expressions to space-free placeholders before
  # matching, which is the one thing a gate must not do: `[^}]*` ran to the
  # next closer anywhere on the line, so an unbalanced `${` before a URL and
  # a `}` after it replaced the URL itself, and nothing downstream ever saw
  # it. The matcher now reads the line as written and edits nothing.
  #
  # Backticks are deliberately NOT one of the balanced forms here. A backtick
  # is also a JavaScript string quote, so pairing them across a space would
  # join a URL to whatever text follows it in the file. The cost is that
  # `https://`cat host`.evil.example.net` is cut at the space and its domain
  # is not seen; that limit is stated in the header.
  while IFS=: read -r ln url; do
    [ -z "$ln" ] && continue
    check_url "$f" "$ln" "$url" "$kind"
  done < <(grep -a '' "$f" 2>/dev/null | sed 's|\\/|/|g' \
    | grep -naoiE '(https?|wss?)://(\$\{\{[^}]*\}\}|\$\{[^}]*\}|\{\{[^}]*\}\}|\$\([^)]*\)|[^[:space:]"'"'"'<>])+' 2>/dev/null)
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
