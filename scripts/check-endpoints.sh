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
#
#     The BACKTICK is the exception, because awk does not track it as a
#     balanced form -- pairing backticks across a space would swallow
#     `https://semver.org`. and `https://user-api.erpc.global`.trim() to end
#     of line, both correct lines. So the authority ends at the first space
#     or terminator inside a backtick expression, and what happens next
#     depends on what is on either side of the backtick:
#       * nothing before it -- reported as a hidden literal;
#       * a letter or digit after it, i.e. a command name -- reported as a
#         host built at runtime, whatever the prefix is;
#       * a declared host or HOST_PATTERNS match before it and a SPACE after
#         it -- ALLOWED. That is a known limit, stated below, and it holds
#         through a pattern as well: `https://erpc.global` cat f`/p` is
#         allowed. This bullet has twice claimed more than the code did,
#         once that every backtick expression was reported and once that
#         one with a space could never be allowed by a pattern.
#   - One assumption here is about the allowlist rather than the grammar:
#     an authority can absorb the LETTERS of a following scheme, and its
#     colon with them -- the colon is removed by the trailing-punctuation
#     strip or reported by the colon check, depending on what follows. The
#     absorbed-letters case is caught by the trailing-scheme-word arm of the
#     mid-punctuation tail test, not by an assumption about the allowlist.
#     An earlier version of this bullet said a match could never absorb the
#     colon and leaned on no declared host ending in http, https, ws or wss;
#     that was true of the regex this scanner replaced, and is not true now.
#   - A host that is ENTIRELY one balanced expression, such as ${MIRROR}, is
#     skipped: there is nothing literal to check. An UNTERMINATED opener is
#     not that case and is reported, because the text after it is literal
#     and is usually the registrable domain. That holds for the four forms
#     awk tracks -- ${{, ${, {{ and $( -- and not for a lone backtick, which
#     is not a tracked opener; see the bullet above.
#   - The scan is driven from SCHEME OCCURRENCES, not from URLs, and that is
#     the one design decision everything else here follows from. See the
#     block above check_occurrence for why the previous design was replaced:
#     in short, it matched a whole URL with a regex whose authority ran over
#     a fixed character class, and that class had to be narrower than the set
#     a URL parser accepts, so some character always ended the match early.
#     Four consecutive review rounds each found one. The attack surface was
#     the complement of that class, and a complement never empties.
#   - What this gate judges, per occurrence: the authority ends where it
#     cannot continue, trailing punctuation is stripped FROM THE END ONLY,
#     and what is left must EQUAL a declared host, an IP-literal or a
#     HOST_PATTERNS match. Nothing is trimmed into shape, and the default is
#     to report.
#   - Shapes this gate does NOT see. The list is NOT COMPLETE and must not
#     be read as if it were -- the rewrite removed the mechanism that
#     produced a new one every round, it did not turn a text gate into a
#     parser.
#
#       * SHELL STRING CONCATENATION NEXT TO A URL, in part. In a shell word,
#         quoted and unquoted parts and substitutions are joined, so a quote
#         or backtick that ends the authority does not end the host the
#         shell builds: "https://erpc.global"$(cat f)/p contacts erpc.global
#         with the command's output appended. The terminator set's safety
#         argument -- none of its characters can appear in a real host -- is
#         about LITERAL text, and runtime joining is exactly what breaks it.
#         Closing the class completely needs a model of how the shell builds
#         a word, which is a parser in a text matcher, the machinery this
#         gate has twice deleted. So it is closed where the shape is
#         unambiguous and open where it is not.
#
#         Closed: a quote ending the host followed at once by `$` or a
#         backtick; a backtick inside the host followed by a letter or digit.
#         Nothing but an interpolation or a command begins that way.
#
#         Open, each pinned by a KNOWN LIMIT case in the self-test:
#           - a backtick right after a declared host, then a space --
#             https://erpc.global` cat f`/p. Short of parsing shell quoting it
#             is the same text as a backtick closing an inline code span
#             before the next word, which is a correct line.
#           - a quote ending the host, then a dot --
#             'https://api.github.com'.evil.example.net/x. In shell the words
#             join; in Rust, TypeScript and Python it is a method call, as in
#             "https://erpc.global".to_string(), and the two cannot be told
#             apart from the text.
#           - a quote ending the host, then a letter, which includes a quote
#             INSIDE the host as the URL Standard permits:
#             https://api.github.com'evil.example.net/x resolves to the host
#             api.github.com'evil.example.net, served by a wildcard record,
#             so the DNS query reaches that zone even though no public CA
#             will issue for the label. Reporting it would also report a
#             possessive in prose, https://erpc.global's page; admitting
#             quotes to the authority instead reads ["https://a","https://b"]
#             as the single host a","https.
#
#         The design holds only while every construct that interpolates at
#         runtime, in every file type tracked here, is either tracked by awk
#         as a balanced form or reported. That is a list, and it lives in
#         check_occurrence and authority_of; a new file type with a new
#         interpolation syntax needs an entry there before it is safe.
#
#       * a URL split across two lines by a multi-line string literal. The
#         Standard deletes LF as it deletes tab and CR; this gate is
#         line-based.
#   - Shapes this header once listed as limits, and which are now CLOSED
#     rather than restated: a colon followed by something that is not a
#     port, which no longer ends the authority, so
#     https://declared:x.evil.example.net/y is reported where it used to be
#     judged as the declared prefix; a backtick expression with nothing
#     before it; and a NUL byte, which used to hide the rest of its line
#     from awk and is now a space by the time awk sees it. One shape that
#     was never on the list is closed too: a `,`, `;`, `)` or backtick
#     between a declared host and a second URL no longer hides that URL,
#     because the second scheme occurrence is scanned in its own right.
#   - A host that is not plain ASCII, or one containing a backslash escape
#     anywhere, is reported: both are literals a reviewer should see, and
#     neither may be skipped just because the matcher finds them awkward.
#     These checks, and the plaintext one above, run on every occurrence
#     before the allowlist question is answered, so no host can reach an
#     "allowed" verdict without passing them first.
#   - A backslash is REFUSED, never resolved. The URL Standard skips it like
#     a slash after a special scheme, but resolving it would make this gate
#     name a host the source does not: "https://\x65vil.example.com" is one
#     compile-time literal in Rust, TypeScript and Python whose real
#     authority is evil.example.com, while skipping the backslash yields
#     x65vil.example.com -- concrete-looking, not the destination, and it
#     would PASS if ever declared. Refusing needs no knowledge of the file's
#     language, which is the machinery this gate has twice deleted.
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
service_host_count=$(printf '%s\n' "$service_hosts" | grep -c . || true)
case "$service_host_count" in ''|*[!0-9]*) service_host_count=0;; esac
if [ "$service_host_count" -lt 5 ]; then
  echo "allowlist extraction produced fewer than 5 hosts; the gate is broken" >&2
  exit 2
fi
# And an empty documentation list would make `grep -vxF ""` pass everything
# through, so service_hosts would grow rather than shrink and the tripwire
# above would never fire — the opposite of the intended failure.
doc_host_count=$(printf '%s\n' "$doc_hosts" | grep -c . || true)
case "$doc_host_count" in ''|*[!0-9]*) doc_host_count=0;; esac
# A non-numeric count is treated as zero rather than left to `[` to reject:
# with a failing `grep` on PATH the substitution was empty, `[ "" -lt 1 ]`
# raised "integer expression expected", and the tripwire fell through
# instead of firing.
#
# This is DEFENSIVE REDUNDANCY, not a tested control, and the difference is
# worth stating. Removing it fails no case, because the only way the count
# goes non-numeric is a failing `grep`, and the scan's own pipeline check
# then refuses the run anyway -- so the exit code is 2 either way. What this
# buys is that the tripwire fires with its own message instead of emitting
# a shell error and falling through to a less specific one.
if [ "$doc_host_count" -lt 1 ]; then
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
  local host prefix suffix lit_pre lit_suf opener closerr after best d c o cl mid tail
  host=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')

  # Find the EARLIEST template delimiter and pair it with ITS OWN closerr.
  # Pairing matters: a backtick is both a template delimiter and a JavaScript
  # string quote, so "after the last closing delimiter" reads the text after
  # the string's closing backtick and loses the real suffix.
  best=""; opener=""; closerr=""
  for d in '${:}' '{{:}}' '$(:)' '`:`'; do
    o="${d%%:*}"; cl="${d##*:}"
    c="${host%%$o*}"
    [ "$c" = "$host" ] && continue
    if [ -z "$opener" ] || [ ${#c} -lt ${#best} ]; then best="$c"; opener="$o"; closerr="$cl"; fi
  done
  [ -n "$opener" ] || return 1
  lit_pre="$best"

  after="${host#*$opener}"
  case "$after" in *"$closerr"*) lit_suf="${after#*$closerr}";; *) return 1;; esac
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
# ---------------------------------------------------------------------------
# The scanner.
#
# This is the INVERTED design, and it replaced a matcher that had produced one
# bypass of the same class in each of four consecutive review rounds. The old
# one matched a whole URL with a regex whose authority ran over a fixed
# character class, then trimmed that match into a host. Both halves were
# wrong in the same way:
#
#   * the authority class had to be NARROWER than the set a URL parser
#     accepts, so there was always a character at which the match ended early
#     and handed over a prefix of the real host. Rounds 9 to 12 found the
#     bare `:`, the slash counts, the trim set, and then the one character
#     between a separator and the next scheme. The attack surface was the
#     COMPLEMENT of that class, and a complement never empties.
#   * `grep -o` emits NON-OVERLAPPING matches, so a match that absorbed the
#     letters of a following scheme consumed that URL too: it was never
#     emitted, never evaluated, and nothing was reported. One URL in, no
#     finding out.
#
# The scan is now driven from SCHEME OCCURRENCES rather than from URLs. awk
# finds every `scheme:` at a word boundary, one at a time, and hands the rest
# of the line to check_occurrence. Three properties follow, and they are the
# whole reason for the rewrite:
#
#   1. No URL can be consumed by an earlier match, because the thing matched
#      is six characters long and the scan continues from just past its
#      colon. Every occurrence is evaluated, whatever its neighbours are.
#   2. There is no "how far does the authority run" question answered by a
#      character class. The authority ends where it cannot continue, and what
#      is left must EQUAL a declared host. Nothing is trimmed into shape.
#   3. The default is REPORT. A shape nobody has thought of fails closerd
#      instead of passing silently, which inverts the one property that cost
#      four rounds.
#
# The cost is real and is the point of the trade: a default-report gate
# reports correct lines until the terminator and trailing-punctuation sets
# cover them. That cost is BOUNDED -- two enumerated lists, fourteen entries
# between them, and a miss is a loud failure on a correct line that someone
# fixes the same day. The old cost was UNBOUNDED: a character class that had
# to be COMPLETE, with no way to know when it was, and a miss was a silent
# pass that survived review rounds.
#
# Each of those fourteen entries has a case that fails when it is dropped.
# Said here only because it was FALSE when first claimed: a review measured
# it and found at most six of eighteen entries covered, six live and
# uncovered, and four doing nothing. The uncovered ones were the real
# problem -- a refactor could drop one and produce false positives that are
# loud to users and silent to CI -- so eight cases were added and the four
# dead entries removed. A list whose completeness is the stated
# justification must not contain an entry that does nothing, because such an
# entry makes the claim unfalsifiable.
#
# Two reasons neither set can hide a destination, which is what makes them
# different in kind from the character class they replaced. Every terminator
# except `"` and `'` is a character the URL Standard FORBIDS in a host, so
# it cannot cut a real host short; those two are the disclosed limit above.
# And no character in the trailing-punctuation set can form a DNS label, so
# stripping a run of them off the end cannot move the registrable domain.

# Where an authority ENDS. A character here cannot be part of one, so the
# authority is the run before it. Space is in the set because normalise()
# has already deleted tab and CR by this point.
#
# `"` and `'` are here although the URL Standard does NOT forbid them in a
# host: `https://a'b.example.net` really does resolve to the host
# a'b.example.net. They end the authority anyway because a quote is how
# source code delimits a URL, and admitting them makes `["https://a",
# "https://b"]` -- a JSON array of two URLs -- read as the single host
# `a","https`. That gap is stated in the header limits; it is the same one
# the previous design had, and it is the only character class decision left
# in the gate.
authority_end='[/?#"'"'"'<> ]'

# Trailing punctuation stripped from the END of an authority, and only from
# the end. This is what lets prose write a URL inside a sentence. Stripping
# at the FIRST occurrence instead -- which the previous design did -- is
# what let `https://api.github.com,evil.example.net` be judged as
# api.github.com.
#
# Why this cannot move a destination, which is the argument the list rests
# on: no character in it can form a DNS label. Stripping a run of them off
# the end therefore cannot change the registrable domain; the only two that
# alter the host string at all are `:` (an empty port) and, before it was
# removed, a trailing root dot -- both the same host.
#
# SIX entries, and each has a case: `]` `;` `:` `}` `!` and a backtick.
# Four more were removed as redundant, after checking that dropping all
# four changed neither the verdict NOR the message on eight probes:
# `.` is already handled by host_allowed stripping a trailing root dot,
# `,` and `)` by the mid-punctuation prefix path below, and `?` cannot
# reach here because it ends the authority in the first place. The list is
# short on purpose: its completeness is what the header offers as the
# bounded cost of reporting by default, so an entry that does nothing is
# worse than absent -- it makes the claim unfalsifiable.
authority_tail_punct='[];:}!`]'

# $1 scheme word (with its colon), $2 the rest of the line after that colon,
# $3 file, $4 line number, $5 prose|code
check_occurrence() {
  local scheme="$1" rest="$2" f="$3" ln="$4" kind="$5" look="${6:-L}"
  local authority host probe paired has_expr tail prefix

  scheme=$(printf '%s' "${scheme%:}" | tr '[:upper:]' '[:lower:]')

  # The authority was computed by awk, which walked it with the balanced
  # expressions in mind. Nothing here re-derives where it ends.
  authority="$rest"

  # userinfo. Every URL parser splits an authority at the LAST '@', so a
  # declared host in the middle vouches for nothing.
  authority="${authority##*@}"

  [ -n "$authority" ] || return 0

  # A QUOTE THAT ENDS THE HOST, FOLLOWED AT ONCE BY AN INTERPOLATION. In a
  # shell word, quoted and unquoted parts are joined, so
  # `"https://erpc.global"$(cat f)/p` contacts erpc.global with the command's
  # output appended -- erpc.global.evil.example.net when that output is
  # `.evil.example.net`. The quote is a terminator here because a quote is
  # how source delimits a URL, so the text past it was never part of the
  # authority, and the allowlist was asked about the declared prefix alone.
  #
  # Closed for `$` and a backtick only, because those two are unambiguous:
  # nothing but an interpolation begins that way, and in the other languages
  # this repository holds the shape is a syntax error, not a correct line.
  # A quote followed by a `.` or a letter is NOT closed -- see the header --
  # because `"https://erpc.global".to_string()` is ordinary Rust and the dot
  # cannot be told apart from shell concatenation without parsing the file.
  case "${look#L}" in
    [\"\']\$*|[\"\']\`*)
      report "$f" "$ln" "a quote ends the host and an interpolation follows it, so the host is built at runtime: $scheme://$authority"
      return 0
      ;;
  esac

  # A backslash ANYWHERE in the authority hides the rest of it. In Rust,
  # TypeScript and Python alike `https://github.com\x2eevil.example.net` is
  # one compile-time literal under evil.example.net. Refusing is strictly
  # safer than resolving, and needs no knowledge of the file's language.
  case "$authority" in
    *\\*)
      report "$f" "$ln" "escape sequence in host, so the literal is hidden: $scheme://$authority"
      return 0
      ;;
  esac

  case "$authority" in
    # An IP-literal ends at its bracket, and its brackets are not trailing
    # punctuation to be stripped.
    \[*\]*)
      host="${authority%%\]*}]"
      ;;
    *)
      # The port: a trailing run of digits, or a trailing balanced
      # expression, which is how a port is written in practice --
      # `127.0.0.1:${PORT}` for the OAuth callback, `:{port}` in a Rust
      # format string. Anchored at the END, so `:{x}.evil.example.net`
      # does not qualify and falls through to the colon check below.
      host=$(printf '%s' "$authority" | LC_ALL=C sed -E \
        's/:([0-9]+|\$\{\{[^}]*\}\}|\$\{[^}]*\}|\{\{[^}]*\}\}|\$\([^)]*\)|\{[^}]*\})$//')

      # Then trailing punctuation, from the end only and as a run, which is
      # what lets prose put a URL in a sentence.
      #
      # Guarded by the expression skeleton: a `}` or `)` that CLOSES a
      # balanced expression is not trailing punctuation, and stripping it
      # turned `${MIRROR}` into `${MIRROR` -- reported for an unexpected
      # character rather than recognised as the wholly-templated host it is.
      # A character is literal exactly when removing the balanced
      # expressions leaves it at the end as well.
      while :; do
        case "$host" in
          *$authority_tail_punct) ;;
          *) break;;
        esac
        case "$(strip_expressions "$host")" in
          *$authority_tail_punct) host="${host%?}";;
          *) break;;
        esac
      done

      # A colon that is not a port. The previous design stopped the match at
      # the first colon and so judged the part before it, which made
      # `https://declared:x.evil.example.net/y` read as the declared host --
      # a limit this gate used to state rather than close. It is closed now:
      # the colon is looked for in the SKELETON, so a colon inside an
      # expression (`solana-snapshot-${a:-b}.erpc.global`) is not one.
      case "$(strip_expressions "$host")" in
        *:*)
          report "$f" "$ln" "a colon in the authority is followed by something that is not a port: $scheme://$host"
          return 0
          ;;
      esac
      ;;
  esac

  [ -n "$host" ] || return 0

  # An expression means the destination is not fixed by what is written.
  # Detected BEFORE the punctuation test below, because a `)` that closes a
  # command substitution is not punctuation inside a host: `$(cat host)`
  # would otherwise be cut to `$(cat host`. An expression-bearing host takes
  # the stricter HOST_PATTERNS path further down in any case, so nothing is
  # lost by skipping the punctuation test for it.
  paired=$(strip_expressions "$host")
  has_expr=no
  [ "$paired" = "$host" ] || has_expr=yes
  case "$paired" in *'${'*|*'{{'*|*'$('*) has_expr=yes;; esac
  if [ "$has_expr" = yes ]; then probe="$paired"; else probe="$host"; fi

  # What remains may still carry punctuation in the MIDDLE, and that is the
  # one place this gate has to interpret rather than measure. `,`, `;`, `)`
  # and a backtick are all legal in a host per the URL Standard --
  # `api.github.com,evil.example.net` resolves -- and they are also how prose
  # and code put a URL inside a larger construct.
  #
  # The test is on the TAIL, not on the character: what follows the first
  # such character decides. Two dot-separated labels is the shortest thing
  # that can carry a registrable domain, and a trailing scheme word is the
  # absorbed letters of a following URL.
  if [ "$has_expr" = no ]; then
    case "$host" in
      *[,\;\)\`]*)
        prefix="${host%%[,\;\)\`]*}"
        tail="${host#*[,\;\)\`]}"
        if printf '%s' "$tail" | LC_ALL=C grep -qE '[A-Za-z0-9-]+\.[A-Za-z0-9-]+|([Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?)$'; then
          report "$f" "$ln" "punctuation inside the host hides the rest of it: $scheme://$host"
          return 0
        fi
        # An EMPTY prefix means the punctuation is the first thing in the
        # authority, so there is no literal part before it and nothing to
        # judge -- and falling through to the `[ -n "$host" ]` test below
        # then RETURNED SUCCESS with real text still unexamined. This was
        # described, when it was closed, as the one silent pass left in this
        # function; it was not -- the case just below, with a declared prefix
        # in front of the backtick, was found a round later. It covered every
        # backtick expression containing a space or any terminator character
        # with nothing before it: `https://`echo evil`.example.net/x` was allowed, in a
        # workflow `run:` step where the backtick really is a command
        # substitution and the host really is contacted.
        #
        # The backtick is the one expression form awk does NOT track as a
        # balanced opener, deliberately: pairing backticks across a space
        # would swallow `` `https://semver.org`. `` and
        # `` `https://user-api.erpc.global`.trim() `` to end of line, both
        # correct lines. So the authority ends early for that form, and the
        # honest answer is to report rather than to resolve or to skip.
        if [ -z "$prefix" ]; then
          report "$f" "$ln" "the authority begins with punctuation, so the literal is hidden: $scheme://$host"
          return 0
        fi
        # A BACKTICK FOLLOWED BY A LETTER OR DIGIT, after a declared prefix.
        # The empty-prefix report above closed one subset of the backtick
        # case and the header then claimed the whole of it, which a review
        # measured false: with a non-empty prefix the truncated prefix
        # answered the allowlist alone, so
        # `https://erpc.global`echo .evil.example.net`/p` was allowed in
        # silence while the shell resolves it to
        # https://erpc.global.evil.example.net/p.
        #
        # What distinguishes it from the correct lines that share the shape:
        # in `` `https://user-api.erpc.global`.trim() `` and
        # `` `https://semver.org`. `` the backtick CLOSES a quote and is
        # followed by punctuation, while a command substitution is followed
        # by the command's name. Closed for that case only. A backtick
        # followed by a SPACE is not closed and is stated in the header,
        # since `` `https://erpc.global` now `` and
        # `` https://erpc.global` cat f` `` are the same text up to the point
        # where only a shell parser could tell them apart.
        case "${host#"$prefix"}" in
          \`[A-Za-z0-9]*)
            report "$f" "$ln" "a backtick inside the host starts a command, so the host is built at runtime: $scheme://$host"
            return 0
            ;;
        esac
        host="$prefix"
        probe="$host"
        ;;
    esac
  fi

  [ -n "$host" ] || return 0

  # These run BEFORE the allowlist question, so that no host can reach an
  # "allowed" verdict carrying plaintext http, a Cyrillic label or an escape.
  if [ -n "$(printf '%s' "$probe" | LC_ALL=C tr -d 'A-Za-z0-9.:_[]-')" ]; then
    report "$f" "$ln" "non-ASCII or unexpected character in host: $scheme://$host"
    return 0
  fi
  if ! is_loopback_host "$host" && [ "$scheme" = http -o "$scheme" = ws ]; then
    report "$f" "$ln" "plaintext $scheme:// outside loopback: $host"
    return 0
  fi

  if [ "$has_expr" = yes ]; then
    # A host that is ENTIRELY one balanced expression has no literal part to
    # check and is skipped; anything else must be pinned on both sides by a
    # declared HOST_PATTERNS pair.
    [ -n "$probe" ] || return 0
    template_host_matches_pattern "$host" && return 0
    report "$f" "$ln" "expression in host, so the literal text does not fix the destination: $scheme://$host"
    return 0
  fi

  if ! host_allowed "$host" "$kind"; then
    report "$f" "$ln" "endpoint not in the allowlist: $scheme://$host  (declare it in $allowlist_src; documentation links go in DOCUMENTATION_HOSTS)"
  fi
}

# The ONE normalisation this gate applies to a line, and the only place it
# rewrites anything. It reproduces what the WHATWG URL Standard does to the
# same text, so that what this gate judges is what a browser, curl or the
# Worker's `fetch` would actually contact:
#
#   * A NUL byte becomes a SPACE, before anything else. This one is not the
#     Standard's doing -- a NUL in a URL is simply invalid -- it is awk's:
#     awk ends a record at a NUL, so `x<NUL>curl https://evil.example.net/x`
#     hid the URL from the scan and was allowed with no output. A space and
#     not a deletion, so that two tokens on either side of the NUL cannot be
#     spliced into a scheme.
#
#   * ASCII tab and CR are DELETED. The Standard strips tab, CR and LF from
#     its input before parsing, so `ht<TAB>tps://evil.example.net` and
#     `https://api.github.com<TAB>.evil.example.net` are both live
#     destinations -- node's `new URL()` resolves them to evil.example.net
#     and api.github.com.evil.example.net -- while a matcher looking for a
#     literal `://` sees nothing in the first and stops at the tab in the
#     second. A LONE CR, from a classic-Mac line ending or a `\r` in a
#     string literal, sits mid-line and does the same thing, which is the
#     case the CR rule is actually for; a trailing CR from a CRLF file is
#     the case where it does nothing.
#   * A tab or CR IMMEDIATELY BEFORE a scheme becomes a space instead of
#     being deleted. There it separates two URLs rather than sitting inside
#     one, and deleting it would splice them into a host that is in neither.
#     Nothing can hide behind this: the text after the separator is matched
#     as a URL in its own right and answers for itself.
#   * The SLASH COUNT is not normalised here, and used to be. The URL
#     Standard's special-authority-ignore-slashes state skips any number of
#     `/` after a special scheme, so `https:h`, `https:/h`, `https:///h` and
#     `https:////h` all resolve to h -- and a rule here rewrote every such
#     run to `://` so that the old regex had a literal `://` to anchor on.
#     The scanner does not anchor on one: awk strips the leading slashes
#     from the remainder itself, whatever their count, including none. The
#     rule was therefore dead, and measured dead before being removed:
#     deleting it changed neither the verdict nor the MESSAGE on any of nine
#     slash and backslash forms, the uppercase scheme among them. Noting
#     how that was established, because "no case fails without it" has been
#     wrong twice on this file: a case can fail to distinguish two designs.
#
#     A BACKSLASH is still refused rather than resolved, by the check in
#     check_occurrence. The Standard skips it in the same state, but
#     resolving it would make this gate name a host the source does not:
#     `"https://\x65vil.example.com"` is one compile-time literal in Rust,
#     TypeScript and Python whose real authority is evil.example.com, while
#     treating the backslash as a slash yields x65vil.example.com -- which
#     is not the destination and would PASS if it were ever declared.
#   * A `)`, `,`, `;` or backtick IMMEDIATELY BEFORE a scheme gets a space
#     inserted, for the same reason as the tab and CR exception above and
#     with a sharper consequence. These are the characters the host is
#     trimmed at, and without this the second URL on such a line was never
#     evaluated AT ALL -- not merely misjudged. `grep -o` emits
#     non-overlapping matches, so on
#     `https://erpc.global,https://evil.example.net/x` the first match ran
#     to the second scheme's colon, the trim reduced it to the declared
#     erpc.global, and the scan then resumed PAST the second scheme: one
#     URL in, no finding out, and the one invariant this gate claims
#     broken. The split makes each URL its own match, judged on its own
#     merits -- which is also the right reading of a comma-separated list,
#     where the second URL really is contacted. It runs AFTER the slash
#     collapse, so a second URL written `,https:host` is separated too.
# The scheme alternation, spelled with character classes because BSD sed has
# no portable case-insensitivity modifier for s/// and the matcher below runs
# `grep -i`. Keeping the two in step matters: a rule that only saw lowercase
# would normalise `https:` and leave `HTTPS:` for the matcher to miss.
scheme_re='([Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?)'
tab=$(printf '\t')
cr=$(printf '\r')
# A literal backtick, so the separator rule can name it without the shell
# reading it as a command substitution.
bt=$(printf '\140')
normalise() {
  tr '\000' ' ' | sed -E -e "s/${tab}${scheme_re}:/ \1:/g" \
         -e "s/${cr}${scheme_re}:/ \1:/g" \
         -e "s/${tab}//g" \
         -e "s/${cr}//g" \
         -e "s#([),;${bt}])${scheme_re}://#\1 \2://#g"
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  is_excepted "$f" && continue
  if [[ "$f" =~ $prose_re ]]; then kind=prose; else kind=code; fi

  # The file is read with cat, which passes every byte and fails only when
  # the file cannot be read. It used to be `grep -a ''`, which exits 1 on a
  # zero-byte file because it selected nothing; under pipefail that read as
  # a failed scan, and an empty staged file blocked the pre-commit hook with
  # a message saying the scanner had failed. A NUL byte is handled in
  # normalise(), not here.
  #
  # awk emits ONE RECORD PER SCHEME OCCURRENCE: line number, the scheme word,
  # and the rest of the line after its colon. It then continues from just
  # past that colon, so a second occurrence on the same line is found whether
  # or not the first one's authority ran over it. That is the property the
  # previous `grep -o` pipeline could not have, and the one that made a URL
  # after a comma disappear from the scan entirely.
  #
  # The occurrence must sit at a word boundary. `xhttps:` is a scheme this
  # gate does not judge -- it is not special, so no parser applies the
  # slash-skipping rule to it and no client fetches it over TLS -- and
  # matching the tail of a word instead reported `let flows:u32 = 1;`.
  # TWO markers, because one was not enough. The sentinel below is emitted
  # by awk's END block, which runs even when awk receives no input -- so a
  # failing `grep` or a failing `normalise` left the sentinel intact and the
  # gate still reported nothing and exited 0. Measured, not reasoned: with a
  # `sed` that exits 1 on PATH, a file containing an undeclared host was
  # allowed. So the whole pipeline's status is checked as well, which
  # `pipefail` (set at the top of this file) makes meaningful: the group
  # emits __scan_failed__ when any stage of it fails.
  scan_complete=no
  scan_failed=no
  while IFS="$tab" read -r ln scheme look rest; do
    [ -n "$ln" ] || continue
    if [ "$scheme" = "__scan_failed__" ]; then scan_failed=yes; continue; fi
    if [ "$scheme" = "__scan_complete__" ]; then scan_complete=yes; continue; fi
    check_occurrence "$scheme" "$rest" "$f" "$ln" "$kind" "$look"
  done < <({ cat -- "$f" | normalise | awk '
    # Where an authority ends. index() rather than a regex, so no character
    # here needs escaping in two languages at once.
    BEGIN {
      re = "(^|[^A-Za-z0-9])([Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?):"
      # The apostrophe via sprintf: `\x` is a gawk/mawk extension, not
      # POSIX awk, and an awk without it would read this string as
      # `/?#"x27<> ` -- making x, 2 and 7 terminators, so that
      # https://x402.erpc.global yielded an empty authority. A silent
      # failure mode, which is the kind this gate must not have.
      TERM = "/?#\"" sprintf("%c", 39) "<> "
    }
    # The authority: the run after the slashes, up to the first character
    # that cannot continue one -- except inside a BALANCED expression, where
    # a space and a closing brace are part of the expression and not the end
    # of the authority. `https://{{ host }}.evil.example.net` has to be seen
    # whole, and `${MIRROR}` must not lose its brace to the terminator set.
    # Walking characters is why this lives in awk: the shell cannot do it
    # without a regex that has to be right in every edge case at once, which
    # is the thing this rewrite removed.
    function authority_of(rest,   i, n, c, c2, c3, out, closer) {
      sub(/^\/+/, "", rest)
      n = length(rest); out = ""; closer = ""; i = 1
      while (i <= n) {
        c = substr(rest, i, 1)
        if (closer != "") {
          if (substr(rest, i, length(closer)) == closer) {
            out = out closer; i += length(closer); closer = ""; continue
          }
          out = out c; i++; continue
        }
        c3 = substr(rest, i, 3); c2 = substr(rest, i, 2)
        if (c3 == "${{") { out = out c3; i += 3; closer = "}}"; continue }
        if (c2 == "${")  { out = out c2; i += 2; closer = "}";  continue }
        if (c2 == "{{")  { out = out c2; i += 2; closer = "}}"; continue }
        if (c2 == "$(")  { out = out c2; i += 2; closer = ")";  continue }
        if (index(TERM, c) > 0) { STOP = substr(rest, i, 2); break }
        out = out c; i++
      }
      return out
    }
    {
      s = $0
      while (match(s, re)) {
        tok = substr(s, RSTART, RLENGTH)
        sub(/^[^A-Za-z]/, "", tok)
        # STOP is the terminator that ended the authority and the character
        # after it, empty when the authority ran to end of line. It travels
        # with an `L` in front so the field is never empty: the read below
        # splits on tab, and bash collapses consecutive tabs as IFS
        # whitespace, so an empty field before the authority would shift
        # the authority into the wrong variable. The authority goes LAST,
        # where an empty one is harmless.
        STOP = ""
        auth = authority_of(substr(s, RSTART + RLENGTH))
        printf "%d\t%s\tL%s\t%s\n", NR, tok, STOP, auth
        s = substr(s, RSTART + RLENGTH)
      }
    }
    # The scan ran to completion. Checked below, because without it this
    # gate FAILS OPEN: the pipeline runs inside a process substitution, so
    # neither pipefail nor any exit status reaches $status, and an awk that
    # cannot start produces zero records -- no findings, exit 0, every URL
    # in the tree allowed. Demonstrated by renaming a variable to one of
    # awk reserved words, which is exactly the mistake that produced this
    # scanner s first draft.
    END { printf "0\t__scan_complete__\t\n" }'; } \
    || printf '0\t__scan_failed__\t\n')

  if [ "$scan_failed" = yes ] || [ "$scan_complete" != yes ]; then
    echo "the scanner did not run to completion on $f; refusing to report a clean result" >&2
    exit 2
  fi

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
