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
#   - One assumption here is about the allowlist rather than the grammar:
#     a match can absorb the LETTERS of a following scheme (never its colon,
#     which no production admits in that position), and the host then ends
#     in http, https, ws or wss. That is caught because no declared host
#     ends in those and HOST_PATTERNS requires .erpc.global last. Declaring
#     a host that ends in one of them would quietly break it.
#   - A host that is ENTIRELY one balanced expression, such as ${MIRROR}, is
#     skipped: there is nothing literal to check. An UNTERMINATED opener is
#     not that case and is reported, because the text after it is literal
#     and is usually the registrable domain.
#   - The matcher applies ONE normalisation to the line, in normalise()
#     below, and nothing else: it reproduces what the WHATWG URL Standard
#     does to its input BEFORE parsing, because that is what a browser,
#     curl and the Worker's fetch all do. Claiming the line was read "as
#     written" was wrong in both directions -- one rewrite was already
#     there, and it was too narrow to be faithful. It then
#     matches the AUTHORITY only, stopping at the first / ? or #, and within
#     it a run of non-space characters or whole balanced ${ }, ${{ }}, {{ }}
#     and $( ) expressions, none of which may contain a /. A space inside
#     one of those does not end the match; nothing in the path is matched,
#     because the authority is all this gate judges. Both bounds exist so
#     that a match can never reach a later URL on the same line and hide it.
#   - Backticks are not one of the balanced forms: a backtick is also a
#     string quote, and pairing them across a space would splice a URL to
#     unrelated text. A backtick inside a host is instead reported when what
#     follows it still carries two dot-separated labels, which is what a
#     registrable domain needs; a backtick followed by punctuation or by a
#     method call is a string quote and is trimmed as before.
#   - The shapes this gate does NOT see. This list is NOT COMPLETE and must
#     not be read as if it were: an earlier version of this header said
#     "two shapes", and the next review found five more. The reason is
#     structural rather than a series of oversights. The matcher ends the
#     authority at a fixed set of characters, and that set is narrower than
#     the set a URL parser accepts, so a character at which the match stops
#     early can always be looked for. What this gate buys is that adding a
#     destination costs effort and shows up in a diff; it is not a proof
#     that none can be written. The ones known today:
#       * a backtick expression containing a space, as in
#         https://`cat host`.evil.example.net. The match ends at the space,
#         and widening the rule far enough to catch it also rejects
#         `https://semver.org`. in prose, which is a correct line.
#       * a colon not followed by digits ends the match, so in
#         https://declared:x.evil.example.net/y the host judged is the part
#         before the colon. No URL parser accepts a non-numeric port --
#         node's new URL() raises ERR_INVALID_URL, curl refuses it -- so
#         this is not a reachable destination. A guard over this shape was
#         tried and removed: its only unique catch was this unreachable
#         form, while it also reported url.strip_prefix("https://") and a
#         declared host followed by ordinary punctuation in a comment.
#       * a single or double quote inside the host ends the match, and
#         unlike the colon this one IS reachable:
#         https://api.github.com'evil.example.net/x resolves to the host
#         api.github.com'evil.example.net, which a wildcard record under
#         evil.example.net serves, so the DNS query reaches that zone even
#         though no public CA will issue a certificate for a label
#         containing a quote. It is open rather than closed because
#         admitting quotes to the authority makes ["https://a","https://b"]
#         -- a JSON array of two URLs with no space between them -- read as
#         the single host a","https, which is a false positive on a correct
#         and common line. The quote characters have been excluded since
#         before this gate was hardened; this entry records it, it is not a
#         new hole.
#       * a URL split across two lines by a multi-line string literal. The
#         Standard deletes LF from its input exactly as it deletes tab and
#         CR, and normalise() handles those two, but this gate reads one
#         line at a time and a rejoined URL is not visible to it.
#   - A host that is not plain ASCII, or one containing a backslash escape
#     anywhere, is reported: both are literals a reviewer should see, and
#     neither may be skipped just because the matcher finds them awkward.
#     These checks, and the plaintext one above, run on every URL before the
#     allowlist question is answered, so no host can reach an "allowed"
#     verdict without passing them first.
#   - normalise() deletes ASCII tab and CR, accepts \ where / is expected
#     after a scheme, and collapses runs of backslashes before a slash.
#     Each form resolves for real: the URL Standard DELETES tab/CR/LF from
#     its input before parsing, and treats \ as / for a special scheme, so
#     ht<TAB>tps://h, https://declared<TAB>.evil.example.net, https:\\h and
#     https:\/\/h are all live destinations that a text matcher looking for
#     a literal :// does not see. The predecessor of this rule was a single
#     pass of s|\\/|/|g, which turned \\/\\/ into \/\/ and so left no ://
#     in the line at all -- a double escape was a complete bypass.
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
  local f="$1" ln="$2" url="$3" kind="$4" scheme rest hostport host has_expr probe paired bt_tail
  scheme=$(printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]')
  rest="${url#*://}"
  hostport="${rest%%/*}"; hostport="${hostport%%\?*}"; hostport="${hostport%%#*}"
  hostport="${hostport##*@}"
  case "$hostport" in
    \[*\]*) host="${hostport%%\]*}]";;
    *)
      # Strip a TRAILING :digits, which is the only port the matcher admits.
      # Cutting at the first colon instead reached inside an expression:
      # `https://solana-snapshot-${a:-b}.erpc.global` became the host
      # `solana-snapshot-${a`, reported for an unexpected character rather
      # than recognised as the declared pattern it is.
      if printf '%s' "$hostport" | LC_ALL=C grep -qE ':[0-9]+$'; then
        host="${hostport%:*}"
      else
        host="$hostport"
      fi
      ;;
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

  # A LONE backtick is treated as a string quote above, which is right for
  # `https://user-api.erpc.global`; -- but only while nothing host-like
  # follows it. When something does, trimming there would drop the
  # registrable domain and allow the host on the strength of what came
  # before, which is the same mechanism as the backslash check.
  #
  # The test is whether the tail LOOKS LIKE a host, not whether it is
  # non-empty. Non-empty was wrong in both directions: it rejected
  # `https://semver.org`. ending a markdown sentence and
  # `https://user-api.erpc.global`.trim(), both declared hosts on correct
  # lines, and -- because the tail was then trimmed at the same punctuation
  # class as the host -- it let `https://github.com`;evil.example.net
  # through, since the tail emptied at the `;`. So: no trim here, and report
  # only when two dot-separated labels survive, which is the shortest thing
  # that can carry a registrable domain.
  if [ "$has_expr" = no ]; then
    case "$host" in
      *'`'*)
        bt_tail="${host#*\`}"
        if printf '%s' "$bt_tail" | LC_ALL=C grep -qE '[A-Za-z0-9-]+\.[A-Za-z0-9-]+'; then
          report "$f" "$ln" "backtick inside the host hides the rest of it: $scheme://$host"
          return 0
        fi
        ;;
    esac
  fi

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

# One definition of an authority, shared by the matcher and by the boundary
# guard below so that tightening one cannot silently invalidate the other.
#
#   [ userinfo "@" ] ( IP-literal | host ) [ ":" digits ]
#
# userinfo admits ':' and '@' and stops at '/'. It has to admit '@': the
# WHATWG URL Standard, and so every browser, curl and URL library, splits
# an authority at the LAST '@', and `hostport="${hostport##*@}"` below is
# written to that rule. A grammar that stopped at the first '@' disagreed
# with it, and `https://a@user-api.erpc.global@evil.example.net/x` was then
# approved on the declared middle component while resolving elsewhere.
url_re='(https?|wss?)://(((\$\{\{[^}/]*\}\}|\$\{[^}/]*\}|\{\{[^}/]*\}\}|\$\([^)/]*\)|[^[:space:]"'"'"'<>/?#])*@)?(\[[0-9A-Fa-f:.]*\]|(\$\{\{[^}/]*\}\}|\$\{[^}/]*\}|\{\{[^}/]*\}\}|\$\([^)/]*\)|[^[:space:]"'"'"'<>/?#:@])+)(:[0-9]+)?)'

# The ONE normalisation this gate applies to a line, and the only place it
# rewrites anything. It reproduces what the WHATWG URL Standard does to the
# same text, so that what this gate judges is what a browser, curl or the
# Worker's `fetch` would actually contact:
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
#   * ANY run of `/` after a special scheme -- including a run of length
#     one, and INCLUDING NONE -- collapses to `://`. This is not cosmetic.
#     The Standard's special-authority-ignore-slashes state skips any number
#     of `/` (and of `\`), so `https:h`, `https:/h`, `https:///h` and
#     `https:////h` all resolve to h exactly as `https://h` does. An earlier
#     version rewrote only the two-character forms `:\\` and `:/\` plus a
#     backslash run before a slash, on the belief that the leniency was
#     about escaped slashes in string literals. It is not, and every shape
#     above passed this gate without being looked at.
#
#     A BACKSLASH is deliberately NOT consumed here, although the Standard
#     skips it in the same state. Resolving it would make this gate name a
#     host the source does not: in Rust, TypeScript and Python alike
#     `"https://\x65vil.example.com"` is one compile-time literal whose real
#     authority is evil.example.com, while skipping the backslash as if it
#     were a slash yields x65vil.example.com -- a concrete-looking host that
#     is not the destination, and that would PASS if it were ever declared.
#     So a backslash anywhere in the authority is reported as a hidden
#     literal by the check in check_url instead, which refuses rather than
#     guesses, and covers `https:\h`, `https:/\h`, `https:\\/\\/h` and
#     `https://\x65vil` alike. Refusing is strictly safer than resolving and
#     needs no knowledge of which language the file is in -- the machinery
#     this gate has twice deleted.
#
#     The cost, which is real: a JavaScript regex literal written to match
#     URLs, such as /^https:\/\//, has `https:` followed by no slash, so
#     `://` is inserted and the host becomes a backslash, which is then
#     reported. No such line exists in the tree today. Write the pattern
#     with a character class, or add the file to --print-exceptions.
# The scheme alternation, spelled with character classes because BSD sed has
# no portable case-insensitivity modifier for s/// and the matcher below runs
# `grep -i`. Keeping the two in step matters: a rule that only saw lowercase
# would normalise `https:` and leave `HTTPS:` for the matcher to miss.
scheme_re='([Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?)'
tab=$(printf '\t')
cr=$(printf '\r')
normalise() {
  sed -E -e "s/${tab}${scheme_re}:/ \1:/g" \
         -e "s/${cr}${scheme_re}:/ \1:/g" \
         -e "s/${tab}//g" \
         -e "s/${cr}//g" \
         -e "s#${scheme_re}:(/)*#\1://#g"
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  is_excepted "$f" && continue
  if [[ "$f" =~ $prose_re ]]; then kind=prose; else kind=code; fi

  # -a so a stray NUL cannot hide the rest of the file from either branch.
  # Escaped slashes (\/\/) are normalised so a JSON or TypeScript string
  # cannot hide a URL from the matcher.
  #
  # The match is the AUTHORITY only -- it stops at the first / ? or # -- and
  # within it a run of non-space characters or whole balanced expressions,
  # so a space inside `${{ ... }}` or `{{ ... }}` does not end it and
  # `https://{{ host }}.evil.example.net` is seen whole. Nothing else of the
  # URL is matched, because the authority is all this gate judges.
  #
  # Both bounds are load-bearing, and each replaced a defect that let a URL
  # escape the gate entirely:
  #
  #   * Stopping at / keeps the balanced branches out of the path. When they
  #     could start after a /, `https://github.com/x$(echo https://evil…)`
  #     was ONE match whose host was the declared github.com, and the inner
  #     URL -- a real destination -- was inside it, so `grep -o` never
  #     emitted it. Allowed, silently.
  #   * Forbidding / INSIDE an expression keeps `://` out of one, so a
  #     balanced span cannot contain a URL even in the authority.
  #   * The authority is spelled out rather than approximated:
  #     [ userinfo "@" ] ( IP-literal | host ) [ ":" digits ]. Earlier
  #     versions matched one undifferentiated run and let check_url trim it
  #     into a host afterwards, and every trim was a silent assumption about
  #     where the authority ended. Each time the run was tightened, one of
  #     those assumptions broke somewhere else:
  #
  #       - a bare : was excluded to stop a match eating the scheme of a
  #         later URL, which also cut the match before the @, so
  #         `https://github.com:x@evil.example.net/x` was read as the
  #         declared github.com and the real destination vanished. A colon
  #         is legal in userinfo, so userinfo now carries its own.
  #       - the IP-literal branch was one element of the run, so
  #         `https://[::1]https://evil.example.net/x` absorbed the next
  #         scheme's letters and the `]` trim then discarded them. It is a
  #         terminal alternative now: a bracketed authority ends at the ].
  #
  #     Spelling the grammar out is what keeps the matcher and the three
  #     derivations in check_url talking about the same thing.
  #
  # The version before that rewrote expressions to placeholders first, which
  # is the one thing a gate must not do: an unbalanced `${` before a URL and
  # a `}` after it replaced the URL itself. Three rounds of this had the one
  # cause -- treating "find the URLs" as a regex over a whole line of
  # arbitrary source. Bounding the match to the authority removes the only
  # freedom the extension had. The invariant to hold on to is not "no
  # rewriting" but: no URL in a tracked file escapes evaluation. The suite
  # asserts that directly.
  #
  # Backticks are deliberately NOT one of the balanced forms here. A backtick
  # is also a JavaScript string quote, so pairing them across a space would
  # join a URL to whatever text follows it in the file. The cost is that
  # `https://`cat host`.evil.example.net` is cut at the space and its domain
  # is not seen; that limit is stated in the header.
  while IFS=: read -r ln url; do
    [ -z "$ln" ] && continue
    check_url "$f" "$ln" "$url" "$kind"
  done < <(grep -a '' "$f" 2>/dev/null | normalise \
    | grep -naoiE "$url_re" 2>/dev/null)

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
