#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/check-oss-hygiene.sh: every rule must actually block a
# known-bad sample and must not block a known-good one. A hygiene gate that is
# never tested quietly stops catching things.
#
#   scripts/tests/check-oss-hygiene.test.sh
set -uo pipefail

repo_root="$(git rev-parse --show-toplevel)"
gate="$repo_root/scripts/check-oss-hygiene.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# Runs the gate on one sample file placed at $rel inside the repo working tree.
# expect = "block" or "allow".
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
    pass=$((pass + 1))
    printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1))
    printf 'FAIL %s (expected %s, exit %s)\n%s\n' "$name" "$expect" "$rc" "$out"
  fi
}

sample_dir="tmp-hygiene-test"

# --- must block -------------------------------------------------------------

check "internal design document by filename" block "docs/architecture.md" \
  "# Architecture"

check "internal assessment by filename" block "$sample_dir/eu-oss-assessment.md" \
  "# assessment"

check "non-public erpc.global host" block "$sample_dir/a.rs" \
  'const URL: &str = "https://admin-internal.erpc.global/v1";'

check "cloudflare account identifier" block "$sample_dir/b.toml" \
  'account_id = "8a313f35be0eb4e99ad5bed9cb7aa99d"'

check "bearer token literal" block "$sample_dir/c.sh" \
  'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef"'

check "credential assignment" block "$sample_dir/d.sh" \
  'export OP_SERVICE_ACCOUNT_TOKEN=ops_abcdefghijklmnopqrstuvwxyz0123456789'

check "solana keypair array" block "$sample_dir/e.json" \
  "[$(python3 -c 'print(",".join(["7"]*64))')]"

check "labelled hex private key" block "$sample_dir/f.rs" \
  'let private_key = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3b4a0d4e5c6f7a8";'

check "PEM private key block" block "$sample_dir/g.pem" \
  '-----BEGIN EC PRIVATE KEY-----'

check "sibling private repository reference" block "$sample_dir/h.md" \
  'See elsoul/internal-ops for the runbook.'

check "this repository is not an internal reference" allow "$sample_dir/h2.md" \
  'Clone it from https://github.com/elsoul/erpc-cli'

check "reviewer team is not an internal reference" allow "$sample_dir/h2b.md" \
  'Reviewers: @elsoul/erpc-cli-maintainers'

check "a sibling sharing this repository's prefix is still blocked" block "$sample_dir/h2c.md" \
  'See elsoul/erpc-cli-internal for the runbook.'

check "mixed-case internal host" block "$sample_dir/h3.rs" \
  'const U: &str = "https://ops-internal.ERPC.global/";'

check "internal docs path reference" block "$sample_dir/i.md" \
  'The record lives in .claude/docs/erpc-cli-management/README.md'

check "developer home path" block "$sample_dir/j.sh" \
  'cp /Users/someone/secrets.txt .'

check "bare 1Password vault identifier" block "$sample_dir/op1.md" \
  'The signing key lives in vault 4xq7zj2mn8d5r3vb6kwth9pcyf.'

check "bare 1Password item identifier" block "$sample_dir/op2.md" \
  'Rotate item gk2m9r4xtp7vn6bq3zdw8scylh after use.'

check "an op:// reference is a pointer, not an identifier" allow "$sample_dir/op3.toml" \
  'identity_ref = "op://abcdefghijklmnopqrstuvwxyz/abcdefghijklmnopqrstuvwxyz/keypair"'

check "committed dotenv" block "$sample_dir/.env" \
  'TOKEN=abc'

# --- must allow -------------------------------------------------------------

check "published host" allow "$sample_dir/k.rs" \
  'const AUTH: &str = "https://auth-api.erpc.global/oauth/token";'

check "op secret reference" allow "$sample_dir/l.toml" \
  'identity_ref = "op://abcdefghijklmnopqrstuvwxyz/abcdefghijklmnopqrstuvwxyz/keypair"'

check "public contract address" allow "$sample_dir/m.rs" \
  'const EURC: &str = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42";'

check "env var name without a value" allow "$sample_dir/n.yml" \
  'CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}'

check "ordinary rust file" allow "$sample_dir/o.rs" \
  'pub fn main() { println!("hello"); }'

check "snapshot mirror host" allow "$sample_dir/p.rs" \
  'const SNAP: &str = "https://solana-snapshot-ams.erpc.global";'

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
