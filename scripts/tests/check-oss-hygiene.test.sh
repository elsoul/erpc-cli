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
  out="$("$sh" "$gate" "$rel" 2>&1)"; rc=$?
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

# The identifiers below are self-evidently placeholders, on purpose. The
# previous fixtures were random-looking 26-character strings, and a reviewer
# reasonably asked whether they had been copied from somewhere -- the only
# reassurance available was that they contained `8` and `9`, which are
# outside the RFC 4648 base32 alphabet a real 1Password identifier uses, so
# they could not have been real. Nobody should have to know that to read a
# test in the file whose own rule exists to keep these identifiers out of a
# public repository. These spell what they are.
check "bare 1Password vault identifier" block "$sample_dir/op1.md" \
  'The signing key lives in vault examplevaultidaaaaaaaaaaaa.'

check "bare 1Password item identifier" block "$sample_dir/op2.md" \
  'Rotate item exampleitemidbbbbbbbbbbbbb after use.'

check "1Password dashboard URL with both identifiers" block "$sample_dir/op2b.md" \
  'See https://my.1password.com/vaults/examplevaultidaaaaaaaaaaaa/items/exampleitemidbbbbbbbbbbbbb'

check "the words vault ID before the identifier" block "$sample_dir/op2c.md" \
  '1Password vault ID examplevaultidaaaaaaaaaaaa.'

check "an op:// reference carrying both ids is a pointer, not a leak" allow "$sample_dir/op3.toml" \
  'identity_ref = "op://abcdefghijklmnopqrstuvwxyz/abcdefghijklmnopqrstuvwxyz/keypair"'

check "an op:// reference with a hyphenated item name" allow "$sample_dir/op3b.toml" \
  'ref = "op://myvault/myitem-abcdefghijklmnopqrstuvwxyz/field"'

check "uppercase base32 beside the word vault is not an identifier" allow "$sample_dir/op4.md" \
  'A base32 blob vault = MFRGGZDFMZTWQ2LKNNWG23TPOB is in prose.'

check "a commit hash beside the word vault is not an identifier" allow "$sample_dir/op5.md" \
  'vault at commit 3f2a9c1e4b7d8a6f5c2e0b9d4a1f6c3e8b5d2a70 today.'

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
