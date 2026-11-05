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

# --- what the next commit holds, as the pre-commit hook runs it -----------------

# check() names its file on the command line, which never exercises the listing or
# the index. These run the gate in a throwaway repository holding the sample and
# the one source file the gate reads.
#
# mktemp is guarded twice. If it failed unnoticed, `cd ""` would succeed and leave
# git running in this checkout.
allowlist_src="$repo_root/crates/erpc-core/src/endpoints.rs"
in_scratch_repo() {
  local repo
  repo="$(mktemp -d)" || exit 3
  scratch_out="$(
    # A hook runs with these set, and they would point git back at this checkout.
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
    [ -n "$repo" ] || exit 3
    cd "$repo" || exit 3
    git init -q . || exit 3
    mkdir -p crates/erpc-core/src .git/info
    cp "$allowlist_src" crates/erpc-core/src/endpoints.rs
    "$@"
  )"; scratch_rc=$?
  rm -rf "$repo"
}

# Block means exit 1: exit 2 is the gate reporting itself broken.
expect_outcome() {
  local name="$1" expect="$2"
  if { [ "$expect" = block ] && [ "$scratch_rc" -eq 1 ]; } || { [ "$expect" = allow ] && [ "$scratch_rc" -eq 0 ]; }; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1)); printf 'FAIL %s (expected %s, exit %s)\n%s\n' "$name" "$expect" "$scratch_rc" "$scratch_out"
  fi
}

# Asserts the message as well as the exit, where a later check would also stop a
# run that got past the one under test.
expect_refusal() {
  local name="$1" want="$2"
  case "$scratch_rc:$scratch_out" in
    2:*"$want"*)
      pass=$((pass + 1)); printf 'ok   %s\n' "$name";;
    *)
      fail=$((fail + 1)); printf 'FAIL %s (exit %s, wanted exit 2 saying "%s")\n%s\n' "$name" "$scratch_rc" "$want" "$scratch_out";;
  esac
}

# Writes $1 and stages it with content $2, then runs the gate with the rest.
stage_and_run() {
  local rel="$1" content="$2"
  shift 2
  mkdir -p "$(dirname -- "$rel")"
  printf '%s\n' "$content" > "$rel"
  git add -A -f
  # Standard input closed, so a gate that reads it instead of the file ends rather
  # than waiting on a terminal.
  "$sh" "$gate" "$@" 2>&1 </dev/null
}

check_staged() {
  local name="$1" expect="$2" rel="$3" content="$4"
  shift 4
  in_scratch_repo stage_and_run "$rel" "$content" --staged "$@"
  expect_outcome "$name" "$expect"
}

gate_staged() {
  "$sh" "$gate" --staged 2>&1 </dev/null
}

commit_staged() {
  git add -A -f
  git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false \
    -c core.hooksPath=/dev/null commit -qm x --no-verify
}

bad_content='See elsoul/internal-ops for the runbook.'
bad_host='const U: &str = "https://hidden-host.erpc.global/";'

# Names that were read by every other form, and those that lefthook used to drop.
for staged_name in " lead.md" "trail.md " "docs/日本語.md" 'docs/a"b.md' 'docs/a\b.md' -tmp-hygiene.md \
  --staged -- - '0:a.md' '1:a.md' "$(printf 'tab\there.md')" "$(printf 'new\nline.md')"; do
  check_staged "staged: the name [$staged_name] is read" block "$staged_name" "$bad_content"
done

# Every content check, with the file in the worktree and then gone from it, so that
# one check reading the worktree instead of the object fails here.
staged_then_removed() {
  mkdir -p "$(dirname -- "$1")"
  printf '%s\n' "$2" > "$1"
  git add -A -f
  rm "$1"
  gate_staged
}
staged_with_nul() {
  { printf 'x\000\n'; printf '%s\n' "$2"; } > "$1"
  git add -A -f
  gate_staged
}
expect_reported() {
  local name="$1" want="$2"
  case "$scratch_rc:$scratch_out" in
    1:*"$want"*)
      pass=$((pass + 1)); printf 'ok   %s\n' "$name";;
    *)
      fail=$((fail + 1)); printf 'FAIL %s (exit %s, wanted exit 1 saying "%s")\n%s\n' "$name" "$scratch_rc" "$want" "$scratch_out";;
  esac
}
staged_nul_on_line() {
  { printf 'x\000 '; printf '%s\n' "$2"; } > "$1"
  git add -A -f
  gate_staged
}
staged_nul_separator() {
  { printf '%s\000%s\n' "$2" "$3"; } > "$1"
  git add -A -f
  gate_staged
}
for sample in \
  'a non-public host|a.rs|const U: &str = "https://hidden-host.erpc.global/";' \
  'a cloud identifier|a.toml|account_id = "abcdefabcdefabcdefabcdefabcdefab"' \
  'a bare 1Password identifier|a.md|Rotate item exampleitemidbbbbbbbbbbbbb after use.' \
  'a bearer token|a.sh|curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef"' \
  'a credential assignment|a.sh|export OP_SERVICE_ACCOUNT_TOKEN=ops_abcdefghijklmnopqrstuvwxyz0123456789' \
  "a keypair array|a.json|[$(python3 -c 'print(",".join(["7"]*64))')]" \
  'a private key|a.rs|let private_key = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3b4a0d4e5c6f7a8";' \
  'a PEM block|a.pem|-----BEGIN EC PRIVATE KEY-----' \
  'an internal reference|a.md|See elsoul/internal-ops for the runbook.'; do
  sample_name="${sample%%|*}"
  sample_rest="${sample#*|}"
  sample_rel="${sample_rest%%|*}"
  sample_text="${sample_rest#*|}"
  check_staged "staged: $sample_name" block "$sample_rel" "$sample_text"
  in_scratch_repo staged_then_removed "$sample_rel" "$sample_text"
  expect_outcome "staged: $sample_name, gone from the worktree" block
  # With a NUL on the line before it. Given a NUL, GNU grep reports nothing and BSD
  # grep reports no line, so the line number is what is asserted.
  in_scratch_repo staged_with_nul "$sample_rel" "$sample_text"
  expect_reported "staged: $sample_name, in a file holding a NUL" "$sample_rel:2:"
  # And on the same line: bash's read cuts the line at a NUL, or joins what is beside it.
  in_scratch_repo staged_nul_on_line "$sample_rel" "$sample_text"
  expect_reported "staged: $sample_name, after a NUL on the line" "$sample_rel:1:"
done

for separated in 'item|exampleitemidbbbbbbbbbbbbb' 'vault|examplevaultidaaaaaaaaaaaa' 'Bearer|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef'; do
  in_scratch_repo staged_nul_separator a.md "${separated%%|*}" "${separated#*|}"
  expect_reported "staged: a NUL as the separator after ${separated%%|*}" "a.md:1:"
done

# The filter and the match each ignore case, and the labels are not always lower case.
check_staged "staged: an upper-case label is still read" block a.md 'Rotate ITEM exampleitemidbbbbbbbbbbbbb after use.'

last_line_without_newline() {
  printf 'Rotate item exampleitemidbbbbbbbbbbbbb' > a.md
  git add -A -f
  gate_staged
}
in_scratch_repo last_line_without_newline
expect_reported "staged: a last line with no newline is read" "a.md:1:"

# Each check, with the tool it runs failing: exit 2, not nothing found. The file holds
# what the check looks for, and the stub fails only on that check's own pattern.
real_grep="$(command -v grep)"
real_sed="$(command -v sed)"
stubbed_tool_run() {
  local tool="$1" real="$2" pattern="$3" content="$4"
  printf '%s\n' "$content" > a.md
  git add -A -f
  mkdir -p .git/stub
  { printf '#!/bin/sh\n'
    printf 'case "$*" in %s) exit 2;; esac\n' "$pattern"
    printf 'exec "%s" "$@"\n' "$real"
  } > ".git/stub/$tool"
  chmod +x ".git/stub/$tool"
  PATH="$PWD/.git/stub:$PATH" "$sh" "$gate" "${@:5}" 2>&1 </dev/null
}
for failing in \
  'host|*._-]+*|const U: &str = "https://hidden-host.erpc.global/";' \
  'identifier|*zone*|account_id = "abcdefabcdefabcdefabcdefabcdefab"' \
  'filter 1Password match|*vault?item*|Rotate item exampleitemidbbbbbbbbbbbbb after use.' \
  'outer 1Password match|*\(vault?item\)s*|Rotate item exampleitemidbbbbbbbbbbbbb after use.' \
  'inner 1Password match|*{26}\$\|*|Rotate item exampleitemidbbbbbbbbbbbbb after use.' \
  'bearer|*Bearer*|Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef' \
  'credential|*OP_SERVICE*|export OP_SERVICE_ACCOUNT_TOKEN=ops_abcdefghijklmnopqrstuvwxyz0123456789' \
  'keypair|*{63}*|clean' \
  'private key|*seed*|clean' \
  'PEM|*BEGIN*|-----BEGIN EC PRIVATE KEY-----' \
  'internal reference|*elsoul*|See elsoul/internal-ops for the runbook.'; do
  failing_name="${failing%%|*}"
  failing_rest="${failing#*|}"
  # The pattern holds a | only as an escaped one, which the case above reads literally.
  failing_text="${failing_rest##*|}"
  failing_pattern="${failing_rest%|*}"
  in_scratch_repo stubbed_tool_run grep "$real_grep" "$failing_pattern" "$failing_text" --staged
  expect_refusal "staged: a failing grep in the $failing_name check is refused" "could not run"
  in_scratch_repo stubbed_tool_run grep "$real_grep" "$failing_pattern" "$failing_text"
  expect_refusal "tracked: a failing grep in the $failing_name check is refused" "could not run"
done

# The file limit makes the next pipe fail for real. With no pipe, a command substitution
# runs nothing, and its empty result must not read as nothing found. $1 is the line of the
# gate to stop before; the content holds what every check looks for. Run from a copy of
# the gate, so this changes nothing but the limit.
no_pipe_from() {
  local at="$1"
  shift
  awk -v at="$at" 'index($0, at) == 1 { print "ulimit -Sn 3" } { print }' "$gate" > .git/gate-copy
  grep -q '^ulimit -Sn 3$' .git/gate-copy || { echo "no line starts with $at"; return 9; }
  printf 'Rotate item exampleitemidbbbbbbbbbbbbb after use. See elsoul/internal-ops\n' > zz.md
  git add -A -f
  "$sh" .git/gate-copy "$@" 2>&1 </dev/null
}
# Only the exit is asserted: with no file descriptor to spare, bash may not manage to
# write the message either.
for no_pipe_at in \
  '  if [ "$read_from" = worktree ]; then' \
  '  # 1. erpc.global' \
  '    run_on "$op_line" sed' \
  '    run_on "$captured" grep' \
  '      run_on "$tok" grep' \
  '  # 6. References'; do
  in_scratch_repo no_pipe_from "$no_pipe_at" --staged
  expect_refusal "staged: no pipe at [$no_pipe_at] is refused" ""
  in_scratch_repo no_pipe_from "$no_pipe_at"
  expect_refusal "tracked: no pipe at [$no_pipe_at] is refused" ""
done

in_scratch_repo stubbed_tool_run sed "$real_sed" '*op:*' 'Rotate item exampleitemidbbbbbbbbbbbbb after use.' --staged
expect_refusal "staged: a failing sed in the 1Password check is refused" "could not run"

check_staged "staged: an internal document is blocked by name" block docs/architecture.md 'Nothing to report.'
check_staged "staged: a dotenv file is blocked by name" block .env 'Nothing to report.'

check_staged "staged: a clean file passes" allow docs/a.md 'Nothing to report.'
check_staged "staged: a published host passes" allow a.rs 'const AUTH: &str = "https://auth-api.erpc.global/oauth/token";'
check_staged "staged: an empty file passes" allow a.md ''

# The gate's own skips still apply.
check_staged "staged: a skipped path is not read" allow target/a.rs "$bad_content"
check_staged "staged: a skipped extension is not read" allow a.png "$bad_content"
# A known limit, which the header states: a skipped path is not judged by name either.
check_staged "staged: a skipped path is not judged by name" allow target/.env 'clean'
check_staged "staged: a skipped directory is not judged by name" allow LICENSES/design.md 'clean'
check_staged "staged: a file quoting the patterns is not read" allow scripts/check-oss-hygiene.sh "$bad_content"

staged_with_file_names() {
  printf 'clean\n' > a.md
  git add -A -f
  "$sh" "$gate" --staged a.md 2>&1 </dev/null
}
in_scratch_repo staged_with_file_names
expect_refusal "staged: file names are refused rather than ignored" "takes no file names"

mistyped_option() {
  printf '%s\n' "$bad_content" > a.md
  git add -A -f
  "$sh" "$gate" --stagd 2>&1 </dev/null
}
in_scratch_repo mistyped_option
expect_refusal "a mistyped option is refused rather than read as a file" "unknown option"

# The file-name form, for a caller passing names it does not control.
in_scratch_repo stage_and_run --staged "$bad_content" -- --staged
expect_outcome "a file named like the option is read after --" block

in_scratch_repo stage_and_run -tmp-hygiene.md "$bad_content" -- -tmp-hygiene.md
expect_outcome "a name starting with a dash is read after --" block

in_scratch_repo stage_and_run docs/a.md "$bad_content" --
expect_outcome "a lone -- scans every tracked file" block

# The index decides, whatever the worktree says.
staged_then_cleaned() {
  printf '%s\n' "$bad_content" > a.md
  git add -A -f
  printf 'clean\n' > a.md
  gate_staged
}
in_scratch_repo staged_then_cleaned
expect_outcome "staged: content cleaned from the worktree afterwards is still read" block

in_scratch_repo staged_then_removed a.md "$bad_content"
expect_outcome "staged: content removed from the worktree afterwards is still read" block

# The checks on a name need no file: they fired only if one was in the worktree.
in_scratch_repo staged_then_removed docs/architecture.md 'clean'
expect_outcome "staged: an internal document removed from the worktree is still blocked" block

in_scratch_repo staged_then_removed .env 'clean'
expect_outcome "staged: a dotenv file removed from the worktree is still blocked" block

clean_staged_dirty_worktree() {
  printf 'clean\n' > a.md
  git add -A -f
  printf '%s\n' "$bad_content" > a.md
  gate_staged
}
in_scratch_repo clean_staged_dirty_worktree
expect_outcome "staged: content not staged is not part of the commit" allow

# A host declared only in the worktree does not vouch for a staged URL.
add_host_to_worktree_allowlist() {
  { printf 'pub const WORKTREE_HOSTS: &[&str] = &["hidden-host.erpc.global"];\n'
    cat "$1"
  } > crates/erpc-core/src/endpoints.rs
}
host_only_in_worktree() {
  printf '%s\n' "$bad_host" > a.rs
  git add -A -f
  add_host_to_worktree_allowlist "$allowlist_src"
  gate_staged
}
in_scratch_repo host_only_in_worktree
expect_outcome "staged: the allowlist is read from the index" block

host_staged_then_reverted() {
  add_host_to_worktree_allowlist "$allowlist_src"
  printf '%s\n' "$bad_host" > a.rs
  git add -A -f
  cp "$allowlist_src" crates/erpc-core/src/endpoints.rs
  gate_staged
}
in_scratch_repo host_staged_then_reverted
expect_outcome "staged: a host staged in the allowlist is honoured" allow

allowlist_deleted() {
  printf 'clean\n' > a.md
  git add -A -f
  git rm -q --cached crates/erpc-core/src/endpoints.rs
  gate_staged
}
in_scratch_repo allowlist_deleted
expect_refusal "staged: an allowlist the commit deletes is refused" "could not read the host allowlist"

# Under `set -u`, bash 3.2 reads an empty array as unbound.
nothing_staged() {
  commit_staged
  gate_staged
}
in_scratch_repo nothing_staged
expect_outcome "staged: nothing staged passes" allow

deleted_path() {
  mkdir docs
  printf '%s\n' "$bad_content" > docs/architecture.md
  commit_staged
  git rm -q docs/architecture.md
  gate_staged
}
in_scratch_repo deleted_path
expect_outcome "staged: a deleted path has nothing to judge" allow

deleted_alongside() {
  printf '%s\n' "$bad_content" > a.md
  commit_staged
  git rm -q a.md
  printf '%s\n' "$bad_content" > b.md
  git add b.md
  gate_staged
}
in_scratch_repo deleted_alongside
expect_outcome "staged: a deletion does not end the scan" block

untouched_path() {
  printf '%s\n' "$bad_content" > a.md
  commit_staged
  printf 'clean\n' > b.md
  git add b.md
  gate_staged
}
in_scratch_repo untouched_path
expect_outcome "staged: a file the commit does not change is not judged" allow

# `git commit -a` and `git commit <path>` give the hook a temporary index.
alternate_index() {
  printf 'clean\n' > a.md
  git add -A -f
  cp .git/index .git/alt-index
  printf '%s\n' "$bad_content" > a.md
  GIT_INDEX_FILE="$PWD/.git/alt-index" git add a.md
  printf 'clean\n' > a.md
  GIT_INDEX_FILE="$PWD/.git/alt-index" "$sh" "$gate" --staged 2>&1 </dev/null
}
in_scratch_repo alternate_index
expect_outcome "staged: the index git names in GIT_INDEX_FILE is the one read" block

renamed_path() {
  printf '%s\n' "$bad_content" > a.md
  commit_staged
  git mv a.md b.md
  gate_staged
}
in_scratch_repo renamed_path
expect_outcome "staged: a renamed file is read at its new name" block

# A name holding a glob matches only itself. The clean file is what the glob would
# match, and it sorts first, so the lookup would find it before the real one.
glob_name() {
  printf 'clean\n' > A.md
  printf '%s\n' "$bad_content" > '[A].md'
  git add -A -f
  gate_staged
}
in_scratch_repo glob_name
expect_outcome "staged: a name holding a glob is read as itself" block

symlink_with_bad_text() {
  ln -s 'elsoul/internal-ops' link.md
  git add -A -f
  gate_staged
}
in_scratch_repo symlink_with_bad_text
expect_outcome "staged: a symlink's link text is read" block

type_change() {
  printf 'clean\n' > a.md
  commit_staged
  rm a.md
  ln -s 'elsoul/internal-ops' a.md
  git add a.md
  gate_staged
}
in_scratch_repo type_change
expect_outcome "staged: a file changed to a symlink is read" block

symlink_clean() {
  printf 'clean\n' > a.md
  ln -s a.md link.md
  git add -A -f
  rm link.md
  printf '%s\n' "$bad_content" > link.md
  gate_staged
}
in_scratch_repo symlink_clean
expect_outcome "staged: a symlink is judged by its object, not by the worktree" allow

unresolved_conflict() {
  local blob
  blob="$(printf 'clean\n' | git hash-object -w --stdin)"
  git add -A -f
  git update-index --add --index-info <<EOF
100644 $blob 1	$1
100644 $blob 2	$1
EOF
  gate_staged
}
in_scratch_repo unresolved_conflict a.md
expect_refusal "staged: an unresolved conflict is refused" "unresolved conflict"

in_scratch_repo unresolved_conflict a.png
expect_refusal "staged: an unresolved conflict on a skipped path is refused" "unresolved conflict"

# A submodule entry holds a commit id, not text, so there is nothing to read. Its
# name is still in the commit.
submodule_entry() {
  git add -A -f
  git update-index --add --cacheinfo "160000,0123456789012345678901234567890123456789,$1"
  mkdir "$1"
  gate_staged
}
in_scratch_repo submodule_entry sub
expect_outcome "staged: a submodule entry is passed over" allow

in_scratch_repo submodule_entry .env
expect_outcome "staged: a submodule entry's name is still judged" block

# A git stub for one gate run, kept under .git so that no listing can see it. $1
# is shell run first, for the call it means to fail, and git runs for the rest.
real_git="$(command -v git)"
stage_then_stubbed_run() {
  local body="$1"
  shift
  printf 'clean\n' > a.md
  git add -A -f
  mkdir -p .git/stub
  printf '#!/bin/sh\n%s\nexec "%s" "$@"\n' "$body" "$real_git" > .git/stub/git
  chmod +x .git/stub/git
  PATH="$PWD/.git/stub:$PATH" "$sh" "$gate" "$@" 2>&1 </dev/null
}

# A listing that is cut short never reaches its finished marker.
in_scratch_repo stage_then_stubbed_run 'case "$1" in diff) printf "a.m"; exit 1;; esac' --staged
expect_refusal "staged: a listing cut partway through a name is refused" "git diff failed"

in_scratch_repo stage_then_stubbed_run 'case "$1" in diff) exit 1;; esac' --staged
expect_refusal "staged: a listing that prints nothing and fails is refused" "git diff failed"

in_scratch_repo stage_then_stubbed_run 'case "$1" in --literal-pathspecs) exit 1;; esac' --staged
expect_refusal "staged: a failed index lookup is refused" "nothing to read"

in_scratch_repo stage_then_stubbed_run 'case "$1" in --literal-pathspecs) printf "100644 0123456789012345678901234567890123456789 0\\tother.md\\000"; exit 0;; esac' --staged
expect_refusal "staged: a lookup answering for another path is refused" "nothing to read"

# Only the scan's own read fails: the allowlist goes by :0:path and the file by
# object id, and a stub failing both would stop at the allowlist check.
in_scratch_repo stage_then_stubbed_run 'case "$1:$3" in cat-file::0:*) ;; cat-file:*) printf "partial\n"; exit 1;; esac' --staged
expect_refusal "staged: a failed read of the index is refused" "could not read the content"

in_scratch_repo stage_then_stubbed_run 'case "$1" in cat-file) exit 1;; esac' --staged
expect_refusal "staged: an unreadable allowlist is refused" "could not read the host allowlist"

# Each file replaces the last in the content, or a finding would be reported again
# under every file after it. $1 adds a submodule entry or not, $2 is the option.
one_file_each() {
  printf '%s\n' "$bad_content" > a.md
  printf 'clean\n' > b.md
  git add -A -f
  case "$1" in
    submodule) git update-index --add --cacheinfo "160000,0123456789012345678901234567890123456789,b-sub"; mkdir b-sub;;
  esac
  "$sh" "$gate" ${2:+"$2"} 2>&1 </dev/null
}
expect_own_file() {
  local name="$1" other="$2"
  case "$scratch_rc:$scratch_out" in
    1:*"$other":*)
      fail=$((fail + 1)); printf 'FAIL %s (reported under %s)\n%s\n' "$name" "$other" "$scratch_out";;
    1:*a.md:1:*)
      pass=$((pass + 1)); printf 'ok   %s\n' "$name";;
    *)
      fail=$((fail + 1)); printf 'FAIL %s (exit %s, wanted exit 1 for a.md)\n%s\n' "$name" "$scratch_rc" "$scratch_out";;
  esac
}
in_scratch_repo one_file_each plain --staged
expect_own_file "staged: a finding stays with its own file" b.md

in_scratch_repo one_file_each plain
expect_own_file "tracked: a finding stays with its own file" b.md

in_scratch_repo one_file_each submodule --staged
expect_own_file "staged: a submodule entry does not inherit a finding" b-sub

in_scratch_repo one_file_each submodule
expect_own_file "tracked: a submodule entry does not inherit a finding" b-sub

# A line of content is not a glob. Expanded against this file's name, it would become
# a line holding an identifier, which the content does not.
line_is_not_a_glob() {
  printf 'item [e]xampleitemidbbbbbbbbbbbbb\n' > a.md
  git add a.md crates
  : > '1:item exampleitemidbbbbbbbbbbbbb'
  gate_staged
}
in_scratch_repo line_is_not_a_glob
expect_outcome "staged: a line of content is not expanded against file names" allow

# The name of a submodule entry is in the commit, whatever the user's diff settings.
submodule_ignored_by_config() {
  git add -A -f
  git config diff.ignoreSubmodules all
  git update-index --add --cacheinfo "160000,0123456789012345678901234567890123456789,.env"
  mkdir .env
  gate_staged
}
in_scratch_repo submodule_ignored_by_config
expect_outcome "staged: diff.ignoreSubmodules does not hide a submodule entry" block

# --- every tracked file, as CI and pre-push run it ------------------------------

gate_tracked() {
  "$sh" "$gate" 2>&1 </dev/null
}

check_tracked() {
  local name="$1" expect="$2" rel="$3" content="$4"
  in_scratch_repo stage_and_run "$rel" "$content"
  expect_outcome "$name" "$expect"
}

# Without -z, git quotes these names, and the quoted form is not a file.
for tracked_name in "docs/日本語.md" 'docs/a"b.md' 'docs/a\b.md' " lead.md" "trail.md " -tmp-hygiene.md - --staged \
  "$(printf 'tab\there.md')" "$(printf 'new\nline.md')"; do
  check_tracked "tracked: the name [$tracked_name] is read" block "$tracked_name" "$bad_content"
done

check_tracked "tracked: a clean non-ASCII file passes" allow "docs/日本語.md" 'Nothing to report.'

tracked_with_nul() {
  { printf 'x\000\n'; printf '%s\n' "$bad_content"; } > a.md
  git add -A -f
  gate_tracked
}
in_scratch_repo tracked_with_nul
expect_reported "tracked: a file holding a NUL is read" "a.md:2:"

tracked_nul_separator() {
  printf 'item\000exampleitemidbbbbbbbbbbbbb\n' > a.md
  git add -A -f
  gate_tracked
}
in_scratch_repo tracked_nul_separator
expect_reported "tracked: a NUL as the separator is read as one" "a.md:1:"

deleted_from_worktree() {
  mkdir -p "$(dirname -- "$1")"
  printf '%s\n' "$2" > "$1"
  git add -A -f
  rm "$1"
  gate_tracked
}
in_scratch_repo deleted_from_worktree a.md "$bad_content"
expect_outcome "tracked: a file deleted from the worktree is read from the index" block

in_scratch_repo deleted_from_worktree a.md 'clean'
expect_outcome "tracked: a clean file deleted from the worktree passes" allow

in_scratch_repo deleted_from_worktree docs/design.md 'clean'
expect_outcome "tracked: an internal document deleted from the worktree is blocked by name" block

tracked_symlink() {
  mkdir -p "$(dirname -- "$1")"
  ln -s "$2" "$1"
  git add -A -f
  gate_tracked
}
in_scratch_repo tracked_symlink l.md 'elsoul/internal-ops'
expect_outcome "tracked: a dangling symlink's link text is read" block

in_scratch_repo tracked_symlink docs/design.md 'nowhere'
expect_outcome "tracked: a dangling symlink is blocked by name" block

symlink_to_directory() {
  mkdir -p elsoul/internal-ops
  ln -s elsoul/internal-ops link.md
  git add link.md
  gate_tracked
}
in_scratch_repo symlink_to_directory
expect_outcome "tracked: a symlink to a directory is read as link text" block

symlink_to_file() {
  printf '%s\n' "$bad_content" > target.bin
  ln -s target.bin link.md
  git add link.md
  gate_tracked
}
in_scratch_repo symlink_to_file
expect_outcome "tracked: a symlink to a file is read through the link" block

tracked_submodule() {
  git add -A -f
  git update-index --add --cacheinfo "160000,0123456789012345678901234567890123456789,$1"
  mkdir "$1"
  gate_tracked
}
in_scratch_repo tracked_submodule sub
expect_outcome "tracked: a submodule entry is passed over" allow

in_scratch_repo tracked_submodule .env
expect_outcome "tracked: a submodule entry's name is still judged" block

tracked_conflict() {
  local blob
  blob="$(printf 'clean\n' | git hash-object -w --stdin)"
  git add -A -f
  git update-index --add --index-info <<EOF
100644 $blob 1	a.md
100644 $blob 2	a.md
EOF
  gate_tracked
}
in_scratch_repo tracked_conflict
expect_refusal "tracked: an unresolved conflict with no file is refused" "unresolved conflict"

# A listing that fails must not read as a clean tree.
corrupt_index_run() {
  git add -A -f
  printf 'not an index' > .git/index
  gate_tracked
}
in_scratch_repo corrupt_index_run
expect_refusal "tracked: a corrupt index is refused" "git ls-files failed"

in_scratch_repo stage_then_stubbed_run 'case "$1" in ls-files) printf "a.m"; exit 1;; esac'
expect_refusal "tracked: a listing cut partway through a name is refused" "git ls-files failed"

in_scratch_repo stage_then_stubbed_run 'case "$1" in ls-files) exit 1;; esac'
expect_refusal "tracked: a listing that prints nothing and fails is refused" "git ls-files failed"

# Fails only for the sample, because the allowlist is read with cat too. A stub, and
# not chmod 000, because root reads that.
unreadable_file() {
  printf 'clean\n' > a.md
  git add -A -f
  mkdir -p .git/stub
  printf '#!/bin/sh\ncase "$*" in *a.md*) exit 1;; esac\nexec "%s" "$@"\n' "$(command -v cat)" > .git/stub/cat
  chmod +x .git/stub/cat
  PATH="$PWD/.git/stub:$PATH" "$sh" "$gate" 2>&1 </dev/null
}
in_scratch_repo unreadable_file
expect_refusal "tracked: a file that cannot be read is refused" "could not read the content"

# --- paths named on the command line --------------------------------------------

named_and_missing() {
  "$sh" "$gate" -- no-such-file.md 2>&1 </dev/null
}
in_scratch_repo named_and_missing
expect_refusal "a named path that is nowhere is refused" "nothing to read"

named_directory() {
  mkdir docs
  printf '%s\n' "$bad_content" > docs/a.md
  git add -A -f
  "$sh" "$gate" -- docs 2>&1 </dev/null
}
in_scratch_repo named_directory
expect_refusal "a named directory is refused, not read as its first file" "nothing to read"

in_scratch_repo stage_and_run - "$bad_content" -- -
expect_outcome "a file named - is read after --, not standard input" block

# The real hook, where lefthook is installed. CI has none and pre-push does.
lefthook_run() {
  mkdir -p scripts
  cp "$repo_root/lefthook.yml" lefthook.yml
  cp "$gate" scripts/check-oss-hygiene.sh
  # lefthook saves unstaged changes with git stash create, which needs a commit.
  commit_staged
  case "${2:-}" in
    clean-file) printf 'clean\n' > "$1";;
    *) printf '%s\n' "$bad_content" > "$1";;
  esac
  git add -A -f
  case "${2:-}" in
    clean-worktree) printf 'clean\n' > "$1";;
  esac
  unset LEFTHOOK LEFTHOOK_EXCLUDE LEFTHOOK_QUIET
  lefthook run pre-commit --command oss-hygiene --no-auto-install --no-tty 2>&1 </dev/null
}
# The report is asserted, so that lefthook failing on its own account is not read
# as the gate blocking, and the clean run shows the command ran.
expect_lefthook() {
  local name="$1" want_rc="$2" want="$3"
  case "$scratch_rc:$scratch_out" in
    "$want_rc":*"$want"*)
      pass=$((pass + 1)); printf 'ok   %s\n' "$name";;
    *)
      fail=$((fail + 1)); printf 'FAIL %s (exit %s, wanted exit %s saying "%s")\n%s\n' "$name" "$scratch_rc" "$want_rc" "$want" "$scratch_out";;
  esac
}
if command -v lefthook >/dev/null 2>&1; then
  in_scratch_repo lefthook_run " lead.md"
  expect_lefthook "lefthook: a leading space reaches the gate" 1 "internal reference"
  in_scratch_repo lefthook_run "trail.md "
  expect_lefthook "lefthook: a trailing space reaches the gate" 1 "internal reference"
  in_scratch_repo lefthook_run "a.md" clean-worktree
  expect_lefthook "lefthook: content cleaned from the worktree is still read" 1 "internal reference"
  in_scratch_repo lefthook_run "a.md" clean-file
  expect_lefthook "lefthook: a clean file passes" 0 "oss-hygiene"
else
  printf 'skip lefthook is not installed, so the real hook was not run\n'
fi

# --- the harness itself ---------------------------------------------------------

# A hook runs this suite with these set. Left in place, they would point the
# scratch repository back at this checkout; pointed nowhere, git init fails instead.
probe_hook_env() {
  (
    export GIT_DIR=/nonexistent/git GIT_WORK_TREE=/nonexistent/tree GIT_INDEX_FILE=/nonexistent/index
    in_scratch_repo stage_and_run a.md "$bad_content" --staged
    exit "$scratch_rc"
  )
}
# Exit 1 means the file was staged and read, which needs all three cleared.
probe_hook_env
if [ "$?" -eq 1 ]; then
  pass=$((pass + 1)); printf 'ok   the harness clears the variables a hook sets\n'
else
  fail=$((fail + 1)); printf 'FAIL the harness must clear the variables a hook sets\n'
fi

# Run from a scratch directory, so that a guard disabled here runs its git there
# instead of in this checkout.
probe_scratch_guard() {
  local stub sandbox
  sandbox="$(mktemp -d)" || exit 3
  stub="$1"
  mkdir -p "$sandbox/stub"
  printf '#!/bin/sh\nexit %s\n' "$stub" > "$sandbox/stub/mktemp"
  chmod +x "$sandbox/stub/mktemp"
  probe_out="$(
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
    cd "$sandbox" || exit 9
    PATH="$sandbox/stub:$PATH"
    in_scratch_repo true
    printf 'returned %s\n' "$scratch_rc"
  )"; probe_rc=$?
  rm -rf "$sandbox"
}

probe_scratch_guard 1
if [ "$probe_rc" -eq 3 ] && [ -z "$probe_out" ]; then
  pass=$((pass + 1)); printf 'ok   a failed mktemp stops the harness\n'
else
  fail=$((fail + 1)); printf 'FAIL a failed mktemp must stop the harness (exit %s)\n%s\n' "$probe_rc" "$probe_out"
fi

probe_scratch_guard 0
if [ "$probe_out" = "returned 3" ]; then
  pass=$((pass + 1)); printf 'ok   an empty mktemp result never reaches cd\n'
else
  fail=$((fail + 1)); printf 'FAIL an empty mktemp result must not reach cd (exit %s)\n%s\n' "$probe_rc" "$probe_out"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
