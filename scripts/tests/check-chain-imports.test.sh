#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/check-chain-imports.sh. Each case builds a small
# chains/ tree in a scratch repository, runs the gate on it, and checks
# both the exit status and why the gate gave it.
set -uo pipefail

# Run the gate and this harness's re-exec under the bash that started it,
# so the bash 3.2 CI job tests the gate under bash 3.2 too.
sh="${BASH:-/bin/bash}"

# A gate must behave the same in any locale, so the suite runs once in C
# and once in a dictionary-collation UTF-8 locale.
if [ -z "${ERPC_TEST_LOCALE:-}" ]; then
  utf8=""
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

source_root="$(git rev-parse --show-toplevel)" || exit 1
repo_root="$(mktemp -d)" || exit 1
trap 'rm -rf "$repo_root"' EXIT
mkdir -p "$repo_root/scripts" || exit 1
cp "$source_root/scripts/check-chain-imports.sh" "$repo_root/scripts/" || exit 1
# Do not let a caller's Git environment point the gate at another repository.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
git init -q "$repo_root" || exit 1
cd "$repo_root" || exit 1
gate="$repo_root/scripts/check-chain-imports.sh"
chains="crates/erpc/src/chains"

# The tree every case starts from: three chains, the one allowed import,
# and references the gate must leave alone.
base() {
  rm -rf "$repo_root/crates"
  mkdir -p "$chains/eth" "$chains/arc" "$chains/nitro/rpc" "$chains/robinhood"
  printf '%s\n' 'pub(crate) mod eth;' 'pub(crate) mod arc;' > "$chains/mod.rs"
  printf '%s\n' 'use crate::chains::eth::rpc::Facts;' 'use crate::node::host::Login;' \
    > "$chains/eth/deploy.rs"
  printf '%s\n' 'use crate::{' '    chains::arc::rpc,' '    node::common::Say,' '};' \
    > "$chains/arc/init.rs"
  printf '%s\n' 'pub(crate) fn admission_session() {}' > "$chains/nitro/rpc/mod.rs"
  printf '%s\n' '    crate::chains::nitro::rpc::admission_session(qualified, args)?;' \
    > "$chains/robinhood/admission.rs"
}

pass=0
fail=0
# check NAME allow|block FILE CONTENT [REPORT]: writes FILE on top of the
# base tree (or removes it when CONTENT is "-"), runs the gate, and checks
# the outcome. A blocking case also names the report it must give, since an
# exit status alone cannot say which rule fired.
check() {
  local name="$1" expect="$2" rel="$3" content="$4" want="${5:-}"
  base
  if [ "$content" = "-" ]; then
    rm -f "$rel"
  else
    mkdir -p "$(dirname "$rel")"
    printf '%b\n' "$content" > "$rel"
  fi
  local out rc
  out="$("$sh" "$gate" 2>&1)"; rc=$?
  if [ "$expect" = allow ] && [ "$rc" -eq 0 ]; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  elif [ "$expect" = block ] && [ "$rc" -ne 0 ] && case "$out" in *"$want"*) true;; *) false;; esac; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1))
    printf 'FAIL %s (expected %s, exit %s, wanted "%s")\n%s\n' "$name" "$expect" "$rc" "$want" "$out"
  fi
}

check "the base tree passes" allow "$chains/eth/extra.rs" '// nothing'
check "a chain may name its own modules" allow "$chains/eth/ops.rs" \
  'use crate::chains::eth::rpc::{Facts, facts};'
check "names that only end in chains are not chain paths" allow "$chains/eth/ops.rs" \
  'let y = erpc_chains::arc::x;'

check "a full path to another chain is refused" block "$chains/eth/ops.rs" \
  'let f = crate::chains::arc::rpc::facts(session)?;' \
  "$chains/eth/ops.rs:1: chains/eth names chains::arc::rpc::facts"
check "another chain inside a use crate group is refused" block "$chains/eth/init.rs" \
  'use crate::{\n    chains::arc::rpc::gb,\n    node::host::Login,\n};' \
  "$chains/eth/init.rs:2: chains/eth names chains::arc::rpc::gb"
check "a bare module import of another chain is refused" block "$chains/arc/ops.rs" \
  'use crate::chains::eth;' \
  "chains/arc names chains::eth"
check "a comment naming another chain is refused" block "$chains/arc/ops.rs" \
  '// see crate::chains::eth::rpc::Facts' \
  "chains/arc names chains::eth::rpc::Facts"
check "a chains brace import is refused" block "$chains/eth/ops.rs" \
  'use crate::chains::{arc, eth};' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a nested module is read too" block "$chains/nitro/rpc/deep.rs" \
  'use crate::chains::eth::rpc::Login;' \
  "chains/nitro names chains::eth::rpc::Login"

check "a chains glob import is refused" block "$chains/eth/ops.rs" \
  'use crate::chains::*;\nfn f() { arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a capitalised name after chains is refused" block "$chains/eth/ops.rs" \
  'use crate::chains::ArcFacts;' \
  "chains/eth names chains::ArcFacts"
check "an alias of the chains module is refused" block "$chains/eth/ops.rs" \
  'use crate::chains as c;\nfn f() { c::arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "an alias inside a use crate group is refused" block "$chains/eth/ops.rs" \
  'use crate::{\n    chains as c,\n    node::host::Login,\n};' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "space after :: is refused" block "$chains/eth/ops.rs" \
  'let f = crate::chains:: arc::rpc::facts;' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "space before :: is refused" block "$chains/eth/ops.rs" \
  'use crate::chains ::arc::rpc;' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "space before :: under rustfmt::skip is refused" block "$chains/eth/ops.rs" \
  '#[rustfmt::skip] fn g() { crate::chains ::arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a comment between chains and :: is refused" block "$chains/eth/ops.rs" \
  '#[rustfmt::skip] fn g() { crate::chains/**/::arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a path split after crate::chains is refused" block "$chains/eth/ops.rs" \
  'use crate::chains\n    ::arc::rpc;' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a path split after a trailing comment is refused" block "$chains/eth/ops.rs" \
  '#[rustfmt::skip] fn g() { crate::chains // x\n    ::arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a path split inside a use crate group is refused" block "$chains/eth/ops.rs" \
  'use crate::{node, chains\n    ::arc};' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "space before chains on a split path is refused" block "$chains/eth/ops.rs" \
  '#[rustfmt::skip] fn g() { crate :: chains\n    ::arc::rpc::facts(); }' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a lone chains in a group is refused" block "$chains/eth/ops.rs" \
  'use crate::{\n    chains\n        ::arc::rpc,\n};' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "an alias split across lines is refused" block "$chains/eth/ops.rs" \
  'use crate::chains as\n    c;' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "prose using the word chains is refused" block "$chains/eth/ops.rs" \
  '// the same holds for the other supported chains' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "a string literal using the word chains is refused" block "$chains/eth/ops.rs" \
  'const NOTE: &str = "all chains";' \
  "chains/eth uses the word chains other than as a path into its own chain"
check "look-alike words beside a real path are not the word" allow "$chains/eth/ops.rs" \
  'let x = crate::chains::eth::rpc::f(my_chains::arc::y, chainset::arc::z);'
check "words that only contain chains are not the word" allow "$chains/eth/ops.rs" \
  'let chains_as = 1;\nlet chainset = 2;\nlet x = my_chains::arc::rpc();'

check "the exception allows its path and what is under it" allow "$chains/robinhood/validator.rs" \
  'crate::chains::nitro::rpc::admission_session::inner();'
check "the exception does not allow another nitro path" block "$chains/robinhood/validator.rs" \
  'crate::chains::nitro::rpc::find(store, args)?;' \
  "chains/robinhood names chains::nitro::rpc::find"
check "the exception does not allow a longer name" block "$chains/robinhood/validator.rs" \
  'crate::chains::nitro::rpc::admission_session_raw();' \
  "chains/robinhood names chains::nitro::rpc::admission_session_raw"
check "the exception is for its importer only" block "$chains/eth/ops.rs" \
  'crate::chains::nitro::rpc::admission_session(qualified, args)?;' \
  "chains/eth names chains::nitro::rpc::admission_session"
check "the exception runs one way only" block "$chains/nitro/rpc/back.rs" \
  'use crate::chains::robinhood::admission;' \
  "chains/nitro names chains::robinhood::admission"
check "an exception that matches nothing fails" block "$chains/robinhood/admission.rs" - \
  "the exception for robinhood -> nitro::rpc::admission_session no longer matches anything"

# check_after NAME REPORT SETUP: runs SETUP (shell commands) on the base
# tree, then expects the gate to block with REPORT. For trees that check's
# single file cannot describe.
check_after() {
  local name="$1" want="$2" setup="$3"
  base
  eval "$setup"
  local out rc
  out="$("$sh" "$gate" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && case "$out" in *"$want"*) true;; *) false;; esac; then
    pass=$((pass + 1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail + 1))
    printf 'FAIL %s (expected block, exit %s, wanted "%s")\n%s\n' "$name" "$rc" "$want" "$out"
  fi
}

check "a NUL byte does not hide a file" block "$chains/eth/ops.rs" \
  '// \0\nuse crate::chains::arc::rpc;' \
  "chains/eth names chains::arc::rpc"
check "a NUL byte on a later line does not hide a file" block "$chains/eth/ops.rs" \
  'use crate::chains::arc::rpc;\nconst N: &str = "a\0b";' \
  "chains/eth names chains::arc::rpc"
# shellcheck disable=SC2016 # check_after evals the setup, so it expands there
check_after "a symlinked file is refused" "$chains/eth/link.rs is a symlink" \
  'printf "%s\n" "use crate::chains::arc::x;" > "$chains/arc/real.rs"; ln -s ../arc/real.rs "$chains/eth/link.rs"'
# shellcheck disable=SC2016 # check_after evals the setup, so it expands there
check_after "a symlinked directory is refused" "$chains/eth/sub is a symlink" \
  'mkdir -p "$repo_root/outside"; printf "%s\n" "use crate::chains::arc::x;" > "$repo_root/outside/x.rs"; ln -s "$repo_root/outside" "$chains/eth/sub"'
# shellcheck disable=SC2016 # check_after evals the setup, so it expands there
check_after "a chain root written as chains/<chain>.rs is refused" \
  "$chains/eth.rs is a .rs file directly in chains/" \
  'printf "%s\n" "use crate::chains::arc::x;" > "$chains/eth.rs"'

# An exception without a dated reason is refused. The scratch copy of the
# gate is edited for this case and put back after it.
cp "$gate" "$gate.orig"
sed 's/|2026-11-25: Robinhood/|Robinhood/' "$gate.orig" > "$gate"
check "an exception without a dated reason is refused" block "$chains/eth/extra.rs" '// nothing' \
  "the exception for robinhood -> nitro::rpc::admission_session needs a reason starting with its date"
mv "$gate.orig" "$gate"

# A file the gate cannot read fails it. Root reads any file whatever its
# mode, so the case is only meaningful, and only run, as another user.
if [ "$(id -u)" -ne 0 ]; then
  base
  printf '%s\n' '// unreadable' > "$chains/eth/locked.rs"
  chmod 000 "$chains/eth/locked.rs"
  out="$("$sh" "$gate" 2>&1)"; rc=$?
  chmod 644 "$chains/eth/locked.rs"
  case "$out" in
    *"could not read $chains/eth/"*)
      if [ "$rc" -ne 0 ]; then
        pass=$((pass + 1)); printf 'ok   %s\n' "a file the gate cannot read fails it"
      else
        fail=$((fail + 1)); printf 'FAIL %s (exit 0)\n%s\n' "a file the gate cannot read fails it" "$out"
      fi;;
    *) fail=$((fail + 1)); printf 'FAIL %s (exit %s)\n%s\n' "a file the gate cannot read fails it" "$rc" "$out";;
  esac
else
  printf 'skip %s (running as root)\n' "a file the gate cannot read fails it"
fi

# The live tree must pass as it stands.
out="$(cd "$source_root" && "$sh" scripts/check-chain-imports.sh 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then
  pass=$((pass + 1)); printf 'ok   %s\n' "the repository passes"
else
  fail=$((fail + 1)); printf 'FAIL %s (exit %s)\n%s\n' "the repository passes" "$rc" "$out"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
