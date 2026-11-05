#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Repository hygiene gate for this public repository. Runs in pre-commit
# (lefthook, what the next commit changes) and in CI (every tracked file).
#
# It is the second net behind gitleaks. gitleaks looks for credential *values*;
# this script looks for things that are not credentials but still must not be
# published: non-public hosts, infrastructure identifiers, and internal
# documents.
#
#   scripts/check-oss-hygiene.sh [--] [files...]  # default: all tracked files
#   scripts/check-oss-hygiene.sh --staged         # what the next commit changes
#
# --staged judges what the next commit changes, not the worktree. It lists the
# paths staged against HEAD itself, reads their content from the index, and takes
# the erpc.global allowlist from the index too. The checks on a path's name need
# only the listing, so they hold whatever the worktree has there. A path the commit
# deletes has nothing to judge. A submodule entry holds a commit id and no text, so
# only its name is judged. This script is still the copy in the worktree; CI's
# no-argument scan runs the committed one.
#
# Without --staged the content is the worktree's, so a no-argument scan judges the
# commit only where the worktree matches it, as it does in CI. A path that is not a
# regular file in the worktree is read from the index: a file deleted from the
# worktree, a dangling symlink, a symlink to a directory. A symlink to a file is read
# through the link. A named path that is in neither place exits 2.
#
# A submodule entry is judged by name in every form. The paths in skip_re are not
# judged at all in any form, by name or by content, so target/.env passes. The paths in
# self_re are not read, because they quote these patterns.
#
# In every form a failed listing, lookup, read or match exits 2, and so does an
# unresolved conflict on a path read from the index.
#
# Policy: docs/public-hosts.md. Response to an accidental commit:
# docs/secret-exposure-response.md.
set -uo pipefail

# Every pattern below is matched against bytes, so the locale must not decide
# what a character class means. Under en_US.UTF-8 — which is what the GitHub
# runners set — a bash range follows collation order, so `[A-Z]` also matches
# lowercase and `[!A-Za-z0-9._-]` stops matching accented letters. Both turned
# live controls into no-ops that still passed their self-tests on a machine
# with no LANG set. The self-tests run under both locales to keep this honest.
export LC_ALL=C

cd "$(git rev-parse --show-toplevel)"

# `--` ends the options, so a caller passing file names it does not control says
# so. An unknown option is refused by name, rather than looked up as a path, so that
# a mistyped --staged says what is wrong.
staged=no
case "${1:-}" in
  --)
    shift
    ;;
  --staged)
    staged=yes
    shift
    if [ "$#" -gt 0 ]; then
      echo "--staged lists the staged paths itself and takes no file names" >&2
      exit 2
    fi
    ;;
  -*)
    echo "unknown option $1; put -- before a file name that starts with a dash" >&2
    exit 2
    ;;
esac

# NUL-separated: without -z, git quotes a non-ASCII name and the quoted form is not
# a path. A path git cannot produce marks a listing that finished. The listing runs in a
# process substitution, so no exit status reaches this shell, and a git that fails, or
# a substitution that never ran, must not read as a tree with fewer files in it.
list_files() {
  local listing_complete=no f
  files=()
  while IFS= read -r -d '' f; do
    if [ "$f" = "/__listing_complete__" ]; then listing_complete=yes; continue; fi
    files+=("$f")
  done < <(git "$@" -z && printf '/__listing_complete__\0')
  if [ "$listing_complete" = no ]; then
    echo "git $1 failed; refusing to report a clean result" >&2
    exit 2
  fi
}

if [ "$staged" = yes ]; then
  # Deleted paths are left out: the commit holds nothing there to judge. A user's
  # diff.ignoreSubmodules would leave out a submodule entry, whose name is judged.
  list_files diff --cached --name-only --diff-filter=d --ignore-submodules=none
elif [ "$#" -gt 0 ]; then
  files=("$@")
else
  list_files ls-files
fi

# Binary-ish, vendored and license files are skipped.
skip_re='(\.lock$|\.png$|\.jpg$|\.gif$|\.ico$|\.woff2?$|^LICENSES/|^LICENSE$|/node_modules/|^target/)'

# Files that quote these patterns on purpose.
# Only the files that genuinely need it: each quotes a pattern this gate
# matches. An exemption is a blanket bypass of every content check, so a
# file that passes without one does not get one.
self_re='^(scripts/check-oss-hygiene\.sh|scripts/tests/(check-oss-hygiene|check-endpoints)\.test\.sh|crates/erpc-core/src/endpoints\.rs)$'

# erpc.global hosts come from the one allowlist, so this gate and
# check-endpoints.sh cannot drift apart. Only the const arrays are read; the
# test module below them names rejected hosts on purpose.
#
# With --staged the allowlist is the one the commit will hold, so a host declared
# only in the worktree does not vouch for a staged URL. An unreadable one comes out
# empty, which the check below reports.
allowlist_src='crates/erpc-core/src/endpoints.rs'
read_allowlist() {
  if [ "$staged" = yes ]; then
    git cat-file blob ":0:$allowlist_src"
  else
    cat -- "$allowlist_src"
  fi
}
allowed_erpc_hosts=$(read_allowlist 2>/dev/null | awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' | grep -oE '"[^"]+"' | tr -d '"' | grep 'erpc\.global$' | sort -u)
allowed_erpc_prefixes=$(read_allowlist 2>/dev/null | awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' | grep -oE '\("[A-Za-z0-9.-]+"' | tr -d '("' | sort -u)
[ -n "$allowed_erpc_hosts" ] || { echo "could not read the host allowlist from $allowlist_src" >&2; exit 2; }

erpc_host_allowed() {
  local host="${1%.}" a pfx
  while IFS= read -r a; do
    [ -n "$a" ] && [ "$host" = "$a" ] && return 0
  done <<EOF
$allowed_erpc_hosts
EOF
  while IFS= read -r pfx; do
    [ -n "$pfx" ] || continue
    case "$host" in
      "$pfx"*".erpc.global")
        local mid="${host#"$pfx"}"; mid="${mid%.erpc.global}"
        case "$mid" in *.*|"") ;; *) return 0;; esac
        ;;
    esac
  done <<EOF
$allowed_erpc_prefixes
EOF
  return 1
}

# Documents that belong in the company's internal documentation, never here.
# Matched by naming convention rather than by listing private titles, so
# this public file does not enumerate what those documents are called.
internal_doc_re='(^|/)(architecture|design|[a-z0-9-]+-design|[a-z0-9-]+-assessment|[a-z0-9-]+-records|[a-z0-9-]+-acceptance|classification)\.md$'

status=0
report() {
  printf '%s:%s: %s\n' "$1" "$2" "$3" >&2
  status=1
}

# The index entry for one path: entry_mode, and entry_blob by object id, because
# the `:path` form reads a name such as 1:a.md as stage 1 of a.md. Literal
# pathspecs, so a name holding a glob matches only itself, and the name is
# compared, because a directory matches the entries under it.
tab="$(printf '\t')"
read_index_entry() {
  local entry="" meta rest
  IFS= read -r -d '' entry < <(git --literal-pathspecs ls-files -s -z -- "$1" || true)
  if [ -z "$entry" ] || [ "${entry#*"$tab"}" != "$1" ]; then
    echo "$1: nothing to read in the worktree or the index; refusing to report a clean result" >&2
    exit 2
  fi
  meta="${entry%%"$tab"*}"
  entry_mode="${meta%% *}"
  rest="${meta#* }"
  entry_blob="${rest%% *}"
  if [ "${rest#* }" != 0 ]; then
    echo "$1: the index holds an unresolved conflict; refusing to report a clean result" >&2
    exit 2
  fi
}

scan_failed() {
  echo "$f: a check could not run; refusing to report a clean result" >&2
  exit 2
}

# A command substitution whose pipe could not be made runs nothing, leaves its variable
# empty, and need not change $?. That reads as nothing found. So what runs inside prints
# its exit status and this marker last, and a capture without them did not run.
#
# finish_capture takes them off captured, along with the newline a command ended with,
# and leaves the status in capture_rc.
finish_capture() {
  local last="${captured##*$'\n'}"
  case "$last" in
    *:finished) ;;
    *) return 1;;
  esac
  capture_rc="${last%:finished}"
  captured="${captured%$'\n'*}"
  # Not ${captured%$'\n'}, which is quadratic on long text that does not end in a newline.
  case "$captured" in *$'\n') captured="${captured%?}";; esac
}

# Reads the content a file holds into content. Every NUL becomes a space. A NUL makes
# grep call the content binary and drop its lines, and bash would drop it from the
# variable, joining what was beside it.
read_content() {
  captured=$("$@" | tr '\000' ' '; printf '\n%s:finished' "$?")
  if ! finish_capture || [ "$capture_rc" -ne 0 ]; then
    echo "$f: could not read the content; refusing to report a clean result" >&2
    exit 2
  fi
  content="$captured"
}

# Runs a command on $1 and leaves what it prints in captured. The marker gives the
# command's status and the substitution's own gives the writer's. A command fed by a
# writer that died saw part of the text, so its finding nothing means nothing.
run_on() {
  local text="$1"
  shift
  captured=$(printf '%s\n' "$text" | { "$@"; printf '\n%s:finished' "$?"; }) || scan_failed
  finish_capture && [ "$capture_rc" -le 1 ] || scan_failed
}

# The lines grep finds in the content go to match_lines. grep exits 1 when it finds
# nothing and above that when it could not look, which must not read the same way. They
# are held in memory and not in a file, because a loop reading a file it cannot open
# ends as if the file were empty. Every line grep prints here holds a line number, so
# splitting on newlines loses none. `set -f` so that a `*` in one is not expanded.
matches() {
  local IFS=$'\n'
  run_on "$content" grep "$@"
  set -f
  match_lines=($captured)
  set +f
}

# --staged has an empty list when a commit only deletes, and bash 3.2 reads an
# empty "${files[@]}" as unbound under `set -u`.
for f in ${files[@]+"${files[@]}"}; do
  # Read the object rather than the file for --staged, whatever the worktree holds
  # there, and for anything that is not a regular file. The lookup comes first, so
  # that a conflict on a path no check reads still stops the run.
  read_from=worktree
  if [ "$staged" = yes ] || [ ! -f "$f" ]; then
    read_index_entry "$f"
    read_from=index
  fi
  [[ "$f" =~ $skip_re ]] && continue

  # 0. Internal documents, matched on the path alone.
  if [[ "$f" =~ $internal_doc_re ]]; then
    report "$f" 1 "internal document: the canonical design and compliance records stay in the company's private documentation; see CONTRIBUTING.md"
  fi

  [[ "$f" =~ $self_re ]] && continue

  # The content the checks below read. A symlink's object is its link text. A name
  # starting with a dash would otherwise be an option to cat, and `-` standard input.
  if [ "$read_from" = worktree ]; then
    case "$f" in -*) read_path="./$f";; *) read_path="$f";; esac
    read_content cat -- "$read_path"
  elif [ "$entry_mode" = 160000 ]; then
    content=""
  else
    read_content git cat-file blob "$entry_blob"
  fi

  # 1. erpc.global hosts outside the published allowlist.
  matches -noiE '[A-Za-z0-9._-]+\.erpc\.global'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    if ! erpc_host_allowed "$match"; then
      report "$f" "$ln" "non-public erpc.global host: $match"
    fi
  done

  # 2. Cloud account / zone / project identifiers.
  matches -noiE '(account|zone|project)[_ -]?id[^0-9a-z]{0,8}[0-9a-f]{32}'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "infrastructure identifier: $match"
  done

  # 2b. Bare 1Password vault or item identifiers.
  #
  # An `op://vault/item/field` reference is a pointer and is allowed, and our
  # convention puts the 26-character ids inside it — so the reference is
  # removed from the line first, which is what makes the exemption real
  # rather than a guard that can never fire. What is left is matched beside
  # the words vault or item, including the plural and the dashboard URL form
  # (.../vaults/<id>/items/<id>). The id itself must be lowercase: real ones
  # are, and matching case-insensitively flagged uppercase base32 in prose.
  matches -nEi 'vault|item'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    op_ln="${line%%:*}"
    op_line="${line#*:}"
    run_on "$op_line" sed 's|op://[A-Za-z0-9._/-]*||g'
    [ "$capture_rc" -eq 0 ] || scan_failed
    run_on "$captured" grep -oiE '(vault|item)s?([^A-Za-z0-9]{1,8}(id|identifier))?[^A-Za-z0-9]{1,8}[A-Za-z0-9]{26}([^A-Za-z0-9]|$)'
    tokens="$captured"
    # `set -f` because the loop word-splits the match on purpose but must
    # not also glob it against the repository root: a `*` or `?` inside the
    # matched separator would otherwise expand to filenames.
    set -f
    for tok in $tokens; do
      run_on "$tok" grep -oE '[A-Za-z0-9]{26}$|[A-Za-z0-9]{26}'
      id="${captured##*$'\n'}"
      [ -n "$id" ] || continue
      # `[[:upper:]]` and not `[A-Z]`: under a non-C locale the range
      # follows collation order and matches lowercase too. LC_ALL=C above
      # already settles this; the class is correct on its own as well.
      case "$id" in *[[:upper:]]*) continue;; esac
      report "$f" "$op_ln" "bare 1Password identifier: $id"
    done
    set +f
  done

  # 3. Bearer token literals.
  matches -noE 'Bearer [A-Za-z0-9._~+/-]{32,}'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "bearer token literal: ${match:0:24}..."
  done

  # 4. Credential assignments with a literal value.
  matches -noE '(OP_SERVICE_ACCOUNT_TOKEN|OP_CONNECT_TOKEN|CLOUDFLARE_API_TOKEN|CARGO_REGISTRY_TOKEN|MINISIGN_SECRET_KEY|AWS_SECRET_ACCESS_KEY|R2_SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{16,}'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "credential assignment: ${match:0:40}..."
  done

  # 5. Blockchain key material (second net behind gitleaks).
  matches -noE '\[([[:space:]]*[0-9]{1,3}[[:space:]]*,){63}[[:space:]]*[0-9]{1,3}[[:space:]]*\]'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "looks like a Solana keypair array: ${match:0:32}..."
  done

  matches -noiE '(priv(ate)?[_-]?key|secret[_-]?key|signing[_-]?key|mnemonic|seed[_-]?phrase)["'"'"'[:space:]]{0,10}[:=][[:space:]]*["'"'"']?(0x)?[0-9a-fA-F]{64}'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "looks like a private key: ${match:0:40}..."
  done

  matches -noE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    report "$f" "$ln" "PEM private key block"
  done

  # 6. References into the company's private repositories and documents.
  # Any sibling repository in the organisation, the internal documentation
  # convention, or a developer home path. Phrased so that this public file does
  # not itself name a private repository.
  matches -noE '(elsoul/[A-Za-z0-9_.-]+|\.claude/docs/|/Users/[A-Za-z0-9_.-]+/)'
  for line in ${match_lines[@]+"${match_lines[@]}"}; do
    ln="${line%%:*}"
    match="${line#*:}"
    # This project's own org paths. Named exactly: a trailing wildcard would
    # admit any private sibling whose name starts with the same prefix.
    case "$match" in
      */erpc-cli|*/erpc-cli-maintainers) continue;;
    esac
    report "$f" "$ln" "internal reference: $match"
  done

  # 7. Committed .env files.
  case "$f" in
    .env|.env.*|*/.env|*/.env.*) report "$f" 1 ".env files must not be committed";;
  esac
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'

check-oss-hygiene: FAILED

This repository is public. Fix the findings above before committing.
  - allowed hosts and identifiers: docs/public-hosts.md
  - if a secret was already committed: docs/secret-exposure-response.md
To bypass for a genuine false positive, adjust the pattern in this script in
the same commit and say why in the commit message. Never use `--no-verify`.
MSG
fi
exit "$status"
