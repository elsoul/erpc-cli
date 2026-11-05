#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Repository hygiene gate for this public repository. Runs in pre-commit
# (lefthook, staged files only) and in CI (every tracked file).
#
# It is the second net behind gitleaks. gitleaks looks for credential *values*;
# this script looks for things that are not credentials but still must not be
# published: non-public hosts, infrastructure identifiers, and internal
# documents.
#
#   scripts/check-oss-hygiene.sh [files...]    # default: all tracked files
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

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  # NUL-separated: without -z, git quotes a non-ASCII name and the quoted form
  # is not a path, so that file would be skipped without a word.
  while IFS= read -r -d '' f; do files+=("$f"); done < <(git ls-files -z)
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
allowlist_src='crates/erpc-core/src/endpoints.rs'
allowed_erpc_hosts=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' "$allowlist_src" 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' | grep 'erpc\.global$' | sort -u)
allowed_erpc_prefixes=$(awk '
  /^#\[cfg\(test\)\]/ { exit }
  /^pub const [A-Z_]+: &\[/ { inside = 1 }
  inside { print }
  inside && /\];/ { inside = 0 }
' "$allowlist_src" 2>/dev/null | grep -oE '\("[A-Za-z0-9.-]+"' | tr -d '("' | sort -u)
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

# Collapses `.`, `..` and empty path segments. A string rather than an array:
# an empty array under `set -u` is an error on the bash 3.2 this gate runs on.
normalize_path() {
  local rest="$1/" out="" seg
  while [ -n "$rest" ]; do
    seg="${rest%%/*}"
    rest="${rest#*/}"
    case "$seg" in
      ""|.) ;;
      ..)
        case "$out" in
          ""|..|*/..) out="${out:+$out/}..";;
          */*) out="${out%/*}";;
          *) out="";;
        esac;;
      *) out="${out:+$out/}$seg";;
    esac
  done
  printf '%s\n' "$out"
}

# Drops what surrounds a path in prose: emphasis at either end, and whatever ends
# a sentence after the directory name.
trim_token_edges() {
  local path="$1" base
  while :; do
    case "$path" in
      [_-]*) path="${path#?}";;
      *) break;;
    esac
  done
  base="$path"
  while :; do
    case "$base" in
      *[._-]) base="${base%?}";;
      *) break;;
    esac
  done
  case "$base" in
    *plans) printf '%s\n' "$base";;
    *) printf '%s\n' "$path";;
  esac
}

# True if $1 names docs/plans anywhere in it, or resolves there from directory $2.
path_names_plans_dir() {
  local path
  path="$(trim_token_edges "$1")"
  case "$path" in */*) ;; *) return 1;; esac
  case "/$(normalize_path "$path")/" in */docs/plans/*) return 0;; esac
  case "$path" in /*) return 1;; esac
  case "/$(normalize_path "$2/$path")/" in /docs/plans/*) return 0;; esac
  return 1
}

# True if URL $1 is this repository's and reaches docs/plans. Folded to lowercase
# because the host treats the owner and repository names that way.
url_names_plans_dir() {
  local url
  url="$(printf '%s' "${1#*://}" | tr '[:upper:]' '[:lower:]')"
  # A colon ends a segment here too, as in `.../docs/plans:12`.
  url="$(trim_token_edges "${url//://}")"
  case "/$(normalize_path "$url")/" in
    */elsoul/erpc-cli/docs/plans/*|*/elsoul/erpc-cli/*/docs/plans/*) return 0;;
  esac
  return 1
}

status=0
report() {
  printf '%s:%s: %s\n' "$1" "$2" "$3" >&2
  status=1
}

for f in "${files[@]}"; do
  # On the path alone and first, so that no file type, symlink or skip rule
  # gets past it.
  case "$f" in
    docs/plans|docs/plans/*|./docs/plans|./docs/plans/*)
      report "$f" 1 "docs/plans is not part of this repository";;
  esac

  [ -f "$f" ] || continue
  [[ "$f" =~ $skip_re ]] && continue

  # A name starting with `-` would reach grep below as an option.
  case "$f" in -*) f="./$f";; esac

  # 0. Internal documents, matched on the path alone.
  if [[ "$f" =~ $internal_doc_re ]]; then
    report "$f" 1 "internal document: the canonical design and compliance records stay in the company's private documentation; see CONTRIBUTING.md"
  fi

  [[ "$f" =~ $self_re ]] && continue

  # 1. erpc.global hosts outside the published allowlist.
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    if ! erpc_host_allowed "$match"; then
      report "$f" "$ln" "non-public erpc.global host: $match"
    fi
  done < <(grep -noiE '[A-Za-z0-9._-]+\.erpc\.global' "$f" 2>/dev/null)

  # 2. Cloud account / zone / project identifiers.
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "infrastructure identifier: $match"
  done < <(grep -noiE '(account|zone|project)[_ -]?id[^0-9a-z]{0,8}[0-9a-f]{32}' "$f" 2>/dev/null)

  # 2b. Bare 1Password vault or item identifiers.
  #
  # An `op://vault/item/field` reference is a pointer and is allowed, and our
  # convention puts the 26-character ids inside it — so the reference is
  # removed from the line first, which is what makes the exemption real
  # rather than a guard that can never fire. What is left is matched beside
  # the words vault or item, including the plural and the dashboard URL form
  # (.../vaults/<id>/items/<id>). The id itself must be lowercase: real ones
  # are, and matching case-insensitively flagged uppercase base32 in prose.
  op_ln=0
  while IFS= read -r op_line; do
    op_ln=$((op_ln + 1))
    case "$op_line" in *[Vv][Aa][Uu][Ll][Tt]*|*[Ii][Tt][Ee][Mm]*) ;; *) continue;; esac
    stripped=$(printf '%s' "$op_line" | sed 's|op://[A-Za-z0-9._/-]*||g')
    # `set -f` because the loop word-splits the match on purpose but must
    # not also glob it against the repository root: a `*` or `?` inside the
    # matched separator would otherwise expand to filenames.
    set -f
    for tok in $(printf '%s' "$stripped" | grep -oiE '(vault|item)s?([^A-Za-z0-9]{1,8}(id|identifier))?[^A-Za-z0-9]{1,8}[A-Za-z0-9]{26}([^A-Za-z0-9]|$)' 2>/dev/null); do
      id=$(printf '%s' "$tok" | grep -oE '[A-Za-z0-9]{26}$|[A-Za-z0-9]{26}' | tail -1)
      [ -n "$id" ] || continue
      # `[[:upper:]]` and not `[A-Z]`: under a non-C locale the range
      # follows collation order and matches lowercase too. LC_ALL=C above
      # already settles this; the class is correct on its own as well.
      case "$id" in *[[:upper:]]*) continue;; esac
      report "$f" "$op_ln" "bare 1Password identifier: $id"
    done
    set +f
  done < <(grep -a '' "$f" 2>/dev/null)

  # 3. Bearer token literals.
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "bearer token literal: ${match:0:24}..."
  done < <(grep -noE 'Bearer [A-Za-z0-9._~+/-]{32,}' "$f" 2>/dev/null)

  # 4. Credential assignments with a literal value.
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "credential assignment: ${match:0:40}..."
  done < <(grep -noE '(OP_SERVICE_ACCOUNT_TOKEN|OP_CONNECT_TOKEN|CLOUDFLARE_API_TOKEN|CARGO_REGISTRY_TOKEN|MINISIGN_SECRET_KEY|AWS_SECRET_ACCESS_KEY|R2_SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{16,}' "$f" 2>/dev/null)

  # 5. Blockchain key material (second net behind gitleaks).
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "looks like a Solana keypair array: ${match:0:32}..."
  done < <(grep -noE '\[([[:space:]]*[0-9]{1,3}[[:space:]]*,){63}[[:space:]]*[0-9]{1,3}[[:space:]]*\]' "$f" 2>/dev/null)

  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "looks like a private key: ${match:0:40}..."
  done < <(grep -noiE '(priv(ate)?[_-]?key|secret[_-]?key|signing[_-]?key|mnemonic|seed[_-]?phrase)["'"'"'[:space:]]{0,10}[:=][[:space:]]*["'"'"']?(0x)?[0-9a-fA-F]{64}' "$f" 2>/dev/null)

  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "PEM private key block"
  done < <(grep -noE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$f" 2>/dev/null)

  # 6. References into the company's private repositories and documents.
  # Any sibling repository in the organisation, the internal documentation
  # convention, or a developer home path. Phrased so that this public file does
  # not itself name a private repository.
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    # This project's own org paths. Named exactly: a trailing wildcard would
    # admit any private sibling whose name starts with the same prefix.
    case "$match" in
      */erpc-cli|*/erpc-cli-maintainers) continue;;
    esac
    report "$f" "$ln" "internal reference: $match"
  done < <(grep -noE '(elsoul/[A-Za-z0-9_.-]+|\.claude/docs/|/Users/[A-Za-z0-9_.-]+/)' "$f" 2>/dev/null)

  # 6b. Paths into docs/plans. This repository has no such directory, so a link
  # there dangles. A net against accidents, not against someone working around
  # it. A token is a run of letters, digits and `_ . : / % -` containing `plans`,
  # which covers Markdown and HTML links and paths in prose or code. Its parts
  # between colons are read as paths, after trimming `_` and `-` from the ends,
  # and a host name with no scheme reads as a path too. A token holding `://` is
  # read as one URL, which counts only if it is this repository's. Not read: a
  # target that is the bare word `plans`, which cannot be told from prose;
  # percent-encoding, backslashes and other capitalisations of a local path;
  # symlink targets; any file grep treats as binary; and the contents of a file
  # skip_re passes over, though a file under docs/plans is refused by name above.
  while IFS=: read -r ln tok; do
    [ -z "$ln" ] && continue
    case "$tok" in *[Ff][Ii][Ll][Ee]://*) tok="${tok#*://}";; esac
    case "$tok" in
      *://*)
        if url_names_plans_dir "$tok"; then
          report "$f" "$ln" "path into docs/plans, which this repository does not contain: $tok"
        fi
        continue;;
    esac
    # Split on colons: `[R1]:../plans/x.md` and `docs/plans/x.md:42` both carry
    # the path beside something else.
    rest="$tok:"
    while [ -n "$rest" ]; do
      part="${rest%%:*}"
      rest="${rest#*:}"
      if path_names_plans_dir "$part" "$(dirname "$f")"; then
        report "$f" "$ln" "path into docs/plans, which this repository does not contain: $tok"
        break
      fi
    done
  done < <(grep -noE '[A-Za-z0-9_.:/%-]*plans[A-Za-z0-9_.:/%-]*' "$f" 2>/dev/null)

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
