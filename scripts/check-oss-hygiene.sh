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

cd "$(git rev-parse --show-toplevel)"

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files)
fi

# Binary-ish, vendored and license files are skipped.
skip_re='(\.lock$|\.png$|\.jpg$|\.gif$|\.ico$|\.woff2?$|^LICENSES/|^LICENSE$|/node_modules/|^target/)'

# Files that quote these patterns on purpose.
self_re='^(scripts/check-oss-hygiene\.sh|scripts/tests/(check-oss-hygiene|check-endpoints|build-manifest)\.test\.sh|docs/public-hosts\.md|docs/secret-exposure-response\.md|\.gitleaks\.toml|crates/erpc-core/src/endpoints\.rs)$'

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

status=0
report() {
  printf '%s:%s: %s\n' "$1" "$2" "$3" >&2
  status=1
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  [[ "$f" =~ $skip_re ]] && continue

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
