#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Fails when tracked files reference hosts, identifiers or credential shapes
# that must not appear in this public repository. See docs/public-hosts.md.
#
# Usage: scripts/check-public-hosts.sh [files...]   (defaults to all tracked files)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files)
fi

# Binary-ish and license files are skipped.
skip_re='(\.lock$|\.png$|\.jpg$|\.gif$|\.ico$|\.woff2?$|^LICENSES/|^LICENSE$)'

allowed_hosts='(auth-api|user-api|mcp-user-api|x402|dashboard|edge|dl|install|solana-snapshot-[a-z]+)\.erpc\.global'

status=0

report() {
  printf '%s:%s: %s\n' "$1" "$2" "$3" >&2
  status=1
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  [[ "$f" =~ $skip_re ]] && continue
  # This script and the allowlist doc name the patterns on purpose.
  case "$f" in
    scripts/check-public-hosts.sh|docs/public-hosts.md|.gitleaks.toml) continue;;
  esac

  # 1. erpc.global hosts outside the allowlist
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    if ! [[ "$match" =~ $allowed_hosts ]]; then
      report "$f" "$ln" "non-public erpc.global host: $match"
    fi
  done < <(grep -noE '[A-Za-z0-9._-]+\.erpc\.global' "$f" || true)

  # 2. Cloudflare account/zone identifiers (32 hex) next to the word account/zone
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "possible Cloudflare account/zone identifier: $match"
  done < <(grep -noiE '(account|zone)[_ -]?id[^0-9a-f]{0,8}[0-9a-f]{32}' "$f" || true)

  # 3. Bearer tokens (long opaque strings after Bearer)
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "bearer token literal: ${match:0:24}..."
  done < <(grep -noE 'Bearer [A-Za-z0-9._~+/-]{32,}' "$f" || true)

  # 4. Credential assignments
  while IFS=: read -r ln match; do
    [ -z "$ln" ] && continue
    report "$f" "$ln" "credential assignment: ${match:0:40}..."
  done < <(grep -noE '(OP_SERVICE_ACCOUNT_TOKEN|OP_CONNECT_TOKEN|CLOUDFLARE_API_TOKEN|CARGO_REGISTRY_TOKEN|MINISIGN_SECRET_KEY)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{16,}' "$f" || true)

  # 5. Committed .env files
  case "$f" in
    .env|.env.*|*/.env|*/.env.*) report "$f" 1 ".env files must not be committed";;
  esac
done

if [ "$status" -ne 0 ]; then
  echo "check-public-hosts: FAILED (see docs/public-hosts.md)" >&2
fi
exit "$status"
