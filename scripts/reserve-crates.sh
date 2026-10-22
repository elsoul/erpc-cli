#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# One-time crates.io name reservation (Phase 0, step 0.7).
#
# Publishes every workspace crate at its current 0.0.1 version so the names are
# owned by the organisation before Trusted Publishing is configured. Run this
# ONCE from a maintainer machine with a short-lived crates.io API token held
# only in the environment; revoke the token immediately afterwards and record
# the revocation in the private ledger.
#
#   CARGO_REGISTRY_TOKEN=... scripts/reserve-crates.sh --dry-run
#   CARGO_REGISTRY_TOKEN=... scripts/reserve-crates.sh
#
# Afterwards, for EVERY crate on crates.io:
#   Settings -> Trusted Publishing -> GitHub: owner elsoul, repo erpc-cli,
#   workflow release.yml, environment release  ->  then enable
#   "Trusted Publishing Only" so API tokens can no longer publish.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

dry_run=""
if [ "${1:-}" = "--dry-run" ]; then dry_run="--dry-run"; fi

if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] && [ -z "$dry_run" ]; then
  echo "CARGO_REGISTRY_TOKEN is required (short-lived token, revoke after use)" >&2
  exit 2
fi

# Publish order follows dependencies: leaves first, the binary last.
crates=(
  erpc-core
  erpc-chain
  erpc-secret
  erpc-ssh
  erpc-api
  erpc-auth
  erpc-ops
  erpc-chain-solana
  erpc-wallet
  erpc-x402
  erpc-ai
  erpc-skills
  erpc-mcp-server
  erpc-release
  erpc
)

for c in "${crates[@]}"; do
  echo "== $c"
  cargo publish -p "$c" --locked $dry_run
  # crates.io needs a moment to index a new crate before dependents resolve it.
  [ -n "$dry_run" ] || sleep 20
done

echo
echo "Done. Now: revoke CARGO_REGISTRY_TOKEN on crates.io, record the revocation,"
echo "and configure Trusted Publishing + 'Trusted Publishing Only' for all ${#crates[@]} crates."
