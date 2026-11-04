#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# crates.io name reservation for workspace crates that are not on crates.io
# yet.
#
# Trusted Publishing can publish a new VERSION of a crate; it cannot create
# the crate. So the first version of every crate is published once from a
# maintainer machine, with a short-lived crates.io API token held only in the
# environment, and Trusted Publishing is configured for it afterwards. 0.0.1
# of the first fourteen crates went up this way on 2026-11-02. This script
# publishes the crates that are still missing, at the workspace's current
# version, and refuses to touch a crate that already exists: a later version
# of an existing crate comes from the signed release pipeline, never from
# here.
#
#   cargo publish --workspace --dry-run --locked   # check packaging first
#   read -rs CARGO_REGISTRY_TOKEN && export CARGO_REGISTRY_TOKEN
#   scripts/reserve-crates.sh [--from <crate>]
#
# `--no-verify`, and why: cargo's verify step builds the packaged crate
# against the crates.io copies of its workspace dependencies, and the copies
# at the current version are the ones the last release published, which a
# crate written since then does not build against. What goes up is a name
# reservation that the next release supersedes, not something anyone depends
# on at this version. The tree itself was built and tested by CI.
#
# There is no per-crate dry run: `cargo publish -p <crate> --dry-run` resolves
# workspace dependencies from crates.io too. The workspace dry run above
# packages against the local tree instead.
#
# crates.io rate-limits NEW crates: a burst of 5, then one every 10 minutes
# (observed 2026-11-02; a 6th publish 20 s after the 5th got HTTP 429). The
# loop paces itself to that. If a publish still fails, wait 10 minutes and
# rerun with `--from <that crate>`; a resumed run assumes the burst is already
# spent and paces every crate.
#
# Afterwards, for EVERY crate published here, on crates.io:
#   Settings -> Trusted Publishing -> GitHub: owner elsoul, repo erpc-cli,
#   workflow release.yml, environment release  ->  then enable
#   "Trusted Publishing Only" so API tokens can no longer publish.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

usage() { echo "usage: $0 [--from <crate>]" >&2; exit 2; }

from=""
[ "$#" -le 2 ] || usage
case "${1:-}" in
  "") [ "$#" -eq 0 ] || usage;;
  --from)
    if [ "$#" -ne 2 ] || [ -z "$2" ]; then usage; fi
    from="$2";;
  *) usage;;
esac

if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
  echo "CARGO_REGISTRY_TOKEN is required (short-lived token, revoke after use)" >&2
  exit 2
fi

pkgid=$(cargo pkgid -p erpc)
version="${pkgid##*[#@]}"

# Every workspace crate, leaves first: a crate goes up after the crates it
# depends on, because crates.io checks that each dependency exists.
crates=(
  erpc-core
  erpc-chain
  erpc-secret
  erpc-ssh
  erpc-auth
  erpc-api
  erpc-ops
  erpc-chain-solana
  erpc-chain-rollup
  erpc-chain-avax
  erpc-chain-bitcoin
  erpc-chain-eth
  erpc-chain-nitro
  erpc-chain-arc
  erpc-chain-sui
  erpc-chain-tron
  erpc-chain-op
  erpc-worker
  erpc-worker-agent
  erpc-wallet
  erpc-x402
  erpc-ai
  erpc-skills
  erpc-mcp-server
  erpc-release
  erpc
)

# The crates that exist on crates.io already. One request per crate, with a
# User-Agent as crates.io asks, so the loop below never publishes to a name
# that is taken: a later version of an existing crate is the release
# pipeline's to publish.
exists() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -A 'erpc-cli reserve-crates (oss@elsoul.nl)' \
    "https://crates.io/api/v1/crates/$1")
  case "$code" in
    200) return 0;;
    404) return 1;;
    *) echo "crates.io answered $code for $1; not guessing" >&2; exit 1;;
  esac
}

missing=()
for c in "${crates[@]}"; do
  if exists "$c"; then
    echo "== $c exists on crates.io; left alone"
  else
    missing+=("$c")
  fi
  sleep 1
done
if [ "${#missing[@]}" -eq 0 ]; then
  echo "every workspace crate is on crates.io; nothing to reserve"
  exit 0
fi
echo "reserving at $version: ${missing[*]}"

burst=5          # new crates crates.io accepts back to back
interval=610     # seconds between new crates after the burst (10 min + slack)

if [ -n "$from" ]; then
  found=""
  for c in "${missing[@]}"; do [ "$c" = "$from" ] && found=1; done
  [ -n "$found" ] || { echo "--from: '$from' is not a crate left to reserve" >&2; exit 2; }
fi

started=""
published=0
spent=0
[ -z "$from" ] || spent=$burst
for c in "${missing[@]}"; do
  if [ -n "$from" ] && [ -z "$started" ]; then
    [ "$c" = "$from" ] || { echo "== $c (skipped, before --from)"; continue; }
  fi
  started=1
  if [ "$published" -gt 0 ] && [ $((published + spent)) -ge "$burst" ]; then
    echo "   waiting ${interval}s for the crates.io new-crate rate limit"
    sleep "$interval"
  elif [ "$published" -gt 0 ]; then
    # crates.io needs a moment to index a new crate before dependents resolve it.
    sleep 20
  fi
  echo "== $c"
  cargo publish -p "$c" --locked --no-verify || {
    echo "publish of $c failed. Fix the cause (for HTTP 429, wait 10 minutes), then rerun: $0 --from $c" >&2
    exit 1
  }
  published=$((published + 1))
done

echo
echo "Done. Now: revoke CARGO_REGISTRY_TOKEN on crates.io, record the revocation,"
echo "and configure Trusted Publishing + 'Trusted Publishing Only' for the ${#missing[@]} crates above."
