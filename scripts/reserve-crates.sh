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
# environment, and Trusted Publishing is configured for it afterwards. The
# first fifteen crates went up this way at 0.0.1 on 2026-11-02, from the tree
# of that day. A crate added since then is reserved the same way, at 0.0.1,
# but not from this tree: what goes up is a PLACEHOLDER -- the name, the
# version 0.0.1, the licence, a description that says what it is, and an
# empty library. No code and no dependencies, so it builds anywhere, docs.rs
# included, and nothing of this tree is published under a version number
# that is not a release. The real crate comes from the signed release
# pipeline at the next tag, as a new version.
#
#   read -rs CARGO_REGISTRY_TOKEN && export CARGO_REGISTRY_TOKEN
#   scripts/reserve-crates.sh [--from <crate>]
#
# Before anything is published, every workspace crate that already exists on
# crates.io must be owned by whoever owns `erpc` there. A name taken by
# someone else stops the run: a placeholder next to a stranger's crate would
# let the next release depend on theirs.
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
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

# Every workspace crate, from cargo, so this list cannot drift from the tree.
crates=()
while IFS= read -r c; do crates+=("$c"); done < <(
  cargo metadata --no-deps --format-version 1 --locked \
    | jq -r '.packages[] | select(.publish == null or (.publish | length) > 0) | .name' | sort
)
[ "${#crates[@]}" -gt 0 ] || { echo "no publishable crate in the workspace" >&2; exit 2; }

api() {
  # One request per call, with a User-Agent as crates.io asks.
  curl -sS -A 'erpc-cli reserve-crates (oss@elsoul.nl)' -w '\n%{http_code}' "https://crates.io/api/v1/crates/$1"
}

# Owners of a crate, one login per line. HTTP 404 means no such crate.
owners_of() {
  local out code body
  out=$(api "$1/owners"); code="${out##*$'\n'}"; body="${out%$'\n'*}"
  case "$code" in
    200) printf '%s\n' "$body" | jq -r '.users[].login' | sort -u;;
    404) return 1;;
    *) echo "crates.io answered $code for $1/owners; not guessing" >&2; exit 1;;
  esac
}

# The owners of `erpc` are the yardstick: every other existing crate must
# share at least one of them.
anchor=$(owners_of erpc) || { echo "erpc itself is not on crates.io; nothing to measure ownership by" >&2; exit 1; }
sleep 1

missing=()
for c in "${crates[@]}"; do
  if owners=$(owners_of "$c"); then
    if [ -z "$(comm -12 <(printf '%s\n' "$anchor") <(printf '%s\n' "$owners"))" ]; then
      echo "$c exists on crates.io and is owned by [$(printf '%s' "$owners" | tr '\n' ' ')], not by the owners of erpc [$(printf '%s' "$anchor" | tr '\n' ' ')]; stopping" >&2
      exit 1
    fi
    echo "== $c exists on crates.io, owned as erpc is; left alone"
  else
    missing+=("$c")
  fi
  sleep 1
done
if [ "${#missing[@]}" -eq 0 ]; then
  echo "every workspace crate is on crates.io; nothing to reserve"
  exit 0
fi
echo "reserving at 0.0.1 with placeholders: ${missing[*]}"

burst=5          # new crates crates.io accepts back to back
interval=610     # seconds between new crates after the burst (10 min + slack)

if [ -n "$from" ]; then
  found=""
  for c in "${missing[@]}"; do [ "$c" = "$from" ] && found=1; done
  [ -n "$found" ] || { echo "--from: '$from' is not a crate left to reserve" >&2; exit 2; }
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The placeholder: a package with nothing in it but what crates.io requires
# and what a reader needs to understand it. `[workspace]` so cargo does not
# look for one above the temporary directory.
placeholder() {
  local name="$1" dir="$work/$1"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "0.0.1"
edition = "2024"
license = "Apache-2.0"
description = "Name reservation for the erpc CLI workspace crate $name. This version holds nothing; the crate is published by the release pipeline of https://github.com/elsoul/erpc-cli from its next tag."
repository = "https://github.com/elsoul/erpc-cli"
homepage = "https://erpc.global"

[workspace]
EOF
  cat > "$dir/src/lib.rs" <<'EOF'
// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A name reservation. The crate itself is published by the release pipeline
//! of <https://github.com/elsoul/erpc-cli> from its next tag.
EOF
  printf '%s' "$dir"
}

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
  fi
  echo "== $c (placeholder 0.0.1)"
  dir=$(placeholder "$c")
  (cd "$dir" && cargo publish) || {
    echo "publish of $c failed. Fix the cause (for HTTP 429, wait 10 minutes), then rerun: $0 --from $c" >&2
    exit 1
  }
  published=$((published + 1))
done

echo
echo "Done. Now: revoke CARGO_REGISTRY_TOKEN on crates.io, record the revocation,"
echo "and configure Trusted Publishing + 'Trusted Publishing Only' for the ${#missing[@]} crates above."
