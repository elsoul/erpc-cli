#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Signs release files with minisign using a key supplied through the
# environment by the protected `release` GitHub environment. Never write the
# secret key to the repository or to a persistent path.
#
#   MINISIGN_SECRET_KEY="$(cat minisign.key)" MINISIGN_PASSWORD=... \
#     scripts/release/sign-manifest.sh release-manifest.json
#
# Produces <file>.minisig next to each input and verifies each signature
# against crates/erpc-release/pubkey.txt before exiting.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

: "${MINISIGN_SECRET_KEY:?MINISIGN_SECRET_KEY must be set (never commit it)}"
pubkey_file="crates/erpc-release/pubkey.txt"
[ -s "$pubkey_file" ] || { echo "missing $pubkey_file" >&2; exit 2; }

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <file>..." >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
umask 077
printf '%s\n' "$MINISIGN_SECRET_KEY" > "$tmpdir/minisign.key"

for f in "$@"; do
  [ -f "$f" ] || { echo "no such file: $f" >&2; exit 2; }
  trusted="erpc $(basename "$f") $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ -n "${MINISIGN_PASSWORD:-}" ]; then
    printf '%s\n' "$MINISIGN_PASSWORD" | minisign -S -s "$tmpdir/minisign.key" -m "$f" -t "$trusted"
  else
    minisign -S -W -s "$tmpdir/minisign.key" -m "$f" -t "$trusted"
  fi
  minisign -V -p "$pubkey_file" -m "$f"
  echo "signed: $f -> $f.minisig"
done
