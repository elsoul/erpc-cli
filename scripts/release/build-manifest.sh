#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Builds release-manifest.json from a directory of cargo-dist artifacts.
#
#   scripts/release/build-manifest.sh <artifacts-dir> <tag> <commit> > release-manifest.json
#
# The manifest is what minisign signs (scripts/release/sign-manifest.sh) and
# what `erpc upgrade` verifies: version, tag, commit, build time, per-target
# archive sha256/size, SBOM hash and the URL of the signed revocation list.
set -euo pipefail

dir="${1:?artifacts dir}"
tag="${2:?tag, e.g. v0.1.0}"
commit="${3:?full commit sha}"

version="${tag#v}"
build_time="${SOURCE_DATE_EPOCH:+$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)}"
build_time="${build_time:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fsize() { if stat -c %s "$1" >/dev/null 2>&1; then stat -c %s "$1"; else stat -f %z "$1"; fi; }

targets_json=""
for archive in "$dir"/erpc-*.tar.gz "$dir"/erpc-*.zip; do
  [ -f "$archive" ] || continue
  name=$(basename "$archive")
  # erpc-<target>.tar.gz | erpc-<target>.zip
  target="${name#erpc-}"; target="${target%.tar.gz}"; target="${target%.zip}"
  entry=$(printf '"%s": {"archive": "%s", "sha256": "%s", "size": %s}' "$target" "$name" "$(sha256 "$archive")" "$(fsize "$archive")")
  targets_json="${targets_json:+$targets_json, }$entry"
done

sbom_sha=""
for sbom in "$dir"/*.cdx.json "$dir"/*.cdx.xml; do
  [ -f "$sbom" ] || continue
  sbom_sha=$(sha256 "$sbom")
  break
done

cat <<EOF
{
  "schema": 1,
  "name": "erpc",
  "version": "$version",
  "tag": "$tag",
  "commit": "$commit",
  "build_time": "$build_time",
  "targets": { $targets_json },
  "sbom_sha256": "$sbom_sha",
  "revoked_versions_url": "https://dl.erpc.global/revoked-versions.json"
}
EOF
