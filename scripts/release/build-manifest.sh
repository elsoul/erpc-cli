#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Builds release-manifest.json from a directory of cargo-dist artifacts.
#
#   scripts/release/build-manifest.sh <artifacts-dir> <tag> <commit> > release-manifest.json
#
# The manifest is what minisign signs (scripts/release/sign-manifest.sh) and
# what docs/verify-release.md tells an operator to check: version, tag, commit,
# build time, per-target archive sha256/size and the SBOM hash. It also carries
# a `revoked_versions_url` field, reserved for a revocation list that nothing
# publishes or consumes yet.
set -euo pipefail

dir="${1:?artifacts dir}"
tag="${2:?tag, e.g. v0.1.0}"
commit="${3:?full commit sha}"

version="${tag#v}"
build_time="${SOURCE_DATE_EPOCH:+$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)}"
build_time="${build_time:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fsize() { if stat -c %s "$1" >/dev/null 2>&1; then stat -c %s "$1"; else stat -f %z "$1"; fi; }

# cargo-dist names an archive erpc-<target>.<ext>. The extension depends on
# the platform and on the dist configuration (.tar.xz by default on unix,
# .zip on Windows), so match every archive extension rather than guessing:
# globbing only .tar.gz silently produced a one-target manifest.
targets_json=""
for archive in "$dir"/erpc-*.tar.xz "$dir"/erpc-*.tar.gz "$dir"/erpc-*.tar.zst "$dir"/erpc-*.zip; do
  [ -f "$archive" ] || continue
  name=$(basename "$archive")
  target="${name#erpc-}"
  target="${target%.tar.xz}"; target="${target%.tar.gz}"; target="${target%.tar.zst}"; target="${target%.zip}"
  # Only release targets, never a source archive or an installer.
  case "$target" in
    *-*-*|*-*) ;;
    *) continue;;
  esac
  entry=$(printf '"%s": {"archive": "%s", "sha256": "%s", "size": %s}' "$target" "$name" "$(sha256 "$archive")" "$(fsize "$archive")")
  targets_json="${targets_json:+$targets_json, }$entry"
done

sbom_sha=""
for sbom in "$dir"/*.cdx.json "$dir"/*.cdx.xml "$dir"/*.cdx; do
  [ -f "$sbom" ] || continue
  sbom_sha=$(sha256 "$sbom")
  break
done

# A signed manifest that vouches for nothing is worse than a missing one:
# it would be mirrored and presented to users as a verification artifact.
[ -n "$targets_json" ] || { echo "no release archives found in $dir; refusing to emit an empty manifest" >&2; exit 1; }
[ -n "$sbom_sha" ] || { echo "no CycloneDX SBOM found in $dir; refusing to emit a manifest without one" >&2; exit 1; }
target_count=$(printf '%s' "$targets_json" | tr ',' '\n' | grep -c '"archive"' || true)
dist_config="$(git rev-parse --show-toplevel)/dist-workspace.toml"
[ -f "$dist_config" ] || { echo "cannot read $dist_config to check the target count" >&2; exit 1; }
# `grep -c` exits 1 when it matches nothing while still printing 0, so `|| true`
# rather than `|| echo 0`, which would append a second line and make the
# numeric comparison error out and skip the check.
expected_targets=$(grep -cE '^[[:space:]]*"[a-z0-9_]+-[a-z0-9_-]+",$' "$dist_config" || true)
[ -n "$expected_targets" ] || expected_targets=0
if [ "$expected_targets" -le 0 ]; then
  echo "could not determine the configured target list from $dist_config" >&2
  exit 1
fi
if [ "$target_count" -ne "$expected_targets" ]; then
  echo "manifest covers $target_count targets but $dist_config configures $expected_targets" >&2
  exit 1
fi

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
