#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Asserts that the files docs/verify-release.md tells an operator to download
# are the files the release pipeline actually attaches to the GitHub Release.
#
# This exists because the signing path is the one part of the pipeline that
# never runs in CI, and it has now been wrong twice. Most recently: the signed
# manifest and its signature were uploaded as a workflow artifact named
# `signed-manifest`, while the generated `announce` job downloads only
# `pattern: artifacts-*` before running `gh release create ... artifacts/*`.
# Both files were produced, signed, and then stranded in an artifact nothing
# ever downloaded -- so the verification procedure described in the docs could
# not be carried out, and nothing failed.
#
# The coupling it checks is invisible in review: a name in our workflow has to
# match a glob in a file cargo-dist generates, and a cargo-dist upgrade may
# change that glob. Hence a test rather than a comment.
set -uo pipefail

export LC_ALL=C

# No locale re-exec here, unlike the gate self-tests. Those exercise character
# classes whose meaning changes with collation; this one compares two strings
# extracted from YAML under LC_ALL=C, which is set above and inherited.

repo_root="$(git rev-parse --show-toplevel)"
generated="$repo_root/.github/workflows/release.yml"
custom="$repo_root/.github/workflows/release-publish.yml"
verify_doc="$repo_root/docs/verify-release.md"

for f in "$generated" "$custom" "$verify_doc"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }
done

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n   %s\n' "$1" "${2:-}"; }

# The announce job of the generated workflow, sliced out so a `pattern:` in
# some other job cannot answer for it.
announce=$(awk '
  /^  announce:/ { inside = 1; next }
  inside && /^  [a-z]/ { exit }
  inside { print }
' "$generated")

[ -n "$announce" ] || { echo "could not find the announce job in $generated" >&2; exit 2; }

download_pattern=$(printf '%s\n' "$announce" | grep -oE 'pattern:[[:space:]]*[^[:space:]]+' | head -1 | sed -E 's/^pattern:[[:space:]]*//')
download_path=$(printf '%s\n' "$announce" | grep -oE '^[[:space:]]*path:[[:space:]]*[^[:space:]]+' | head -1 | sed -E 's/^[[:space:]]*path:[[:space:]]*//')
create_line=$(printf '%s\n' "$announce" | grep -F 'gh release create' | head -1)
cleanup_line=$(printf '%s\n' "$announce" | grep -oE 'rm -f artifacts/[^[:space:]]+' | head -1)

# 1. The pattern exists at all. If cargo-dist stops using a pattern, every
#    assertion below is vacuous and must not quietly pass.
if [ -n "$download_pattern" ]; then
  ok "the announce job downloads artifacts by pattern ($download_pattern)"
else
  bad "the announce job downloads artifacts by pattern" \
      "no 'pattern:' in the announce job; the rest of this file is now vacuous"
fi

# 2. The name our workflow uploads the signed manifest under must match it.
#    This is the assertion that failed before the fix.
manifest_artifact=$(awk '
  /uses: actions\/upload-artifact/ { name = ""; block = 1 }
  block && /name:/ && name == "" { line = $0; sub(/^[[:space:]]*name:[[:space:]]*/, "", line); name = line }
  block && /release-manifest\.json/ { print name; exit }
' "$custom")

if [ -z "$manifest_artifact" ]; then
  bad "the signed manifest is uploaded under a name the announce job downloads" \
      "no upload-artifact step in release-publish.yml carries release-manifest.json"
elif [ -z "$download_pattern" ]; then
  bad "the signed manifest is uploaded under a name the announce job downloads" \
      "no download pattern to compare against"
else
  case "$manifest_artifact" in
    $download_pattern)
      ok "the signed manifest is uploaded under a name the announce job downloads";;
    *)
      bad "the signed manifest is uploaded under a name the announce job downloads" \
          "uploaded as '$manifest_artifact', which does not match '$download_pattern', so neither the manifest nor its signature reaches the release";;
  esac
fi

# 3. The release has to be created from the directory those artifacts land in.
if [ -n "$create_line" ] && [ -n "$download_path" ]; then
  case "$create_line" in
    *"$download_path"/*)
      ok "the release is created from the directory the artifacts download into";;
    *)
      bad "the release is created from the directory the artifacts download into" \
          "download path '$download_path' does not appear in: $create_line";;
  esac
else
  bad "the release is created from the directory the artifacts download into" \
      "could not find both a download 'path:' and a 'gh release create' line"
fi

# 4. The cleanup step between them must not delete what we just attached.
if [ -z "$cleanup_line" ]; then
  ok "the cleanup step deletes nothing we attach (no cleanup step)"
else
  glob="${cleanup_line#rm -f }"
  glob="${glob#artifacts/}"
  deleted=""
  for f in release-manifest.json release-manifest.json.minisig; do
    case "$f" in
      $glob) deleted="$deleted $f";;
    esac
  done
  if [ -z "$deleted" ]; then
    ok "the cleanup step deletes nothing we attach"
  else
    bad "the cleanup step deletes nothing we attach" \
        "'$cleanup_line' would remove:$deleted"
  fi
fi

# 5. And the page must name exactly the files the pipeline attaches. BOTH
#    directions, because one was not enough: checking only
#    attached-is-documented would still pass if the page regained a
#    `latest.json` row, which is the exact drift this branch removes.
uploaded_files=$(awk '
  /uses: actions\/upload-artifact/ { block = 1; next }
  block && /release-manifest/ { line = $0; sub(/^[[:space:]]*/, "", line); sub(/^artifacts\//, "", line); print line }
  block && /if-no-files-found/ { block = 0 }
' "$custom")

[ -n "$uploaded_files" ] || bad "the verification page names the files the pipeline attaches" \
  "no release-manifest paths found in the upload step"

missing=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
  grep -qF "$f" "$verify_doc" || missing="$missing $f"
done <<EOF
$uploaded_files
EOF

if [ -n "$uploaded_files" ]; then
  if [ -z "$missing" ]; then
    ok "the verification page names the files the pipeline attaches"
  else
    bad "the verification page names the files the pipeline attaches" \
        "attached but not mentioned in docs/verify-release.md:$missing"
  fi
fi

# 6. The reverse direction: every release file the page tells the operator
#    to fetch must be one the pipeline attaches. Without this the page could
#    name a file that no longer exists -- `latest.json` and its signature
#    were exactly that until this branch removed them -- and the operator
#    would be told to verify something they cannot download.
documented_files=$(grep -ohE '[A-Za-z0-9_.-]+\.(json|minisig)' "$verify_doc" 2>/dev/null | sort -u)

if [ -z "$documented_files" ]; then
  bad "every release file the page names is one the pipeline attaches" \
      "no .json or .minisig filename found in docs/verify-release.md"
else
  undelivered=""
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    case "
$uploaded_files
" in
      *"
$d
"*) ;;
      *) undelivered="$undelivered $d";;
    esac
  done <<EOF
$documented_files
EOF
  if [ -z "$undelivered" ]; then
    ok "every release file the page names is one the pipeline attaches"
  else
    bad "every release file the page names is one the pipeline attaches" \
        "named in docs/verify-release.md but never attached:$undelivered"
  fi
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
