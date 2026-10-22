#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Rewrites `uses: owner/repo@<tag>` lines in the given workflow files to the
# full commit SHA of that tag, keeping the tag as a trailing comment:
#   uses: actions/checkout@v5          ->  uses: actions/checkout@<sha> # v5
# Lines already pinned to a 40-hex SHA are left alone. Requires `gh`.
#
# Usage: scripts/pin-actions.sh .github/workflows/*.yml
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <workflow.yml>..." >&2
  exit 2
fi

resolve_sha() {
  local repo="$1" ref="$2"
  local obj sha type
  # Tags first (annotated tags point at a tag object; peel to the commit), then branches.
  if obj=$(gh api "repos/$repo/git/ref/tags/$ref" --jq '.object.sha + " " + .object.type' 2>/dev/null); then
    sha=${obj% *}; type=${obj#* }
    if [ "$type" = "tag" ]; then
      sha=$(gh api "repos/$repo/git/tags/$sha" --jq '.object.sha')
    fi
  elif obj=$(gh api "repos/$repo/git/ref/heads/$ref" --jq '.object.sha' 2>/dev/null); then
    sha=$obj
  else
    echo "cannot resolve $repo@$ref (no such tag or branch)" >&2
    return 1
  fi
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "unexpected sha for $repo@$ref: $sha" >&2; return 1; }
  printf '%s' "$sha"
}

for file in "$@"; do
  tmp=$(mktemp)
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^([[:space:]]*-?[[:space:]]*uses:[[:space:]]*)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[A-Za-z0-9_./-]+)?@([A-Za-z0-9_.-]+)[[:space:]]*(#.*)?$ ]]; then
      prefix="${BASH_REMATCH[1]}"; repo="${BASH_REMATCH[2]}"; sub="${BASH_REMATCH[3]}"; ref="${BASH_REMATCH[4]}"
      if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        printf '%s\n' "$line" >> "$tmp"
        continue
      fi
      sha=$(resolve_sha "$repo" "$ref")
      printf '%s%s%s@%s # %s\n' "$prefix" "$repo" "$sub" "$sha" "$ref" >> "$tmp"
    else
      printf '%s\n' "$line" >> "$tmp"
    fi
  done < "$file"
  mv "$tmp" "$file"
  echo "pinned: $file"
done
