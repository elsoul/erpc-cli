#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Fetches a mainnet snapshot into an empty node from the best of several
# sources. Each source answers /snapshot.tar.bz2 and
# /incremental-snapshot.tar.bz2 with a redirect to its newest archives, whose
# names carry their slots.
#
# 1. Ask every source for its newest full and incremental snapshot. A source
#    that does not answer in a few seconds (one outside its network, say) is
#    left out.
# 2. Keep the sources whose incremental is within MAX_LAG_SLOTS of the newest.
# 3. Download from each for SAMPLE_SECONDS, over as many connections as the
#    download would use, and take the fastest.
# 4. A source that serves byte ranges is downloaded by aria2c over many
#    connections; one that does not (an agave node behind a proxy) by curl
#    over one.
# 5. The incremental is fetched last, newest at that moment, on top of the
#    full snapshot just downloaded.
#
# Archives are written under a .part name and renamed when complete, so the
# validator never finds half an archive. When no source can be used, nothing
# is downloaded and the validator fetches a snapshot itself.
#
# Env (with defaults):
#   SOURCES          space-separated base URLs, in order of preference  (required)
#   DEST             where the validator reads snapshots                (/mnt/snapshot)
#   MAX_LAG_SLOTS    how far behind the newest a source may be          (3000, about 20 minutes)
#   SAMPLE_SECONDS   how long each source is timed                      (5)
#   CONNECTIONS      aria2c connections for a source with ranges        (16)
#   LOWEST_SPEED     below this aria2c gives up and the URL is resolved again (2M)

set -euo pipefail

SOURCES="${SOURCES:?SOURCES is required}"
DEST="${DEST:-/mnt/snapshot}"
MAX_LAG_SLOTS="${MAX_LAG_SLOTS:-3000}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-5}"
CONNECTIONS="${CONNECTIONS:-16}"
LOWEST_SPEED="${LOWEST_SPEED:-2M}"

# Progress goes to stderr, so functions can print their results on stdout.
say() { printf 'snapshot: %s\n' "$*" >&2; }

# The archive a source redirects KIND (snapshot or incremental-snapshot) to,
# as an absolute URL; nothing when it does not answer with a redirect.
resolve() {
  local out code url
  out=$(curl -s -m 10 -o /dev/null -r 0-0 -w '%{http_code} %{redirect_url}' "$1/$2.tar.bz2" 2>/dev/null) || true
  code=${out%% *}
  url=${out#* }
  case "$code" in
    30[12378]) [ -n "$url" ] && [ "$url" != "$out" ] && printf '%s' "$url" ;;
  esac
}

# The archive's file name, without a query string.
name_of() {
  local path=${1%%\?*}
  printf '%s' "${path##*/}"
}

# snapshot-<slot>-<hash>.tar.zst → <slot>
full_slot() {
  [[ $1 =~ ^snapshot-([0-9]+)-[1-9A-HJ-NP-Za-km-z]+\.tar\.(zst|bz2|gz|lz4)$ ]] && printf '%s' "${BASH_REMATCH[1]}"
}

# incremental-snapshot-<base>-<slot>-<hash>.tar.zst → "<base> <slot>"
incremental_slots() {
  [[ $1 =~ ^incremental-snapshot-([0-9]+)-([0-9]+)-[1-9A-HJ-NP-Za-km-z]+\.tar\.(zst|bz2|gz|lz4)$ ]] &&
    printf '%s %s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# Downloads KIND from SOURCE into DEST as NAME. RANGES is yes or no.
fetch() {
  local source=$1 kind=$2 name=$3 ranges=$4 url attempt
  if [ -e "$DEST/$name" ]; then
    say "$name is already here"
    return 0
  fi
  for attempt in 1 2 3 4 5 6; do
    url=$(resolve "$source" "$kind")
    if [ -z "$url" ]; then
      say "$source stopped answering for $kind (attempt $attempt)"
      sleep 5
      continue
    fi
    # The source moved on to a newer archive while this one was downloading;
    # the old one may be gone, so the caller starts again.
    if [ "$(name_of "$url")" != "$name" ]; then
      say "$source now serves $(name_of "$url") instead of $name"
      rm -f "$DEST/$name.part" "$DEST/$name.part.aria2"
      return 1
    fi
    if [ "$ranges" = yes ] && command -v aria2c >/dev/null; then
      # A presigned URL lasts minutes, but a request started on it runs to
      # the end; a retry after that resolves the URL again and resumes.
      # Connections that slow to a crawl are not dropped by aria2c on its
      # own (rpc1, 2026-10-24: the last 7 GB of 125 at 200 KB/s for half an
      # hour), so below LOWEST_SPEED it gives up and this loop resumes on a
      # fresh URL.
      if aria2c --continue=true --allow-overwrite=true --auto-file-renaming=false \
        --max-connection-per-server="$CONNECTIONS" --split="$CONNECTIONS" --min-split-size=64M \
        --lowest-speed-limit="$LOWEST_SPEED" \
        --file-allocation=none --max-tries=3 --retry-wait=3 --console-log-level=warn \
        --summary-interval=60 --dir="$DEST" --out="$name.part" "$url"; then
        mv -f "$DEST/$name.part" "$DEST/$name"
        say "downloaded $name"
        return 0
      fi
    else
      # No ranges, so no resuming: each attempt starts over.
      rm -f "$DEST/$name.part"
      if curl -fsS --connect-timeout 10 -o "$DEST/$name.part" "$url"; then
        mv -f "$DEST/$name.part" "$DEST/$name"
        say "downloaded $name"
        return 0
      fi
    fi
    say "the download of $name from $source failed (attempt $attempt)"
    sleep 5
  done
  rm -f "$DEST/$name.part" "$DEST/$name.part.aria2"
  return 1
}

# One line per usable source: "<start slot> <source> <full snapshot name>".
probe() {
  local source full_url inc_url full_name slot inc start
  for source in $SOURCES; do
    full_url=$(resolve "$source" snapshot)
    full_name=$(name_of "$full_url")
    slot=$(full_slot "$full_name" || true)
    if [ -z "$slot" ]; then
      say "$source: no answer"
      continue
    fi
    start=$slot
    inc_url=$(resolve "$source" incremental-snapshot)
    inc=$(incremental_slots "$(name_of "$inc_url")" || true)
    if [ -n "$inc" ] && [ "${inc%% *}" = "$slot" ]; then
      start=${inc#* }
    fi
    say "$source: full $slot, newest slot $start"
    printf '%s %s %s\n' "$start" "$source" "$full_name"
  done
}

# Times SOURCE's full snapshot: prints "<bytes per second> <yes|no ranges>".
sample() {
  local url out code speed
  url=$(resolve "$1" snapshot)
  [ -n "$url" ] || { printf '0 no'; return; }
  out=$(curl -s -o /dev/null -r 0- -m "$SAMPLE_SECONDS" -w '%{http_code} %{speed_download}' "$url" 2>/dev/null) || true
  code=${out%% *}
  speed=${out#* }
  speed=${speed%%.*}
  case "$code" in
    206) printf '%s yes' "$(sample_parallel "$url")" ;;
    200) printf '%s no' "${speed:-0}" ;;
    *) printf '0 no' ;;
  esac
}

# Times URL over CONNECTIONS ranged requests at once, as aria2c would fetch
# it: prints bytes per second.
sample_parallel() {
  local i total=0 bytes
  for ((i = 0; i < CONNECTIONS; i++)); do
    curl -s -o /dev/null -r "$((i * 268435456))-" -m "$SAMPLE_SECONDS" -w '%{size_download}\n' "$1" 2>/dev/null &
  done | {
    while read -r bytes; do total=$((total + ${bytes%%.*})); done
    printf '%s' "$((total / SAMPLE_SECONDS))"
  }
}

# Picks the source to download from: prints "<source> <ranges> <full name>".
choose() {
  local probes newest start source name speed ranges best="" best_name="" best_speed=0 best_ranges=no
  probes=$(probe)
  [ -n "$probes" ] || return 1
  newest=$(printf '%s\n' "$probes" | sort -n -k1,1 | tail -n 1 | cut -d' ' -f1)
  while read -r start source name; do
    if [ "$start" -lt $((newest - MAX_LAG_SLOTS)) ]; then
      say "$source is $((newest - start)) slots behind the newest; left out"
      continue
    fi
    read -r speed ranges <<<"$(sample "$source")"
    if [ "$ranges" = yes ]; then
      say "$source: $((speed / 1000000)) MB/s over $CONNECTIONS connections"
    else
      say "$source: $((speed / 1000000)) MB/s over one connection (no ranges)"
    fi
    if [ "$speed" -gt "$best_speed" ]; then
      best=$source best_name=$name best_speed=$speed best_ranges=$ranges
    fi
  done <<<"$probes"
  [ -n "$best" ] || return 1
  printf '%s %s %s\n' "$best" "$best_ranges" "$best_name"
}

main() {
  mkdir -p "$DEST"
  rm -f "$DEST"/*.part "$DEST"/*.part.aria2

  local round chosen source ranges full_name slot inc_url inc_name inc
  for round in 1 2; do
    chosen=$(choose) || {
      say "no source can be used; the validator fetches a snapshot itself"
      return 0
    }
    read -r source ranges full_name <<<"$chosen"
    say "downloading $full_name from $source"
    if fetch "$source" snapshot "$full_name" "$ranges"; then
      break
    fi
    full_name=""
    say "round $round failed"
  done
  if [ -z "$full_name" ]; then
    say "no full snapshot was downloaded; the validator fetches one itself"
    return 0
  fi
  slot=$(full_slot "$full_name")

  # The newest incremental on top of this full snapshot, from the chosen
  # source first and the others after.
  inc_name=""
  for s in "$source" $SOURCES; do
    inc_url=$(resolve "$s" incremental-snapshot)
    inc=$(incremental_slots "$(name_of "$inc_url")" || true)
    if [ -n "$inc" ] && [ "${inc%% *}" = "$slot" ]; then
      inc_name=$(name_of "$inc_url")
      read -r _ ranges <<<"$(sample "$s")"
      if fetch "$s" incremental-snapshot "$inc_name" "$ranges"; then
        break
      fi
      inc_name=""
    fi
  done
  if [ -z "$inc_name" ]; then
    say "no incremental on top of slot $slot; the validator catches up from the full snapshot"
  fi

  # Older archives would only fill the disk: the validator loads the newest.
  find "$DEST" -maxdepth 1 -type f \( -name 'snapshot-*.tar.*' -o -name 'incremental-snapshot-*.tar.*' \) \
    ! -name "$full_name" ${inc_name:+! -name "$inc_name"} -print -delete | sed 's/^/snapshot: removed /' >&2
  say "done: $full_name${inc_name:+ and $inc_name}"
}

# Run unless sourced, so the functions can be tried one by one.
[[ "${BASH_SOURCE[0]}" != "$0" ]] || main "$@"
