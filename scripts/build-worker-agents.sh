#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the erpc worker agents that erpc embeds (crates/erpc/build.rs):
# static musl binaries for x86_64 and aarch64 Linux, cross-built with
# cargo-zigbuild on every host the same way, so that a rebuild on another
# runner gives the same bytes and rebuild-compare can check them.
#
#   scripts/build-worker-agents.sh [OUT_DIR]   # default: target/worker-agents
#
# Prints the directory. Under GitHub Actions it also sets
# ERPC_WORKER_AGENTS_DIR and ERPC_REQUIRE_WORKER_AGENTS=1 for the steps
# after it, so the erpc built next carries them or fails.
#
# Needs: the toolchain of rust-toolchain.toml, zig, and cargo-zigbuild.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/target/worker-agents}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# The paths rustc and build.rs see: Windows ones under Git Bash.
native() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# Where the checkout and the crate sources are differs by runner
# (/home/runner, /Users/runner, D:\a): paths in panic messages would make
# the agents differ by host, so they are remapped to fixed ones.
export RUSTFLAGS="--remap-path-prefix=$(native "$root")=/erpc --remap-path-prefix=$(native "$cargo_home")=/cargo"

for machine in x86_64 aarch64; do
  target="$machine-unknown-linux-musl"
  rustup target add "$target" >/dev/null
  cargo zigbuild --manifest-path "$root/Cargo.toml" --locked --release \
    -p erpc-worker-agent --target "$target" >&2
  cp "$root/target/$target/release/erpc-worker-agent" "$out/erpc-worker-agent-$machine-linux"
  echo "erpc-worker-agent-$machine-linux $(digest "$out/erpc-worker-agent-$machine-linux")" >&2
done

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "ERPC_WORKER_AGENTS_DIR=$(native "$out")"
    echo "ERPC_REQUIRE_WORKER_AGENTS=1"
  } >> "$GITHUB_ENV"
fi
echo "$out"
