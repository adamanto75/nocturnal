#!/bin/bash
# Rebuild a Nocturnal release and print the hashes, so anyone can check that a
# published binary really was built from the published source.
#
#   ./reproducible-build.sh <git-tag>
#
# The point is not that this script is trustworthy. The point is that you can
# run it, compare its output to the SHA256SUMS.txt in the release, and stop
# taking the author's word for what is in a binary you are about to hand your
# keys to.
#
# WHAT MAKES A BUILD REPRODUCIBLE HERE
#
# Rust bakes absolute paths into binaries (debug info, panic messages), so the
# same source built in two directories produces two different files. Measured on
# this project: /root/repro-a and /root/repro-b gave a9af23e6… and 0772736e…
# from byte-identical source. `--remap-path-prefix` rewrites those paths to
# fixed strings and the difference disappears.
#
# The build therefore happens at a FIXED path, and the cargo registry is remapped
# too, so your home directory does not leak in either.
#
# WHAT IT DOES NOT PROMISE
#
# The toolchain and the C library are part of the input. A different Rust
# version, a different distribution, or a different libc will produce a
# different — not wrong — binary. Match the environment below or expect a
# mismatch that means nothing.
#
#   Rust      1.82.0
#   OS        Debian 12 (bookworm), x86_64
#   Also      cmake and a C++ toolchain, for RandomX
set -euo pipefail

TAG="${1:?usage: reproducible-build.sh <git-tag>   e.g. v0.1.3-testnet}"
REPO="${REPO:-https://github.com/adamanto75/nocturnal}"
BUILD_ROOT="${BUILD_ROOT:-/build}"

command -v cargo >/dev/null || { echo "cargo not found"; exit 1; }
RUSTV="$(rustc --version | cut -d' ' -f2)"
[ "$RUSTV" = "1.82.0" ] || echo "WARNING: rustc is $RUSTV, not 1.82.0 — hashes will differ"

# A fixed build path is half the trick: nothing to remap if it never varies.
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"
git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$BUILD_ROOT/src"
cd "$BUILD_ROOT/src/noct"

# The other half: the dependency sources live under your home directory, which
# differs per user, so remap that too.
export RUSTFLAGS="--remap-path-prefix=$BUILD_ROOT/src/noct=/noct --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
# Timestamps are an input to some build scripts; pin it.
export SOURCE_DATE_EPOCH=1

cargo build --release -p noct-node --features randomx
cargo build --release -p noct-pool --features randomx
cargo build --release -p noct-wallet --bins

cd target/release
strip noctd noct-cli noct-miner noct-walletd noct-poold 2>/dev/null || true

echo
echo "Built from $TAG. Compare these against the release's SHA256SUMS.txt:"
echo
sha256sum noctd noct-cli noct-miner noct-walletd noct-poold
echo
echo "The release ships a tar.gz, not loose binaries, so its published hash covers"
echo "the archive. Extract the release archive and compare file-by-file against"
echo "the hashes above — archive metadata (timestamps, ordering) is not yet"
echo "reproducible, so the ARCHIVE hash is expected to differ. The binaries are"
echo "what matter, and they are what this compares."
