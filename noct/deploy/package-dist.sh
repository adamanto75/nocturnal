#!/usr/bin/env bash
# Assemble the Linux release archive: the five binaries plus a README, packed
# reproducibly.
#
# Two things this fixes, both found by somebody downloading a release.
#
# **The archive had no README.** It unpacked to five bare executables with
# nothing saying what any of them was — and the person who downloaded it had
# wanted the desktop wallet, which is a different file on the same page. Five
# unexplained binaries is not an answer to "I wanted a wallet".
#
# **The archive hash was not reproducible**, so every release said "the ARCHIVE
# hash is expected to differ, check the binaries inside one at a time". There has
# been a `package-release.sh` in this directory that fixes exactly that, and the
# release steps were not using it. A verification instruction nobody can follow
# in one step is one most people will not follow at all.
#
# Usage: deploy/package-dist.sh <tag> <built-release-dir> [out-dir]
#   e.g. deploy/package-dist.sh v0.3.15-testnet /build/src/noct/target/release
set -euo pipefail

TAG="${1:?usage: package-dist.sh <tag> <built-release-dir> [out-dir]}"
BUILT="${2:?usage: package-dist.sh <tag> <built-release-dir> [out-dir]}"
OUT="${3:-/root/pkg-$TAG}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARIES=(noctd noct-cli noct-miner noct-walletd noct-poold)

# The version as the installer spells it: v0.3.15-testnet -> 0.3.15
INSTALLER_VERSION="$(printf '%s' "$TAG" | sed -e 's/^v//' -e 's/-testnet$//')"

name="nocturnal-$TAG"
rm -rf "$OUT"
mkdir -p "$OUT/$name"

for b in "${BINARIES[@]}"; do
    cp "$BUILT/$b" "$OUT/$name/$b"
done

# The README names the version it shipped with, so a copy found on disk years
# later still says which release it belongs to.
sed -e "s/VERSION/$TAG/g" -e "s/INSTALLER/$INSTALLER_VERSION/g" \
    "$HERE/README-dist.txt" > "$OUT/$name/README.txt"

cd "$OUT"
"$HERE/package-release.sh" "$name-linux-x64.tar.gz" \
    $(printf "%s/%s\n" "$name" "${BINARIES[@]}") "$name/README.txt"

echo
echo "contents:"
tar tzf "$name-linux-x64.tar.gz"
echo
echo "binaries (compare with LINUX-BINARY-SHA256SUMS.txt):"
cd "$name" && sha256sum "${BINARIES[@]}"
