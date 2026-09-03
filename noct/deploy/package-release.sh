#!/usr/bin/env bash
# Package release binaries into a byte-for-byte reproducible tar.gz.
#
# `reproducible-build.sh` makes the *binaries* reproducible; the archive around
# them was not, so the published SHA256SUMS.txt could never itself be checked —
# only the files inside it, by hand, one at a time. Anyone verifying a release
# had to be told "the archive hash is expected to differ", which is exactly the
# sentence an attacker would like everyone to be used to reading.
#
# What makes a tar non-deterministic, and how each is pinned here:
#   * operand order        -> the caller's argument order is sorted away below
#   * directory walk order -> --sort=name
#   * timestamps           -> --mtime, from SOURCE_DATE_EPOCH
#   * owner/group names    -> --owner/--group/--numeric-owner
#   * pax extended headers -> atime/ctime dropped
#   * gzip header          -> -n, or it stores the source name and time
#
# The operand-order one is easy to miss: --sort=name orders the members tar
# finds when it walks a directory, and does NOT reorder paths listed explicitly
# on the command line. Packaging the same three files in two different orders
# produced two different archives until this sorted them itself.
#
# Usage: deploy/package-release.sh <output.tar.gz> <file>...
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <output.tar.gz> <file>..." >&2
    exit 2
fi

out=$1
shift

# Same pin as the build. Any fixed value works; it must not be "now".
: "${SOURCE_DATE_EPOCH:=1}"

printf '%s\n' "$@" | LC_ALL=C sort \
  | tar --sort=name \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        --owner=0 --group=0 --numeric-owner \
        --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
        --no-recursion -T - -cf - \
  | gzip -n -9 > "$out"

echo "wrote $out"
sha256sum "$out"
