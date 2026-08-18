#!/usr/bin/env bash
#
# Install noctd as a hardened, always-on Noct seed node on a Linux host.
#
# Run this ON the server (a fresh Ubuntu/Debian VPS is assumed), from a checkout
# of the repo. It builds the RandomX node, installs it as a systemd service, and
# starts it. Re-running upgrades the binary in place.
#
#   sudo ./deploy/install-seed-node.sh [--repo /path/to/noct] [--no-build]
#
# See docs/DEPLOY-SEED-NODE.md for the full runbook (firewall, seeds, DNS).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD=1
for arg in "$@"; do
  case "$arg" in
    --repo) shift; REPO="$1"; shift ;;
    --no-build) BUILD=0 ;;
  esac
done

BIN=/usr/local/bin/noctd
UNIT=/etc/systemd/system/noctd.service
DATA=/var/lib/noct

if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)"; exit 1; fi

echo "==> Building the RandomX node (release)"
if [[ $BUILD -eq 1 ]]; then
  # RandomX links a vendored C++ library: needs a C/C++ toolchain + cmake.
  # rustup is expected to provide the pinned 1.82 toolchain (see rust-toolchain).
  command -v cargo >/dev/null || { echo "cargo not found — install Rust 1.82"; exit 1; }
  command -v cmake >/dev/null || { echo "cmake not found — apt-get install -y cmake build-essential"; exit 1; }
  ( cd "$REPO" && cargo build --release -p noct-node --bin noctd --features randomx )
  install -m 0755 "$REPO/target/release/noctd" "$BIN"
else
  echo "    (--no-build) expecting an existing $BIN"
  test -x "$BIN" || { echo "no binary at $BIN"; exit 1; }
fi
echo "    installed $("$BIN" --help 2>&1 | head -1 || true) -> $BIN"

echo "==> Creating the service account and data dir"
id -u noct >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin noct
install -d -o noct -g noct -m 0750 "$DATA"

echo "==> Installing the systemd unit"
install -m 0644 "$REPO/deploy/noctd.service" "$UNIT"
systemctl daemon-reload
systemctl enable noctd
systemctl restart noctd

echo "==> Done. Node status:"
sleep 2
systemctl --no-pager --lines=8 status noctd || true

cat <<'EOF'

Next steps (see docs/DEPLOY-SEED-NODE.md):
  1. Open the P2P port in your cloud firewall / security group:  9333/tcp
     (Leave RPC 9334 closed — it is localhost-only by design.)
  2. Confirm reachability from another host:   nc -vz <PUBLIC_IP> 9333
  3. Check sync/height locally:                curl -s 127.0.0.1:9334/info
  4. Peer multiple seeds: add `--seed <other-ip>:9333` lines to the unit's
     ExecStart, then: systemctl daemon-reload && systemctl restart noctd
  5. Once your seed IPs are stable, bake them into DEFAULT_SEEDS
     (node/src/lib.rs) and rebuild the wallet/installer so clients auto-connect.
EOF
