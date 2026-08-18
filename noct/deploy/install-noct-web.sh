#!/usr/bin/env bash
#
# Install the Noct website + read-only explorer on a Debian/Ubuntu machine —
# normally a fresh LXC container.
#
# It installs TWO services:
#
#   noctd      a full testnet node, RPC bound to LOOPBACK ONLY. It syncs over
#              ordinary P2P from the baked-in seed addresses, so it needs no
#              route to your other subnets and exposes no admin port.
#
#   noct-web   the public site + explorer, which reads that node over 127.0.0.1.
#
# The point of the pair is that the node's admin RPC (mine / submitblock /
# submit_tx) never leaves the machine. noct-web cannot reach those endpoints
# either: its route table is an exhaustive whitelist and the binary has no POST
# handler at all. This script verifies that before it finishes.
#
# Usage:  sudo ./install-noct-web.sh [--listen 0.0.0.0:8080]
#
set -euo pipefail

LISTEN="0.0.0.0:8080"
SEEDS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --listen) LISTEN="$2"; shift 2 ;;
    # Repeatable. Without it the node uses the seed addresses compiled into the
    # binary, which are PUBLIC. That fails on a machine sitting behind the same
    # router as those seeds, because reaching your own public IP from inside
    # needs NAT hairpinning and many routers do not do it — measured here: a
    # container on the seeds' own LAN could not connect to them by public
    # address, but reached one directly on its LAN address immediately. So pass
    # the LAN address when installing alongside your own seeds.
    # (Public seeds are seed1.nocturnalcoin.com / seed2.nocturnalcoin.com:19333.)
    --seed)   SEEDS="$SEEDS --seed $2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
for b in noctd noct-web; do
  [ -f "$HERE/$b" ] || { echo "missing $HERE/$b — run this from the unpacked bundle" >&2; exit 1; }
done

echo "==> installing binaries"
install -m 0755 "$HERE/noctd"    /usr/local/bin/noctd
install -m 0755 "$HERE/noct-web" /usr/local/bin/noct-web

# noctd must be a RandomX build or it cannot validate real testnet blocks: a
# Keccak build computes a different PoW and would reject the whole chain.
if ! strings /usr/local/bin/noctd | grep -qx RandomX; then
  echo "FATAL: noctd is not a RandomX build — it would reject every real block" >&2
  exit 1
fi

echo "==> service users (no login, no home)"
id -u noct     >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin noct
id -u noct-web >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin noct-web
install -d -o noct -g noct -m 0750 /var/lib/noct

echo "==> systemd units"
cat > /etc/systemd/system/noctd.service <<UNIT
[Unit]
Description=Noct testnet node (explorer backend)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=noct
Group=noct
# RPC on loopback ONLY. It is an administrative interface — it can start mining
# and submit blocks — and nothing outside this machine has any business reaching
# it. P2P dials OUT to the baked-in testnet seeds; no inbound port is required,
# so this needs no firewall change and no route to your other subnets.
ExecStart=/usr/local/bin/noctd \
    --network testnet \
    --rpc 127.0.0.1:19334 \
    --p2p 0.0.0.0:19333 \
    --data-dir /var/lib/noct \
    --max-outbound 12${SEEDS}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
StateDirectory=noct
ReadWritePaths=/var/lib/noct
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/noct-web.service <<UNIT
[Unit]
Description=Noct website + read-only block explorer
After=noctd.service network-online.target
Wants=network-online.target

[Service]
Type=simple
User=noct-web
Group=noct-web
# Its own user, owning nothing: no keys, no chain data, and it writes no files
# (the site is compiled into the binary, so there is no document root either).
ExecStart=/usr/local/bin/noct-web --listen ${LISTEN} --node 127.0.0.1:19334 --rate-limit 120
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now noctd noct-web

# Several of the hardening directives above need mount namespacing, which older
# systemd (Debian 12's 252) cannot set up inside an unprivileged LXC on a recent
# kernel — the service then crash-loops with status=226/NAMESPACE forever.
# Debian 13's systemd 257 handles it. Rather than demand a particular base image,
# detect the failure and drop only the directives that cannot work, loudly.
MOUNT_NS_DIRECTIVES='^(PrivateTmp|PrivateDevices|ProtectSystem|ProtectHome|ProtectKernelTunables|ProtectKernelModules|ProtectControlGroups|ReadWritePaths|StateDirectory)='

degrade_if_namespacing_unsupported() {
  svc="$1"
  sleep 3
  systemctl is-active --quiet "$svc" && return 0
  journalctl -u "$svc" -n 30 --no-pager 2>/dev/null | grep -q '226/NAMESPACE' || return 0

  echo "    !! $svc cannot use mount namespacing on this system (systemd $(systemctl --version | head -1 | awk '{print $2}') in an unprivileged container)."
  echo "    !! Dropping the mount-based protections so it can run. Process isolation"
  echo "    !! (own user, no privileges, restricted syscalls) is retained."
  # `%` as the delimiter: the pattern itself is full of `|` alternations.
  sed -i -E "s%${MOUNT_NS_DIRECTIVES}%# unsupported here: &%" "/etc/systemd/system/${svc}.service"
  systemctl daemon-reload
  systemctl restart "$svc"
  sleep 3
}

for svc in noctd noct-web; do degrade_if_namespacing_unsupported "$svc"; done

# A service that is not running must never be mistaken for a service that is
# safely refusing requests. Check liveness FIRST; the probe below is only
# meaningful against something actually listening.
for svc in noctd noct-web; do
  if ! systemctl is-active --quiet "$svc"; then
    echo >&2
    echo "FATAL: $svc did not start. This is a startup failure, NOT a security result." >&2
    echo "       journalctl -u $svc -n 50 --no-pager" >&2
    exit 1
  fi
done

echo "==> waiting for the node to answer"
for _ in $(seq 1 45); do
  curl -sf --max-time 2 127.0.0.1:19334/info >/dev/null 2>&1 && break
  sleep 2
done

PORT="${LISTEN##*:}"
echo
echo "==> node:"; curl -s --max-time 5 127.0.0.1:19334/info || echo "  (no answer yet — journalctl -u noctd -n 50)"
echo

# `curl -w '%{http_code}'` already prints 000 when it cannot connect, so do NOT
# add `|| echo 000`: that appends a second value and yields "000000", which
# matches nothing and reads like a bug in the server rather than in the check.
probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" || true; }

echo "==> verifying the admin surface is unreachable through the website"
FAILED=0
UNREACHABLE=0
for p in /mine /submitblock /submit_tx /mining/start /getblocktemplate /info; do
  code=$(probe "http://127.0.0.1:${PORT}${p}")
  printf '    %-20s %s\n' "$p" "$code"
  case "$code" in
    404) ;;
    000) UNREACHABLE=1 ;;
    *)   FAILED=1 ;;
  esac
done
code=$(probe -X POST "http://127.0.0.1:${PORT}/mine")
printf '    %-20s %s\n' "POST /mine" "$code"
case "$code" in
  405) ;;
  000) UNREACHABLE=1 ;;
  *)   FAILED=1 ;;
esac

if [ "$UNREACHABLE" != 0 ]; then
  echo >&2
  echo "FATAL: could not reach noct-web on port ${PORT} — the check proved nothing." >&2
  echo "       Fix that before trusting any result above." >&2
  exit 1
fi
if [ "$FAILED" != 0 ]; then
  echo >&2
  echo "FATAL: an admin path answered something other than 404/405." >&2
  echo "       The node's control surface may be exposed. Stopping noct-web." >&2
  systemctl stop noct-web
  exit 1
fi

echo
echo "    all admin paths 404, POST 405 — the node's control surface is not exposed."

PEERS=$(curl -s --max-time 5 127.0.0.1:19334/info | grep -oE '"peers":[0-9]+' | cut -d: -f2 || echo 0)
HEIGHT=$(curl -s --max-time 5 127.0.0.1:19334/info | grep -oE '"height":[0-9]+' | cut -d: -f2 || echo 0)
if [ "${PEERS:-0}" = "0" ]; then
  echo
  echo "    WARNING: the node has no peers and is at height ${HEIGHT:-?}. The site will"
  echo "    work but the explorer will show almost nothing until it syncs."
  echo "    If this machine is behind the same router as your seed nodes, their"
  echo "    public addresses will not resolve back inward on most routers."
  echo "    Re-run with their LAN address, e.g.:  --seed 10.10.10.240:19333"
fi
echo
echo "Site is up on port ${PORT}:  http://$(hostname -I | awk '{print $1}'):${PORT}"
echo "Logs: journalctl -u noct-web -f   |   journalctl -u noctd -f"
