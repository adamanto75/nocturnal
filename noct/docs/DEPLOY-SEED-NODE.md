# Deploying a Nocturnal seed node (testnet bootstrap)

A **seed node** is a public, always-on `noctd` that new nodes connect to first in
order to discover the rest of the network. Bootstrapping a decentralized network
needs at least one reachable seed; two or three in different locations is better,
so no single host is a single point of failure.

This runbook stands one up on a Linux VPS. The artifacts it uses live in
[`../deploy/`](../deploy): a hardened `noctd.service` systemd unit and
`install-seed-node.sh`.

> **Scope.** Everything here you run on *your* server — provisioning a host and
> opening a firewall port needs your cloud account, so it can't be automated from
> the build machine. The package makes it a copy-paste.

---

## 1. Prerequisites

- A small Linux VPS with a **static public IP** (1–2 vCPU, 2 GB RAM is plenty for
  a non-mining seed; the RandomX *verifier* is light — the 2 GB dataset is only
  built when mining).
- Ports: **9333/tcp inbound open** (P2P). Leave **9334 (RPC) closed** — it is
  bound to localhost by design and exposes mining/submit control.
- Build toolchain on the server (or build elsewhere and copy the binary — it must
  be a Linux build):
  ```bash
  sudo apt-get update && sudo apt-get install -y build-essential cmake git curl
  # Rust pinned to 1.82 (matches the workspace toolchain):
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.82.0
  . "$HOME/.cargo/env"
  ```

## 2. Install

```bash
git clone <your-repo> noct-src && cd noct-src/noct
sudo ./deploy/install-seed-node.sh
```

The script builds `noctd --features randomx` (real PoW), installs it to
`/usr/local/bin/noctd`, creates a `noct` service user and `/var/lib/noct`, and
installs + starts the `noctd` systemd service. It prints the node status and the
next steps below.

Verify it's up:
```bash
systemctl status noctd
curl -s 127.0.0.1:9334/info        # {"height":…,"peers":…,"tip":…}
```

## 3. Open the firewall

Open **9333/tcp inbound** in your cloud provider's security group / firewall, and
on the host if one is enabled:
```bash
sudo ufw allow 9333/tcp
```
Confirm from another machine:
```bash
nc -vz <PUBLIC_IP> 9333        # should connect
```

**Do not** open 9334. The RPC is an admin surface (mining control, tx/block
submission). Reach it only over SSH, e.g. `ssh -L 9334:127.0.0.1:9334 user@host`.

### If you need the RPC reachable off-box (remote miners / a pool)

`noctd` **refuses to start** with a non-loopback RPC address unless a token is
set, so an unauthenticated RPC cannot be exposed by accident. To serve it:

```bash
sudo install -d -o noct -g noct -m 0700 /etc/noct
openssl rand -hex 32 | sudo tee /etc/noct/rpc-token >/dev/null
sudo chown noct:noct /etc/noct/rpc-token && sudo chmod 0400 /etc/noct/rpc-token
```

Then in the unit's `ExecStart`, use `--rpc 0.0.0.0:9334 --rpc-token-file
/etc/noct/rpc-token`, open 9334, and give clients the token.

**Turn TLS on at the same time.** The token is a bearer credential sent on
*every* request, so over plaintext a single observed request hands an attacker
the node's entire RPC — and a wallet syncing through it reveals exactly the
activity Nocturnal exists to keep private. `noctd` will run without it and says so
loudly at startup; do not leave it that way.

With a domain name, use an ordinary certificate:

```bash
# in ExecStart
--rpc 0.0.0.0:9334 --rpc-token-file /etc/noct/rpc-token \
--rpc-tls-cert /etc/letsencrypt/live/seed.example.com/fullchain.pem \
--rpc-tls-key  /etc/letsencrypt/live/seed.example.com/privkey.pem
```
```bash
noct-miner --address <B58> --node https://seed.example.com:9334 --token-file ./rpc-token
noct-cli   balance --node https://seed.example.com:9334 --node-token-file ./rpc-token
```

Without one, generate a self-signed certificate and publish its fingerprint —
`noctd` prints it at every startup — and have clients pin it:

```bash
noct-poold --tls-generate /etc/noct --tls-names seed.example.com,203.0.113.7
```
```bash
noct-miner --address <B58> --node https://203.0.113.7:9334 \
           --node-fingerprint <SHA256> --token-file ./rpc-token
```

(`--tls-generate` lives on `noct-poold` but produces an ordinary PEM pair that
`noctd` accepts.) There is deliberately no flag to skip verification.

Prefer the `*-file` flags throughout: a token passed on the command line shows up
in the process list and shell history.

A TLS-terminating reverse proxy or a VPN/SSH tunnel remains a fine alternative —
but a plaintext RPC across the public internet is not.

**Rate limiting.** Every source IP gets a refilling budget, with expensive calls
(`/getblocktemplate`, `/submitblock`, `/submit_tx`) charged 10× a status read, so
one client cannot monopolise the consensus lock. The default
(`--rpc-rate-limit 2000` units/s, burst 2×) is far above real mining load — a
mainnet miner needs roughly 10 units/s — and over-quota callers get `429` with
`Retry-After`. Raise it if you host many miners behind one NAT (they share an
IP), or set `0` to disable. `noct-miner` treats `429` as transient and retries a
solved block rather than discarding it.

## 4. Run more than one seed, peered together

Deploy the same way on 2–3 hosts. Then peer them so they form a mesh from the
start: on each seed, add the *others* to the unit's `ExecStart`:
```
    --seed 203.0.113.20:9333 \
    --seed 198.51.100.30:9333 \
```
then:
```bash
sudo systemctl daemon-reload && sudo systemctl restart noctd
```
Each node also learns further peers automatically via peer exchange; `--seed`
just guarantees a warm start.

## 5. Point clients at your seeds (`DEFAULT_SEEDS`)

New nodes and the wallet auto-connect to the addresses baked into
[`node/src/lib.rs`](../node/src/lib.rs) `DEFAULT_SEEDS`. Once your seed IPs are
stable, add them:

```rust
pub const DEFAULT_SEEDS: &[&str] = &[
    "seed1.noct.example:9333",   // prefer a DNS name over a bare IP,
    "seed2.noct.example:9333",   // so you can re-point without a rebuild
];
```

Prefer **DNS names** (e.g. an A record per seed) so you can move a seed to a new
IP without shipping a new binary. Then rebuild and redistribute the clients:

```bash
cd noct
# node + wallet binaries:
cargo build --release -p noct-wallet --bins
./build_rx.bat        # (Windows) RandomX noctd; on Linux: cargo build --release -p noct-node --features randomx
# desktop installer (Windows): cd ../desktop && npm run dist
```

Nodes can always override at runtime with `--seed …` (add) or `--no-default-seeds`
(ignore the baked list).

## 6. Operate

| task | command |
|------|---------|
| status / logs | `systemctl status noctd` · `journalctl -u noctd -f` |
| height & peers | `curl -s 127.0.0.1:9334/info` |
| upgrade | `git pull && sudo ./deploy/install-seed-node.sh` (rebuilds + restarts) |
| stop / start | `sudo systemctl stop noctd` · `start` |
| data location | `/var/lib/noct` (chain store; safe to back up) |

The unit restarts the node on failure and on boot. The block store persists
across restarts and re-validates on replay.

## 7. Security notes

- **RPC stays on localhost.** The systemd unit binds `--rpc 127.0.0.1:9334`. If
  you do move it off-box, a token is mandatory (`noctd` will not start without
  one) and TLS should be too — see §3.
- **Bans are prefix-based.** A misbehaving peer is banned by the address it
  actually connected from: the single address for IPv4, the whole **/64** for
  IPv6 — a subscriber is routinely handed an entire /64, so banning one address
  out of it would achieve nothing. Loopback stays per-port so local multi-node
  testing works. Nothing to configure; it is worth knowing before you wonder why
  a ban seems to cover more than one address.
- The unit runs `noctd` as an unprivileged `noct` user under systemd sandboxing
  (`ProtectSystem=strict`, `NoNewPrivileges`, private tmp/devices, write access
  limited to `/var/lib/noct`).
- A seed node holds **no wallet key** and mines nothing by default — it only
  relays blocks/transactions and answers peer discovery. If you want a seed to
  also mine, add `--mine --miner-address <B58>` to `ExecStart` (this builds the
  ~2 GB RandomX dataset and uses real CPU).
- This is **pre-mainnet**. The network parameters (genesis, address tags, RandomX
  seed) are still placeholders (see `docs/SPECIFICATION.md` §16); a mainnet
  launch will reset the chain, so treat this deployment as the testnet.
