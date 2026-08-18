# Deploying the Nocturnal website + explorer (`noct-web`)

`noct-web` serves the project's landing page and a read-only block explorer. It
is the only Nocturnal process intended to be reachable by the public, so its design
goal is narrow: **be worth nothing to compromise.**

It holds no keys, no wallet and no chain data. It writes nothing to disk. The
site is compiled into the binary, so there is no document root to escape from.
It reads the chain by asking a node you control, and it cannot ask that node to
do anything.

---

## What stops the explorer from becoming an attack path

A node's RPC is an **administrative** interface: `/mine`, `/submitblock`,
`/submit_tx` and `/mining/start` all change state. Putting a web page in front
of it is exactly how that surface gets exposed by accident. Three properties
prevent it here, and each is enforced by construction rather than by care:

1. **The route table is an exhaustive whitelist**, not a filter. `route()` in
   [`../web/src/main.rs`](../web/src/main.rs) matches three literal paths plus
   `/api/block/<u64>`; everything else is `NotFound`. There is no pass-through
   case and no string concatenation into a node URL, so no path — including
   `/api/../mine` — can reach an endpoint that was not written out by hand.
2. **There is no POST handler in the binary.** Not a disabled one; none. Every
   POST is a 405 regardless of path.
3. **The height is parsed as a `u64`** before it reaches the node client, so a
   path component cannot smuggle anything through.

These are covered by tests in the same file (`cargo test -p noct-web`), so a
future edit that adds a pass-through route fails the build rather than quietly
exposing the node.

The node's RPC token, if any, is held by this server and never sent to the
browser. Upstream errors are logged with detail and returned to the client as a
flat `upstream node unavailable` — the node's own error text names the node's
address, and republishing that would map your internal network for visitors.

---

## 1. Prerequisites

- A small Linux host or LXC container (1 vCPU, 512 MB is ample — it does no
  cryptography and keeps no state).
- A reachable `noctd` **RPC**, normally on the same host over loopback. If the
  node is elsewhere, keep the RPC on a private network and give it a token.
- Ports: whatever you serve on (**8080** below, or 80/443 behind a proxy).

## 2. Build and install

```bash
git clone <your-repo> noct-src && cd noct-src/noct
cargo build --release -p noct-web
sudo install -m 0755 target/release/noct-web /usr/local/bin/noct-web
sudo useradd --system --no-create-home --shell /usr/sbin/nologin noct-web
sudo install -m 0644 deploy/noct-web.service /etc/systemd/system/noct-web.service
sudo systemctl daemon-reload && sudo systemctl enable --now noct-web
```

Verify:
```bash
curl -s 127.0.0.1:8080/api/info
systemctl status noct-web
```

`noct-web` does **not** need the `randomx` feature — it never validates a block.

## 3. Confirm the admin surface is unreachable

Do this on every deployment; it is two seconds and it is the whole point.

```bash
for p in /mine /submitblock /submit_tx /mining/start /getblocktemplate /info; do
  printf '%-20s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$p")"
done
curl -s -o /dev/null -w 'POST /mine -> %{http_code}\n' -X POST http://127.0.0.1:8080/mine
```

Every path must print **404** and the POST must print **405**. Anything else
means you are not running the binary you think you are.

## 4. TLS

The site is public and static, so TLS here protects visitors from tampering and
surveillance rather than protecting a secret. Serve it either way:

**Directly:**
```
ExecStart=/usr/local/bin/noct-web \
    --listen 0.0.0.0:443 \
    --node 127.0.0.1:9334 \
    --tls-cert /etc/noct/web.crt \
    --tls-key /etc/noct/web.key
```
Binding 443 as a non-root user needs `AmbientCapabilities=CAP_NET_BIND_SERVICE`
in the unit.

**Behind a reverse proxy** (nginx, Caddy) terminating TLS: keep `noct-web` on
loopback and add `--trusted-proxy <PROXY_IP>` so rate limiting counts the real
client IP from `X-Forwarded-For` instead of charging every request to the proxy's
single address. Only set this for a proxy you actually run — the header is
attacker-controlled otherwise.

## 5. Serving with no domain (IP only)

This works today with no extra steps: point a browser at `http://<HOST_IP>:8080`.
The page is entirely self-contained — no fonts, scripts, or assets are fetched
from anywhere — so it renders correctly with no DNS and no CDN.

Adding a domain later changes nothing in the application: point an A record at
the host and either issue a certificate or put a proxy in front. There are no
absolute URLs in the page to update.

## 6. Options

| Flag | Default | Notes |
|---|---|---|
| `--listen` | `0.0.0.0:8080` | Public bind address. Note the default is **not** loopback: this is the process that is meant to face the network. |
| `--node` | `127.0.0.1:19334` | The node's **admin** RPC. Keep it private. |
| `--node-token-file` | — | Prefer over `--node-token`; command lines are world-readable. |
| `--node-fingerprint` | — | Pin the node's TLS cert when the RPC is remote and TLS. |
| `--tls-cert` / `--tls-key` | — | Must be given together. |
| `--rate-limit` | `120` | Cost units/sec per client IP (a page is 1, an API call is 4). `0` disables. |
| `--trusted-proxy` | — | Only when a proxy you run sits in front. |

Connections are additionally capped at 256 concurrent, the request head at 16 KiB
and 64 headers, and idle sockets are dropped after 15 seconds. See
[the DoS note](#f31-idle-connections) below for why the last one matters.

---

## Publishing to Autonomi (or any serverless network)

Autonomi stores immutable, content-addressed data and runs no server. The live
explorer cannot work there — there is nothing to answer `/api/info`. Visitors
read the site through a local gateway ([AntTP](https://github.com/traktion/AntTP),
[dweb](https://github.com/happybeing/dweb)), so a relative fetch resolves against
*their* gateway, not yours.

`noct-web --emit-static` writes a version that needs no server: the page plus a
`chain.json` snapshot published inside the same archive.

```bash
noct-web --emit-static ./site --node 127.0.0.1:9334
ant file upload -p -x ./site
```

The upload prints an archive address. That address is the site.

### Why a snapshot and not just an API URL

The obvious alternative — leave the explorer live and point it at a public
gateway — works, and quietly defeats the purpose. Every visitor's browser would
connect to whoever runs that gateway, handing them an IP address for each person
who reads a privacy coin's website. People fetch a site from Autonomi precisely
so that reading it tells nobody they read it.

The emitted page therefore fetches **only relative paths**, enforced by the test
`the_page_fetches_only_relative_paths`, which fails the build if an absolute
origin ever appears in the page.

Note that on Autonomi the CSP is served by the visitor's gateway, not by you, so
that header is no longer a guarantee you control. The substantive property — the
page requests nothing off its own origin — holds regardless, which is why it is
enforced in the source rather than only in a header.

### Immutability cuts both ways

Uploaded data cannot be deleted, by you or anyone. For a page whose current job
is carrying "testnet only, unaudited, 50% premine", permanence is mostly a
feature. But note:

- **The snapshot freezes.** The page says "Snapshot taken &lt;date&gt; — not
  live" rather than presenting stale numbers as current. Refresh by re-emitting
  and re-uploading, which yields a **new address**.
- **Every version stays readable forever at its own address.** After mainnet
  launches, the testnet page still exists saying coins are worthless. Publish
  under a name/pointer that you can repoint, and treat the raw archive address as
  a permanent record rather than the thing you advertise.
- Re-read the page copy before each upload as though it will be quoted back to
  you in five years — because it can be.

### Paying, and the key

Uploads are paid in ANT on Arbitrum. The CLI reads an EVM private key from a
`SECRET_KEY` environment variable.

**That key spends real money, so it gets the same handling as the premine key:
never in a cloud-synced folder, never on a command line.** This repository lives
under `OneDrive`, so do not put a wallet key anywhere inside it. Export it into
the environment for the one command that needs it:

```bash
read -rs SECRET_KEY && export SECRET_KEY && ant file upload -p -x ./site && unset SECRET_KEY
```

Check the cost before committing: `ant file cost ./site`.

---

## F31: idle connections

Found while building this server, and present in `noct-poold` and the node RPC
too — all three are fixed.

A per-IP rate limiter is consulted **after** a full request head has been read.
A client that opens a socket and simply never finishes its request therefore
never reaches the limiter, and holds a worker thread and a connection slot for
as long as it likes. Measured against this server before the fix: **256 silent
half-open connections — no bandwidth, no completed requests — put every real
visitor on a 503, indefinitely.**

The fix is a read/write timeout set on the socket at accept time, before the TLS
handshake so a peer cannot stall there either. Verified: after the fix the same
attack degrades the site for one timeout window and then it serves normally
again.

This bounds the attack rather than eliminating it. An attacker willing to
re-open connections every 15 seconds can still occupy slots — but that is
sustained, visible traffic from an address you can block, instead of a handful of
sockets opened once and left. If this server is ever exposed to a hostile
internet rather than a testnet audience, put a reverse proxy with per-IP
connection limits in front of it and use `--trusted-proxy`.

---

## What this deliberately does not do

- **No search box, no address lookup.** An explorer that resolves addresses
  invites people to paste a wallet address into a website, which is the opposite
  of what a privacy coin should encourage. Stealth addresses mean there is
  nothing useful to look up anyway.
- **No analytics, no third-party anything.** A privacy coin whose site loads a
  font from someone else's server reports every visitor to that server. The CSP
  (`default-src 'none'`) makes this a build-time property, not a promise.
- **No transaction submission.** Broadcasting is a wallet's job, over a node the
  user chooses.
