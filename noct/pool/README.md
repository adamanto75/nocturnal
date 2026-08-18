# noct-pool — mining pool

A pool lets small miners share the variance of block discovery: instead of
waiting a very long time for a whole block, each miner is paid for *shares* —
solutions to a deliberately easier target that prove work was done.

Two pieces:

| | |
|---|---|
| **`noct_pool`** (library) | the part that must be right: share validation and reward division. No I/O, generic over the proof of work, tested with the cheap Keccak placeholder. |
| **`noct-poold`** (daemon) | polls a node for templates, serves miners, submits found blocks. |

## Running it

```bash
# 1. a node (its RPC is authenticated, so the pool needs the token)
noctd --rpc 127.0.0.1:9334 --rpc-token-file ./token

# 2. the pool, paid at an address it controls
noct-poold --address <POOL_ADDRESS> \
           --node 127.0.0.1:9334 --node-token-file ./token \
           --listen 0.0.0.0:9500 --share-difficulty 5000

# 3. any miner — the pool speaks the node's own miner API, so the stock
#    miner works unmodified. `--address` is where that miner gets paid.
noct-miner --address <MINER_ADDRESS> --node <POOL_HOST>:9500
```

## Facing the internet: turn TLS on

The commands above are plaintext, which is fine on a LAN and **not fine** on the
internet. Every request a miner makes carries the address it wants to be paid at,
so without TLS anyone positioned between the miner and the pool can rewrite that
address and take the income — and the miner sees nothing wrong, because its
shares keep being accepted. It just never gets paid.

**With a domain name**, get a certificate the ordinary way (certbot, acme.sh,
Caddy) and point the pool at it. Miners need no extra flags:

```bash
noct-poold --address <POOL_ADDRESS> --listen 0.0.0.0:9500 \
           --tls-cert /etc/letsencrypt/live/pool.example.com/fullchain.pem \
           --tls-key  /etc/letsencrypt/live/pool.example.com/privkey.pem
```
```bash
noct-miner --address <MINER_ADDRESS> --pool https://pool.example.com:9500
```

**Without a domain name**, generate a self-signed certificate and publish its
fingerprint. Miners pin it — the SSH host-key model: nobody vouches for the
identity, but the same identity is checked on every connection, and an
interceptor cannot produce a matching certificate.

```bash
noct-poold --tls-generate /etc/noct --tls-names pool.example.com,203.0.113.7
```

That prints the fingerprint to publish. Miners then use:

```bash
noct-miner --address <MINER_ADDRESS> --pool https://203.0.113.7:9500 \
           --pool-fingerprint <SHA256>
```

There is deliberately no flag to skip verification. A miner given no fingerprint
for a self-signed pool refuses to connect, which is the correct outcome: the
alternative is a flag everybody turns on, and then TLS is just a slower way to
send plaintext.

**Behind a reverse proxy** (nginx, Caddy) terminating TLS instead, bind the pool
to localhost and tell it which address the proxy is:

```bash
noct-poold --address <POOL_ADDRESS> --listen 127.0.0.1:9500 --trusted-proxy 127.0.0.1
```

`--trusted-proxy` is not optional in that deployment. Without it every miner
appears to come from the proxy, so the per-IP rate limiter meters the entire pool
through one bucket and throttles everybody at once. With it, `X-Forwarded-For` is
believed **only** from the listed addresses — never from a miner, which could
otherwise mint itself an unlimited number of rate-limit buckets.

The pool's own link to the node can be encrypted the same way
(`--node https://… --node-fingerprint …`), which matters when they are not on the
same machine: the RPC token is sent on every request.

`GET /stats` reports the current job, share target, blocks found, and each
miner's share of the payout window.

**Everything must be built on the same proof of work.** A node, pool, and miner
that disagree cannot work together — the miner's shares are simply never valid.
`build_rx.bat` builds all three on RandomX for exactly this reason. The daemons
also advertise their PoW in `/getblocktemplate`, and `noct-miner` refuses to
start against a mismatch rather than grinding uselessly.

## How payment is decided

Shares are paid **PPLNS**: the last N shares (8192 by default) split the reward,
rather than only those since the last block. Paying per-round would reward "pool
hopping" — mining only at the start of rounds, where a proportional scheme
over-pays — so a sliding window is what makes that unprofitable.

Two properties the library guarantees, both covered by tests:

- **A share is paid once.** Submissions are re-hashed by the pool, and a repeated
  nonce is rejected. Otherwise one lucky nonce could be resubmitted forever.
- **A split loses nothing.** Proportional division is floored and the remainder
  handed out largest-first, so the payouts sum to *exactly* the reward. Naive
  rounding makes a pool leak atomic units on every block.

## Payouts

Pass `--wallet` and the pool settles its own books. The safety argument, in order:

1. **A round owes nobody until the chain buries it.** Pool income is a coinbase
   output — unspendable for `COINBASE_MATURITY` (60) blocks, and erasable by a
   reorg before then. Rounds are held, then credited.
2. **The intent to pay is persisted before anything is sent.** Sending money and
   recording that you sent it cannot be atomic, so the balance is reserved first.
3. **An interrupted payment is never silently repaid.** On restart, anything left
   in flight becomes `unresolved`: not refunded, not retried, surfaced for a human
   to reconcile against the chain. Paying twice cannot be undone; paying late can.
4. **The fee comes out of the payment**, split proportionally. A pool owes miners
   the entire block reward, so it holds nothing of its own to pay a fee with —
   this is not optional bookkeeping, it is the difference between payouts working
   and every one failing with `InsufficientFunds`.

Miners are paid in batches (one transaction, one shared fee) once they clear
`--payout-threshold`. `/stats` shows outstanding balances and any unresolved
payments; the ledger file is plain text and readable.

## Private pools: registering miners

By default the pool is open — anyone can attach and be paid at whatever address
they send, which is how public pools work and is deliberate. For a private, solo
or invite-only pool, register the miners instead:

```bash
noct-poold --add-miner <MINER_ADDRESS> --miner-auth ./miners.txt --label alice-home
```

That mints a token and prints it. Give it to the miner, who mines with:

```bash
noct-miner --pool https://pool.example.com:9500 --token-file ./my-token --worker rig-1
```

Then start the pool with `--miner-auth ./miners.txt`. Two things change:

- **Anonymous miners are refused**, including on `/stats` — a pool that
  registers its miners is a private one, and its stats say who is mining, to
  which address, and how much they earn.
- **The token decides the payout address, and the request cannot override it.**
  `--address` is ignored. A miner cannot mine to an address you never
  registered, and cannot be confused with, or impersonate, another miner.

Revoking a miner is deleting its line and restarting — which is the thing an IP
ban cannot do, since a ban also removes everyone else behind the same router.

**Tokens are secrets sent on every request, so run TLS.** The daemon warns
loudly at startup if credentials are configured without it.

## Worker names

`--worker <name>` names a rig. It costs nothing and is worth setting whenever one
person runs more than one machine: without it, every rig under a payout address
shares a single vardiff assignment, and a difficulty averaged across a fast rig
and a slow one suits neither.

Worker names affect **only** how share rates are measured and what `/stats`
reports per rig. Payment is decided per payout address and nothing about a worker
name can change it — several rigs are still one payee.

## Operator fee

`--fee-percent 1.5` keeps 1.5% of each block before the rest is split among
miners. It defaults to **zero** — a pool that took money without being told to
would be indefensible.

No transfer is involved: the whole coinbase already pays the pool's own address,
so the operator's share is simply the part never credited to a miner. The fee and
the miners' pool sum to exactly the block reward, at every reward and every rate,
and the rounding remainder always goes to the miners.

The rate and the running total are reported on `/stats` (`fee_percent`,
`operator_earned`, `operator_pending`) and printed at every startup whether or
not one is set. A fee a miner cannot check is the thing that makes people
distrust pools.

The operator's cut is realised only when a round matures, at exactly the moment
the miners' is — before that, a reorg can still erase the block.

## Not built yet

Nothing outstanding for the pool itself. The wider open item is the professional
audit; see `../SECURITY-REVIEW.md`.
