# Nocturnal testnet

**Coins on this network are worthless, deliberately and permanently.** The
premine is paid to a wallet whose seed phrase is published below, so anybody can
spend it. Nothing here is an asset.

The testnet exists so the thing that eventually launches has already been run in
anger: across real machines, over real networks, through restarts, forks, clock
skew and hostile peers. It runs the **same code** as mainnet — the same genesis
construction, the same premine mechanism, the same emission curve — and differs
only in the constants in [`core/src/params.rs`](../core/src/params.rs). A testnet
that ran different code would not be testing what launches.

## How the two networks are kept apart

Four independent barriers, so no single mistake can merge them:

| | mainnet | testnet |
|---|---|---|
| p2p magic | `0x4E4F4354` (`NOCT`) | `0x544E4354` (`TNCT`) |
| genesis timestamp | 1750000000 | 1760000000 |
| premine | 500,000 NOCT | 50,000 NOCT |
| address prefix | `C…` | `X…` |
| p2p / RPC ports | 9333 / 9334 | 19333 / 19334 |

1. **Magic** — a handshake from the wrong network is dropped before its chain is
   even considered.
2. **Genesis id** — different timestamp *and* different premine, so the chains
   have different roots. A peer that somehow passed the magic check is still
   rejected as a foreign chain.
3. **Address tag** — a testnet address cannot be pasted into a mainnet wallet, or
   the reverse. They are visibly different at a glance: `C…` versus `X…`.
4. **Ports** — both networks can run on one machine without collision.

`noctd` additionally refuses to start if its `--miner-address` belongs to a
different network than `--network`, so a node cannot quietly mine testnet blocks
to a mainnet address.

Verified live: a testnet node told to dial a mainnet node never connects, while
two testnet nodes peer normally.

## Running a testnet node

```bash
noctd --network testnet --data-dir ~/.noct-testnet
```

Defaults follow the network: p2p on `127.0.0.1:19333`, RPC on `127.0.0.1:19334`.
An explicit `--p2p` / `--rpc` still wins. To accept peers from outside, bind p2p
to a public address and leave the RPC on loopback (or set `--rpc-token-file`;
`noctd` refuses to serve an unauthenticated RPC off-box).

If the RPC does face the internet, give it `--rpc-tls-cert` / `--rpc-tls-key` as
well. The token rides on every request, so in plaintext one observed request is
the whole credential — and a wallet's queries are exactly the activity a privacy
coin should not be broadcasting. `noctd` prints its certificate fingerprint at
startup for clients that need to pin a self-signed one; see
`DEPLOY-SEED-NODE.md`. This is testnet, but the habits are the point.

## A testnet wallet

```bash
noct-cli new --network testnet --wallet testnet.key
```

Every `noct-cli` command takes `--network`. A testnet wallet's addresses start
with `X`, and its local validating chain is rooted at the testnet genesis, so it
will not sync against a mainnet node.

## The faucet premine

The 50,000 NOCT genesis premine is spendable by anyone, on purpose. It makes the
allocation independently verifiable and gives the network coins to move around
without waiting to mine them.

```
address: C8g2g3XDmz3N3dgXLgBSwqVNt77cHWHsUp5fzVcGv7sJktzY4J9Vh2Ahrj4G2rnD6nFH5uU2HcaueNMfGixCS1Bn6SfCDY

phrase:  solve leave enact inform twin bleak picture swarm slim animal spell
         evidence memory share index lemon soft drama hire utility scorpion
         tool expand digital
```

> Publishing a seed phrase is *only* ever acceptable because this wallet holds
> nothing of value. Never treat this as a pattern to copy.

Restore it with:

```bash
noct-cli restore --network testnet --mnemonic-stdin --wallet faucet.key
```

The genesis constants derived from that address are checked into `params.rs` and
are reproducible — anyone can regenerate and compare them:

```bash
NOCT_TESTNET_ADDRESS=C8g2g3XDmz3N3dgXLgBSwqVNt77cHWHsUp5fzVcGv7sJktzY4J9Vh2Ahrj4G2rnD6nFH5uU2HcaueNMfGixCS1Bn6SfCDY \
  cargo test -p noct-core print_testnet_genesis_params -- --ignored --nocapture
```

## Seed nodes

`DEFAULT_SEEDS` in [`node/src/lib.rs`](../node/src/lib.rs) is still empty. It has
to be populated with real, always-on hosts (and the binaries rebuilt) before the
testnet can bootstrap itself; until then nodes need `--peer` to find each other.
Deployment scripts live in [`deploy/`](../deploy/).
