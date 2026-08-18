# Nocturnal (NOCT)

A Monero-style privacy coin in Rust. Confidential amounts, sender ambiguity,
unlinkable one-time recipient addresses, CPU-friendly proof of work.

**Website:** https://nocturnalcoin.com &nbsp;·&nbsp; **Source:** https://github.com/adamanto75/nocturnal

> ### Status: testnet. Unaudited. Read this before anything else.
>
> * **Not launched.** This is a testnet. Coins have no value and the chain will
>   be reset before mainnet.
> * **Unaudited.** Eighteen internal review passes and one independent model
>   review found and fixed real bugs — including an 8.79-second denial of
>   service and a fork-choice rule that disagreed with consensus. Internal
>   review is not a substitute for a professional audit, and none has been
>   commissioned.
> * **50% premine.** The planned mainnet genesis mints 500,000 NOCT — half the
>   supply parameter — to the founder. This is a deliberate policy decision, and
>   it is the single most consequential economic parameter here. Judge it
>   accordingly.
> * **Placeholder parameters.** Mainnet genesis timestamp, address tags and the
>   RandomX seed schedule are not final.

## What it is

Amounts are hidden by Pedersen commitments with Bulletproofs+ range proofs,
senders by CLSAG ring signatures over a fixed ring of 16, and recipients by
one-time stealth addresses with subaddress support. Proof of work is RandomX.

The cryptography is deliberately **not** novel: it uses the `monero-oxide`
crates — Monero's reviewed construction — so that it can be audited by
comparison against a system that has been attacked for a decade. What is new is
the surrounding chain, and that is the part that needs review.

## Naming

The project is **Nocturnal** and the unit is **NOCT**. Every crate, binary and
path is spelled `noct*` — `noct-core`, `noctd`, `/var/lib/noct`. Same thing
abbreviated, not a second project: the short form appears in consensus-visible
constants (address tags, domain separators, network magic `NOCT`), so it is not
renamed. **In code, `noct*` is authoritative.**

## Build

Rust is pinned to **1.82** (no `rustup` assumptions, no edition 2024).

```bash
cargo test --workspace                      # 290 tests
cargo build --release -p noct-wallet --bins # noct-cli, noct-walletd
cargo build --release -p noct-node --features randomx   # noctd with real PoW
```

`--features randomx` needs `cmake` and a C++ toolchain. Without it `noctd`
builds with a Keccak placeholder PoW that **cannot validate the real chain**.

## Run a testnet node

```bash
noctd --network testnet --data-dir ~/.noct-testnet
noct-cli new --network testnet --wallet testnet.key
noct-miner --address <YOUR_TESTNET_ADDRESS> --node 127.0.0.1:19334
```

The node RPC is an **administrative** interface — it can start mining and submit
blocks. Keep it on loopback, or set a token and serve it over TLS. `noctd`
refuses to start with an unauthenticated RPC on a non-loopback address.

## Layout

| Crate | What it is |
|---|---|
| `noct/core` | Consensus: keys, addresses, RingCT, CLSAG, chain, mempool, wire format |
| `noct/wallet` | Wallet library, `noct-cli`, `noct-walletd` |
| `noct/node` | `noctd` — P2P, RPC, block store |
| `noct/pool` | `noct-poold` — PPLNS mining pool |
| `noct/tls` | Shared rustls server/client with certificate pinning |
| `noct/web` | `noct-web` — website and read-only block explorer |
| `noct/swap` | Experimental Monero-style atomic swaps to Ethereum |

## Documentation

* [`noct/docs/SPECIFICATION.md`](noct/docs/SPECIFICATION.md) — normative protocol spec; the reference an auditor diffs against
* [`noct/SECURITY-REVIEW.md`](noct/SECURITY-REVIEW.md) — every internal review pass, every bug found, and the conclusions that turned out wrong
* [`noct/docs/REVIEW-BRIEF.md`](noct/docs/REVIEW-BRIEF.md) — start here if you are reviewing this code
* [`noct/docs/DEPENDENCIES.md`](noct/docs/DEPENDENCIES.md) — the cryptography supply chain

## Security

Found something? Please report it privately rather than opening a public issue:
see the contact in `SECURITY.md`. The security review document is my own
argument about this code, and at least one conclusion in it is probably wrong —
independent disagreement is the point.

## License

MIT — see [LICENSE](LICENSE). Dependencies are MIT and BSD-3-Clause.
