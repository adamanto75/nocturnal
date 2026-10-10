# Nocturnal (NOCT) — third-party security audit brief

Prepared for prospective auditors. Grounded in the code at tag
`v0.3.27-testnet` (commit `8384b5c`). This document exists so a reviewer can
scope and quote the engagement accurately, and so budget is spent on the code
that actually carries risk rather than on re-reviewing audited upstream crates.

---

## 1. What Nocturnal is

Nocturnal is a **pre-mainnet, Monero-style privacy cryptocurrency** implemented
from scratch in Rust (~109k lines across 7 crates; the production code is a
smaller fraction, the rest is tests). It is a complete layer-1: consensus, P2P,
PoW mining, two shielded transaction pools, a wallet, a mining pool, and a block
explorer. There is no smart-contract VM — this is a coin, not a contract
platform, so the audit surface is protocol and cryptography, not Solidity/BPF.

Headline parameters (consensus-frozen; see `core/src/emission.rs`,
`core/src/block.rs`, `core/src/params.rs`):

- **Supply:** 1,000,000 NOCT, 10^12 atomic units, smooth emission curve.
- **Premine:** 500,000 NOCT (50%) minted at genesis to the founder — see §3.
- **PoW:** RandomX (`randomx-rs`), 120 s target block time, Monero-style
  difficulty (window + lag + outlier-cut + 2× clamp).
- **Two value pools with a turnstile:** a transparent-amount **ring** pool
  (RingCT/CLSAG, ring size 16, Bulletproofs+) and a **shielded** pool
  (Zcash Orchard / Halo2). The invariant `ring + shielded == emitted` is
  enforced in consensus (`core/src/chain.rs`).
- **Coinbase maturity 100; max reorg depth 100.**

The whitepaper commits to a professional third-party audit before mainnet; this
is that engagement.

## 2. The two design choices every reviewer will question — stated up front

Please assess these for **correct implementation**, not as defects to be argued
away. Both are deliberate and, after launch, immutable.

1. **The 50% founder premine is intentional economic policy.** It is the single
   most consequential economic parameter and every reviewer raises it. The
   question we want answered is mechanical, not philosophical: is it *exactly*
   50%, minted **inside** the emission curve (not added on top of it), spendable
   **only** by the founder key, and consistent with the turnstile? Correctness
   is pinned by `genesis_is_identical_everywhere_and_immutable` and
   `the_premine_is_inside_the_curve_not_on_top_of_it`. The founder key has been
   verified against the baked public constants (`premine-key-image`).

2. **Block validity depends on the validating node's wall clock, by design.**
   Nocturnal keeps a Monero-like future-time-limit (FTL) against local wall
   time rather than a median-past-only rule. This was a deliberate decision (so
   a stalled network can recover from an outage) and is **not** an oversight.
   We want the reviewer to understand the tradeoff and confirm it cannot be
   abused beyond the known, accepted window — not to flag "uses wall clock" as a
   finding without that analysis.

## 3. Cryptography stack — and what is ALREADY audited (the cost lever)

The most important thing for scoping: **most of the heavy cryptography is
vendored from already-audited upstreams. Do not pay to re-audit it.** What
Nocturnal wrote is the *integration* around those primitives, and that is where
the audit value is.

| Component | Crate / version | Audit status | In scope here? |
|---|---|---|---|
| Orchard shielded circuit (Halo2 Action proof) | `orchard 0.15.5` | Audited upstream by Electric Coin Company / zkSecurity; every release **< 0.14 was yanked** for an unsound circuit, so the pinned ≥ 0.15 line matters | **No** — review our *use* of it, not the circuit |
| RingCT primitives: CLSAG, Bulletproofs+ | `monero-clsag`, `monero-bulletproofs`, `monero-primitives`, `monero-ed25519` (0.1, the monero-oxide first-party extractions of Monero's audited code) | Derived from audited Monero | **No** — review our *use*, not the math |
| RandomX PoW | `randomx-rs 1` (the Monero RandomX) | Mature, widely deployed | **No** |
| Scalar/point arithmetic | `curve25519-dalek 4` | Industry standard | **No** |

**What Nocturnal wrote, and what the audit should focus on:**

- The **turnstile** that ties the two pools together (`ring + shielded ==
  emitted`), and every path that mints, moves, or destroys value across the
  ring/shielded boundary (coinbase shapes, shield/unshield).
- **Stealth addresses & one-time keys** (`core/src/stealth.rs`,
  `core/src/keys.rs`, `core/src/address.rs`), **key images** and double-spend
  prevention (`core/src/ring.rs`), and **decoy/ring-member selection** (gamma
  selector).
- **Consensus rules** (`core/src/chain.rs`): emission, coinbase maturity, reorg
  / rollback correctness, difficulty, the genesis/premine construction, and the
  on-disk block store with body pruning (`node/src/store.rs`).
- The **mempool**, **P2P/transport** (`node/src/transport.rs`), and the
  **HTTP/RPC + mining-pool** network surfaces (`node/src/rpc.rs`, `pool/`).
- The **wallet** (`wallet/`): spend construction, scan-state persistence, key
  handling.

## 4. Recommended scope, priority-ordered

Scope is the main lever on price. A sensible engagement is P0+P1 on the code in
§3 "what Nocturnal wrote," explicitly excluding the §3 vendored circuits.

- **P0 — monetary integrity & consensus.** Emission curve and total-supply cap;
  the turnstile invariant; the premine (exactly 50%, inside the curve,
  founder-only); coinbase maturity; double-spend / key-image uniqueness; reorg
  and rollback correctness; the block store + pruning (serve-from-disk must
  never corrupt or truncate the chain).
- **P0 — the crypto integration glue.** Stealth/one-time key derivation, amount
  commitments and balance, the ring↔shielded boundary, decoy selection
  (anonymity-set quality), nothing-spendable-on-disk guarantees.
- **P1 — network resilience.** P2P eclipse/partition behaviour, mempool bounds,
  DoS on the RPC/pool/wallet HTTP surfaces, connection and rate limits.
- **P1 — wallet.** Key file handling, scan-state persistence integrity, change
  handling, fee floor.
- **P2 — supply-chain / release.** Reproducible build pipeline and release
  integrity (Linux builds are reproducible; see §7).

**Explicitly out of scope** (and why): the Orchard Halo2 circuit, Monero CLSAG
and Bulletproofs+ internals, and RandomX — all audited upstream (§3). The ETH
atomic-swap design (`docs/eth-atomic-swap.md`) and any wNOCT bridge are
post-mainnet and **not** part of this review.

## 5. Known-issue history — what adversarial testing already found and fixed

We run a continuous adversarial testnet; sharing the fixed-finding history so you
can calibrate and avoid rediscovery (details in the test suites and commit log):

- P2P **address-book eclipse** via gossip flooding (per-source quota added).
- **Unbounded mempool** (bounded).
- **HTTP request-head and response head/body** unbounded reads on every server
  **and** client (all bounded).
- Mining-pool **connection flood** and **per-source-IP** monopolisation (capped;
  trusted-proxy aware).
- A **node-memory** growth problem (full chain + bodies held in RAM) — fixed by
  pruning buried block bodies and serving them from the on-disk log.
- A self-inflicted **disk-I/O-under-the-consensus-lock** regression that the
  pruning fix introduced on the block-serving paths (both P2P `GetBlock` and RPC
  `/block` now classify under a brief lock and read off it).

These are fixed and deployed; they indicate the security posture and the kind of
issues we care about, not open items.

## 6. Where to start reading

- `docs/SPECIFICATION.md` — the protocol spec.
- `core/src/` — consensus and crypto (start with `chain.rs`, `emission.rs`,
  `block.rs`, `ring.rs`, `stealth.rs`, `params.rs`).
- `node/src/` — `transport.rs` (P2P), `store.rs` (block store), `rpc.rs`.
- `wallet/`, `pool/` — the client-facing surfaces.
- The test suites are extensive and double as executable documentation of intent.

## 7. Build, test, reproduce

- **Toolchain (pinned):** Rust **1.85.1** (required by `orchard`), Debian 13
  (trixie), g++ **14.2.0**. `rust-toolchain.toml` pins the compiler.
- **Build:** `cargo build --release --features randomx` (the `randomx` feature
  gates real RandomX PoW; without it a Keccak placeholder is used and the node
  refuses to run on a real network).
- **Reproducible Linux builds:** proven cross-machine; `reproducible-build.sh`
  documents the exact environment. Published releases ship
  `LINUX-BINARY-SHA256SUMS.txt` a reviewer can reproduce independently.
- **Tests:** `cargo test` across the workspace.

## 8. What we expect back

A written report with severity-ranked findings (impact + concrete
reproduction), an assessment of the §2 design decisions as implemented, and a
re-review of our fixes. We will remediate and request a fix-verification pass.

## 9. Engaging an auditor — notes on keeping it affordable

- **Scope to §3 "what Nocturnal wrote"**, excluding the vendored circuits. This
  is the single biggest cost lever; an auditor quoting the whole tree including
  Orchard's circuit will quote a multiple of what the real surface needs.
- Expect a **premium for Rust + privacy + zk** expertise; this is not a
  commodity token audit.
- Consider **fixed-scope quotes from several firms**, and confirm the *reviewers*
  (not just the firm) have Rust + RingCT/Halo2 experience and can see sample
  reports. Ask each firm about independence (no token holdings, no paid
  listings) and whether a fix-verification pass is included.

## 10. Contact

Founder / maintainer: the address on file for this repository.
