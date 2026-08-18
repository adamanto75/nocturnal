# NOCT ⇄ ETH Atomic Swaps — Feasibility & Design Spike

Status: **research spike** (2026-07-24). No production code yet. This maps the
proven Monero⇄Ethereum atomic-swap construction onto Nocturnal's actual crypto and
records what is reusable, what Nocturnal must add, and the risks.

Decision context: the long-term plan is *both* atomic swaps (trustless, now) and
a wrapped `wNOCT` token (DeFi liquidity, later). This spike covers the atomic-swap
core. Nothing here precludes a `wNOCT` bridge later; they share almost no code.

---

## 1. Verdict

**Feasible, and — importantly — with *no changes to Nocturnal consensus*.** The swap
runs on Nocturnal's existing transaction format (normal RingCT outputs spent with a
single CLSAG). Everything new lives *around* the chain:

- a new **wallet capability**: joint (2-of-2) accounts,
- a **cross-curve DLEQ** dependency (reusable — see §4),
- an **Ethereum swap contract**,
- a **swap daemon** that runs the protocol and watches both chains.

Nocturnal is Monero-shaped (ed25519 spend/view keys, stealth one-time outputs, CLSAG),
so the [AthanorLabs ETH-XMR swap](https://github.com/AthanorLabs/atomic-swap) is a
near-direct blueprint. The heaviest *new* risk is the DLEQ proof and the daemon's
timeout/finality safety — not the chain itself.

---

## 2. The construction (why it works without scripts)

Nocturnal, like Monero, has **no scripting** — you cannot put an HTLC on-chain. The
trick is asymmetric: the **Ethereum contract** carries all the conditional logic,
and the NOCT side needs only a *2-of-2 joint output* whose spend key is the sum of
two secrets. Revealing a secret on Ethereum hands the other party the missing half
of the NOCT spend key.

Roles (following the reference protocol): **Alice holds ETH, wants NOCT. Bob holds
NOCT, wants ETH.**

1. **Keygen + DLEQ (off-chain).** Each party picks a secret scalar (`s_a`, `s_b`).
   Each publishes that secret's public point on **both** curves — `s·G_ed25519`
   (for the NOCT joint account) and `s·G_secp256k1` (for the ETH contract) — plus a
   **cross-group DLEQ proof** that both points share the same scalar. Without the
   DLEQ, a cheater could commit to different secrets on the two chains and steal.

2. **Bob locks NOCT** into the joint account with spend public key
   `S = S_a + S_b` (ed25519). Its spend *secret* is `s_a + s_b`, which neither
   party alone holds. Bob shares the account's **view key** so Alice can detect the
   locked output and (via Nocturnal's ECDH amount encryption) verify the amount.

3. **Alice deploys the ETH swap contract**, locking her ETH, embedding `S_a`, `S_b`
   (secp256k1) and two timeouts `t0 < t1`.

4. **Alice calls `Ready()`** once she has confirmed the NOCT is locked to the
   expected key and amount at sufficient depth.

5. **Bob calls `Claim(s_b)`** → contract checks `s_b·G == S_b`, sends Bob the ETH,
   and *publishes `s_b`*. Alice reads `s_b`, computes `s_a + s_b`, and **spends the
   NOCT**. Swap complete: Alice has NOCT, Bob has ETH.

### Refund paths (no one can get both)
- **Bob never locks NOCT / Alice bails before `Ready()`:** Alice `Refund(s_a)`
  before `t0` → reclaims ETH, revealing `s_a`; Bob then reclaims his own NOCT.
- **Bob never claims after `Ready()`:** after `t1`, Alice `Refund(s_a)`.
- **Alice never calls `Ready()`:** after `t0`, Bob may `Claim()` anyway.
- Contract invariant: `Claim()` and `Refund()` are never simultaneously callable
  (mutually exclusive windows), preventing a mempool-ordering double-take.

### Stated protocol limitations (inherit these)
- **Directional roles.** The NOCT-holder can only be one side of the trade and the
  ETH-holder the other (in the reference impl, XMR-maker / ETH-taker). Not a
  symmetric "send either way" bridge.
- **Liveness / timeout discipline.** Parties must act well inside `[t0, t1]`;
  calling near a boundary risks an indeterminate state. The daemon must never race
  a timeout.
- **Peer-to-peer, needs counterparties.** It's an exchange protocol, not a
  liquidity pool. Bootstrapping makers/takers is a real problem (a `wNOCT` pool
  later is the DeFi-liquidity answer).

---

## 3. Mapping onto Nocturnal's actual crypto

This is the part that makes or breaks feasibility. It maps cleanly:

| Swap needs | Nocturnal today (`noct-core`) | Fit |
|---|---|---|
| Sum of spend keys `S = S_a + S_b` | `PublicKey(EdwardsPoint)` supports point add; `PrivateKey(Scalar)` supports scalar add | ✅ direct |
| Lock funds to a joint address | `address::Address { spend_public, view_public }`; outputs are just points | ✅ pay to a joint address |
| Detect the locked output with a shared view key | `stealth::is_ours` / `expected_output` need only the **view** secret | ✅ view-only scan already exists |
| Verify the hidden amount | RingCT ECDH amount encryption is opened with the shared view key (`tx::ReceivedOutput`) | ✅ |
| Spend the joint output once you hold `s_a+s_b` | one-time spend secret is `x = H_s(rA) + b`; here `b = s_a + s_b`, so `x = H_s(rA) + s_a + s_b`. `stealth::output_secret` computes the `H_s(rA)` part; add the peer's revealed share | ✅ **single-signer** CLSAG — no 2-party signing needed |
| Sign the spend | `ring::Clsag::sign` takes one spend secret `x` | ✅ unchanged |

**Key insight:** because the swap ends with *one* party holding the full combined
secret, Nocturnal needs **no interactive 2-party CLSAG signing**. The reconstructing
party just derives `x = H_s(rA) + s_a + s_b` and signs a normal CLSAG. The
`H_s(rA)` term is computable by both (shared view key + the tx public key `R`).

So the only genuinely new **wallet** primitive is a *joint account*:
- build an `Address` from `S_a + S_b` and a shared view key,
- scan/track its outputs (reuse existing view-key scanning),
- spend once the combined spend secret is known (reuse existing CLSAG).

No changes to blocks, consensus, or the tx format.

---

## 4. What's reusable vs. what we build

**Reusable (do not reinvent):**
- **Cross-curve DLEQ (ed25519 ↔ secp256k1).** This is the hard cryptography, and
  it already exists in the ecosystem Nocturnal is *already in*:
  - **serai `dleq` crate** — Nocturnal already depends on serai's Monero crates, so this
    is the natural, same-provenance choice (verify it exposes the cross-group
    secp256k1↔ed25519 proof / `experimental` feature).
  - alternatives: [go-dleq](https://github.com/AthanorLabs/go-dleq),
    [dleq-rs](https://github.com/noot/dleq-rs),
    [comit cross-curve-dleq](https://github.com/comit-network/cross-curve-dleq)
    (all implement MRL-0010).
- **ETH swap contract + secp256k1 DL-check.** The contract verifies `s·G == S` on
  secp256k1 via the well-known `ecrecover` trick. AthanorLabs' Solidity contract is
  an audited-ish reference to adapt.
- **swapd / swapcli architecture** (libp2p peer discovery, offer book, protocol
  state machine, chain watchers) — adapt the AthanorLabs design; swap the Monero
  RPC calls for Nocturnal's `noct-wallet` + node RPC.

**We build (Nocturnal-specific):**
1. `noct-wallet` **joint-account** module (create / scan / spend). *No consensus
   change.* This is the core new primitive and the right first coding step.
2. A **secp256k1 keypair + DLEQ** helper in a new `noct-swap` crate (or the daemon).
3. The **swap daemon** (`noct-swapd`): protocol state machine, ETH client
   (contract deploy/claim/refund/watch), NOCT client (lock/scan/reconstruct/spend),
   timeout scheduler, crash-recovery (persist swap state so a restart never loses a
   refund window).
4. The **Ethereum contract** (adapt reference) + deployment/verification.
5. A **finality policy** (see §5).

---

## 5. Nocturnal-specific risks & decisions

- **Reorg / finality depth.** Before Alice calls `Ready()` (committing to release
  ETH), the NOCT lock must be buried deep enough that a Nocturnal reorg can't undo it.
  Nocturnal caps reorgs at `MAX_REORG_DEPTH = 100` (`noct-node`), and difficulty retargets
  to a 120 s block target — pick a confirmation depth (e.g. ~10–20 blocks) with
  margin, and set `t0/t1` from *both* chains' expected finality. A young, low-
  hashrate Nocturnal network is **more** reorg-prone, so be conservative early.
- **DLEQ correctness is funds-critical.** A broken/misused DLEQ lets a counterparty
  commit different secrets per chain and take both assets. Use a reviewed
  implementation; never hand-roll it. This is the single highest-risk component.
- **Timeout races.** The daemon must treat `t0/t1` as hard deadlines with generous
  safety margins, survive restarts (persist state), and re-broadcast/retry claims
  and refunds. A missed refund window = lost funds.
- **Amount & key binding.** Alice must verify, before `Ready()`, that the locked
  output is (a) to exactly `S_a + S_b`, (b) the agreed amount (via shared view key),
  and (c) actually spendable (correct commitment). Bake these checks into the daemon.
- **Privacy footprint.** The swap itself leaks little on-chain (the NOCT lock looks
  like an ordinary output; only the two counterparties share the view key). Good —
  this preserves Nocturnal's privacy far better than a transparent `wNOCT` bridge would.
- **The premine optics** don't directly touch a trustless swap (no custodian), which
  is another reason to lead with swaps over a founder-run `wNOCT` custodian.
- **Directional-role UX.** Document clearly that early on NOCT↔ETH is one-directional
  per role; a two-sided market needs both maker and taker liquidity.

---

## 6. Proposed phasing (build order)

1. **Spike → prototype the joint-account primitive** — ✅ **DONE** (`noct-wallet`,
   `src/joint.rs`). `JointContribution` (per-party `s_i`,`v_i`) + `JointAccount`
   (`assemble` sums to `S_a+S_b` / `v_a+v_b`; `into_account` accepts only the full
   `s_a+s_b`, rejecting either half). Nocturnal wrinkle handled: an independent summed
   view key (not `H_s(spend)`), sound because scan/spend only read the key fields.
   Tests prove: both parties derive the same joint address; funds locked to it are
   spendable **only** with the reconstructed sum, swept via an ordinary CLSAG the
   chain accepts. **No consensus change**, as predicted.
2. **DLEQ integration** — ✅ **DONE** (`noct-swap` crate, excluded from the default
   workspace). `SharedSecret::prove(seed)` generates a scalar and proves its
   ed25519 + secp256k1 public keys share it (serai `dleq`, `experimental` +
   `serialize`; `EfficientLinearDLEq<ProjectivePoint, EdwardsPoint>`); `verify`
   returns both points; the ed25519 point's bytes decode as a NOCT joint spend
   half. Tested: prove/verify bind the same scalar, proof round-trips through bytes,
   tampered proof rejected. **Builds on Rust 1.82** — needs `base64ct = "=1.6.0"`
   (newer wants edition2024), `k256` `bits` feature (for `PrimeFieldBits`), and the
   `flexible-transcript` dep renamed to `transcript`. **⚠ The cross-group proof is
   unaudited/experimental** ("no formal proofs") — acceptable for a prototype, must
   be revisited before mainnet (this is true of every cross-curve DLEQ that exists).
3. **ETH contract** — ✅ **DONE (contract + crypto cross-check; live-EVM test
   pending).** `swap/eth/NoctSwap.sol` — a native-ETH, one-swap-per-deployment
   contract adapted from AthanorLabs' SwapCreator (ERC-20/relayer dropped):
   `setReady`/`claim(s)`/`refund(s)` with `timeout1<timeout2`, the exact reference
   timing windows, and the on-chain secp256k1 DL check via Vitalik's
   `ecrecover(0,27,GX,s·GX mod N)` ecmul trick. Compiles clean (solc 0.8.26,
   ~2.7 KB). `noct_swap::eth` provides `point_commitment` (keccak256(x‖y)) +
   `mul_verify`; tests PROVE the DLEQ's secp256k1 output is accepted by the
   contract check and that the ecrecover trick recovers `s·G` for our scalar —
   closing the Rust↔Solidity crypto-integration risk **without a live EVM**.
   **Still to do:** deploy + exercise claim/refund/timeout on a funded testnet
   (Sepolia) with a real EVM harness (hardhat/anvil).
4. **`noct-swapd` daemon** — ◑ **CORE DONE (state machine); I/O wiring pending.**
   `swap/src/protocol.rs` — the pure protocol FSM (`Swap`, `Role`, `State`, `Event`,
   `Action`), no I/O, mirroring `NoctSwap.sol`'s timeline for both roles. Exhaustive
   unit tests: both happy paths, claim-after-timeout1, refund-before-ready,
   refund-after-timeout2, Bob-reclaims-on-refund, clean pre-commit abort, terminal
   inertness, and the safety invariant *Alice never sweeps without Bob's revealed
   secret*. **Still to wire (the I/O edges, need live chains to exercise):** an
   Ethereum JSON-RPC client (deploy/setReady/claim/refund + event watching for
   `NoctSwap.sol`), a Nocturnal client (lock/scan-at-depth/sweep the joint account), a
   timeout driver off the contract's `timeout1/2`, and **persisted FSM state** so a
   restart never misses a refund window. Safety depends on those edges feeding
   depth-confirmed, validated events (documented in `protocol.rs`).
5. **Only after** Nocturnal's own long testnet + audit: security-review the swap stack
   (DLEQ, contract, daemon state machine) as its own audited component, then mainnet.

Do **not** ship any of this against mainnet until Nocturnal itself is testnet-hardened
and audited — a swap stack on an unproven chain multiplies risk.

---

## 7. Building it into the wallet (target UX & the liquidity problem)

North-star UX: **one multi-asset wallet holding NOCT + ETH with an in-app swap**
("deposit ETH, swap to NOCT and back"). Buildable, but with a critical caveat.

- **ETH support is easy:** an Ethereum account is a secp256k1 keypair + RPC; the app
  can show both balances, give an ETH deposit address, and send/receive ETH.
- **The swap is a client to a P2P *market*, not a self-contained converter.** An
  atomic swap needs a **counterparty**; the "Swap" button only works when there is
  liquidity on the wanted side. Bidirectional is possible but each direction needs
  its own liquidity, plus the directional maker/taker role quirk (§2).
- **Instant-feel requires a liquidity layer** (the part people underestimate):
  1. **Maker bots** — someone runs standing two-sided liquidity (holds inventory of
     both assets + price risk). An ongoing ops/business commitment, not a build.
  2. **wNOCT + DEX pool** — smoothest UX, but reintroduces all wNOCT tradeoffs
     (custodial, honeypot, transparent token, privacy boundary) and still needs a
     seeded pool.
- **Costs of one app doing everything:** it now guards **ETH keys + NOCT keys + a
  timeout-critical daemon** (bigger blast radius); and talking to an ETH RPC leaks
  the ETH address and links ETH↔NOCT activity, eroding Nocturnal's privacy (mitigate with
  own node / careful RPC).
- **Structure:** protocol in `noct-swapd`; the desktop wallet is a front-end
  bundling an **ETH account module + noct-swapd + swap UI**. This is the **top layer**
  of the stack — only after the swap rails (§6 steps 1–4) work.

## 8. Open questions to resolve before coding phase 2+

- ~~Does serai's `dleq` expose the cross-group proof usably on our toolchain?~~
  **Answered: yes** — `noct-swap` uses `dleq` 0.4.1 `experimental`+`serialize` on
  Rust 1.82 (with the `base64ct`/`k256 bits`/`transcript`-rename pins). Open follow-
  up: it is unaudited experimental crypto — commission a review or find a proven
  construction before mainnet.
- Confirmation depth & `t0/t1` values as a function of Nocturnal's live hashrate/reorg
  behaviour (revisit after testnet difficulty data).
- Which Ethereum deployment target(s) — L1 mainnet gas cost vs. an L2 for cheaper
  claims/refunds.
- Does Nocturnal want subaddresses anyway (they'd also unlock the future `wNOCT` deposit-
  attribution path)? Independent of swaps, but worth sequencing together.

---

### Sources
- AthanorLabs ETH-XMR atomic swap — https://github.com/AthanorLabs/atomic-swap (protocol.md)
- Gugger, *Bitcoin–Monero Cross-chain Atomic Swap* — https://eprint.iacr.org/2020/1126.pdf
- go-dleq — https://github.com/AthanorLabs/go-dleq · dleq-rs — https://github.com/noot/dleq-rs · comit cross-curve-dleq — https://github.com/comit-network/cross-curve-dleq
- serai `dleq` crate — https://docs.serai.exchange/rust/dleq
