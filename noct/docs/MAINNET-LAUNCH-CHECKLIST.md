# Mainnet launch checklist

What has to be true before Nocturnal mainnet launches, what is already done, and
what remains. Grounded in the code as of 2026-10-08 (v0.3.24-testnet). This is a
map, not an authorization: launching is a one-way door (see §5).

The single switch that *is* the launch is **`MAINNET_SEEDS`** in
`noct/node/src/lib.rs`. It is deliberately empty; `noctd` prints "MAINNET HAS NOT
LAUNCHED" and refuses to lean on seeds while it is (lib.rs ~325), and a test pins
it empty (lib.rs ~3331). Filling it with reachable seed hostnames is the act of
launching. Everything below is what should be true before that line changes.

---

## 1. Frozen and done — the protocol and genesis

These are consensus-visible and settled; changing any of them makes a different
chain, so they must not move after launch.

- **Monetary policy.** `MONEY_SUPPLY = 1,000,000 NOCT`, `ATOMIC_UNITS = 10^12`,
  smooth-emission curve (`emission.rs`). Difficulty is Monero-style
  (window + lag + outlier-cut + 2x clamp), `TARGET_BLOCK_TIME = 120 s`.
- **Premine.** Genesis mints **500,000 NOCT = 50 % of supply** to the founder
  (`block.rs` `PREMINE_AMOUNT`, wired into `MAINNET.premine_amount`). Founder
  **public** spend/view keys are baked in (`PREMINE_SPEND_PUBLIC` /
  `PREMINE_VIEW_PUBLIC`); the one-time secret `r` is published on purpose
  (linking only — spending needs the private spend key). It stays a **transparent
  ring output** (decided 2026-09-30); the founder shields it later with an
  ordinary tx. Pinned by `genesis_is_identical_everywhere_and_immutable` and
  `the_premine_is_inside_the_curve_not_on_top_of_it`.
- **Two pools + turnstile.** Ring (RingCT/CLSAG ring-16, Bulletproofs+) and
  shielded (Orchard/Halo2), with `ring + shielded == emitted` enforced.
- **Ring size 16, exact** (hard-forked pre-launch, 2026-08-16). **Coinbase
  maturity 100** (was the headline §16 gap; fixed and deployed). **Min-fee floor**
  (mempool policy). **Gamma decoy selection** (wired in).
- **Network separation.** Mainnet magic `0x4E4F4354` ("NOCT"), ports 9333/9334;
  testnet `0x544E4354`, 19333/19334 — distinct in every byte and port, pinned by
  tests.
- **Build & release trust.** Linux binaries reproducible (fixed path +
  `--remap-path-prefix`, build-id dropped), **cross-machine reproducibility
  proven**, the release archive reproducible too. `reproducible-build.sh`
  documents the exact environment (Rust 1.85.1, Debian 13/trixie, g++ 14.2.0).
- **Network & tooling shipped.** Joinable-from-outside p2p (proven), mining pool,
  desktop wallet, CLI, web explorer.
- **Adversarial hardening (this session).** p2p connection-flood cap + per-source
  cap; gossip/address-book eclipse resistance; shielded `UnknownAnchor` scoring
  fix; HTTP request-head and response head/body bounds on every server and
  client; pool per-IP connection cap; RPC admin-rail and desktop-IPC audits.

## 2. Hard launch gates — the switch itself

- [ ] **Stand up mainnet seed infrastructure** with **stable DNS hostnames**
  (not raw IPs). A baked-in IP cannot change without reissuing every binary, so
  `MAINNET_SEEDS` must hold hostnames. Needs ≥2 independent public endpoints, as
  testnet has (`seed1`/`seed2`).
- [ ] **Fill `MAINNET_SEEDS`** with those hostnames, update the test that
  currently pins it empty, and cut the release built from that tag. This is the
  launch.
- [ ] **Confirm the baked founder public keys correspond to the securely-held
  private key** at its off-tree location (per memory:
  `C:\Users\MINE\Noct-Founder\mainnet-founder.key`). Verify by deriving the
  public keys from the private key and diffing against the baked constants —
  **do this yourself; the private key must never enter the repo, a build host, or
  a cloud-synced folder.** If the baked keys are ever wrong, the premine is
  unspendable and genesis cannot change after launch.

## 3. Outstanding requirements — the whitepaper's own bar

- [ ] **Professional third-party audit.** The explicit pre-mainnet requirement;
  every release still says "Still unaudited." Brief the auditor that the **50 %
  premine is deliberate policy, not a defect** (it is the most consequential
  economic parameter and every reviewer will raise it), and that **block validity
  depends on the validating node's clock by design** (Monero-like wall-clock FTL,
  kept deliberately so an outage can recover — see roadmap 2026, "I DECLINED the
  median-based FTL").
- [ ] **A long, genuinely adversarial testnet.** Ongoing. This session closed a
  broad set of findings, but the duration/coverage bar is a judgment call: decide
  what "enough" is (e.g. sustained multi-party mining, a shielded-traffic load
  period, a reorg/outage drill) before calling it.

## 4. Should-fix before mainnet — trust & quality, not consensus

- [x] **`SPECIFICATION.md §16` walked (2026-10-09).** Closed: 1 (coinbase
  maturity), 2 (gamma decoys), 3 (PoW gating — `network_requires_randomx`, no
  mainnet override, pinned by a test), 5 (wallet scan state now persisted in
  `wallet/src/state.rs` with reorg-safe refuse-and-rebuild), 9 (min relay fee),
  10 (accepted-not-kept). Reviewed/sound: 7 (difficulty). Accepted decisions, not
  work: 6 (deep-partition resync is manual by design), 8 (atomic-swap crate ships
  in nothing). **Only two items still need action, both tracked above:** §16.4
  (ratify the address tag `0x13`, now locked by the published premine — §2; set
  `GENESIS_TIMESTAMP` near launch — §5) and §16.11 (node holds the whole chain in
  memory — the next item below).
- [ ] **Node memory (§16.11).** Every block is kept in RAM with its decoded
  transactions (~23 KB/block measured), so resident memory grows with chain
  length; only the output set and spent-key-image set are strictly needed.
  Interim mitigation is a raised memory cap on the fleet; the real fix is serving
  blocks from the on-disk log. It sets node hardware requirements, so decide
  before mainnet whether to fix it or document the requirement.
- [ ] **Windows installer: code-signing and the reproducibility gap.** The
  installer is unsigned (SmartScreen warns) and not reproducible — acceptable on
  testnet, weaker for software people will hand real keys to. Decide whether to
  sign it and/or document the gap prominently for mainnet.
- [ ] **Decide the testnet-reset story.** Testnet coins are worthless and the
  chain resets before mainnet; the reset is also where a genesis-affecting change
  would land. Make sure no mainnet-affecting change is still pending that would
  need a genesis change after launch.

## 5. Launch is a one-way door

Once `MAINNET_SEEDS` is live and anyone mines on it, the genesis id and every
consensus constant in §1 are **permanent** — there is no reset and no retrofit
(the same reason v0.1.0–v0.1.3 hashes are never republished). Treat the
mainnet-enabling release as irreversible: build it reproducibly from a pushed
tag, verify the genesis and premine against the held key one last time, and only
then change the seed line.

## Not launch blockers (post-mainnet roadmap)

ETH atomic-swap bridge / wNOCT (`docs/eth-atomic-swap.md`) and the zk Orchard
*pool* alongside the ring pool (`docs/orchard-pool.md`) are future features, not
prerequisites for launch.
