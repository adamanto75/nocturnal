# Nocturnal — Internal Security Review (Pre-Testnet Pass 1)

Adversarial correctness/security review of the `noct-core` protocol and `noct-wallet`,
covering all 14 modules. Conducted as a self-review with four independent reviewer
passes over the money-critical surface (inflation/balance, double-spend/key-images,
malleability/signature-binding, stealth/keys/consensus/PoW), each finding
cross-checked against the source. **Not** a substitute for the professional audit
planned before mainnet — see "Scope & limits".

## Summary

The core cryptographic construction is sound. The double-spend / key-image surface
and the signature/hash binding surface were each reviewed independently and found to
have **no exploitable defect**. One **High-severity inflation bug** was found and
fixed, plus two medium consensus/privacy gaps and several low-severity hardening
items.

All findings below marked **Fixed** are addressed in the tree, with regression tests
where the defect was exploitable. Test count after fixes: **84** (79 core + 5 wallet),
`cargo test` green, zero warnings.

---

## Findings

### F1 — Coinbase amount overflow → inflation — **HIGH — Fixed**

`Coinbase::total()` summed attacker-controlled `u64` output amounts with an unchecked
`.sum()`. Coinbase output amounts are supplied by whoever produces the block (reachable
over the wire via `p2p` → `add_block`). A crafted multi-output coinbase with amounts
`2^63` and `2^63 + allowed` sums to `2^64 + allowed`, which **wraps to `allowed`** in
release builds — so `is_valid(allowed)` passed while the outputs carried their real,
enormous amounts into the global output set, later spendable through ordinary RingCT.
Net: mint ~`2^64` atomic units against a legitimate reward of ~`2^44`. In debug builds
the same `.sum()` **panics**, i.e. a consensus-halting DoS.

Confirmed independently by all four reviewer passes. The fee/subsidy paths were already
`checked_add`; only this sum was missed.

**Fix:** `Coinbase::total()` now returns `Option<u64>` via `checked_add`; `is_valid`
requires `total() == Some(allowed_reward)`. Regression test
`block::coinbase_amount_overflow_is_rejected`.

### F2 — No future-timestamp limit → difficulty collapse — **MEDIUM — Fixed**

Block timestamps were bounded only from below (median-time-past). A miner could set a
timestamp far in the future; the next difficulty retarget divides accumulated work by
`elapsed = ts_last − ts_first`, so a huge timestamp collapses difficulty to
`MIN_DIFFICULTY = 1`, after which `check_hash` accepts any PoW. This does not win fork
choice (each low-work block adds only 1 to cumulative difficulty) but degrades
difficulty integrity and enables cheap block spam on a followed chain.

**Fix:** added `FUTURE_TIME_LIMIT` (2 h) and a check in `add_block` rejecting
`timestamp > now + FUTURE_TIME_LIMIT`. Regression test
`chain::far_future_timestamp_is_rejected`. (Monero additionally uses a median-based FTL;
that refinement can layer on.)

### F3 — Non-canonical / torsion point decoding — **LOW — Fixed**

`PublicKey::from_bytes` and `KeyImage::from_bytes` used bare `decompress()`, which
accepts non-canonical `y` (≥ p) encodings and torsion / small-order points. This allowed
address malleability (two byte strings → same key, checksum recomputable) and admitted
non-prime-order points as keys. Not demonstrably exploitable for theft (stealth
derivation cofactor-clears; the key-image path is torsion-checked inside CLSAG verify),
but an input-hygiene gap.

**Fix:** both decoders now reject non-canonical encodings (re-compress equality) and
non-`is_torsion_free()` points.

### F4 — Unchecked emission accumulation — **LOW — Fixed**

`self.emitted += subsidy` used unchecked `+=`, inconsistent with the surrounding
`checked_add` discipline. Only reachable after emitting ~`2^64` units (astronomically
many blocks), so not practically exploitable.

**Fix:** `saturating_add`.

### F5 — txid covers malleable signature encodings — **LOW (latent) — Addressed**

`Transaction::hash()` covers the CLSAG and Bulletproofs+ byte encodings, so a wire
deserializer that accepted non-canonical scalar/point encodings would reopen txid
malleability. **Addressed** by the strict decoder in `core/src/wire.rs`: every
Nocturnal-level point (public key, commitment, key image, pseudo-out, ring member) is decoded
through the canonical + prime-order `from_bytes` checks, trailing bytes are rejected, and
lengths are never trusted for allocation. Serai's `Clsag::read` / `Bulletproof::read_plus`
handle the proof-internal scalars/points (canonical scalar reads; key-image torsion is
additionally enforced in CLSAG verify). Round-trip + reject-non-canonical + reject-trailing
tests in `wire`.

### F6 — Merkle tree-shape ambiguity — **LOW (latent) — Fixed**

A Merkle root does not pin the *shape* of its tree: `root([X, C]) == root([A, B, C])`
when `X = keccak(A‖B)`, so a shorter leaf list of interior nodes hashes identically.
Exploiting it needs a leaf preimage, so it was never practically reachable.

Originally slated to be "fixed" by porting Monero's exact `tree_hash` — but on
inspection Monero's tree has the **same** property, so that port would have bought
compatibility we don't want (Nocturnal is not Monero-wire-compatible) and no security.

**Fixed** properly instead by committing the **leaf count** alongside the root in
`Block::hashing_blob`, which pins the tree shape outright for four bytes — something
Monero does not do.

### F7 — `KeyImage::from_bytes` torsion (latent reopening) — **LOW — Fixed (with F3)**

`KeyImage::from_bytes` has no caller today, but once a wire path deserializes key images,
a torsioned variant of a spent image could enter `spent_key_images` as a distinct entry
(bypassing the spent-set) unless it is forced through CLSAG verify. Hardened alongside F3
(the decoder now rejects torsion/non-canonical), and the `wire` decode path routes key
images through `KeyImage::from_bytes` (canonical + torsion) and the transaction through
`Transaction::verify` → `Clsag::verify` before it is trusted.

---

### F8 — Unbounded difficulty retarget → chain can become unmineable — **MEDIUM — Fixed**

Found during node integration testing (not the static review). The retarget
`next = work · TARGET / elapsed` had no per-step bound, so a run of blocks with
near-instant timestamps (elapsed ≈ 0) multiplies difficulty by a large factor
*every block*, compounding within a handful of blocks to a value no one can mine —
a liveness/consensus failure. Two peered nodes mining rapidly reproduced it (a test
block took hours).

**Fix:** clamp each retarget to at most `MAX_DIFFICULTY_STEP` (2×) up or down versus
the previous block's difficulty (`pow.rs`). This damps volatility and self-stabilizes
the miner. The existing retarget unit tests remain green (their swings were already
within 2×). A full port of Monero's damped windowed algorithm remains on the
pre-testnet list.

### F9 — No minimum ring size → transparent transactions — **MEDIUM — Fixed**

A transaction input could carry a ring of size 1 (no decoys), fully deanonymizing the
spender and polluting the anonymity set of anyone who draws it as a decoy.

**Fix:** `chain.validate_tx` rejects any input ring smaller than `MIN_RING_SIZE`
(placeholder 11; Monero mandates 16). Enforced for both mempool admission and block
validation. Regression test `chain::ring_below_minimum_is_rejected`.

### F10 — No canonical genesis block / network id — **MEDIUM — Fixed**

Surfaced by live fork-resolution testing, not the static review. Nocturnal has **no fixed
genesis**: every node mines its own block 0 with its own coinbase. Two independently
started nodes therefore share *no* history, and "reorg" degenerates into one node
adopting the other's entire chain from height 0 (observed live: a node dropped both its
blocks and took a peer's 6).

Reorg behaved correctly given the inputs, but the underlying property was wrong for a
real network: chain identity was not pinned, so a node could be convinced to adopt
**any** heavier chain from scratch, including one from a different network entirely.

**Fixed:**
* `Block::genesis()` — a canonical, hardcoded block 0 that every chain is rooted at.

  > ⚠️ **CORRECTED 2026-08-15 — this paragraph was factually wrong and is the most
  > important correction in this document.** It originally read: *"It pays nothing
  > (no outputs, no reward), so there is no premine and no key that could claim
  > genesis coins; emission still starts in full at block 1."*
  >
  > That was true when F10 was written and **has not been true since the premine
  > landed**. Genesis now carries a **single coinbase output of `PREMINE_AMOUNT`
  > = 500,000 NOCT — 50% of the supply parameter — to the founder keys baked into
  > `ChainParams`**, and the emission curve continues from that baseline rather
  > than starting from zero (see Pass 13). The claim was never revisited when the
  > code moved.
  >
  > Found by the independent review, not by the author. It is exactly the F28
  > failure mode applied to prose instead of code: a conclusion that was correct
  > when written, left standing after the thing it described changed. An auditor
  > reading only this pass would have concluded there is no premine — about the
  > single most consequential economic parameter in the project.

  The genesis coinbase is subject to the same `COINBASE_MATURITY` rule as any other
  (see Pass 3), and its `tx_public` comes from a published `GENESIS_TX_SECRET`, which
  is what makes the premine output auditable by anyone rather than merely asserted.
* `Blockchain::new` applies genesis directly — it is the axiom the consensus rules are
  defined against and cannot be validated by them — so every node starts at height 1
  with the same root.
* Genesis is **immutable**: `rollback_to` clamps to height 1, and `try_reorg` rejects
  any branch forking at height 0 (`CannotReplaceGenesis`). A chain that does not
  descend from our genesis can never be adopted, however much work it carries.
* `NETWORK_ID` is advertised in `Wire::Tip` and a foreign network's tip is ignored —
  a fast explicit rejection layered over the genesis guarantee.

Note for readers of the live logs: two same-network nodes resolving a fork at height 1
still looks like "dropped N, applied M". That is now *correct* fork choice between peers
sharing a root, not the identity failure described above.

## Surface reviewed and found clean (no code change)

- **Inflation / balance:** every confidential output is mandatorily range-proven;
  the RingCT balance `Σ pseudo-outs == Σ outputs + fee·H` holds; pseudo-outs are tied to
  real ring-member amounts via CLSAG's commitment-to-zero; the fee is bound in both the
  signing message and the balance equation. (Only F1 broke amount binding, at the
  coinbase.)
- **Double-spend / key images:** key image `I = x·H_p(P)` is uniquely determined and
  torsion/identity-checked on the mandatory verify path (serai CLSAG); coverage is
  complete across intra-tx, intra-block (`block_images`), and cross-block
  (`spent_key_images`); state commit is atomic-after-validation (no corrupt state on a
  rejected block); mempool conflict + eviction correct.
- **Malleability / signature binding:** `signing_message` binds every semantically
  relevant field (version, R, fee, per-input key image + full ring, every output incl.
  encrypted amount, range proof); `pseudo_out` is bound inside CLSAG; `block.id()` /
  PoW commit to the coinbase and every tx hash via the Merkle root; `add_block`
  re-derives and checks tx hashes; all manual serializations are length-prefixed
  (no concatenation ambiguity).
- **PoW `check_hash`:** the 256-bit `h · difficulty < 2^256` test is correct at all
  boundaries; no `u128` overflow; checked against node-computed difficulty, not a
  block-supplied value.
- **Stealth:** cofactor clearing is symmetric across sender/recipient; detection implies
  spendability (no detect-but-can't-spend divergence); crafted-point torsion is
  annihilated by the ×8.
- **P2P:** transactions/blocks are fully validated before relay; gossip terminates via
  seen-set dedup; no panic on peer input in the pure `Node` logic.
- **Wallet:** global-index reconstruction matches the chain's assignment order; spent
  marking and change handling correct.

---

## Scope & limits

- Assumes the correctness of the underlying audited/maintained primitives
  (`curve25519-dalek`, serai's `monero-bulletproofs` / `monero-clsag`). Their internals
  were not re-audited here. Recall these are consumed via the community `-mirror` crates;
  **repin to an upstream serai git revision (or the audited crates) before mainnet.**
- This is a first internal pass, not the professional audit. It did not include
  formal verification, fuzzing, side-channel/timing analysis, or economic/game-theoretic
  modeling.
- Known accepted simplifications remain (RandomX stubbed by Keccak; embedded rings vs.
  offset references; no wire serialization; simple difficulty retarget; heuristic gamma
  decoys; reorg execution deferred) — tracked separately in the build roadmap, not
  security findings.

## Remaining security-relevant hardening before testnet

1. ~~Wire-format deserializer must reject non-canonical encodings~~ — **done** (`wire.rs`).
2. ~~Merkle shape ambiguity~~ — **done** (leaf count committed; the Monero `tree_hash`
   port was dropped as cargo-cult: same property, no compatibility benefit).
3. ~~Difficulty outlier-cut + lag~~ — **done** (`pow.rs`: lag, trim, and step clamp).
4. ~~Reorg execution with per-block undo~~ — **done** (`chain.rs`: `rollback_to` /
   `try_reorg`, validated against a copy so a bad or lighter branch cannot corrupt state).
   **Still open:** wiring reorg into P2P — a node has no way to *discover* a competing
   branch (block requests are by height, which is ambiguous across forks), so the
   mechanism exists but nothing triggers it yet.
5. ~~Real RandomX~~ — **done and wired into `noctd`** (`cargo build -p noct-node
   --features randomx` in an MSVC/cmake env → the daemon mines and verifies on real
   RandomX; verified live). Default build stays Keccak/no-C++-toolchain. RandomX
   **seed/epoch rotation is done** — `pow::randomx_seed_height` schedule, the chain
   rekeys the PoW per block via a default-no-op `ProofOfWork::reseed`, VMs cached per
   epoch. Still to do for miners: `FLAG_FULL_MEM` (~2 GB dataset) for speed.
6. Median-based future-time-limit; raise `MIN_RING_SIZE` toward Monero's 16; proper
   Dandelion stem successor graph; canonical genesis is done (F10).

---

# Nocturnal — Internal Security Review (Pass 2: Networking & Mining)

Covers the code added after Pass 1: real RandomX multi-threaded mining
(`randomx/`, `node/src/miner.rs`), peer discovery / handshake / address book /
ban-scoring / rate-limits (`node/src/transport.rs`), the new wire messages
(`core/src/{p2p,wire}.rs`), and the block-sync fix in `node/src/lib.rs`.

## Findings

### F11 — Peer gossip could advertise non-routable addresses — **MEDIUM — Fixed**

The address book learned every address a peer gossiped (`Wire::Peers`) or advertised
in its handshake, unfiltered. A remote peer could therefore make a node dial
loopback/private/link-local addresses — probing services on the node's own host or
LAN (an SSRF-style vector), or flooding its book (capped at 1024) with unreachable
junk to crowd out real peers.

**Fixed:** `Discovery::learn_gossip` filters untrusted gossip through
`routable()`: it always rejects unspecified, multicast, broadcast, documentation,
and port-0 addresses; a node bound to a **routable** address additionally rejects
loopback/private/link-local gossip. A node bound to **loopback** is treated as a
local/test node and keeps local peers (so local multi-node testing still works).
Operator-supplied `--seed`/`--peer` still use the unfiltered `learn` — an operator
may legitimately point at a LAN/loopback peer. Tested both modes.

### F12 — Bans are per-(IP,port), evadable by port rotation — **LOW — Fixed**

Ban-scoring keyed on the peer's advertised listen address — its IP plus the port
it named in its own `Version` message. The port is attacker-supplied, so a
misbehaving peer reset its score simply by advertising a fresh port on every
reconnect, and a ban lasted exactly one connection. The ban was also only
consulted *after* the handshake, so a banned peer got a free connection each time
regardless.

Never severe: it could not get a third party banned (the score was tied to the
real connecting IP, which TCP does not let a peer spoof), and throughput stayed
capped by the 5000 msg/s limit and by the proof-of-work cost of producing anything
that scores.

**Fix:** `BanKey` (`node/src/transport.rs`) derives the key from the address TCP
actually connected from, and the ban is now checked at accept time, before a
single message is read. Which *prefix* is the substantive part:

* **IPv4 — the single address.** Another IPv4 address costs real money, while a
  whole /24 routinely holds unrelated people, so banning one would punish
  bystanders for a neighbour's behaviour.
* **IPv6 — the /64.** One subscriber is routinely handed an entire /64: 18
  quintillion addresses. Banning a single one of them is not a weaker measure, it
  is *no* measure — the next connection simply uses another. The /64 is the
  smallest unit corresponding to "one subscriber", and banning wider would again
  catch bystanders.
* **Loopback — per-port.** Several nodes on `127.0.0.1` are distinct nodes during
  local testing; collapsing them would make one test node ban all the others.
* **IPv4-mapped IPv6 is folded back to IPv4**, or one mapped client would ban
  every other mapped client at once.

The score table is capped (`MAX_SCORED_PEERS`), evicting the lowest score when
full — an attacker cycling addresses would otherwise turn a defensive counter into
a memory leak, the same lesson as F13 and the rate limiter's client table.

6 regression tests, including the port-rotation and IPv6-address-rotation
evasions, and that neither an unrelated host nor a neighbouring /64 is caught.

**A bug found reviewing this fix, before it shipped:** the first cut scored every
peer under `ip:0`, but the loopback key deliberately *includes* the port — so a
loopback ban was recorded under an address no check would ever match, and local
banning silently did nothing at all. `ban_target` now routes explicitly: off
loopback the real IP with the port dropped; on loopback the peer's advertised
listen address, since an inbound socket's source port is ephemeral and the
advertised one is the only stable identifier there. That address is self-declared
and so rotatable — exactly what F12 is about — but the threat model on loopback is
"my own test nodes", and the alternative is a ban that never matches.

### F13 — `seen_blocks` / `seen_txs` grow without bound — **LOW — Fixed**

Both dedup sets grew for the life of the process (one entry per block id / tx hash
ever seen), a slow memory leak on a long-running node.

**Fixed:** `BoundedSet` (a `HashSet` + FIFO `VecDeque`) caps each at `SEEN_CAP`
(100 000) and evicts the oldest on overflow. Safe for gossip dedup: a re-seen
*old* block sits below our tip (handled without re-broadcast) and a re-seen old tx
fails validation, so evicting ancient ids never reopens a gossip loop — it only
bounds memory. Tested (`bounded_set_caps_memory_and_evicts_oldest`).

### F14 — No self-connection / duplicate-link detection — **LOW — Fixed**

Self-dial was avoided only by an exact `self_addr` match (a `0.0.0.0`-bound or
multi-homed node could connect to itself), and two nodes that simultaneously dialed
each other kept both redundant links.

**Fixed:** a random per-process nonce rides in the `Version` handshake. A peer
whose nonce equals ours is a self-connection and is dropped; a nonce we are already
connected to is a duplicate link and is dropped. Nonces are released on
disconnect. Tested (`self_and_duplicate_handshake_nonces_are_rejected`).

### F15 — Fork-collection bandwidth is attacker-triggerable — **LOW (PoW-gated) — Fixed**

A peer that presents a differing block at a height we hold triggers
`begin_branch_collection`, re-downloading up to `MAX_REORG_DEPTH` (100) blocks.
Originally a peer could (a) replay the *same* differing block to make us re-collect
the whole branch repeatedly, and (b) feed a branch of invalid blocks that wasted
that bandwidth without earning any misbehavior points.

**Fixed:**
* **Replay dedup** — the triggering block's id is inserted into `seen_blocks` when a
  collection starts, so a re-send of the same block is deduped instead of starting a
  fresh 100-block download. A genuinely-advancing fork still triggers via its *newer*
  blocks, and the collect path re-pulls the trigger regardless, so real reorgs are
  unaffected.
* **Scored invalid branches** — `finish_reorg` now penalises a peer
  (`MISBEHAVIOR_INVALID_BLOCK`) whose collected branch fails `try_reorg` with an
  actual validity error (bad PoW/coinbase/tx). Benign outcomes are **not** scored:
  `NotHeavier` (a valid lighter fork) and `BadPrevId` (a fork deeper than
  `MAX_REORG_DEPTH`, indistinguishable from an honest deep fork). Tested
  (`finish_reorg_scores_invalid_branch_but_not_a_deep_fork`,
  `fork_trigger_block_is_marked_seen_to_stop_replay`).

A dedicated per-peer *rate* limiter on collection restarts is still a reasonable
belt-and-suspenders addition for the audit, but replay-dedup + scoring closes the
practical amplification vector.

## Surface reviewed and found clean (no change needed)

- **`unsafe impl Send` (RandomX `VmCell`, `Epoch`).** Sound: a `RandomXVM` and the
  `RandomXCache`/`RandomXDataset` it links are only ever *moved* to one worker
  thread and then used by that thread alone; the shared dataset/cache are immutable
  after construction and only *read* during hashing (RandomX's own multi-thread
  mining model), with atomic (`Arc`) refcounts. Per-VM scratchpad is not shared.
  Verified numerically: full-mem mining hashes equal the light verify VM's
  (`mining_hashers_agree_with_light_verification`).
- **Miner concurrency (`miner.rs`).** `grind` partitions the nonce space by residue
  (no duplicated work), shares only atomics + a `Mutex<Option<Block>>` written once
  on a win; `thread::scope` joins all workers before returning. Mining runs entirely
  off the consensus lock; a stale solve is rejected by `submit_mined_block`.
- **Ban-injection resistance.** A peer can only raise its *own* score (keyed to its
  real IP); it cannot get an honest third party banned.
- **Wire decoding DoS.** `read_vec` never pre-allocates from an untrusted length and
  is bounded by the 8 MiB frame cap; the new `SocketAddr` codec consumes ≥7 bytes per
  entry; `MAX_SHARE`=32 bounds what we hand out; `read_u16`/`take` are length-checked.
  A test (`decode_never_panics_on_adversarial_input`) throws random byte soup and
  every truncation of each valid message at `decode_message`/tx/block — errors, never
  panics.
- **Handshake.** Wrong `network_id` or `genesis_id` disconnects immediately, before
  any sync work — layered over the genesis-immutability guarantee (F10).
- **Rate limiting.** 5000 msg/s per connection; normal request/response sync is
  round-trip-bounded and well under it (verified: honest peers never false-banned).

## Remaining before the professional audit

- ~~Repin serai `-mirror` deps~~ — **done (2026-08-14)**: `core/Cargo.toml` now
  uses the first-party `monero-oxide` crates (`monero-primitives`,
  `monero-bulletproofs`, `monero-clsag`, `monero-ed25519`), and the migration was
  proven non-hard-forking by replaying the live chain. See `docs/DEPENDENCIES.md`
  §6. The RandomX bindings (`randomx-rs`) and the TLS tree (§8) should both be in
  audit scope.
- **F12** (IP/prefix-based bans) is now fixed, as are **F13** (bounded dedup
  sets), **F14** (self/duplicate-connection nonce) and **F15** (scored +
  replay-deduped fork-collection). A per-peer collection-restart rate limiter
  would still complement F15.
- ~~Fuzz the wire deserializer~~ — a no-panic adversarial test exists and a
  long campaign has now been run on it (see Pass 12). The coverage-guided
  `cargo-fuzz` targets still need a nightly toolchain and remain an audit task.
- The premine, emission constants, and RandomX seed schedule are economic/consensus
  parameters the audit should review, not just the code.

---

# Nocturnal — Internal Security Review (Pass 3: Subaddresses, Coinbase Maturity, External Mining)

Reviewed the code added since Pass 2 — none of it had yet been through a security
pass:

1. **Subaddresses**, which changed the **transaction format** (the
   `additional_tx_public` per-output transaction-key vector),
2. the **coinbase maturity** consensus rule and the per-output metadata it added,
3. the **external-miner RPCs** (`/getblocktemplate`, `/submitblock`) — a new,
   unauthenticated request surface, plus the `noct-miner` reference miner.

Two real vulnerabilities were found and fixed, both introduced by this work. Test
count after the pass: **146** (104 core + 27 node + 15 wallet).

## Findings

### F16 — Unbounded `additional_tx_public` → relayed CPU-exhaustion DoS — **HIGH — Fixed**

The subaddress change added a per-output transaction-key vector to every
transaction, but nothing bounded or validated its length:

- `Transaction::verify` never checked it, so a transaction carrying an
  arbitrarily long vector was **valid** — it would be admitted to the mempool and
  **relayed to every peer**, turning one cheap message into network-wide load.
- The wire decoder read the count and then decoded that many points. Each key
  costs a decompression **plus a torsion check**, so cost scaled with a single
  attacker-controlled `u32`.

The vector sits inside the ordinary transaction body, so the only ceiling was the
8 MiB message cap: 8 MiB / 32 bytes = **262,144 keys**. Measured on this machine
(release build): decoding that many keys takes **7.6 seconds of CPU** — for one
transaction, which would then be forwarded to every peer.

**Fix (defence in depth, both layers):**

- *Decode* (`wire.rs`): the count is bounded **before any key is decoded** — a
  legitimate vector is empty or one key per output, and a transaction can carry at
  most `MAX_COMMITMENTS` outputs (the range-proof aggregation limit), so a larger
  count is invalid by construction. Rejected with the new `WireError::TooLarge`.
  This is what actually stops the CPU burn, since decoding happens before
  verification.
- *Consensus* (`tx.rs`): `Transaction::verify` now requires the vector to be
  either empty or exactly one key per output, else `TxError::BadAdditionalKeys`.
  This also closes a correctness hole: a **short** vector silently fell back to
  `tx_public` for the outputs past its end.

Regression tests: `oversized_additional_key_count_is_rejected_before_decoding_keys`
(asserts rejection happens on the count alone, in <500 ms, with no key bytes
supplied) and `mismatched_additional_key_count_is_rejected`.

### F17 — Duplicate outputs → coinbase-maturity bypass — **MEDIUM — Fixed**

Outputs are identified by `[P, C]`, and the maturity rule resolves a ring member
back to its global index through that key to learn whether it is an immature
coinbase. `push_output` inserted into that index map with `insert`, which
**overwrites** on collision, and nothing rejected duplicate outputs.

So a second output with the same `[P, C]` silently replaced the first in the
index — and with it, the first's `OutputMeta`. Exploit:

1. A miner mines a block; its coinbase output is immature.
2. The miner publishes a transaction containing an output that copies that
   coinbase's `[P, C]` byte-for-byte. Both are attacker-chosen wire values, and a
   coinbase commitment's opening is public (mask 1 over a public amount), so the
   duplicate can satisfy the range proof and balance.
3. Once mined, the index maps `[P, C]` to the new, **non-coinbase** entry, which
   has no maturity requirement.
4. The original coinbase now resolves to that entry and is spendable — the
   maturity rule is bypassed for the miner's own freshly-mined coins, which is
   precisely what the rule exists to prevent.

**Fix:** `add_block` rejects any block creating an output that already exists, or
that repeats within the same block (`ChainError::DuplicateOutput`). The check is
O(1) per output against the existing membership map plus an in-block set, so it
adds no meaningful validation cost. Honest transactions never collide: one-time
keys derive from a random per-transaction key, making a repeat cryptographically
negligible.

Regression test: `duplicate_output_is_rejected_closing_the_maturity_bypass`.

## Surface reviewed and found clean (no change needed)

- **Maturity enforced over every ring member, not just the real one.** Because
  ring signatures hide which member is real, checking only the "real" input would
  be meaningless — the rule is applied to all members, so an immature coinbase
  cannot be spent by hiding it among decoys.
- **Maturity in validation is O(1).** `validate_tx` resolves each ring member with
  a hash-map lookup and a vector index; no scan of the output set enters a
  block-validation path, so the rule adds no DoS surface. (The O(n) eligible-decoy
  scan lives in `assemble_ring`, which only *wallets* call when building a
  transaction — never the node when validating. It was nonetheless **optimised
  after this pass**: output heights are non-decreasing in index, so the immature
  outputs form a bounded suffix; selection now scans only that suffix instead of
  the whole output set, keeping ring assembly independent of chain size.)
- **Maturity survives reorgs.** `maturity` is an ordinary field of `Blockchain`,
  so `try_reorg`'s candidate clone carries it; `pop_block` truncates `output_meta`
  in lock-step with `outputs`, keeping per-output metadata aligned with the index
  space.
- **Genesis premine is subject to maturity.** It is recorded as a coinbase output
  at height 0, so it is not spendable until the chain is `COINBASE_MATURITY`
  blocks deep — no special case that would exempt the most valuable output.
- **`/submitblock` trusts nothing.** A submitted block goes through exactly the
  same `add_block` validation as one arriving from a peer (PoW, timestamps,
  coinbase reward, every transaction, maturity, and now duplicate outputs). A
  stale submission (the chain advanced mid-grind) is detected by a `prev_id` check
  and rejected rather than mis-applied. A malicious miner can only waste its own
  work.
- **`/getblocktemplate` leaks no key material.** It returns a block paying a
  caller-supplied address, plus the epoch seed and target — all public. A fresh
  transaction keypair is generated per call, so there is no key reuse across
  templates.
- **Subaddress unlinkability.** The offset `m = H_s("noct_subaddress" ‖ a ‖ i ‖ j)`
  binds to the view secret, so subaddresses of different wallets at the same index
  are unrelated, and an observer cannot link a subaddress to the main address
  without `a`. Scanning derives ownership from `D' = P − k·G` compared against the
  wallet's own table; no on-chain marker identifies the recipient.

## Open / accepted (documented, pre-mainnet)

- **F18 — RPC was unauthenticated — MEDIUM — Fixed (2026-08-09).** `/mine`,
  `/submitblock`, and `/getblocktemplate` are administrative and originally took
  no credentials, so exposing the RPC handed those controls to anyone who could
  reach the port. Now:
  - a shared **bearer token** (`--rpc-token-file` / `--rpc-token`) is required on
    every request, compared in **constant time** so it cannot be recovered from
    response timing;
  - authentication happens **before the request body is read**, so an
    unauthenticated client cannot make the node buffer up to `MAX_BODY`;
  - **fail-closed binding**: `run` refuses to start when the RPC is bound to a
    non-loopback address without a token, so an open RPC cannot be exposed by
    accident. Unauthenticated operation remains possible only on loopback.

  Verified live: no token and a wrong token both give `401`; the correct token
  succeeds; `noct-miner --token-file` mines against an authenticated node while
  the same miner without a token is refused; a non-loopback bind without a token
  aborts startup with an actionable message. Unit tests cover the header parsing
  and the constant-time compare.

  *Follow-up — rate limiting, now implemented (2026-08-12).* Authentication says
  *who* may call but not how much, so an authenticated client could still pin the
  consensus lock through the expensive endpoints. Each source IP now has a
  refilling token bucket, with requests charged by cost —
  `/getblocktemplate`, `/submitblock`, `/mine`, `/submit_tx` cost 10, block reads
  2, status reads 1 — so the actual DoS lever is bounded rather than just the
  request count. Default `--rpc-rate-limit 2000` units/s (burst 2×; `0`
  disables); over-quota requests get `429` with `Retry-After`.

  Two properties worth noting for review: the limiter runs **before**
  authentication, so an unauthenticated flood is bounded too; and its client
  table is **pruned**, since a map keyed by attacker-chosen source addresses
  would otherwise be a memory-exhaustion vector — a fully-refilled bucket is
  indistinguishable from an untracked client, so dropping full buckets bounds
  memory without letting a limited client escape its penalty (regression test:
  `client_table_stays_bounded_without_letting_limited_clients_escape`).

  Verified live: a drained bucket returns `429 + Retry-After`; a template request
  is refused when the remaining budget is below its cost while a cheap status read
  still passes; and a miner running flat out under the default limit produced 750
  blocks with **0 solutions dropped**. That last point exposed a real defect
  introduced by limiting — `noct-miner` discarded a solved block on a transient
  refusal — so submission now retries with backoff; proof-of-work is too expensive
  to throw away on a `429`.

  *Residual, documented:* the token is still a bearer credential over cleartext
  HTTP — across an untrusted network it needs a TLS proxy or tunnel. Rate limiting
  is also per-IP, so miners behind one NAT share a budget (raise the limit, or
  give each its own endpoint).
- **Metadata leak: presence of additional keys.** A transaction paying a
  subaddress publishes the per-output key vector, revealing that *some* output
  pays a subaddress (not which, nor to whom). Monero's design has the same
  property; noted so the audit can rule on it rather than discover it.
- Carried forward from Pass 2: **F12** (per-(IP,port) bans, evadable by port
  rotation).

## Remaining before the professional audit

- Everything listed at the end of Pass 2 still applies, except the serai repin,
  which is **done** — see `docs/DEPENDENCIES.md` §6. The economic parameters
  (premine, emission, RandomX seed schedule) remain for the audit.
- **Fuzzing (updated).** The wire codec now has (a) a deterministic *mutational*
  fuzzer that runs in the normal suite on stable
  (`mutational_fuzz_decoders_are_panic_free_and_canonical`) — it mutates valid
  encodings and asserts no panic, **canonicality** (anything that decodes must
  re-encode to identical bytes), and **identifier stability** across a round
  trip; and (b) `cargo-fuzz` (libFuzzer) targets in `noct/fuzz` with a seed
  corpus, for coverage-guided campaigns. The libFuzzer targets require a
  **nightly** toolchain and so have **not been executed** in this environment
  (the project is pinned to stable 1.82) — running them is an audit task. The
  stable harness self-checks that it actually reaches the canonicality property,
  so it cannot silently degrade into a vacuous pass.
- The two consensus rules added since Pass 2 — **coinbase maturity** (depth, and
  the enforce-over-all-ring-members choice) and **duplicate-output rejection** —
  should be reviewed as consensus changes, not just as code.

---

# Pass 4 — wallet recovery (restore from seed phrase)

Scope: the GUI restore-from-seed-phrase flow added to the desktop wallet, and
the `noct-cli restore` path underneath it.

## Findings

### F19 — Seed phrase passed as a command-line argument — **HIGH — Fixed**

`noct-cli restore` took the phrase as `--mnemonic "word1 … word24"`. Command-line
arguments are **not private**: on Windows any process can read another's full
command line (`Win32_Process.CommandLine`), and on Linux any user can read
`/proc/<pid>/cmdline`. A seed phrase is the entire wallet — whoever reads it can
spend every coin the wallet will ever hold, and rotating it is not possible.

This was not theoretical. Earlier in the same session, this project read a
running process's `--miner-address` straight out of `Win32_Process.CommandLine`
while diagnosing an unrelated problem. The identical technique would have
captured a phrase during a restore.

Wiring a GUI to the flag would have made it far worse: a person recovering a
wallet is, by definition, holding real funds, and would have had no idea the
phrase was briefly world-readable.

**Fixed** by reading the phrase from **stdin** (`--mnemonic-stdin`, or
`--mnemonic -`). The desktop app passes it via the child process's stdin and
never places it in `args`; `test-wallet-setup.js` asserts that no element of the
generated argument list contains any part of the phrase. The literal `--mnemonic`
form is retained for interactive use and now prints a warning naming the
exposure.

### F20 — A restore could silently open the wrong wallet — **LOW — Fixed**

A seed phrase with words transposed can still satisfy the BIP39 checksum: the
restore then succeeds and produces a **valid but different** wallet, showing a
zero balance. That is indistinguishable from "my coins are gone", and the
person's natural next move — restore again, or give up — does not recover them.

**Fixed** with a two-step flow. `--dry-run` validates the phrase and reports the
address it opens **without writing a key file**, so the app can show which wallet
is about to be opened. When the app has a pinned wallet and the phrase opens a
different one, it says so explicitly, names both addresses, and explains that a
valid phrase in the wrong order opens a different, empty wallet. Committing is a
separate, deliberate click.

## Surface reviewed and found clean (no change needed)

- **Overwrite protection.** `cmd_restore` refuses when the key file exists, and
  the GUI never works around it; `--dry-run` deliberately skips the check because
  it writes nothing.
- **Renderer isolation.** The setup window runs with `contextIsolation: true` and
  `nodeIntegration: false`, and reaches the main process only through five
  `invoke` channels. It cannot spawn processes or touch the filesystem itself.
- **Normalisation placement.** The phrase is normalised in the **main** process,
  not the renderer, so the trusted side does not depend on the window having
  done it.
- **Pin handling.** An explicit restore rewrites the pin, which is correct: it is
  a deliberate choice of wallet, made after the mismatch warning above.

## Found by end-to-end testing

- **The preload bridge was broken in the real app.** The setup window's preload
  did `require('./wallet-setup')`, which works under unit tests but **not in
  Electron**: preloads are sandboxed by default and may require only `electron`
  and a few Node built-ins. The bridge therefore failed to load, and the window
  could not talk to the main process at all — a defect no unit test could reach,
  because the unit tests stub exactly that boundary.

  Resolved **without weakening the sandbox**: rather than setting
  `sandbox: false` to make `require` work, the word-count call was moved onto an
  IPC channel, so the window that handles seed phrases keeps every isolation
  default (`sandbox`, `contextIsolation`, no `nodeIntegration`) and reaches the
  main process only through the five declared channels. `sandbox: true` is now
  stated explicitly rather than inherited, so a future Electron default cannot
  quietly change it.

  Covered by `desktop/test-e2e-setup.js` (`npm run test:e2e`), which drives a
  real Electron instance through the whole recovery flow against the throwaway
  `demo` wallet.

## Open / accepted

- The phrase is a JavaScript string in the main process for the duration of the
  restore, and Node offers no reliable way to zero it. Bounded by process
  lifetime; worth revisiting only alongside a broader secret-handling pass.
- The end-to-end test runs in **dev mode**, so it exercises the packaged app's
  code but not its packaging. The asar allowlist is checked separately after each
  bundle.

---

# Pass 5 — network separation

Scope: introducing a testnet distinct from mainnet, and what running the two side
by side revealed.

## Findings

### F21 — Peer registry never removed disconnected peers — **HIGH — Fixed**

`Peers` held its connections in a `Vec` with `add` returning a positional index,
and had **no removal method at all**. Every connection that ended — for any
reason — left its entry behind for the lifetime of the process, each one holding
an `Arc<Mutex<TcpStream>>`, i.e. a live socket handle.

Consequences, all remotely triggerable by an unauthenticated peer:

* **Socket / memory exhaustion.** Connect, let the handshake fail, repeat. Each
  cycle costs the attacker nothing and permanently consumes a file descriptor
  and an allocation on the victim.
* **Degraded propagation.** `flood` writes to every registry entry, so each dead
  peer adds a failing write to *every* block and transaction broadcast. Block
  relay slows down in proportion to the attack.

The paths that discard a connection are exactly the cheap ones: foreign network,
foreign genesis, self-connection, duplicate link, flooding ban, or a peer simply
restarting. No misbehaviour was even required — ordinary churn leaked.

**How it surfaced.** Not by review. A testnet node was pointed at a mainnet node
to confirm they refused each other; they did, but both reported a peer count
climbing by one every ten seconds as the connection manager retried. The
separation was working — the cleanup was not. The bug predates this pass and
would have hit mainnet under normal peer churn.

**Fixed** by keying the registry on a monotonically increasing id
(`HashMap<usize, PeerWriter>`) and removing the entry on every exit path,
including the early return when the handshake send fails. Ids are never reused,
so a late cleanup from a closed connection cannot evict a live peer that would
otherwise have inherited its slot — the specific bug a `Vec` with index reuse
would have introduced while fixing this one.

Regression tests in `node/src/transport.rs::registry_tests`: removal drops
exactly one entry, ids are never reused, a stale removal cannot evict a live
peer, and 200 connect/disconnect cycles leave the registry empty. Verified live:
the same two-node setup now holds a flat peer count of 0, while two same-network
nodes still peer normally.

## Surface reviewed and found clean (no change needed)

- **Separation is layered.** Magic, genesis id, address tag and default ports all
  differ, so no single mistake merges the networks. The genesis id check is the
  one that matters most, since it is derived rather than declared.
- **Same code path.** `Block::genesis_for` builds both networks from
  `ChainParams`; the testnet cannot drift away from the code mainnet launches
  with.
- **`Blockchain::new` still means mainnet.** Every existing caller keeps its
  behaviour; a silent switch would have been catastrophic, and a test pins it.
- **Miner address is network-checked.** `run` refuses to start when the miner
  address belongs to another network.

## Open / accepted

- `DEFAULT_SEEDS` is empty and is **not** yet per-network. It must become a
  per-network list before either chain can bootstrap without `--peer`.
- The testnet premine's seed phrase is published (`docs/TESTNET.md`). Acceptable
  only because the wallet is worthless by construction.

---

# Pass 6 — dependency migration + backup verification

## Dependency migration (not a finding — a resolved risk)

The **F-series risk carried since Pass 1** — that Nocturnal's RingCT cryptography came
from a *third-party republish* (`*-mirror`) whose provenance an auditor would
have had to establish by hand — is now closed. The tree builds on the
**first-party** `monero-oxide` crates (`monero-primitives`, `monero-bulletproofs`,
`monero-clsag`, `monero-ed25519`, all 0.1.0, published 2026-07-31).

Proven byte-compatible before adoption, in increasing order of strength:

1. `H_p` identical across 35 inputs — so key images are unchanged.
2. 188 tests green, including every CLSAG, range-proof and key-image test.
3. **The live 673-block chain re-validates in full.** Blocks mined and signed
   under the mirrors were replayed by a node built on the new crates: height 673,
   emitted `500320332066626570`, tip `5fb3363473f2eb3b…`.

Point 3 is the one that matters — a changed byte format would have failed the
replay. This is **not** a hard fork. Full detail in `docs/DEPENDENCIES.md` §6.

## New surface: `POST /api/verify-seed`

Lets someone check a **transcribed** recovery phrase against the open wallet.

The threat it addresses is not an invalid phrase — it is a *valid* one. Two
transposed words usually still satisfy the BIP39 checksum and simply open a
different, empty wallet. Discovered at recovery time, that is indistinguishable
from funds having vanished, and by then the original copy is gone.

Design constraints, all enforced:

- **Writes nothing.** No key file, no state change; it is a comparison.
- **Never returns either phrase.** A mismatch reports only *that* it differs and
  which word position first diverges — enough to find a slip, not enough to
  reconstruct the answer from repeated queries (the position is derived from the
  submission the caller already holds).
- **Compares against this wallet's phrase**, and re-derives the address to confirm,
  rather than merely checking well-formedness.
- Same trust boundary as the existing `GET /api/seed`, which already returns the
  phrase to a loopback-bound UI — so no new exposure.
- The UI clears the typed copy on success and never renders the real phrase into
  the check box.

Verified live across five cases: correct phrase, numbered-list formatting,
**two words transposed** (caught, first difference located), one word short, and
empty input.

## Still open

- Pool miner-facing port has no authentication (pre-internet).
- F12 (IP/prefix bans) remains deferred.

---

# Pass 7 — mining pool, pre-internet hardening

Scope: `noct-poold`'s miner-facing port, which is unauthenticated **by design**
(anonymous miners are how public pools work) and would be the first thing an
attacker reaches.

## F22 — Share submission was an unmetered CPU amplifier — **HIGH — Fixed**

The pool **re-hashes every share it is sent**. Under RandomX that is on the order
of a millisecond of CPU per submission, while *producing* a bogus share costs the
sender nothing — no proof of work is required to make the pool do proof-of-work
verification. A few thousand junk submissions a second saturate the pool, and
legitimate miners are starved of the very service they are pointed at.

Nothing metered this: no rate limit, and no cap on concurrent connections (each
one a thread, so a socket flood exhausted threads independently).

**Fixed** by reusing the node's `RateLimiter` (made `pub` rather than duplicating
a second token bucket that could drift) with pool-specific, asymmetric costs:

| path | cost | why |
|---|---|---|
| `POST /submitblock` | 50 | forces a PoW verification |
| `GET /getblocktemplate` | 10 | clones the current job |
| everything else | 1 | cheap reads |

Default budget `--rate-limit 1000` units/s ≈ **20 shares/s/IP sustained, 40
burst** — far above any honest miner, far below a flood. `0` disables it, which is
only sane on a private LAN. The charge is applied **before** the request is
processed, so an over-budget caller never reaches the expensive path.

Connections are capped at `MAX_CONNECTIONS = 512`, refused with `503` *before* a
thread is spawned, and the counter is released on every exit path including
errors — a leak there would wedge the pool shut after 512 failures.

**Verified live.** A flood of `/submitblock` against a pool at `--rate-limit 200`
(4 shares/s): first ~10 accepted, then a steady stream of `429`, recovering
automatically as the bucket refilled. Then the case that matters — an **unmodified
`noct-miner`** against the same limited pool: **4 blocks found, 4 shares
credited, 100% of the window, zero rate-limit hits.** A limit that throttles
honest miners is one an operator disables, which is worse than no limit.

Tests in `noct-poold::hardening_tests` pin the properties rather than the
numbers: a share must cost an order of magnitude more than a read, and the
default budget must leave an honest miner unaffected (15–100 shares/s).

## Also fixed: a misleading miner error

After finding a block the pool briefly has no job while it fetches the next
template, and answered `{"error":"no job yet …"}`. The miner reported that as
`malformed template response` — so a *correct* transient state looked like a
protocol fault, on every block. That trains an operator to ignore the message,
and then a genuinely malformed response goes unnoticed. The miner now
distinguishes the two: `waiting for work: no job yet — the pool is still
fetching work`.

## Still open before a public pool

- **Per-miner credentials.** Identity is still the payout address supplied on
  `/getblocktemplate`, remembered per source IP.
- **TLS.** Shares and payout addresses cross the wire in clear.
- **Vardiff**, and **persistence of the PPLNS window** across restarts (a restart
  currently forfeits miners' unpaid credit in the window).
- The limiter is **per-IP**, so many miners behind one NAT share a budget.

## F23 — A restart silently forfeited miners' unpaid work — **MEDIUM — Fixed**

The payout ledger was already crash-safe, but it only records work once a round
has **matured**. Everything between — shares accepted into the PPLNS window but
not yet paid — lived purely in memory. Any restart, crash or ordinary redeploy
discarded it.

That is not a crash-recovery inconvenience; it is a silent transfer of value. The
window is what the *next* block's reward is split against, so work that vanished
is simply redistributed to whoever mines next, and the miner who did it has no
way to detect that it happened. A pool that restarts weekly quietly skims from
whoever was mid-window each time.

**Fixed** with an append-only window log (`pool/src/window_log.rs`), recovered at
startup and seeded into the pool via `Pool::restore_window`.

Design choices, each for a reason:

* **Append-only, not a periodic snapshot.** A snapshot chooses how much work to
  lose on a crash — a few seconds of it, every time. One line per accepted share
  loses nothing.
* **Written *before* the share is acknowledged.** A crash between telling a miner
  "accepted" and recording it would lose credit the miner has every reason to
  believe is banked.
* **A write failure is loud but not fatal.** Rejecting the share would cost the
  miner work it genuinely did; the operator is warned that durability is broken.
* **Corrupt or truncated lines are skipped, never fatal.** A pool that refuses to
  boot pays nobody, which is strictly worse than one that boots having dropped a
  line. A torn final line — the realistic crash artefact — costs at most that one
  share.
* **Recovery truncates to the window exactly as live acceptance does**, so a
  restart cannot resurrect work that had already aged out and dilute everyone
  else's split.
* **Compacted** past 4× the window size, so a long-running pool's log and startup
  cost stay bounded.

Six tests in `window_log`, including the torn-tail and corrupt-line cases and a
bound check. **Verified live:** a miner earned 5 shares (weight 5000, 100% of the
window), the pool was killed and restarted, and it came back reporting
`5 share(s) recovered from an earlier run` with the split unchanged.

A Windows-specific bug surfaced while writing it: compaction renames over the log,
and the append handle was still open, so `rename` failed with `Access denied`. The
handle is now scoped closed first. On Unix the rename would have succeeded and
silently stranded the open handle on an unlinked inode — the same latent defect,
just quieter.

## F24 — Shares behind one NAT were paid to the wrong miner — **HIGH — Fixed**

The pool attributed every share by **source IP alone**: whichever payout address
that IP last registered when fetching work (`miners: HashMap<IpAddr, String>`).

Two rigs behind one router present the same source IP. The second to ask for work
silently overwrote the first, and from that moment **both miners' shares were
credited — and paid — to whichever address had registered most recently.** The
losing miner received nothing for real work, and neither party had any way to
observe it: the pool's own `/stats` showed a single, plausible-looking miner.

This is not an exotic configuration. Several rigs behind one home router is the
ordinary small-miner setup, so any public pool would have mispaid a large fraction
of its users from the first day.

**Fixed** by attributing a share to the payout address carried **on the submission
itself** (`POST /submitblock?address=…`), which involves no shared state to
collide over. `noct-miner` now sends it; the node ignores the parameter, so the
same miner still works unmodified against a node.

Ordering is deliberate (`attribute_miner`):

1. the address on the submission, **only if it decodes** — an undecodable one
   would strand the payout at settlement, long after the miner had gone;
2. otherwise the per-IP registration, so miners predating this change still work
   (they remain exposed to the collision, which is why the miner was updated);
3. otherwise the raw IP, so work is never *silently* uncredited — an operator can
   see it in `/stats` and settle it by hand.

Four tests in `attribution_tests`, the first being the NAT collision itself.
**Verified live:** two miners on one source IP, mining simultaneously to different
addresses, were credited **separately and proportionally** (62.5% / 37.5%). Before
the fix the whole window would have gone to one of them.

## Vardiff — per-miner share difficulty (not a finding; closes an F22 interaction)

A single fixed share target cannot suit every miner, and after F22 it actively
misbehaved: a fast rig at a low target submits shares constantly and spends its
whole **rate-limit budget while behaving perfectly honestly**, so the pool
throttles the miner it most wants. Throttling was the wrong lever; raising that
miner's target is the right one. At the other end, a slow rig may find nothing
inside the PPLNS window and earn nothing for real work.

`pool/src/vardiff.rs` gives each miner its own target, retuned toward one share
every `--vardiff-target-secs` (default 15).

**Why this cannot redistribute income.** A share's weight is the difficulty *in
force when it was accepted*, not a share count. One share at 4× the target is
credited exactly as much as four at the base. Retargeting therefore changes how
often work is **reported**, never what it is **worth** — the property that makes
per-miner difficulty safe, pinned by
`vardiff_integration_tests::a_harder_target_pays_proportionally_more_per_share`.

Deliberate choices:

* **A damped proportional step**, clamped to `max_step` (4×) per move and to
  `[min, max]`. Share discovery is Poisson: intervals vary hugely at a perfectly
  tuned target, and an undamped controller chasing each sample oscillates, which
  is worse for the miner than being slightly mistuned.
* **Rates are measured with an EWMA**, for the same reason.
* **A new miner is never retuned** — there is nothing measured to retune from.
* **The previous target is remembered**, and a share is accepted if it meets
  *either* target, credited at whichever it met. A miner may already be grinding
  on the old target when we retune; rejecting that work would punish it for our
  adjustment.
* **Retuning happens when work is issued**, not when a share arrives, keeping
  those ambiguous moments rare and predictable.

12 tests (7 controller, 5 daemon), including convergence on a steady miner and
saturation at extreme difficulties. **Verified live:** a real miner starting at
target 200 was retuned through 207 → 290 → 513 → 819 → 1120 and settled at 441 —
climb, overshoot, damp back — with **16 shares accepted, 0 rejected, 0 rate-limit
hits**, while an idle miner that had never submitted anything was still issued the
base 200.

---

## Pass 9 — transport security (2026-08-14)

Everything Nocturnal speaks over HTTP was plaintext. Three findings, all fixed; the
first two were the reason this pass happened, the third was found by accident
while testing it.

### F25 — Miner payout addresses in plaintext → income theft — **HIGH — Fixed**

Every request a miner makes to a pool carries the address it wants to be paid
at, on an unauthenticated port intended to face the internet. Two consequences,
and the second is the serious one:

* **Observation** — anyone on the path learns which addresses are mining where
  and how hard, which is a deanonymisation surface in a privacy coin.
* **Modification** — an attacker who can rewrite the traffic replaces the
  address with their own. The pool credits and eventually *pays* the attacker.
  The victim's client sees its shares accepted exactly as before; the failure has
  **no symptom** until the money does not arrive, and even then the miner has no
  way to tell theft from a pool that simply does not pay.

The same argument covers the node's RPC, where the `Authorization: Bearer` token
is sent on **every request** — one observed request is the entire credential —
and a wallet's queries, which reveal exactly the activity the project exists to
keep private.

**Fix:** `noct-tls`, a leaf crate wrapping rustls, wired into every HTTP surface:

* `noct-poold --tls-cert/--tls-key` (and `--tls-generate` for operators with no
  domain name), `noct-miner --pool https://… [--pool-fingerprint …]`,
  `noctd --rpc-tls-cert/--rpc-tls-key`, and the wallet's `NodeClient`.
* A `Stream` enum over plain/TLS implementing `Read`/`Write`, so the existing
  hand-rolled HTTP was reused rather than rewritten. TLS sessions cannot be
  `try_clone`d the way sockets can, so both servers now read fully and then
  write, which suits their `Connection: close` protocol exactly.
* Certificate **pinning** for self-signed pools (SSH host-key model), because
  the realistic alternative to it is not "get a proper certificate", it is
  "run without TLS". Deliberately **no** verification-skipping flag anywhere:
  such a flag is the one everyone turns on, and it makes TLS a slower plaintext.
* Handshakes run on the worker thread, not the accept loop, and remain behind
  `MAX_CONNECTIONS` — a handshake is the most expensive thing an anonymous
  caller can trigger before saying anything, so it stays inside the F22 bound.

**Verified live:** node and pool both serving TLS, pool→node pinned, miner→pool
pinned, blocks mined end to end. A **wrong** fingerprint is refused with an
actionable message; a self-signed certificate with **no** fingerprint is refused
(`UnknownIssuer`); plaintext against the TLS port gets nothing.

### F26 — Reverse-proxy deployment silently collapses the rate limiter — **MEDIUM — Fixed**

Terminating TLS at nginx or Caddy is a normal deployment, and it breaks F22
without any visible sign: every miner then arrives from the proxy's address, so
the per-IP token bucket meters the **entire pool** through one bucket. The
protection does not fail open — it fails *shut*, throttling every honest miner at
once as soon as the pool has more than a handful.

The obvious repair is worse than the disease: believing `X-Forwarded-For` from
anyone lets a single miner put a fresh fake address in the header on every
request and mint itself an unlimited number of buckets — precisely the
exhaustion F22 exists to prevent.

**Fix:** `--trusted-proxy <IP,…>`. The header is honoured only from listed
addresses and ignored from everyone else, and the **last** entry is used, not the
first — a proxy appends the address it saw, and anything to its left came from
the client and is unverifiable. 4 tests in `noct-poold::proxy_tests`, the first
of which is the forgery attempt.

### F27 — Unvalidated payout address at registration → diluted rewards — **MEDIUM — Fixed**

Found by accident: a client started with a junk `--address` during TLS testing
appeared in `/stats` as a miner with 2% of the PPLNS window.

F24 validated the address carried on a *submission* but not the one registered
on `/getblocktemplate`, which was inserted into the per-IP map unchecked. An
undecodable string therefore became a miner identity that accrues real weight and
**can never be paid** — so its slice of every reward is allocated and then lost,
diluting every miner who can be paid. A typo in one participant's command line
was enough to do it, no malice required; done deliberately and repeatedly it is a
cheap way to burn a pool's payouts.

**Fix:** the registration path validates exactly as the submission path does.
Work from a client with an undecodable address now falls back to its source IP —
visible to the operator in `/stats`, and not mistakable for a payee. Regression
test `attribution_tests::an_undecodable_address_never_becomes_a_paid_identity`.

### Still open

* **Per-miner credentials.** Attribution by submitted address is correct for
  deciding *who to pay*; it is not authentication, and one miner can still claim
  another's name. This is the last item before a genuinely public pool.
* **P2P is still unencrypted.** Out of scope here and a separate design question
  (Monero's is likewise unencrypted); it carries no credentials and no payout
  addresses, which is why it is not this pass's problem.

---

## Pass 10 — miner credentials (closes the last item from Pass 9)

Pass 9 ended with one gap: attribution by submitted payout address is correct for
deciding *who to pay*, but it is not authentication. This closes it.

### What was actually wrong, stated precisely

It is worth being exact, because the obvious worry is not the real one.
**Submitting valid work under someone else's address is not theft** — it credits
them, so an attacker doing it is making a donation. The genuine problems were:

* **Vardiff interference.** A target is retuned from the measured share rate of
  whoever submits under an identity. Anyone who knows a victim's payout address
  could submit under it and drive that miner's difficulty somewhere it does not
  belong. Griefing, not theft, but it costs a victim real earnings and is
  invisible to them.
* **No revocation.** The only lever against an abusive miner was banning its IP,
  which also removes everyone else behind the same router — a home-mining setup
  is exactly where that hurts.
* **No way to run a closed pool at all.** Anonymous access was mandatory, so the
  only thing between the pool and a stranger was the rate limiter.

### The design, and the property that matters

`pool/src/auth.rs`, **opt-in** via `--miner-auth <FILE>`. A public pool leaves it
off and is completely unchanged — this must not quietly close open pools, and a
test pins that.

When it is on:

> **the credential decides the payout address; the request cannot override it.**

`--address` is ignored entirely rather than merged with, preferred over, or
fallen back to. There is then nothing self-declared left in a miner's identity,
so impersonation and confusion are not defended against — they are unrepresentable.

Deliberate choices:

* **Random 256-bit tokens, not passwords.** A password needs a slow KDF (argon2,
  bcrypt) because people choose guessable ones; a token cannot be guessed and
  needs no stretching. It also reuses the node's existing bearer-token shape, so
  a miner's `--token-file` already works with no new plumbing.
* **Constant-time lookup that always scans every entry.** A hash-map lookup is
  the obvious implementation and leaks, via timing, both which tokens exist and
  how close a guess was. The cost here is a few dozen fixed-size comparisons.
* **Every malformed line is fatal at startup**, including an address that does
  not decode (the F27 defect, caught before any work is done) and a duplicated
  token (two miners who cannot be told apart or revoked separately). A skipped
  line would mean a miner that mines and is never paid, discovered only by
  someone eventually noticing they earned nothing.
* **One refusal message for every failure** — absent, malformed, wrong and
  revoked tokens are indistinguishable, so a guesser learns nothing about how far
  they got.
* **`/stats` requires a token too when credentials are on.** A pool that
  registers its miners is a private one, and its stats list who mines, to which
  address, and what they earn — publishing that in a privacy coin would be an odd
  thing to do by default.
* **`--add-miner` generates credentials** for the same reason `--tls-generate`
  exists: the alternative to an easy path is a weak hand-picked token, or the
  feature going unused.

### Worker names, and the separation that keeps them safe

`--worker <name>` exists because vardiff created a new problem: several rigs
under one payout address shared one assignment, and a target averaged across a
fast rig and a slow one suits neither.

The identity is therefore split in two. **Money is accounted per payout address**
and nothing here touches that path; the *session* (`address.worker`) decides only
whose share rate is averaged together and what `/stats` reports per rig. A
mistake in that half can mis-tune a difficulty; it cannot misdirect a payment.
Worker names are attacker-supplied and reach JSON and logs, so they are reduced
to a safe alphabet and 24 characters rather than escaped — and dropped rather
than rejected, since a bad worker name should cost a miner its per-rig
statistics, never its earnings.

11 tests (6 in `auth`, 5 in `noct-poold::credential_tests`).

**Verified live** on a TLS pool with two registered miners: an unregistered miner
refused; `/stats` refused without a token; a miner running `--address <BOB>` with
**Alice's** token credited to **Alice**; and Alice's two rigs metered apart
(rig-1 400, rig-2 2363) while being paid as **one** payee (2763, 62.3%), with Bob
paid separately (1675, 37.7%).

### Remaining

* **An operator fee** — the pool currently keeps nothing.
* **P2P encryption** — unchanged from Pass 9, and still a separate question.

---

## Pass 11 — pool operator fee

Not a finding; the last pool feature, recorded because it touches money.

`--fee-percent` keeps a share of each block before the rest is split among
miners. It defaults to **zero** — a pool that took money without being told to
would be indefensible.

**No transfer is involved.** The whole coinbase already pays the pool's own
address, so the operator's share is simply the part never credited to a miner.
That removes an entire class of failure: there is no fee payment that can fail,
be lost, or be sent twice.

Deliberate choices:

* **Basis points, not a percentage float.** Money must not be divided by a value
  that cannot represent 0.1 exactly, and a fee is something an operator publishes
  and a miner checks — `0.1` read back as `0.09999999` in a log line is not a
  number anyone can audit.
* **Exact by construction.** `apply_fee` returns `(fee, miners)` summing to
  exactly the reward, through `u128` so `reward × 10_000` cannot overflow;
  `split_reward` then divides the miners' portion with its own exactness
  guarantee. The chain of custody from block to payout is exact end to end,
  swept over awkward rewards (including `u64::MAX`) and rates in tests.
* **Rounding goes to the miners.** The operator writes the code and sets the
  rate; the party without that power gets the sub-unit.
* **A rate at or above 100% is refused, not clamped.** Someone typing
  `--fee-percent 100` has almost certainly confused percent with basis points,
  and "the miners get nothing" is not a mistake to discover from the payouts.
  `apply_fee` is still safe on its own if handed one.
* **Realised only at maturity**, the same moment the miners' share is, and for
  the same reason: before that a reorg can erase the block.
* **Published, not buried.** The rate and running totals are on `/stats`
  (`fee_percent`, `operator_earned`, `operator_pending`) and printed at every
  startup *whether or not one is set*. A fee a miner cannot check is what makes
  people distrust pools.

The ledger records each block's whole reward alongside what miners were credited,
so the fee is derivable per round and the file accounts for every atomic unit
rather than leaving an unexplained gap. Ledgers written before fees existed load
as "kept nothing", which is what those pools did.

6 tests. **Verified live** at 2.5%: three blocks, each split to the atomic unit
(`476837158203 = 11920928955 + 464916229248`, and the fee equal to the floored
2.5% in every case).

---

## Pass 12 — extended fuzzing campaign (stable toolchain)

The `fuzz/` targets are coverage-guided (libFuzzer) and need a **nightly**
toolchain, which is not installed here; installing one is the project owner's
call, so they remain unexecuted and an audit task. That is a real limitation and
is not worked around below — what follows is a different, weaker instrument run
much harder.

`wire::tests::mutational_fuzz_decoders_are_panic_free_and_canonical` now takes
two overrides, `NOCT_FUZZ_ITERS` and `NOCT_FUZZ_SEED`, so the same harness can be
run as a campaign without changing what it does in the normal suite (the default
run is bit-for-bit what it always was; the seed is *mixed into* the constant
rather than replacing it).

**Campaign: 4 × 240,000 = 960,000 mutations**, four independent mutation
sequences over six valid seed encodings (transaction, block, and four message
types). Result: **545,188 inputs decoded and were checked**, and every one
re-encoded to identical bytes. **Zero panics. Zero non-canonical encodings.**

What that does and does not establish:

* **Does:** the decoders do not panic, index out of bounds, or allocate from an
  untrusted length across a large volume of structurally-plausible malformed
  input; and no two distinct byte strings were found that decode to the same
  object — the malleability class behind F5, which would let an identifier be
  substituted.
* **Does not:** this is blind mutation, not coverage-guided search. It cannot
  claim to have reached every branch, and it says nothing about semantic
  validity — only about the decode boundary. A libFuzzer campaign would be
  strictly better and is still wanted.

One harness change worth noting: the self-check that the fuzzer actually *reaches*
its property was a fixed floor of 40, calibrated for the default 180 mutations.
At campaign length that would have been trivially satisfied — a guard that passes
for the wrong reason. It is now a fraction of the work actually attempted, so it
stays meaningful at any campaign size. (~57% of mutations decode.)

---

## Pass 13 — reorg state restoration and monetary policy

Two money-critical areas that every previous pass had deferred to "the audit
should review this". Neither had a dedicated pass, and both are the kind of thing
that fails silently rather than loudly.

**No defects found.** What follows is what was checked and, more usefully, the
tests that now hold the properties in place.

### Reorg: applying a block and undoing it must be exact

`pop_block` has to reverse everything `add_block` wrote. If it misses anything,
the node carries silent corruption forward — and every consequence is quiet:

* a key image left marked spent locks an honest user out of their own coins,
  permanently, with no error anywhere;
* an output left in the ring set can be drawn as a decoy that no longer exists,
  producing transactions nobody can verify;
* stale `emitted` miscounts the subsidy from that point on, so the node computes
  a different block reward than the rest of the network and forks itself off.

Checked by enumerating every mutable field of `Blockchain` (ten of them, the
other three being immutable config) and confirming each is undone, and that the
`Undo` record is captured *before* any mutation — it is, at the top of the commit
phase, so `outputs_len_before` and `emitted_before` are genuine pre-images.

Also confirmed: a key image repeated **within one block** is rejected
(`block_images`) rather than relying on the spent set, which at that point has
not been written yet. Two transactions in one block spending the same output
would otherwise both pass validation.

The existing rollback test checked a hand-picked list — height, output count,
emission, one key image. That is exactly how a *newly added* field escapes: it
fails nothing, because nothing looks at it. Added
`state_fingerprint`, which hashes **all** mutable state (sorting the hash map and
set, whose iteration order is not stable), and two tests asserting apply-then-undo
is byte-identical: one over a block containing a real spend, repeated three times,
and one over a six-block branch, which is what a real reorg rolls back.

**The tests were verified to fail when the undo is broken** — removing the single
line that restores `emitted` makes both fail with the intended message. A test
that cannot fail is not evidence.

### Monetary policy

`base_reward(e) = max((MONEY_SUPPLY − e) >> 20, TAIL_EMISSION)`, with the premine
counted as already-emitted so the curve continues from that baseline rather than
being added on top.

The reasoning that the smooth phase cannot exceed `MONEY_SUPPLY` ("each block
takes a fraction of what remains, so it asymptotes") is correct — and is exactly
the sort of argument that stays persuasive after someone edits a constant and
makes it false. So it is now simulated instead: the whole smooth phase is walked
block by block, asserting at every step that the total never exceeds the supply
parameter and that the subsidy never rises.

Measured, not assumed:

* **3,627,154 blocks** of smooth emission from zero, ending at **96.85%** of
  `MONEY_SUPPLY`, after which the tail continues forever (by design, as in
  Monero).
* From the premined baseline, **2,900,337 blocks** remain — about **11 years** at
  the 120-second target block time.
* `saturating_sub` is what keeps this safe past the supply parameter: a plain
  subtraction would underflow to an enormous remainder and mint a colossal
  subsidy. Pinned by asserting `base_reward(MONEY_SUPPLY) == TAIL_EMISSION` and
  the same at `u64::MAX`.
* `emitted` accumulates only the **subsidy**, never fees — correct, since fees
  are recycled coins rather than new issuance.

One durability note, not a defect: `emitted` is a `u64` accumulating tail
emission forever, so it saturates after roughly 18.4 million NOCT — on the order
of two thousand years at the tail rate. `saturating_add` means it degrades by
freezing the counter rather than wrapping, and a frozen counter yields the tail
subsidy, which is the correct answer anyway.

**For the audit, stated plainly:** the premine is **50% of the supply
parameter**. That is a policy decision, not a defect, and it is deliberate — but
it is the single most consequential economic parameter here and any reviewer will
raise it, so it should be reviewed as policy rather than discovered as a surprise.

---

## Pass 14 — F28, found by independent review

### F28 — Unbounded length-prefixed vectors → decode-time CPU amplification — **HIGH — Fixed**

**Found by an independent model review, not by this document's author.** Recorded
that way deliberately: the value of the finding is inseparable from where it came
from.

`read_vec` read a `u32` length and decoded that many items with no protocol
bound. Not trusting a length for *allocation* — the invariant this module
documented and relied on — only prevents "claim four billion items, send a
hundred bytes". It does nothing about an attacker who **supplies the bytes**,
because the work done is proportional to the items actually decoded.

Ring members are the ideal vehicle: 64 bytes buys two point decompressions plus
torsion checks, the best work-per-byte ratio in the format.

**Measured, before the fix: a single transaction padded to the 8 MiB p2p frame
cap took 8.79 seconds to reject.** No valid signature, range proof, or balance is
required — the cost is incurred during decoding, long before `Transaction::verify`
is reached. A handful of such messages per second from one peer stalls a node,
and the sender pays only the bandwidth.

**This is the same defect as F16**, which was found and fixed for
`additional_tx_public` in Pass 3 — and the reasoning written there
("an attacker could pad the vector to the message-size cap and force that many
point decompressions") applies verbatim to `ring`, `inputs`, `outputs`,
`tx_hashes` and `Peers`. The fix was applied to the one field where the bug was
noticed and never generalised. That is the more useful lesson than the bug: **a
fix that states a general principle in its own comment, and is then applied to a
single instance, is a half-fix**, and the author is the person least likely to
notice, having already filed the issue as closed.

**Fix:** `read_vec` now takes a protocol maximum and rejects on the length alone,
before any item is decoded — `MAX_RING_SIZE` (256), `MAX_INPUTS` (256),
`MAX_COMMITMENTS` for outputs (both transaction and coinbase),
`MAX_TXS_PER_BLOCK` (8192), `MAX_PEERS_PER_MESSAGE` (1024). All are several times
any legitimate value, so nothing valid is rejected; a second test asserts exactly
that, including that a real block still round-trips.

**After the fix the same 8 MiB message is rejected in 33.8 µs — a factor of
260,000.** The regression test asserts on **elapsed time**, not just the error,
because a test that only checked the error code would pass while the decoder
still ground through every member.

### What this says about the internal review

Thirteen passes of self-review did not find this, while an outside reader found
it quickly — and found it precisely by disbelieving a stated invariant. The
module asserted that lengths are "never used to pre-allocate, so a lie about a
vector's size cannot exhaust memory", which is true and was treated as though it
settled the question. It did not: memory was never the expensive part.

The general lesson for the professional audit: **the comments in this codebase
explain the author's reasoning, and where that reasoning is wrong the comment
will be confidently wrong too.** They are a guide to intent, not evidence of
correctness.

---

## Pass 15 — independent review, round two

The second round found **no new exploitable defect**, which is itself worth
recording. It did find two places where this document or its tests asserted more
than they established. Both are corrected.

### The genesis paragraph in F10 was factually wrong — **CORRECTED**

F10 stated that genesis *"pays nothing (no outputs, no reward), so there is no
premine and no key that could claim genesis coins."* True when written; false
since the premine landed. Genesis carries **500,000 NOCT — 50% of the supply
parameter** — to founder keys baked into `ChainParams`.

An auditor reading that pass alone would have concluded the chain has no premine.
That is the single most consequential economic fact about Nocturnal, and this document
denied it. Corrected in place, with the original text preserved so the error is
visible rather than quietly erased.

It is the F28 failure mode applied to prose: a conclusion correct at the time,
left standing after the thing it described changed. Worth generalising — **every
"fixed / found clean" verdict in this document is a claim about the code as it was
on the day it was written**, and this project has moved a great deal since.

### `state_fingerprint` did not do what its comment claimed — **FIXED**

Pass 13 introduced a fingerprint over all mutable `Blockchain` state and claimed
it meant *"the next field added either gets undone or breaks this test."* That was
false. The fingerprint listed fields by hand, so a newly added field would simply
not appear in it — the test would pass while `pop_block` silently failed to
restore it, which is exactly the silent corruption the test exists to catch.

**Fixed** by destructuring `Blockchain` exhaustively: every field is bound by
name, immutable configuration explicitly discarded with `_`. Adding a field now
**stops the file compiling** until someone decides whether it belongs in the
fingerprint. Verified by adding a field and confirming
`error[E0027]: pattern does not mention field`.

The claim is now true. Before, it was a comment describing a property the code did
not have — the same category of error as the F10 paragraph and F28 itself.

### On the round-two findings not acted on

The review also observed that several "surface reviewed and found clean"
conclusions rest on a check existing rather than on that check being reached by
every path. As a general criticism of this document that is fair and is now stated
plainly at the top of this pass. As a specific claim about `add_block` /
`pop_block` it independently re-derived Pass 13's conclusions and found no defect:
`Undo` captured before mutation, all ten mutable fields restored, intra-block key
images rejected before the persistent set is touched, and no path by which a
second spend of one image reaches it.

Its one factual slip: it believed `chain.rs` had not been supplied, when it had.
Worth noting because it means its coverage of the highest-value file was narrower
than it reported — a reminder that an independent reviewer's *stated* scope is
also a claim to verify.

---

## Pass 16 — F29, the gossip layer's fork-choice rule

### F29 — Tip advertised height, not work → a heavier chain was undiscoverable — **HIGH — Fixed**

Consensus decides forks on **cumulative difficulty**
(`Blockchain::would_reorg_to` compares total work). The gossip layer did not:
`Wire::Tip` carried `(network, height, tip_id)`, the tip id was discarded, and
the handler acted only on `height > our height`.

So **the network implemented "longest chain" while consensus implemented
"heaviest chain"** — two different rules in one system.

The consequence is not subtle. A peer whose branch carries more total work but is
no taller than ours said nothing the node could act on: no branch collection
began, `try_reorg` was never reached, and the node stayed on the lighter chain
while every peer disagreed with it. That is a persistent chain split reachable
without any attacker — a burst of hashrate on a fork produces exactly this shape,
a shorter chain with more work.

Worth being clear about what *did* already work, since an earlier note of mine
overstated the gap: fork collection was fully wired. A competing block arriving by
gossip — at a height we hold, or at our tip with `BadPrevId` — already triggered
`begin_branch_collection` → `try_reorg`. The defect was narrower and worse: the
one path that is *supposed* to advertise chain state could not express the
quantity fork choice is decided on.

**Fix:** `Wire::Tip` now carries cumulative difficulty as a fourth field, and the
handler is driven by it:

* same tip id ⇒ we already agree, do nothing (whatever height is claimed);
* not heavier by `would_reorg_to` ⇒ ignore it, **however long it claims to be** —
  a longer-but-lighter chain must never move us;
* heavier **and** taller ⇒ sequential catch-up, much cheaper than collecting a
  branch, and if it turns out to be a fork the first block fails `BadPrevId` and
  `react_block` escalates;
* heavier but **no taller** ⇒ it must have diverged, so collect the branch
  directly. *This is the case that was previously unreachable.*

This is a **wire format change**. Both testnet seeds are updated together.

4 tests: the equal-height-heavier case, a longer-but-lighter tip being ignored, an
identical tip costing nothing even with an inflated work claim, and a foreign
network being refused first.

**The first test was initially worthless and I nearly shipped it that way.** It
tried to *mine* an equal-height heavier branch and skipped itself when it could
not — printing `[f29] skipped` and passing green. Rewritten to assert the
**decision** (a heavier equal-height tip must start a branch download), with no
escape hatch, and then verified by restoring the old height-only rule and
confirming it fails with `got []`. A test that quietly declines to run is worse
than no test, because it reports success.

---

## Pass 17 — ring size: raised to 16, and made exact

Carried from the "remaining before mainnet" list. **Not a defect report** — a
deliberate consensus change, made now because pre-launch is the only time it is
free. It is a hard fork.

### What changed

`MIN_RING_SIZE = 11` (a floor) became `RING_SIZE = 16` (**exact**). An input
whose ring is any other length is invalid, in either direction, with a new
`ChainError::BadRingSize`.

### Why exact, and not simply a higher floor

The task as written was "raise the minimum". Raising it is the smaller half of
the problem, and on its own leaves a real privacy defect standing.

A floor prevents the obvious harm: a ring of one deanonymises the spender and
pollutes the anonymity set of everyone who later draws that output as a decoy.
But a floor permits 16, 17, 24 — and a **variable ring size is itself an
identifying mark**. If transactions may carry different counts, the count
partitions users by whichever wallet, version or setting produced them, and the
effective anonymity set becomes the group sharing that choice rather than the
ring itself. A user who picks an unusually large ring is *less* private, not
more, because almost nobody else made that choice.

Uniformity is the property being defended. Monero mandates an exact size for
precisely this reason, and this now matches it.

### One definition, so the layers cannot drift

`DEFAULT_RING_SIZE` in the wallet is now a re-export of the consensus constant
rather than its own `11`. With an exact rule, a wallet holding a different
opinion would not merely be less private — every transaction it built would be
rejected by the network. Two constants that must agree, in two crates, is a bug
waiting to happen; there is now one.

The wire decoder's `MAX_RING_SIZE` (256) is deliberately *not* tied to it: that
is a cheap sanity bound applied before any member is decoded (F28), and keeping
it loose means the consensus size can change without a wire format change.

### Tests

Two, replacing the old `ring_below_minimum_is_rejected`:

* **wrong size refused in either direction** — 1, 5, `RING_SIZE − 1` and
  `RING_SIZE + 1` are each built as real rings and each rejected. The oversized
  case is the one a floor would have let through, and the chain is warmed up far
  enough that the ring genuinely assembles, so the rejection is consensus
  refusing the size rather than the wallet failing to find decoys;
* **exact size accepted** — so the rule above is not simply rejecting everything.

### A note on how this went

The first attempt failed with `BadTimestamp`, not a ring error. Two mistakes:
`make_block` takes an **offset** from the genesis timestamp rather than an
absolute time, and 40 warm-up blocks push the median-time-past beyond a
hardcoded `5_000`. Worth recording because a test that fails for an unrelated
reason is one edit away from a test that *passes* for an unrelated reason.

Separately, a scripted edit to the constant swallowed the neighbouring
`MTP_WINDOW` and `FUTURE_TIME_LIMIT` definitions. They were restored and their
values **verified against the specification's constants table** (11 blocks, 2
hours) rather than from memory — reconstructing a consensus constant from recall
is exactly the way a subtle chain split gets introduced.

---

## Pass 18 — F30, the future-timestamp rule

### F30 — A block ahead of our clock banned the peer that sent it — **MEDIUM — Fixed**

Carried from the "median-based future-time-limit" item. Investigating it turned
up something more concrete than the refinement that was planned.

Two timestamp rules guard a block, and they are **not the same kind of rule**:

* `timestamp > median_time_past` — **chain-derived**, so every node computes the
  same answer. A violation is permanent and is genuine evidence of a bad block.
* `timestamp <= now + FUTURE_TIME_LIMIT` — **local wall-clock**, the only
  validity rule in the system that depends on something outside the chain. Two
  nodes whose clocks differ disagree about the very same block, and **the node
  that is wrong — the slow one — is the one that rejects it.**

Both returned `BadTimestamp`, and `react_block` scored anything that was not
`BadPrevId` as an invalid block:

```rust
Err(_) => out.misbehavior += MISBEHAVIOR_INVALID_BLOCK,   // 50 points
```

`BAN_THRESHOLD` is 100. So **two blocks from a correctly-synchronised peer ban
it**, on a node whose own clock is behind — and the victim is the peer with the
*better* clock. A node with a slow clock therefore progressively bans exactly the
peers most able to feed it the real chain, and isolates itself. No attacker is
needed; a stale NTP configuration does it.

**Fix:** a distinct `ChainError::TimestampTooFarAhead`, and `react_block` scores
nothing for it. The block is deliberately **not** marked seen, so it is
re-fetched and applied normally once the clock catches up. The verdict is "not
yet", not "invalid".

Two tests: the chain-derived rejection is still permanent and distinct, and a
future block scores **zero** misbehaviour while remaining re-fetchable. Verified
by removing the fix and confirming the score returns as **50**.

### On the "median-based FTL" that was planned instead

The original note suggested replacing the wall-clock bound with one derived from
the median timestamp, which would make every validity rule chain-derived and
remove the clock dependency entirely. **On inspection that is worse, and it is
not done.**

A cap of `median_time_past + limit` would make recovery from an outage
impossible: after the chain stalls for longer than the limit, every candidate
block is either at or below the median (rejected) or beyond `median + limit`
(also rejected), and the chain cannot restart without a coordinated rule change.
Bitcoin and Monero both keep a wall-clock upper bound for exactly this reason,
accepting the clock-skew exposure as the lesser problem.

So the residual is deliberate and worth stating plainly for the audit: **block
validity depends on the validating node's clock, by design, as it does in
Monero.** What has been fixed is the part that was genuinely wrong — treating
that clock-dependent disagreement as misbehaviour by the sender.

---

## Pass 19 — the public website, and F31

Adding `noct-web` (the landing page and read-only block explorer) meant putting
a Nocturnal process in front of strangers for the first time. Two things came out of
it: a design that keeps the node's admin surface unreachable, and a denial of
service that turned out to affect all three of Nocturnal's HTTP servers.

### The gateway's security property

A node's RPC is an **administrative** interface — `/mine`, `/submitblock`,
`/submit_tx`, `/mining/*` all change state. The usual way this goes wrong is a
web frontend that proxies `/api/<whatever>` through to the node, at which point
`/api/../mine` is a live question about your path normalisation.

`noct-web` avoids the question rather than answering it:

* `route()` is an **exhaustive whitelist** — three literal paths plus
  `/api/block/<u64>`. There is no pass-through arm and no string concatenation
  into a node URL, so an endpoint that was not written out by hand cannot be
  reached by any input.
* **There is no POST handler in the binary.** Not disabled — absent. Every
  non-GET is refused before a route is considered.
* The height is parsed as a `u64` before it reaches the node client.
* The node's RPC token is held server-side and never reaches a browser.

Tested by `no_path_reaches_a_mutating_node_endpoint`, and confirmed live: every
one of `/mine`, `/submitblock`, `/submit_tx`, `/mining/start`,
`/getblocktemplate`, `/info`, `/api/../mine` returns 404, and every POST 405.

Also fixed here: the gateway echoed the node's own error text to the client,
which names the node — `cannot reach http://10.10.10.75:19334`. On a public site
that publishes the operator's internal topology to every visitor. The detail now
goes to the operator's log and the client gets a flat `upstream node
unavailable`. Regression test: `an_upstream_error_does_not_leak_the_node_address`.

## F31 — An idle socket held a worker thread indefinitely — **MEDIUM — Fixed**

**Where.** `noct-web`, `noct-poold`, and the node's RPC — all three accept loops.

**The defect.** None of the three set a socket timeout on an accepted
connection. Each has a per-IP rate limiter, but a limiter is consulted *after* a
full request head has been read. A client that opens a socket and never finishes
its request therefore never reaches the limiter at all, and occupies a worker
thread and a connection slot for free, for as long as it cares to.

`noct-web` additionally read headers in an unbounded loop, so a client could
also hold a thread by sending headers forever, or grow the line buffer without
limit by never sending a newline.

**Measured.** Against `noct-web` with its 256-connection cap: 256 sockets, each
sent the 16 bytes `GET / HTTP/1.1\r\n` and nothing further, no bandwidth and not
one completed request. Every real visitor got **503, indefinitely**. This is the
cheapest attack found in the project so far — it needs no hash power, no
transactions, and essentially no traffic.

**The fix.** A read and write timeout set at accept time, *before* the TLS
handshake so a peer cannot stall in the handshake either — 15s for the website,
30s for the pool and node RPC, which legitimately serve slower clients
submitting blocks and shares. `noct-web` also caps the request head at 16 KiB
and 64 headers, and answers `431` rather than serving a truncated request line.

**Verified.** Re-running the identical attack after the fix: 503 while the
window elapses, then **200** — the site recovers on its own, where before it did
not recover at all.

**Residual, stated plainly.** This bounds the attack; it does not eliminate it.
An attacker who re-opens connections every timeout window can still occupy
slots. The difference is that this is now sustained, visible traffic from an
address that can be blocked, rather than a handful of sockets opened once and
abandoned. A per-IP *connection* cap (as opposed to a per-IP request cap) is the
real fix and is not implemented; for a public deployment, a reverse proxy that
enforces one, plus `--trusted-proxy`, is the recommendation in
[DEPLOY-WEB.md](DEPLOY-WEB.md).

### One implementation, not three

`client_ip` — the `X-Forwarded-For` handling, which is a security decision about
whose word to take — existed only in `noct-poold`. Rather than copy it into
`noct-web`, it moved to `noct_node::rpc` and both binaries now call the same
function. A subtly divergent second copy of "which header do we believe" is
exactly how one of two servers ends up trusting one it should not. The pool's
three existing proxy tests were kept and still pass against the shared function.
