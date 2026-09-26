# A second value pool: Orchard (Halo 2) beside the ring pool

Status: **design, no code** (2026-09-26). The dependency spike is done and its
numbers are in §2; nothing has been written in `core/`, `node/`, `wallet/` or
`pool/` yet. This document is the thing to argue with before any of that
happens.

Decision context: Noct keeps its ring pool (RingCT/CLSAG/Bulletproofs+) **and**
gains a zk-SNARK shielded pool built on Zcash's Orchard. Both exist permanently,
users pick a pool per transaction, and value moves between them in either
direction. Block rewards and the genesis premine are created **inside** the
Orchard pool. Proof of work stays RandomX; nothing about mining changes.

---

## 1. Verdict

**Feasible, and unlike the atomic-swap spike this one is a consensus change** —
a new transaction version, new chain state, and new validation rules. It is a
hard fork, which is why it happens now, while Noct is still on a testnet that
can be reset.

What is genuinely new, in rough order of risk:

1. **Chain state that is not a set.** The ring pool needs a set of spent key
   images. Orchard needs a *nullifier set* **and** an append-only Merkle tree of
   note commitments whose root history is part of consensus. A tree is much
   harder to roll back than a set, and this project has already been bitten by
   rollback bugs — persistence-on-restart alone turned out to be three stacked
   faults rather than one.
2. **The turnstile.** Each pool's total supply is tracked publicly and may never
   go negative, so a counterfeiting bug in one pool's cryptography cannot
   silently inflate the other.
3. **Shielded coinbase maturity** (§7), which is the one place where Noct's
   existing rules and Orchard's anonymity genuinely conflict, and where this
   design departs from Zcash.

What is *not* a problem: the cryptography is a maintained, audited crate
(`orchard` 0.15.5, Halo 2, no trusted setup), verification is cheap enough for
consensus, and both bundle shapes Noct needs are supported today.

---

## 2. What the spike measured

Run with `OrchardCircuitVersion::FixedPostNu6_2` only. Every `orchard` release
before 0.14.0 is **yanked** — the original Action circuit was unsound — and
`orchard_insecure_v1` is never used.

| | Windows dev box | Linux node (EPYC 7C13) |
|---|---|---|
| Proving key build (once, at startup) | 1,520 ms | — |
| Verifying key build (once, at startup) | 901 ms | — |
| Prove, 1 action | ~500 ms | ~750 ms |
| **Verify, 1 action** | **~5 ms** | **~9 ms** |
| Proof size | 4,992 bytes | 4,992 bytes |

Two results decide the design:

- **A custom value balance works.** An outputs-only bundle reports exactly
  `-value`. That number *is* the turnstile: it is the public statement "this
  much entered the shielded pool".
- **A coinbase-shaped bundle works.** `BundleType::Coinbase` with
  `Flags::SPENDS_DISABLED` builds, proves and verifies, so a block reward can be
  a shielded note with no spends.

Verification is what every node pays on every block, and at ~9 ms per action a
full block of shielded transactions is affordable. Proving is paid by whoever
makes a transaction (and by the pool, per payout), and half a second is fine.

---

## 3. The two pools

| Part | Ring pool | Orchard pool |
|---|---|---|
| Crypto | ed25519, CLSAG rings of 16, Bulletproofs+ (`monero-oxide`) | Pallas/Vesta, Halo 2 (no trusted setup) |
| Double-spend check | key images | nullifier set |
| Chain state | output set | note-commitment tree + anchor history |
| Keys | existing Noct keys and subaddresses | separate Orchard spending key, FVK, address |
| Amounts | Pedersen commitments | inside the proof |
| Status | built, running on testnet | to build |

Both are private. They are not redundant: the ring pool's anonymity comes from
a 16-member ring, the Orchard pool's from the whole tree of notes. The ring
pool's guarantees are the weaker of the two, which is the reason for building
this at all.

---

## 4. Transaction format

A new transaction version carries an **optional** Orchard bundle beside the
existing ring inputs and outputs. A transaction may be ring-only (exactly what
exists now), Orchard-only, or both — "both" is what a cross-pool transfer is.

```
tx v2 = {
    ring_inputs:   [Input]        // as today: key image, ring, CLSAG
    ring_outputs:  [Output]       // as today: stealth key, commitment, encrypted amount
    fee:           u64            // public, as today
    cross:         i64            // public; + into Orchard, - out of Orchard
    orchard:       Option<Bundle> // anchor, actions, proof, binding sig, flags, value_balance
}
```

Old nodes must reject a v2 transaction outright rather than ignore the bundle —
otherwise they would see a ring side that does not balance and, worse, could be
convinced value appeared from nowhere. That is what makes this a hard fork.

### How the two sides balance

The ring side already balances homomorphically against a **public** fee. The
rule in `core/src/tx.rs` today is

```
Σ pseudo-outs == Σ output commitments + fee·H
```

and the cross-pool amount is simply a second public term on the right:

```
Σ pseudo-outs == Σ output commitments + (fee + cross)·H   // cross > 0: value leaving the ring pool
```

which reuses `Commitment::fee` unchanged — the same construction applied to a
second public number.

The Orchard bundle must then declare `value_balance = -cross`, negative meaning
value entering the shielded pool. Unshielding is the same equation with `cross`
negative: the ring side may create more output value than it consumed, exactly
by the amount the bundle says left the shielded pool.

So a cross-pool transfer is two public numbers that must agree. This is why the
crossing amount cannot be private — and being explicit about that is better than
a design that pretends otherwise.

---

## 5. The turnstile

Chain state gains two running totals:

```
ring_total:    u64   // value currently in the ring pool
orchard_total: u64   // value currently in the Orchard pool
```

Every transaction moves value between them by `cross`, and coinbase adds to
`orchard_total`. **Any block whose application would drive either total below
zero is invalid**, and so is any individual transaction.

The point is containment, and it is worth stating plainly: if Halo 2, or our use
of it, ever allows a forged proof, the damage is capped at `orchard_total` — the
attacker cannot mint ring-pool coins, because taking value out of the shielded
pool requires the shielded total to cover it. The same holds in reverse. Zcash
adopted this after real inflation bugs, and it is the cheapest insurance in this
whole design.

The totals are consensus state: they are computed by every node, persisted, and
rolled back on reorg exactly like the output set.

---

## 6. Storage, and the part that will go wrong

The nullifier set is easy — it is the key-image set again: a `HashSet<[u8;32]>`,
insert on apply, remove on undo.

**The note-commitment tree is not.** It is append-only, 32 levels deep, and its
root after every block is consensus data. Three things must survive a restart
and roll back correctly on reorg:

- the tree **frontier** (enough of the rightmost path to append),
- the **anchor history** — recent roots, because a transaction proves membership
  against a root that was current when its wallet built it,
- the two **pool totals**.

Rolling a tree back is where this will break if it breaks. The options:

1. **Per-block undo records**: store, for each block, the note commitments it
   appended and the nullifiers it added. Undo pops exactly that many leaves.
   This is the same shape as the existing `Undo` and fits how the chain already
   thinks. Recommended.
2. Snapshot the frontier every block. Simple, larger, and wasteful at Noct's
   block rate.

Whichever is chosen, the test that matters is not "does it append correctly" but
**"is the root after a reorg identical to the root of a node that never saw the
abandoned branch"** — byte for byte. That is the property that cost this
project three stacked bugs to learn.

**Anchor depth** must be chosen against the existing constants: `MAX_REORG_DEPTH`
is 100 and `COINBASE_MATURITY` is 100. An anchor older than the deepest reorg the
chain will accept can never be invalidated by one, so **accepting anchors from
the last 100 blocks costs nothing and is the natural choice**.

---

## 7. Coinbase, the premine, and a maturity problem Zcash does not have

The plan is that block rewards and the 500,000 NOCT genesis premine are created
directly as shielded notes: `BundleType::Coinbase`, spends disabled,
`value_balance = -reward`. The spike confirms the crate builds, proves and
verifies exactly that.

**But coinbase maturity does not survive the move to a shielded pool.** Noct
requires a coinbase to be buried 100 blocks before it can be spent: maturity
must be at least as deep as the deepest reorg the chain accepts, so that a reorg
can never unspend an already-spent reward. In the ring pool this is checked at
spend time, because the output being spent is identified. **In Orchard nobody
can tell which note is being spent — that is the entire feature.** A validator
handed a shielded spend cannot ask "is that note 100 blocks old?".

Two ways out:

1. **Delay insertion.** A coinbase note's commitment is not added to the tree
   until the block is 100 deep. Until then it does not exist as far as any anchor
   is concerned, so it cannot be proven against and therefore cannot be spent.
   Maturity becomes a property of the tree rather than of the spend, and needs no
   circuit change. **Recommended.**
2. Put a height in the note and enforce it in the circuit. This means a custom
   circuit, which means leaving the audited one. Rejected on those grounds alone.

Option 1 has a consequence to accept deliberately: the tree's contents lag the
chain tip by 100 blocks for coinbase notes, so `orchard_total` and "notes
spendable" are not the same number, and the wallet must show a pending balance.
That is the same thing miners already live with.

Note also that **this is off Zcash's path**: from NU6.3, Zcash consensus requires
*zero* Orchard actions in a coinbase transaction. The crate still builds such a
bundle, and Noct would be relying on a capability upstream no longer exercises in
that position. It deserves its own adversarial test, not just a unit test.

---

## 8. Fees

Orchard actions are large (~5 KB each) and cost every node ~9 ms to verify, so
the fee must be size-based rather than flat, and should price verification, not
just bytes. A rough shape, to be fixed with real numbers before launch:

```
fee = base + per_byte·size + per_action·actions
```

A cross-pool transfer should use `BundleType::UNPADDED` rather than the default.
The crate's own documentation says UNPADDED is for "pool migrations, where the
per-pool value balances reveal the transfer" — which is exactly this case. The
default pads to two actions for indistinguishability, and here the transfer's
shape is already public, so padding buys nothing and costs a second proof.

---

## 9. Wallet

The Orchard side is a second wallet inside the same wallet:

- **Keys**: an Orchard spending key, full viewing key, and an address type with
  its own prefix, distinct from the existing Noct address so the two can never be
  pasted into each other.
- **Scanning** is trial decryption of every action in every block, not the
  view-key tagging the ring pool uses. This is the expensive part of a shielded
  wallet and the thing that decides whether the wallet is usable.
- **Witnesses**: a note's Merkle path must be kept current as the tree grows, for
  every unspent note. This is new state the wallet must persist and, like the
  node's tree, roll back on reorg.
- **Choosing a pool** per send, with the privacy cost (§11) surfaced rather than
  buried.

The wallet-state work already done (public-only records, secrets re-derived on
load, checksummed, owner-only) is the right foundation: Orchard note records must
follow the same rule — **nothing that can spend is written to disk**.

---

## 10. The mining pool

The pool mines into an Orchard address, so its rewards are shielded notes and
**paying miners requires Orchard spends**. Consequences:

- The pool proves ~500 ms per payout transaction. With batching (several
  recipients per transaction, as now) this is not a bottleneck.
- The pool's wallet needs witnesses and scanning, like any Orchard wallet.
- Miners may want payout to either pool. Paying into the ring pool means the
  pool performs an unshield, and the amount is public — which for a pool payout
  it effectively already is.
- The existing ledger invariants (`owed + non-lost payments == credited_total`)
  are unaffected: they are bookkeeping, not chain state.

---

## 11. Privacy costs, stated plainly

- **Crossing is public.** Shielding X and later unshielding X links the two
  events. The wallet should round amounts and add random delays; that lowers the
  correlation but does not remove it. Anyone who shields and unshields the same
  unusual amount has told the chain something.
- **The anonymity set is split** between two pools for as long as both exist,
  which is permanent by decision. A small shielded pool is a weak shielded pool,
  and the ring pool keeps whatever weaknesses rings have.
- Coinbase notes lag the tip by 100 blocks (§7), which makes freshly-mined
  shielded value distinguishable from the rest by timing.

---

## 12. Build order

Each step ends with tests and leaves the chain in a state that still works.

1. **`core`**: Orchard types, bundle encode/decode, the new transaction version,
   the balance equation with `cross`, and the turnstile totals — all pure, all
   unit-testable with no node.
2. **`core` chain state**: nullifier set, commitment tree, anchor history, undo
   records. The reorg-equivalence test from §6 is the acceptance gate.
3. **`node`**: proof and signature verification in block validation, mempool
   rules, and the proving/verifying keys built once at startup (1.5 s / 0.9 s —
   startup cost, not per block).
4. **Coinbase and premine** as Orchard notes, with the delayed-insertion maturity
   rule.
5. **`wallet`**: keys, scanning, witnesses, spending, pool choice.
6. **`pool`**: Orchard payouts.
7. **Adversarial pass** (§13), then a testnet reset — every node stopped before
   any node is wiped — then a release.

---

## 13. Adversarial checklist

Written now, so it is not invented after the code exists:

- a proof padded with trailing data (GHSA-2x4w-pxqw-58v9), and an identity `epk`
- a bundle using the yanked pre-0.14 circuit, or `orchard_insecure_v1`
- the same nullifier twice in one block, and across two blocks
- a stale anchor, an anchor from an abandoned branch, and an anchor 101 blocks old
- turnstile underflow: unshield more than `orchard_total`, in one transaction and
  spread across a block
- a reorg that crosses the pool boundary: a shielding transaction abandoned, its
  notes rolled out of the tree, and the root compared against a clean node
- a coinbase note spent before 100 blocks, via an anchor that should not contain it
- a v2 transaction presented to a v1 node (must be rejected, not ignored)

---

## 14. Open questions

1. **Does delayed insertion (§7) interact badly with anchor depth?** A wallet
   building against a 100-block-old anchor and a coinbase note inserted at
   exactly 100 blocks are the same boundary; off-by-one here is a consensus
   split.
2. **Fee constants.** Needs measurement against real block sizes, not a guess.
3. **Does the pool pay in NOCT-ring or NOCT-shielded by default?** Affects miner
   UX and the pool's own privacy.
4. **Scanning cost on a phone-class device** — trial decryption per action is the
   number that decides whether a light wallet is possible at all.
5. **Do we keep `orchard`'s bundle encoding on the wire, or Noct's own?**
   Upstream's is battle-tested; ours would be consistent with the rest of the
   chain. Prefer upstream's unless there is a reason.

### Sources

- `orchard` 0.15.5 — crate source and `CHANGELOG.md` (NU6.2/NU6.3 entries and the
  0.14.0 security fixes) in the cargo registry.
- Spike: `scratchpad/orchard-spike`, and `/root/orchard-spike` on the build box.
- `docs/DEPENDENCIES.md` for the toolchain move (Rust 1.85.1) this depends on.
