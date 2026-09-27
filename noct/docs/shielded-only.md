# One pool: the shielded-only alternative, considered and rejected

Status: **rejected 2026-09-27**. Kept as a record of a road not taken. The
design in force is the two-pool one in [`orchard-pool.md`](orchard-pool.md).

> **Why it was rejected.** It was adopted briefly on the belief that offering a
> choice of pool was "optional privacy" in Zcash's sense. It is not, and the
> difference matters: Zcash's choice is between private and **public**, where
> picking public publishes a transaction's sender, recipient and amount for
> ever. The two-pool choice is between **two private protocols** — ring
> signatures or zk proofs — and neither publishes a transaction's contents.
> Nobody can opt out of privacy and nobody can leak by accident.
>
> What remains public in the two-pool design is the **amount** moved when value
> crosses between pools, and only for those who cross. That is a far smaller
> leak than a transparent pool, and it does not justify giving up a choice of
> mechanism, one anonymity model as a fallback for the other, or the
> containment the turnstile provides.
>
> Everything below is still accurate about what a single pool would mean, and
> §4 (coinbase maturity by delayed insertion) is what the chain does either way.

Nocturnal holds all value in **one** pool, built on the Orchard protocol
(Halo 2, no trusted setup). The RingCT/CLSAG pool is removed from consensus.
Proof of work stays RandomX. There is no transparent pool and no second pool to
move value to, so **privacy is not a choice a user makes** — it is the only way
the chain represents value.

**The model is Pirate Chain's, not Zcash's.** Zcash has the same shielded
cryptography but keeps a transparent pool beside it, so most of its value sits
unshielded and the shielded set is small. Pirate Chain took Zcash's machinery
and removed the choice: shielded is the only thing that exists. That is what
this document specifies. Two differences from Pirate worth stating:

- Pirate uses **Sapling** (Groth16), which depends on a trusted-setup ceremony.
  This uses **Orchard** (Halo 2), which has **no trusted setup** — there is no
  ceremony whose participants must be believed.
- Proof of work stays **RandomX**, as Monero's is, so mining remains CPU-shaped
  rather than Equihash on specialised hardware.

From Monero it keeps the principle — privacy is mandatory, not a mode — and the
mining model. What it gives up is Monero's *mechanism*: a ring of sixteen decoys
is replaced by an anonymity set of every note the chain has ever created.

---

## 1. Why, and what it cost to decide

The two-pool design made the crossing amount public. That was not an
implementation shortcut: the pools prove balance in different groups — Pedersen
commitments over ed25519 on one side, value commitments over Pallas on the
other — and a point on one curve cannot be added to a point on the other. The
only quantity both sides could agree on was a plain integer.

Hiding it would have required proving that a value committed on ed25519 equals a
value committed on Pallas: a cross-curve equality proof, in the consensus path.
This project's standing rule is that its cryptography is deliberately
unoriginal, so that it can be audited by comparison against systems that have
been attacked for years. A bespoke cross-curve proof is the opposite of that.
And even with the amount hidden, a transaction touching both pools is *visibly*
a crossing unless every transaction carries a bundle.

So the crossing is made private by removing it. With coinbase and the premine
minted as shielded notes, a fresh chain's ring pool would start empty and have
no way to ever receive anything — one-way turnstile and shielded-only are the
same thing on a chain that has not launched.

**What this costs, accepted deliberately:**

- **The turnstile no longer protects anything.** Its purpose was containment: a
  counterfeiting bug in one pool could not inflate the other. With one pool
  holding the entire supply, a flaw in Halo 2 — or in our use of it — is a flaw
  in all of it. This is the real price, and it is paid for privacy that cannot
  be opted out of.
- **The audit story changes.** "Compare it against Monero" becomes "compare it
  against Orchard as Zcash ships it, and against Pirate Chain's deployment of
  the same family". Equally defensible, but it is a different claim, and the
  reviewed `monero-oxide` stack stops carrying weight.
- **There is no fallback.** Nothing can retreat to a simpler pool if Orchard is
  found wanting.

---

## 2. What a transaction is now

```
tx := fee          u64, public
      bundle       an Orchard bundle, required
```

No ring inputs, no ring outputs, no `cross`, no range proof, no CLSAG. The
bundle carries everything: which notes are spent (as nullifiers), which are
created (as commitments), and the proof that the arithmetic holds.

**The fee is the bundle's value balance.** A transaction states
`value_balance = +fee`: that much value leaves the shielded pool. The block's
coinbase then mints `subsidy + fees` back into it. Across a block the supply
rises by exactly the subsidy, and a fee is never in anyone's hands in between.

This is how both Zcash and Pirate Chain pay fees from a shielded pool, and it
is the reason a single pool needs no second pool to pay fees from.

**Amounts are never public.** The fee is, as it must be — a miner has to see
what it is being paid — and everything else is inside the proof.

---

## 3. What the chain keeps

Most of the shielded machinery already built stands unchanged:

| Part | Status |
|---|---|
| Nullifier set | as built — the double-spend check |
| Note-commitment tree + anchor history | as built, `ANCHOR_DEPTH = MAX_REORG_DEPTH` |
| Bundle wire format | as built, proof length derived not declared |
| Coinbase maturity by delayed insertion | as built (§4) |
| Supply | one total, replacing the two-pool turnstile |
| Reorg rollback | as built: restore, never invert |

And what leaves consensus: the output set, key images, ring maturity, decoy
selection, the aggregate range proof, and the balance equation over Pedersen
commitments.

---

## 4. Coinbase, unchanged by this decision

A block reward is an Orchard bundle with spends disabled and
`value_balance = -(subsidy + fees)`. The genesis premine is the same shape.

Maturity still cannot be checked at spend time — an Orchard spend names nothing,
which is the entire feature — so it remains a property of the **tree**: a
coinbase note is withheld from the commitment tree until the chain has reached
`created_height + COINBASE_MATURITY`, matching the ring pool's old rule exactly.
Until then no anchor contains it, so no proof can be made against it.

The consequence to accept is unchanged: the spendable supply lags the emitted
supply by up to a maturity window, and a wallet must show that as pending.

---

## 5. What has to be rewritten

This is the honest scope. It is not a small change.

1. **`core::tx`** — one transaction form: fee plus bundle. The ring transaction,
   its signing message, its balance rule and the `cross` field all go.
2. **`core::block`** — the coinbase becomes a bundle. Block validation checks
   the bundle rather than a coinbase output, and checks
   `value_balance == -(subsidy + fees)`.
3. **`core::chain`** — the output set, key-image set, ring maturity and decoy
   selection leave. What remains is the shielded state, already built.
4. **`core::wire`** — transaction and block encodings follow.
5. **`wallet`** — Orchard keys, trial-decryption scanning, note witnesses,
   spending. The RingCT wallet is replaced, not adapted.
6. **`node`** — the miner must build and prove a coinbase bundle (~500 ms) on
   every block it mines; that is now on the critical path of block production.
7. **`pool`** — payouts become Orchard spends; the ledger is unaffected.
8. **Genesis changes**, so the chain id changes. The testnet resets — every node
   stopped before any node is wiped.

**Kept in the tree, out of consensus:** the `monero-oxide` ring stack and
`core::ring`, `core::amounts`. They are not deleted in the same change that
removes them from the rules — a rule change and a code deletion should not be
reviewed as one thing — but nothing on the chain can reach them.

---

## 6. Order of work

Each step leaves the tree building and tested.

1. This document, and the superseded parts of `orchard-pool.md` marked as such.
2. The shielded-only transaction in `core`, with the fee-as-value-balance rule.
3. The coinbase bundle, and block validation for it.
4. Chain state: the ring parts removed, the shielded state promoted to *the*
   state.
5. Wire formats.
6. Wallet.
7. Miner and pool.
8. Adversarial pass, testnet reset, release.

---

## 7. Open questions

1. **Minimum fee, and who sets it.** With no transparent pool, a fee of zero is
   expressible; the mempool needs a policy or a consensus floor.
2. **Does anything still need `pools.rs`?** One pool needs one counter, not a
   turnstile. The module should shrink to a supply total or go.
3. **Scanning cost on a light client** — trial decryption per action is now the
   only way to find your own money. This decides whether a phone wallet is
   possible at all, and it is no longer optional for any user.
4. **Dummy-action policy.** Orchard pads to two actions by default. With every
   transaction shielded, padding is what makes transaction shapes uniform, and
   the default deserves a deliberate choice rather than inheritance.
