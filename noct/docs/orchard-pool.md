# A second value pool: Orchard (Halo 2) beside the ring pool

> **THIS IS THE DESIGN.** A shielded-only alternative was considered on
> 2026-09-27 and rejected; see [`shielded-only.md`](shielded-only.md) for what it
> would have meant and why it was not taken.
>
> The decision turns on a distinction worth stating plainly. Zcash lets a user
> choose between **private and public**, and anyone choosing public publishes
> everything about that transaction for ever. This design lets a user choose
> between **two private protocols** — ring signatures or zk proofs. Neither
> option publishes a transaction's contents, so nobody can opt out of privacy
> and nobody can leak by accident. The only thing that is public is the
> **amount** moved when value crosses between the pools, for the people who
> choose to cross.

Status: **design, no code** (2026-09-26). The dependency spike is done and its
numbers are in §2; nothing has been written in `core/`, `node/`, `wallet/` or
`pool/` yet. This document is the thing to argue with before any of that
happens.

Decision context: Noct keeps its ring pool (RingCT/CLSAG/Bulletproofs+) **and**
gains a zk-SNARK shielded pool built on Zcash's Orchard. Both exist permanently,
users pick a pool per transaction, and value moves between them in either
direction. A miner chooses which pool its **block reward** is created in. The
**genesis premine stays a transparent ring output** — see the decision at the end
of §12. Proof of work stays RandomX; nothing about mining changes.

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

## 6a. Which pool a block reward lands in — the miner decides

If every reward were minted into one pool, that pool would be where all new
value enters, and anyone who preferred the other one would have to cross to get
there — publishing an amount purely for choosing a mechanism. A choice that is
free in one direction and costs privacy in the other is not much of a choice.

So **the miner nominates the pool its coinbase pays into**, per block, the same
way it already nominates an address. Both pools receive fresh value, and a user
can live entirely inside either one without ever crossing.

Consequences, each of which has to be handled rather than assumed:

* Block validation must accept a coinbase in either shape — a ring output, or an
  Orchard bundle with spends disabled — and check the reward against the same
  subsidy either way.
* The supply invariant becomes `ring + shielded == emitted` with the coinbase
  crediting whichever pool the block named. That is already how the turnstile
  is written; it takes the pool as an argument.
* A shielded coinbase matures by delayed insertion (§7); a ring coinbase matures
  as it always has. They must mature on the same block, and there is a test that
  says so rather than restating the arithmetic.
* Mining a shielded coinbase costs a proof (~500 ms) on the block-production
  path. A miner that would rather not pay it can nominate the ring pool, which
  is another reason not to force the choice.

**Built, in `core/src/block.rs` and `core/src/shielded_state.rs`.** Three things
about it were not obvious and are worth recording.

*The output count is the discriminant.* A shielded coinbase carries no ring
outputs, and a ring coinbase always carries at least one, because it has to pay a
reward and `TAIL_EMISSION` is a floor. So an empty output vector — and only an
empty one — is followed by a bundle tag. A ring coinbase's bytes are therefore
unchanged, which is what keeps its hash, every block id built on it, and the
chain id itself unchanged.

*Fees cross when the reward is shielded.* The subsidy is new coins and mints into
whichever pool the miner named. Fees are **not** new coins: the transactions that
paid them did so on the ring side. Paying them into the shielded pool moves them,
so the turnstile is told, or the two pools would drift apart by one block's fees
every time a miner chose the other one. Emitted supply is identical either way,
and there is a test that compares the two paths rather than restating the sum.

*A coinbase bundle needs a sighash of its own.* It has nothing around it to bind
to — no ring inputs, no fee to cover, no other transaction — so an authorized one
could otherwise be lifted out of its block and replayed in another claiming the
same reward. It is bound to `height ‖ prev_id`, both fixed before mining starts,
so a miner proves its bundle once per template and then searches nonces freely.

---

## 6b. What the bundle's signatures cover, and why the proof is not enough

Found while wiring the coinbase up, and it applied to the v2 transaction as
written too: **`Bundle::verify_proof` does not check the value balance.**

`value_balance` is a public input carried *beside* the proof. What ties it to the
actions' value commitments is the **binding signature**, whose validating key is
derived as `Σ cv_net − value_balance·R` — a key that can be signed under only if
the two agree. Verify the proof and not the binding signature and a bundle may
claim any balance it likes: on the way into the pool that mints coins from
nothing, and on the way out it mints them in the ring pool. It is the whole of
the turnstile's arithmetic, resting on one signature. The **spend authorization**
signatures are the other half: the proof shows a note exists and that `rk` is its
correct randomized key, but only a signature under `rk` shows the owner agreed.

So consensus calls `ShieldedBundle::verify(sighash)`, never `verify_proof` alone,
and the two sighashes are:

| Bundle | Signed over |
|---|---|
| In a transaction | `"noct.tx.bundle.v1" ‖ signed core` |
| In a coinbase | `"noct.coinbase.bundle.v1" ‖ height ‖ prev_id` |

The **signed core** is everything a transaction commits to except its
signatures: version, transaction keys, fee, key images and rings, outputs, range
proof, and `cross`. Both signature systems sign it, and that is what stops them
chasing each other — the ring signatures sign the core *plus* the authorized
bundle, while the bundle signs the core *alone*. If the bundle's signatures also
covered the ring signatures, each side would have to be made after the other.

The consequence for the API: a wallet cannot hand a finished bundle to
`Transaction::build_with_shielded`, because the sighash covers a ring side that
does not exist until part-way through building. It passes a callback that is
handed the sighash and returns the authorized bundle.

A test rewrites `value_balance` in an encoded bundle and asserts that the proof
still verifies while the binding signature does not — the inflation bug stated as
an executable claim rather than a paragraph.

---

## 7. Coinbase, the premine, and a maturity problem Zcash does not have

Block rewards can be created directly as shielded notes: `BundleType::Coinbase`,
spends disabled, `value_balance = -reward`. The spike confirms the crate builds,
proves and verifies exactly that, and the miner chooses per block template.

**The genesis premine is the exception, and deliberately so** — it stays a
transparent ring output. See the decision at the end of §12: a genesis bundle
would have to be a baked constant that can never be corrected, and at genesis the
pool holds one note, so shielding it there buys nothing the founder cannot get
later with an ordinary transaction.

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

**Built, in `wallet/src/shielded.rs`.** What was decided along the way:

*One seed, both pools.* A Noct wallet is a single 32-byte spend secret and the
24-word phrase encodes it directly, so the Orchard key is derived from those same
bytes — hashed with a domain tag first, then through ZIP-32's own
`SpendingKey::from_zip32_seed` at `m/32'/1337'/account'`. An existing backup
restores the shielded side too, and there is no second thing to write down and
lose. The coin type is a placeholder (Noct has no SLIP-44 number) and is pinned by
a test, because changing it silently changes every address the wallet ever handed
out.

*Positions come from core, not from the wallet.* Leaf order is consensus, and a
coinbase note enters the tree maturity blocks after the one that made it, so the
wallet cannot compute positions from what it sees in a block. It asks
`ShieldedState::block_commitments` — one statement of that ordering, in core, and
the wallet is a consumer of it. `apply_block` appends exactly the same list.

*Every block is checked against the chain's root.* `scan_block` takes the chain's
shielded state from **both** sides of the block: the earlier one decides leaf
order, the later one is what its own tree is compared against. Scanning out of
order otherwise produces positions that are wrong and nothing that looks wrong —
balances still add up, and the failure surfaces much later as a transaction the
network rejects for no visible reason.

*No rollback, by design.* The ring side already settled this: a node shorter than
the wallet has scanned is reported and the caller rebuilds, because that can cost
time and never correctness. Inverting a witness is the arithmetic the node refused
to do to its own tree, with less to check it against. So a reorg surfaces as a
root mismatch at the block that caused it.

*What is on disk, and why it is allowed to be.* The note plaintexts, positions,
witnesses and the wallet's copy of the tree. A note plaintext does not let its
reader spend — that needs the spend authorizing key, which comes from the seed and
is never written — but it does reveal value and recipient, exactly as the ring
records already reveal which outputs are the wallet's and what they were worth.
Nullifiers are **recomputed** on load rather than stored, so a reader cannot watch
the wallet's spends. Loading checks the file against the chain: same root, same
leaf count, and every unspent note's witness must give a path to *that note* under
a root the chain still accepts.

### The shape a shielded-to-shielded payment takes

Making the wallet usable needed one thing the transaction format did not yet
express, and §4 had deferred: **a transaction with no ring side at all.** Without
it, someone who wants to live inside the shielded pool has to touch the ring pool
to move money, which is most of the point gone.

The fee is what makes it work. A shielded-to-shielded payment states `fee = F` and
`cross = -F`: that much value leaves the pool for the ring side, where fees live,
and the block's coinbase collects it like any other fee. The ring balance rule
needs no special case — `0 == 0 + (F + (-F))·H` — which is the payoff for having
written that rule once. So the transaction has no inputs, no outputs, and no range
proof, and the structural check stops deciding: with a bundle present, either half
of the ring side may be empty and the balance rule decides. The range proof became
`Option`, present exactly when there are outputs to cover, which leaves a version 1
transaction's bytes untouched. A full shield with no change uses the same freedom
on the other half — ring inputs, no ring outputs, and no change output to tie the
payment back.

While wiring this up, one more gap closed: the mempool was admitting shielded
transactions without checking their anchor or nullifiers, so a replayed
double-spend of a note bought an attacker a proof verification per copy. Those are
hash lookups and now happen before `verify`, which is the same argument the ring
side's admission order already made.

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

**Built, from the payout side.** A miner's payout address may now be **either
kind**, and one transaction pays a mixed batch. That is the half that matters to a
miner, and it works with the pool's income as it is today — ring coinbases — so it
did not have to wait for the pool to mine into an Orchard address.

*One decoder, one decision.* `AnyAddress::decode` accepts either kind and lives in
core, because the pool validated payout addresses in five places and five copies of
that decision would reject shielded miners in some of them and accept them in
others — which is worse than rejecting them everywhere.

*Fund each side from its own pool, and cross only the shortfall.* A crossing
publishes its amount, so it happens when it must and not out of habit. Shielded
payees are paid from the pool's own notes when the notes cover them, and then
**nothing crosses at all** — the transaction is two independent halves sharing a
fee. Otherwise they are paid by crossing in, and the total entering the pool is
public. An all-ring batch is still byte-for-byte the version 1 transaction the pool
has always built: no bundle, no proof, nothing to pay for.

*Both halves of the pool's wallet are synced and saved together.* The state file
(`wallet::state`, now version 3) carries the shielded half, because rescanning for
it would mean trial-decrypting every action in the chain on every payout run. They
sync in one pass over the blocks rather than two, since the shielded side needs the
chain's shielded state from *both sides of each block* and a second pass could not
supply the earlier one without rewinding.

Two consequences worth recording, both found by building this rather than by
reasoning about it:

- **Paying a ring address needs at least one ring input**, even when the money comes
  out of the shielded pool. The ring outputs' masks have to cancel against a
  pseudo-out, and a wallet with no ring outputs has nothing to supply one. So a pool
  that pays ring addresses has to keep some ring value, and a purely shielded pool
  could not unshield at all.
- **A shielded wallet cannot join the commitment tree in the middle.** A note's
  position is its index among every note the chain has ever made, so scanning has to
  start at genesis — the same rule the ring side has for global output indices. It
  is now its own error (`BehindTheChain`) rather than being reported as a diverged
  tree, because it is a different mistake with a different remedy.


### The shielded coinbase, and where the proof goes

**Built.** `--miner-address` and `/getblocktemplate?address=` both take either kind
of address, and that choice decides which pool the reward is created in. §10's
opening sentence is now true: a pool can mine into an Orchard address and its
income is notes.

*The shape is consensus, so it lives in core.* `Coinbase::create_shielded` is the
only thing that builds one: spends disabled, exactly the reward as the bundle's
value balance, and the sighash of `coinbase_sighash`. Two implementations of that
would be two block templates, one of which the network rejects.

*The proof is cached per template, and that is correctness rather than speed.* A
shielded reward costs a zero-knowledge proof, and a miner polls
`/getblocktemplate` on a loop. Nothing in the coinbase depends on the nonce or the
timestamp — only on the height, the parent, the reward and the recipient — so two
requests with those four the same get the *same* coinbase back, not an equivalent
one. Handing back an equivalent one would move the Merkle root the miner was
grinding and throw away whatever it had in flight. The cache invalidates by key
comparison, not by time: a new block changes the height and the parent, an accepted
transaction changes the reward, and either way the next request reproves. Once per
template, not once per poll. The recipient is part of the key because the address
arrives per request, so two miners polling one node must not be handed each other's
reward. A test mines through this path and fails if the cache is removed.

*A shielded reward that cannot be built serves no template.* It does not fall back
to a ring coinbase: that would pay a miner into a pool it did not ask for, and it
would find out from its wallet rather than from the RPC. `/getblocktemplate`
answers 503 with the reason.

*The generated default stays a ring address.* `noctd` writes a `miner.key` holding
a ring spend secret, and deriving a shielded address from it as well would be
right — but printing only one of the two would misdescribe what was just created.
An operator who wants notes says so.

**What this closes.** The loop the delayed-insertion rule exists for now runs end
to end and is tested as one thing: a reward is created as a note, withheld from the
commitment tree until it matures, found by the wallet in the block that made it,
reported as *pending* rather than as balance, and spent once an anchor contains it.
A pool mining into the pool then pays shielded miners with nothing crossing but the
fee.

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
4. **Coinbase** as Orchard notes (the premine excepted — see below), with the delayed-insertion maturity
   rule.
5. **`wallet`**: keys, scanning, witnesses, spending, pool choice.
6. **`pool`**: Orchard payouts.
7. **Adversarial pass** (§13), then a testnet reset — every node stopped before
   any node is wiped — then a release.

**Status: 1–6 are done.** What is left is step 7, and it is the step that decides
whether any of this should be deployed:

- The **adversarial pass** of §13, against a running node.
- **CLOSED — the minimum-fee floor** (open question 1). `MIN_FEE_PER_KB` is a
  mempool *policy* rule: a transaction below it is neither relayed nor pooled,
  and is still perfectly valid to the chain, so nodes that disagree about the
  number cannot fork.

  It was added on the theory that a zero-fee transaction costs verifiers a proof
  per action, so shielded traffic needed a per-action surcharge. **Measured, that
  theory is backwards.** Warm verification, per kilobyte: a ring payment to eight
  recipients costs 5,540 µs/KB, a shielding 1,106, a shielded-only transfer 637.
  Orchard proofs are large but fast; the expensive shape is an aggregate
  Bulletproofs+ range proof over many ring outputs. A per-action surcharge would
  have taxed the cheap case and left the dear one alone, so the floor is per byte
  only — the unit the mempool's byte cap and its eviction rule already use.

  What actually defends CPU is not the size of the number but the *position of
  the check*: the fee is judged before verification and before relay, in both the
  mempool and the node's gossip path. A low fee earns **no misbehaviour points**,
  since it is our policy rather than the sender's dishonesty.
- **DECIDED, not open: the premine stays a transparent ring output.** §7 planned to
  mint it as a note in genesis. Rejected on three grounds:

  1. **It could never be corrected.** Genesis must be byte-identical on every node,
     and a shielded coinbase needs a Halo 2 proof built from an rng, so the bundle
     cannot be computed at runtime. It would be a baked ~10 KB constant, forever,
     guarding 50% of supply; malformed, the premine is unspendable and the only
     remedy is a new chain.
  2. **It leans on an unexercised path.** §7 already notes that from NU6.3 Zcash
     requires *zero* Orchard actions in a coinbase. Relying on that for a block
     template is a calculated risk; baking it into the chain's axiom is not the
     same bet.
  3. **It buys almost nothing.** At genesis the shielded pool holds exactly one
     note, so spending it identifies it as the premine anyway. The privacy accrues
     as the pool grows — equally true if the founder shields it afterwards.

  What the transparent output keeps is accountability: the allocation is visible,
  and `premine-key-image` publishes the key image a spend would reveal, so anyone
  can verify it has not moved. The founder shields it with an ordinary transaction
  whenever they choose, and `wallet/tests/premine_shielding.rs` proves that works
  against the real genesis under the real maturity rule — because leaving genesis
  alone is only sound if that door is open, and a decision resting on an untested
  claim is a guess.
- Then the testnet reset. This is a consensus change from end to end — a new
  transaction version, a second coinbase shape, a tree in the chain state — so
  nothing about it is compatible with the running fleet.

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
