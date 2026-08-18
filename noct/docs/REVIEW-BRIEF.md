# Independent Review Brief

**For a reviewer who did not write this code** — another model, or a person. It is
written to be pasted at the top of a review session, ahead of the files.

The single most useful thing you can do is **disagree with the author**. Nearly
all of this was written by one agent, which also wrote its own security review.
Self-review catches slips; it does not catch a *misconception*, because the same
wrong assumption is applied twice. Your value is in the assumptions, not the
typos.

---

## What this is

The project is **Nocturnal**, unit **NOCT**; all code is spelled `noct*`
(`noct-core`, `noctd`, `/var/lib/noct`). Same project, abbreviated — the short
form is authoritative in code and is not renamed because it appears in
consensus-visible constants.

Nocturnal is a Monero-style privacy coin in Rust: RingCT with Pedersen commitments,
Bulletproofs+ range proofs, CLSAG ring signatures, stealth one-time addresses,
key images for double-spend prevention, and RandomX proof-of-work. It is
pre-mainnet with a live testnet. The cryptographic primitives are **not**
hand-rolled — they come from the `monero-oxide` crates (see
`docs/DEPENDENCIES.md`).

Money at stake if it launches: a fixed 1,000,000 NOCT supply, of which 500,000 is
a genesis premine.

## Read these first, in this order

1. `docs/SPECIFICATION.md` — what the protocol claims to do. **Review the claims
   themselves, not just whether the code matches them.**
2. `SECURITY-REVIEW.md` — 11 internal passes, findings F1–F27. Treat this as the
   author's argument, not as established fact. Assume at least one conclusion in
   it is wrong.
3. The code, below.

## Where the money is — review these hardest

| file | why it matters |
|---|---|
| `core/src/tx.rs` | transaction assembly and `verify`. Balance, fees, the `additional_tx_public` vector (F16 lived here). |
| `core/src/amounts.rs` | Pedersen commitments and range proofs. A commitment that can be opened two ways is unlimited inflation. |
| `core/src/ring.rs` | CLSAG signing/verification and key-image derivation `I = x·H_p(P)`. If two different spends can produce the same key image, honest users get locked out; if one spend can produce two, that is a double-spend. |
| `core/src/chain.rs` | block validation, the spent key-image set, output indexing, coinbase maturity, reorg handling (`pop_block` must undo *everything* `add_block` did). |
| `core/src/block.rs` | coinbase construction and emission (F1, an inflation bug, was here). |
| `core/src/wire.rs` | the deserializer. Every byte here is attacker-supplied. |

## The questions worth asking

Ranked by what would actually be catastrophic:

1. **Can supply be inflated?** Any path where outputs exceed inputs plus subsidy
   plus fees — including integer overflow, an unchecked sum, a commitment that
   balances while amounts do not, or a coinbase that pays more than the emission
   curve allows at that height.
2. **Can a coin be spent twice?** Any way to get two accepted spends of one
   output past the key-image set — including a key image that varies for the same
   output, a non-canonical encoding that hashes differently, or state that a
   reorg fails to roll back.
3. **Can two honest nodes disagree about the same block?** Validation that
   depends on anything non-deterministic — iteration order of a hash map, system
   time, floating point, locale, platform integer width. A consensus split is as
   damaging as theft and much harder to fix after launch.
4. **Can a transaction be made unspendable, or a user's funds be locked?**
   Including by a third party.
5. **Is the privacy claim actually met?** Ring signatures with a real decoy
   distribution, no linkability between a subaddress and its parent, nothing
   distinguishing about transactions the wallet builds.
6. **Can one peer cheaply degrade the network?** CPU or memory amplification,
   unbounded growth of any per-peer table, anything where verifying costs far
   more than producing.

## What is already known — do not spend time re-finding these

- **Network parameters are placeholders.** Genesis timestamp, address tags and
  the RandomX seed schedule are not final. Known, deliberate, tracked in
  `docs/SPECIFICATION.md` §16.
- **P2P traffic is unencrypted.** Monero's is too. It carries no credentials and
  no payout addresses. HTTP surfaces *are* now TLS (`tls/`).
- **The `additional_tx_public` vector's presence leaks that subaddresses were
  used.** Monero has the same property.
- **`cargo-fuzz` targets exist in `fuzz/` but have never been run** — they need a
  nightly toolchain that was not available. A stable in-suite mutational fuzzer
  does run. If you can run the nightly targets, that is high value.
- The following were found and fixed; the *fixes* are worth checking, the bugs
  are not worth re-finding: F1 coinbase overflow, F16 unbounded additional keys,
  F17 duplicate-output maturity bypass, F22 pool share amplification, F27 diluted
  rewards.

## Out of scope

The mining pool (`pool/`), TLS (`tls/`) and the desktop wrapper are **not
consensus code** — a defect there can cost one operator money or leak a
connection, but cannot inflate supply or split the chain. Review them only after
the core, and say so if you do.

## How to report

For each finding, state: **the concrete input or sequence** that triggers it,
**what an attacker gains**, and **why you believe the existing code does not
already prevent it**. A finding without a mechanism is a guess, and guesses cost
more to check than they are worth.

If you conclude something is fine, say that too — "I looked at X and it holds
because Y" is genuinely useful, and rarer than it should be.

## Building it

Pinned to Rust 1.82, edition 2021. `cargo test` builds and runs everything
without the RandomX toolchain (a Keccak placeholder PoW stands in). Several
dependencies are pinned to pre-`edition2024` releases so the pinned toolchain can
fetch them; that is deliberate, not neglect — see `docs/DEPENDENCIES.md`.
