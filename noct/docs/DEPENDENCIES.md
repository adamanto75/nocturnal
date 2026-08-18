# Cryptographic Dependencies & the serai Repin Plan

**Status:** pre-mainnet. This documents Nocturnal's RingCT cryptography dependencies,
why they are sourced the way they are, the risks that carries, and the concrete
plan to repin them before mainnet. It is written for the audit.

## 1. What Nocturnal depends on

Nocturnal's confidential-transaction cryptography (Pedersen commitments,
Bulletproofs+, CLSAG ring signatures, generators) is **not hand-rolled**. It is
serai's Monero implementation — chosen so Nocturnal reuses Monero's reviewed
construction and an auditor can diff against Monero. `core/Cargo.toml` pulls four
crates:

| import name           | crate on crates.io            | version | edition | MSRV | Cargo.lock checksum (sha256, prefix) |
|-----------------------|-------------------------------|---------|---------|------|--------------------------------------|
| `monero-primitives`   | `monero-primitives-mirror`    | 0.1.0   | 2021    | 1.80 | `4f0bb4f7…` |
| `monero-bulletproofs` | `monero-bulletproofs-mirror`  | 0.1.0   | 2021    | 1.80 | `12680d39…` |
| `monero-clsag`        | `monero-clsag-mirror`         | 0.1.0   | 2021    | 1.80 | `876a1cf8…` |
| `monero-generators`   | `monero-generators-mirror`    | 0.4.0   | 2021    | —    | `b651dda8…` |

They are renamed via `package = "…-mirror"` so the code imports clean
`monero_*` paths. All build on the pinned Rust 1.82 toolchain (edition 2021,
MSRV ≤ 1.80).

## 2. Why the `-mirror` crates

serai's canonical `monero-*` crates on crates.io (`monero-primitives`,
`monero-bulletproofs`, …) are **empty placeholder stubs** — 0-byte `lib.rs`,
published to reserve the names "until audited." serai ships the real code only in
its git repository, not (yet) as functional crates.io releases.

The `-mirror` crates are a **third-party republish** of serai's real code, cut
from serai's `develop` branch by an external maintainer (`sneurlax`). Their own
description states the intent plainly:

> "Mirrored … from serai for downstream crate-publishing purposes until serai
> publishes their crates; **use the versions from serai in production.** This
> crate will be **unpublished/deleted as soon as possible.**"

Each mirror's `repository` field points at the exact serai source path it
mirrors, e.g. `monero-clsag-mirror` →
`github.com/serai-dex/serai/tree/develop/networks/monero/ringct/clsag`.

## 3. Risks

1. **Third-party republish (provenance).** The mirror is not published by serai.
   An auditor must confirm the mirror bytes are the reviewed serai code,
   unmodified — not trust the republisher.
2. **Availability.** The maintainer intends to delete the mirrors. If they are
   yanked from crates.io, a *fresh* dependency fetch fails. (Existing checked-out
   builds are unaffected — see mitigations.)
3. **Drift.** The mirror tracks serai `develop` at the point it was cut; upstream
   has since moved on (and raised its toolchain — §4).

## 4. Why we can't simply repin to upstream today

The obvious fix — depend on serai directly, `git = "…serai", rev = "<pinned>"` —
is blocked by the toolchain:

- **Current upstream serai pins Rust 1.89** (`rust-toolchain.toml` channel
  `1.89`). Nocturnal is deliberately pinned to **Rust 1.82** (no `rustup`, no
  edition 2024), a constraint that has shaped many dependency pins across the
  workspace (`zeroize = "=1.8.1"`, `base64ct = "=1.6.0"`, etc.).
- Repinning to current upstream serai therefore forces a toolchain bump to 1.89,
  which is a project-wide decision with its own cascade (edition-2024 transitive
  requirements elsewhere), **not** a mechanical dependency swap.

So the repin is a *decision gated on the toolchain*, best made deliberately —
ideally in coordination with the audit — rather than forced now.

## 5. Mitigations already in place

- **`Cargo.lock` pins exact bytes.** Every mirror is locked to a version *and a
  sha256 checksum* (§1). `cargo build --locked` verifies them, so the compiled
  crypto is byte-for-byte reproducible from the current lockfile even if the
  registry entry changes. (Confirmed: `cargo build --locked` succeeds.)
- **Source is cached.** The exact `.crate` sources sit in the local cargo
  registry cache; keep an offline backup of the four `.crate` files so a
  deletion cannot block a rebuild before the repin lands.

These give *reproducibility*. They do not give *provenance* (§3.1) or long-term
*availability* for fresh environments (§3.2) — that's what the repin fixes.

## 6. The repin plan (execute at/with the audit)

Ranked; do the first that the audit timeline allows.

**Option A — pin to upstream serai at a fixed rev (preferred).**
1. Bump the workspace toolchain to serai's (currently 1.89) as a deliberate,
   reviewed change; fix the edition-2024 fallout across the tree.
2. Replace the four `…-mirror` deps with git deps on `serai-dex/serai` at a
   single pinned `rev` (the reviewed commit), keeping the `package` renames.
3. **Verify byte-equivalence:** diff each mirror's `src/` against that serai rev's
   corresponding path (the mirror's `repository` field names it). Confirm the
   only differences are packaging (Cargo.toml metadata), not code. Record the
   diff in the audit.
4. Re-run the full suite; the crypto behavior must be identical (the mirror *is*
   this code today).

**Option B — wait for serai's audited crates.io release, then pin those.**
serai publishes functional `monero-*` crates → drop the mirror rename, pin exact
versions. Cleanest provenance, but depends on serai's timeline.

**Option C — vendor the reviewed source in-tree.**
If neither A nor B is ready by mainnet, `cargo vendor` the four crates (from the
verified serai rev) into the repo so the build no longer depends on the mirror's
continued existence. **Caveat for this repo:** the `randomx` and `swap` crates are
excluded from the workspace and have their own dependency trees; a workspace-wide
`vendor` + source-replacement config will break their independent builds unless
they are vendored too. Vendor with that in mind (or scope the source replacement).

## 7. Audit checklist for this area

- [ ] Confirm each mirror's `src/` equals the named serai path at a pinned rev
      (provenance).
- [ ] Ratify the toolchain decision (stay 1.82 + vendor, or bump to serai's).
- [ ] Execute Option A/B/C and re-verify the full test suite.
- [ ] Re-review any `=`-pinned transitive crates (`zeroize`, `base64ct`, …) after
      a toolchain change.
- [ ] Keep offline `.crate` backups until the repin lands (availability).

---

## 6. Migration spike — first-party `monero-oxide` crates (2026-08-14)

**The blocker recorded in §5 is gone.** serai's Monero code has been spun out into
its own project, **`monero-oxide`** (`github.com/monero-oxide/monero-oxide`), and
the canonical crates on crates.io are no longer placeholders:

| crate | version | published | size | MSRV |
|---|---|---|---|---|
| `monero-primitives`   | 0.1.0 | 2026-07-31 | 4,351 B  | 1.56 |
| `monero-bulletproofs` | 0.1.0 | 2026-07-31 | 25,721 B | 1.67 |
| `monero-clsag`        | 0.1.0 | 2026-07-31 | 22,653 B | 1.65 |

(The old stubs were `0.0.1` at ~818 B. The `-mirror` crates we depend on today
were last touched **2024-09-22**.)

Every MSRV is **below our pinned 1.82**, so this does *not* force the toolchain
bump that blocked the 2026-08-05 attempt.

### Measured, not estimated

A spike in a throwaway copy of the tree:

* **Resolves** on Rust 1.82 — no edition2024 wall, no MSRV conflict.
* **8 compile errors, in 2 files** (`core/src/amounts.rs`, `core/src/ring.rs`).
  Import moves and small signature changes; no restructuring.
* Symbol map:
  * `monero_primitives::Commitment` → **`monero_ed25519::Commitment`**
  * `monero_primitives::Decoys` → **`monero_clsag::Decoys`**
  * `monero_generators::hash_to_point(b)` → **`monero_ed25519::Point::biased_hash(b)`**
  * `monero-generators` has split into `monero-ed25519` + `monero-bulletproofs-generators`;
    a new `monero-io` crate carries the serialization helpers.
* `monero_ed25519::Point` is a **newtype over `curve25519_dalek::EdwardsPoint`**
  with `from`/`into`, so conversions at the CLSAG boundary are mechanical.

### The consensus question, answered

Key images are `I = x·H_p(P)`. Had `H_p` changed by one bit, every key image on
the chain would change: historical blocks would fail to validate and the
spent-set would be silently reindexed — a hard fork, not an upgrade.

A standalone harness compared the mirror's `hash_to_point` against
`Point::biased_hash` over 35 inputs (fixed byte patterns plus real compressed
public keys). **Identical on every one.** `biased_hash` documents parity with
monero-project's `hash_to_ec` (Elligator 2), which matches the observed result.

**Adopting these crates does not change key images.**

### Remaining risk before committing

Byte-format compatibility of **BP+ range proofs and CLSAG signatures** is not yet
proven — only `H_p` is. The existing suite is the arbiter: the CLSAG, range-proof
and wire round-trip tests must pass unchanged, and `Transaction::hash()` covers
the proof encodings, so a format change would surface as failing txids rather
than silently.

**Scope: hours, not days** — but it is consensus-critical code, so it should be
done deliberately, with the full 188-test suite green before and after, and the
diff reviewed as a crypto change rather than a dependency bump.

### Migration COMPLETED (2026-08-14)

The swap is done in the working tree. `core/Cargo.toml` now depends on the
first-party crates; the four `-mirror` dependencies are gone.

Code changes were confined to two files and were purely mechanical — upstream
wraps scalars and points in its own newtypes over curve25519-dalek:

* `amounts.rs` — `Commitment::calculate()` → `commit()`, and `Scalar` /
  `Point` / `CompressedPoint` conversions at the crate boundary (BP+ verification
  now takes compressed points).
* `ring.rs` — `hash_to_point(b)` → `Point::biased_hash(b)`; `Decoys` imported
  from `monero-clsag`; CLSAG's ring, key image and pseudo-out passed compressed.

**Verification, in increasing order of strength:**

1. `H_p` byte-identical to the mirror across 35 inputs (the spike above).
2. **188 tests green**, including every CLSAG, range-proof, key-image and
   wire round-trip test.
3. **The live 673-block chain re-validates in full.** A copy of the real
   `blocks.dat` — every block mined, every ring signature and range proof
   produced under the *mirror* crates — was replayed by a node built on the new
   crates: `restored chain to height 673`, emitted `500320332066626570`, tip
   `5fb3363473f2eb3b…`. Every block's PoW, coinbase, commitments, range proofs,
   CLSAG signatures and key images re-verified.

That third point is the one that matters: had any byte format shifted, the chain
would have failed to replay. **This is not a hard fork.**

The `-mirror` `.crate` files in `deps/serai-mirror-backup/` are retained for
provenance — they are what the existing chain was produced with, and an auditor
may want to diff them against the first-party sources.

---

## 8. Transport security dependencies (`noct-tls`, 2026-08-14)

TLS is a **new third-party surface**, so it is recorded here for the audit
alongside the RingCT crates — with one important scoping note: **none of it is
consensus code**. `noct-core` does not depend on any of it. A defect in this
tree can compromise a connection; it cannot mint coins, alter a block, or change
what the network agrees on. Keeping it in a separate leaf crate (`noct-tls`) is
what makes that statement checkable rather than merely asserted.

| crate                 | version  | role |
|-----------------------|----------|------|
| `rustls`              | 0.23.43  | the TLS 1.2/1.3 implementation |
| `ring`                | 0.17.14  | the cryptographic backend rustls is configured with |
| `rustls-webpki`       | 0.103.14 | certificate path validation |
| `rustls-pki-types`    | 1.15.1   | certificate/key types |
| `rustls-pemfile`      | 2.2.0    | reading PEM certificates and keys |
| `rustls-native-certs` | 0.8.4    | the operating system's trust store |
| `sha2`                | 0.10.9   | certificate fingerprints (pinning) |
| `rcgen`               | 0.13.2   | generating a self-signed certificate for operators without a domain |

**Why rustls and not OpenSSL.** A memory-safe implementation, a far smaller
attack surface, no system library whose patch level we would have to track
per-platform, and no C build step. It is widely deployed and has been
independently audited.

**Why the `ring` backend and not the default `aws-lc-rs`.** Buildability only:
aws-lc-rs requires cmake and nasm on Windows, and this crate must build in the
same plain shell as the rest of the workspace. Both are supported rustls
backends.

**Why `rcgen` ships in the product** rather than telling operators to run
`openssl`. A pool operator with no easy way to produce a PEM pair runs without
TLS — that is what actually happens. `noct-poold --tls-generate` removes the
excuse. It is used only by that one subcommand.

### New pins

Two crates in this tree publish releases requiring Cargo's `edition2024`
feature, which does not exist in the pinned 1.82 toolchain. Both are pinned to
the last version that builds:

* `zeroize = "=1.8.1"`
* `time = "=0.3.36"`

These are the same class of pin as §1: not a preference, a hard toolchain
constraint. They should be revisited whenever the toolchain moves.

### The one piece of security-relevant logic we wrote

`tls/src/pin.rs` implements a `ServerCertVerifier` that trusts exactly one
certificate by SHA-256, for pools without a domain name. Its design note is in
the module itself; for the audit, the two things to check are:

1. **Only the leaf is compared** — matching anywhere in the chain would let
   anyone holding a certificate signed by the pinned one impersonate the server.
2. **The handshake signature checks are delegated** to the provider's own
   `verify_tls12_signature` / `verify_tls13_signature`, not reimplemented.
   Without them, pinning a *public* certificate would prove nothing.

Pinning intentionally replaces the expiry and hostname checks along with the
chain check, which is coherent (the identity being verified is the key) but is a
real difference from CA verification — so the CA path remains the default
wherever a domain name exists. There is no flag anywhere in the crate that
disables verification.
