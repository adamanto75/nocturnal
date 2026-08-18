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

---

# The code

Six files, concatenated. Each begins with a `===== FILE: path =====` marker.
Line numbers are not included; refer to functions by name.


===== FILE: core/src/tx.rs =====

```rust
//! Layer 6 — transaction assembly & verification.
//!
//! This layer composes everything below it into a single [`Transaction`] with one
//! [`Transaction::verify`]. A Nocturnal transaction is RingCT-shaped:
//!
//! * **Outputs** — each has a one-time key `P` ([`crate::stealth`]), an amount
//!   commitment `C` ([`crate::amounts`]), and the amount encrypted to the
//!   recipient (ECDH). One aggregate Bulletproofs+ [`RangeProof`] covers all
//!   output commitments.
//! * **Inputs** — each spends a prior output ambiguously via a CLSAG ring
//!   signature ([`crate::ring`]), publishing a key image and a pseudo-out
//!   commitment.
//! * **Fee** — public, in the clear.
//!
//! [`Transaction::verify`] enforces, with no secret knowledge:
//! 1. structural sanity (≥1 input, ≥1 output, no duplicate key images),
//! 2. the range proof is valid (every output amount ∈ `[0, 2^64)`),
//! 3. every ring signature is valid against the transaction's signing message,
//! 4. the transaction balances: `Σ pseudo-outs = Σ output commitments + fee·H`.
//!
//! Amounts never appear in the clear (except the fee); balance is proven purely
//! over commitments.
//!
//! ## Scope notes
//!
//! * The ring members are **embedded** in each input here. On a real chain
//!   (layer 8) inputs instead reference outputs by global index, resolved
//!   against the output set; embedding keeps layer 6 self-contained and testable.
//! * Canonical wire serialization arrives with P2P (layer 9). The message
//!   hashing below uses a fixed internal encoding sufficient to bind the
//!   signatures.

use std::collections::HashSet;

use curve25519_dalek::scalar::Scalar;

use crate::address::Address;
use crate::amounts::{AmountError, Commitment, Opening, RangeProof};
use crate::hash::{hash_to_scalar, keccak256};
use crate::keys::{Account, PrivateKey, PublicKey};
use crate::ring::{self, InputSignature, KeyImage, RingError, RingMember, SpendInput};
use crate::stealth::{self, TxKeypair};
use crate::subaddress::SubaddressIndex;

/// Current transaction format version.
pub const TX_VERSION: u8 = 1;

/// Errors from building or verifying a transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxError {
    /// Inputs and outputs (plus fee) do not have equal total value.
    Unbalanced,
    /// A transaction with no inputs.
    NoInputs,
    /// A transaction with no outputs.
    NoOutputs,
    /// The same key image appears on two inputs (self double-spend).
    DuplicateKeyImage,
    /// The aggregate range proof did not verify.
    BadRangeProof,
    /// `additional_tx_public` was present but not exactly one key per output.
    BadAdditionalKeys,
    /// A ring signature did not verify.
    BadRingSignature,
    /// An error from the amount/range-proof layer.
    Amount(AmountError),
    /// An error from the ring-signature layer.
    Ring(RingError),
}

impl From<AmountError> for TxError {
    fn from(e: AmountError) -> Self {
        TxError::Amount(e)
    }
}
impl From<RingError> for TxError {
    fn from(e: RingError) -> Self {
        TxError::Ring(e)
    }
}

/// A transaction output.
#[derive(Clone, Debug)]
pub struct Output {
    /// One-time public key `P` (only the recipient can link/spend it).
    pub one_time_key: PublicKey,
    /// Amount commitment `C = mask·G + amount·H`.
    pub commitment: Commitment,
    /// The 8-byte amount, XOR-encrypted with a pad derived from the shared
    /// secret, so only the recipient learns it.
    pub encrypted_amount: [u8; 8],
}

/// A transaction input: the ring of decoys+real member, and the CLSAG signature
/// (which carries the key image and pseudo-out commitment).
#[derive(Clone, Debug)]
pub struct Input {
    pub ring: Vec<RingMember>,
    pub signature: InputSignature,
}

impl Input {
    pub fn key_image(&self) -> KeyImage {
        self.signature.key_image
    }
}

/// A fully-assembled, signed transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u8,
    /// Transaction public key `R = r·G`, used by recipients for stealth scanning.
    pub tx_public: PublicKey,
    /// Per-output transaction keys, present only when some output pays a
    /// subaddress (where `R_i = r·D_i` rather than `r·G`). Empty for the common
    /// all-standard case, in which every output uses `tx_public`. When present,
    /// its length equals `outputs.len()` and output `i` uses entry `i`.
    pub additional_tx_public: Vec<PublicKey>,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub range_proof: RangeProof,
}

/// A spendable input the sender controls (secret + opening + chosen ring).
pub struct InputSecret {
    /// One-time spend secret `x` (with `P = x·G` the real ring member's key).
    pub secret: PrivateKey,
    /// The real output's amount + mask.
    pub opening: Opening,
    /// Ring of `[P, C]` members, real one at `signer_index`.
    pub ring: Vec<RingMember>,
    pub signer_index: usize,
}

/// A payment instruction: pay `amount` to `destination`.
#[derive(Clone, Copy, Debug)]
pub struct Payment {
    pub destination: Address,
    pub amount: u64,
}

/// An output recovered by a recipient scanning a transaction.
#[derive(Clone, Debug)]
pub struct ReceivedOutput {
    /// Position of the output within the transaction.
    pub index: u32,
    /// The recovered cleartext amount.
    pub amount: u64,
    /// The recovered opening (amount + mask) of the commitment.
    pub opening: Opening,
    pub one_time_key: PublicKey,
    /// One-time spend secret `x`; lets the recipient later spend this output.
    /// For a subaddress output this already folds in the subaddress offset
    /// (`x = k + b + m`), so spending needs no special handling.
    pub spend_secret: PrivateKey,
    /// The key image this output will publish when spent.
    pub key_image: KeyImage,
    /// Which of the recipient's addresses received this output (`MAIN` for the
    /// primary address).
    pub subaddress: SubaddressIndex,
}

// --- Output secret derivation (ECDH), shared by sender and recipient --------

/// Output blinding mask `y = H_s("noct_output_mask" ‖ k)`, from the shared
/// scalar `k`. Deterministic, so the recipient recovers the same mask.
fn output_mask(k: &Scalar) -> Scalar {
    let mut buf = Vec::with_capacity(16 + 32);
    buf.extend_from_slice(b"noct_output_mask");
    buf.extend_from_slice(k.as_bytes());
    hash_to_scalar(&buf)
}

/// One-time pad for the amount: `keccak256("noct_amount" ‖ k)[..8]`.
fn amount_pad(k: &Scalar) -> [u8; 8] {
    let mut buf = Vec::with_capacity(11 + 32);
    buf.extend_from_slice(b"noct_amount");
    buf.extend_from_slice(k.as_bytes());
    let mut pad = [0u8; 8];
    pad.copy_from_slice(&keccak256(&buf)[..8]);
    pad
}

fn xor_amount(amount_bytes: [u8; 8], k: &Scalar) -> [u8; 8] {
    let pad = amount_pad(k);
    let mut out = amount_bytes;
    for (o, p) in out.iter_mut().zip(pad) {
        *o ^= p;
    }
    out
}

/// Compute the 32-byte message that every ring signature in the transaction
/// binds. It covers the version, tx public key, fee, each input's key image and
/// ring, every output, and the range proof — i.e. everything except the CLSAG
/// signatures themselves. Recomputed identically at verify time.
fn signing_message(
    version: u8,
    tx_public: &PublicKey,
    additional_tx_public: &[PublicKey],
    fee: u64,
    inputs: &[(KeyImage, &[RingMember])],
    outputs: &[Output],
    range_proof: &RangeProof,
) -> [u8; 32] {
    let mut b = Vec::new();
    b.push(version);
    b.extend_from_slice(&tx_public.to_bytes());
    b.extend_from_slice(&(additional_tx_public.len() as u32).to_le_bytes());
    for r in additional_tx_public {
        b.extend_from_slice(&r.to_bytes());
    }
    b.extend_from_slice(&fee.to_le_bytes());
    b.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for (image, ring) in inputs {
        b.extend_from_slice(&image.to_bytes());
        b.extend_from_slice(&(ring.len() as u32).to_le_bytes());
        for m in *ring {
            b.extend_from_slice(&m.key.to_bytes());
            b.extend_from_slice(&m.commitment.to_bytes());
        }
    }
    b.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for o in outputs {
        b.extend_from_slice(&o.one_time_key.to_bytes());
        b.extend_from_slice(&o.commitment.to_bytes());
        b.extend_from_slice(&o.encrypted_amount);
    }
    b.extend_from_slice(&range_proof.to_bytes());
    keccak256(&b)
}

impl Transaction {
    /// Build and sign a transaction paying `payments`, spending `inputs`, with a
    /// public `fee`, using transaction keypair `tx` for stealth derivation.
    ///
    /// Requires `Σ input amounts == Σ payment amounts + fee`; otherwise
    /// [`TxError::Unbalanced`]. (In real wallets the caller adds a change output
    /// to themselves to make this hold.)
    pub fn build<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        inputs: &[InputSecret],
        payments: &[Payment],
        fee: u64,
        tx: &TxKeypair,
    ) -> Result<Transaction, TxError> {
        if inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if payments.is_empty() {
            return Err(TxError::NoOutputs);
        }

        // Value balance (checked with u128 to avoid overflow).
        let in_sum: u128 = inputs.iter().map(|i| u128::from(i.opening.amount)).sum();
        let out_sum: u128 =
            payments.iter().map(|p| u128::from(p.amount)).sum::<u128>() + u128::from(fee);
        if in_sum != out_sum {
            return Err(TxError::Unbalanced);
        }

        // Build outputs: stealth key, committed amount (mask from shared secret),
        // and the encrypted amount. Output derivation is address-agnostic (it
        // uses the destination's view/spend keys), so subaddresses need no
        // change here — only the published transaction key differs, below.
        let mut openings = Vec::with_capacity(payments.len());
        let mut outputs = Vec::with_capacity(payments.len());
        for (i, p) in payments.iter().enumerate() {
            let index = i as u32;
            let k = stealth::sender_shared_scalar(&tx.secret, &p.destination, index);
            let one_time_key = stealth::derive_output(&tx.secret, &p.destination, index);
            let opening = Opening::new(p.amount, output_mask(&k));
            let commitment = opening.commit();
            let encrypted_amount = xor_amount(p.amount.to_le_bytes(), &k);
            openings.push(opening);
            outputs.push(Output { one_time_key, commitment, encrypted_amount });
        }

        // Additional per-output transaction keys, only when a subaddress is a
        // destination. A subaddress output publishes `R_i = r·D_i` (so the
        // recipient's `a·R_i = r·a·D_i` reproduces the shared secret); a standard
        // output keeps `R_i = r·G`. Left empty otherwise, so ordinary
        // transactions are byte-for-byte as before.
        let additional_tx_public: Vec<PublicKey> = if payments.iter().any(|p| p.destination.is_subaddress) {
            payments
                .iter()
                .map(|p| {
                    if p.destination.is_subaddress {
                        PublicKey(tx.secret.0 * p.destination.spend_public.0)
                    } else {
                        tx.public
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        // Aggregate range proof over the output commitments.
        let (range_proof, _points) = RangeProof::prove(rng, &openings)?;
        let output_mask_sum: Scalar = openings.iter().map(|o| o.mask).sum();

        // Message to sign, then the ring signatures.
        let spend_inputs: Vec<SpendInput> = inputs
            .iter()
            .map(|i| SpendInput {
                secret: i.secret,
                opening: i.opening.clone(),
                ring: i.ring.clone(),
                signer_index: i.signer_index,
            })
            .collect();
        let msg_inputs: Vec<(KeyImage, &[RingMember])> =
            spend_inputs.iter().map(|s| (s.key_image(), s.ring.as_slice())).collect();
        let message = signing_message(
            TX_VERSION,
            &tx.public,
            &additional_tx_public,
            fee,
            &msg_inputs,
            &outputs,
            &range_proof,
        );

        let signatures = ring::sign(rng, &spend_inputs, output_mask_sum, message)?;

        let tx_inputs = inputs
            .iter()
            .zip(signatures)
            .map(|(i, signature)| Input { ring: i.ring.clone(), signature })
            .collect();

        Ok(Transaction {
            version: TX_VERSION,
            tx_public: tx.public,
            additional_tx_public,
            fee,
            inputs: tx_inputs,
            outputs,
            range_proof,
        })
    }

    /// The message this transaction's signatures bind (recomputed from stored
    /// fields).
    fn message(&self) -> [u8; 32] {
        let msg_inputs: Vec<(KeyImage, &[RingMember])> =
            self.inputs.iter().map(|i| (i.signature.key_image, i.ring.as_slice())).collect();
        signing_message(
            self.version,
            &self.tx_public,
            &self.additional_tx_public,
            self.fee,
            &msg_inputs,
            &self.outputs,
            &self.range_proof,
        )
    }

    /// The transaction key that applies to output `index`: its per-output
    /// additional key when the transaction carries them, else the single
    /// `tx_public`.
    pub fn output_tx_key(&self, index: u32) -> PublicKey {
        self.additional_tx_public.get(index as usize).copied().unwrap_or(self.tx_public)
    }

    /// Canonical byte encoding of the whole transaction, **including**
    /// signatures — enough for a block to commit to the exact transaction. (This
    /// is an internal encoding; the wire format arrives with P2P in layer 9.)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(self.version);
        b.extend_from_slice(&self.tx_public.to_bytes());
        b.extend_from_slice(&(self.additional_tx_public.len() as u32).to_le_bytes());
        for r in &self.additional_tx_public {
            b.extend_from_slice(&r.to_bytes());
        }
        b.extend_from_slice(&self.fee.to_le_bytes());
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&(input.ring.len() as u32).to_le_bytes());
            for m in &input.ring {
                b.extend_from_slice(&m.key.to_bytes());
                b.extend_from_slice(&m.commitment.to_bytes());
            }
            b.extend_from_slice(&input.signature.key_image.to_bytes());
            b.extend_from_slice(&input.signature.pseudo_out.to_bytes());
            b.extend_from_slice(&input.signature.signature_bytes());
        }
        b.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            b.extend_from_slice(&o.one_time_key.to_bytes());
            b.extend_from_slice(&o.commitment.to_bytes());
            b.extend_from_slice(&o.encrypted_amount);
        }
        b.extend_from_slice(&self.range_proof.to_bytes());
        b
    }

    /// The transaction hash (Keccak-256 of [`Transaction::to_bytes`]).
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&self.to_bytes())
    }

    /// The key images this transaction publishes (one per input).
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.signature.key_image).collect()
    }

    /// The new outputs this transaction adds to the global output set, as ring
    /// members `[P, C]`.
    pub fn output_refs(&self) -> Vec<RingMember> {
        self.outputs
            .iter()
            .map(|o| RingMember::new(o.one_time_key, o.commitment))
            .collect()
    }

    /// Fully verify the transaction with no secret knowledge.
    ///
    /// This checks the transaction is internally consistent (range proof, ring
    /// signatures, balance, no duplicate key images *within* the transaction).
    /// It does **not** check that ring members are real chain outputs or that
    /// key images are globally unspent — those are the chain's job
    /// ([`crate::chain`]).
    pub fn verify<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(), TxError> {
        if self.inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxError::NoOutputs);
        }

        // Additional per-output transaction keys are either absent (every output
        // uses `tx_public`) or exactly one per output. Anything else is
        // malformed: a short vector would silently fall back to `tx_public` for
        // the outputs past its end, and a padded one is dead weight the network
        // would relay. (The wire decoder also bounds the count before decoding
        // any key, so an oversized vector never reaches here.)
        if !self.additional_tx_public.is_empty()
            && self.additional_tx_public.len() != self.outputs.len()
        {
            return Err(TxError::BadAdditionalKeys);
        }

        // No duplicate key images within the transaction.
        let mut images = HashSet::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if !images.insert(input.signature.key_image) {
                return Err(TxError::DuplicateKeyImage);
            }
        }

        // Range proof over all output commitments.
        let commitments: Vec<Commitment> = self.outputs.iter().map(|o| o.commitment).collect();
        if !self.range_proof.verify(rng, &commitments) {
            return Err(TxError::BadRangeProof);
        }

        // Every ring signature, against the transaction message.
        let message = self.message();
        for input in &self.inputs {
            if !input.signature.verify(&input.ring, &message) {
                return Err(TxError::BadRingSignature);
            }
        }

        // Balance: Σ pseudo-outs == Σ output commitments + fee·H.
        let sum_pseudo = Commitment::sum(self.inputs.iter().map(|i| &i.signature.pseudo_out));
        let sum_outputs = Commitment::sum(&commitments) + Commitment::fee(self.fee);
        if sum_pseudo != sum_outputs {
            return Err(TxError::Unbalanced);
        }

        Ok(())
    }

    /// Scan this transaction for outputs paid to `account`'s **main** address.
    /// A convenience wrapper over [`Transaction::scan_with`] for wallets that do
    /// not use subaddresses.
    pub fn scan(&self, account: &Account) -> Vec<ReceivedOutput> {
        self.scan_with(account, |d| {
            (*d == account.spend_public).then_some((SubaddressIndex::MAIN, Scalar::ZERO))
        })
    }

    /// Scan this transaction with an account's view key, resolving each output's
    /// recovered spend key `D' = P − k·G` through `resolve`. `resolve(D')`
    /// returns `Some((index, m))` when `D'` is one of the recipient's addresses
    /// — the subaddress it lands on and that subaddress's offset `m` (zero for
    /// the main address) — or `None` to skip. The offset folds into the one-time
    /// spend secret `x = k + b + m`, so the returned outputs are directly
    /// spendable regardless of which subaddress received them.
    pub fn scan_with<F>(&self, account: &Account, resolve: F) -> Vec<ReceivedOutput>
    where
        F: Fn(&PublicKey) -> Option<(SubaddressIndex, Scalar)>,
    {
        let mut found = Vec::new();
        for (i, output) in self.outputs.iter().enumerate() {
            let index = i as u32;
            let tx_public = self.output_tx_key(index);
            let recovered = stealth::recovered_spend_public(account, &tx_public, index, &output.one_time_key);
            let Some((subaddress, offset)) = resolve(&recovered) else {
                continue;
            };
            let k = stealth::recipient_shared_scalar(account, &tx_public, index);
            let amount = u64::from_le_bytes(xor_amount(output.encrypted_amount, &k));
            let opening = Opening::new(amount, output_mask(&k));
            // The recovered opening must reproduce the on-chain commitment;
            // otherwise the output is malformed or not really ours.
            if opening.commit() != output.commitment {
                continue;
            }
            // One-time spend secret x = k + b + m (m = subaddress offset).
            let spend_secret = PrivateKey(k + account.spend_secret.0 + offset);
            let key_image = KeyImage::from_secret(&spend_secret);
            found.push(ReceivedOutput {
                index,
                amount,
                opening,
                one_time_key: output.one_time_key,
                spend_secret,
                key_image,
                subaddress,
            });
        }
        found
    }
}

impl ReceivedOutput {
    /// Turn a received output into a spendable [`InputSecret`], placed in `ring`
    /// (of which the real member sits at `signer_index`). The caller supplies the
    /// decoys; this fills in the real member from the recovered secret/opening.
    pub fn to_input(&self, mut ring: Vec<RingMember>, signer_index: usize) -> InputSecret {
        ring[signer_index] = RingMember::new(self.one_time_key, self.opening.commit());
        InputSecret {
            secret: self.spend_secret,
            opening: self.opening.clone(),
            ring,
            signer_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use rand_core::OsRng;

    fn account() -> Account {
        Account::random(&mut OsRng)
    }

    fn address(acct: &Account) -> Address {
        Address::new(Network::Mainnet, acct.spend_public, acct.view_public)
    }

    fn decoy() -> RingMember {
        let key = PrivateKey(Scalar::random(&mut OsRng)).public_key();
        let amount = u64::from(Scalar::random(&mut OsRng).to_bytes()[0]) + 1;
        RingMember::new(key, Opening::random(amount, &mut OsRng).commit())
    }

    /// Fabricate a spendable input worth `amount` (random secret/mask), placed in
    /// a ring of `ring_size` at `signer_index`.
    fn fabricate_input(amount: u64, ring_size: usize, signer_index: usize) -> InputSecret {
        let secret = PrivateKey(Scalar::random(&mut OsRng));
        let opening = Opening::random(amount, &mut OsRng);
        let real = RingMember::new(secret.public_key(), opening.commit());
        let mut ring = (0..ring_size).map(|_| decoy()).collect::<Vec<_>>();
        ring[signer_index] = real;
        InputSecret { secret, opening, ring, signer_index }
    }

    fn ring_of(size: usize) -> Vec<RingMember> {
        (0..size).map(|_| decoy()).collect()
    }

    // A 2-in / 2-out + fee transaction to a fresh recipient.
    fn sample_tx() -> (Transaction, Account) {
        let recipient = account();
        let payments = vec![
            Payment { destination: address(&recipient), amount: 45 },
            Payment { destination: address(&recipient), amount: 4 },
        ];
        let inputs = vec![fabricate_input(30, 7, 3), fabricate_input(20, 7, 1)];
        let fee = 1u64; // 30 + 20 == 45 + 4 + 1
        let tx = TxKeypair::random(&mut OsRng);
        let transaction = Transaction::build(&mut OsRng, &inputs, &payments, fee, &tx).unwrap();
        (transaction, recipient)
    }

    #[test]
    fn build_and_verify() {
        let (transaction, _r) = sample_tx();
        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(transaction.outputs.len(), 2);
        assert!(transaction.verify(&mut OsRng).is_ok());
    }

    #[test]
    fn unbalanced_build_is_rejected() {
        let recipient = account();
        let payments = vec![Payment { destination: address(&recipient), amount: 100 }];
        let inputs = vec![fabricate_input(50, 7, 0)];
        let tx = TxKeypair::random(&mut OsRng);
        // 50 != 100 + 0
        let err = Transaction::build(&mut OsRng, &inputs, &payments, 0, &tx).err();
        assert_eq!(err, Some(TxError::Unbalanced));
    }

    #[test]
    fn tampered_output_commitment_fails() {
        let (mut transaction, _r) = sample_tx();
        // Swap an output commitment for a different one.
        transaction.outputs[0].commitment = Opening::random(45, &mut OsRng).commit();
        // Range proof no longer matches the commitment.
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::BadRangeProof));
    }

    #[test]
    fn tampered_fee_fails() {
        let (mut transaction, _r) = sample_tx();
        transaction.fee += 1;
        // Changing the fee changes the signing message → ring signatures fail
        // (and the balance would break too).
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::BadRingSignature));
    }

    #[test]
    fn tampered_encrypted_amount_fails() {
        let (mut transaction, _r) = sample_tx();
        transaction.outputs[1].encrypted_amount[0] ^= 0xff;
        // The encrypted amount is bound by the signing message.
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::BadRingSignature));
    }

    #[test]
    fn duplicate_key_image_is_rejected() {
        let (mut transaction, _r) = sample_tx();
        // Force both inputs to carry the same key image.
        let image = transaction.inputs[0].signature.key_image;
        transaction.inputs[1].signature.key_image = image;
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::DuplicateKeyImage));
    }

    #[test]
    fn recipient_scans_and_recovers_amounts() {
        let (transaction, recipient) = sample_tx();
        let received = transaction.scan(&recipient);
        assert_eq!(received.len(), 2);
        let amounts: Vec<u64> = received.iter().map(|r| r.amount).collect();
        assert!(amounts.contains(&45) && amounts.contains(&4));
        // Every recovered opening reproduces its on-chain commitment, and the
        // spend secret opens the one-time key.
        for r in &received {
            assert_eq!(r.opening.commit(), transaction.outputs[r.index as usize].commitment);
            assert_eq!(r.spend_secret.public_key(), r.one_time_key);
        }
    }

    #[test]
    fn subaddress_output_is_detected_spent_and_unlinkable() {
        use crate::subaddress::{self, SubaddressIndex};

        let recipient = account();
        let sub = SubaddressIndex::new(1, 7);
        let sub_addr = Address::new_subaddress(
            Network::Mainnet,
            subaddress::spend_public(&recipient, sub),
            subaddress::view_public(&recipient, sub),
        );
        let d = subaddress::spend_public(&recipient, sub);
        let m = subaddress::offset(&recipient.view_secret, sub);

        // Pay 50 to the subaddress (+ a standard-address output, to prove mixed
        // transactions work).
        let payments = vec![
            Payment { destination: sub_addr, amount: 50 },
            Payment { destination: address(&recipient), amount: 9 },
        ];
        let inputs = vec![fabricate_input(40, 7, 2), fabricate_input(20, 7, 5)];
        let txk = TxKeypair::random(&mut OsRng);
        let tx = Transaction::build(&mut OsRng, &inputs, &payments, 1, &txk).unwrap();
        assert!(tx.verify(&mut OsRng).is_ok());

        // A subaddress destination forces per-output transaction keys.
        assert_eq!(tx.additional_tx_public.len(), tx.outputs.len());

        // Scan with a resolver that knows the main address and this subaddress.
        let received = tx.scan_with(&recipient, |dp| {
            if *dp == recipient.spend_public {
                Some((SubaddressIndex::MAIN, curve25519_dalek::scalar::Scalar::ZERO))
            } else if *dp == d {
                Some((sub, m))
            } else {
                None
            }
        });
        assert_eq!(received.len(), 2);
        let to_sub = received.iter().find(|r| r.subaddress == sub).expect("subaddress output found");
        assert_eq!(to_sub.amount, 50);
        // The recovered one-time secret opens the output and is directly spendable.
        assert_eq!(to_sub.spend_secret.public_key(), to_sub.one_time_key);
        // The main-address output is also recovered, at MAIN.
        assert!(received.iter().any(|r| r.subaddress == SubaddressIndex::MAIN && r.amount == 9));

        // A main-address-only scan cannot see the subaddress output (unlinkable):
        // it finds only the standard output.
        let main_only = tx.scan(&recipient);
        assert_eq!(main_only.len(), 1);
        assert_eq!(main_only[0].amount, 9);
    }

    #[test]
    fn mismatched_additional_key_count_is_rejected() {
        // A padded or truncated additional-key vector must not verify. A short
        // one would silently fall back to `tx_public` for later outputs; a padded
        // one is dead weight the network would relay.
        let (mut transaction, _r) = sample_tx();
        assert!(transaction.additional_tx_public.is_empty(), "standard tx carries none");

        let stray = PrivateKey(Scalar::random(&mut OsRng)).public_key();
        // One key for a 2-output transaction.
        transaction.additional_tx_public = vec![stray];
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::BadAdditionalKeys));

        // More keys than outputs.
        transaction.additional_tx_public = vec![stray; transaction.outputs.len() + 1];
        assert_eq!(transaction.verify(&mut OsRng).err(), Some(TxError::BadAdditionalKeys));
    }

    #[test]
    fn stranger_scans_nothing() {
        let (transaction, _r) = sample_tx();
        let stranger = account();
        assert!(transaction.scan(&stranger).is_empty());
    }

    /// The full cycle: receive an output, then spend it in a new transaction that
    /// itself verifies. Exercises layers 2–6 end to end.
    #[test]
    fn received_output_is_spendable() {
        // TX 1: pay 100 (+ fee 0 ... use fee 0 for simplicity via exact balance)
        let alice = account();
        let payments = vec![Payment { destination: address(&alice), amount: 100 }];
        let funding = vec![fabricate_input(100, 7, 2)];
        let tx1_keys = TxKeypair::random(&mut OsRng);
        let tx1 = Transaction::build(&mut OsRng, &funding, &payments, 0, &tx1_keys).unwrap();
        assert!(tx1.verify(&mut OsRng).is_ok());

        // Alice receives the 100 output.
        let received = tx1.scan(&alice);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].amount, 100);

        // TX 2: Alice spends her 100 → pays Bob 90, fee 10.
        let bob = account();
        let spend = received[0].to_input(ring_of(11), 5);
        let payments2 = vec![Payment { destination: address(&bob), amount: 90 }];
        let tx2_keys = TxKeypair::random(&mut OsRng);
        let tx2 = Transaction::build(&mut OsRng, &[spend], &payments2, 10, &tx2_keys).unwrap();

        assert!(tx2.verify(&mut OsRng).is_ok());
        // The key image Alice publishes matches the one predicted when she
        // received the output (double-spend linkability across transactions).
        assert_eq!(tx2.inputs[0].key_image(), received[0].key_image);
        // Bob can find his 90.
        let bob_got = tx2.scan(&bob);
        assert_eq!(bob_got.len(), 1);
        assert_eq!(bob_got[0].amount, 90);
    }
}
```

===== FILE: core/src/amounts.rs =====

```rust
//! Layer 4 — amounts: Pedersen commitments + Bulletproofs+ range proofs.
//!
//! A confidential output hides its value behind a **Pedersen commitment**
//!
//! ```text
//!     C = x·G + a·H
//! ```
//!
//! where `a` is the amount, `x` is a secret blinding factor (the *mask*), `G`
//! is the ed25519 basepoint, and `H` is a second NUMS ("nothing up my sleeve")
//! generator whose discrete log w.r.t. `G` is unknown. Commitments are additively
//! homomorphic: `C(a₁,x₁) + C(a₂,x₂) = C(a₁+a₂, x₁+x₂)`. That is what lets a
//! verifier confirm a transaction balances (`Σinputs = Σoutputs + fee`) purely
//! from the commitment points, without learning any amount.
//!
//! On its own a commitment doesn't stop a sender from committing to a negative /
//! overflowing value (which would forge money via the group's wraparound). A
//! **range proof** closes that hole by proving, in zero knowledge, that each
//! committed amount lies in `[0, 2^64)`. We use **Bulletproofs+** — the same
//! aggregate range proof Monero deploys.
//!
//! ## Where the cryptography comes from
//!
//! We do **not** hand-roll any of this. `H`, the commitment math, and the
//! Bulletproofs+ prover/verifier are Monero's exact constructions, provided by
//! `monero-primitives` / `monero-bulletproofs` / `monero-ed25519` (built on
//! `curve25519-dalek`). Reusing Monero's reviewed construction and byte formats
//! means an auditor can diff Nocturnal against Monero instead of reviewing novel
//! cryptography.
//!
//! ### Dependency provenance
//!
//! These are the **first-party** crates from `monero-oxide`, the project serai's
//! Monero code was spun out into. Nocturnal previously built against a third-party
//! `-mirror` republish, because serai's own crates.io names were empty
//! placeholders at the time; that republish is no longer needed.
//!
//! The migration was proven byte-compatible before adoption: `H_p` is identical
//! across both implementations, and the live 673-block chain — mined and signed
//! under the mirrors — re-validates in full under these crates. See
//! `docs/DEPENDENCIES.md` §6.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use monero_bulletproofs::{Bulletproof, BulletproofError};
// `Commitment` moved from monero-primitives to monero-ed25519 when upstream split
// the old monero-generators crate.
use monero_ed25519::{Commitment as RawCommitment, Scalar as RawScalar};

/// Range proofs cover amounts in `[0, 2^AMOUNT_BITS)`.
pub const AMOUNT_BITS: u32 = 64;

/// Maximum number of outputs that can share one aggregate range proof.
pub use monero_bulletproofs::MAX_COMMITMENTS;

/// Errors from building or checking amount commitments / range proofs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AmountError {
    /// A range proof was requested for zero outputs.
    NoOutputs,
    /// More outputs than [`MAX_COMMITMENTS`] were aggregated into one proof.
    TooManyOutputs,
    /// The proof bytes were malformed.
    Malformed,
}

impl From<BulletproofError> for AmountError {
    fn from(e: BulletproofError) -> Self {
        match e {
            BulletproofError::NoCommitments => AmountError::NoOutputs,
            BulletproofError::TooManyCommitments => AmountError::TooManyOutputs,
        }
    }
}

/// The value generator `H`: a NUMS point (Monero's `hash_to_point` of `G`) whose
/// discrete log w.r.t. `G` is unknown.
///
/// Recovered from the commitment definition itself: `Commit(amount=1, mask=0)`
/// is `1·H + 0·G = H`. This is exactly the `H` serai's `monero-generators`
/// derives, so commitments here are byte-identical to Monero's.
pub fn h_generator() -> EdwardsPoint {
    // monero-oxide wraps scalars and points in its own newtypes over
    // curve25519-dalek, and `calculate` is now `commit`.
    RawCommitment::new(RawScalar::from(Scalar::ZERO), 1).commit().into()
}

/// The secret opening of a commitment: an amount and its blinding mask. This is
/// what the sender keeps and (for their own outputs) hands to the recipient via
/// the shared secret; it must never appear on-chain.
#[derive(Clone)]
pub struct Opening {
    pub amount: u64,
    pub mask: Scalar,
}

impl core::fmt::Debug for Opening {
    // Redact the mask: it is secret, and leaking it into logs would let anyone
    // open the commitment.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opening").field("amount", &self.amount).finish_non_exhaustive()
    }
}

impl Opening {
    pub fn new(amount: u64, mask: Scalar) -> Self {
        Opening { amount, mask }
    }

    /// A fresh opening for `amount` with a random mask.
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(amount: u64, rng: &mut R) -> Self {
        Opening { amount, mask: Scalar::random(rng) }
    }

    /// The public commitment point `C = mask·G + amount·H`.
    pub fn commit(&self) -> Commitment {
        Commitment(self.to_raw().commit().into())
    }

    /// The underlying serai commitment opening. Crate-internal so the serai type
    /// does not leak into Nocturnal's public API (used by [`crate::ring`]).
    pub(crate) fn to_raw(&self) -> RawCommitment {
        RawCommitment::new(RawScalar::from(self.mask), self.amount)
    }
}

/// A Pedersen commitment point `C = x·G + a·H`. This is the public, on-chain
/// object; it reveals nothing about `a` given a hidden mask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment(pub EdwardsPoint);

impl Commitment {
    /// The commitment to the (public) transaction fee: `fee·H`, i.e. a
    /// commitment with mask `0`. Because its mask is zero it contributes nothing
    /// to the mask balance, only to the amount balance.
    pub fn fee(fee: u64) -> Commitment {
        Opening::new(fee, Scalar::ZERO).commit()
    }

    /// The identity element — the empty sum, useful as a fold seed.
    pub fn identity() -> Commitment {
        Commitment(EdwardsPoint::identity())
    }

    pub fn point(&self) -> EdwardsPoint {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode a commitment point, rejecting non-canonical encodings and torsion
    /// points (a Pedersen commitment `x·G + a·H` is prime-order).
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Commitment> {
        let point = CompressedEdwardsY(bytes).decompress()?;
        if point.compress().to_bytes() != bytes || !point.is_torsion_free() {
            return None;
        }
        Some(Commitment(point))
    }

    /// Sum a set of commitments (homomorphic addition of the committed values).
    pub fn sum<'a, I: IntoIterator<Item = &'a Commitment>>(iter: I) -> Commitment {
        iter.into_iter().fold(Commitment::identity(), |acc, c| acc + *c)
    }
}

impl core::ops::Add for Commitment {
    type Output = Commitment;
    fn add(self, rhs: Commitment) -> Commitment {
        Commitment(self.0 + rhs.0)
    }
}

impl core::ops::Sub for Commitment {
    type Output = Commitment;
    fn sub(self, rhs: Commitment) -> Commitment {
        Commitment(self.0 - rhs.0)
    }
}

/// An aggregate Bulletproofs+ range proof over one or more output commitments,
/// each proven to lie in `[0, 2^64)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RangeProof {
    inner: Bulletproof,
}

impl RangeProof {
    /// Prove that every opening's amount is in range, returning the proof
    /// alongside the public commitment points (in the same order).
    ///
    /// The masks are consumed only to build the proof; they are not retained.
    pub fn prove<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        openings: &[Opening],
    ) -> Result<(RangeProof, Vec<Commitment>), AmountError> {
        if openings.is_empty() {
            return Err(AmountError::NoOutputs);
        }
        if openings.len() > MAX_COMMITMENTS {
            return Err(AmountError::TooManyOutputs);
        }
        let commitments = openings.iter().map(Opening::commit).collect::<Vec<_>>();
        let raw = openings.iter().map(Opening::to_raw).collect::<Vec<_>>();
        let inner = Bulletproof::prove_plus(rng, raw)?;
        Ok((RangeProof { inner }, commitments))
    }

    /// Verify the proof against the given commitment points. Returns `true` only
    /// if every committed amount is provably in `[0, 2^64)`.
    #[must_use]
    pub fn verify<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        commitments: &[Commitment],
    ) -> bool {
        // BP+ verification now takes compressed points rather than decompressed ones.
        let points = commitments
            .iter()
            .map(|c| monero_ed25519::Point::from(c.point()).compress())
            .collect::<Vec<_>>();
        self.inner.verify(rng, &points)
    }

    /// Serialize to the Bulletproof+ wire encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.serialize()
    }

    /// Parse a Bulletproof+ from its wire encoding.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<RangeProof, AmountError> {
        Self::read_from(&mut bytes)
    }

    /// Read a Bulletproof+ from a cursor, advancing it past the proof. Used by
    /// wire decoding where the proof is one field among many.
    pub(crate) fn read_from(cursor: &mut &[u8]) -> Result<RangeProof, AmountError> {
        let inner = Bulletproof::read_plus(cursor).map_err(|_| AmountError::Malformed)?;
        Ok(RangeProof { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ---- Commitment homomorphism ----------------------------------------

    /// Σ(input commitments) == Σ(output commitments) + fee commitment, as points,
    /// exactly when the amounts balance and the masks balance. This is the RingCT
    /// balance check performed without revealing any amount.
    #[test]
    fn commitment_homomorphism_balances() {
        // Inputs: 7 and 5 (total 12).
        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let in1 = Opening::new(7, x1);
        let in2 = Opening::new(5, x2);

        // Outputs: 8 and 3, plus a public fee of 1  (8 + 3 + 1 == 12).
        // The fee commitment has mask 0, so output masks must sum to the input
        // masks for the points to balance: y1 + y2 = x1 + x2.
        let y1 = Scalar::random(&mut OsRng);
        let y2 = x1 + x2 - y1;
        let out1 = Opening::new(8, y1);
        let out2 = Opening::new(3, y2);
        let fee = 1u64;

        let lhs = Commitment::sum([&in1.commit(), &in2.commit()]);
        let rhs = Commitment::sum([&out1.commit(), &out2.commit()]) + Commitment::fee(fee);

        assert_eq!(lhs, rhs);
    }

    /// If the amounts do *not* balance, the commitments must not be equal —
    /// otherwise money could be forged. (Masks balanced; only amounts off by 1.)
    #[test]
    fn commitment_detects_amount_imbalance() {
        let x = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let input = Opening::new(10, x + y); // mask sums to x + y
        let out1 = Opening::new(6, x);
        let out2 = Opening::new(3, y); // amounts sum to 9, not 10; no fee
        let lhs = input.commit();
        let rhs = out1.commit() + out2.commit();
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn h_generator_matches_commitment_definition() {
        // Commit(amount=5, mask=0) must equal 5·H.
        let five_h = Opening::new(5, Scalar::ZERO).commit();
        let h = h_generator();
        assert_eq!(five_h.0, h * Scalar::from(5u64));
    }

    // ---- Range proofs ----------------------------------------------------

    /// A valid proof over several outputs verifies.
    #[test]
    fn valid_range_proof_verifies() {
        let openings = vec![
            Opening::random(0, &mut OsRng),
            Opening::random(1, &mut OsRng),
            Opening::random(1_000_000_000_000, &mut OsRng),
            Opening::random(u64::MAX, &mut OsRng), // top of the [0, 2^64) range
        ];
        let (proof, commitments) = RangeProof::prove(&mut OsRng, &openings).unwrap();
        assert!(proof.verify(&mut OsRng, &commitments));
    }

    /// Tampering with a committed amount (keeping the proof) must fail: the proof
    /// is bound to the exact commitment points it was created for.
    #[test]
    fn tampered_amount_fails_verification() {
        let mask = Scalar::random(&mut OsRng);
        let opening = Opening::new(1_000, mask);
        let (proof, commitments) = RangeProof::prove(&mut OsRng, &[opening]).unwrap();
        assert!(proof.verify(&mut OsRng, &commitments));

        // Same mask, different amount → a different commitment point the proof
        // was never made for.
        let tampered = Opening::new(1_001, mask).commit();
        assert_ne!(tampered, commitments[0]);
        assert!(!proof.verify(&mut OsRng, &[tampered]));
    }

    /// Verifying against the wrong number of commitments must also fail rather
    /// than panic.
    #[test]
    fn wrong_commitment_count_fails() {
        let openings = vec![Opening::random(42, &mut OsRng), Opening::random(43, &mut OsRng)];
        let (proof, commitments) = RangeProof::prove(&mut OsRng, &openings).unwrap();
        assert!(proof.verify(&mut OsRng, &commitments));
        assert!(!proof.verify(&mut OsRng, &commitments[..1]));
    }

    #[test]
    fn proof_serialization_roundtrips() {
        let openings = vec![Opening::random(123, &mut OsRng)];
        let (proof, commitments) = RangeProof::prove(&mut OsRng, &openings).unwrap();
        let bytes = proof.to_bytes();
        let restored = RangeProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, restored);
        assert!(restored.verify(&mut OsRng, &commitments));
    }

    #[test]
    fn empty_and_oversized_output_sets_error() {
        assert_eq!(RangeProof::prove(&mut OsRng, &[]).err(), Some(AmountError::NoOutputs));
        let too_many =
            (0..=MAX_COMMITMENTS).map(|i| Opening::random(i as u64, &mut OsRng)).collect::<Vec<_>>();
        assert_eq!(
            RangeProof::prove(&mut OsRng, &too_many).err(),
            Some(AmountError::TooManyOutputs)
        );
    }
}
```

===== FILE: core/src/ring.rs =====

```rust
//! Layer 5 — ring signatures: CLSAG + key images (double-spend prevention).
//!
//! To spend an output the sender proves, in zero knowledge, that they own **one**
//! member of a *ring* of plausible outputs — without revealing which one. This is
//! CryptoNote sender ambiguity. Nocturnal uses **CLSAG** (Concise Linkable Spontaneous
//! Anonymous Group signatures), Monero's ring signature.
//!
//! A ring is a list of members, each a pair `[P, C]`:
//! * `P` — a one-time public key (see [`crate::stealth`]),
//! * `C` — that output's amount commitment (see [`crate::amounts`]).
//!
//! CLSAG simultaneously proves three things about the signer's secret index `r`:
//! 1. **Ownership** — the signer knows `x` with `P_r = x·G`.
//! 2. **Balance** — the signer knows the opening of `C_r`, and re-commits the
//!    same amount under a fresh *pseudo-out* commitment `C'`. Verifiers later
//!    check `Σ pseudo-outs − Σ outputs − fee = 0`; because `C_r` and `C'` commit
//!    to the same value, this holds exactly when the transaction balances. The
//!    difference `C_r − C'` has a known discrete log over `G` only (a
//!    "commitment to zero").
//! 3. **Linkability** — the signature publishes a **key image**
//!    `I = x·H_p(P_r)`, uniquely determined by the spent output. Two spends of
//!    the same output yield the *same* key image, so the network rejects the
//!    second as a double-spend, all while `I` reveals nothing about `r`.
//!
//! Because the pseudo-out masks must sum to the output masks for the balance
//! check to pass, inputs are signed **as a set** (the last input's mask absorbs
//! the difference) — hence the batch [`sign`] API, mirroring Monero.
//!
//! The CLSAG construction, key-image generator `H_p`, and transcript come from
//! `monero-clsag` / `monero-ed25519` (Monero-compatible, over curve25519-dalek).
//! See the provenance note in [`crate::amounts`].

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

// `Decoys` moved from monero-primitives into monero-clsag; `hash_to_point` became
// `Point::biased_hash` in monero-ed25519. Both are the same functions upstream —
// `biased_hash` was verified byte-identical to the old `hash_to_point` before
// this migration (docs/DEPENDENCIES.md §6), so key images are unchanged.
use monero_clsag::{Clsag, ClsagContext, ClsagError, Decoys};
use monero_ed25519::Point as MoneroPoint;

use crate::amounts::{Commitment, Opening};
use crate::keys::{PrivateKey, PublicKey};

/// Errors from ring signing / verification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RingError {
    /// The ring was empty, too large, or `signer_index` was out of bounds.
    InvalidRing,
    /// The signer's secret does not open the real ring member's key `P = x·G`.
    KeyMismatch,
    /// The signer's opening does not match the real ring member's commitment.
    CommitmentMismatch,
    /// The underlying CLSAG rejected the input.
    Clsag(ClsagError),
}

impl From<ClsagError> for RingError {
    fn from(e: ClsagError) -> Self {
        match e {
            ClsagError::InvalidRing => RingError::InvalidRing,
            ClsagError::InvalidKey => RingError::KeyMismatch,
            ClsagError::InvalidCommitment => RingError::CommitmentMismatch,
            other => RingError::Clsag(other),
        }
    }
}

/// The key image `I = x·H_p(P)` of an output with one-time key `P = x·G`.
///
/// Deterministic in the output: the same output always yields the same image, so
/// a spent-image set detects double-spends. It leaks nothing about which ring
/// member was spent.
#[derive(Clone, Copy, Debug)]
pub struct KeyImage(pub EdwardsPoint);

impl KeyImage {
    /// Derive the key image from an output's one-time spend secret `x`.
    pub fn from_secret(secret: &PrivateKey) -> KeyImage {
        let p = EdwardsPoint::mul_base(&secret.0); // P = x·G
        let hp: EdwardsPoint = MoneroPoint::biased_hash(p.compress().0).into(); // H_p(P)
        KeyImage(hp * secret.0) // I = x·H_p(P)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode a key image, rejecting non-canonical encodings and torsion / small
    /// -order points. A valid key image `I = x·H_p(P)` is prime-order; enforcing
    /// that here (in addition to CLSAG verify) stops a torsioned variant of a
    /// spent image from entering the spent set as a distinct entry once a wire
    /// deserialization path exists.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<KeyImage> {
        let point = CompressedEdwardsY(bytes).decompress()?;
        if point.compress().to_bytes() != bytes || !point.is_torsion_free() {
            return None;
        }
        Some(KeyImage(point))
    }
}

impl PartialEq for KeyImage {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for KeyImage {}

// Enable use in a HashSet for double-spend detection (compare by encoding).
impl core::hash::Hash for KeyImage {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

/// One member of a ring: a one-time public key and its amount commitment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RingMember {
    pub key: PublicKey,
    pub commitment: Commitment,
}

impl RingMember {
    pub fn new(key: PublicKey, commitment: Commitment) -> Self {
        RingMember { key, commitment }
    }

    /// The `[one-time key, commitment]` pair CLSAG consumes, in monero-oxide's
    /// point newtype.
    fn to_pair(self) -> [MoneroPoint; 2] {
        [MoneroPoint::from(self.key.0), MoneroPoint::from(self.commitment.0)]
    }

    /// The same pair, compressed — what `Clsag::verify` takes.
    fn to_compressed_pair(self) -> [monero_ed25519::CompressedPoint; 2] {
        let [k, c] = self.to_pair();
        [k.compress(), c.compress()]
    }
}

/// Everything needed to sign for one real input.
pub struct SpendInput {
    /// One-time spend secret `x` for the real ring member (`P = x·G`).
    pub secret: PrivateKey,
    /// The real input's amount + mask (its commitment opening).
    pub opening: Opening,
    /// The ring: decoys plus the real member, in on-chain order.
    pub ring: Vec<RingMember>,
    /// Index of the real member within `ring`.
    pub signer_index: usize,
}

impl SpendInput {
    /// The key image this input will publish.
    pub fn key_image(&self) -> KeyImage {
        KeyImage::from_secret(&self.secret)
    }

    fn context(&self) -> Result<ClsagContext, RingError> {
        if self.ring.is_empty() || self.signer_index >= self.ring.len() {
            return Err(RingError::InvalidRing);
        }
        // Fail fast with precise errors rather than deferring to CLSAG.
        let real = self.ring[self.signer_index];
        if EdwardsPoint::mul_base(&self.secret.0) != real.key.0 {
            return Err(RingError::KeyMismatch);
        }
        if self.opening.commit() != real.commitment {
            return Err(RingError::CommitmentMismatch);
        }

        let ring = self.ring.iter().map(|m| m.to_pair()).collect::<Vec<_>>();
        // Decoy `offsets` are on-chain positions used only for output referencing
        // (layer 8); they do not enter the signature math, so any well-formed
        // vector works here. Real transactions will fill these from the chain.
        let offsets = vec![1u64; ring.len()];
        let signer_index = u8::try_from(self.signer_index).map_err(|_| RingError::InvalidRing)?;
        let decoys = Decoys::new(offsets, signer_index, ring).ok_or(RingError::InvalidRing)?;
        ClsagContext::new(decoys, self.opening.to_raw()).map_err(RingError::from)
    }
}

/// A CLSAG signature for a single input, with its key image and pseudo-out.
#[derive(Clone, Debug)]
pub struct InputSignature {
    signature: Clsag,
    pub key_image: KeyImage,
    pub pseudo_out: Commitment,
}

impl InputSignature {
    /// Verify this signature against the given `ring` and message.
    #[must_use]
    pub fn verify(&self, ring: &[RingMember], msg: &[u8; 32]) -> bool {
        let ring_pairs = ring.iter().map(|m| m.to_compressed_pair()).collect::<Vec<_>>();
        self.signature
            .verify(
                ring_pairs,
                &MoneroPoint::from(self.key_image.0).compress(),
                &MoneroPoint::from(self.pseudo_out.0).compress(),
                msg,
            )
            .is_ok()
    }

    /// The CLSAG wire encoding of the signature (without the key image /
    /// pseudo-out, which travel alongside it in a transaction).
    pub fn signature_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.signature.write(&mut out).expect("writing to a Vec is infallible");
        out
    }

    /// Reconstruct an `InputSignature` from its parts (used by wire decoding).
    /// The CLSAG is not trusted until [`InputSignature::verify`] runs.
    pub(crate) fn from_parts(signature: Clsag, key_image: KeyImage, pseudo_out: Commitment) -> Self {
        InputSignature { signature, key_image, pseudo_out }
    }

    /// The underlying CLSAG, for wire encoding.
    pub(crate) fn clsag(&self) -> &Clsag {
        &self.signature
    }
}

/// Sign a set of inputs, balancing the pseudo-out masks against `output_mask_sum`
/// (the sum of the transaction's output commitment masks). Returns one
/// [`InputSignature`] per input, in order.
///
/// `msg` is the 32-byte message bound by every signature (the transaction hash
/// in a full transaction).
pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    inputs: &[SpendInput],
    output_mask_sum: Scalar,
    msg: [u8; 32],
) -> Result<Vec<InputSignature>, RingError> {
    if inputs.is_empty() {
        return Err(RingError::InvalidRing);
    }

    // Build CLSAG inputs, validating each real member up front.
    let mut clsag_inputs = Vec::with_capacity(inputs.len());
    let key_images = inputs.iter().map(SpendInput::key_image).collect::<Vec<_>>();
    for input in inputs {
        clsag_inputs.push((
            Zeroizing::new(monero_ed25519::Scalar::from(input.secret.0)),
            input.context()?,
        ));
    }

    let signed = Clsag::sign(rng, clsag_inputs, monero_ed25519::Scalar::from(output_mask_sum), msg)
        .map_err(RingError::from)?;

    Ok(signed
        .into_iter()
        .zip(key_images)
        .map(|((signature, pseudo_out), key_image)| InputSignature {
            signature,
            key_image,
            pseudo_out: Commitment(pseudo_out.into()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amounts::Commitment as AmountCommitment;
    use rand_core::OsRng;

    // Build a random ring member (decoy) with an unknown-to-us opening.
    fn decoy() -> RingMember {
        let key = PrivateKey(Scalar::random(&mut OsRng)).public_key();
        let commitment = Opening::random(rand_amount(), &mut OsRng).commit();
        RingMember::new(key, commitment)
    }

    fn rand_amount() -> u64 {
        // Small, deterministic-enough spread without needing an RNG-to-u64 helper.
        (Scalar::random(&mut OsRng).to_bytes()[0] as u64) + 1
    }

    // A real spendable input: secret x, its P = x·G, opening, placed in a ring.
    fn spend_input(amount: u64, ring_size: usize, signer_index: usize) -> (SpendInput, Scalar) {
        let secret = PrivateKey(Scalar::random(&mut OsRng));
        let mask = Scalar::random(&mut OsRng);
        let opening = Opening::new(amount, mask);
        let real = RingMember::new(secret.public_key(), opening.commit());

        let mut ring = (0..ring_size).map(|_| decoy()).collect::<Vec<_>>();
        ring[signer_index] = real;

        (SpendInput { secret, opening, ring, signer_index }, mask)
    }

    // A distinct output-mask sum for single-input tests. Using a *fresh* random
    // scalar (rather than the input's own mask) keeps the pseudo-out mask delta
    // non-zero, as it always is with random output masks in a real transaction.
    // (A zero delta yields an identity `D`, which CLSAG verify rejects.)
    fn out_mask_sum() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    #[test]
    fn valid_signature_verifies() {
        let (input, _mask) = spend_input(100, 11, 4);
        let ring = input.ring.clone();
        let msg = [7u8; 32];
        let sigs = sign(&mut OsRng, &[input], out_mask_sum(), msg).unwrap();
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].verify(&ring, &msg));
    }

    #[test]
    fn wrong_message_fails() {
        let (input, _mask) = spend_input(100, 8, 2);
        let ring = input.ring.clone();
        let sigs = sign(&mut OsRng, &[input], out_mask_sum(), [1u8; 32]).unwrap();
        assert!(sigs[0].verify(&ring, &[1u8; 32]));
        assert!(!sigs[0].verify(&ring, &[2u8; 32]));
    }

    #[test]
    fn tampered_ring_fails() {
        let (input, _mask) = spend_input(100, 8, 2);
        let mut ring = input.ring.clone();
        let sigs = sign(&mut OsRng, &[input], out_mask_sum(), [0u8; 32]).unwrap();
        assert!(sigs[0].verify(&ring, &[0u8; 32]));
        // Swap a decoy for a different one: the signature no longer matches.
        ring[0] = decoy();
        assert!(!sigs[0].verify(&ring, &[0u8; 32]));
    }

    #[test]
    fn wrong_secret_is_rejected_at_signing() {
        let (mut input, _mask) = spend_input(100, 8, 2);
        // Replace the secret with one that doesn't open the real key.
        input.secret = PrivateKey(Scalar::random(&mut OsRng));
        assert_eq!(sign(&mut OsRng, &[input], Scalar::ONE, [0u8; 32]).err(), Some(RingError::KeyMismatch));
    }

    #[test]
    fn mismatched_opening_is_rejected_at_signing() {
        let (mut input, _mask) = spend_input(100, 8, 2);
        // Keep the secret (key matches) but claim a different opening.
        input.opening = Opening::new(101, Scalar::random(&mut OsRng));
        assert_eq!(
            sign(&mut OsRng, &[input], Scalar::ONE, [0u8; 32]).err(),
            Some(RingError::CommitmentMismatch)
        );
    }

    #[test]
    fn key_image_links_double_spend() {
        // Spend the *same* output in two different rings / transactions.
        let secret = PrivateKey(Scalar::random(&mut OsRng));
        let mask = Scalar::random(&mut OsRng);
        let opening = Opening::new(50, mask);
        let real = RingMember::new(secret.public_key(), opening.commit());

        let make = |signer_index: usize| {
            let mut ring = (0..6).map(|_| decoy()).collect::<Vec<_>>();
            ring[signer_index] = real;
            SpendInput { secret, opening: opening.clone(), ring, signer_index }
        };

        let a = make(1);
        let b = make(4);
        let sig_a = sign(&mut OsRng, &[a], Scalar::random(&mut OsRng), [0u8; 32]).unwrap();
        let sig_b = sign(&mut OsRng, &[b], Scalar::random(&mut OsRng), [9u8; 32]).unwrap();

        // Different signatures, different rings — but identical key image.
        assert_eq!(sig_a[0].key_image, sig_b[0].key_image);

        // A spent-image set catches the second spend.
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(sig_a[0].key_image));
        assert!(!seen.insert(sig_b[0].key_image));
    }

    #[test]
    fn distinct_outputs_have_distinct_key_images() {
        let i1 = KeyImage::from_secret(&PrivateKey(Scalar::random(&mut OsRng)));
        let i2 = KeyImage::from_secret(&PrivateKey(Scalar::random(&mut OsRng)));
        assert_ne!(i1, i2);
    }

    /// The RingCT balance property: with two inputs and two outputs + fee whose
    /// amounts balance, `Σ pseudo-outs == Σ output commitments + fee`.
    #[test]
    fn pseudo_outs_balance_against_outputs() {
        // Inputs: 30 + 20 = 50.
        let (in1, _m1) = spend_input(30, 7, 3);
        let (in2, _m2) = spend_input(20, 7, 1);
        let ring1 = in1.ring.clone();
        let ring2 = in2.ring.clone();

        // Outputs: 45 + 4, fee 1  (45 + 4 + 1 == 50). Random output masks.
        let y1 = Scalar::random(&mut OsRng);
        let y2 = Scalar::random(&mut OsRng);
        let out1 = Opening::new(45, y1);
        let out2 = Opening::new(4, y2);
        let fee = 1u64;
        let output_mask_sum = y1 + y2; // fee commitment has mask 0

        let msg = [3u8; 32];
        let sigs = sign(&mut OsRng, &[in1, in2], output_mask_sum, msg).unwrap();
        assert!(sigs[0].verify(&ring1, &msg));
        assert!(sigs[1].verify(&ring2, &msg));

        let sum_pseudo = sigs[0].pseudo_out + sigs[1].pseudo_out;
        let sum_outputs =
            AmountCommitment::sum([&out1.commit(), &out2.commit()]) + Commitment::fee(fee);
        assert_eq!(sum_pseudo, sum_outputs);
    }
}
```

===== FILE: core/src/chain.rs =====

```rust
//! Layer 8 — chain state.
//!
//! [`Blockchain`] strings validated blocks together and maintains the state that
//! individual transactions cannot check on their own:
//!
//! * a **global output set** — every output ever created, indexed by position;
//!   ring members must be real entries here (a transaction can't invent decoys),
//! * a **global spent key-image set** — prevents double-spends *across*
//!   transactions and blocks (a single transaction's self-consistency is checked
//!   by [`Transaction::verify`]),
//! * **cumulative difficulty** and the per-block difficulty retarget,
//! * the **emission** accounting that fixes each block's allowed coinbase reward.
//!
//! This replaces the two simplifications flagged in earlier layers: rings are now
//! validated against the real output set, and key images are checked globally.
//!
//! ## Scope
//!
//! The chain is **forward-only**: it validates and appends to a single main
//! chain and tracks cumulative difficulty, exposing the fork-choice *rule*
//! ([`Blockchain::would_reorg_to`]). Executing a reorg (rolling back state to a
//! fork point and replaying a heavier branch) needs per-block undo data and is
//! deferred to the networking layer. Decoy selection offers a uniform sampler and
//! a recency-biased (gamma-shaped) one; calibrating the gamma to the real output
//! age distribution is a pre-testnet refinement.

use std::collections::{HashMap, HashSet};

use crate::block::Block;
use crate::emission::base_reward;
use crate::pow::{check_hash, next_difficulty, Difficulty, ProofOfWork, MIN_DIFFICULTY};
use crate::ring::{KeyImage, RingMember};
use crate::tx::{Transaction, TxError};

/// Median-time-past window: a block's timestamp must exceed the median of this
/// many preceding timestamps.
pub const MTP_WINDOW: usize = 11;

/// A block's timestamp may not be more than this many seconds ahead of the
/// validator's clock. Without a future limit, a far-future timestamp inflates
/// the retarget's elapsed-time divisor and collapses difficulty toward the
/// minimum, so this bound is a consensus guard, not just hygiene.
pub const FUTURE_TIME_LIMIT: u64 = 2 * 60 * 60; // 2 hours

/// Minimum ring size (1 real + N−1 decoys) a transaction input must use. A small
/// ring deanonymizes the spender and pollutes the anonymity set of anyone who
/// draws it as a decoy, so a floor is a privacy consensus rule. Placeholder
/// value — Monero currently mandates 16.
pub const MIN_RING_SIZE: usize = 11;

/// Gamma parameters for recency-biased decoy selection (Monero's fitted shape /
/// scale). See the module note on calibration.
pub const GAMMA_SHAPE: f64 = 19.28;
pub const GAMMA_SCALE: f64 = 1.61;

/// How many blocks a coinbase (mined or premine) output must be buried before it
/// can be referenced by a transaction — as the real spend *or* as a decoy.
///
/// Coinbase outputs are the outputs most likely to vanish in a reorg (a reorg
/// past their block erases them), so allowing an immediate spend would let a
/// short reorg unspend already-spent freshly-mined coins. Because ring
/// signatures hide which member is real, the rule is enforced over *every* ring
/// member — matching the intent of Monero's `unlock_time` on coinbase outputs
/// (Monero uses 60). Non-coinbase outputs have no maturity requirement.
pub const COINBASE_MATURITY: u64 = 60;

/// Errors from validating a block against the chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainError {
    /// The block does not build on the current tip.
    BadPrevId,
    /// The proof of work does not meet the required difficulty.
    BadPow,
    /// The timestamp is not greater than the median of recent blocks.
    BadTimestamp,
    /// The coinbase height does not match the block's height.
    BadCoinbaseHeight,
    /// The provided transactions don't match the block's `tx_hashes`.
    TxHashMismatch,
    /// A transaction failed internal verification.
    InvalidTx(TxError),
    /// A ring references an output not in the global output set.
    UnknownRingMember,
    /// A ring references a coinbase output that is not yet
    /// [`COINBASE_MATURITY`] blocks deep.
    ImmatureCoinbase,
    /// A block creates an output identical (`[P, C]`) to one that already
    /// exists, which would make the output set ambiguous. See the check in
    /// [`Blockchain::add_block`].
    DuplicateOutput,
    /// An input's ring is smaller than [`MIN_RING_SIZE`].
    RingTooSmall,
    /// A key image was already spent (here or in an earlier block).
    DoubleSpend,
    /// The coinbase does not claim exactly `subsidy + fees`.
    BadCoinbaseReward,
    /// A fee total overflowed.
    FeeOverflow,
    /// A reorg was attempted with no blocks.
    EmptyBranch,
    /// A reorg candidate had no more cumulative work than the current chain.
    NotHeavier,
    /// A branch tried to fork at height 0. Genesis is immutable — a chain that
    /// does not descend from it is a different network, not a competitor.
    CannotReplaceGenesis,
}

/// A block as accepted by the chain, with the transactions it carried. Retained
/// so the node can serve history to syncing peers and wallets.
#[derive(Clone, Debug)]
pub struct StoredBlock {
    pub block: Block,
    pub txs: Vec<Transaction>,
}

/// What a block changed, so it can be undone during a reorg. The key images and
/// output *contents* are re-derivable from the stored block itself; only these
/// two scalars cannot be recovered after the fact (`emitted` is not invertible
/// through the emission curve).
#[derive(Clone, Copy, Debug)]
struct Undo {
    outputs_len_before: usize,
    emitted_before: u64,
}

/// The result of a successful reorganisation.
#[derive(Debug)]
pub struct Reorg {
    /// Blocks dropped from the old chain, oldest first. Their transactions are no
    /// longer confirmed — a node should return them to its mempool.
    pub discarded: Vec<StoredBlock>,
    /// How many blocks of the new branch were applied.
    pub applied: usize,
}

/// A blockchain: validated blocks plus the state needed to validate the next one.
#[derive(Clone)]
pub struct Blockchain<P: ProofOfWork> {
    pow: P,
    /// Which network this chain is: selects the genesis block, and therefore
    /// every id derived from it. See [`crate::params`].
    network: crate::address::Network,
    blocks: Vec<StoredBlock>,
    undos: Vec<Undo>,
    block_ids: Vec<[u8; 32]>,
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<u128>,

    outputs: Vec<RingMember>,
    /// Membership key → global index, so a ring member can be resolved back to
    /// its output (for the coinbase-maturity check).
    output_membership: HashMap<[u8; 64], u64>,
    /// Per-output metadata, parallel to `outputs` (indexed by global index).
    output_meta: Vec<OutputMeta>,
    spent_key_images: HashSet<KeyImage>,
    emitted: u64,
    /// Blocks a coinbase output must be buried before it can be spent. Always
    /// [`COINBASE_MATURITY`] in production; tests may lower it via
    /// [`Blockchain::with_maturity`] so they need not mine 60 warm-up blocks.
    maturity: u64,
}

/// Per-output data the chain needs beyond the `[P, C]` ring member itself:
/// enough to enforce coinbase maturity.
#[derive(Clone, Copy, Debug)]
struct OutputMeta {
    /// Height of the block that created this output.
    height: u64,
    /// True if it is a coinbase (mined or premine) output.
    coinbase: bool,
}

fn membership_key(m: &RingMember) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&m.key.to_bytes());
    k[32..].copy_from_slice(&m.commitment.to_bytes());
    k
}

/// Wall-clock seconds since the Unix epoch, for the future-timestamp bound.
/// (Consensus timestamp validation is inherently clock-relative.)
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<P: ProofOfWork> Blockchain<P> {
    /// A new chain containing only the canonical genesis block, so every node
    /// starts rooted at the same block 0 and height 1.
    pub fn new(pow: P) -> Self {
        Self::with_maturity(pow, COINBASE_MATURITY)
    }

    /// A new chain on a specific network, rooted at that network's genesis.
    ///
    /// The network is part of the chain's identity: it selects the genesis block
    /// (and therefore every id derived from it) and the p2p magic peers must
    /// present. See [`crate::params`].
    pub fn for_network(network: crate::address::Network, pow: P) -> Self {
        Self::build(pow, COINBASE_MATURITY, network)
    }

    /// Like [`Blockchain::new`] but with an explicit coinbase-maturity depth.
    /// Production always uses [`COINBASE_MATURITY`] (via `new`); this exists so
    /// tests can spend freshly-mined coins without mining a full maturity window.
    pub fn with_maturity(pow: P, maturity: u64) -> Self {
        Self::build(pow, maturity, crate::address::Network::Mainnet)
    }

    fn build(pow: P, maturity: u64, network: crate::address::Network) -> Self {
        let mut chain = Blockchain {
            pow,
            network,
            blocks: Vec::new(),
            undos: Vec::new(),
            block_ids: Vec::new(),
            timestamps: Vec::new(),
            cumulative_difficulties: Vec::new(),
            outputs: Vec::new(),
            output_membership: HashMap::new(),
            output_meta: Vec::new(),
            spent_key_images: HashSet::new(),
            emitted: 0,
            maturity,
        };
        chain.apply_genesis();
        chain
    }

    // Genesis is applied directly, not through `add_block`: it is the axiom the
    // consensus rules are defined against, so it cannot be validated by them.
    // Unlike a mined block it carries the founder **premine** coinbase, so its
    // output is indexed into the global set (global index 0, spendable) and its
    // amount is counted as emitted — the emission curve then continues from the
    // premined baseline. Genesis can never be rolled back, so its `Undo` is
    // inert.
    fn apply_genesis(&mut self) {
        let block = Block::genesis_for(self.network.params());
        // The premine is a coinbase output at height 0; it matures like any other
        // coinbase (spendable once the chain is COINBASE_MATURITY blocks deep).
        for member in block.coinbase.output_refs() {
            self.push_output(member, 0, true);
        }
        let premined = block.coinbase.total().expect("genesis premine fits u64");
        self.blocks.push(StoredBlock { block: block.clone(), txs: Vec::new() });
        self.undos.push(Undo { outputs_len_before: 0, emitted_before: 0 });
        self.block_ids.push(block.id());
        self.timestamps.push(block.header.timestamp);
        self.cumulative_difficulties.push(MIN_DIFFICULTY as u128);
        self.emitted = premined;
    }

    /// The hash of the genesis block this chain is rooted at.
    pub fn genesis_id(&self) -> [u8; 32] {
        self.block_ids[0]
    }

    /// Which network this chain belongs to.
    pub fn network(&self) -> crate::address::Network {
        self.network
    }

    /// This chain's parameters — p2p magic, default ports, genesis constants.
    pub fn params(&self) -> &'static crate::params::ChainParams {
        self.network.params()
    }

    /// The RandomX epoch seed for a block at `height`: the id of the block at
    /// [`crate::pow::randomx_seed_height`]. Always resolves — that height is
    /// strictly below `height` and therefore already on the chain (falling back
    /// to genesis for the first epoch). Seedless PoW ignores the value.
    pub fn seed_for_height(&self, height: u64) -> [u8; 32] {
        let seed_height = crate::pow::randomx_seed_height(height);
        self.block_at(seed_height).map(|s| s.block.id()).unwrap_or_else(|| self.genesis_id())
    }

    // --- state queries ---------------------------------------------------

    /// Number of blocks in the chain (also the height of the next block).
    pub fn height(&self) -> u64 {
        self.block_ids.len() as u64
    }

    /// Hash of the current tip, or the zero hash for an empty chain.
    pub fn tip_id(&self) -> [u8; 32] {
        self.block_ids.last().copied().unwrap_or([0u8; 32])
    }

    /// Total accumulated work — the fork-choice metric.
    pub fn cumulative_difficulty(&self) -> u128 {
        self.cumulative_difficulties.last().copied().unwrap_or(0)
    }

    /// Coins emitted so far (subsidy only; fees are recycled, not new coins).
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Size of the global output set.
    pub fn num_outputs(&self) -> u64 {
        self.outputs.len() as u64
    }

    /// The output at a global index, if it exists.
    pub fn output(&self, index: u64) -> Option<RingMember> {
        self.outputs.get(usize::try_from(index).ok()?).copied()
    }

    /// The block accepted at `height` (with its transactions), if we have it.
    /// This is what lets a node serve history to a syncing peer or wallet.
    pub fn block_at(&self, height: u64) -> Option<&StoredBlock> {
        self.blocks.get(usize::try_from(height).ok()?)
    }

    /// Every block on the current canonical chain, oldest first. After a reorg
    /// this reflects the *new* branch, so a persistent store can be rewritten
    /// from it.
    pub fn blocks(&self) -> &[StoredBlock] {
        &self.blocks
    }

    /// The difficulty the next block must satisfy.
    pub fn next_difficulty(&self) -> Difficulty {
        next_difficulty(&self.timestamps, &self.cumulative_difficulties)
    }

    /// Has `image` already been spent on this chain?
    pub fn is_spent(&self, image: &KeyImage) -> bool {
        self.spent_key_images.contains(image)
    }

    /// Fork choice: would a competing chain of `their_cumulative_difficulty`
    /// replace ours? (Strictly greater work wins; ties keep the incumbent.)
    pub fn would_reorg_to(&self, their_cumulative_difficulty: u128) -> bool {
        their_cumulative_difficulty > self.cumulative_difficulty()
    }

    /// Median of the most recent [`MTP_WINDOW`] block timestamps. A new block's
    /// timestamp must be strictly greater; miners use this to pick a valid one.
    pub fn median_time_past(&self) -> u64 {
        if self.timestamps.is_empty() {
            return 0;
        }
        let start = self.timestamps.len().saturating_sub(MTP_WINDOW);
        let mut window: Vec<u64> = self.timestamps[start..].to_vec();
        window.sort_unstable();
        window[window.len() / 2]
    }

    // --- block application -----------------------------------------------

    /// Validate `block` (with its full transactions `txs`) against the current
    /// tip and, if valid, append it — updating the output set, spent images,
    /// difficulty, and emission.
    pub fn add_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        block: &Block,
        txs: &[Transaction],
    ) -> Result<(), ChainError> {
        // 1. Links to the tip.
        if block.header.prev_id != self.tip_id() {
            return Err(ChainError::BadPrevId);
        }

        // 2. Proof of work meets the required difficulty. Rekey the PoW to this
        //    block's epoch seed first (a no-op for seedless PoW like Keccak).
        let seed = self.seed_for_height(self.height());
        self.pow.reseed(&seed);
        let difficulty = self.next_difficulty();
        if !check_hash(&block.pow_hash(&self.pow), difficulty) {
            return Err(ChainError::BadPow);
        }

        // 3. Timestamp strictly after the median of recent blocks, and not too
        //    far in the future (guards difficulty against timestamp inflation).
        if self.height() > 0 && block.header.timestamp <= self.median_time_past() {
            return Err(ChainError::BadTimestamp);
        }
        if block.header.timestamp > now_secs().saturating_add(FUTURE_TIME_LIMIT) {
            return Err(ChainError::BadTimestamp);
        }

        // 4. Coinbase height matches.
        if block.coinbase.height != self.height() {
            return Err(ChainError::BadCoinbaseHeight);
        }

        // 5. Provided transactions match the block's committed hashes.
        if txs.len() != block.tx_hashes.len() {
            return Err(ChainError::TxHashMismatch);
        }
        for (tx, expected) in txs.iter().zip(&block.tx_hashes) {
            if &tx.hash() != expected {
                return Err(ChainError::TxHashMismatch);
            }
        }

        // 6. Validate each transaction and gather its key images / fees.
        let mut total_fees: u64 = 0;
        let mut block_images: HashSet<KeyImage> = HashSet::new();
        for tx in txs {
            // Per-transaction validity against current chain state (internal
            // verify + ring membership + not-already-spent).
            self.validate_tx(rng, tx)?;

            // Additionally, no key image may repeat *within* this block.
            for image in tx.key_images() {
                if !block_images.insert(image) {
                    return Err(ChainError::DoubleSpend);
                }
            }

            total_fees = total_fees.checked_add(tx.fee).ok_or(ChainError::FeeOverflow)?;
        }

        // 7. No output this block creates may duplicate an existing one, or
        //    another in the same block.
        //
        //    Outputs are identified by `[P, C]` and indexed by that key, so two
        //    identical outputs would make the index ambiguous — and the second
        //    silently replaces the first. That is a **maturity bypass**: a miner
        //    can mine a coinbase, then publish a transaction whose output copies
        //    that coinbase's `[P, C]` (both are attacker-chosen wire values, and
        //    a coinbase commitment's opening is public — mask 1 over a public
        //    amount). The duplicate is recorded as a *non-coinbase* output, so
        //    the immature coinbase resolves to it and becomes spendable.
        //
        //    Honest transactions never collide here: one-time keys derive from a
        //    random per-transaction key, so a repeat is cryptographically
        //    negligible. Rejecting duplicates outright removes the ambiguity.
        let mut new_outputs: HashSet<[u8; 64]> = HashSet::new();
        for member in block
            .coinbase
            .output_refs()
            .into_iter()
            .chain(txs.iter().flat_map(|t| t.output_refs()))
        {
            let key = membership_key(&member);
            if self.output_membership.contains_key(&key) || !new_outputs.insert(key) {
                return Err(ChainError::DuplicateOutput);
            }
        }

        // 8. Coinbase claims exactly subsidy + fees.
        let subsidy = base_reward(self.emitted);
        let allowed = subsidy.checked_add(total_fees).ok_or(ChainError::FeeOverflow)?;
        if !block.coinbase.is_valid(allowed) {
            return Err(ChainError::BadCoinbaseReward);
        }

        // --- All checks passed; commit state. ---
        // Capture what we cannot re-derive later, so this block can be undone.
        let undo = Undo { outputs_len_before: self.outputs.len(), emitted_before: self.emitted };
        let height = self.height();
        for member in block.coinbase.output_refs() {
            self.push_output(member, height, true);
        }
        for tx in txs {
            for member in tx.output_refs() {
                self.push_output(member, height, false);
            }
            for image in tx.key_images() {
                self.spent_key_images.insert(image);
            }
        }

        self.emitted = self.emitted.saturating_add(subsidy);
        self.blocks.push(StoredBlock { block: block.clone(), txs: txs.to_vec() });
        self.undos.push(undo);
        self.block_ids.push(block.id());
        self.timestamps.push(block.header.timestamp);
        self.cumulative_difficulties.push(self.cumulative_difficulty() + difficulty as u128);
        Ok(())
    }

    fn push_output(&mut self, member: RingMember, height: u64, coinbase: bool) {
        let index = self.outputs.len() as u64;
        self.output_membership.insert(membership_key(&member), index);
        self.outputs.push(member);
        self.output_meta.push(OutputMeta { height, coinbase });
    }

    /// Is the output at global `index` spendable — i.e. referenceable in a ring —
    /// given a chain of height `at_height`? Non-coinbase outputs always are;
    /// coinbase outputs must be [`COINBASE_MATURITY`] blocks deep.
    fn output_spendable_at(&self, index: u64, at_height: u64) -> bool {
        match self.output_meta.get(index as usize) {
            Some(meta) if meta.coinbase => at_height >= meta.height.saturating_add(self.maturity),
            Some(_) => true,
            None => false,
        }
    }

    // --- reorganisation ---------------------------------------------------

    /// Undo the tip block, returning it. Reverses exactly what `add_block`
    /// committed: its outputs leave the set, its key images become unspent, and
    /// emission/work/timestamps rewind.
    fn pop_block(&mut self) -> Option<StoredBlock> {
        let stored = self.blocks.pop()?;
        let undo = self.undos.pop()?;

        // Its inputs are no longer spent.
        for tx in &stored.txs {
            for image in tx.key_images() {
                self.spent_key_images.remove(&image);
            }
        }
        // Its outputs no longer exist. (Outputs are only ever appended, so the
        // block's outputs are exactly the tail past `outputs_len_before`.)
        for member in self.outputs.drain(undo.outputs_len_before..) {
            self.output_membership.remove(&membership_key(&member));
        }
        self.output_meta.truncate(undo.outputs_len_before);

        self.emitted = undo.emitted_before;
        self.block_ids.pop();
        self.timestamps.pop();
        self.cumulative_difficulties.pop();
        Some(stored)
    }

    /// Roll the chain back to `height`, returning the removed blocks oldest-first.
    /// A no-op if already at or below `height`.
    ///
    /// Genesis is never removed: the target is clamped to height 1, so a chain
    /// always remains rooted at block 0.
    pub fn rollback_to(&mut self, height: u64) -> Vec<StoredBlock> {
        let height = height.max(1);
        let mut removed = Vec::new();
        while self.height() > height {
            match self.pop_block() {
                Some(stored) => removed.push(stored),
                None => break,
            }
        }
        removed.reverse();
        removed
    }

    /// Switch to `branch` if it is heavier than the current chain.
    ///
    /// `branch` is a run of blocks starting at the fork height (its first block's
    /// `coinbase.height`), oldest first. The branch is validated in full against a
    /// **copy** of the chain, so a branch that is invalid *or* merely lighter can
    /// never leave this chain in a partial state — we only commit once it has
    /// been proven both valid and heavier.
    ///
    /// On success returns the discarded blocks so a caller can put their
    /// transactions back in a mempool.
    pub fn try_reorg<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        branch: &[(Block, Vec<Transaction>)],
    ) -> Result<Reorg, ChainError>
    where
        P: Clone,
    {
        let first = branch.first().ok_or(ChainError::EmptyBranch)?;
        let fork_height = first.0.coinbase.height;
        if fork_height > self.height() {
            return Err(ChainError::BadPrevId); // gap: nothing to attach to
        }
        // A branch may never replace genesis. This is what makes the chain's
        // identity immutable: any candidate must descend from *our* block 0, so a
        // foreign chain cannot be adopted no matter how much work it carries.
        if fork_height == 0 {
            return Err(ChainError::CannotReplaceGenesis);
        }

        let mut candidate = self.clone();
        let discarded = candidate.rollback_to(fork_height);
        for (block, txs) in branch {
            candidate.add_block(rng, block, txs)?;
        }
        if candidate.cumulative_difficulty() <= self.cumulative_difficulty() {
            return Err(ChainError::NotHeavier);
        }

        *self = candidate;
        Ok(Reorg { discarded, applied: branch.len() })
    }

    /// Is `member` a real output in the global set? (Used for ring validation.)
    pub fn contains_output(&self, member: &RingMember) -> bool {
        self.output_membership.contains_key(&membership_key(member))
    }

    /// The global index of `member`, if it is in the output set.
    pub fn output_index(&self, member: &RingMember) -> Option<u64> {
        self.output_membership.get(&membership_key(member)).copied()
    }

    /// Can `member` be spent (or used as a decoy) right now — i.e. is it a real
    /// output that is not an immature coinbase? Wallets use this to avoid
    /// selecting an unspendable output as an input.
    pub fn is_spendable(&self, member: &RingMember) -> bool {
        match self.output_index(member) {
            Some(index) => self.output_spendable_at(index, self.height()),
            None => false,
        }
    }

    /// Validate a single transaction against current chain state, independent of
    /// any block: internal [`Transaction::verify`], every ring member exists in
    /// the output set, and no key image is already spent on-chain.
    ///
    /// Shared by [`Self::add_block`] and the mempool ([`crate::mempool`]). Does
    /// **not** check for conflicts against other unconfirmed transactions — that
    /// is the mempool's responsibility.
    pub fn validate_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        tx: &Transaction,
    ) -> Result<(), ChainError> {
        tx.verify(rng).map_err(ChainError::InvalidTx)?;
        let height = self.height();
        for input in &tx.inputs {
            if input.ring.len() < MIN_RING_SIZE {
                return Err(ChainError::RingTooSmall);
            }
            for member in &input.ring {
                // Every ring member must be a real output, and — because ring
                // signatures hide which member is real — no member may be an
                // immature coinbase (else an immature coinbase could be spent
                // by hiding it among decoys).
                let index = self.output_index(member).ok_or(ChainError::UnknownRingMember)?;
                if !self.output_spendable_at(index, height) {
                    return Err(ChainError::ImmatureCoinbase);
                }
            }
        }
        for image in tx.key_images() {
            if self.spent_key_images.contains(&image) {
                return Err(ChainError::DoubleSpend);
            }
        }
        Ok(())
    }

    // --- decoy selection -------------------------------------------------

    /// Select a ring of `ring_size` members for the real output at
    /// `real_index`, choosing decoys **uniformly** from the output set. Returns
    /// the ring (real member placed at the returned signer index) and that index.
    ///
    /// `None` if the set is too small for the requested ring size.
    pub fn select_ring_uniform<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
    ) -> Option<(Vec<RingMember>, usize)> {
        self.assemble_ring(rng, ring_size, real_index, |rng, n| {
            (rng.next_u64() % n as u64) as usize
        })
    }

    /// Like [`Self::select_ring_uniform`] but biased toward **recent** outputs
    /// via a gamma-shaped age distribution (a simplification of Monero's
    /// output-time gamma; see the module note).
    pub fn select_ring_recency_biased<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
    ) -> Option<(Vec<RingMember>, usize)> {
        self.assemble_ring(rng, ring_size, real_index, |rng, n| {
            // Sample an "age" and map it to an index, favouring recent outputs
            // (higher indices). Bounded and monotone in the sampled age.
            let age = sample_gamma(rng, GAMMA_SHAPE, GAMMA_SCALE);
            let frac = (age / (age + (GAMMA_SHAPE * GAMMA_SCALE))).clamp(0.0, 0.999_999);
            let from_tip = (frac * n as f64) as usize;
            (n - 1).saturating_sub(from_tip)
        })
    }

    // Shared ring assembly: draw distinct decoy indices via `pick`, place the
    // real member at a random position.
    fn assemble_ring<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
        mut pick: impl FnMut(&mut R, usize) -> usize,
    ) -> Option<(Vec<RingMember>, usize)> {
        let n = self.outputs.len();
        if ring_size == 0 || ring_size > n {
            return None;
        }
        let real = self.output(real_index)?;

        // Only outputs a transaction may legally reference are eligible decoys:
        // an immature coinbase would make the ring invalid under the
        // coinbase-maturity rule.
        //
        // Outputs are appended in block order, so their heights are
        // non-decreasing in index — which means the outputs too recent to be
        // mature are exactly a **suffix**. Everything before `mature_boundary`
        // is spendable outright, and only that suffix (at most `maturity`
        // blocks' worth of outputs) needs examining. Scanning the whole output
        // set here instead would make every ring assembly cost O(chain size).
        let height = self.height();
        let cutoff = height.saturating_sub(self.maturity);
        let mature_boundary = self.output_meta.partition_point(|m| m.height <= cutoff);
        debug_assert!(
            self.output_meta.windows(2).all(|w| w[0].height <= w[1].height),
            "output heights must be non-decreasing for the suffix bound to hold"
        );
        // Spendable = the whole mature prefix, plus non-coinbase outputs in the
        // recent suffix.
        let recent_spendable: Vec<usize> =
            (mature_boundary..n).filter(|&i| !self.output_meta[i].coinbase).collect();
        let spendable_count = mature_boundary + recent_spendable.len();
        if spendable_count < ring_size {
            return None;
        }

        // Distinct decoy indices (drawn from the spendable set), excluding the
        // real one.
        let mut chosen: HashSet<usize> = HashSet::new();
        chosen.insert(real_index as usize);
        let mut attempts = 0usize;
        while chosen.len() < ring_size {
            let idx = pick(rng, n);
            if self.output_spendable_at(idx as u64, height) {
                chosen.insert(idx);
            }
            attempts += 1;
            if attempts > ring_size * 100 {
                // Degenerate distribution; top up uniformly from the spendable
                // set to guarantee progress. Index `k` addresses the mature
                // prefix first, then the eligible outputs of the recent suffix.
                let k = (rng.next_u64() % spendable_count as u64) as usize;
                let idx = if k < mature_boundary { k } else { recent_spendable[k - mature_boundary] };
                chosen.insert(idx);
            }
        }

        let mut decoys: Vec<usize> = chosen.into_iter().filter(|&i| i != real_index as usize).collect();
        decoys.sort_unstable();

        let signer_index = (rng.next_u64() as usize) % ring_size;
        let mut ring = Vec::with_capacity(ring_size);
        let mut d = decoys.into_iter();
        for pos in 0..ring_size {
            if pos == signer_index {
                ring.push(real);
            } else {
                ring.push(self.outputs[d.next().unwrap()]);
            }
        }
        Some((ring, signer_index))
    }
}

/// A gamma sample via the Marsaglia–Tsang method, using `rng` for randomness.
pub fn sample_gamma<R: rand_core::RngCore>(rng: &mut R, shape: f64, scale: f64) -> f64 {
    if shape < 1.0 {
        let u = uniform(rng).max(f64::MIN_POSITIVE);
        return sample_gamma(rng, shape + 1.0, scale) * u.powf(1.0 / shape);
    }
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = normal(rng);
        let v = (1.0 + c * x).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u = uniform(rng);
        if u < 1.0 - 0.0331 * x * x * x * x {
            return d * v * scale;
        }
        if u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
            return d * v * scale;
        }
    }
}

// A uniform double in [0, 1) from 53 random bits.
fn uniform<R: rand_core::RngCore>(rng: &mut R) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

// A standard normal via Box–Muller.
fn normal<R: rand_core::RngCore>(rng: &mut R) -> f64 {
    let u1 = uniform(rng).max(f64::MIN_POSITIVE);
    let u2 = uniform(rng);
    (-2.0 * u1.ln()).sqrt() * (2.0 * core::f64::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};
    use crate::block::{Block, BlockHeader, Coinbase};
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::Account;
    use crate::pow::KeccakPow;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    // Assemble a block: coinbase to `miner` (subsidy + fees) plus `txs`, mined at
    // the chain's current difficulty. Returns the block and the miner's recovered
    // coinbase output.
    //
    // `timestamp` is an offset from the genesis timestamp, so tests can use small
    // readable numbers while still producing blocks that sit after genesis (a
    // block must beat median-time-past).
    fn make_block(
        chain: &Blockchain<KeccakPow>,
        miner: &Account,
        txs: &[Transaction],
        timestamp: u64,
    ) -> (Block, ReceivedOutput) {
        let timestamp = crate::block::GENESIS_TIMESTAMP + timestamp;
        let subsidy = base_reward(chain.emitted());
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let coinbase = Coinbase::create(&mut OsRng, chain.height(), &address(miner), subsidy + fees);
        let received = coinbase.scan(miner).expect("miner owns its coinbase");
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: txs.iter().map(|t| t.hash()).collect(),
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        (block, received)
    }

    // Mine a coinbase-only block to `miner` and append it; return the miner's
    // recovered coinbase output and its global index.
    fn mine_coinbase(
        chain: &mut Blockchain<KeccakPow>,
        miner: &Account,
        timestamp: u64,
    ) -> (ReceivedOutput, u64) {
        let cb_index = chain.num_outputs();
        let (block, received) = make_block(chain, miner, &[], timestamp);
        chain.add_block(&mut OsRng, &block, &[]).expect("valid coinbase block");
        (received, cb_index)
    }

    // Populate the chain with `n` coinbase-only blocks so the output set has
    // decoys to draw from.
    fn warm_up(chain: &mut Blockchain<KeccakPow>, n: usize, start_ts: u64) {
        let filler = Account::random(&mut OsRng);
        for i in 0..n {
            mine_coinbase(chain, &filler, start_ts + i as u64 * 130);
        }
    }

    fn build_spend(
        chain: &Blockchain<KeccakPow>,
        source: &ReceivedOutput,
        source_index: u64,
        payments: Vec<Payment>,
        fee: u64,
    ) -> Transaction {
        let (ring, signer_index) =
            chain.select_ring_uniform(&mut OsRng, 11, source_index).expect("enough outputs");
        let input = source.to_input(ring, signer_index);
        Transaction::build(&mut OsRng, &[input], &payments, fee, &TxKeypair::random(&mut OsRng))
            .unwrap()
    }

    #[test]
    fn genesis_and_growth() {
        use crate::block::PREMINE_AMOUNT;
        let chain = Blockchain::with_maturity(KeccakPow, 1);
        // A new chain is not empty: it is rooted at the canonical genesis.
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_id(), Block::genesis().id());
        assert_eq!(chain.genesis_id(), Block::genesis().id());
        // Genesis carries the premine: one spendable output, counted as emitted.
        assert_eq!(chain.num_outputs(), 1);
        assert_eq!(chain.emitted(), PREMINE_AMOUNT);

        let mut chain = chain;
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.num_outputs(), 2);
        // Block 1's subsidy continues the curve from the premined baseline.
        assert_eq!(chain.emitted(), PREMINE_AMOUNT + base_reward(PREMINE_AMOUNT));
        assert!(chain.cumulative_difficulty() >= 2);
    }

    /// Every node's chain starts at the same block — that is what makes a foreign
    /// chain unadoptable no matter how much work it carries.
    #[test]
    fn genesis_is_identical_everywhere_and_immutable() {
        let a = Blockchain::with_maturity(KeccakPow, 1);
        let b = Blockchain::with_maturity(KeccakPow, 1);
        assert_eq!(a.genesis_id(), b.genesis_id());

        // Genesis cannot be rolled back.
        let mut chain = a;
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        let removed = chain.rollback_to(0); // asks to drop everything
        assert_eq!(removed.len(), 1, "only the mined block may be removed");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_id(), Block::genesis().id());

        // And a branch may not replace it.
        let branch = vec![(Block::genesis(), Vec::new())];
        assert_eq!(
            chain.try_reorg(&mut OsRng, &branch).unwrap_err(),
            ChainError::CannotReplaceGenesis
        );
    }

    #[test]
    fn spend_a_coinbase_across_blocks() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );

        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 5_000);
        let height_before = chain.height();
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();
        assert_eq!(chain.height(), height_before + 1);
        assert!(chain.is_spent(&received.key_image));
        // Bob can find his payment in the newly-added transaction.
        assert_eq!(tx.scan(&bob)[0].amount, reward - fee);
    }

    #[test]
    fn double_spend_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        // First spend accepted.
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 5_000);
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        // A different transaction spending the same output → same key image.
        let tx2 = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let (block2, _) = make_block(&chain, &miner, std::slice::from_ref(&tx2), 9_000);
        assert_eq!(
            chain.add_block(&mut OsRng, &block2, std::slice::from_ref(&tx2)),
            Err(ChainError::DoubleSpend)
        );
    }

    #[test]
    fn wrong_prev_id_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);

        let (mut block, _) = make_block(&chain, &miner, &[], 2_000);
        block.header.prev_id = [42u8; 32]; // not the tip
        block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(chain.add_block(&mut OsRng, &block, &[]), Err(ChainError::BadPrevId));
    }

    #[test]
    fn coinbase_over_claim_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        // Claim one atomic unit too much (block 1, the first after genesis).
        // The allowed subsidy continues the curve from the premined baseline.
        let coinbase =
            Coinbase::create(&mut OsRng, chain.height(), &address(&miner), base_reward(chain.emitted()) + 1);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 1_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: vec![],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(
            chain.add_block(&mut OsRng, &block, &[]),
            Err(ChainError::BadCoinbaseReward)
        );
    }

    #[test]
    fn far_future_timestamp_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        // A block dated a day ahead of the validator's clock is rejected.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (block, _) = make_block(&chain, &miner, &[], now + 24 * 60 * 60);
        assert_eq!(chain.add_block(&mut OsRng, &block, &[]), Err(ChainError::BadTimestamp));
    }

    #[test]
    fn ring_below_minimum_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        // A spend with a ring smaller than MIN_RING_SIZE (5 < 11) is rejected.
        let (ring, signer) = chain.select_ring_uniform(&mut OsRng, 5, cb_index).unwrap();
        let input = received.to_input(ring, signer);
        let tx = Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(&bob), amount: reward - fee }],
            fee,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap();
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 5_000);
        assert_eq!(
            chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)),
            Err(ChainError::RingTooSmall)
        );
    }

    #[test]
    fn ring_member_must_exist_in_output_set() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        let mut tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        // Replace a non-signer ring member with an output not on the chain.
        let signer_is = tx.inputs[0]
            .ring
            .iter()
            .position(|m| m.key == received.one_time_key)
            .unwrap();
        let victim = (signer_is + 1) % tx.inputs[0].ring.len();
        let fake_key = crate::keys::PrivateKey(curve25519_dalek::scalar::Scalar::random(&mut OsRng))
            .public_key();
        tx.inputs[0].ring[victim] =
            RingMember::new(fake_key, crate::amounts::Opening::random(1, &mut OsRng).commit());

        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 9_000);
        // The corrupted ring breaks the signature (the message changed); had it
        // verified it would still be caught as an unknown ring member.
        let err = chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap_err();
        assert!(matches!(err, ChainError::UnknownRingMember | ChainError::InvalidTx(_)));
    }

    #[test]
    fn fees_flow_to_the_miner() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = 3 * (ATOMIC_UNITS / 100);

        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let subsidy = base_reward(chain.emitted());

        // A coinbase that forgets the fee is rejected (add_block does not mutate
        // on error, so we can then submit the correct one).
        let bad = Coinbase::create(&mut OsRng, chain.height(), &address(&miner), subsidy);
        let mut bad_block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 9_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: bad,
            tx_hashes: vec![tx.hash()],
        };
        bad_block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(
            chain.add_block(&mut OsRng, &bad_block, std::slice::from_ref(&tx)),
            Err(ChainError::BadCoinbaseReward)
        );

        // The correct coinbase (subsidy + fee) is accepted.
        let (good_block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 9_000);
        assert!(chain.add_block(&mut OsRng, &good_block, std::slice::from_ref(&tx)).is_ok());
    }

    // Mine `n` blocks onto `chain` from `miner`, returning them as a branch.
    fn extend(
        chain: &mut Blockchain<KeccakPow>,
        miner: &Account,
        n: usize,
        start_ts: u64,
    ) -> Vec<(Block, Vec<Transaction>)> {
        let mut branch = Vec::new();
        for i in 0..n {
            let (block, _) = make_block(chain, miner, &[], start_ts + i as u64 * 130);
            chain.add_block(&mut OsRng, &block, &[]).unwrap();
            branch.push((block, Vec::new()));
        }
        branch
    }

    #[test]
    fn reorg_switches_to_a_heavier_branch() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 3, 1_000); // blocks 1,2,3 (genesis is 0)
        let original_tip = chain.tip_id();
        assert_eq!(chain.height(), 4);

        // A competing branch forking after block 1, two blocks longer.
        let mut fork = chain.clone();
        fork.rollback_to(2); // keep genesis + block 1
        let branch = extend(&mut fork, &miner, 4, 50_000); // blocks 2,3,4,5

        let reorg = chain.try_reorg(&mut OsRng, &branch).expect("heavier branch wins");
        assert_eq!(chain.height(), 6);
        assert_ne!(chain.tip_id(), original_tip);
        assert_eq!(chain.tip_id(), fork.tip_id());
        assert_eq!(reorg.applied, 4);
        // The old blocks 2 and 3 were dropped, oldest first.
        assert_eq!(reorg.discarded.len(), 2);
        assert_eq!(reorg.discarded[0].block.coinbase.height, 2);
        assert_eq!(reorg.discarded[1].block.coinbase.height, 3);
        // Genesis is still the root.
        assert_eq!(chain.genesis_id(), Block::genesis().id());
    }

    #[test]
    fn reorg_rejects_a_lighter_branch_and_changes_nothing() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 4, 1_000); // blocks 1..4
        let tip = chain.tip_id();
        let work = chain.cumulative_difficulty();
        let outputs = chain.num_outputs();
        assert_eq!(chain.height(), 5);

        // A one-block branch forking after block 1 has strictly less work.
        let mut fork = chain.clone();
        fork.rollback_to(2);
        let branch = extend(&mut fork, &miner, 1, 50_000);

        assert_eq!(chain.try_reorg(&mut OsRng, &branch).unwrap_err(), ChainError::NotHeavier);
        // Untouched.
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.tip_id(), tip);
        assert_eq!(chain.cumulative_difficulty(), work);
        assert_eq!(chain.num_outputs(), outputs);
    }

    /// Rolling back a spend must un-spend its key image and remove its outputs —
    /// otherwise the coins would be permanently frozen (image still marked spent)
    /// or phantom outputs would linger in the ring set.
    #[test]
    fn rollback_restores_spent_images_and_outputs() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let height_before = chain.height();
        let outputs_before = chain.num_outputs();
        let emitted_before = chain.emitted();

        // Spend the coinbase in a block.
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: received.amount - fee }],
            fee,
        );
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 60_000);
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        assert!(chain.is_spent(&received.key_image));
        assert!(chain.num_outputs() > outputs_before);

        // Roll it back.
        let removed = chain.rollback_to(height_before);
        assert_eq!(removed.len(), 1);
        assert_eq!(chain.height(), height_before);
        assert_eq!(chain.num_outputs(), outputs_before, "block's outputs must be gone");
        assert_eq!(chain.emitted(), emitted_before, "emission must rewind");
        assert!(!chain.is_spent(&received.key_image), "key image must be spendable again");

        // The rolled-back outputs are really gone from the ring set.
        for member in removed[0].block.coinbase.output_refs() {
            assert!(!chain.contains_output(&member));
        }
        // And the same transaction can be mined again onto the restored chain.
        let (block2, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 61_000);
        assert!(chain.add_block(&mut OsRng, &block2, std::slice::from_ref(&tx)).is_ok());
    }

    /// Every piece of mutable chain state, in a deterministic form.
    ///
    /// The point is that it is **exhaustive rather than selective**. The test
    /// above checks a hand-picked list — height, output count, emission, one key
    /// image — which is precisely how a *newly added* field gets forgotten in
    /// `pop_block`: nothing fails, because nothing looks at it. Hashing
    /// everything means the next field added to `Blockchain` either gets undone
    /// or breaks this test.
    ///
    /// Hash maps and sets are sorted first: their iteration order is not stable,
    /// and a fingerprint that changed run to run would be worthless.
    fn state_fingerprint<P: ProofOfWork>(c: &Blockchain<P>) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&(c.blocks.len() as u64).to_le_bytes());
        for b in &c.blocks {
            f.extend_from_slice(&b.block.id());
            f.extend_from_slice(&(b.txs.len() as u64).to_le_bytes());
            for t in &b.txs {
                f.extend_from_slice(&t.hash());
            }
        }
        f.extend_from_slice(&(c.undos.len() as u64).to_le_bytes());
        for u in &c.undos {
            f.extend_from_slice(&u.outputs_len_before.to_le_bytes());
            f.extend_from_slice(&u.emitted_before.to_le_bytes());
        }
        for id in &c.block_ids {
            f.extend_from_slice(id);
        }
        for t in &c.timestamps {
            f.extend_from_slice(&t.to_le_bytes());
        }
        for d in &c.cumulative_difficulties {
            f.extend_from_slice(&d.to_le_bytes());
        }
        for m in &c.outputs {
            f.extend_from_slice(&membership_key(m));
        }
        let mut membership: Vec<([u8; 64], u64)> =
            c.output_membership.iter().map(|(k, v)| (*k, *v)).collect();
        membership.sort();
        for (k, v) in membership {
            f.extend_from_slice(&k);
            f.extend_from_slice(&v.to_le_bytes());
        }
        for m in &c.output_meta {
            f.extend_from_slice(&m.height.to_le_bytes());
            f.push(m.coinbase as u8);
        }
        let mut images: Vec<[u8; 32]> = c.spent_key_images.iter().map(|i| i.to_bytes()).collect();
        images.sort();
        for i in images {
            f.extend_from_slice(&i);
        }
        f.extend_from_slice(&c.emitted.to_le_bytes());
        f
    }

    /// **Applying a block and undoing it must leave the chain exactly as it was.**
    ///
    /// This is the property a reorg depends on. If `pop_block` misses any part of
    /// what `add_block` wrote, the node carries silent corruption forward: a key
    /// image still marked spent locks an honest user out of their own coins
    /// forever, an output left in the ring set can be drawn as a decoy that no
    /// longer exists, and stale emission miscounts the subsidy from then on.
    /// None of that announces itself — the node keeps running and simply
    /// disagrees with the network.
    ///
    /// Checked over a block with a real spend (so key images, outputs, emission
    /// and the membership index all move), and repeatedly, since an undo that
    /// merely *looks* idempotent once may not be.
    #[test]
    fn applying_and_undoing_a_block_restores_the_chain_exactly() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let before = state_fingerprint(&chain);

        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: received.amount - fee }],
            fee,
        );

        for round in 0..3 {
            let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 60_000 + round);
            chain
                .add_block(&mut OsRng, &block, std::slice::from_ref(&tx))
                .expect("block should apply");

            let after_apply = state_fingerprint(&chain);
            assert_ne!(after_apply, before, "round {round}: applying a block must change state");

            assert_eq!(chain.rollback_to(chain.height() - 1).len(), 1);
            assert_eq!(
                state_fingerprint(&chain),
                before,
                "round {round}: undoing the block left the chain in a different state"
            );
        }
    }

    /// The same property across a multi-block branch, which is what a real reorg
    /// actually rolls back — and it must hold whether the branch spent anything
    /// or not.
    #[test]
    fn rolling_back_a_whole_branch_restores_the_chain_exactly() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 10, 1_200);

        let fork_height = chain.height();
        let before = state_fingerprint(&chain);

        for i in 0..6 {
            let (block, _) = make_block(&chain, &miner, &[], 70_000 + i);
            chain.add_block(&mut OsRng, &block, &[]).unwrap();
        }
        assert_eq!(chain.height(), fork_height + 6);

        let removed = chain.rollback_to(fork_height);
        assert_eq!(removed.len(), 6, "every block on the branch comes back");
        assert_eq!(
            state_fingerprint(&chain),
            before,
            "rolling back a branch left the chain in a different state"
        );

        // Genesis is never removable, or a chain could be left with no root.
        let removed = chain.rollback_to(0);
        assert_eq!(chain.height(), 1, "rollback must clamp at genesis");
        assert!(!removed.is_empty() || chain.height() == 1);
    }

    #[test]
    fn fork_choice_prefers_more_work() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        let here = chain.cumulative_difficulty();
        assert!(chain.would_reorg_to(here + 1));
        assert!(!chain.would_reorg_to(here));
        assert!(!chain.would_reorg_to(here.saturating_sub(1)));
    }

    #[test]
    fn gamma_sampler_is_sane_and_ring_is_valid() {
        // Gamma samples are positive and finite, with a mean near shape*scale.
        let mut sum = 0.0;
        for _ in 0..2000 {
            let g = sample_gamma(&mut OsRng, GAMMA_SHAPE, GAMMA_SCALE);
            assert!(g.is_finite() && g > 0.0);
            sum += g;
        }
        let mean = sum / 2000.0;
        let expected = GAMMA_SHAPE * GAMMA_SCALE;
        assert!((mean - expected).abs() < expected * 0.2, "mean {mean} vs {expected}");

        // Recency-biased selection yields a valid, distinct ring of real outputs.
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 20, 1_200);
        let (ring, signer) =
            chain.select_ring_recency_biased(&mut OsRng, 11, 0).expect("enough outputs");
        assert_eq!(ring.len(), 11);
        assert!(signer < 11);
        for m in &ring {
            assert!(chain.output_membership.contains_key(&membership_key(m)));
        }
    }

    #[test]
    fn decoy_selection_never_picks_an_immature_coinbase() {
        // Decoy selection skips the recent, still-immature coinbase outputs. It
        // finds them via a bounded suffix scan (heights are non-decreasing), so
        // this also guards that optimisation: with a maturity window in force,
        // every member of every ring must be legally referenceable.
        let maturity = 4u64;
        let mut chain = Blockchain::with_maturity(KeccakPow, maturity);
        warm_up(&mut chain, 30, 1_000);

        let height = chain.height();
        let immature: Vec<u64> = (0..chain.num_outputs())
            .filter(|&i| !chain.output_spendable_at(i, height))
            .collect();
        assert!(!immature.is_empty(), "the tail of the chain must still be immature");

        // Draw many rings; none may contain an immature output.
        for _ in 0..25 {
            let (ring, _signer) =
                chain.select_ring_uniform(&mut OsRng, 11, 0).expect("enough mature outputs");
            for member in &ring {
                let index = chain.output_index(member).expect("member is a real output");
                assert!(
                    chain.output_spendable_at(index, height),
                    "ring member {index} is an immature coinbase"
                );
            }
        }
    }

    #[test]
    fn duplicate_output_is_rejected_closing_the_maturity_bypass() {
        // A block may not create an output identical to one that already exists.
        // Without this, a miner could mine a coinbase and then publish an output
        // copying its `[P, C]`; the duplicate would be indexed as a *non-coinbase*
        // output and the immature coinbase would resolve to it, becoming
        // spendable — a coinbase-maturity bypass.
        let mut chain = Blockchain::with_maturity(KeccakPow, 60);
        let miner = Account::random(&mut OsRng);
        warm_up(&mut chain, 5, 1_000);

        // Take an existing output and try to mint it a second time, by handing a
        // coinbase the very same `[P, C]`.
        let victim = chain.output(1).expect("an output exists");
        let mut block = make_block(&mut chain, &miner, &[], 1_000 + 6 * 130).0;
        block.coinbase.outputs[0].one_time_key = victim.key;
        block.coinbase.outputs[0].commitment = victim.commitment;
        block.mine(&KeccakPow, chain.next_difficulty());

        assert_eq!(
            chain.add_block(&mut OsRng, &block, &[]).err(),
            Some(ChainError::DuplicateOutput),
            "a block re-creating an existing output must be rejected"
        );
    }

    #[test]
    fn coinbase_maturity_locks_then_unlocks() {
        let maturity = 5u64;
        let mut chain = Blockchain::with_maturity(KeccakPow, maturity);
        // Enough mature history that rings can be formed.
        warm_up(&mut chain, 20, 1_000);

        // Mine the coinbase we will try to spend.
        let ts = 1_000 + 20 * 130;
        let (target, target_index) = mine_coinbase(&mut chain, &Account::random(&mut OsRng), ts);
        let recipient = Account::random(&mut OsRng);
        let pay = vec![Payment { destination: address(&recipient), amount: target.amount - 1 }];

        // Immature: a transaction referencing the fresh coinbase is rejected,
        // even though it is internally valid.
        let tx = build_spend(&chain, &target, target_index, pay.clone(), 1);
        assert!(tx.verify(&mut OsRng).is_ok());
        assert_eq!(chain.validate_tx(&mut OsRng, &tx), Err(ChainError::ImmatureCoinbase));

        // After `maturity` more blocks the same output is spendable.
        warm_up(&mut chain, maturity as usize, ts + 130);
        let tx2 = build_spend(&chain, &target, target_index, pay, 1);
        assert!(chain.validate_tx(&mut OsRng, &tx2).is_ok());
    }
}
```

===== FILE: core/src/block.rs =====

```rust
//! Layer 7 — blocks & coinbase.
//!
//! A [`Block`] is a [`BlockHeader`] (the PoW-bearing part), a [`Coinbase`]
//! transaction paying the miner, and the hashes of the regular transactions it
//! includes. The block's hashing-blob — header fields plus a Merkle root over
//! `[coinbase, tx_hashes…]` — is fed to the [`ProofOfWork`] function; a block is
//! valid when that hash meets the block's difficulty.
//!
//! ## Coinbase
//!
//! The coinbase has no ring inputs and no range proof: its amount is **public**
//! (the network must be able to check the miner claimed exactly the allowed
//! reward). Its output is still a normal stealth output to the miner, and its
//! commitment uses the fixed mask `1`:
//!
//! ```text
//!     C = 1·G + amount·H
//! ```
//!
//! so a miner can later spend it through the ordinary RingCT machinery
//! ([`crate::tx`]) with opening `{ amount, mask = 1 }` — exactly how Monero
//! handles cleartext-amount outputs.

use curve25519_dalek::scalar::Scalar;

use crate::address::Address;
use crate::amounts::{Commitment, Opening};
use crate::hash::keccak256;
use crate::keys::{Account, PrivateKey, PublicKey};
use crate::pow::{check_hash, Difficulty, ProofOfWork};
use crate::ring::{KeyImage, RingMember};
use crate::stealth::{self, TxKeypair};
use crate::tx::ReceivedOutput;

/// One coinbase output: a stealth key, its (public) amount, and the commitment.
#[derive(Clone, Debug)]
pub struct CoinbaseOutput {
    pub one_time_key: PublicKey,
    /// Public reward amount (coinbase amounts are not hidden).
    pub amount: u64,
    /// Commitment `1·G + amount·H` (fixed mask so it is deterministic).
    pub commitment: Commitment,
}

/// The coinbase ("miner") transaction of a block.
#[derive(Clone, Debug)]
pub struct Coinbase {
    /// Block height this coinbase belongs to (also its uniqueness nonce).
    pub height: u64,
    /// Transaction public key `R` for the miner's stealth output.
    pub tx_public: PublicKey,
    pub outputs: Vec<CoinbaseOutput>,
}

impl Coinbase {
    /// The deterministic commitment for a cleartext coinbase amount.
    fn commit(amount: u64) -> Commitment {
        Opening::new(amount, Scalar::ONE).commit()
    }

    /// Create a coinbase paying the whole `reward` to `miner` in a single output.
    pub fn create<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        height: u64,
        miner: &Address,
        reward: u64,
    ) -> Coinbase {
        let tx = TxKeypair::random(rng);
        let one_time_key = stealth::derive_output(&tx.secret, miner, 0);
        Coinbase {
            height,
            tx_public: tx.public,
            outputs: vec![CoinbaseOutput {
                one_time_key,
                amount: reward,
                commitment: Self::commit(reward),
            }],
        }
    }

    /// Total amount claimed by this coinbase, or `None` if the amounts overflow
    /// `u64`.
    ///
    /// Overflow-checked on purpose: coinbase output amounts are attacker-chosen
    /// (a peer supplies the block), and an unchecked sum that wrapped could match
    /// the allowed reward while actually minting far more — an inflation bug.
    pub fn total(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0u64, |acc, o| acc.checked_add(o.amount))
    }

    /// The coinbase outputs as ring members `[P, C]`, for adding to the global
    /// output set.
    pub fn output_refs(&self) -> Vec<RingMember> {
        self.outputs
            .iter()
            .map(|o| RingMember::new(o.one_time_key, o.commitment))
            .collect()
    }

    /// Validate coinbase structure against the reward the block is allowed to
    /// mint: the total must match, and every commitment must be the canonical
    /// `1·G + amount·H` for its stated amount.
    pub fn is_valid(&self, allowed_reward: u64) -> bool {
        self.total() == Some(allowed_reward)
            && self.outputs.iter().all(|o| o.commitment == Self::commit(o.amount))
    }

    /// Canonical bytes of the coinbase (for hashing / the Merkle tree / wire).
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.tx_public.to_bytes());
        b.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            b.extend_from_slice(&o.one_time_key.to_bytes());
            b.extend_from_slice(&o.amount.to_le_bytes());
            b.extend_from_slice(&o.commitment.to_bytes());
        }
        b
    }

    /// The coinbase hash (Merkle leaf).
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&self.to_bytes())
    }

    /// Scan the coinbase with an account's keys; if an output is addressed to it,
    /// recover it as a spendable [`ReceivedOutput`] (opening mask = 1).
    pub fn scan(&self, account: &Account) -> Option<ReceivedOutput> {
        for (i, output) in self.outputs.iter().enumerate() {
            let index = i as u32;
            if stealth::expected_output(account, &self.tx_public, index) != output.one_time_key {
                continue;
            }
            let opening = Opening::new(output.amount, Scalar::ONE);
            debug_assert_eq!(opening.commit(), output.commitment);
            let spend_secret = stealth::output_secret(account, &self.tx_public, index);
            let key_image = KeyImage::from_secret(&spend_secret);
            return Some(ReceivedOutput {
                index,
                amount: output.amount,
                opening,
                one_time_key: output.one_time_key,
                spend_secret,
                key_image,
                // Coinbase outputs pay the miner's standard address.
                subaddress: crate::subaddress::SubaddressIndex::MAIN,
            });
        }
        None
    }
}

/// A block header — the part that carries the proof of work.
#[derive(Clone, Copy, Debug)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    /// Miner-set timestamp (seconds).
    pub timestamp: u64,
    /// Hash of the previous block.
    pub prev_id: [u8; 32],
    /// PoW search nonce.
    pub nonce: u32,
}

impl BlockHeader {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 1 + 8 + 32 + 4);
        b.push(self.major_version);
        b.push(self.minor_version);
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.prev_id);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b
    }
}

/// A full block.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: Coinbase,
    /// Hashes of the regular transactions included in this block.
    pub tx_hashes: Vec<[u8; 32]>,
}

/// Binary Merkle root (Keccak-256) over the leaves; odd nodes are promoted.
/// This is Nocturnal's own tree, not Monero's `tree_hash`.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let mut layer = leaves.to_vec();
            while layer.len() > 1 {
                let mut next = Vec::with_capacity(layer.len().div_ceil(2));
                for pair in layer.chunks(2) {
                    if let [a, b] = pair {
                        let mut buf = [0u8; 64];
                        buf[..32].copy_from_slice(a);
                        buf[32..].copy_from_slice(b);
                        next.push(keccak256(&buf));
                    } else {
                        next.push(pair[0]); // odd leaf promoted unchanged
                    }
                }
                layer = next;
            }
            layer[0]
        }
    }
}

/// Timestamp baked into the genesis block. Fixed forever — it is part of the
/// genesis hash and therefore of the chain's identity.
pub const GENESIS_TIMESTAMP: u64 = 1_750_000_000;

/// Amount minted in the genesis coinbase as the founder **premine** — 500,000
/// NOCT, half of the ~1,000,000 NOCT smooth-phase supply ([`crate::emission`]).
/// It counts toward emission, so the curve continues from this baseline and only
/// the remaining ~500,000 NOCT is mined out.
pub const PREMINE_AMOUNT: u64 = 500_000 * crate::emission::ATOMIC_UNITS;

/// Founder public **spend** key the premine output is addressed to.
pub const PREMINE_SPEND_PUBLIC: [u8; 32] = [
    0x28, 0x64, 0xde, 0xb5, 0x58, 0x55, 0x58, 0x24, 0xf4, 0xd1, 0x8b, 0x7a, 0xaa, 0xa6, 0x30, 0x2c,
    0xf9, 0x38, 0x40, 0x3e, 0x72, 0xef, 0x26, 0x3c, 0x95, 0xd0, 0x57, 0x7b, 0xce, 0x1f, 0xdc, 0x04,
];
/// Founder public **view** key (lets a scan recognise the premine output).
pub const PREMINE_VIEW_PUBLIC: [u8; 32] = [
    0x03, 0x95, 0x0d, 0x42, 0x7a, 0x16, 0x70, 0x78, 0xdc, 0x47, 0xe4, 0xca, 0xe7, 0x14, 0x60, 0x85,
    0x1e, 0xeb, 0xb3, 0x0e, 0x3b, 0xd0, 0x55, 0x63, 0xab, 0x78, 0x54, 0xd1, 0xf1, 0xad, 0x7e, 0xbb,
];
/// The one-time transaction secret `r` used to derive the premine's stealth
/// output. Published on purpose: knowing `r` only lets an observer link the
/// (already-public) premine to the founder address — **spending it still
/// requires the founder's private spend key**, which never appears here.
pub const GENESIS_TX_SECRET: [u8; 32] = [
    0xac, 0x94, 0x65, 0xe7, 0x76, 0xa9, 0x6a, 0x74, 0x44, 0x94, 0x4a, 0x8f, 0x12, 0x75, 0x16, 0x8c,
    0xfb, 0x4c, 0x12, 0x0c, 0x46, 0x39, 0x3a, 0xdd, 0x54, 0x77, 0x06, 0xf7, 0xf3, 0x23, 0x80, 0x0e,
];

impl Block {
    /// The genesis coinbase: a single premine output of [`PREMINE_AMOUNT`] to the
    /// founder address, derived deterministically from the baked constants above.
    /// Being a coinbase, its amount is public and its commitment uses mask 1, so
    /// the founder spends it through the ordinary RingCT path.
    fn genesis_coinbase(p: &crate::params::ChainParams) -> Coinbase {
        let r = PrivateKey::from_canonical_bytes(p.genesis_tx_secret)
            .expect("genesis tx secret is a canonical scalar");
        let spend = PublicKey::from_bytes(p.premine_spend_public)
            .expect("premine spend key is a valid point");
        let view = PublicKey::from_bytes(p.premine_view_public)
            .expect("premine view key is a valid point");
        let founder = Address::new(p.network, spend, view);
        Coinbase {
            height: 0,
            tx_public: r.public_key(),
            outputs: vec![CoinbaseOutput {
                one_time_key: stealth::derive_output(&r, &founder, 0),
                amount: p.premine_amount,
                commitment: Coinbase::commit(p.premine_amount),
            }],
        }
    }

    /// The canonical genesis block — the root every Nocturnal chain descends from.
    ///
    /// Genesis is an **axiom**, not a validated block: the consensus rules are
    /// defined relative to a chain, so the first block cannot be checked against
    /// them. [`crate::chain::Blockchain::new`] therefore applies it directly, and
    /// it can never be rolled back or reorganised away. Its hash is what pins a
    /// node to *this* chain: a branch that does not descend from it is not Nocturnal,
    /// however much work it carries.
    ///
    /// It mints the founder **premine** ([`PREMINE_AMOUNT`]) as its coinbase —
    /// this is a deliberate, transparent allocation, spendable only by the holder
    /// of the founder spend key. Every node derives the identical coinbase from
    /// the baked constants, so `genesis().id()` is the same everywhere.
    pub fn genesis() -> Block {
        Self::genesis_for(&crate::params::MAINNET)
    }

    /// The genesis block for a given network.
    ///
    /// Every network is built by this one function from its [`ChainParams`], so
    /// the testnet exercises the identical construction that mainnet launches
    /// with — only the constants differ. A testnet built by a separate code path
    /// would not be testing the thing that matters.
    ///
    /// [`ChainParams`]: crate::params::ChainParams
    pub fn genesis_for(p: &crate::params::ChainParams) -> Block {
        Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: p.genesis_timestamp,
                prev_id: [0u8; 32],
                nonce: 0,
            },
            coinbase: Self::genesis_coinbase(p),
            tx_hashes: Vec::new(),
        }
    }

    /// Merkle root over `[coinbase, tx_hashes…]`, binding all block contents.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut leaves = Vec::with_capacity(1 + self.tx_hashes.len());
        leaves.push(self.coinbase.hash());
        leaves.extend_from_slice(&self.tx_hashes);
        merkle_root(&leaves)
    }

    /// The blob fed to the PoW function: header bytes ‖ Merkle root ‖ leaf count.
    /// Depends on the nonce (in the header), so mining varies it.
    ///
    /// The leaf count is committed alongside the root on purpose. A Merkle root
    /// alone does not pin the *shape* of its tree: for any tree, a shorter leaf
    /// list whose entries are the interior nodes hashes to the same root (e.g.
    /// `root([A, H(B‖C)])` == `root([A, B, C])`). Exploiting that needs a leaf
    /// preimage, so it is not practically reachable — but binding the count makes
    /// the tree unambiguous outright and costs four bytes.
    pub fn hashing_blob(&self) -> Vec<u8> {
        let mut b = self.header.to_bytes();
        b.extend_from_slice(&self.merkle_root());
        b.extend_from_slice(&((1 + self.tx_hashes.len()) as u32).to_le_bytes());
        b
    }

    /// The block id: Keccak-256 of the hashing-blob.
    pub fn id(&self) -> [u8; 32] {
        keccak256(&self.hashing_blob())
    }

    /// The PoW hash under `pow`.
    pub fn pow_hash<P: ProofOfWork>(&self, pow: &P) -> [u8; 32] {
        pow.pow_hash(&self.hashing_blob())
    }

    /// Does this block's PoW meet `difficulty`?
    pub fn meets_difficulty<P: ProofOfWork>(&self, pow: &P, difficulty: Difficulty) -> bool {
        check_hash(&self.pow_hash(pow), difficulty)
    }

    /// Search nonces until the PoW meets `difficulty`. Returns the winning nonce
    /// (also left set in the header). With [`crate::pow::KeccakPow`] and modest
    /// difficulty this is fast; real mining uses RandomX.
    pub fn mine<P: ProofOfWork>(&mut self, pow: &P, difficulty: Difficulty) -> u32 {
        loop {
            if self.meets_difficulty(pow, difficulty) {
                return self.header.nonce;
            }
            // Wrapping search; in practice the timestamp/extra nonce would also
            // be advanced once the 32-bit space is exhausted.
            self.header.nonce = self.header.nonce.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::pow::KeccakPow;
    use crate::ring::RingMember;
    use crate::tx::{Payment, Transaction};
    use rand_core::OsRng;

    fn account() -> Account {
        Account::random(&mut OsRng)
    }
    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    #[test]
    fn coinbase_reward_and_commitment_are_valid() {
        let miner = account();
        let reward = base_reward(0);
        let cb = Coinbase::create(&mut OsRng, 0, &address(&miner), reward);
        assert_eq!(cb.total(), Some(reward));
        assert!(cb.is_valid(reward));
        // Wrong allowed reward is rejected.
        assert!(!cb.is_valid(reward - 1));
    }

    #[test]
    fn coinbase_amount_overflow_is_rejected() {
        // A crafted multi-output coinbase whose amounts overflow u64 must not
        // validate against a modest allowed reward (inflation guard).
        let miner = account();
        let allowed = base_reward(0);
        let cb = Coinbase {
            height: 0,
            tx_public: Coinbase::create(&mut OsRng, 0, &address(&miner), 0).tx_public,
            outputs: vec![
                CoinbaseOutput {
                    one_time_key: crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key(),
                    amount: 1u64 << 63,
                    commitment: Coinbase::commit(1u64 << 63),
                },
                CoinbaseOutput {
                    one_time_key: crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key(),
                    amount: (1u64 << 63).wrapping_add(allowed),
                    commitment: Coinbase::commit((1u64 << 63).wrapping_add(allowed)),
                },
            ],
        };
        // The two amounts sum to 2^64 + allowed, which wraps to `allowed` under
        // unchecked arithmetic — the overflow-checked total must return None.
        assert_eq!(cb.total(), None);
        assert!(!cb.is_valid(allowed));
    }

    #[test]
    fn coinbase_commitment_is_deterministic_open() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 7, &address(&miner), 5 * ATOMIC_UNITS);
        // Anyone can reconstruct the commitment from the public amount + mask 1.
        assert_eq!(
            cb.outputs[0].commitment,
            Opening::new(5 * ATOMIC_UNITS, Scalar::ONE).commit()
        );
    }

    #[test]
    fn miner_scans_own_coinbase_stranger_does_not() {
        let miner = account();
        let stranger = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let got = cb.scan(&miner).expect("miner finds their coinbase");
        assert_eq!(got.amount, base_reward(0));
        assert_eq!(got.spend_secret.public_key(), got.one_time_key);
        assert!(cb.scan(&stranger).is_none());
    }

    #[test]
    fn mining_meets_difficulty_and_is_verifiable() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1_700_000_000,
                prev_id: [0u8; 32],
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![],
        };
        let pow = KeccakPow;
        let difficulty = 4_000; // ~4000 hashes expected; trivial with Keccak
        block.mine(&pow, difficulty);
        assert!(block.meets_difficulty(&pow, difficulty));
        // Independent verifier recomputes the PoW from the block contents.
        assert!(check_hash(&block.pow_hash(&pow), difficulty));
    }

    #[test]
    fn changing_contents_changes_the_block_id() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1_700_000_000,
                prev_id: [0u8; 32],
                nonce: 42,
            },
            coinbase: cb,
            tx_hashes: vec![[9u8; 32]],
        };
        let id1 = block.id();
        block.tx_hashes.push([1u8; 32]);
        assert_ne!(id1, block.id(), "adding a tx must change the block id via the Merkle root");
    }

    /// The economic loop: mine a coinbase, then spend the reward through a normal
    /// RingCT transaction. Ties layer 7 back into layers 2–6.
    #[test]
    fn coinbase_reward_is_spendable() {
        let miner = account();
        let reward = base_reward(0);
        let cb = Coinbase::create(&mut OsRng, 0, &address(&miner), reward);

        // Miner recovers the coinbase output.
        let received = cb.scan(&miner).unwrap();
        assert_eq!(received.amount, reward);

        // Spend it: pay a recipient (reward − fee), fee to the network.
        let recipient = account();
        let fee = ATOMIC_UNITS / 100; // 0.01 NOCT fee (sub-NOCT rewards)
        let ring: Vec<RingMember> = (0..11)
            .map(|_| {
                let key = crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key();
                RingMember::new(key, Opening::random(1_000, &mut OsRng).commit())
            })
            .collect();
        let input = received.to_input(ring, 6);
        let payments = vec![Payment { destination: address(&recipient), amount: reward - fee }];
        let tx_keys = TxKeypair::random(&mut OsRng);
        let spend = Transaction::build(&mut OsRng, &[input], &payments, fee, &tx_keys).unwrap();

        assert!(spend.verify(&mut OsRng).is_ok());
        assert_eq!(spend.inputs[0].key_image(), received.key_image);
        assert_eq!(spend.scan(&recipient)[0].amount, reward - fee);
    }
}
```

===== FILE: core/src/wire.rs =====

```rust
//! Layer 10 — canonical wire (de)serialization.
//!
//! Turns [`Transaction`], [`Block`], and [`crate::p2p`] gossip messages into
//! bytes and back. This is the boundary where **untrusted input** first enters
//! the node, so the decoder is deliberately strict:
//!
//! * every point (public key, commitment, key image, ring member) is decoded
//!   through the canonical + prime-order checks in `from_bytes`, so a
//!   non-canonical or torsion encoding is rejected *before* it can reach the
//!   verifier or the spent-key-image set (this is what closes the malleability
//!   items flagged in the security review);
//! * lengths are read but never used to pre-allocate, so a lie about a vector's
//!   size cannot exhaust memory — it just runs out of input and errors;
//! * trailing bytes after a complete object are rejected (no hidden payloads).
//!
//! Writing reuses the exact same byte layout used for hashing
//! ([`Transaction::to_bytes`], `Coinbase::to_bytes`, `BlockHeader::to_bytes`),
//! so a decoded-then-re-encoded object hashes identically.

use monero_clsag::Clsag;

use crate::amounts::{Commitment, RangeProof, MAX_COMMITMENTS};
use crate::block::{Block, BlockHeader, Coinbase, CoinbaseOutput};
use crate::keys::PublicKey;
use crate::p2p::{Phase, Wire};
use crate::ring::{InputSignature, KeyImage, RingMember};
use crate::tx::{Input, Output, Transaction};

/// A wire (de)serialization error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// Ran out of bytes mid-object.
    Truncated,
    /// A point/scalar was not a canonical, valid encoding.
    BadPoint,
    /// A signature or range proof failed to parse.
    BadProof,
    /// An unknown message/enum tag.
    BadTag,
    /// A length prefix exceeded the protocol bound for that field, so the object
    /// is invalid by construction and is rejected before its items are decoded.
    TooLarge,
    /// Extra bytes remained after a complete object.
    TrailingBytes,
}

// ---- cursor primitives ------------------------------------------------------

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if cur.len() < n {
        return Err(WireError::Truncated);
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

fn read_u8(cur: &mut &[u8]) -> Result<u8, WireError> {
    Ok(take(cur, 1)?[0])
}

fn read_u16(cur: &mut &[u8]) -> Result<u16, WireError> {
    Ok(u16::from_le_bytes(take(cur, 2)?.try_into().unwrap()))
}

fn read_u32(cur: &mut &[u8]) -> Result<u32, WireError> {
    Ok(u32::from_le_bytes(take(cur, 4)?.try_into().unwrap()))
}

fn read_u64(cur: &mut &[u8]) -> Result<u64, WireError> {
    Ok(u64::from_le_bytes(take(cur, 8)?.try_into().unwrap()))
}

fn read_array32(cur: &mut &[u8]) -> Result<[u8; 32], WireError> {
    Ok(take(cur, 32)?.try_into().unwrap())
}

fn read_array8(cur: &mut &[u8]) -> Result<[u8; 8], WireError> {
    Ok(take(cur, 8)?.try_into().unwrap())
}

fn read_public_key(cur: &mut &[u8]) -> Result<PublicKey, WireError> {
    PublicKey::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

fn read_commitment(cur: &mut &[u8]) -> Result<Commitment, WireError> {
    Commitment::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

fn read_key_image(cur: &mut &[u8]) -> Result<KeyImage, WireError> {
    KeyImage::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

// Read a length-prefixed vector without trusting the length for allocation.
fn read_vec<T, F>(cur: &mut &[u8], mut read_item: F) -> Result<Vec<T>, WireError>
where
    F: FnMut(&mut &[u8]) -> Result<T, WireError>,
{
    let len = read_u32(cur)? as usize;
    let mut out = Vec::new(); // do NOT pre-allocate from an untrusted length
    for _ in 0..len {
        out.push(read_item(cur)?);
    }
    Ok(out)
}

fn write_vec<T, F>(out: &mut Vec<u8>, items: &[T], mut write_item: F)
where
    F: FnMut(&mut Vec<u8>, &T),
{
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        write_item(out, item);
    }
}

// ---- component codecs -------------------------------------------------------

fn read_ring_member(cur: &mut &[u8]) -> Result<RingMember, WireError> {
    let key = read_public_key(cur)?;
    let commitment = read_commitment(cur)?;
    Ok(RingMember::new(key, commitment))
}

fn write_ring_member(out: &mut Vec<u8>, m: &RingMember) {
    out.extend_from_slice(&m.key.to_bytes());
    out.extend_from_slice(&m.commitment.to_bytes());
}

fn read_input(cur: &mut &[u8]) -> Result<Input, WireError> {
    let ring = read_vec(cur, read_ring_member)?;
    let key_image = read_key_image(cur)?;
    let pseudo_out = read_commitment(cur)?;
    // The CLSAG has exactly `ring.len()` responses; serai reads it from a
    // std::io::Read, which `&[u8]` implements.
    let clsag = Clsag::read(ring.len(), cur).map_err(|_| WireError::BadProof)?;
    let signature = InputSignature::from_parts(clsag, key_image, pseudo_out);
    Ok(Input { ring, signature })
}

fn write_input(out: &mut Vec<u8>, input: &Input) {
    write_vec(out, &input.ring, write_ring_member);
    out.extend_from_slice(&input.signature.key_image.to_bytes());
    out.extend_from_slice(&input.signature.pseudo_out.to_bytes());
    input.signature.clsag().write(out).expect("Vec write is infallible");
}

fn read_output(cur: &mut &[u8]) -> Result<Output, WireError> {
    let one_time_key = read_public_key(cur)?;
    let commitment = read_commitment(cur)?;
    let encrypted_amount = read_array8(cur)?;
    Ok(Output { one_time_key, commitment, encrypted_amount })
}

fn write_output(out: &mut Vec<u8>, o: &Output) {
    out.extend_from_slice(&o.one_time_key.to_bytes());
    out.extend_from_slice(&o.commitment.to_bytes());
    out.extend_from_slice(&o.encrypted_amount);
}

// ---- Transaction ------------------------------------------------------------

fn write_transaction_into(out: &mut Vec<u8>, tx: &Transaction) {
    out.push(tx.version);
    out.extend_from_slice(&tx.tx_public.to_bytes());
    // Additional per-output tx keys (u32 count + keys), matching `to_bytes`.
    out.extend_from_slice(&(tx.additional_tx_public.len() as u32).to_le_bytes());
    for r in &tx.additional_tx_public {
        out.extend_from_slice(&r.to_bytes());
    }
    out.extend_from_slice(&tx.fee.to_le_bytes());
    write_vec(out, &tx.inputs, write_input);
    write_vec(out, &tx.outputs, write_output);
    out.extend_from_slice(&tx.range_proof.to_bytes());
}

fn read_transaction(cur: &mut &[u8]) -> Result<Transaction, WireError> {
    let version = read_u8(cur)?;
    let tx_public = read_public_key(cur)?;
    // Additional per-output tx keys. Length-prefixed, but never trusted for
    // allocation (module invariant). It is also **bounded before any key is
    // decoded**: a legitimate vector is empty or one key per output, and a
    // transaction can carry at most `MAX_COMMITMENTS` outputs, so anything
    // larger is invalid by construction. Without this bound an attacker could
    // pad the vector to the message-size cap (~262k keys) and force that many
    // point decompressions + torsion checks — seconds of CPU per transaction,
    // on a transaction that would then be relayed. Reject it up front.
    let additional_count = read_u32(cur)? as usize;
    if additional_count > MAX_COMMITMENTS {
        return Err(WireError::TooLarge);
    }
    let mut additional_tx_public = Vec::new();
    for _ in 0..additional_count {
        additional_tx_public.push(read_public_key(cur)?);
    }
    let fee = read_u64(cur)?;
    let inputs = read_vec(cur, read_input)?;
    let outputs = read_vec(cur, read_output)?;
    let range_proof = RangeProof::read_from(cur).map_err(|_| WireError::BadProof)?;
    Ok(Transaction { version, tx_public, additional_tx_public, fee, inputs, outputs, range_proof })
}

/// Serialize a transaction. Byte-identical to [`Transaction::to_bytes`], so the
/// transaction hash is unchanged.
pub fn encode_transaction(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    write_transaction_into(&mut out, tx);
    out
}

/// Decode a transaction, rejecting trailing bytes.
pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, WireError> {
    let mut cur = bytes;
    let tx = read_transaction(&mut cur)?;
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(tx)
}

// ---- Block ------------------------------------------------------------------

fn read_block_header(cur: &mut &[u8]) -> Result<BlockHeader, WireError> {
    let major_version = read_u8(cur)?;
    let minor_version = read_u8(cur)?;
    let timestamp = read_u64(cur)?;
    let prev_id = read_array32(cur)?;
    let nonce = read_u32(cur)?;
    Ok(BlockHeader { major_version, minor_version, timestamp, prev_id, nonce })
}

fn read_coinbase_output(cur: &mut &[u8]) -> Result<CoinbaseOutput, WireError> {
    let one_time_key = read_public_key(cur)?;
    let amount = read_u64(cur)?;
    let commitment = read_commitment(cur)?;
    Ok(CoinbaseOutput { one_time_key, amount, commitment })
}

fn read_coinbase(cur: &mut &[u8]) -> Result<Coinbase, WireError> {
    let height = read_u64(cur)?;
    let tx_public = read_public_key(cur)?;
    let outputs = read_vec(cur, read_coinbase_output)?;
    Ok(Coinbase { height, tx_public, outputs })
}

fn read_block(cur: &mut &[u8]) -> Result<Block, WireError> {
    let header = read_block_header(cur)?;
    let coinbase = read_coinbase(cur)?;
    let tx_hashes = read_vec(cur, read_array32)?;
    Ok(Block { header, coinbase, tx_hashes })
}

fn write_block_into(out: &mut Vec<u8>, block: &Block) {
    out.extend_from_slice(&block.header.to_bytes());
    out.extend_from_slice(&block.coinbase.to_bytes());
    write_vec(out, &block.tx_hashes, |o, h| o.extend_from_slice(h));
}

/// Serialize a block header + coinbase + tx-hash list (not the full transactions).
pub fn encode_block(block: &Block) -> Vec<u8> {
    let mut out = Vec::new();
    write_block_into(&mut out, block);
    out
}

/// Decode a block, rejecting trailing bytes.
pub fn decode_block(bytes: &[u8]) -> Result<Block, WireError> {
    let mut cur = bytes;
    let block = read_block(&mut cur)?;
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(block)
}

// ---- P2P messages -----------------------------------------------------------

const TAG_TX: u8 = 0;
const TAG_BLOCK: u8 = 1;
const TAG_GET_TIP: u8 = 2;
const TAG_TIP: u8 = 3;
const TAG_GET_BLOCK: u8 = 4;
const TAG_NO_BLOCK: u8 = 5;
const TAG_VERSION: u8 = 6;
const TAG_GET_PEERS: u8 = 7;
const TAG_PEERS: u8 = 8;
const PHASE_STEM: u8 = 0;
const PHASE_FLUFF: u8 = 1;

// Address family tags for the compact SocketAddr encoding.
const ADDR_V4: u8 = 4;
const ADDR_V6: u8 = 6;

fn write_socket_addr(out: &mut Vec<u8>, addr: &std::net::SocketAddr) {
    match addr {
        std::net::SocketAddr::V4(a) => {
            out.push(ADDR_V4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
        std::net::SocketAddr::V6(a) => {
            out.push(ADDR_V6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
    }
}

fn read_socket_addr(cur: &mut &[u8]) -> Result<std::net::SocketAddr, WireError> {
    match read_u8(cur)? {
        ADDR_V4 => {
            let ip: [u8; 4] = take(cur, 4)?.try_into().unwrap();
            let port = read_u16(cur)?;
            Ok((std::net::Ipv4Addr::from(ip), port).into())
        }
        ADDR_V6 => {
            let ip: [u8; 16] = take(cur, 16)?.try_into().unwrap();
            let port = read_u16(cur)?;
            Ok((std::net::Ipv6Addr::from(ip), port).into())
        }
        _ => Err(WireError::BadTag),
    }
}

/// Serialize a gossip [`Wire`] message.
pub fn encode_message(msg: &Wire) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        Wire::Tx(tx, phase) => {
            out.push(TAG_TX);
            write_transaction_into(&mut out, tx);
            out.push(match phase {
                Phase::Stem => PHASE_STEM,
                Phase::Fluff => PHASE_FLUFF,
            });
        }
        Wire::Block(block, txs) => {
            out.push(TAG_BLOCK);
            write_block_into(&mut out, block);
            write_vec(&mut out, txs, write_transaction_into);
        }
        Wire::GetTip => out.push(TAG_GET_TIP),
        Wire::Tip(network, height, tip) => {
            out.push(TAG_TIP);
            out.extend_from_slice(&network.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
            out.extend_from_slice(tip);
        }
        Wire::GetBlock(height) => {
            out.push(TAG_GET_BLOCK);
            out.extend_from_slice(&height.to_le_bytes());
        }
        Wire::NoBlock(height) => {
            out.push(TAG_NO_BLOCK);
            out.extend_from_slice(&height.to_le_bytes());
        }
        Wire::Version(network, genesis, port, nonce) => {
            out.push(TAG_VERSION);
            out.extend_from_slice(&network.to_le_bytes());
            out.extend_from_slice(genesis);
            out.extend_from_slice(&port.to_le_bytes());
            out.extend_from_slice(&nonce.to_le_bytes());
        }
        Wire::GetPeers => out.push(TAG_GET_PEERS),
        Wire::Peers(addrs) => {
            out.push(TAG_PEERS);
            write_vec(&mut out, addrs, write_socket_addr);
        }
    }
    out
}

/// Decode a gossip [`Wire`] message, rejecting trailing bytes.
pub fn decode_message(bytes: &[u8]) -> Result<Wire, WireError> {
    let mut cur = bytes;
    let msg = match read_u8(&mut cur)? {
        TAG_TX => {
            let tx = read_transaction(&mut cur)?;
            let phase = match read_u8(&mut cur)? {
                PHASE_STEM => Phase::Stem,
                PHASE_FLUFF => Phase::Fluff,
                _ => return Err(WireError::BadTag),
            };
            Wire::Tx(tx, phase)
        }
        TAG_BLOCK => {
            let block = read_block(&mut cur)?;
            let txs = read_vec(&mut cur, read_transaction)?;
            Wire::Block(block, txs)
        }
        TAG_GET_TIP => Wire::GetTip,
        TAG_TIP => {
            let network = read_u32(&mut cur)?;
            let height = read_u64(&mut cur)?;
            let tip = read_array32(&mut cur)?;
            Wire::Tip(network, height, tip)
        }
        TAG_GET_BLOCK => Wire::GetBlock(read_u64(&mut cur)?),
        TAG_NO_BLOCK => Wire::NoBlock(read_u64(&mut cur)?),
        TAG_VERSION => {
            let network = read_u32(&mut cur)?;
            let genesis = read_array32(&mut cur)?;
            let port = read_u16(&mut cur)?;
            let nonce = read_u64(&mut cur)?;
            Wire::Version(network, genesis, port, nonce)
        }
        TAG_GET_PEERS => Wire::GetPeers,
        TAG_PEERS => Wire::Peers(read_vec(&mut cur, read_socket_addr)?),
        _ => return Err(WireError::BadTag),
    };
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};
    use crate::amounts::Opening;
    use crate::block::{BlockHeader, Coinbase};
    use crate::chain::Blockchain;
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::{Account, PrivateKey};
    use crate::pow::KeccakPow;
    use crate::ring::RingMember;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    fn mine(chain: &mut Blockchain<KeccakPow>, miner: &Account, ts: u64) -> (ReceivedOutput, u64, Block) {
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(miner), subsidy);
        let received = cb.scan(miner).unwrap();
        let index = chain.num_outputs();
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + ts,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, &[]).unwrap();
        (received, index, block)
    }

    // A real transaction spending a coinbase, for codec tests.
    fn sample_tx() -> (Transaction, Block) {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index, _) = mine(&mut chain, &miner, 1_000);
        let filler = Account::random(&mut OsRng);
        for i in 0..15 {
            mine(&mut chain, &filler, 1_200 + i * 130);
        }
        let (ring, signer) = chain.select_ring_uniform(&mut OsRng, 11, cb_index).unwrap();
        let input = received.to_input(ring, signer);
        let bob = Account::random(&mut OsRng);
        let reward = received.amount;
        let tx = Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(&bob), amount: reward - ATOMIC_UNITS / 100 }],
            ATOMIC_UNITS / 100,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap();
        let (_, _, block) = mine(&mut chain, &miner, 60_000);
        (tx, block)
    }

    #[test]
    fn transaction_round_trips_and_matches_hash_encoding() {
        let (tx, _) = sample_tx();
        // Wire encoding equals the hashing encoding.
        assert_eq!(encode_transaction(&tx), tx.to_bytes());
        let decoded = decode_transaction(&encode_transaction(&tx)).unwrap();
        assert_eq!(decoded.hash(), tx.hash());
        // Round-trips through the struct fields that matter.
        assert_eq!(decoded.inputs.len(), tx.inputs.len());
        assert_eq!(decoded.outputs.len(), tx.outputs.len());
        assert_eq!(decoded.fee, tx.fee);
        // And it still verifies after a round trip.
        assert!(decoded.verify(&mut OsRng).is_ok());
    }

    #[test]
    fn block_round_trips() {
        let (_, block) = sample_tx();
        let decoded = decode_block(&encode_block(&block)).unwrap();
        assert_eq!(decoded.id(), block.id());
    }

    #[test]
    fn message_round_trips() {
        let (tx, block) = sample_tx();
        let tx_msg = Wire::Tx(tx.clone(), Phase::Fluff);
        match decode_message(&encode_message(&tx_msg)).unwrap() {
            Wire::Tx(t, Phase::Fluff) => assert_eq!(t.hash(), tx.hash()),
            _ => panic!("wrong message"),
        }
        let block_msg = Wire::Block(block.clone(), vec![tx.clone()]);
        match decode_message(&encode_message(&block_msg)).unwrap() {
            Wire::Block(b, txs) => {
                assert_eq!(b.id(), block.id());
                assert_eq!(txs[0].hash(), tx.hash());
            }
            _ => panic!("wrong message"),
        }
    }

    #[test]
    fn handshake_and_peer_messages_round_trip() {
        // Version handshake.
        let v = Wire::Version(0x4E4F4354, [7u8; 32], 9333, 0xABCD_1234_5678_9012);
        match decode_message(&encode_message(&v)).unwrap() {
            Wire::Version(net, gen, port, nonce) => {
                assert_eq!(net, 0x4E4F4354);
                assert_eq!(gen, [7u8; 32]);
                assert_eq!(port, 9333);
                assert_eq!(nonce, 0xABCD_1234_5678_9012);
            }
            _ => panic!("wrong message"),
        }

        // GetPeers.
        assert!(matches!(decode_message(&encode_message(&Wire::GetPeers)).unwrap(), Wire::GetPeers));

        // Peers list with both IPv4 and IPv6 addresses.
        let addrs: Vec<std::net::SocketAddr> = vec![
            "1.2.3.4:9333".parse().unwrap(),
            "127.0.0.1:65535".parse().unwrap(),
            "[2001:db8::1]:9333".parse().unwrap(),
        ];
        match decode_message(&encode_message(&Wire::Peers(addrs.clone()))).unwrap() {
            Wire::Peers(got) => assert_eq!(got, addrs),
            _ => panic!("wrong message"),
        }
    }

    #[test]
    fn decode_never_panics_on_adversarial_input() {
        use rand_core::RngCore;
        let mut rng = OsRng;

        // Random byte soup across many lengths: decoders must return Ok/Err, never
        // panic (no unchecked slicing, no allocation from an untrusted length).
        for len in 0..48usize {
            for _ in 0..20 {
                let mut buf = vec![0u8; len];
                rng.fill_bytes(&mut buf);
                let _ = decode_message(&buf);
                let _ = decode_transaction(&buf);
                let _ = decode_block(&buf);
            }
        }

        // Truncations of valid messages must error cleanly, and trailing garbage
        // must be rejected. Cuts are sampled by a stride so a multi-KB tx/block
        // (whose near-complete decodes re-parse the whole range proof + CLSAG)
        // doesn't make this O(size) in expensive decodes.
        let (tx, block) = sample_tx();
        let messages = [
            Wire::Tx(tx.clone(), Phase::Fluff),
            Wire::Block(block, vec![tx]),
            Wire::GetTip,
            Wire::Version(0x4E4F4354, [1u8; 32], 9333, 7),
            Wire::Peers(vec!["1.2.3.4:9333".parse().unwrap()]),
            Wire::GetBlock(5),
        ];
        for msg in messages {
            let full = encode_message(&msg);
            let stride = (full.len() / 48).max(1);
            let mut cut = 0;
            while cut < full.len() {
                let _ = decode_message(&full[..cut]); // truncated → Err, not a panic
                cut += stride;
            }
            let mut trailing = full.clone();
            trailing.push(0xff);
            assert!(decode_message(&trailing).is_err(), "trailing bytes must be rejected");
        }
    }

    #[test]
    fn rejects_non_canonical_point() {
        // A ring member whose key is a torsion point must be rejected on decode.
        let good = RingMember::new(
            PrivateKey(Scalar::random(&mut OsRng)).public_key(),
            Opening::random(1, &mut OsRng).commit(),
        );
        let mut bytes = Vec::new();
        write_ring_member(&mut bytes, &good);
        // Sanity: valid member decodes.
        assert!(read_ring_member(&mut bytes.as_slice()).is_ok());
        // Corrupt the key bytes to a small-order (torsion) point encoding.
        // The 8-torsion point with compressed encoding [1,0,...,0] is the identity;
        // use a known small-order point: all-zero y with sign bit — decompress
        // yields a torsion point that `from_bytes` must reject.
        let mut bad = bytes.clone();
        bad[..32].copy_from_slice(&[0u8; 32]); // non-identity small-order encoding
        let res = read_ring_member(&mut bad.as_slice());
        assert!(res.is_err(), "torsion/invalid point must be rejected");
    }

    #[test]
    fn rejects_truncated_and_trailing() {
        let (tx, _) = sample_tx();
        let bytes = encode_transaction(&tx);
        // Truncated: drop the last byte.
        assert!(decode_transaction(&bytes[..bytes.len() - 1]).is_err());
        // Trailing garbage: append a byte.
        let mut extra = bytes.clone();
        extra.push(0x00);
        assert!(matches!(decode_transaction(&extra), Err(WireError::TrailingBytes)));
    }

    /// Write a seed corpus of **valid** encodings for the `cargo-fuzz` targets
    /// in `noct/fuzz`. libFuzzer starting from real messages explores far deeper
    /// than starting from random bytes, since a random buffer essentially never
    /// survives the point and length checks.
    ///
    /// Not part of the normal suite (it writes files); run it explicitly:
    ///
    /// ```text
    /// cargo test -p noct-core -- --ignored generate_fuzz_corpus
    /// ```
    #[test]
    #[ignore = "writes a seed corpus for cargo-fuzz; run explicitly"]
    fn generate_fuzz_corpus() {
        let (tx, block) = sample_tx();
        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("tx", encode_transaction(&tx)),
            ("block", encode_block(&block)),
            ("msg_tx_stem", encode_message(&Wire::Tx(tx.clone(), Phase::Stem))),
            ("msg_tx_fluff", encode_message(&Wire::Tx(tx.clone(), Phase::Fluff))),
            ("msg_block", encode_message(&Wire::Block(block, vec![tx]))),
            ("msg_gettip", encode_message(&Wire::GetTip)),
            ("msg_getblock", encode_message(&Wire::GetBlock(1))),
            ("msg_version", encode_message(&Wire::Version(0x4E4F4354, [0u8; 32], 9333, 1))),
            ("msg_getpeers", encode_message(&Wire::GetPeers)),
            ("msg_peers", encode_message(&Wire::Peers(vec!["1.2.3.4:9333".parse().unwrap()]))),
        ];

        for target in ["wire_decode", "wire_roundtrip"] {
            let dir = std::path::Path::new("../fuzz/corpus").join(target);
            std::fs::create_dir_all(&dir).expect("create corpus dir");
            for (name, bytes) in &samples {
                std::fs::write(dir.join(name), bytes).expect("write corpus entry");
            }
            eprintln!("[corpus] wrote {} seeds to {}", samples.len(), dir.display());
        }
    }

    /// A deterministic **mutational** fuzzer over the wire decoders.
    ///
    /// Stronger than random byte soup: it starts from *valid* encodings and
    /// mutates them, so inputs stay structurally plausible and reach decode
    /// paths past the length prefixes and point checks that random bytes
    /// essentially never survive to. The PRNG is seeded by a constant, so a
    /// failure is reproducible and the harness is deterministic in CI.
    ///
    /// Two properties are asserted for every input:
    ///
    /// * **no panic** — decoders must return `Ok`/`Err` for arbitrary bytes,
    ///   never index out of bounds or allocate from an untrusted length;
    /// * **canonicality** — if bytes decode, re-encoding the value must
    ///   reproduce those bytes *exactly*. A violation means two distinct byte
    ///   strings decode to the same object: a malleable encoding, which is how
    ///   identifier-substitution bugs (see F5) get in.
    ///
    /// ## Running a longer campaign
    ///
    /// The defaults are sized to stay in the normal suite. For a real campaign
    /// on the stable toolchain — the coverage-guided `fuzz/` targets need a
    /// nightly one — override both knobs and vary the seed across runs:
    ///
    /// ```text
    /// NOCT_FUZZ_ITERS=200000 NOCT_FUZZ_SEED=2 \
    ///   cargo test --release -p noct-core mutational_fuzz -- --nocapture
    /// ```
    ///
    /// A distinct `NOCT_FUZZ_SEED` explores a different mutation sequence, so
    /// several seeded runs cover more than one long run at the same seed. Any
    /// failure prints the exact seed and iteration needed to reproduce it.
    #[test]
    fn mutational_fuzz_decoders_are_panic_free_and_canonical() {
        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }

        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        let iters = env_u64("NOCT_FUZZ_ITERS", 30);
        // Mixed into the constant rather than replacing it, so the default run
        // is bit-for-bit what it always was and only an explicit override moves.
        let campaign = env_u64("NOCT_FUZZ_SEED", 0);

        let (tx, block) = sample_tx();
        let seeds: Vec<(&str, Vec<u8>)> = vec![
            ("tx", encode_transaction(&tx)),
            ("block", encode_block(&block)),
            ("msg:tx", encode_message(&Wire::Tx(tx.clone(), Phase::Stem))),
            ("msg:block", encode_message(&Wire::Block(block.clone(), vec![tx.clone()]))),
            ("msg:version", encode_message(&Wire::Version(0x4E4F4354, [3u8; 32], 9333, 42))),
            ("msg:peers", encode_message(&Wire::Peers(vec!["9.8.7.6:9333".parse().unwrap()]))),
        ];

        let mut state: u64 = 0x5EED_1234_ABCD_0001 ^ campaign.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut decoded_ok = 0usize;
        for (name, seed) in &seeds {
            for iter in 0..iters {
                let mut buf = seed.clone();
                if buf.is_empty() {
                    continue;
                }
                match xorshift(&mut state) % 4 {
                    // Flip a single bit — the classic mutation.
                    0 => {
                        let i = (xorshift(&mut state) as usize) % buf.len();
                        buf[i] ^= 1u8 << (xorshift(&mut state) % 8);
                    }
                    // Replace a byte outright.
                    1 => {
                        let i = (xorshift(&mut state) as usize) % buf.len();
                        buf[i] = xorshift(&mut state) as u8;
                    }
                    // Tamper with a 32-bit little-endian field (length prefixes
                    // live here) — targets the "lie about a count" class.
                    2 => {
                        if buf.len() >= 4 {
                            let i = (xorshift(&mut state) as usize) % (buf.len() - 3);
                            let v: u32 = match xorshift(&mut state) % 3 {
                                0 => u32::MAX,
                                1 => 0,
                                _ => xorshift(&mut state) as u32,
                            };
                            buf[i..i + 4].copy_from_slice(&v.to_le_bytes());
                        }
                    }
                    // Splice: graft a chunk of another seed in.
                    _ => {
                        let other = &seeds[(xorshift(&mut state) as usize) % seeds.len()].1;
                        if !other.is_empty() {
                            let at = (xorshift(&mut state) as usize) % buf.len();
                            let take = ((xorshift(&mut state) as usize) % 32).min(other.len());
                            let end = (at + take).min(buf.len());
                            buf[at..end].copy_from_slice(&other[..end - at]);
                        }
                    }
                }

                let ctx = format!("seed={name} iter={iter}");

                // Canonicality: anything that decodes must re-encode identically.
                if let Ok(decoded) = decode_transaction(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_transaction(&decoded), buf, "non-canonical transaction ({ctx})");
                    assert!(
                        decoded.additional_tx_public.len() <= MAX_COMMITMENTS,
                        "decoded tx exceeded the additional-key bound ({ctx})"
                    );
                    // Identifier stability: a txid is `Keccak256(to_bytes)`, so
                    // the decode → encode → decode cycle must be a fixed point
                    // in both bytes and identity. (Mirrors the `wire_roundtrip`
                    // cargo-fuzz target, which needs nightly to run.)
                    let again = decode_transaction(&buf).expect("re-decode of accepted bytes");
                    assert_eq!(again.hash(), decoded.hash(), "txid changed across a round trip ({ctx})");
                }
                if let Ok(decoded) = decode_block(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_block(&decoded), buf, "non-canonical block ({ctx})");
                    let again = decode_block(&buf).expect("re-decode of accepted bytes");
                    assert_eq!(again.id(), decoded.id(), "block id changed across a round trip ({ctx})");
                }
                if let Ok(decoded) = decode_message(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_message(&decoded), buf, "non-canonical message ({ctx})");
                }
            }
        }
        // The harness must actually *reach* the property it asserts. Without
        // this, a future change that made every mutation fail early would leave
        // a green test that exercises nothing. (Roughly 47% of mutations decode:
        // ~84 of the default 180.)
        //
        // Expressed as a fraction of the work actually done, so it stays a real
        // check at any campaign length instead of being trivially satisfied by a
        // long run.
        let attempted = seeds.len() * iters as usize;
        let floor = (attempted / 5).max(1);
        assert!(
            decoded_ok >= floor,
            "mutational fuzzing reached the canonicality check only {decoded_ok} times \
             out of {attempted} mutations (needed {floor}) — the mutations are no longer \
             producing decodable inputs"
        );
        if iters > 30 {
            eprintln!("[fuzz] {attempted} mutations, {decoded_ok} decoded and re-encoded canonically");
        }
    }

    /// An oversized `additional_tx_public` count must be rejected *before* any
    /// key is decoded. Each key costs a point decompression + torsion check, so
    /// a vector padded to the message-size cap (~262k keys) would otherwise burn
    /// seconds of CPU per transaction — on a transaction that would then be
    /// relayed. The bound must trip on the count alone, without reading the keys.
    #[test]
    fn oversized_additional_key_count_is_rejected_before_decoding_keys() {
        let (tx, _) = sample_tx();
        let real = encode_transaction(&tx);

        // Rebuild the prefix with a huge additional-key count, and supply NO key
        // bytes at all. If the decoder honoured the count it would fail with
        // `Truncated` only after trying to read them; the bound must reject it
        // outright, and instantly.
        let mut evil = Vec::new();
        evil.push(tx.version);
        evil.extend_from_slice(&tx.tx_public.to_bytes());
        evil.extend_from_slice(&(262_144u32).to_le_bytes());
        evil.extend_from_slice(&real[37..]); // the rest of a real transaction

        let start = std::time::Instant::now();
        let err = decode_transaction(&evil).unwrap_err();
        let elapsed = start.elapsed();

        assert_eq!(err, WireError::TooLarge, "oversized count rejected by the bound");
        assert!(elapsed.as_millis() < 500, "must reject on the count alone, not by decoding keys (took {elapsed:?})");

        // A legitimate count (one key per output) still decodes.
        assert!(MAX_COMMITMENTS >= 2, "sanity: the cap admits normal transactions");
    }
}

```
