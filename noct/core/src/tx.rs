//! Layer 6 — transaction assembly & verification.
//!
//! This layer composes everything below it into a single [`Transaction`] with one
//! [`Transaction::verify`]. A Noct transaction is RingCT-shaped:
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
