//! Layer 5 — ring signatures: CLSAG + key images (double-spend prevention).
//!
//! To spend an output the sender proves, in zero knowledge, that they own **one**
//! member of a *ring* of plausible outputs — without revealing which one. This is
//! CryptoNote sender ambiguity. Noct uses **CLSAG** (Concise Linkable Spontaneous
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
