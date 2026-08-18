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
//! means an auditor can diff Noct against Monero instead of reviewing novel
//! cryptography.
//!
//! ### Dependency provenance
//!
//! These are the **first-party** crates from `monero-oxide`, the project serai's
//! Monero code was spun out into. Noct previously built against a third-party
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
    /// does not leak into Noct's public API (used by [`crate::ring`]).
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
