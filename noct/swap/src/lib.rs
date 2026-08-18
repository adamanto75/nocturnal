//! Cross-group (ed25519 ⇄ secp256k1) DLEQ for ETH⇄NOCT atomic swaps.
//!
//! ## ⚠ EXPERIMENTAL crypto
//!
//! This uses serai's `dleq` cross-group proof under its `experimental` feature —
//! **unaudited, with no formal proofs** (only the single-curve part of `dleq` was
//! audited). It is genuinely frontier crypto; every available cross-curve DLEQ
//! (comit, secp256kfun, this) is a "proof of concept". Fine for a **pre-testnet
//! prototype**, but it MUST be revisited — a formal review/audit, or a proven
//! alternative — before any mainnet swap holds real value. See
//! `docs/eth-atomic-swap.md`.
//!
//! ## What it does
//!
//! A proof binds one secret scalar `s` to BOTH `s·G` on ed25519 (a swap party's
//! NOCT joint-account spend half `S_i`, see `noct_wallet::joint`) and `s·G` on
//! secp256k1 (the value the Ethereum swap contract verifies). Without this, a
//! party could commit to *different* secrets on the two chains and steal. The
//! scalar is generated from a seed and is bounded to fit both scalar fields (the
//! smaller being ed25519's, ~2^252).

pub mod eth;
pub mod protocol;

use core::ops::Deref;

use blake2::{Blake2b512, Digest};
use dalek_ff_group::EdwardsPoint;
use dleq::cross_group::{DLEqError, EfficientLinearDLEq, Generators};
use group::{Group, GroupEncoding};
use hex_literal::hex;
use k256::ProjectivePoint;
use rand_core::{CryptoRng, RngCore};
use transcript::{RecommendedTranscript, Transcript};
use zeroize::Zeroizing;

/// The cross-group proof we use: the batch-verifiable ("efficient") variant,
/// binding a scalar across secp256k1 (`G0`) and ed25519 (`G1`).
pub type CrossGroupProof = EfficientLinearDLEq<ProjectivePoint, EdwardsPoint>;

/// Fiat–Shamir transcript label. Both parties derive the identical transcript.
fn transcript() -> RecommendedTranscript {
    RecommendedTranscript::new(b"noct/eth-atomic-swap/dleq/v1")
}

/// The agreed nothing-up-my-sleeve generators for each curve — a primary
/// (the curve's standard generator) and a secondary of unknown relative discrete
/// log. Both swap parties MUST use the identical pair.
///
/// These are serai's reference alt generators; a production protocol should fix
/// its own and document their derivation.
fn generators() -> (Generators<ProjectivePoint>, Generators<EdwardsPoint>) {
    (
        Generators::new(
            ProjectivePoint::GENERATOR,
            ProjectivePoint::from_bytes(
                &hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into(),
            )
            .unwrap(),
        )
        .unwrap(),
        Generators::new(
            EdwardsPoint::generator(),
            EdwardsPoint::from_bytes(&hex!(
                "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
            ))
            .unwrap(),
        )
        .unwrap(),
    )
}

/// A freshly-proven cross-group secret held by one swap party.
pub struct SharedSecret {
    /// The proof to hand the counterparty (serialize with [`Self::proof_bytes`]).
    pub proof: CrossGroupProof,
    /// `s` as an ed25519 scalar — this party's NOCT joint-account spend half.
    pub ed25519_scalar: Zeroizing<dalek_ff_group::Scalar>,
    /// `s` as a secp256k1 scalar — for the Ethereum side of the swap.
    pub secp256k1_scalar: Zeroizing<k256::Scalar>,
}

impl SharedSecret {
    /// Generate a fresh shared scalar from `seed` (should be ≥32 random bytes) and
    /// prove its ed25519 and secp256k1 public keys share it.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, seed: &[u8]) -> Self {
        let (proof, keys) = CrossGroupProof::prove(
            rng,
            &mut transcript(),
            generators(),
            Blake2b512::new().chain_update(seed),
        );
        SharedSecret { proof, secp256k1_scalar: keys.0, ed25519_scalar: keys.1 }
    }

    /// The ed25519 public key `s·G` as 32 canonical bytes — decodes directly with
    /// `noct_core::keys::PublicKey::from_bytes` as this party's joint spend half.
    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        (EdwardsPoint::generator() * *self.ed25519_scalar.deref()).to_bytes()
    }

    /// The ed25519 secret `s` as 32 canonical little-endian bytes — decodes with
    /// `noct_core::keys::PrivateKey::from_canonical_bytes` as the joint spend half
    /// secret (revealed only when the swap settles).
    pub fn ed25519_secret_bytes(&self) -> [u8; 32] {
        use ff::PrimeField;
        let repr = self.ed25519_scalar.deref().to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_ref());
        out
    }

    /// Serialize the proof to send to the counterparty.
    pub fn proof_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.proof.write(&mut buf).expect("writing to a Vec cannot fail");
        buf
    }
}

/// Parse a counterparty's serialized proof.
pub fn read_proof(bytes: &[u8]) -> std::io::Result<CrossGroupProof> {
    CrossGroupProof::read::<&[u8]>(&mut &bytes[..])
}

/// Verify a counterparty's proof, returning the two public keys it binds:
/// `(secp256k1 point, ed25519 point)`. The ed25519 point is their NOCT joint
/// spend half `S_i`; the secp256k1 point is what the Ethereum contract checks.
pub fn verify<R: RngCore + CryptoRng>(
    rng: &mut R,
    proof: &CrossGroupProof,
) -> Result<(ProjectivePoint, EdwardsPoint), DLEqError> {
    proof.verify(rng, &mut transcript(), generators())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn prove_and_verify_bind_the_same_scalar_across_both_curves() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = SharedSecret::prove(&mut OsRng, &seed);

        // Verify returns the two public keys the proof binds.
        let (secp_pub, ed_pub) = verify(&mut OsRng, &secret.proof).expect("valid proof");

        // Each public key really is scalar·G on its curve.
        let (g_secp, g_ed) = generators();
        assert_eq!(g_secp.primary * *secret.secp256k1_scalar.deref(), secp_pub);
        assert_eq!(g_ed.primary * *secret.ed25519_scalar.deref(), ed_pub);

        // The ed25519 public bytes decode to that same point (usable as a NOCT
        // joint spend half), and the secret bytes reproduce it.
        assert_eq!(EdwardsPoint::from_bytes(&secret.ed25519_public_bytes()).unwrap(), ed_pub);
        use ff::PrimeField;
        let s = dalek_ff_group::Scalar::from_repr(secret.ed25519_secret_bytes().into()).unwrap();
        assert_eq!(EdwardsPoint::generator() * s, ed_pub);
    }

    #[test]
    fn a_proof_round_trips_through_bytes_and_still_verifies() {
        let secret = SharedSecret::prove(&mut OsRng, b"noct-dleq-serialize-test-seed-000");
        let bytes = secret.proof_bytes();
        let parsed = read_proof(&bytes).expect("re-parse");
        let (secp_a, ed_a) = verify(&mut OsRng, &secret.proof).unwrap();
        let (secp_b, ed_b) = verify(&mut OsRng, &parsed).unwrap();
        assert_eq!(secp_a, secp_b);
        assert_eq!(ed_a, ed_b);
    }

    #[test]
    fn tampered_proof_bytes_do_not_verify() {
        let secret = SharedSecret::prove(&mut OsRng, b"noct-dleq-tamper-test-seed-000000");
        let mut bytes = secret.proof_bytes();
        // Flip a byte in the middle of the proof.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        // Either it fails to parse, or it parses but fails verification — never
        // accepts a corrupted proof.
        let rejected = match read_proof(&bytes) {
            Err(_) => true,
            Ok(p) => verify(&mut OsRng, &p).is_err(),
        };
        assert!(rejected, "a tampered proof must be rejected");
    }
}
