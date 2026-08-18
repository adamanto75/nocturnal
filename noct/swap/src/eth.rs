//! Ethereum-side helpers for the swap: the on-chain commitment to a secp256k1
//! public key, and a local replica of the contract's discrete-log check.
//!
//! The `NoctSwap` contract (see `eth/NoctSwap.sol`) stores a **commitment** to
//! each party's secp256k1 public key — `keccak256(x‖y)` — and, when a secret is
//! revealed, checks `s·G` matches it via Vitalik's ecrecover-as-ecmul trick. The
//! swap daemon needs to compute that commitment (to embed in the contract) and to
//! confirm — before funding — that its own DLEQ-derived secret will be accepted.
//! These helpers do exactly that, and the tests verify the DLEQ's secp256k1
//! output satisfies the real on-chain check.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// The contract's commitment to `point`: `keccak256(x ‖ y)` over the 32-byte
/// big-endian affine coordinates. Its low 160 bits are the point's Ethereum
/// address.
pub fn point_commitment(point: &ProjectivePoint) -> [u8; 32] {
    let affine = point.to_affine();
    let enc = affine.to_encoded_point(false); // 0x04 ‖ x(32) ‖ y(32)
    keccak256(&enc.as_bytes()[1..65])
}

/// The Ethereum address of `point` — the low 160 bits of [`point_commitment`].
pub fn eth_address(point: &ProjectivePoint) -> [u8; 20] {
    let c = point_commitment(point);
    let mut a = [0u8; 20];
    a.copy_from_slice(&c[12..32]);
    a
}

/// Local replica of the contract's `mulVerify(s, commitment)`: `true` iff `s·G`
/// matches the committed point (compared on the low 160 bits, exactly as the
/// contract's `uint160` comparison does).
pub fn mul_verify(scalar: &Scalar, commitment: &[u8; 32]) -> bool {
    let point = ProjectivePoint::GENERATOR * scalar;
    point_commitment(&point)[12..32] == commitment[12..32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify, SharedSecret};
    use core::ops::Deref;
    use rand_core::OsRng;

    #[test]
    fn dleq_secp_output_is_accepted_by_the_contract_check() {
        let secret = SharedSecret::prove(&mut OsRng, b"noct-eth-mulverify-seed-000000000");
        let (secp_pub, _ed) = verify(&mut OsRng, &secret.proof).unwrap();

        // The commitment Alice would put in the contract for this party.
        let commitment = point_commitment(&secp_pub);

        // Revealing the correct secret passes the on-chain check…
        assert!(mul_verify(secret.secp256k1_scalar.deref(), &commitment), "correct secret accepted");
        // …and any other scalar is rejected.
        let wrong = *secret.secp256k1_scalar.deref() + Scalar::ONE;
        assert!(!mul_verify(&wrong, &commitment), "wrong secret rejected");
    }

    /// Rigorously confirm the contract's *mechanism* — `ecrecover(0, 27, GX,
    /// s·GX mod N)` — recovers `s·G` for our DLEQ scalar, i.e. the on-chain trick
    /// accepts exactly the value we produce.
    #[test]
    fn ecrecover_ecmul_trick_recovers_s_times_g() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        use k256::elliptic_curve::PrimeField;

        let secret = SharedSecret::prove(&mut OsRng, b"noct-eth-ecrecover-seed-000000000");
        let s = *secret.secp256k1_scalar.deref();
        let expected = ProjectivePoint::GENERATOR * s; // S = s·G

        // r = generator x-coordinate (GX); s_sig = s·GX mod N; recovery id 0 (R = G).
        let gen_enc = ProjectivePoint::GENERATOR.to_affine().to_encoded_point(false);
        let gx_bytes = *gen_enc.x().unwrap();
        let gx = Scalar::from_repr(gx_bytes).unwrap();
        let s_sig = s * gx;

        let sig = Signature::from_scalars(gx_bytes, s_sig.to_bytes()).unwrap();
        let recovered =
            VerifyingKey::recover_from_prehash(&[0u8; 32], &sig, RecoveryId::from_byte(0).unwrap())
                .unwrap();

        assert_eq!(
            recovered.as_affine(),
            &expected.to_affine(),
            "ecrecover trick must recover s·G"
        );
        // And its address equals the point's commitment low-160 (what the contract compares).
        let recovered_point = ProjectivePoint::from(*recovered.as_affine());
        assert_eq!(eth_address(&recovered_point), eth_address(&expected));
    }
}
