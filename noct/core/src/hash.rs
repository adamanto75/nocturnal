//! Hashing primitives.
//!
//! Noct uses **original Keccak-256** (the pre-standardization padding used by
//! Monero/Ethereum via `tiny_keccak::Keccak::v256`), *not* NIST SHA3-256. The
//! two differ only in the domain-separation byte, but they are not
//! interchangeable — every hash in the protocol must go through here.

use curve25519_dalek::scalar::Scalar;
use tiny_keccak::{Hasher, Keccak};

/// Original Keccak-256 over `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// `H_s(x)` — hash to scalar.
///
/// Defined as `Scalar::from_bytes_mod_order(keccak256(x))`. Reducing mod the
/// group order ℓ means the result is a uniformly-distributed scalar for all
/// practical purposes (the bias from reducing a 256-bit value mod ℓ ≈ 2^252 is
/// negligible), matching Monero's `hash_to_scalar`.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_known_vector() {
        // Original Keccak-256 of the empty input (the Ethereum/Monero value),
        // which differs from NIST SHA3-256 of "".
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn hash_to_scalar_is_reduced() {
        // The result must be a canonical (already-reduced) scalar.
        let s = hash_to_scalar(b"noct");
        assert_eq!(Scalar::from_canonical_bytes(s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn hash_to_scalar_is_deterministic() {
        assert_eq!(hash_to_scalar(b"noct"), hash_to_scalar(b"noct"));
        assert_ne!(hash_to_scalar(b"noct"), hash_to_scalar(b"noctt"));
    }
}
