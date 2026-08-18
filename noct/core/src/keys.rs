//! Keys and dual-key accounts.
//!
//! Noct is a CryptoNote-style dual-key system: every account has a **spend**
//! keypair and a **view** keypair. The view secret is *derived* from the spend
//! secret (`a = H_s(b)`), so a single 32-byte spend secret is the whole wallet.
//! Handing out the view secret lets a third party detect incoming outputs
//! (see [`crate::stealth`]) without the ability to spend.

use crate::hash::hash_to_scalar;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

/// A secret scalar (a private key).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrivateKey(pub Scalar);

/// A public group element (a public key), always a point on the prime-order
/// subgroup because it is produced as `scalar · G`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub EdwardsPoint);

impl PrivateKey {
    /// The corresponding public key `x · G`.
    pub fn public_key(&self) -> PublicKey {
        // `mul_base` uses the precomputed basepoint table; equivalent to
        // `&self.0 * ED25519_BASEPOINT_TABLE`.
        PublicKey(EdwardsPoint::mul_base(&self.0))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Parse a canonical (already-reduced) scalar. Returns `None` for
    /// non-canonical encodings so we never silently accept malleable secrets.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).map(PrivateKey)
    }
}

impl PublicKey {
    /// The 32-byte compressed Edwards-Y encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decompress a 32-byte public key. Returns `None` unless the bytes are a
    /// **canonical** encoding of a **prime-order** point.
    ///
    /// Rejecting non-canonical `y` (≥ p) prevents two distinct byte strings from
    /// decoding to the same key (address malleability); rejecting torsion /
    /// small-order points keeps public keys in the prime-order subgroup.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let point = CompressedEdwardsY(bytes).decompress()?;
        if point.compress().to_bytes() != bytes || !point.is_torsion_free() {
            return None;
        }
        Some(PublicKey(point))
    }
}

/// A dual-key account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Account {
    pub spend_secret: PrivateKey,
    pub view_secret: PrivateKey,
    pub spend_public: PublicKey,
    pub view_public: PublicKey,
}

impl Account {
    /// Build an account from a spend secret. The view secret is derived as
    /// `a = H_s(b)`, matching the convention locked in for the whole coin.
    pub fn from_spend_secret(spend_secret: Scalar) -> Self {
        let view_scalar = hash_to_scalar(spend_secret.as_bytes());
        let spend = PrivateKey(spend_secret);
        let view = PrivateKey(view_scalar);
        Account {
            spend_public: spend.public_key(),
            view_public: view.public_key(),
            spend_secret: spend,
            view_secret: view,
        }
    }

    /// Generate a fresh random account.
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        Self::from_spend_secret(Scalar::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn view_secret_is_derived_from_spend() {
        let acct = Account::from_spend_secret(Scalar::from(42u64));
        assert_eq!(acct.view_secret.0, hash_to_scalar(&acct.spend_secret.to_bytes()));
    }

    #[test]
    fn public_keys_are_scalar_times_g() {
        let acct = Account::random(&mut OsRng);
        assert_eq!(acct.spend_public, acct.spend_secret.public_key());
        assert_eq!(acct.view_public, acct.view_secret.public_key());
    }

    #[test]
    fn public_key_roundtrips_through_bytes() {
        let acct = Account::random(&mut OsRng);
        let bytes = acct.spend_public.to_bytes();
        assert_eq!(PublicKey::from_bytes(bytes).unwrap(), acct.spend_public);
    }
}
