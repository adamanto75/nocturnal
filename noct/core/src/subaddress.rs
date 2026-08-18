//! Subaddresses — many unlinkable receiving addresses under one view key.
//!
//! A wallet can derive an unbounded family of subaddresses indexed by
//! `(account, index)`. Each has its own public keys but is detected with the
//! *same* view secret, and none can be linked to another — or to the main
//! address — without that view secret. This is the CryptoNote/Monero subaddress
//! scheme, adapted to Noct's `a = H_s(b)` key convention.
//!
//! For `(account i, index j)`, with main spend key `B` and view secret `a`:
//!
//! * offset       `m = H_s("noct_subaddress" ‖ a ‖ i_le ‖ j_le)`
//! * spend public `D = B + m·G`
//! * view public  `C = a·D`
//! * spend secret `d = b + m`   (so `d·G == D`)
//!
//! The **main** address `(0, 0)` is special-cased to the standard address
//! `(B, a·G)` with `m = 0`, so an existing wallet's primary address is
//! unchanged. Sending to a subaddress uses a per-output transaction key
//! `R = r·D` instead of `r·G` (see [`crate::stealth`]); the derived shared
//! secret is `r·C = a·R`, so scanning still needs only the view secret.

use crate::hash::hash_to_scalar;
use crate::keys::{Account, PrivateKey, PublicKey};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

/// Identifies a subaddress within a wallet: a major `account` and minor
/// `index`. `(0, 0)` is the wallet's main address.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct SubaddressIndex {
    pub account: u32,
    pub index: u32,
}

impl SubaddressIndex {
    /// The wallet's primary address.
    pub const MAIN: SubaddressIndex = SubaddressIndex { account: 0, index: 0 };

    pub fn new(account: u32, index: u32) -> Self {
        SubaddressIndex { account, index }
    }

    /// True for the primary address `(0, 0)`.
    pub fn is_main(&self) -> bool {
        self.account == 0 && self.index == 0
    }
}

/// The subaddress offset scalar `m` for `(account, index)`; `0` for the main
/// address. Requires only the view secret, so a view-only wallet can derive it.
pub fn offset(view_secret: &PrivateKey, sub: SubaddressIndex) -> Scalar {
    if sub.is_main() {
        return Scalar::ZERO;
    }
    let mut buf = Vec::with_capacity(15 + 32 + 8);
    buf.extend_from_slice(b"noct_subaddress");
    buf.extend_from_slice(view_secret.0.as_bytes());
    buf.extend_from_slice(&sub.account.to_le_bytes());
    buf.extend_from_slice(&sub.index.to_le_bytes());
    hash_to_scalar(&buf)
}

/// The subaddress spend public key `D = B + m·G` (the main `B` for `(0, 0)`).
pub fn spend_public(account: &Account, sub: SubaddressIndex) -> PublicKey {
    if sub.is_main() {
        return account.spend_public;
    }
    let m = offset(&account.view_secret, sub);
    PublicKey(account.spend_public.0 + EdwardsPoint::mul_base(&m))
}

/// The subaddress view public key `C = a·D` (the standard `a·G` for `(0, 0)`).
pub fn view_public(account: &Account, sub: SubaddressIndex) -> PublicKey {
    if sub.is_main() {
        return account.view_public;
    }
    let d = spend_public(account, sub).0;
    PublicKey(account.view_secret.0 * d)
}

/// The subaddress one-time spend secret `d = b + m`, with `d·G == D`. Requires
/// the spend secret.
pub fn spend_secret(account: &Account, sub: SubaddressIndex) -> PrivateKey {
    if sub.is_main() {
        return account.spend_secret;
    }
    let m = offset(&account.view_secret, sub);
    PrivateKey(account.spend_secret.0 + m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn main_index_is_the_standard_address() {
        let acct = Account::random(&mut OsRng);
        assert_eq!(offset(&acct.view_secret, SubaddressIndex::MAIN), Scalar::ZERO);
        assert_eq!(spend_public(&acct, SubaddressIndex::MAIN), acct.spend_public);
        assert_eq!(view_public(&acct, SubaddressIndex::MAIN), acct.view_public);
        assert_eq!(spend_secret(&acct, SubaddressIndex::MAIN), acct.spend_secret);
    }

    #[test]
    fn spend_secret_opens_spend_public() {
        let acct = Account::random(&mut OsRng);
        for (i, j) in [(0, 1), (1, 0), (3, 7), (255, 4096)] {
            let sub = SubaddressIndex::new(i, j);
            assert_eq!(spend_secret(&acct, sub).public_key(), spend_public(&acct, sub));
        }
    }

    #[test]
    fn view_public_is_a_times_d() {
        let acct = Account::random(&mut OsRng);
        let sub = SubaddressIndex::new(2, 5);
        let d = spend_public(&acct, sub);
        assert_eq!(view_public(&acct, sub), PublicKey(acct.view_secret.0 * d.0));
    }

    #[test]
    fn distinct_indices_give_distinct_subaddresses() {
        let acct = Account::random(&mut OsRng);
        let a = spend_public(&acct, SubaddressIndex::new(0, 1));
        let b = spend_public(&acct, SubaddressIndex::new(0, 2));
        let c = spend_public(&acct, SubaddressIndex::new(1, 1));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        // And none equals the main address.
        assert_ne!(a, acct.spend_public);
    }

    #[test]
    fn subaddresses_are_unlinkable_without_view_secret() {
        // Two different accounts produce unrelated subaddresses at the same
        // index — the offset binds to the view secret.
        let a1 = Account::random(&mut OsRng);
        let a2 = Account::random(&mut OsRng);
        let sub = SubaddressIndex::new(0, 1);
        assert_ne!(offset(&a1.view_secret, sub), offset(&a2.view_secret, sub));
    }
}
