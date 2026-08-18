//! One-time (stealth) addresses — receiver privacy.
//!
//! For each output the sender derives a fresh one-time public key `P` that only
//! the recipient can link to their address and only the recipient can spend.
//!
//! Locked-in conventions (shared by both sides):
//!
//! * transaction key `R = r·G` (one `r` per transaction, published in the tx),
//! * shared secret is **cofactor-cleared** (`×8` via `mul_by_cofactor`) to kill
//!   any small-subgroup component before it enters the hash,
//! * derivation scalar `k = H_s( (8·shared).compress() ‖ index_le )`,
//! * one-time key `P = k·G + B_spend`,
//! * sender computes `shared = r·A_view`; recipient recomputes `shared = a·R`
//!   (both equal `r·a·G`) and checks the derived `P`,
//! * one-time spend secret `x = k + b_spend`, and `x·G == P`.
//!
//! `index` is the output's position within its transaction, encoded
//! little-endian as `u32` (outputs-per-tx never approaches 2^32).

use crate::address::Address;
use crate::hash::hash_to_scalar;
use crate::keys::{Account, PrivateKey, PublicKey};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

/// A transaction secret key `r` and its public `R = r·G`.
#[derive(Clone, Copy, Debug)]
pub struct TxKeypair {
    pub secret: PrivateKey,
    pub public: PublicKey,
}

impl TxKeypair {
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let secret = Scalar::random(rng);
        TxKeypair {
            public: PublicKey(EdwardsPoint::mul_base(&secret)),
            secret: PrivateKey(secret),
        }
    }
}

/// The derivation scalar `k = H_s( (8·shared).compress() ‖ index_le )`.
///
/// `shared` is the raw Diffie–Hellman point (`r·A` for the sender, `a·R` for the
/// recipient); the cofactor multiplication happens here so callers cannot forget
/// it.
fn derivation_scalar(shared: EdwardsPoint, index: u32) -> Scalar {
    let d = shared.mul_by_cofactor(); // ×8
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(d.compress().as_bytes());
    buf[32..36].copy_from_slice(&index.to_le_bytes());
    hash_to_scalar(&buf)
}

/// Sender side: the derivation scalar `k` for `recipient`'s `index`-th output.
///
/// Both parties can compute this shared scalar; it seeds the one-time key and
/// (in [`crate::tx`]) the output's amount mask and amount encryption.
pub fn sender_shared_scalar(tx_secret: &PrivateKey, recipient: &Address, index: u32) -> Scalar {
    derivation_scalar(tx_secret.0 * recipient.view_public.0, index) // r·A
}

/// Recipient side: the same derivation scalar `k`, recomputed with the view key.
pub fn recipient_shared_scalar(account: &Account, tx_public: &PublicKey, index: u32) -> Scalar {
    derivation_scalar(account.view_secret.0 * tx_public.0, index) // a·R
}

/// Sender side: derive the one-time public key `P` for `recipient`'s `index`-th
/// output, given this transaction's secret key `r`.
pub fn derive_output(tx_secret: &PrivateKey, recipient: &Address, index: u32) -> PublicKey {
    let k = sender_shared_scalar(tx_secret, recipient, index);
    PublicKey(EdwardsPoint::mul_base(&k) + recipient.spend_public.0)
}

/// Recipient side: the one-time public key this account *expects* at
/// `(tx_public, index)`. Compare against the actual output key to decide
/// ownership.
pub fn expected_output(account: &Account, tx_public: &PublicKey, index: u32) -> PublicKey {
    let k = recipient_shared_scalar(account, tx_public, index);
    PublicKey(EdwardsPoint::mul_base(&k) + account.spend_public.0)
}

/// Recipient side: does `one_time` at `(tx_public, index)` belong to `account`?
///
/// Requires only the **view** secret — this is exactly the scan operation a
/// view-only wallet performs.
pub fn is_ours(
    account: &Account,
    tx_public: &PublicKey,
    index: u32,
    one_time: &PublicKey,
) -> bool {
    &expected_output(account, tx_public, index) == one_time
}

/// Recipient side: recover the **spend public key** an output was addressed to,
/// `D' = P − k·G`. For a main-address output this is the account's spend public
/// `B`; for a subaddress output it is that subaddress's `D`. The caller matches
/// `D'` against the addresses it knows (its subaddress table) to decide
/// ownership — this is how one view key detects arbitrarily many subaddresses.
///
/// `tx_public` is the transaction key that applies to *this* output (the
/// per-output additional key when the transaction carries them, else the single
/// transaction key).
pub fn recovered_spend_public(
    account: &Account,
    tx_public: &PublicKey,
    index: u32,
    one_time: &PublicKey,
) -> PublicKey {
    let k = recipient_shared_scalar(account, tx_public, index);
    PublicKey(one_time.0 - EdwardsPoint::mul_base(&k))
}

/// Recipient side: the one-time **spend secret** `x = k + b` for an output known
/// to belong to `account`. Requires the spend secret.
///
/// `x·G == P` for the corresponding one-time public key `P`.
pub fn output_secret(account: &Account, tx_public: &PublicKey, index: u32) -> PrivateKey {
    let k = recipient_shared_scalar(account, tx_public, index);
    PrivateKey(k + account.spend_secret.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use rand_core::OsRng;

    fn recipient_account() -> Account {
        Account::random(&mut OsRng)
    }

    fn address_of(acct: &Account) -> Address {
        Address::new(Network::Mainnet, acct.spend_public, acct.view_public)
    }

    #[test]
    fn sender_and_recipient_agree_on_p() {
        let acct = recipient_account();
        let addr = address_of(&acct);
        let tx = TxKeypair::random(&mut OsRng);

        let p_sender = derive_output(&tx.secret, &addr, 0);
        let p_recipient = expected_output(&acct, &tx.public, 0);
        assert_eq!(p_sender, p_recipient);
        assert!(is_ours(&acct, &tx.public, 0, &p_sender));
    }

    #[test]
    fn spend_secret_opens_the_one_time_key() {
        let acct = recipient_account();
        let addr = address_of(&acct);
        let tx = TxKeypair::random(&mut OsRng);

        let p = derive_output(&tx.secret, &addr, 7);
        let x = output_secret(&acct, &tx.public, 7);
        // x·G == P
        assert_eq!(x.public_key(), p);
    }

    #[test]
    fn other_account_does_not_detect_output() {
        let me = recipient_account();
        let addr = address_of(&me);
        let stranger = recipient_account();
        let tx = TxKeypair::random(&mut OsRng);

        let p = derive_output(&tx.secret, &addr, 0);
        assert!(is_ours(&me, &tx.public, 0, &p));
        assert!(!is_ours(&stranger, &tx.public, 0, &p));
    }

    #[test]
    fn index_changes_the_output() {
        let acct = recipient_account();
        let addr = address_of(&acct);
        let tx = TxKeypair::random(&mut OsRng);
        assert_ne!(derive_output(&tx.secret, &addr, 0), derive_output(&tx.secret, &addr, 1));
    }
}
