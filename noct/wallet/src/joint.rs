//! 2-of-2 joint accounts — the NOCT side of an ETH⇄NOCT atomic swap.
//!
//! Two parties each hold a secret spend half (`s_a`, `s_b`). Funds locked to the
//! joint account can be swept only by an entity that knows the **sum** `s_a + s_b`,
//! which seeds the account's one-time spend key. The view key is shared — each
//! party contributes a view secret and both learn the sum `v_a + v_b` — so both
//! can *detect* the locked output while neither can *spend* it alone.
//!
//! In the swap (see `docs/eth-atomic-swap.md`): Bob locks NOCT to the joint
//! account; the Ethereum swap contract later reveals one party's `s_i`, letting
//! the other reconstruct `s_a + s_b` and sweep the NOCT with an ordinary
//! single-signer CLSAG. No consensus change and no interactive 2-party signing.
//!
//! ## Noct wrinkle
//!
//! A normal [`Account`] derives its view key as `a = H_s(b)` — impossible to
//! compute here without both spend halves. A joint account instead uses an
//! **independent** summed view key. This is sound: the stealth/scan/spend
//! primitives only ever read the `(view_secret, spend_public, spend_secret)`
//! fields; nothing re-derives `H_s(spend)` or assumes that invariant.

use curve25519_dalek::scalar::Scalar;
use noct_core::address::{Address, Network};
use noct_core::keys::{Account, PrivateKey, PublicKey};

/// One party's secret contribution to a joint account.
#[derive(Clone, Copy)]
pub struct JointContribution {
    /// This party's secret spend half `s_i` (revealed only when the swap settles).
    pub spend_secret: PrivateKey,
    /// This party's view half `v_i` — shared with the counterparty up front so
    /// both can scan the joint account.
    pub view_secret: PrivateKey,
}

impl JointContribution {
    /// A fresh random contribution.
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        JointContribution {
            spend_secret: PrivateKey(Scalar::random(rng)),
            view_secret: PrivateKey(Scalar::random(rng)),
        }
    }

    /// The public spend half `S_i = s_i·G` handed to the counterparty (the secret
    /// itself stays private until the swap reveals it).
    pub fn spend_public(&self) -> PublicKey {
        self.spend_secret.public_key()
    }
}

/// The shared 2-of-2 account. Both parties assemble the identical instance from
/// their own contribution plus the counterparty's *public* spend half and *secret*
/// view half. Scanning needs only this; spending needs the reconstructed sum.
#[derive(Clone, Copy)]
pub struct JointAccount {
    network: Network,
    spend_public: PublicKey, // S_a + S_b
    view_secret: PrivateKey, // v_a + v_b
    view_public: PublicKey,  // (v_a + v_b)·G
}

impl JointAccount {
    /// Assemble from our contribution plus the counterparty's shared halves: their
    /// spend **public** key and their view **secret**.
    pub fn assemble(
        network: Network,
        ours: &JointContribution,
        their_spend_public: PublicKey,
        their_view_secret: PrivateKey,
    ) -> Self {
        let spend_public = PublicKey(ours.spend_public().0 + their_spend_public.0);
        let view_secret = PrivateKey(ours.view_secret.0 + their_view_secret.0);
        JointAccount {
            network,
            spend_public,
            view_public: view_secret.public_key(),
            view_secret,
        }
    }

    /// The address funds are locked to.
    pub fn address(&self) -> Address {
        Address::new(self.network, self.spend_public, self.view_public)
    }

    /// The joint public spend key `S_a + S_b` — what a reconstructed secret must
    /// multiply to.
    pub fn spend_public(&self) -> PublicKey {
        self.spend_public
    }

    /// The shared view secret `v_a + v_b`, for a view-only scan of the joint
    /// account before the spend secret is known.
    pub fn view_secret(&self) -> PrivateKey {
        self.view_secret
    }

    /// Given the reconstructed joint spend secret `s = s_a + s_b`, the spendable
    /// [`Account`] that can sweep the locked output. Returns `None` if `s` does not
    /// match the joint spend key — so a wrong or *partial* secret (one party's half
    /// alone) can never build a spendable account.
    pub fn into_account(&self, joint_spend_secret: PrivateKey) -> Option<Account> {
        if joint_spend_secret.public_key() != self.spend_public {
            return None; // s·G ≠ S_a + S_b
        }
        Some(Account {
            spend_public: self.spend_public,
            view_public: self.view_public,
            spend_secret: joint_spend_secret,
            view_secret: self.view_secret,
        })
    }
}

/// Reconstruct the joint spend secret `s_a + s_b` from the two secret halves.
pub fn reconstruct_spend_secret(a: &PrivateKey, b: &PrivateKey) -> PrivateKey {
    PrivateKey(a.0 + b.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn both_parties_assemble_the_same_joint_address() {
        let alice = JointContribution::random(&mut OsRng);
        let bob = JointContribution::random(&mut OsRng);
        let from_alice =
            JointAccount::assemble(Network::Mainnet, &alice, bob.spend_public(), bob.view_secret);
        let from_bob =
            JointAccount::assemble(Network::Mainnet, &bob, alice.spend_public(), alice.view_secret);
        assert_eq!(from_alice.address().encode(), from_bob.address().encode());
        assert_eq!(from_alice.spend_public(), from_bob.spend_public());
    }

    #[test]
    fn only_the_full_sum_yields_a_spendable_account() {
        let alice = JointContribution::random(&mut OsRng);
        let bob = JointContribution::random(&mut OsRng);
        let ja =
            JointAccount::assemble(Network::Mainnet, &alice, bob.spend_public(), bob.view_secret);

        // Either half alone is rejected.
        assert!(ja.into_account(alice.spend_secret).is_none());
        assert!(ja.into_account(bob.spend_secret).is_none());

        // The reconstructed sum is accepted, and the account is self-consistent.
        let s = reconstruct_spend_secret(&alice.spend_secret, &bob.spend_secret);
        let acct = ja.into_account(s).expect("full secret spendable");
        assert_eq!(acct.spend_secret.public_key(), acct.spend_public);
        assert_eq!(acct.view_secret.public_key(), acct.view_public);
    }
}
