//! The shielded pool: Orchard bundles as this chain uses them.
//!
//! A thin layer over the `orchard` crate that fixes the choices consensus must
//! not leave open, and exposes only what the chain actually needs from a bundle:
//! what it moves, what it spends, and which tree root it proves against.
//!
//! Three decisions live here rather than at every call site, because a chain
//! that makes them inconsistently is a chain that forks:
//!
//! * **One circuit, and it is the fixed one.** [`CIRCUIT`] is
//!   `FixedPostNu6_2`. Every `orchard` release up to and including 0.13.1 is
//!   yanked because the original Action circuit was unsound, and
//!   `orchard_insecure_v1` exists in the crate but must never be reachable from
//!   here.
//! * **One verifying key**, built once and shared. Building it costs about a
//!   second, which is a startup cost; paying it per block would not be.
//! * **One sign convention.** A bundle states its value balance from the
//!   *shielded* pool's point of view, and the rest of Noct states crossings from
//!   the *ring* pool's. [`ShieldedBundle::cross`] is the single place that
//!   converts, so no other code has to remember which way round it is.
//!
//! Serialization is not here yet: `orchard` does not serialize bundles (Zcash
//! does that in `zcash_primitives`), so Noct writes its own encoding, and that
//! is its own change.

use std::sync::OnceLock;

use orchard::bundle::Authorized;
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use orchard::Bundle;

/// The only Orchard circuit this chain will verify against.
///
/// `orchard_insecure_v1` is the unsound original and is never used. Changing
/// this constant is a consensus change: proofs made for one circuit do not
/// verify under another.
pub const CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::FixedPostNu6_2;

/// The shared verifying key for [`CIRCUIT`].
///
/// Built on first use and kept for the life of the process — roughly a second
/// of work, which a node pays once at startup rather than per block. It holds no
/// secret: a verifying key is public by construction, and every node has the
/// same one.
pub fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT))
}

/// Why a bundle was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedError {
    /// The zero-knowledge proof did not verify.
    BadProof,
    /// The bundle was built for a different circuit than [`CIRCUIT`].
    WrongCircuit { found: OrchardCircuitVersion },
    /// The value balance has no negation, so it cannot be stated as a ring-side
    /// crossing. Only `i64::MIN` does this.
    UnrepresentableValue,
}

impl std::fmt::Display for ShieldedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldedError::BadProof => f.write_str("shielded: the proof did not verify"),
            ShieldedError::WrongCircuit { found } => {
                write!(f, "shielded: bundle built for {found:?}, this chain verifies {CIRCUIT:?}")
            }
            ShieldedError::UnrepresentableValue => {
                f.write_str("shielded: value balance cannot be expressed as a crossing")
            }
        }
    }
}

impl std::error::Error for ShieldedError {}

/// An authorised Orchard bundle, as it appears in a Noct transaction.
///
/// The value balance is carried as `i64`: Noct's whole supply fits with room to
/// spare, and a signed integer is what the turnstile arithmetic wants.
#[derive(Clone, Debug)]
pub struct ShieldedBundle(Bundle<Authorized, i64>);

impl ShieldedBundle {
    /// Wrap a bundle, refusing one built for another circuit.
    ///
    /// Checked here, at the boundary, so no later code has to: a bundle that got
    /// this far is one this chain can verify.
    pub fn new(bundle: Bundle<Authorized, i64>) -> Result<Self, ShieldedError> {
        let found = bundle.bundle_version().circuit_version();
        if found != CIRCUIT {
            return Err(ShieldedError::WrongCircuit { found });
        }
        Ok(ShieldedBundle(bundle))
    }

    /// The bundle's own value balance, from the **shielded pool's** point of
    /// view: positive means value left the shielded pool, negative means value
    /// entered it.
    pub fn value_balance(&self) -> i64 {
        *self.0.value_balance()
    }

    /// The same movement, stated from the **ring pool's** point of view — the
    /// `cross` the rest of Noct uses.
    ///
    /// The two are negations of each other: value entering the shielded pool
    /// (`value_balance` negative) is value that left the ring pool (`cross`
    /// positive). This function is the only place that flips it.
    ///
    /// `i64::MIN` is refused rather than negated. Negation wraps in release and
    /// the wrap reads as `i64::MIN` again — a crossing that would move value on
    /// one side and not the other.
    pub fn cross(&self) -> Result<i64, ShieldedError> {
        self.value_balance().checked_neg().ok_or(ShieldedError::UnrepresentableValue)
    }

    /// How many actions the bundle has. Each is one proof's worth of
    /// verification work and about 5 KB of block space.
    pub fn actions(&self) -> usize {
        self.0.actions().len()
    }

    /// The commitment-tree root this bundle's spends prove membership against.
    ///
    /// The chain decides whether this anchor is one it still accepts; the bundle
    /// only states it.
    pub fn anchor(&self) -> [u8; 32] {
        self.0.anchor().to_bytes()
    }

    /// Every nullifier this bundle publishes, in canonical byte form.
    ///
    /// These are the shielded pool's equivalent of key images: the chain rejects
    /// a bundle whose nullifier it has already seen, which is what stops a note
    /// being spent twice without anyone learning which note it was.
    pub fn nullifiers(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.0.actions().iter().map(|a| a.nullifier().to_bytes())
    }

    /// Whether this bundle may spend notes. False for a coinbase bundle, where
    /// every spend must be a dummy.
    pub fn spends_enabled(&self) -> bool {
        self.0.flags().spends_enabled()
    }

    /// Whether this bundle may create notes.
    pub fn outputs_enabled(&self) -> bool {
        self.0.flags().outputs_enabled()
    }

    /// Verify the zero-knowledge proof against the shared verifying key.
    ///
    /// This is the expensive half of validating a bundle — about 9 ms per action
    /// on a node — and it is all a node has to go on: a valid proof is the only
    /// evidence that the notes involved exist and the arithmetic holds.
    pub fn verify_proof(&self) -> Result<(), ShieldedError> {
        self.0.verify_proof(verifying_key()).map_err(|_| ShieldedError::BadProof)
    }

    /// The wrapped bundle, for code that needs the crate's own type.
    pub fn inner(&self) -> &Bundle<Authorized, i64> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::builder::{Builder, BundleType};
    use orchard::bundle::{BundleVersion, Flags};
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::value::NoteValue;
    use orchard::Anchor;
    use rand_core::{OsRng, RngCore};

    /// The proving key, built once for the whole test module.
    ///
    /// Building one costs about a second and a half, and these tests would
    /// otherwise each pay it. Proving in a debug build is slow enough already;
    /// tests that prove should stay few and share this.
    fn proving_key() -> &'static orchard::circuit::ProvingKey {
        static PK: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
        PK.get_or_init(|| orchard::circuit::ProvingKey::build(CIRCUIT))
    }

    /// `SpendingKey::random` is private to the crate, and not every 32 bytes is
    /// a valid key, so this retries on the rare rejection.
    fn spending_key() -> SpendingKey {
        loop {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
                return sk;
            }
        }
    }

    /// Build an outputs-only bundle worth `value`, proved and authorised.
    ///
    /// `coinbase` picks the two shapes Noct needs: value crossing in from the
    /// ring pool, and a block reward minted straight into the shielded pool.
    fn built(value: u64, coinbase: bool) -> Bundle<Authorized, i64> {
        let mut rng = OsRng;
        let version = BundleVersion::orchard_v2();
        let fvk = FullViewingKey::from(&spending_key());
        let recipient = fvk.address_at(0u32, Scope::External);

        let (kind, flags) = if coinbase {
            (BundleType::Coinbase, Flags::SPENDS_DISABLED)
        } else {
            // A crossing's shape is already public — the value balance states it
            // — so padding to the default two actions would buy no privacy and
            // cost a second proof.
            (BundleType::UNPADDED, version.default_flags())
        };

        let mut builder = Builder::new(kind, version, flags, Anchor::empty_tree())
            .expect("flags are valid for this bundle version");
        builder
            .add_output(None, recipient, NoteValue::from_raw(value), [0u8; 512])
            .expect("an outputs-only bundle accepts an output");

        builder
            .build::<i64>(&mut rng)
            .expect("bundle builds")
            .expect("a bundle is produced")
            .0
            .create_proof(proving_key(), &mut rng)
            .expect("proving succeeds")
            .prepare(rng, [0u8; 32])
            .finalize()
            .expect("binding signature")
    }

    /// The conversion the rest of Noct depends on. A bundle says "5,000 entered
    /// the shielded pool" as `-5000`; the ring side must read that as "5,000 left
    /// the ring pool", `cross = +5000`. Reversing it would make a shielding
    /// transaction look like an unshielding one, and mint ring coins.
    #[test]
    fn a_bundle_states_its_movement_the_opposite_way_round_from_the_ring_side() {
        let b = ShieldedBundle::new(built(5_000, false)).expect("fixed circuit");
        assert_eq!(b.value_balance(), -5_000, "value entering the pool is negative");
        assert_eq!(b.cross().unwrap(), 5_000, "which is value leaving the ring pool");
    }

    /// The crossing a bundle implies must be exactly what the turnstile then
    /// applies — these are two halves of one rule and are checked together.
    #[test]
    fn the_crossing_a_bundle_implies_is_the_one_the_turnstile_applies() {
        use crate::pools::{Pool, PoolTotals};

        let b = ShieldedBundle::new(built(5_000, false)).expect("fixed circuit");
        let mut totals = PoolTotals::new();
        totals.mint(Pool::Ring, 10_000).unwrap();
        totals.apply_cross(b.cross().unwrap()).expect("the crossing applies");

        assert_eq!((totals.ring(), totals.shielded()), (5_000, 5_000));
        assert_eq!(totals.total().unwrap(), 10_000, "a crossing moves value, never creates it");
    }

    /// A coinbase bundle must not be able to spend: every spend in it would have
    /// to be a dummy, and the flags say so up front.
    #[test]
    fn a_coinbase_bundle_cannot_spend() {
        let b = ShieldedBundle::new(built(9_000_000_000, true)).expect("fixed circuit");
        assert!(!b.spends_enabled(), "a block reward spends nothing");
        assert!(b.outputs_enabled(), "but it does create a note");
        assert_eq!(b.cross().unwrap(), 9_000_000_000);
    }

    /// The proof is the only evidence a node has, so verifying it must work
    /// through the shared key — and the key must be the fixed circuit's.
    #[test]
    fn a_well_formed_bundle_verifies_against_the_shared_key() {
        let b = ShieldedBundle::new(built(1, false)).expect("fixed circuit");
        assert_eq!(b.verify_proof(), Ok(()));
        assert_eq!(b.actions(), 1, "UNPADDED means exactly the actions asked for");
        assert_eq!(b.nullifiers().count(), 1, "one action publishes one nullifier");
    }

    /// The circuit this chain accepts is pinned. If this ever reads
    /// `orchard_insecure_v1`, the chain is verifying proofs made for a circuit
    /// known to be unsound.
    #[test]
    fn the_pinned_circuit_is_the_fixed_one() {
        assert_eq!(CIRCUIT, OrchardCircuitVersion::FixedPostNu6_2);
        let b = ShieldedBundle::new(built(1, false)).expect("fixed circuit");
        assert_eq!(b.inner().bundle_version().circuit_version(), CIRCUIT);
    }
}
