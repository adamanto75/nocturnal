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
use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
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

/// The shared **proving** key for [`CIRCUIT`].
///
/// Built on first use and kept for the life of the process, like
/// [`verifying_key`], and about as expensive to build. It holds no secret
/// either — a proving key is public parameters, and what makes a proof yours is
/// the witness you feed it, not this.
///
/// A node never needs one; a wallet and a miner both do, because both create
/// notes. It lives here rather than in either of them so there is one circuit
/// and one key, and no chance of proving against a circuit the chain does not
/// verify against.
pub fn proving_key() -> &'static ProvingKey {
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT))
}

/// Why a bundle was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedError {
    /// The zero-knowledge proof did not verify.
    BadProof,
    /// An action's spend authorization signature did not verify under its `rk`.
    BadSpendAuth,
    /// The binding signature did not verify, so the stated value balance is not
    /// the one the actions' value commitments add up to.
    BadBindingSignature,
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
            ShieldedError::BadSpendAuth => {
                f.write_str("shielded: a spend authorization signature did not verify")
            }
            ShieldedError::BadBindingSignature => {
                f.write_str("shielded: the binding signature did not verify")
            }
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

    /// Every note commitment this bundle creates, in the order the tree must
    /// append them.
    ///
    /// Order is consensus: the tree's root depends on it, and two nodes that
    /// appended the same commitments in a different order would disagree about
    /// every anchor afterwards.
    pub fn commitments(&self) -> impl Iterator<Item = orchard::note::ExtractedNoteCommitment> + '_ {
        self.0.actions().iter().map(|a| *a.cmx())
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

    /// Verify **everything** the bundle asserts, against the message it was
    /// signed over. This is what consensus must call; `verify_proof` alone is not
    /// enough, and the reason is worth stating plainly.
    ///
    /// The proof does not cover the value balance. `value_balance` is a public
    /// input carried beside the proof, and what ties it to the actions' value
    /// commitments is the **binding signature**: its validating key is derived as
    /// `Σ cv_net − value_balance·R`, which is a key somebody can sign under only
    /// if the two agree. Verify the proof and not the binding signature and a
    /// bundle may claim any balance it likes — which on the way into the pool is
    /// minting coins from nothing, and on the way out is minting them in the ring
    /// pool. It is the whole of the turnstile's arithmetic, in one signature.
    ///
    /// The **spend authorization** signatures are the other half: the proof shows
    /// a note exists and that `rk` is the right randomized key for it, but only a
    /// signature under `rk` shows its owner agreed to spend it.
    ///
    /// `sighash` is what both are signed over, and it must commit to everything
    /// that could otherwise be changed around the bundle — otherwise an
    /// authorized bundle can be lifted out of one context and replayed in
    /// another.
    pub fn verify(&self, sighash: &[u8; 32]) -> Result<(), ShieldedError> {
        // Signatures first: they are microseconds, the proof is milliseconds, and
        // a bundle that fails either is rejected either way.
        for action in self.0.actions() {
            action
                .rk()
                .verify(sighash, action.authorization())
                .map_err(|_| ShieldedError::BadSpendAuth)?;
        }
        self.0
            .binding_validating_key()
            .verify(sighash, self.0.authorization().binding_signature())
            .map_err(|_| ShieldedError::BadBindingSignature)?;
        self.verify_proof()
    }

    /// Which Orchard circuit this bundle was built for. Always [`CIRCUIT`] for a
    /// bundle that exists — `new` refuses any other — which is the point.
    pub fn circuit(&self) -> OrchardCircuitVersion {
        self.0.bundle_version().circuit_version()
    }

    /// The wrapped bundle, for code that needs the crate's own type.
    pub fn inner(&self) -> &Bundle<Authorized, i64> {
        &self.0
    }
}

// --- wire encoding ----------------------------------------------------------
//
// `orchard` does not serialize bundles — Zcash does that in `zcash_primitives`,
// as part of its own transaction format — so Noct defines its own. The layout
// follows the conventions in [`crate::wire`]: little-endian integers, a count
// bounded before anything is allocated, and no trailing bytes.
//
// ```text
// bundle := u16  action_count            1..=MAX_ACTIONS
//           action × action_count        884 bytes each, fixed
//           u8    flags
//           i64   value_balance          little-endian
//           [u8;32] anchor
//           proof                        exactly expected_proof_size(action_count)
//           [u8;64] binding signature
//
// action := cv_net 32 ‖ nullifier 32 ‖ rk 32 ‖ cmx 32
//           ‖ epk 32 ‖ enc_ciphertext 580 ‖ out_ciphertext 80
//           ‖ spend_auth_sig 64
// ```
//
// **The proof is not length-prefixed.** Its length is a function of the action
// count, so there is no field for an attacker to inflate: a proof padded with
// trailing data (GHSA-2x4w-pxqw-58v9) is not so much rejected here as
// unrepresentable. The crate checks the same property again in
// `try_from_parts`, and both are kept — one of them is a parser that cannot
// express the attack, the other a library that refuses it.

use nonempty::NonEmpty;
use orchard::bundle::{BundleVersion, Flags};
use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
use orchard::primitives::redpallas::{self, SpendAuth};
use orchard::value::ValueCommitment;
use orchard::{Action, Anchor, Proof};

/// The bundle version this chain speaks.
///
/// One version, for the same reason there is one circuit: a chain that accepts
/// two has to agree about both.
pub fn bundle_version() -> BundleVersion {
    BundleVersion::orchard_v2()
}

/// Bytes one action occupies on the wire.
pub const ACTION_BYTES: usize = 32 + 32 + 32 + 32 + 32 + 580 + 80 + 64;

/// The most actions one bundle may carry.
///
/// A bound, not a target: at this count a bundle is about 1.6 MB — the actions
/// plus a proof that grows with them — which fits a block body with room to
/// spare, while a larger claim is refused before a byte is allocated.
pub const MAX_ACTIONS: usize = 512;

/// The largest a bundle can legitimately be: [`MAX_ACTIONS`] actions and the
/// proof that goes with them.
///
/// A bound for whoever embeds a bundle in something larger — a transaction has
/// to know when to stop reading — and checked before any slice is taken, like
/// every other length in [`crate::wire`].
pub fn max_bundle_bytes() -> usize {
    2 + MAX_ACTIONS * ACTION_BYTES + 1 + 8 + 32 + Proof::expected_proof_size(MAX_ACTIONS) + 64
}

/// Why a bundle could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleWireError {
    /// Ran out of bytes.
    Truncated,
    /// Bytes remained after a complete bundle.
    TrailingBytes,
    /// Zero actions, or more than [`MAX_ACTIONS`].
    BadActionCount(usize),
    /// A point or key was not a canonical encoding of a valid element.
    BadEncoding(&'static str),
    /// The flags byte is not one this bundle version can express.
    BadFlags,
    /// The crate refused the assembled bundle: a non-canonical proof size, an
    /// identity `rk` or `epk`, or flags it will not represent.
    Refused,
}

impl std::fmt::Display for BundleWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleWireError::Truncated => f.write_str("shielded bundle: ran out of bytes"),
            BundleWireError::TrailingBytes => {
                f.write_str("shielded bundle: bytes after the end of the bundle")
            }
            BundleWireError::BadActionCount(n) => {
                write!(f, "shielded bundle: {n} actions (minimum 1, limit {MAX_ACTIONS})")
            }
            BundleWireError::BadEncoding(what) => {
                write!(f, "shielded bundle: {what} is not a canonical encoding")
            }
            BundleWireError::BadFlags => f.write_str("shielded bundle: unrepresentable flags"),
            BundleWireError::Refused => {
                f.write_str("shielded bundle: refused by the orchard crate as malformed")
            }
        }
    }
}

impl std::error::Error for BundleWireError {}

impl ShieldedBundle {
    /// Serialize to Noct's canonical bundle encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let actions = self.0.actions();
        let proof = self.0.authorization().proof().as_ref();
        let mut out =
            Vec::with_capacity(2 + actions.len() * ACTION_BYTES + 1 + 8 + 32 + proof.len() + 64);

        out.extend_from_slice(&(actions.len() as u16).to_le_bytes());
        for a in actions.iter() {
            out.extend_from_slice(&a.cv_net().to_bytes());
            out.extend_from_slice(&a.nullifier().to_bytes());
            out.extend_from_slice(&<[u8; 32]>::from(a.rk()));
            out.extend_from_slice(&a.cmx().to_bytes());
            out.extend_from_slice(&a.encrypted_note().epk_bytes);
            out.extend_from_slice(&a.encrypted_note().enc_ciphertext);
            out.extend_from_slice(&a.encrypted_note().out_ciphertext);
            out.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
        }
        // Cannot fail for a bundle that exists: `try_from_parts` refuses
        // unrepresentable flags on the way in, so every built bundle has some.
        out.push(self.0.flags().to_byte(bundle_version()).unwrap_or(0));
        out.extend_from_slice(&self.value_balance().to_le_bytes());
        out.extend_from_slice(&self.0.anchor().to_bytes());
        out.extend_from_slice(proof);
        out.extend_from_slice(&<[u8; 64]>::from(self.0.authorization().binding_signature()));
        out
    }

    /// Decode a bundle from untrusted bytes.
    ///
    /// Strict in the way the rest of [`crate::wire`] is strict: the action count
    /// is bounded before anything is allocated, every point is decoded through
    /// its canonical check, the proof's length is derived rather than read, and
    /// bytes left over are an error rather than something to ignore.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleWireError> {
        let mut cur = bytes;

        let count =
            usize::from(u16::from_le_bytes(take(&mut cur, 2)?.try_into().expect("two bytes")));
        // Bounded before a single action is decoded, let alone allocated: an
        // inflated count must cost the sender, not us.
        if count == 0 || count > MAX_ACTIONS {
            return Err(BundleWireError::BadActionCount(count));
        }

        // Capacity is capped rather than taken from the count, so the claim
        // itself buys no allocation.
        let mut actions = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let cv_net = ValueCommitment::from_bytes(&array32(&mut cur)?)
                .into_option()
                .ok_or(BundleWireError::BadEncoding("cv_net"))?;
            let nullifier = Nullifier::from_bytes(&array32(&mut cur)?)
                .into_option()
                .ok_or(BundleWireError::BadEncoding("nullifier"))?;
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(array32(&mut cur)?)
                .map_err(|_| BundleWireError::BadEncoding("rk"))?;
            let cmx = ExtractedNoteCommitment::from_bytes(&array32(&mut cur)?)
                .into_option()
                .ok_or(BundleWireError::BadEncoding("cmx"))?;

            let epk_bytes = array32(&mut cur)?;
            let mut enc_ciphertext = [0u8; 580];
            enc_ciphertext.copy_from_slice(take(&mut cur, 580)?);
            let mut out_ciphertext = [0u8; 80];
            out_ciphertext.copy_from_slice(take(&mut cur, 80)?);
            let spend_auth: [u8; 64] = take(&mut cur, 64)?.try_into().expect("64 bytes");

            // `Action::from_parts` rejects an identity `rk` and an identity or
            // non-canonical `epk` — the other half of the disclosure whose proof
            // half is handled by the derived length above.
            let action = Action::from_parts(
                nullifier,
                rk,
                cmx,
                TransmittedNoteCiphertext { epk_bytes, enc_ciphertext, out_ciphertext },
                cv_net,
                redpallas::Signature::<SpendAuth>::from(spend_auth),
            )
            .map_err(|_| BundleWireError::Refused)?;
            actions.push(action);
        }

        let flags = Flags::from_byte(read_u8(&mut cur)?, bundle_version())
            .ok_or(BundleWireError::BadFlags)?;
        let value_balance = i64::from_le_bytes(take(&mut cur, 8)?.try_into().expect("eight bytes"));
        let anchor = Anchor::from_bytes(array32(&mut cur)?)
            .into_option()
            .ok_or(BundleWireError::BadEncoding("anchor"))?;

        // Derived, never read from the wire.
        let proof = Proof::new(take(&mut cur, Proof::expected_proof_size(count))?.to_vec());
        let binding: [u8; 64] = take(&mut cur, 64)?.try_into().expect("64 bytes");

        if !cur.is_empty() {
            return Err(BundleWireError::TrailingBytes);
        }

        let bundle = orchard::Bundle::try_from_parts(
            NonEmpty::from_vec(actions).ok_or(BundleWireError::BadActionCount(0))?,
            flags,
            value_balance,
            anchor,
            orchard::bundle::Authorized::from_parts(proof, redpallas::Signature::from(binding)),
            bundle_version(),
        )
        .map_err(|_| BundleWireError::Refused)?;

        ShieldedBundle::new(bundle).map_err(|_| BundleWireError::Refused)
    }
}

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], BundleWireError> {
    if cur.len() < n {
        return Err(BundleWireError::Truncated);
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Ok(head)
}

fn array32(cur: &mut &[u8]) -> Result<[u8; 32], BundleWireError> {
    Ok(take(cur, 32)?.try_into().expect("32 bytes"))
}

fn read_u8(cur: &mut &[u8]) -> Result<u8, BundleWireError> {
    Ok(take(cur, 1)?[0])
}

#[cfg(test)]
pub(crate) mod tests {
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
        super::proving_key()
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
    pub(crate) fn built_bundle(value: u64, coinbase: bool) -> Bundle<Authorized, i64> {
        built_bundle_signed(value, coinbase, [0u8; 32])
    }

    /// A coinbase bundle paying `values` — one note each — signed over `sighash`.
    ///
    /// Exists so the adversarial tests can build the shape consensus must refuse:
    /// a reward split across more than one note.
    pub(crate) fn built_coinbase_notes(
        values: &[u64],
        sighash: [u8; 32],
    ) -> Bundle<Authorized, i64> {
        let mut rng = OsRng;
        let version = BundleVersion::orchard_v2();
        let fvk = FullViewingKey::from(&spending_key());
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut builder =
            Builder::new(BundleType::Coinbase, version, Flags::SPENDS_DISABLED, Anchor::empty_tree())
                .expect("coinbase flags are valid");
        for value in values {
            builder
                .add_output(None, recipient, NoteValue::from_raw(*value), [0u8; 512])
                .expect("an outputs-only bundle accepts an output");
        }
        builder
            .build::<i64>(&mut rng)
            .expect("bundle builds")
            .expect("a bundle is produced")
            .0
            .create_proof(proving_key(), &mut rng)
            .expect("proving succeeds")
            .prepare(rng, sighash)
            .finalize()
            .expect("binding signature")
    }

    /// As [`built_bundle`], but signed over a chosen sighash — what a real
    /// consensus check needs, since the signatures are what bind the bundle to
    /// its context.
    pub(crate) fn built_bundle_signed(
        value: u64,
        coinbase: bool,
        sighash: [u8; 32],
    ) -> Bundle<Authorized, i64> {
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
            .prepare(rng, sighash)
            .finalize()
            .expect("binding signature")
    }

    /// The conversion the rest of Noct depends on. A bundle says "5,000 entered
    /// the shielded pool" as `-5000`; the ring side must read that as "5,000 left
    /// the ring pool", `cross = +5000`. Reversing it would make a shielding
    /// transaction look like an unshielding one, and mint ring coins.
    #[test]
    fn a_bundle_states_its_movement_the_opposite_way_round_from_the_ring_side() {
        let b = ShieldedBundle::new(built_bundle(5_000, false)).expect("fixed circuit");
        assert_eq!(b.value_balance(), -5_000, "value entering the pool is negative");
        assert_eq!(b.cross().unwrap(), 5_000, "which is value leaving the ring pool");
    }

    /// The crossing a bundle implies must be exactly what the turnstile then
    /// applies — these are two halves of one rule and are checked together.
    #[test]
    fn the_crossing_a_bundle_implies_is_the_one_the_turnstile_applies() {
        use crate::pools::{Pool, PoolTotals};

        let b = ShieldedBundle::new(built_bundle(5_000, false)).expect("fixed circuit");
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
        let b = ShieldedBundle::new(built_bundle(9_000_000_000, true)).expect("fixed circuit");
        assert!(!b.spends_enabled(), "a block reward spends nothing");
        assert!(b.outputs_enabled(), "but it does create a note");
        assert_eq!(b.cross().unwrap(), 9_000_000_000);
    }

    /// The proof is the only evidence a node has, so verifying it must work
    /// through the shared key — and the key must be the fixed circuit's.
    #[test]
    fn a_well_formed_bundle_verifies_against_the_shared_key() {
        let b = ShieldedBundle::new(built_bundle(1, false)).expect("fixed circuit");
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
        let b = ShieldedBundle::new(built_bundle(1, false)).expect("fixed circuit");
        assert_eq!(b.inner().bundle_version().circuit_version(), CIRCUIT);
    }
}

#[cfg(test)]
mod wire_tests {
    use super::tests::{built_bundle, built_bundle_signed};
    use super::*;

    /// **The reason `verify_proof` is not enough.** `value_balance` rides beside
    /// the proof, not inside it, so a relayer can rewrite it and the proof still
    /// verifies. What catches it is the binding signature, whose validating key
    /// is derived from the balance — change the balance and there is no key any
    /// signature was made under.
    ///
    /// This is the inflation bug the coin would have had: a bundle claiming to
    /// bring in ten times what it created, minting the difference.
    #[test]
    fn rewriting_the_value_balance_leaves_the_proof_valid_and_the_binding_signature_broken() {
        let sighash = [7u8; 32];
        let honest = ShieldedBundle::new(built_bundle_signed(5_000, false, sighash))
            .expect("fixed circuit");
        assert_eq!(honest.verify(&sighash), Ok(()));

        // Rewrite the balance in place: actions ‖ flags, then the i64.
        let mut bytes = honest.to_bytes();
        let at = 2 + honest.actions() * ACTION_BYTES + 1;
        assert_eq!(
            i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()),
            -5_000,
            "the balance is where the layout says it is"
        );
        bytes[at..at + 8].copy_from_slice(&(-50_000i64).to_le_bytes());

        let forged = ShieldedBundle::from_bytes(&bytes).expect("it decodes — nothing is malformed");
        assert_eq!(forged.cross().unwrap(), 50_000, "and claims ten times the value");
        assert_eq!(forged.verify_proof(), Ok(()), "the proof does not cover the balance");
        assert_eq!(
            forged.verify(&sighash),
            Err(ShieldedError::BadBindingSignature),
            "so the binding signature is the only thing standing between this and inflation"
        );
    }

    /// A bundle authorized for one message must not verify against another. This
    /// is what stops an authorized bundle being lifted into a different
    /// transaction or a different block.
    #[test]
    fn a_bundle_does_not_verify_against_a_message_it_did_not_sign() {
        let b = ShieldedBundle::new(built_bundle_signed(5_000, false, [7u8; 32]))
            .expect("fixed circuit");
        assert_eq!(b.verify(&[7u8; 32]), Ok(()));
        assert_eq!(b.verify(&[8u8; 32]), Err(ShieldedError::BadSpendAuth));
    }

    /// The shape of a bundle on the wire, stated as a number so a change to the
    /// layout cannot pass unnoticed. 884 bytes per action, and a proof whose
    /// length comes from the action count rather than from the wire.
    #[test]
    fn the_encoding_has_the_length_its_parts_add_up_to() {
        let b = ShieldedBundle::new(built_bundle(5_000, false)).unwrap();
        let bytes = b.to_bytes();
        let expected =
            2 + b.actions() * ACTION_BYTES + 1 + 8 + 32 + Proof::expected_proof_size(b.actions()) + 64;
        assert_eq!(bytes.len(), expected);
        assert_eq!(ACTION_BYTES, 884);
    }

    /// Everything consensus reads off a bundle must survive the round trip
    /// unchanged. The value balance especially: it is the number the turnstile
    /// moves, and a bundle that decodes to a different one would move the wrong
    /// amount of money.
    #[test]
    fn a_bundle_survives_the_round_trip_intact() {
        for (value, coinbase) in [(5_000u64, false), (9_000_000_000, true), (1, false)] {
            let original = ShieldedBundle::new(built_bundle(value, coinbase)).unwrap();
            let bytes = original.to_bytes();
            let back = ShieldedBundle::from_bytes(&bytes).expect("decodes");

            assert_eq!(back.value_balance(), original.value_balance());
            assert_eq!(back.cross().unwrap(), original.cross().unwrap());
            assert_eq!(back.anchor(), original.anchor());
            assert_eq!(back.actions(), original.actions());
            assert_eq!(
                back.nullifiers().collect::<Vec<_>>(),
                original.nullifiers().collect::<Vec<_>>()
            );
            assert_eq!(back.spends_enabled(), original.spends_enabled());
            assert_eq!(back.outputs_enabled(), original.outputs_enabled());
            // And it is still a bundle whose proof verifies — the encoding did
            // not quietly corrupt the one thing a node relies on.
            assert_eq!(back.verify_proof(), Ok(()));
            // Encoding is canonical: the same bundle always produces the same
            // bytes, so two nodes hash it alike.
            assert_eq!(back.to_bytes(), bytes);
        }
    }

    /// A padded proof is the attack GHSA-2x4w-pxqw-58v9 describes: extra bytes
    /// that cost every node bandwidth and storage without changing validity.
    /// Here it is not rejected so much as unrepresentable — the decoder reads
    /// exactly as many proof bytes as the action count implies, so the padding
    /// lands where trailing bytes are refused.
    #[test]
    fn a_proof_padded_with_extra_bytes_cannot_be_expressed() {
        let b = ShieldedBundle::new(built_bundle(5_000, false)).unwrap();
        let mut padded = b.to_bytes();
        padded.extend_from_slice(&[0u8; 64]);
        assert_eq!(ShieldedBundle::from_bytes(&padded).unwrap_err(), BundleWireError::TrailingBytes);
    }

    /// Nothing may follow a complete bundle: a hidden payload that every node
    /// relays and stores is a cost imposed for free.
    #[test]
    fn trailing_bytes_are_refused() {
        let b = ShieldedBundle::new(built_bundle(1, false)).unwrap();
        let mut bytes = b.to_bytes();
        bytes.push(0);
        assert_eq!(ShieldedBundle::from_bytes(&bytes).unwrap_err(), BundleWireError::TrailingBytes);
    }

    /// Every truncation must be an error rather than a panic. This walks the
    /// whole encoding, which is the only way to be sure no field reads past its
    /// end on some length nobody thought to try.
    #[test]
    fn every_truncation_is_refused_and_never_panics() {
        let b = ShieldedBundle::new(built_bundle(1, false)).unwrap();
        let bytes = b.to_bytes();
        for cut in 0..bytes.len() {
            match ShieldedBundle::from_bytes(&bytes[..cut]) {
                Err(_) => {}
                Ok(_) => panic!("a bundle cut to {cut} bytes must not decode"),
            }
        }
        assert!(ShieldedBundle::from_bytes(&bytes).is_ok(), "the whole thing still decodes");
    }

    /// An action count of zero is not a bundle, and a count past the cap is
    /// refused on the claim alone — before the bytes behind it are read, so a
    /// four-thousand-action claim in a short message costs nothing.
    #[test]
    fn the_action_count_is_bounded_before_anything_is_read() {
        let mut zero = vec![0u8; 2];
        zero.extend_from_slice(&[0u8; 4000]);
        assert_eq!(ShieldedBundle::from_bytes(&zero).unwrap_err(), BundleWireError::BadActionCount(0));

        let mut huge = ((MAX_ACTIONS + 1) as u16).to_le_bytes().to_vec();
        huge.extend_from_slice(&[0u8; 16]); // nowhere near enough to back the claim
        assert_eq!(ShieldedBundle::from_bytes(&huge).unwrap_err(), BundleWireError::BadActionCount(MAX_ACTIONS + 1));
    }

    /// A point that is not a canonical encoding of a valid element is refused at
    /// the parser, not passed inward. `cv_net` is first in an action, so it is
    /// the one this reaches.
    #[test]
    fn a_non_canonical_point_is_refused() {
        let b = ShieldedBundle::new(built_bundle(1, false)).unwrap();
        let mut bytes = b.to_bytes();
        // All-ones is not a valid Pallas point encoding.
        for byte in bytes[2..34].iter_mut() {
            *byte = 0xff;
        }
        assert_eq!(ShieldedBundle::from_bytes(&bytes).unwrap_err(), BundleWireError::BadEncoding("cv_net"));
    }

    /// A flags byte this bundle version cannot express is refused rather than
    /// silently reinterpreted.
    #[test]
    fn unrepresentable_flags_are_refused() {
        let b = ShieldedBundle::new(built_bundle(1, false)).unwrap();
        let mut bytes = b.to_bytes();
        let flags_at = 2 + b.actions() * ACTION_BYTES;
        bytes[flags_at] = 0xff;
        assert_eq!(ShieldedBundle::from_bytes(&bytes).unwrap_err(), BundleWireError::BadFlags);
    }

    /// The proof length the decoder derives comes from the crate's own
    /// constants. If those ever drift, Noct's wire format silently changes
    /// meaning — so the numbers are pinned here, where a change is loud.
    #[test]
    fn the_derived_proof_length_is_pinned() {
        assert_eq!(Proof::expected_proof_size(1), 4_992);
        assert_eq!(Proof::expected_proof_size(2), 7_264);
    }

    /// Corrupting the proof must not decode into a bundle that then claims to
    /// verify. The length is right, so this gets past the parser and has to be
    /// caught by the proof check — which is exactly the division of labour
    /// intended.
    #[test]
    fn a_corrupted_proof_decodes_but_does_not_verify() {
        let b = ShieldedBundle::new(built_bundle(1, false)).unwrap();
        let mut bytes = b.to_bytes();
        let proof_at = 2 + b.actions() * ACTION_BYTES + 1 + 8 + 32;
        bytes[proof_at] ^= 0x01;
        // Asserted rather than tolerated: the parser checks the proof's length,
        // not its content, so this must get through and be caught by the proof
        // check. A test that accepted either outcome could pass while the
        // decoder silently rejected everything.
        let decoded = ShieldedBundle::from_bytes(&bytes)
            .expect("the length is unchanged, so the parser has nothing to object to");
        assert_eq!(decoded.verify_proof(), Err(ShieldedError::BadProof));
    }
}
