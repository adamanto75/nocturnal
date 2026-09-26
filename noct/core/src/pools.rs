//! The two value pools, and the rule that keeps a bug in one from reaching the
//! other.
//!
//! Noct holds value in two places: the **ring pool** (RingCT outputs, CLSAG,
//! Bulletproofs+) and the **shielded pool** (Orchard notes, Halo 2). A coin is
//! in exactly one of them at a time, and a transaction may move value across.
//!
//! Everything about a coin inside a pool is private. The **amount that crosses
//! between pools is not** — it cannot be, because the two pools prove balance by
//! different means and the only thing that can reconcile them is a number both
//! can read. That is a real privacy cost, stated here rather than buried:
//! shielding X and later unshielding X links the two events.
//!
//! What the public number buys is containment. Each pool's supply is tracked,
//! and **neither total may ever go below zero**. If the Orchard circuit, or our
//! use of it, ever allows a forged proof, the damage stops at the shielded
//! total: value cannot be taken out of a pool that does not hold it, so
//! ring-pool coins cannot be minted from a shielded-side break. The same holds
//! in the other direction. Zcash adopted this rule after real inflation bugs,
//! and it is the cheapest insurance in the design.
//!
//! This module is deliberately arithmetic only: no proofs, no keys, no chain.
//! The rule is simple enough to read in one sitting, which is the point.

use std::fmt;

/// Which pool value is held in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// RingCT outputs: the pool Noct launched with.
    Ring,
    /// Orchard notes.
    Shielded,
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Pool::Ring => "ring",
            Pool::Shielded => "shielded",
        })
    }
}

/// Why a movement was refused.
///
/// Every variant carries what it needs to be reported without consulting
/// anything else: a rejection that cannot be explained is one nobody can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnstileError {
    /// The movement would take more out of a pool than it holds. **This is the
    /// error the whole module exists for.**
    Underflow { pool: Pool, held: u64, taking: u64 },
    /// The movement would push a pool above what a `u64` can hold, which means
    /// more than the entire supply and therefore a bug upstream.
    Overflow { pool: Pool, held: u64, adding: u64 },
    /// `i64::MIN` has no positive counterpart, so it cannot be a movement.
    NotRepresentable,
}

impl fmt::Display for TurnstileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TurnstileError::Underflow { pool, held, taking } => write!(
                f,
                "turnstile: taking {taking} from the {pool} pool, which holds {held}"
            ),
            TurnstileError::Overflow { pool, held, adding } => {
                write!(f, "turnstile: adding {adding} to the {pool} pool, which holds {held}")
            }
            TurnstileError::NotRepresentable => {
                f.write_str("turnstile: movement is not a representable amount")
            }
        }
    }
}

impl std::error::Error for TurnstileError {}

/// How much value each pool holds.
///
/// Consensus state: every node computes it, and two nodes that disagree about it
/// are on different chains. It is `Copy` and eight bytes wider than nothing,
/// so an undo record can simply keep the previous value rather than trying to
/// invert a movement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolTotals {
    ring: u64,
    shielded: u64,
}

impl PoolTotals {
    pub const fn new() -> Self {
        PoolTotals { ring: 0, shielded: 0 }
    }

    pub const fn ring(&self) -> u64 {
        self.ring
    }

    pub const fn shielded(&self) -> u64 {
        self.shielded
    }

    /// What the two pools hold together.
    ///
    /// This must equal the chain's emitted supply at every height. Nothing here
    /// enforces that — the chain does — but it is the check worth writing at
    /// every seam, because a drift between the two means value was created or
    /// destroyed somewhere that nobody is looking.
    pub fn total(&self) -> Option<u64> {
        self.ring.checked_add(self.shielded)
    }

    /// Value created into a pool: a block reward, or the genesis premine.
    pub fn mint(&mut self, pool: Pool, amount: u64) -> Result<(), TurnstileError> {
        let held = self.get(pool);
        let sum = held
            .checked_add(amount)
            .ok_or(TurnstileError::Overflow { pool, held, adding: amount })?;
        self.set(pool, sum);
        Ok(())
    }

    /// Apply a transaction's cross-pool movement.
    ///
    /// `cross` is stated from the **ring pool's** point of view, matching the
    /// field a transaction carries: positive means that much left the ring pool
    /// and appeared in the shielded pool (a shielding transaction), negative
    /// means the reverse. Zero is the overwhelmingly common case — an ordinary
    /// transaction within one pool — and must be free.
    ///
    /// Either direction can be refused, and the refusal is the feature.
    pub fn apply_cross(&mut self, cross: i64) -> Result<(), TurnstileError> {
        match cross {
            0 => Ok(()),
            // `-i64::MIN` overflows, so it can never be turned into an amount.
            // A transaction carrying it is malformed rather than merely large.
            i64::MIN => Err(TurnstileError::NotRepresentable),
            c if c > 0 => {
                let amount = c as u64;
                self.take(Pool::Ring, amount)?;
                // If this fails the taking above must not stand, so the mint is
                // attempted on a copy first and committed only together.
                self.mint(Pool::Shielded, amount).inspect_err(|_| {
                    self.ring += amount;
                })
            }
            c => {
                let amount = c.unsigned_abs();
                self.take(Pool::Shielded, amount)?;
                self.mint(Pool::Ring, amount).inspect_err(|_| {
                    self.shielded += amount;
                })
            }
        }
    }

    /// Remove value from a pool, refusing to take more than it holds.
    fn take(&mut self, pool: Pool, amount: u64) -> Result<(), TurnstileError> {
        let held = self.get(pool);
        let left = held
            .checked_sub(amount)
            .ok_or(TurnstileError::Underflow { pool, held, taking: amount })?;
        self.set(pool, left);
        Ok(())
    }

    fn get(&self, pool: Pool) -> u64 {
        match pool {
            Pool::Ring => self.ring,
            Pool::Shielded => self.shielded,
        }
    }

    fn set(&mut self, pool: Pool, value: u64) {
        match pool {
            Pool::Ring => self.ring = value,
            Pool::Shielded => self.shielded = value,
        }
    }
}

/// How a cross-pool movement enters the ring pool's balance equation.
///
/// The ring pool already proves balance against a public fee:
///
/// ```text
/// Σ pseudo-outs == Σ output commitments + fee·H
/// ```
///
/// A cross-pool amount is a second public term in that same equation, and the
/// side it lands on is the whole of the arithmetic. Value **leaving** the ring
/// pool is spent like a fee is spent — it joins the right-hand side. Value
/// **entering** the ring pool was not consumed from any ring output, so it joins
/// the left, exactly as a coinbase's subsidy would.
///
/// Returns `(add_to_inputs_side, add_to_outputs_side)`.
pub fn cross_terms(cross: i64) -> Result<(u64, u64), TurnstileError> {
    match cross {
        0 => Ok((0, 0)),
        i64::MIN => Err(TurnstileError::NotRepresentable),
        c if c > 0 => Ok((0, c as u64)),
        c => Ok((c.unsigned_abs(), 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_crossing_leaves_the_total_alone() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Ring, 1_000).unwrap();
        let before = t.total().unwrap();

        t.apply_cross(400).unwrap();
        assert_eq!((t.ring(), t.shielded()), (600, 400));
        assert_eq!(t.total().unwrap(), before, "crossing must not create or destroy value");

        t.apply_cross(-250).unwrap();
        assert_eq!((t.ring(), t.shielded()), (850, 150));
        assert_eq!(t.total().unwrap(), before);
    }

    /// The rule the module exists for: a pool cannot pay out what it does not
    /// hold. A forged shielded proof claiming to unshield more than the shielded
    /// pool contains is stopped here, whatever the proof says.
    #[test]
    fn a_pool_cannot_pay_out_more_than_it_holds() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Ring, 100).unwrap();
        t.apply_cross(60).unwrap(); // ring 40, shielded 60

        let err = t.apply_cross(-61).expect_err("unshielding 61 from 60 must be refused");
        assert_eq!(err, TurnstileError::Underflow { pool: Pool::Shielded, held: 60, taking: 61 });

        let err = t.apply_cross(41).expect_err("shielding 41 from 40 must be refused");
        assert_eq!(err, TurnstileError::Underflow { pool: Pool::Ring, held: 40, taking: 41 });
    }

    /// A refused movement must leave the totals exactly as they were. A
    /// half-applied turnstile would be worse than none: it would quietly move
    /// value out of one pool without putting it in the other.
    #[test]
    fn a_refused_movement_changes_nothing() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Ring, 100).unwrap();
        t.apply_cross(60).unwrap();
        let before = t;

        for bad in [-61, 41, i64::MIN] {
            let _ = t.apply_cross(bad);
            assert_eq!(t, before, "refusing {bad} must not have moved anything");
        }
    }

    /// The failure that would be invisible: taking succeeds and minting
    /// overflows, leaving value destroyed. Contrived — it needs a pool near
    /// `u64::MAX` — but the rollback is what makes it not matter.
    #[test]
    fn an_overflowing_mint_rolls_back_the_take() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Ring, 10).unwrap();
        t.mint(Pool::Shielded, u64::MAX - 5).unwrap();
        let before = t;

        let err = t.apply_cross(6).expect_err("the shielded side cannot hold 6 more");
        assert!(matches!(err, TurnstileError::Overflow { pool: Pool::Shielded, .. }));
        assert_eq!(t, before, "the ring side must not have been debited");
    }

    /// `i64::MIN` has no positive counterpart, so it is not an amount at all.
    /// Negating it would panic in debug and wrap in release — the wrap being the
    /// dangerous one, since it would read as a movement of zero.
    #[test]
    fn the_unnegatable_amount_is_refused_rather_than_wrapped() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Shielded, 1_000).unwrap();
        assert_eq!(t.apply_cross(i64::MIN), Err(TurnstileError::NotRepresentable));
        assert_eq!(cross_terms(i64::MIN), Err(TurnstileError::NotRepresentable));
    }

    /// An ordinary transaction inside one pool moves nothing, and must not be
    /// able to fail: this path runs on every transaction on the chain.
    #[test]
    fn a_transaction_within_one_pool_is_free() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Ring, 7).unwrap();
        let before = t;
        assert_eq!(t.apply_cross(0), Ok(()));
        assert_eq!(t, before);
        assert_eq!(cross_terms(0), Ok((0, 0)));
    }

    /// Which side of the balance equation a crossing lands on. Getting this
    /// backwards would let a shielding transaction mint ring coins, so it is
    /// pinned rather than left to the reader.
    #[test]
    fn a_crossing_lands_on_the_side_that_makes_it_cost_something() {
        // Leaving the ring pool is spent like a fee: right-hand side.
        assert_eq!(cross_terms(500), Ok((0, 500)));
        // Entering the ring pool was never consumed from a ring output: it joins
        // the inputs side, as a subsidy does.
        assert_eq!(cross_terms(-500), Ok((500, 0)));
    }

    /// Minting is how a block reward and the premine enter a pool, so both pools
    /// must accept it and the total must follow.
    #[test]
    fn minting_credits_the_named_pool_only() {
        let mut t = PoolTotals::new();
        t.mint(Pool::Shielded, 50_000).unwrap();
        assert_eq!((t.ring(), t.shielded()), (0, 50_000));
        t.mint(Pool::Ring, 1).unwrap();
        assert_eq!((t.ring(), t.shielded()), (1, 50_000));
        assert_eq!(t.total().unwrap(), 50_001);
    }
}
