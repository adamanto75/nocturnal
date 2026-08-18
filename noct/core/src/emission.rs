//! Layer 7 — emission curve (monetary policy).
//!
//! Noct emits coins with a Monero-style smoothly-decreasing subsidy plus a
//! constant tail. Each block's *base* subsidy is a fixed-shift fraction of the
//! yet-to-be-emitted supply:
//!
//! ```text
//!     base = (MONEY_SUPPLY − already_emitted) >> EMISSION_SPEED_FACTOR
//! ```
//!
//! so the reward halves-ish geometrically as coins are mined, until it falls to
//! the [`TAIL_EMISSION`] floor, which then continues forever (keeping mining
//! incentivised once the smooth phase ends). A block's coinbase pays
//! `base_reward + transaction fees`.
//!
//! All amounts are in **atomic units**; `1 NOCT = 10^12 atomic` ([`ATOMIC_UNITS`]).
//!
//! Noct's smooth phase asymptotes to [`MONEY_SUPPLY`] ≈ 1,000,000 NOCT. Half of
//! that is minted up front as the genesis **premine** (see
//! [`crate::block::PREMINE_AMOUNT`]); the emission curve continues from that
//! premined baseline, so the remaining ~500,000 NOCT is mined out before the
//! tail. These constants are still tunable before the network goes live.

/// Atomic units per whole coin (12 decimals, like Monero).
pub const ATOMIC_UNITS: u64 = 1_000_000_000_000;

/// The supply parameter driving the emission formula: the asymptote of the
/// smooth phase (the tail then carries emission past it). ~1,000,000 NOCT.
pub const MONEY_SUPPLY: u64 = 1_000_000 * ATOMIC_UNITS;

/// Right-shift applied to the remaining supply each block. Larger = slower.
pub const EMISSION_SPEED_FACTOR: u32 = 20;

/// The perpetual per-block tail subsidy (0.03 NOCT) once the smooth phase ends.
/// Scaled to the 1M supply (roughly Monero's tail-to-supply ratio).
pub const TAIL_EMISSION: u64 = 30_000_000_000;

/// The base block subsidy given `already_emitted` atomic units mined so far
/// (excluding fees). Never below [`TAIL_EMISSION`].
pub fn base_reward(already_emitted: u64) -> u64 {
    let smooth = MONEY_SUPPLY.saturating_sub(already_emitted) >> EMISSION_SPEED_FACTOR;
    smooth.max(TAIL_EMISSION)
}

/// The full coinbase amount a miner may claim at a block: base subsidy + fees.
/// Returns `None` on overflow (a malformed fee total).
pub fn block_reward(already_emitted: u64, total_fees: u64) -> Option<u64> {
    base_reward(already_emitted).checked_add(total_fees)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_reward_is_the_full_shift() {
        // With nothing emitted, base = MONEY_SUPPLY >> factor.
        assert_eq!(base_reward(0), MONEY_SUPPLY >> EMISSION_SPEED_FACTOR);
        assert!(base_reward(0) > TAIL_EMISSION);
    }

    #[test]
    fn reward_decreases_monotonically() {
        // Sample points inside the ~1M supply so the smooth term is still above
        // the tail (past the asymptote every reward would just be the tail).
        let a = base_reward(0);
        let b = base_reward(100_000 * ATOMIC_UNITS);
        let c = base_reward(400_000 * ATOMIC_UNITS);
        assert!(a > b, "reward should fall as coins are emitted");
        assert!(b > c);
        assert!(c > TAIL_EMISSION);
    }

    #[test]
    fn tail_emission_is_the_floor() {
        // Once the smooth part drops below the tail, the tail holds.
        assert_eq!(base_reward(u64::MAX), TAIL_EMISSION);
        // And a point deep into emission where smooth < tail.
        let deep = MONEY_SUPPLY - (TAIL_EMISSION << EMISSION_SPEED_FACTOR) / 2;
        assert_eq!(base_reward(deep), TAIL_EMISSION);
    }

    #[test]
    fn block_reward_adds_fees() {
        assert_eq!(block_reward(0, 5).unwrap(), base_reward(0) + 5);
        assert_eq!(block_reward(u64::MAX, 0).unwrap(), TAIL_EMISSION);
        // Overflow is reported, not wrapped.
        assert_eq!(block_reward(0, u64::MAX), None);
    }
}

#[cfg(test)]
mod economics {
    use super::*;

    /// **The question that matters: can the smooth phase mint more than the
    /// supply parameter?**
    ///
    /// Answered by simulation rather than argument, because the argument
    /// ("each block takes a fraction of what is left, so it asymptotes") is
    /// exactly the kind of reasoning that stays convincing after someone changes
    /// a constant and makes it false. This walks the entire smooth phase, block
    /// by block, and checks the invariant at every step.
    ///
    /// The tail deliberately carries emission *past* `MONEY_SUPPLY` afterwards —
    /// that is Monero's design and it is intentional here — so the invariant is
    /// specifically about the smooth phase.
    #[test]
    fn the_smooth_phase_never_mints_more_than_the_supply_parameter() {
        let mut emitted: u64 = 0;
        let mut blocks: u64 = 0;
        let mut previous = u64::MAX;

        loop {
            let reward = base_reward(emitted);
            if reward <= TAIL_EMISSION {
                break; // the smooth phase is over
            }
            // The subsidy must never rise: a curve that went back up would mean
            // mining late paid better than mining early, and would break every
            // assumption about the schedule.
            assert!(reward <= previous, "subsidy rose at block {blocks}: {previous} -> {reward}");
            previous = reward;

            emitted = emitted.checked_add(reward).expect("emission overflowed u64");
            assert!(
                emitted <= MONEY_SUPPLY,
                "smooth phase minted {emitted} > MONEY_SUPPLY {MONEY_SUPPLY} at block {blocks}"
            );
            blocks += 1;
            assert!(blocks < 50_000_000, "smooth phase did not terminate");
        }

        // Sanity on the shape: it should take millions of blocks, not a handful
        // (which would mean the shift is wrong and the coin front-loads).
        assert!(blocks > 1_000_000, "smooth phase ended after only {blocks} blocks");
        // And it should end close under the asymptote, not far short of it.
        let pct = (emitted as f64) * 100.0 / (MONEY_SUPPLY as f64);
        assert!(pct > 90.0, "smooth phase only reached {pct:.1}% of the supply parameter");
        eprintln!("[emission] smooth phase: {blocks} blocks, {pct:.2}% of MONEY_SUPPLY, then tail");
    }

    /// The premine is part of emission, not additional to it — so the curve
    /// simply continues from that baseline and the total is unchanged.
    ///
    /// Pins the first mined block's reward to the value the live chain actually
    /// pays, which is what ties this constant to observed behaviour rather than
    /// to a comment.
    #[test]
    fn the_premine_is_inside_the_curve_not_on_top_of_it() {
        use crate::block::PREMINE_AMOUNT;
        assert_eq!(PREMINE_AMOUNT, MONEY_SUPPLY / 2, "premine is half the supply parameter");

        // What a miner is paid for the block right after genesis.
        assert_eq!(base_reward(PREMINE_AMOUNT), 476_837_158_203);

        // Emission from a premined baseline must still respect the asymptote.
        let mut emitted = PREMINE_AMOUNT;
        let mut blocks = 0u64;
        loop {
            let reward = base_reward(emitted);
            if reward <= TAIL_EMISSION {
                break;
            }
            emitted += reward;
            assert!(emitted <= MONEY_SUPPLY, "premined curve exceeded the supply parameter");
            blocks += 1;
            assert!(blocks < 50_000_000);
        }
        eprintln!("[emission] with premine: {blocks} more blocks to the tail");
    }

    /// No input may panic, wrap, or produce a subsidy outside its bounds —
    /// including values past the supply parameter, which the tail reaches in
    /// normal operation.
    #[test]
    fn the_subsidy_is_bounded_at_every_input() {
        let ceiling = MONEY_SUPPLY >> EMISSION_SPEED_FACTOR;
        for emitted in [
            0,
            1,
            TAIL_EMISSION,
            MONEY_SUPPLY / 2,
            MONEY_SUPPLY - 1,
            MONEY_SUPPLY,
            MONEY_SUPPLY + 1,
            MONEY_SUPPLY * 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let r = base_reward(emitted);
            assert!(r >= TAIL_EMISSION, "subsidy {r} fell below the tail at emitted={emitted}");
            assert!(r <= ceiling, "subsidy {r} exceeded the genesis subsidy at emitted={emitted}");
        }

        // Past the supply parameter the answer is exactly the tail — this is the
        // `saturating_sub` doing its job; a plain subtraction would underflow to
        // a colossal remainder and mint an enormous subsidy.
        assert_eq!(base_reward(MONEY_SUPPLY), TAIL_EMISSION);
        assert_eq!(base_reward(u64::MAX), TAIL_EMISSION);

        // Fees on top must never wrap into a small number.
        assert_eq!(block_reward(0, u64::MAX), None);
        assert_eq!(block_reward(MONEY_SUPPLY, 5), Some(TAIL_EMISSION + 5));
    }
}
