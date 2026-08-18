//! Per-miner share difficulty ("vardiff").
//!
//! A single fixed share target cannot suit every miner. Too low and a fast rig
//! submits hundreds of shares a second — pointless work for the pool, which
//! re-hashes each one, and enough to spend its whole rate-limit budget while
//! behaving perfectly honestly. Too high and a slow rig may find nothing at all
//! within the PPLNS window and earn nothing for real work.
//!
//! Vardiff gives each miner its own target, retuned so that everyone submits at
//! roughly the same comfortable rate — one share every [`VardiffParams::target_secs`].
//!
//! ## Why this does not change what anyone is paid
//!
//! A share's weight in the payout split is the difficulty **in force when it was
//! accepted**, not a count of shares. A miner at difficulty 4000 submitting one
//! share is credited exactly as much as a miner at 1000 submitting four. So
//! retuning a target changes how often work is *reported*, never how much it is
//! *worth* — which is the property that makes vardiff safe to apply per miner.
//!
//! ## Shape of the controller
//!
//! Deliberately a damped proportional step, not something cleverer:
//!
//! * scale by `observed / target`, so a miner submitting twice too fast has its
//!   difficulty doubled;
//! * clamp each move to [`VardiffParams::max_step`], so one unlucky gap cannot
//!   fling a miner to a target it will never hit;
//! * clamp the result into `[min, max]`.
//!
//! Share-finding is a Poisson process: intervals vary wildly even at a perfectly
//! tuned difficulty. An undamped controller chasing each sample would oscillate,
//! which is worse for the miner than being slightly mistuned.

use noct_core::pow::Difficulty;

/// Tuning for the retarget controller.
#[derive(Clone, Copy, Debug)]
pub struct VardiffParams {
    /// Seconds between shares we aim each miner at. Short enough that the pool
    /// sees work steadily (and a miner sees progress), long enough that share
    /// traffic stays negligible.
    pub target_secs: f64,
    /// Never retarget below this; a floor keeps a trivially small target from
    /// letting one miner flood the pool.
    pub min: Difficulty,
    /// Never retarget above this.
    pub max: Difficulty,
    /// Largest multiplicative move in one retarget, up or down.
    pub max_step: f64,
}

impl Default for VardiffParams {
    fn default() -> Self {
        VardiffParams {
            target_secs: 15.0,
            min: 100,
            max: 1 << 40,
            max_step: 4.0,
        }
    }
}

/// The difficulty to issue next, given how long this miner actually took to find
/// its recent share(s).
///
/// `observed_secs` is the average interval between that miner's recent shares.
/// Returns `current` unchanged when there is nothing to go on.
pub fn retarget(current: Difficulty, observed_secs: f64, p: &VardiffParams) -> Difficulty {
    // No usable sample: a non-finite or negative interval means the caller has
    // not measured anything yet. Changing difficulty on no evidence is worse
    // than leaving it alone.
    if !observed_secs.is_finite() || observed_secs < 0.0 {
        return clamp(current, p);
    }

    // Shares arriving faster than the target mean the difficulty is too low, so
    // scale it up in proportion, and vice versa.
    //
    // An observed interval of exactly zero (two shares within the clock's
    // resolution) is a real signal that the target is far too low, so it takes
    // the largest permitted step up rather than dividing by zero.
    let ratio = if observed_secs <= f64::EPSILON {
        p.max_step
    } else {
        (p.target_secs / observed_secs).clamp(1.0 / p.max_step, p.max_step)
    };

    // `current` can be large; go through f64 and saturate rather than wrapping.
    let scaled = (current as f64) * ratio;
    let next = if scaled >= Difficulty::MAX as f64 {
        Difficulty::MAX
    } else if scaled < 1.0 {
        1
    } else {
        scaled.round() as Difficulty
    };
    clamp(next, p)
}

fn clamp(d: Difficulty, p: &VardiffParams) -> Difficulty {
    // A caller could hand us min > max; prefer the floor, since too-easy is a
    // pool-load problem while too-hard silently starves a miner of all credit.
    d.max(p.min).min(p.max.max(p.min))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> VardiffParams {
        VardiffParams { target_secs: 15.0, min: 100, max: 1_000_000, max_step: 4.0 }
    }

    /// A miner submitting exactly on target should be left alone. A controller
    /// that fidgets when nothing is wrong only adds noise.
    #[test]
    fn a_miner_on_target_is_left_alone() {
        assert_eq!(retarget(1_000, 15.0, &p()), 1_000);
    }

    /// The case that motivates the whole module: a fast rig at a low target
    /// floods the pool and burns its rate-limit budget. Raise its difficulty.
    #[test]
    fn a_fast_miner_is_made_to_work_harder() {
        // Four times too fast → four times the difficulty.
        assert_eq!(retarget(1_000, 15.0 / 4.0, &p()), 4_000);
        // Twice too fast → twice.
        assert_eq!(retarget(1_000, 7.5, &p()), 2_000);
    }

    /// And the converse: a slow rig that would otherwise earn nothing inside the
    /// window gets an easier target.
    #[test]
    fn a_slow_miner_is_given_an_easier_target() {
        assert_eq!(retarget(4_000, 60.0, &p()), 1_000);
    }

    /// One unlucky gap must not fling a miner somewhere it can never return
    /// from. Share intervals are Poisson — long gaps happen at a perfectly good
    /// difficulty.
    #[test]
    fn a_single_wild_sample_cannot_move_it_far() {
        let params = p();
        // An hour with no share: still only one max_step down.
        assert_eq!(retarget(100_000, 3_600.0, &params), 100_000 / 4);
        // Two shares inside the clock's resolution: only one max_step up.
        assert_eq!(retarget(1_000, 0.0, &params), 4_000);
    }

    /// Bounds are bounds, including when the caller passes nonsense.
    #[test]
    fn the_result_stays_inside_its_bounds() {
        let params = p();
        // Would fall below the floor.
        assert_eq!(retarget(params.min, 10_000.0, &params), params.min);
        // Would rise above the ceiling.
        assert_eq!(retarget(params.max, 0.001, &params), params.max);
        // Absurd inputs must not panic or produce something unusable.
        for bad in [f64::NAN, f64::INFINITY, -1.0, -0.0] {
            let d = retarget(1_000, bad, &params);
            assert!((params.min..=params.max).contains(&d), "{bad} produced {d}");
        }
    }

    /// Huge difficulties must saturate, never wrap — a wrapped value would hand a
    /// miner a trivial target and let it flood the pool.
    #[test]
    fn extreme_difficulties_saturate_rather_than_wrap() {
        let params = VardiffParams { max: Difficulty::MAX, ..p() };
        let d = retarget(Difficulty::MAX, 0.001, &params);
        assert_eq!(d, Difficulty::MAX, "must saturate at the top");
        let d = retarget(1, 100_000.0, &params);
        assert!(d >= params.min, "must not underflow below the floor");
    }

    /// Repeatedly applying the controller to a miner whose true rate is fixed
    /// must converge, not oscillate. This is the property the damping exists for.
    #[test]
    fn it_converges_on_a_steady_miner() {
        let params = p();
        // A miner whose hashrate finds difficulty 8_000 in exactly 15s. At any
        // other difficulty d, its observed interval is 15 * d / 8000.
        let mut d: Difficulty = 100;
        for _ in 0..20 {
            let observed = 15.0 * (d as f64) / 8_000.0;
            d = retarget(d, observed, &params);
        }
        let drift = (d as f64 - 8_000.0).abs() / 8_000.0;
        assert!(drift < 0.01, "settled at {d}, expected ~8000");
    }
}
