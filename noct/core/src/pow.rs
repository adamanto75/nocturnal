//! Layer 7 — proof of work & difficulty adjustment.
//!
//! The PoW *function* is abstracted behind the [`ProofOfWork`] trait so the rest
//! of the chain never hard-codes it. Noct will use **RandomX** (Monero's
//! ASIC-resistant, CPU-friendly PoW) via FFI bindings; that lands near testnet.
//! Until then [`KeccakPow`] is a stand-in so blocks, mining, and difficulty are
//! fully testable now.
//!
//! A hash "meets" a difficulty when, interpreting the 32-byte hash as a
//! little-endian 256-bit integer `h`, `h · difficulty < 2^256` — equivalently
//! `h ≤ ⌊(2^256−1) / difficulty⌋`. So difficulty `d` means roughly one in `d`
//! hashes qualify. This is Monero's `check_hash`, implemented without bigints by
//! multiplying the 256-bit hash by the 64-bit difficulty and checking nothing
//! carries past 256 bits.

use crate::hash::keccak256;

/// Per-block difficulty. Cumulative chain work is tracked as `u128`.
pub type Difficulty = u64;

/// Target seconds between blocks (2 minutes).
pub const TARGET_BLOCK_TIME: u64 = 120;

/// Number of recent blocks the difficulty retarget averages over.
pub const DIFFICULTY_WINDOW: usize = 720;

/// The smallest difficulty the retarget will return.
pub const MIN_DIFFICULTY: Difficulty = 1;

/// The maximum per-block difficulty change factor (up or down). Bounds the
/// retarget so a burst of fast (or slow) blocks cannot swing difficulty wildly
/// in a single step.
pub const MAX_DIFFICULTY_STEP: u64 = 2;

/// How many of the most recent blocks the retarget ignores. Timestamps near the
/// tip are the easiest for a miner to manipulate (and the least settled), so the
/// window is taken from further back — Monero's "lag".
pub const DIFFICULTY_LAG: usize = 15;

/// How many outlier timestamps to discard from *each* end of the sorted window.
/// A miner who lies about their timestamp — high or low — lands in the trimmed
/// tail and cannot move the retarget at all.
pub const DIFFICULTY_CUT: usize = 60;

/// Number of blocks a RandomX-style seed (epoch key) stays fixed. Must be a
/// power of two. The PoW dataset is expensive to build, so it only rotates once
/// per epoch; rotating at all stops miners precomputing it forever.
pub const RANDOMX_EPOCH_BLOCKS: u64 = 2048;

/// Lag before a seed takes effect, so the seed block is deeply confirmed (and its
/// hash cannot be ground by a miner racing the epoch boundary).
pub const RANDOMX_EPOCH_LAG: u64 = 64;

/// The height whose block hash keys the PoW for a block at `height`.
///
/// Constant within an epoch, stepping every [`RANDOMX_EPOCH_BLOCKS`] with
/// [`RANDOMX_EPOCH_LAG`] blocks of lag — Monero's `rx_seedheight`. Seedless PoW
/// ([`KeccakPow`]) ignores this entirely.
pub fn randomx_seed_height(height: u64) -> u64 {
    if height <= RANDOMX_EPOCH_BLOCKS + RANDOMX_EPOCH_LAG {
        0
    } else {
        (height - RANDOMX_EPOCH_LAG - 1) & !(RANDOMX_EPOCH_BLOCKS - 1)
    }
}

/// One independent hashing worker for a mining thread: a boxed closure that maps
/// a block hashing-blob to its PoW hash. Each is used by exactly one thread, so a
/// set of them hashes in parallel with no shared lock. See
/// [`ProofOfWork::mining_hashers`].
pub type Hasher = Box<dyn Fn(&[u8]) -> [u8; 32] + Send>;

/// A proof-of-work hash function over an arbitrary block hashing-blob.
pub trait ProofOfWork {
    /// The 32-byte PoW hash of `blob`.
    fn pow_hash(&self, blob: &[u8]) -> [u8; 32];

    /// Rekey the function to the epoch `seed` (a past block hash) before hashing
    /// blocks in that epoch. The default is a no-op: seedless functions like
    /// [`KeccakPow`] don't rotate. RandomX rebuilds (and caches) its VM per seed.
    fn reseed(&self, _seed: &[u8; 32]) {}

    /// Produce `count` independent hashers keyed to `seed`, one per mining
    /// thread, each safe to call concurrently on its own thread.
    ///
    /// The default returns `count` reseeded clones — correct and lock-free for a
    /// stateless function like [`KeccakPow`], where a clone shares no mutable
    /// state. RandomX **overrides** this so each thread gets its own VM over a
    /// single shared dataset; without that, all threads would contend on one VM
    /// mutex and multi-threading would buy nothing.
    fn mining_hashers(&self, seed: &[u8; 32], count: usize) -> Vec<Hasher>
    where
        Self: Sized + Clone + Send + 'static,
    {
        (0..count.max(1))
            .map(|_| {
                let p = self.clone();
                p.reseed(seed);
                Box::new(move |blob: &[u8]| p.pow_hash(blob)) as Hasher
            })
            .collect()
    }
}

/// Placeholder PoW: plain Keccak-256. **Not** ASIC-resistant — a stand-in for
/// RandomX until the FFI bindings are wired in. Do not ship to mainnet.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakPow;

impl ProofOfWork for KeccakPow {
    fn pow_hash(&self, blob: &[u8]) -> [u8; 32] {
        keccak256(blob)
    }
}

/// Does `hash` (as a little-endian 256-bit integer) satisfy `difficulty`?
///
/// True iff `hash · difficulty < 2^256`. Difficulty `0` is treated as trivially
/// satisfiable.
pub fn check_hash(hash: &[u8; 32], difficulty: Difficulty) -> bool {
    if difficulty <= 1 {
        return true;
    }
    let d = difficulty as u128;
    // Multiply the 256-bit little-endian hash by `d`, word by word, tracking the
    // carry. If any carry remains past the top 64-bit word, the product needed a
    // 5th word — i.e. it reached 2^256 — so the hash does not meet difficulty.
    let mut carry: u128 = 0;
    for i in 0..4 {
        let word = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap()) as u128;
        let product = word * d + carry;
        carry = product >> 64; // high half feeds the next word
    }
    carry == 0
}

/// The next block's difficulty, from the `timestamps` and `cumulative_difficulties`
/// of the preceding blocks (parallel slices, oldest→newest).
///
/// Averages over the most recent [`DIFFICULTY_WINDOW`] blocks:
/// `next = total_work · TARGET_BLOCK_TIME / elapsed_time`. Faster-than-target
/// blocks raise difficulty; slower ones lower it.
///
/// Block timestamps are miner-chosen and therefore adversarial. Three defences,
/// applied in order:
///
/// 1. **Lag** — the newest [`DIFFICULTY_LAG`] blocks are excluded, so the
///    retarget never leans on the least-settled tips.
/// 2. **Outlier trim** — the window's timestamps are sorted and
///    [`DIFFICULTY_CUT`] are discarded from each end (once the window is large
///    enough to afford it), so a miner who lies high or low lands in the
///    discarded tail and moves nothing.
/// 3. **Step clamp** — the result may change by at most
///    [`MAX_DIFFICULTY_STEP`]× per block, which damps volatility and stops a run
///    of near-instant timestamps from compounding difficulty to an unmineable
///    value.
///
/// Work is taken over the same index range as the trimmed timestamps. Because
/// the timestamps are sorted while the cumulative-difficulty series is not, this
/// pairs a robust *time* estimate with the chronological *work* of a comparable
/// span — the same trade Monero makes.
pub fn next_difficulty(timestamps: &[u64], cumulative_difficulties: &[u128]) -> Difficulty {
    debug_assert_eq!(timestamps.len(), cumulative_difficulties.len());
    let n = timestamps.len();
    if n < 2 {
        return MIN_DIFFICULTY;
    }

    // 1. Lag: drop the newest blocks (only if that still leaves a usable window).
    let end = if n > DIFFICULTY_LAG + 1 { n - DIFFICULTY_LAG } else { n };
    let start = end.saturating_sub(DIFFICULTY_WINDOW);
    let window_ts = &timestamps[start..end];
    let window_cum = &cumulative_difficulties[start..end];
    let length = window_ts.len();
    if length < 2 {
        return MIN_DIFFICULTY;
    }

    // 2. Outlier trim: sort, then cut from both ends when the window is full
    //    enough that `keep` samples remain.
    let mut sorted = window_ts.to_vec();
    sorted.sort_unstable();
    let keep = DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT;
    let (cut_begin, cut_end) = if length <= keep {
        (0, length)
    } else {
        let begin = (length - keep + 1) / 2;
        (begin, begin + keep)
    };

    let time_span = sorted[cut_end - 1].saturating_sub(sorted[cut_begin]).max(1) as u128;
    let total_work = window_cum[cut_end - 1] - window_cum[cut_begin];
    let raw = total_work.saturating_mul(TARGET_BLOCK_TIME as u128) / time_span;

    // 3. Step clamp, relative to the previous block's difficulty.
    let last = cumulative_difficulties[n - 1] - cumulative_difficulties[n - 2];
    let lo = (last / MAX_DIFFICULTY_STEP as u128).max(MIN_DIFFICULTY as u128);
    let hi = last.saturating_mul(MAX_DIFFICULTY_STEP as u128).max(MIN_DIFFICULTY as u128);

    raw.clamp(lo, hi).clamp(MIN_DIFFICULTY as u128, Difficulty::MAX as u128) as Difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_one_accepts_anything() {
        assert!(check_hash(&[0xff; 32], 1));
        assert!(check_hash(&[0xff; 32], 0));
    }

    #[test]
    fn all_zero_hash_meets_any_difficulty() {
        assert!(check_hash(&[0x00; 32], Difficulty::MAX));
    }

    #[test]
    fn max_hash_fails_difficulty_two() {
        // h = 2^256 − 1; h·2 ≥ 2^256, so it must fail.
        assert!(!check_hash(&[0xff; 32], 2));
    }

    #[test]
    fn small_hash_passes_moderate_difficulty() {
        // h = 1 (little-endian) meets any difficulty up to 2^64.
        let mut h = [0u8; 32];
        h[0] = 1;
        assert!(check_hash(&h, 1_000_000));
        assert!(check_hash(&h, Difficulty::MAX));
    }

    #[test]
    fn harder_difficulty_is_strictly_stronger() {
        // A hash with its top byte set: h ≈ 2^248. It meets d=2 but not a d that
        // pushes the product past 2^256 (d ≈ 2^8).
        let mut h = [0u8; 32];
        h[31] = 0x01; // most-significant byte (little-endian) → h = 2^248
        assert!(check_hash(&h, 100)); // 2^248 · 100 < 2^256
        assert!(!check_hash(&h, 1 << 9)); // 2^248 · 2^9 = 2^257 ≥ 2^256
    }

    // Build a synthetic history of `blocks` blocks, each mined at fixed
    // difficulty `d` and taking `spacing` seconds.
    fn history(blocks: usize, d: u128, spacing: u64) -> (Vec<u64>, Vec<u128>) {
        let mut ts = Vec::new();
        let mut cum = Vec::new();
        let mut t = 1_000u64;
        let mut c = 0u128;
        for _ in 0..blocks {
            ts.push(t);
            c += d;
            cum.push(c);
            t += spacing;
        }
        (ts, cum)
    }

    #[test]
    fn on_target_difficulty_is_stable() {
        let (ts, cum) = history(100, 5000, TARGET_BLOCK_TIME);
        // Blocks arriving exactly on target keep difficulty ~constant.
        assert_eq!(next_difficulty(&ts, &cum), 5000);
    }

    #[test]
    fn fast_blocks_raise_difficulty() {
        let (ts, cum) = history(100, 5000, TARGET_BLOCK_TIME / 2);
        // Twice as fast ⇒ ~2× difficulty.
        assert!(next_difficulty(&ts, &cum) > 9000);
    }

    #[test]
    fn slow_blocks_lower_difficulty() {
        let (ts, cum) = history(100, 5000, TARGET_BLOCK_TIME * 2);
        // Half as fast ⇒ ~½ difficulty.
        assert!(next_difficulty(&ts, &cum) < 3000);
    }

    #[test]
    fn short_history_returns_minimum() {
        assert_eq!(next_difficulty(&[], &[]), MIN_DIFFICULTY);
        assert_eq!(next_difficulty(&[5], &[10]), MIN_DIFFICULTY);
    }

    #[test]
    fn randomx_seed_schedule() {
        let e = RANDOMX_EPOCH_BLOCKS;
        let lag = RANDOMX_EPOCH_LAG;

        // The whole first epoch (plus lag) is keyed by genesis.
        assert_eq!(randomx_seed_height(0), 0);
        assert_eq!(randomx_seed_height(1), 0);
        assert_eq!(randomx_seed_height(e + lag), 0);

        // Just past the threshold, the seed steps to the first epoch boundary.
        assert_eq!(randomx_seed_height(e + lag + 1), e);

        // Within one seed-epoch every height maps to the same seed height, and
        // the next epoch steps by exactly one epoch. A seed-epoch spans the
        // heights `[k*e + lag + 1, (k+1)*e + lag]`.
        let base = 3 * e + lag + 1; // first height of a seed-epoch
        let sh = randomx_seed_height(base);
        assert_eq!(sh % e, 0);
        assert_eq!(randomx_seed_height(base + e - 1), sh, "same epoch → same seed height");
        assert_eq!(randomx_seed_height(base + e) - sh, e, "next epoch steps by one epoch");

        // Seed height is always a multiple of the epoch length and below `height`.
        for h in [e + lag + 5, 5 * e, 12345, 100_000] {
            let s = randomx_seed_height(h);
            assert_eq!(s % e, 0);
            assert!(s < h);
        }
    }

    /// With a full window, a miner lying about a timestamp — absurdly high or
    /// low — falls in the trimmed tail and cannot meaningfully move the retarget.
    ///
    /// The influence is not exactly zero: discarding an outlier shifts the
    /// trimmed window by one sample, worth one block-interval of `time_span`. The
    /// property that matters is that a wildly dishonest timestamp is bounded to
    /// that, instead of swinging difficulty by orders of magnitude.
    #[test]
    fn outlier_timestamps_are_trimmed_away() {
        let blocks = DIFFICULTY_WINDOW + DIFFICULTY_LAG + 50; // full window available
        let (ts, cum) = history(blocks, 5000, TARGET_BLOCK_TIME);
        let honest = next_difficulty(&ts, &cum) as i64;

        // A timestamp claimed ~300 years in the future.
        let mut high = ts.clone();
        high[100] = 10_000_000_000;
        let with_high = next_difficulty(&high, &cum) as i64;
        assert!(
            (with_high - honest).abs() * 100 <= honest,
            "future outlier moved difficulty {honest} -> {with_high} (>1%)"
        );

        // A timestamp claimed at the epoch.
        let mut low = ts.clone();
        low[200] = 1;
        let with_low = next_difficulty(&low, &cum) as i64;
        assert!(
            (with_low - honest).abs() * 100 <= honest,
            "past outlier moved difficulty {honest} -> {with_low} (>1%)"
        );
    }

    /// The lag means the newest blocks' timestamps are not consulted at all.
    #[test]
    fn recent_timestamps_are_ignored_via_lag() {
        let blocks = DIFFICULTY_WINDOW + DIFFICULTY_LAG + 50;
        let (ts, cum) = history(blocks, 5000, TARGET_BLOCK_TIME);
        let honest = next_difficulty(&ts, &cum);

        // Garbage in the lagged (most recent) region changes nothing.
        let mut tip_lies = ts.clone();
        for t in tip_lies.iter_mut().skip(blocks - DIFFICULTY_LAG) {
            *t = 9_000_000_000;
        }
        assert_eq!(next_difficulty(&tip_lies, &cum), honest);
    }
}
