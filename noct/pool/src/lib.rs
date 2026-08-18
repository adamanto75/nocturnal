//! `noct-pool` — the accounting core of a Noct mining pool.
//!
//! A pool lets many small miners share the variance of block discovery. It sits
//! between miners and a node:
//!
//! 1. it fetches a block template from a node ([`Job`]), one that pays the
//!    **pool's** address, and hands it to miners at a deliberately **lower
//!    difficulty** than the network's;
//! 2. miners return *shares* — solutions meeting that easier target. A share is
//!    statistical proof of work performed, and is what the pool pays for;
//! 3. occasionally a share also meets the real network difficulty. That share
//!    *is* a block: the pool submits it to the node and the round pays out.
//!
//! This crate is the part that must be right: validating shares and dividing the
//! reward. It performs **no I/O** and is generic over the proof of work, so it is
//! fully testable with the cheap [`KeccakPow`](noct_core::pow::KeccakPow) — the
//! same split the node and chain use. Network plumbing belongs in a daemon on
//! top.
//!
//! ## What has to be true
//!
//! * **A share must be real work.** Every submission is re-hashed by the pool;
//!   nothing is taken on the miner's word.
//! * **A share may be paid only once.** Without duplicate detection a miner
//!   could resubmit one lucky nonce forever and drain the pool. Nonces are
//!   tracked per job, and the record is freed when the job retires.
//! * **A payout split must conserve the reward exactly.** Naive proportional
//!   division loses atomic units to rounding, so a pool slowly leaks (or, worse,
//!   over-pays). [`Pool::split_reward`] distributes every unit by the
//!   largest-remainder method.

pub mod auth;
pub mod payout;
pub mod vardiff;
pub mod window_log;

use std::collections::{HashMap, HashSet, VecDeque};

use noct_core::block::Block;
use noct_core::pow::{check_hash, Difficulty, ProofOfWork};
use noct_core::tx::Transaction;

/// Identifies a miner for accounting — typically the payout address it
/// registered with, so the pool can pay it later.
pub type MinerId = String;

/// Identifies a job handed to miners.
pub type JobId = u64;

/// How many shares the PPLNS window keeps by default. Paying the last N shares
/// (rather than only those in the current round) is what makes "pool hopping" —
/// mining only at the start of rounds, where a proportional scheme over-pays —
/// unprofitable.
pub const DEFAULT_WINDOW: usize = 8_192;

/// How many jobs stay live at once. Old jobs are retired oldest-first, which
/// also frees their recorded nonces, so pool memory cannot grow without bound on
/// miner-supplied input.
pub const MAX_LIVE_JOBS: usize = 8;

/// Work handed to miners: a block template plus the parameters needed to check
/// solutions against it.
pub struct Job {
    pub id: JobId,
    /// The unmined block. Miners vary `header.nonce`.
    pub block: Block,
    /// Transactions the template commits to, needed to submit a found block.
    pub txs: Vec<Transaction>,
    /// The real difficulty a solution must meet to be a *block*.
    pub network_difficulty: Difficulty,
    /// Epoch seed the proof of work must be keyed to.
    pub seed: [u8; 32],
    /// Nonces already credited on this job, so no share is paid twice.
    seen_nonces: HashSet<u32>,
}

/// One accepted share, as recorded in the payout window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub miner: MinerId,
    /// The share difficulty in force when it was accepted — its weight in the
    /// split. Recorded per share so changing the target later cannot retroative
    /// revalue work already done.
    pub weight: Difficulty,
}

/// What a submission turned out to be.
#[derive(Debug)]
pub enum ShareOutcome {
    /// Valid work, credited to the miner.
    Accepted,
    /// Valid work that *also* meets network difficulty: submit it as a block.
    /// Carries the solved block and its transactions.
    Block(Box<(Block, Vec<Transaction>)>),
    /// The nonce did not meet even the share target.
    TooEasy,
    /// This (job, nonce) was already credited.
    Duplicate,
    /// The job is unknown or has been retired.
    UnknownJob,
}

/// Compared by *outcome*: two `Block` results are the same when they carry the
/// same solved block. (`Block`/`Transaction` are not themselves `Eq`, and the
/// block id is the meaningful identity anyway.)
impl PartialEq for ShareOutcome {
    fn eq(&self, other: &Self) -> bool {
        use ShareOutcome::*;
        match (self, other) {
            (Accepted, Accepted) | (TooEasy, TooEasy) => true,
            (Duplicate, Duplicate) | (UnknownJob, UnknownJob) => true,
            (Block(a), Block(b)) => a.0.id() == b.0.id(),
            _ => false,
        }
    }
}
impl Eq for ShareOutcome {}

/// The pool's share ledger.
pub struct Pool<P: ProofOfWork> {
    pow: P,
    jobs: HashMap<JobId, Job>,
    /// Job ids oldest-first, so retiring is deterministic.
    job_order: VecDeque<JobId>,
    next_job_id: JobId,
    /// The target miners are asked to meet. Far below network difficulty, so
    /// shares arrive steadily enough to measure a miner's contribution.
    share_difficulty: Difficulty,
    /// The PPLNS window: the most recent accepted shares, oldest-first.
    window: VecDeque<Share>,
    window_size: usize,
}

impl<P: ProofOfWork> Pool<P> {
    /// A pool asking miners for `share_difficulty` work, paying over a window of
    /// the last `window_size` shares.
    pub fn new(pow: P, share_difficulty: Difficulty, window_size: usize) -> Self {
        Pool {
            pow,
            jobs: HashMap::new(),
            job_order: VecDeque::new(),
            next_job_id: 1,
            share_difficulty: share_difficulty.max(1),
            window: VecDeque::new(),
            window_size: window_size.max(1),
        }
    }

    /// Seed the payout window with shares recovered from disk.
    ///
    /// Called once at startup, before any miner is served, so credit earned
    /// before a restart is honoured rather than silently forfeited. Truncated to
    /// the window size exactly as live acceptance would, so recovery can never
    /// resurrect work that had already aged out and dilute everyone else's split.
    pub fn restore_window(&mut self, shares: impl IntoIterator<Item = Share>) {
        for share in shares {
            self.window.push_back(share);
            while self.window.len() > self.window_size {
                self.window.pop_front();
            }
        }
    }

    /// The current share target.
    pub fn share_difficulty(&self) -> Difficulty {
        self.share_difficulty
    }

    /// Retarget. Shares already in the window keep the weight they were accepted
    /// at, so this never revalues past work.
    pub fn set_share_difficulty(&mut self, difficulty: Difficulty) {
        self.share_difficulty = difficulty.max(1);
    }

    /// Publish a template as a new job and return its id. Retires the oldest job
    /// once [`MAX_LIVE_JOBS`] are live.
    pub fn add_job(
        &mut self,
        block: Block,
        txs: Vec<Transaction>,
        network_difficulty: Difficulty,
        seed: [u8; 32],
    ) -> JobId {
        let id = self.next_job_id;
        self.next_job_id += 1;
        self.jobs.insert(
            id,
            Job { id, block, txs, network_difficulty, seed, seen_nonces: HashSet::new() },
        );
        self.job_order.push_back(id);
        while self.job_order.len() > MAX_LIVE_JOBS {
            if let Some(old) = self.job_order.pop_front() {
                self.jobs.remove(&old); // frees that job's recorded nonces too
            }
        }
        id
    }

    /// A live job, if it has not been retired.
    pub fn job(&self, id: JobId) -> Option<&Job> {
        self.jobs.get(&id)
    }

    /// Number of live jobs.
    pub fn live_jobs(&self) -> usize {
        self.jobs.len()
    }

    /// Validate and credit a submission.
    ///
    /// The pool **re-computes** the proof of work; a miner's claim is never
    /// taken at face value. A solution that also meets the job's network
    /// difficulty is returned as [`ShareOutcome::Block`] — and is still credited
    /// as a share, since finding a block is work like any other.
    pub fn submit_share(&mut self, miner: &str, job_id: JobId, nonce: u32) -> ShareOutcome {
        let d = self.share_difficulty;
        self.submit_share_at(miner, job_id, nonce, d)
    }

    /// Submit a share against a **specific** target, rather than the pool-wide
    /// one.
    ///
    /// This is what makes per-miner difficulty ([`crate::vardiff`]) work: each
    /// miner is judged against the target it was actually issued. The share is
    /// weighted at that same difficulty, so a miner on a hard target submitting
    /// one share is credited exactly as much as one on an easy target submitting
    /// proportionally more — retargeting changes how often work is *reported*,
    /// never what it is *worth*.
    ///
    /// The caller is responsible for passing a target the miner was genuinely
    /// issued. Passing an arbitrarily low one would let a miner be paid full
    /// weight for trivial work.
    pub fn submit_share_at(
        &mut self,
        miner: &str,
        job_id: JobId,
        nonce: u32,
        share_difficulty: Difficulty,
    ) -> ShareOutcome {
        let share_difficulty = share_difficulty.max(1);
        let Some(job) = self.jobs.get_mut(&job_id) else {
            return ShareOutcome::UnknownJob;
        };

        // Reject a replayed nonce *before* spending time hashing it.
        if !job.seen_nonces.insert(nonce) {
            return ShareOutcome::Duplicate;
        }

        let mut block = job.block.clone();
        block.header.nonce = nonce;
        self.pow.reseed(&job.seed);
        let hash = block.pow_hash(&self.pow);

        if !check_hash(&hash, share_difficulty) {
            return ShareOutcome::TooEasy;
        }

        // Credit the work.
        self.window.push_back(Share { miner: miner.to_string(), weight: share_difficulty });
        while self.window.len() > self.window_size {
            self.window.pop_front();
        }

        if check_hash(&hash, job.network_difficulty) {
            let txs = job.txs.clone();
            ShareOutcome::Block(Box::new((block, txs)))
        } else {
            ShareOutcome::Accepted
        }
    }

    /// The current payout window, oldest share first.
    pub fn window(&self) -> &VecDeque<Share> {
        &self.window
    }

    /// Total weight of each miner in the window.
    pub fn weights(&self) -> HashMap<MinerId, u128> {
        let mut out: HashMap<MinerId, u128> = HashMap::new();
        for share in &self.window {
            *out.entry(share.miner.clone()).or_insert(0) += share.weight as u128;
        }
        out
    }

    /// Divide `total` among the miners in the window, in proportion to the work
    /// each contributed.
    ///
    /// The result **sums to exactly `total`**: proportional shares are floored,
    /// then the units lost to flooring are handed out one each to the miners
    /// with the largest remainders (ties broken by miner id, so the split is
    /// deterministic and reproducible from the ledger). Returned sorted by miner
    /// id. An empty window pays nobody — the caller decides what to do with an
    /// unearned reward rather than the split silently swallowing it.
    pub fn split_reward(&self, total: u64) -> Vec<(MinerId, u64)> {
        let weights = self.weights();
        let total_weight: u128 = weights.values().sum();
        if total_weight == 0 || total == 0 {
            return Vec::new();
        }

        // Floor each miner's exact share, and remember the fractional part.
        let mut payouts: Vec<(MinerId, u64, u128)> = weights
            .into_iter()
            .map(|(miner, weight)| {
                let exact = (total as u128) * weight;
                let floored = (exact / total_weight) as u64;
                let remainder = exact % total_weight;
                (miner, floored, remainder)
            })
            .collect();

        // Hand out the units lost to flooring, largest remainder first.
        let distributed: u64 = payouts.iter().map(|(_, amount, _)| *amount).sum();
        let mut leftover = total - distributed;
        payouts.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        for entry in payouts.iter_mut() {
            if leftover == 0 {
                break;
            }
            entry.1 += 1;
            leftover -= 1;
        }

        payouts.sort_by(|a, b| a.0.cmp(&b.0));
        payouts.into_iter().map(|(miner, amount, _)| (miner, amount)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::address::{Address, Network};
    use noct_core::block::{BlockHeader, Coinbase, GENESIS_TIMESTAMP};
    use noct_core::keys::Account;
    use noct_core::pow::KeccakPow;
    use rand_core::OsRng;

    fn pool_address() -> Address {
        let a = Account::random(&mut OsRng);
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    /// An unmined template, as a node's `/getblocktemplate` would supply.
    fn template() -> (Block, Vec<Transaction>) {
        let coinbase = Coinbase::create(&mut OsRng, 1, &pool_address(), 500_000);
        let block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: GENESIS_TIMESTAMP + 120,
                prev_id: [7u8; 32],
                nonce: 0,
            },
            coinbase,
            tx_hashes: Vec::new(),
        };
        (block, Vec::new())
    }

    fn pool(share_difficulty: Difficulty) -> Pool<KeccakPow> {
        Pool::new(KeccakPow, share_difficulty, DEFAULT_WINDOW)
    }

    /// Search for a nonce whose hash meets `difficulty` but not `too_hard`.
    fn find_nonce(block: &Block, difficulty: Difficulty) -> u32 {
        let mut b = block.clone();
        for nonce in 0..2_000_000u32 {
            b.header.nonce = nonce;
            if check_hash(&b.pow_hash(&KeccakPow), difficulty) {
                return nonce;
            }
        }
        panic!("no nonce met difficulty {difficulty}");
    }

    #[test]
    fn a_share_meeting_the_target_is_credited() {
        let mut p = pool(100);
        let (block, txs) = template();
        // Network difficulty far above the share target, so this is a share only.
        let job = p.add_job(block.clone(), txs, u64::MAX, [0u8; 32]);

        let nonce = find_nonce(&block, 100);
        assert_eq!(p.submit_share("alice", job, nonce), ShareOutcome::Accepted);
        assert_eq!(p.window().len(), 1);
        assert_eq!(p.window()[0].miner, "alice");
        assert_eq!(p.window()[0].weight, 100);
    }

    #[test]
    fn work_below_the_target_is_rejected_and_uncredited() {
        // Ask for a target high enough that nonce 0 almost certainly misses.
        let mut p = pool(1 << 40);
        let (block, txs) = template();
        let job = p.add_job(block.clone(), txs, u64::MAX, [0u8; 32]);

        let mut b = block;
        b.header.nonce = 0;
        // Guard the fixture: this test is only meaningful if nonce 0 really misses.
        assert!(!check_hash(&b.pow_hash(&KeccakPow), 1 << 40), "fixture: nonce 0 must miss");

        assert_eq!(p.submit_share("mallory", job, 0), ShareOutcome::TooEasy);
        assert!(p.window().is_empty(), "worthless work must not be credited");
    }

    #[test]
    fn a_replayed_nonce_is_only_ever_paid_once() {
        // Without this, one lucky nonce could be resubmitted forever.
        let mut p = pool(100);
        let (block, txs) = template();
        let job = p.add_job(block.clone(), txs, u64::MAX, [0u8; 32]);
        let nonce = find_nonce(&block, 100);

        assert_eq!(p.submit_share("alice", job, nonce), ShareOutcome::Accepted);
        assert_eq!(p.submit_share("alice", job, nonce), ShareOutcome::Duplicate);
        // Not even under a different name.
        assert_eq!(p.submit_share("bob", job, nonce), ShareOutcome::Duplicate);
        assert_eq!(p.window().len(), 1, "credited exactly once");
    }

    #[test]
    fn a_share_meeting_network_difficulty_is_reported_as_a_block() {
        // Share target and network target both trivial, so the first solution is
        // simultaneously a share and a block.
        let mut p = pool(1);
        let (block, txs) = template();
        let job = p.add_job(block.clone(), txs, 1, [0u8; 32]);

        match p.submit_share("alice", job, 12_345) {
            ShareOutcome::Block(found) => {
                let (solved, _txs) = *found;
                assert_eq!(solved.header.nonce, 12_345, "the winning nonce is carried out");
                assert_eq!(solved.coinbase.height, 1);
            }
            other => panic!("expected a block, got {other:?}"),
        }
        // Finding a block is still work, and is paid as a share.
        assert_eq!(p.window().len(), 1);
    }

    #[test]
    fn unknown_and_retired_jobs_are_refused() {
        let mut p = pool(1);
        assert_eq!(p.submit_share("alice", 999, 0), ShareOutcome::UnknownJob);

        // Publishing past the cap retires the oldest job.
        let (block, txs) = template();
        let first = p.add_job(block.clone(), txs.clone(), u64::MAX, [0u8; 32]);
        for _ in 0..MAX_LIVE_JOBS {
            p.add_job(block.clone(), txs.clone(), u64::MAX, [0u8; 32]);
        }
        assert_eq!(p.live_jobs(), MAX_LIVE_JOBS, "live jobs are bounded");
        assert_eq!(
            p.submit_share("alice", first, 0),
            ShareOutcome::UnknownJob,
            "a retired job no longer accepts shares"
        );
    }

    #[test]
    fn the_payout_window_is_bounded() {
        let mut p = Pool::new(KeccakPow, 1, 4); // window of 4
        let (block, txs) = template();
        let job = p.add_job(block, txs, u64::MAX, [0u8; 32]);
        for nonce in 0..10u32 {
            // Share difficulty 1 accepts everything, so each nonce is a share.
            assert_eq!(p.submit_share("alice", job, nonce), ShareOutcome::Accepted);
        }
        assert_eq!(p.window().len(), 4, "only the last N shares are retained");
    }

    #[test]
    fn reward_splits_in_proportion_to_work() {
        let mut p = Pool::new(KeccakPow, 1, DEFAULT_WINDOW);
        let (block, txs) = template();
        let job = p.add_job(block, txs, u64::MAX, [0u8; 32]);
        // alice does 3× bob's work.
        for nonce in 0..3u32 {
            p.submit_share("alice", job, nonce);
        }
        p.submit_share("bob", job, 100);

        let split = p.split_reward(1_000);
        assert_eq!(split, vec![("alice".to_string(), 750), ("bob".to_string(), 250)]);
    }

    #[test]
    fn a_split_never_creates_or_loses_a_single_atomic_unit() {
        // Rounding is where pools quietly leak. Across awkward miner counts and
        // reward sizes, the split must always sum to exactly the reward.
        for miners in [1usize, 2, 3, 7, 11, 13] {
            for total in [1u64, 2, 999, 1_000, 1_000_003, u64::MAX / 4] {
                let mut p = Pool::new(KeccakPow, 1, DEFAULT_WINDOW);
                let (block, txs) = template();
                let job = p.add_job(block, txs, u64::MAX, [0u8; 32]);
                for i in 0..miners {
                    p.submit_share(&format!("miner{i}"), job, i as u32);
                }

                let split = p.split_reward(total);
                let paid: u64 = split.iter().map(|(_, amount)| *amount).sum();
                assert_eq!(paid, total, "{miners} miners splitting {total}");
                assert_eq!(split.len(), miners, "everyone with work gets an entry");

                // Largest-remainder never moves anyone more than one unit off
                // their exact proportional share.
                let fair = total / miners as u64;
                for (_, amount) in &split {
                    assert!(
                        amount.abs_diff(fair) <= 1,
                        "equal work should pay equally (±1 unit): {amount} vs {fair}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_window_pays_nobody() {
        let p = pool(1);
        assert!(p.split_reward(1_000).is_empty());
    }

    #[test]
    fn retargeting_does_not_revalue_work_already_done() {
        let mut p = pool(1);
        let (block, txs) = template();
        let job = p.add_job(block, txs, u64::MAX, [0u8; 32]);
        p.submit_share("alice", job, 0); // weight 1

        p.set_share_difficulty(1_000);
        let job2 = {
            let (b, t) = template();
            p.add_job(b, t, u64::MAX, [0u8; 32])
        };
        let _ = job2;

        assert_eq!(p.window()[0].weight, 1, "the old share keeps its original weight");
        assert_eq!(p.share_difficulty(), 1_000);
    }
}

#[cfg(test)]
mod vardiff_integration_tests {
    use super::*;
    use noct_core::pow::KeccakPow;

    fn pool() -> Pool<KeccakPow> {
        Pool::new(KeccakPow, 1, DEFAULT_WINDOW)
    }

    /// Find a nonce that genuinely meets `difficulty` for this job, starting the
    /// search at `from`. Real work, not an assumption — a share only counts if it
    /// actually satisfies the target it was issued.
    fn mine_for(p: &Pool<KeccakPow>, job_id: JobId, difficulty: Difficulty, from: u32) -> u32 {
        let job = p.job(job_id).expect("job exists");
        let mut block = job.block.clone();
        for n in from..from + 5_000_000 {
            block.header.nonce = n;
            if check_hash(&block.pow_hash(&KeccakPow), difficulty) {
                return n;
            }
        }
        panic!("no nonce met difficulty {difficulty}");
    }

    /// THE PROPERTY THAT MAKES PER-MINER DIFFICULTY SAFE.
    ///
    /// Retargeting must change how often work is *reported*, never what it is
    /// *worth*. A miner on a 4× harder target submitting one share must be paid
    /// the same as one on the easy target submitting four — otherwise vardiff
    /// would quietly redistribute income every time it retuned someone.
    #[test]
    fn a_harder_target_pays_proportionally_more_per_share() {
        let mut p = pool();
        // Difficulty 1 accepts every nonce, so this exercises the weighting
        // rather than the hashing.
        let job = p.add_job(Block::genesis(), Vec::new(), Difficulty::MAX, [0u8; 32]);

        // "fast" is on 4x the target and submits once; "slow" submits four times.
        let n = mine_for(&p, job, 4, 1);
        assert_eq!(p.submit_share_at("fast", job, n, 4), ShareOutcome::Accepted);
        let mut from = 100;
        for _ in 0..4 {
            let n = mine_for(&p, job, 1, from);
            assert_eq!(p.submit_share_at("slow", job, n, 1), ShareOutcome::Accepted);
            from = n + 1;
        }

        let w = p.weights();
        assert_eq!(w["fast"], 4, "one share at difficulty 4 is worth 4");
        assert_eq!(w["slow"], 4, "four shares at difficulty 1 are worth 4");

        // And therefore the split is even, despite a 4:1 difference in share count.
        let split = p.split_reward(1_000);
        let paid = |who: &str| {
            split.iter().find(|(m, _)| m == who).map(|(_, amt)| *amt).unwrap_or(0)
        };
        assert_eq!(paid("fast"), paid("slow"), "equal work must pay equally");
        assert_eq!(paid("fast") + paid("slow"), 1_000, "and the reward is conserved");
    }

    /// A share is judged against the target passed in, not the pool-wide one.
    #[test]
    fn the_supplied_target_is_the_one_enforced() {
        let mut p = Pool::new(KeccakPow, 1, DEFAULT_WINDOW);
        let job = p.add_job(Block::genesis(), Vec::new(), Difficulty::MAX, [0u8; 32]);
        // An impossible target rejects work the pool-wide target would have taken.
        assert_eq!(
            p.submit_share_at("m", job, 1, Difficulty::MAX),
            ShareOutcome::TooEasy,
            "the per-miner target must be enforced, not the global one"
        );
        assert!(p.window().is_empty(), "a rejected share earns nothing");
    }

    /// Weights recorded earlier must not be revalued when a miner is retargeted;
    /// otherwise a retune would rewrite the value of work already done.
    #[test]
    fn retargeting_does_not_revalue_past_shares() {
        let mut p = pool();
        let job = p.add_job(Block::genesis(), Vec::new(), Difficulty::MAX, [0u8; 32]);
        let n = mine_for(&p, job, 2, 1);
        assert_eq!(p.submit_share_at("m", job, n, 2), ShareOutcome::Accepted);
        let before = p.weights()["m"];
        // Later shares at a new target add to it; they do not rewrite it.
        let n = mine_for(&p, job, 8, n + 1);
        assert_eq!(p.submit_share_at("m", job, n, 8), ShareOutcome::Accepted);
        assert_eq!(p.weights()["m"], before + 8, "old weight preserved, new one added");
    }
}
