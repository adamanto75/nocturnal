//! Multi-threaded background miner, kept entirely off the consensus lock.
//!
//! Each mining round builds a block template under the lock (fast), then grinds
//! the nonce across N threads **without** the lock — so the node stays responsive
//! to RPC and P2P while hashing. Real parallelism comes from
//! [`ProofOfWork::mining_hashers`], which hands each thread an independent hasher
//! (for RandomX, its own VM over a shared dataset).
//!
//! Mining is live-tunable through [`MiningControl`]: the RPC layer flips it on/off
//! and changes the thread count without restarting the node, and reads the
//! hashrate / blocks-found counters for the wallet UI.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use noct_core::block::Block;
use noct_core::p2p::Wire;
use noct_core::pow::{check_hash, Hasher, ProofOfWork};
use rand_core::OsRng;

use crate::transport::Peers;
use crate::{MiningJob, NodeState};

/// Shared, live-tunable mining state. One instance lives in [`NodeState`]; the
/// miner thread, the hashrate sampler, and the RPC layer all hold `Arc` clones.
pub struct MiningControl {
    active: AtomicBool,
    threads: AtomicUsize,
    /// Cumulative hashes computed since start (drives the hashrate sampler).
    hashes: AtomicU64,
    /// Hashes over the most recent sample second — what the UI shows.
    hashrate: AtomicU64,
    blocks_found: AtomicU64,
}

impl MiningControl {
    pub fn new(active: bool, threads: usize) -> Arc<Self> {
        Arc::new(MiningControl {
            active: AtomicBool::new(active),
            threads: AtomicUsize::new(threads.max(1)),
            hashes: AtomicU64::new(0),
            hashrate: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
        })
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
    pub fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
    }
    pub fn threads(&self) -> usize {
        self.threads.load(Ordering::Relaxed).max(1)
    }
    /// Set the worker-thread count (takes effect on the next round). Clamped to a
    /// sane range so an RPC caller can't ask for zero or an absurd fleet.
    pub fn set_threads(&self, n: usize) {
        self.threads.store(n.clamp(1, 1024), Ordering::Relaxed);
    }
    pub fn hashrate(&self) -> u64 {
        self.hashrate.load(Ordering::Relaxed)
    }
    pub fn blocks_found(&self) -> u64 {
        self.blocks_found.load(Ordering::Relaxed)
    }
}

/// Grind `job` across `hashers.len()` threads until one thread's nonce solves the
/// block or mining is switched off. Threads partition the nonce space by residue
/// (thread `t` tries `t, t+N, t+2N, …`), so they never duplicate work. Returns the
/// solved block (nonce set) or `None` if mining was stopped first.
///
/// No staleness check here on purpose: [`NodeState::submit_mined_block`] already
/// discards a block whose parent is no longer the tip, and a solo miner's tip only
/// moves when it mines — so a lock-free grind is both simpler and faster.
fn grind(job: &MiningJob, hashers: Vec<Hasher>, control: &MiningControl) -> Option<Block> {
    let n = hashers.len().max(1) as u32;
    let stop = AtomicBool::new(false);
    let winner: Mutex<Option<Block>> = Mutex::new(None);
    let difficulty = job.difficulty;

    thread::scope(|s| {
        for (tid, hasher) in hashers.into_iter().enumerate() {
            let stop = &stop;
            let winner = &winner;
            let mut block = job.block.clone();
            s.spawn(move || {
                let mut nonce = tid as u32;
                let mut local: u64 = 0;
                loop {
                    if stop.load(Ordering::Relaxed) || !control.is_active() {
                        break;
                    }
                    block.header.nonce = nonce;
                    let h = hasher(&block.hashing_blob());
                    local += 1;
                    if local >= 256 {
                        control.hashes.fetch_add(local, Ordering::Relaxed);
                        local = 0;
                    }
                    if check_hash(&h, difficulty) {
                        if !stop.swap(true, Ordering::SeqCst) {
                            *winner.lock().unwrap() = Some(block.clone());
                        }
                        break;
                    }
                    nonce = nonce.wrapping_add(n);
                }
                control.hashes.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    winner.into_inner().unwrap()
}

/// Launch the background miner and a 1 Hz hashrate sampler. Both run for the life
/// of the process; mining only actually grinds while `control` is active.
pub fn spawn(state: Arc<Mutex<NodeState>>, peers: Peers, control: Arc<MiningControl>) {
    // Hashrate sampler: once a second, publish (hashes this second) as the rate.
    {
        let control = Arc::clone(&control);
        thread::spawn(move || {
            let mut last = 0u64;
            loop {
                thread::sleep(Duration::from_secs(1));
                let now = control.hashes.load(Ordering::Relaxed);
                control.hashrate.store(now.wrapping_sub(last), Ordering::Relaxed);
                last = now;
            }
        });
    }

    thread::spawn(move || loop {
        if !control.is_active() {
            control.hashrate.store(0, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        // Build a template + snapshot the PoW handle under the lock (both fast).
        let (job, pow) = {
            let mut node = state.lock().unwrap();
            let job = node.build_block_template(&mut OsRng);
            (job, node.pow())
        };

        // Off-lock: hand each thread its own hasher for this block's epoch seed.
        let hashers = pow.mining_hashers(&job.seed, control.threads());
        let solved = grind(&job, hashers, &control);

        if let Some(block) = solved {
            let accepted = {
                let mut node = state.lock().unwrap();
                node.submit_mined_block(&mut OsRng, block, job.txs)
            };
            if let Some((block, txs)) = accepted {
                control.blocks_found.fetch_add(1, Ordering::Relaxed);
                peers.flood(&Wire::Block(block, txs));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::address::{Address, Network};
    use noct_core::keys::Account;
    use noct_core::pow::check_hash;
    use rand_core::OsRng;

    fn miner_address() -> Address {
        let a = Account::random(&mut OsRng);
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    #[test]
    fn control_toggles_and_clamps_threads() {
        let c = MiningControl::new(false, 4);
        assert!(!c.is_active());
        c.set_active(true);
        assert!(c.is_active());
        assert_eq!(c.threads(), 4);
        c.set_threads(0); // clamped up to 1
        assert_eq!(c.threads(), 1);
        c.set_threads(9999); // clamped down to the cap
        assert_eq!(c.threads(), 1024);
    }

    #[test]
    fn parallel_grind_solves_a_block_and_counts_hashes() {
        let mut node = NodeState::new(miner_address());
        let job = node.build_block_template(&mut OsRng);
        let pow = node.pow();
        let control = MiningControl::new(true, 4);

        // Four independent hashers grind the template; at genesis difficulty (1)
        // any hash qualifies, so a solved block comes back with a valid PoW.
        let hashers = pow.mining_hashers(&job.seed, 4);
        let solved = grind(&job, hashers, &control).expect("a block is found");
        assert_eq!(solved.header.prev_id, job.block.header.prev_id);
        assert!(check_hash(&solved.pow_hash(&pow), job.difficulty));
        assert!(control.hashes.load(Ordering::Relaxed) >= 1);

        // The freshly-mined block is accepted onto the chain.
        assert!(node.submit_mined_block(&mut OsRng, solved, job.txs).is_some());
        assert_eq!(node.height(), 2);
    }

    #[test]
    fn grind_stops_when_mining_is_switched_off() {
        let mut node = NodeState::new(miner_address());
        let job = node.build_block_template(&mut OsRng);
        let pow = node.pow();
        // Inactive control: every worker breaks immediately, so no block is found.
        let control = MiningControl::new(false, 2);
        let hashers = pow.mining_hashers(&job.seed, 2);
        assert!(grind(&job, hashers, &control).is_none());
    }
}
