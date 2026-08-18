//! Real RandomX proof of work for Noct.
//!
//! [`RandomXPow`] implements [`noct_core::pow::ProofOfWork`], so it drops into the
//! consensus code exactly where the placeholder [`noct_core::pow::KeccakPow`]
//! goes — `Blockchain<RandomXPow>` mines and verifies with genuine, ASIC-resistant
//! RandomX. That the swap is a single type parameter is the whole point of the
//! trait: the chain, blocks, and difficulty never knew which PoW they used.
//!
//! ## Seeds (epoch key)
//!
//! RandomX is keyed by a *seed*. Monero rotates it every ~2048 blocks off a past
//! block hash so the PoW dataset changes over time. Here the seed is fixed at
//! construction; wiring epoch rotation (rebuild the VM when the seed block
//! changes) is a follow-up. Genesis's block id is the natural first seed — every
//! node derives the same one.
//!
//! ## Cost
//!
//! Light mode (cache only, the default here) needs a few hundred MB and is slow
//! per hash — fine for a node verifying occasional blocks. A miner wants
//! `RandomXFlag::FLAG_FULL_MEM` (a ~2 GB dataset) for speed; that is a
//! construction option, not a protocol change.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use noct_core::pow::{Hasher, ProofOfWork};
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

// A RandomX VM holds raw pointers into the C library, so it is neither `Send` nor
// `Sync` by default. `Send` is asserted here, sound under the conditions this
// crate upholds: a VM (and the cache/dataset it links) is only ever *moved* to a
// worker thread and then used by that thread alone — never *called* from two
// threads at once. The verification VM is additionally serialised by a `Mutex`;
// each mining VM is owned outright by one grinding thread. The dataset the mining
// VMs share is read-only during hashing, so concurrent reads are safe.
struct VmCell(RandomXVM);
unsafe impl Send for VmCell {}

impl VmCell {
    fn hash(&self, blob: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0.calculate_hash(blob).expect("randomx hashing failed"));
        out
    }
}

/// Everything keyed to one epoch seed: the RandomX cache, the light-mode VM used
/// for verification, and (once mining has needed it) the heavyweight full-memory
/// dataset shared by all mining VMs.
struct Epoch {
    cache: RandomXCache,
    verify: Arc<Mutex<VmCell>>,
    /// Built lazily on the first mine of this epoch (~2 GB, tens of seconds), then
    /// reused for every mining round until the epoch rotates.
    dataset: Option<RandomXDataset>,
}

// `RandomXCache`/`RandomXDataset` are `Arc`-wrapped raw C buffers, hence not
// `Send` by default. Retaining them here (so mining can rebuild VMs cheaply) is
// sound to share across threads: both are immutable after construction, hashing
// only ever *reads* them, and their reference counts are atomic. Only VMs built
// from clones — themselves `Send` via `VmCell` — are handed to worker threads.
unsafe impl Send for Epoch {}

struct Inner {
    /// One epoch per seed. Building the cache/VM is expensive, so they are kept.
    epochs: HashMap<Vec<u8>, Epoch>,
    /// The seed currently in effect — the VM `pow_hash` uses.
    current: Vec<u8>,
    /// Flags for the cache and the light verification VM.
    cache_flags: RandomXFlag,
    /// Flags for mining VMs — the cache flags plus `FLAG_FULL_MEM` (dataset mode).
    mine_flags: RandomXFlag,
}

/// Real RandomX proof of work with per-epoch rekeying.
///
/// The active VM is selected by [`ProofOfWork::reseed`]; the consensus code calls
/// it with each block's epoch seed before hashing (see
/// `Blockchain::seed_for_height`). Epochs are cached per seed so a boundary costs
/// one rebuild, not one per block.
///
/// Verification uses a single light (cache-only, ~256 MB) VM behind a mutex.
/// Mining uses [`ProofOfWork::mining_hashers`], which builds one full-memory
/// dataset per epoch (lazily) and hands each grinding thread its **own** VM over
/// that shared dataset — so N cores hash in genuine parallel with no lock, at
/// dataset-mode speed. Light and full-memory RandomX produce identical hashes, so
/// a full-mem-mined block verifies against the light VM.
///
/// `Clone` is cheap and shares all state (`Arc`), so a `Blockchain<RandomXPow>`
/// cloned for a reorg trial — and the node's mining and verifying copies — stay
/// keyed together.
#[derive(Clone)]
pub struct RandomXPow {
    inner: Arc<Mutex<Inner>>,
}

impl RandomXPow {
    /// Build a RandomX PoW with an initial `seed`. Verification is light mode;
    /// mining upgrades to a full-memory dataset on demand.
    pub fn new(seed: &[u8]) -> Result<Self, String> {
        Self::with_flags(seed, RandomXFlag::get_recommended_flags())
    }

    /// Build with explicit cache/verify flags. Mining VMs add `FLAG_FULL_MEM`.
    pub fn with_flags(seed: &[u8], cache_flags: RandomXFlag) -> Result<Self, String> {
        let epoch = build_epoch(cache_flags, seed)?;
        let mut epochs = HashMap::new();
        epochs.insert(seed.to_vec(), epoch);
        Ok(RandomXPow {
            inner: Arc::new(Mutex::new(Inner {
                epochs,
                current: seed.to_vec(),
                cache_flags,
                mine_flags: cache_flags | RandomXFlag::FLAG_FULL_MEM,
            })),
        })
    }

    /// The number of distinct-seed epochs currently cached.
    pub fn cached_vms(&self) -> usize {
        self.inner.lock().unwrap().epochs.len()
    }

    // The verification VM for the currently-active seed.
    fn current_vm(&self) -> Arc<Mutex<VmCell>> {
        let inner = self.inner.lock().expect("randomx inner mutex poisoned");
        Arc::clone(&inner.epochs[&inner.current].verify)
    }
}

fn build_epoch(cache_flags: RandomXFlag, seed: &[u8]) -> Result<Epoch, String> {
    let cache = RandomXCache::new(cache_flags, seed).map_err(|e| format!("randomx cache: {e}"))?;
    let vm = RandomXVM::new(cache_flags, Some(cache.clone()), None)
        .map_err(|e| format!("randomx vm: {e}"))?;
    Ok(Epoch { cache, verify: Arc::new(Mutex::new(VmCell(vm))), dataset: None })
}

impl ProofOfWork for RandomXPow {
    fn pow_hash(&self, blob: &[u8]) -> [u8; 32] {
        let vm = self.current_vm();
        let vm = vm.lock().expect("randomx vm mutex poisoned");
        vm.hash(blob)
    }

    fn reseed(&self, seed: &[u8; 32]) {
        let mut inner = self.inner.lock().expect("randomx inner mutex poisoned");
        if inner.current == seed {
            return; // already keyed to this epoch
        }
        if !inner.epochs.contains_key(seed.as_slice()) {
            // First block of a new epoch: build (and keep) its cache + verify VM.
            let flags = inner.cache_flags;
            let epoch = build_epoch(flags, seed).expect("failed to build RandomX epoch");
            inner.epochs.insert(seed.to_vec(), epoch);
        }
        inner.current = seed.to_vec();
    }

    fn mining_hashers(&self, seed: &[u8; 32], count: usize) -> Vec<Hasher> {
        // 1. Ensure the epoch exists; grab its cache and any already-built dataset.
        //    Held only briefly — never across the slow dataset build below.
        let (cache, mine_flags, existing) = {
            let mut inner = self.inner.lock().expect("randomx inner mutex poisoned");
            if !inner.epochs.contains_key(seed.as_slice()) {
                let flags = inner.cache_flags;
                let epoch = build_epoch(flags, seed).expect("failed to build RandomX epoch");
                inner.epochs.insert(seed.to_vec(), epoch);
            }
            let epoch = &inner.epochs[seed.as_slice()];
            (epoch.cache.clone(), inner.mine_flags, epoch.dataset.clone())
        };

        // 2. Build the ~2 GB dataset off the lock on first use, then cache it so
        //    later rounds in this epoch are instant.
        let dataset = match existing {
            Some(ds) => ds,
            None => {
                let ds = RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache.clone(), 0)
                    .expect("failed to build RandomX dataset");
                let mut inner = self.inner.lock().expect("randomx inner mutex poisoned");
                if let Some(epoch) = inner.epochs.get_mut(seed.as_slice()) {
                    epoch.dataset = Some(ds.clone());
                }
                ds
            }
        };

        // 3. One independent full-memory VM per thread, all sharing the dataset.
        (0..count.max(1))
            .map(|_| {
                let vm = RandomXVM::new(mine_flags, Some(cache.clone()), Some(dataset.clone()))
                    .expect("failed to build RandomX mining VM");
                let cell = VmCell(vm);
                // Capture the whole `VmCell` (Send), not its inner field, so the
                // boxed hasher is Send for the grinding thread.
                Box::new(move |blob: &[u8]| cell.hash(blob)) as Hasher
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::address::{Address, Network};
    use noct_core::block::{Block, BlockHeader, Coinbase, GENESIS_TIMESTAMP};
    use noct_core::chain::Blockchain;
    use noct_core::emission::base_reward;
    use noct_core::keys::Account;
    use rand_core::OsRng;

    /// The bindings must reproduce RandomX's official reference vector, so we know
    /// the PoW is genuine and not an accidental stub.
    #[test]
    fn matches_randomx_reference_vector() {
        let pow = RandomXPow::new(b"test key 000").unwrap();
        let hash = pow.pow_hash(b"This is a test");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f");
    }

    /// Rekeying to a new epoch seed genuinely changes the PoW function, and VMs
    /// are cached per seed (an epoch boundary costs one rebuild; returning to a
    /// known seed costs none).
    #[test]
    fn reseed_rotates_the_pow_and_caches_vms() {
        let pow = RandomXPow::new(&[0u8; 32]).unwrap();
        assert_eq!(pow.cached_vms(), 1);
        let h0 = pow.pow_hash(b"block blob");

        // New epoch seed → different hash, second VM cached.
        let seed_a = [1u8; 32];
        pow.reseed(&seed_a);
        let h1 = pow.pow_hash(b"block blob");
        assert_ne!(h0, h1, "a new seed must change the PoW hash");
        assert_eq!(pow.cached_vms(), 2);

        // Reseeding to the same seed is a no-op (no rebuild).
        pow.reseed(&seed_a);
        assert_eq!(pow.cached_vms(), 2);
        assert_eq!(pow.pow_hash(b"block blob"), h1);

        // Returning to the original seed reuses its cached VM (no new build) and
        // reproduces the original hash.
        pow.reseed(&[0u8; 32]);
        assert_eq!(pow.cached_vms(), 2);
        assert_eq!(pow.pow_hash(b"block blob"), h0);
    }

    /// Multi-threaded mining must produce the *same* hash the light verification
    /// VM does — otherwise full-mem-mined blocks would fail verification. This
    /// builds the ~2 GB dataset once and checks several independent mining VMs
    /// agree with the light VM (and each other).
    #[test]
    fn mining_hashers_agree_with_light_verification() {
        let pow = RandomXPow::new(b"noct-mine-test").unwrap();
        let seed = [7u8; 32];
        pow.reseed(&seed);
        let blob = b"a noct block hashing blob";

        let expected = pow.pow_hash(blob); // light, cache-mode verification VM
        let hashers = pow.mining_hashers(&seed, 3); // full-mem, dataset-mode
        assert_eq!(hashers.len(), 3);
        for h in &hashers {
            assert_eq!(h(blob), expected, "full-mem mining hash must equal light hash");
        }
    }

    /// The crux: a real Noct block mines and verifies on a chain whose PoW is
    /// RandomX. Difficulty at height 1 is the minimum, so a single RandomX hash
    /// suffices — this stays fast while exercising the genuine function.
    #[test]
    fn mines_and_verifies_a_block_with_randomx() {
        // Seed the PoW from genesis — every node derives the same key.
        let genesis_seed = Blockchain::new(RandomXPow::new(b"noct-seed").unwrap()).genesis_id();
        let pow = RandomXPow::new(&genesis_seed).unwrap();

        let mut chain = Blockchain::new(pow);
        assert_eq!(chain.height(), 1); // genesis

        let miner = Account::random(&mut OsRng);
        let addr = Address::new(Network::Mainnet, miner.spend_public, miner.view_public);
        let reward = base_reward(chain.emitted());
        let coinbase = Coinbase::create(&mut OsRng, chain.height(), &addr, reward);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: GENESIS_TIMESTAMP + 120,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: vec![],
        };

        // Mine with real RandomX, then have the chain re-verify it with real
        // RandomX inside add_block.
        let difficulty = chain.next_difficulty();
        block.mine(&RandomXPow::new(&genesis_seed).unwrap(), difficulty);
        assert!(block.meets_difficulty(&RandomXPow::new(&genesis_seed).unwrap(), difficulty));

        chain.add_block(&mut OsRng, &block, &[]).expect("RandomX block accepted");
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.tip_id(), block.id());
    }
}
