//! Layer 8 — chain state.
//!
//! [`Blockchain`] strings validated blocks together and maintains the state that
//! individual transactions cannot check on their own:
//!
//! * a **global output set** — every output ever created, indexed by position;
//!   ring members must be real entries here (a transaction can't invent decoys),
//! * a **global spent key-image set** — prevents double-spends *across*
//!   transactions and blocks (a single transaction's self-consistency is checked
//!   by [`Transaction::verify`]),
//! * **cumulative difficulty** and the per-block difficulty retarget,
//! * the **emission** accounting that fixes each block's allowed coinbase reward.
//!
//! This replaces the two simplifications flagged in earlier layers: rings are now
//! validated against the real output set, and key images are checked globally.
//!
//! ## Scope
//!
//! The chain is **forward-only**: it validates and appends to a single main
//! chain and tracks cumulative difficulty, exposing the fork-choice *rule*
//! ([`Blockchain::would_reorg_to`]). Executing a reorg (rolling back state to a
//! fork point and replaying a heavier branch) needs per-block undo data and is
//! deferred to the networking layer. Decoy selection offers a uniform sampler and
//! a recency-biased (gamma-shaped) one; calibrating the gamma to the real output
//! age distribution is a pre-testnet refinement.

use std::collections::{HashMap, HashSet};

use crate::block::Block;
use crate::emission::base_reward;
use crate::pow::{check_hash, next_difficulty, Difficulty, ProofOfWork, MIN_DIFFICULTY};
use crate::ring::{KeyImage, RingMember};
use crate::tx::{Transaction, TxError};

/// How many recent block timestamps the median-time-past is taken over.
///
/// A block's timestamp must be strictly greater than this median, which stops a
/// miner from dragging timestamps backwards to manipulate the difficulty
/// retarget while tolerating the modest clock skew of honest miners.
pub const MTP_WINDOW: usize = 11;

/// How far ahead of local time a block's timestamp may be (2 hours).
///
/// Unbounded future timestamps collapse the difficulty retarget: it divides
/// accumulated work by elapsed time, so a timestamp far in the future drives
/// difficulty toward the minimum and makes the chain trivially mineable
/// (security review F2).
pub const FUTURE_TIME_LIMIT: u64 = 2 * 60 * 60;

/// The **exact** number of ring members every input must have.
///
/// A minimum would not be enough. A ring of one deanonymises the spender
/// outright and pollutes the anonymity set of everyone who later draws that
/// output as a decoy, so a floor is clearly needed — but a *variable* size is
/// itself an identifying mark. If transactions may carry 11, 16 or 24 members,
/// the count partitions users by whatever wallet or setting produced them, and
/// the effective anonymity set is the group sharing that choice rather than the
/// ring. Monero mandates an exact size for this reason, and this matches it at
/// 16.
///
/// Consensus-critical: changing it is a hard fork, since it decides which
/// transactions are valid.
pub const RING_SIZE: usize = 16;

/// Gamma parameters for recency-biased decoy selection, from Monero's fit to
/// observed spend ages.
///
/// **These describe the log of an age in seconds, not an age.** A sample `x`
/// from `Gamma(shape, rate)` is exponentiated: `age_seconds = e^x`. With a mean
/// of `shape / rate = 11.97`, the median spend age lands around
/// `e^11.97 ≈ 1.8 days`, with a long tail toward older outputs — which is what
/// real spending looks like.
///
/// `1.61` is a **rate**, so the scale passed to a shape/scale sampler is its
/// reciprocal. Feeding 1.61 in as a scale inflates the mean from 11.97 to 31.0,
/// and dropping the exponentiation destroys the shape altogether: both mistakes
/// were present here, and together they placed every decoy in a narrow band in
/// the *middle* of the output set with none near the tip — the opposite of
/// recency bias, and worse than choosing uniformly.
pub const GAMMA_SHAPE: f64 = 19.28;
pub const GAMMA_RATE: f64 = 1.61;
/// The scale a shape/scale gamma sampler needs: `1 / rate`.
pub const GAMMA_SCALE: f64 = 1.0 / GAMMA_RATE;

/// How many blocks a coinbase (mined or premine) output must be buried before it
/// can be referenced by a transaction — as the real spend *or* as a decoy.
///
/// Coinbase outputs are the outputs most likely to vanish in a reorg (a reorg
/// past their block erases them), so allowing an immediate spend would let a
/// short reorg unspend already-spent freshly-mined coins. Because ring
/// signatures hide which member is real, the rule is enforced over *every* ring
/// member — matching the intent of Monero's `unlock_time` on coinbase outputs
/// (Monero uses 60). Non-coinbase outputs have no maturity requirement.
///
/// # Why 100, and not Monero's 60
///
/// This must be at least as deep as the deepest reorg a node will accept, or the
/// rule protects against *short* reorgs only: with maturity at 60 and
/// [`noct_node::MAX_REORG_DEPTH`] at 100, a reorg of 61 to 100 blocks was
/// permitted and would invalidate a coinbase that had already matured and been
/// spent — the precise outcome this constant exists to prevent.
///
/// The invariant is `COINBASE_MATURITY >= MAX_REORG_DEPTH`, and it is pinned by
/// a test. There were two ways to close it. Lowering the reorg cap to 60 needs
/// no consensus change, which is tempting, but a node that falls further behind
/// than the cap can never rejoin by reorganising — it is stranded on its own
/// fork until someone resyncs it by hand. On this network that is not a
/// theoretical failure: it is the one that actually happens. A tighter cap makes
/// it happen sooner, so the cap stayed at 100 and this rose to meet it.
///
/// 100 is also Bitcoin's maturity. Neither Bitcoin nor Monero caps reorg depth
/// at all, relying on hashrate to make deep reorgs impractical; this chain does
/// cap it, which is what makes the invariant necessary here.
///
/// The cost is that a miner waits 100 blocks rather than 60 — about three and a
/// half hours at a two-minute target, against Bitcoin's sixteen.
pub const COINBASE_MATURITY: u64 = 100;

/// Errors from validating a block against the chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainError {
    /// The block does not build on the current tip.
    BadPrevId,
    /// The proof of work does not meet the required difficulty.
    BadPow,
    /// The timestamp is not greater than the median of recent blocks.
    ///
    /// Permanently invalid: the median is chain-derived, so every node computes
    /// the same answer and the block can never become acceptable.
    BadTimestamp,
    /// The timestamp is further ahead of *this node's clock* than
    /// [`FUTURE_TIME_LIMIT`] allows.
    ///
    /// Kept distinct from [`ChainError::BadTimestamp`] because it is **not a
    /// permanent verdict and not evidence of misbehaviour**. It is the one
    /// validity rule that depends on local wall-clock time rather than on the
    /// chain, so two nodes whose clocks differ can disagree about the very same
    /// block — and the node that is *slow* is the one that rejects it. Treating
    /// that as an invalid block would score, and eventually ban, an honest peer
    /// for having the more accurate clock. The block simply becomes valid a
    /// little later.
    TimestampTooFarAhead,
    /// The coinbase height does not match the block's height.
    BadCoinbaseHeight,
    /// The provided transactions don't match the block's `tx_hashes`.
    TxHashMismatch,
    /// A transaction failed internal verification.
    InvalidTx(TxError),
    /// A ring references an output not in the global output set.
    UnknownRingMember,
    /// A ring references a coinbase output that is not yet
    /// [`COINBASE_MATURITY`] blocks deep.
    ImmatureCoinbase,
    /// A block creates an output identical (`[P, C]`) to one that already
    /// exists, which would make the output set ambiguous. See the check in
    /// [`Blockchain::add_block`].
    DuplicateOutput,
    /// An input's ring is not exactly [`RING_SIZE`] members.
    BadRingSize,
    /// A key image was already spent (here or in an earlier block).
    DoubleSpend,
    /// The coinbase does not claim exactly `subsidy + fees`.
    BadCoinbaseReward,
    /// A fee total overflowed.
    FeeOverflow,
    /// A reorg was attempted with no blocks.
    EmptyBranch,
    /// A reorg candidate had no more cumulative work than the current chain.
    NotHeavier,
    /// A branch tried to fork at height 0. Genesis is immutable — a chain that
    /// does not descend from it is a different network, not a competitor.
    CannotReplaceGenesis,
}

/// A block as accepted by the chain, with the transactions it carried. Retained
/// so the node can serve history to syncing peers and wallets.
#[derive(Clone, Debug)]
pub struct StoredBlock {
    pub block: Block,
    pub txs: Vec<Transaction>,
}

/// What a block changed, so it can be undone during a reorg. The key images and
/// output *contents* are re-derivable from the stored block itself; only these
/// two scalars cannot be recovered after the fact (`emitted` is not invertible
/// through the emission curve).
#[derive(Clone, Copy, Debug)]
struct Undo {
    outputs_len_before: usize,
    emitted_before: u64,
}

/// The result of a successful reorganisation.
#[derive(Debug)]
pub struct Reorg {
    /// Blocks dropped from the old chain, oldest first. Their transactions are no
    /// longer confirmed — a node should return them to its mempool.
    pub discarded: Vec<StoredBlock>,
    /// How many blocks of the new branch were applied.
    pub applied: usize,
}

/// A blockchain: validated blocks plus the state needed to validate the next one.
#[derive(Clone)]
pub struct Blockchain<P: ProofOfWork> {
    pow: P,
    /// Which network this chain is: selects the genesis block, and therefore
    /// every id derived from it. See [`crate::params`].
    network: crate::address::Network,
    blocks: Vec<StoredBlock>,
    undos: Vec<Undo>,
    block_ids: Vec<[u8; 32]>,
    timestamps: Vec<u64>,
    cumulative_difficulties: Vec<u128>,

    outputs: Vec<RingMember>,
    /// Membership key → global index, so a ring member can be resolved back to
    /// its output (for the coinbase-maturity check).
    output_membership: HashMap<[u8; 64], u64>,
    /// Per-output metadata, parallel to `outputs` (indexed by global index).
    output_meta: Vec<OutputMeta>,
    spent_key_images: HashSet<KeyImage>,
    emitted: u64,
    /// Blocks a coinbase output must be buried before it can be spent. Always
    /// [`COINBASE_MATURITY`] in production; tests may lower it via
    /// [`Blockchain::with_maturity`] so they need not mine 60 warm-up blocks.
    maturity: u64,
}

/// Per-output data the chain needs beyond the `[P, C]` ring member itself:
/// enough to enforce coinbase maturity.
#[derive(Clone, Copy, Debug)]
struct OutputMeta {
    /// Height of the block that created this output.
    height: u64,
    /// True if it is a coinbase (mined or premine) output.
    coinbase: bool,
}

fn membership_key(m: &RingMember) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&m.key.to_bytes());
    k[32..].copy_from_slice(&m.commitment.to_bytes());
    k
}

/// Wall-clock seconds since the Unix epoch, for the future-timestamp bound.
/// (Consensus timestamp validation is inherently clock-relative.)
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<P: ProofOfWork> Blockchain<P> {
    /// A new chain containing only the canonical genesis block, so every node
    /// starts rooted at the same block 0 and height 1.
    pub fn new(pow: P) -> Self {
        Self::with_maturity(pow, COINBASE_MATURITY)
    }

    /// A new chain on a specific network, rooted at that network's genesis.
    ///
    /// The network is part of the chain's identity: it selects the genesis block
    /// (and therefore every id derived from it) and the p2p magic peers must
    /// present. See [`crate::params`].
    pub fn for_network(network: crate::address::Network, pow: P) -> Self {
        Self::build(pow, COINBASE_MATURITY, network)
    }

    /// Like [`Blockchain::new`] but with an explicit coinbase-maturity depth.
    /// Production always uses [`COINBASE_MATURITY`] (via `new`); this exists so
    /// tests can spend freshly-mined coins without mining a full maturity window.
    pub fn with_maturity(pow: P, maturity: u64) -> Self {
        Self::build(pow, maturity, crate::address::Network::Mainnet)
    }

    fn build(pow: P, maturity: u64, network: crate::address::Network) -> Self {
        let mut chain = Blockchain {
            pow,
            network,
            blocks: Vec::new(),
            undos: Vec::new(),
            block_ids: Vec::new(),
            timestamps: Vec::new(),
            cumulative_difficulties: Vec::new(),
            outputs: Vec::new(),
            output_membership: HashMap::new(),
            output_meta: Vec::new(),
            spent_key_images: HashSet::new(),
            emitted: 0,
            maturity,
        };
        chain.apply_genesis();
        chain
    }

    // Genesis is applied directly, not through `add_block`: it is the axiom the
    // consensus rules are defined against, so it cannot be validated by them.
    // Unlike a mined block it carries the founder **premine** coinbase, so its
    // output is indexed into the global set (global index 0, spendable) and its
    // amount is counted as emitted — the emission curve then continues from the
    // premined baseline. Genesis can never be rolled back, so its `Undo` is
    // inert.
    fn apply_genesis(&mut self) {
        let block = Block::genesis_for(self.network.params());
        // The premine is a coinbase output at height 0; it matures like any other
        // coinbase (spendable once the chain is COINBASE_MATURITY blocks deep).
        for member in block.coinbase.output_refs() {
            self.push_output(member, 0, true);
        }
        let premined = block.coinbase.total().expect("genesis premine fits u64");
        self.blocks.push(StoredBlock { block: block.clone(), txs: Vec::new() });
        self.undos.push(Undo { outputs_len_before: 0, emitted_before: 0 });
        self.block_ids.push(block.id());
        self.timestamps.push(block.header.timestamp);
        self.cumulative_difficulties.push(MIN_DIFFICULTY as u128);
        self.emitted = premined;
    }

    /// The hash of the genesis block this chain is rooted at.
    pub fn genesis_id(&self) -> [u8; 32] {
        self.block_ids[0]
    }

    /// Which network this chain belongs to.
    pub fn network(&self) -> crate::address::Network {
        self.network
    }

    /// This chain's parameters — p2p magic, default ports, genesis constants.
    pub fn params(&self) -> &'static crate::params::ChainParams {
        self.network.params()
    }

    /// The RandomX epoch seed for a block at `height`: the id of the block at
    /// [`crate::pow::randomx_seed_height`]. Always resolves — that height is
    /// strictly below `height` and therefore already on the chain (falling back
    /// to genesis for the first epoch). Seedless PoW ignores the value.
    pub fn seed_for_height(&self, height: u64) -> [u8; 32] {
        let seed_height = crate::pow::randomx_seed_height(height);
        self.block_at(seed_height).map(|s| s.block.id()).unwrap_or_else(|| self.genesis_id())
    }

    // --- state queries ---------------------------------------------------

    /// Number of blocks in the chain (also the height of the next block).
    pub fn height(&self) -> u64 {
        self.block_ids.len() as u64
    }

    /// Hash of the current tip, or the zero hash for an empty chain.
    pub fn tip_id(&self) -> [u8; 32] {
        self.block_ids.last().copied().unwrap_or([0u8; 32])
    }

    /// Total accumulated work — the fork-choice metric.
    pub fn cumulative_difficulty(&self) -> u128 {
        self.cumulative_difficulties.last().copied().unwrap_or(0)
    }

    /// Coins emitted so far (subsidy only; fees are recycled, not new coins).
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Size of the global output set.
    pub fn num_outputs(&self) -> u64 {
        self.outputs.len() as u64
    }

    /// The output at a global index, if it exists.
    pub fn output(&self, index: u64) -> Option<RingMember> {
        self.outputs.get(usize::try_from(index).ok()?).copied()
    }

    /// The block accepted at `height` (with its transactions), if we have it.
    /// This is what lets a node serve history to a syncing peer or wallet.
    pub fn block_at(&self, height: u64) -> Option<&StoredBlock> {
        self.blocks.get(usize::try_from(height).ok()?)
    }

    /// Every block on the current canonical chain, oldest first. After a reorg
    /// this reflects the *new* branch, so a persistent store can be rewritten
    /// from it.
    pub fn blocks(&self) -> &[StoredBlock] {
        &self.blocks
    }

    /// The difficulty the next block must satisfy.
    pub fn next_difficulty(&self) -> Difficulty {
        next_difficulty(&self.timestamps, &self.cumulative_difficulties)
    }

    /// Has `image` already been spent on this chain?
    pub fn is_spent(&self, image: &KeyImage) -> bool {
        self.spent_key_images.contains(image)
    }

    /// Fork choice: would a competing chain of `their_cumulative_difficulty`
    /// replace ours? (Strictly greater work wins; ties keep the incumbent.)
    pub fn would_reorg_to(&self, their_cumulative_difficulty: u128) -> bool {
        their_cumulative_difficulty > self.cumulative_difficulty()
    }

    /// Median of the most recent [`MTP_WINDOW`] block timestamps. A new block's
    /// timestamp must be strictly greater; miners use this to pick a valid one.
    pub fn median_time_past(&self) -> u64 {
        if self.timestamps.is_empty() {
            return 0;
        }
        let start = self.timestamps.len().saturating_sub(MTP_WINDOW);
        let mut window: Vec<u64> = self.timestamps[start..].to_vec();
        window.sort_unstable();
        window[window.len() / 2]
    }

    // --- block application -----------------------------------------------

    /// Validate `block` (with its full transactions `txs`) against the current
    /// tip and, if valid, append it — updating the output set, spent images,
    /// difficulty, and emission.
    pub fn add_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        block: &Block,
        txs: &[Transaction],
    ) -> Result<(), ChainError> {
        // 1. Links to the tip.
        if block.header.prev_id != self.tip_id() {
            return Err(ChainError::BadPrevId);
        }

        // 2. Proof of work meets the required difficulty. Rekey the PoW to this
        //    block's epoch seed first (a no-op for seedless PoW like Keccak).
        let seed = self.seed_for_height(self.height());
        self.pow.reseed(&seed);
        let difficulty = self.next_difficulty();
        if !check_hash(&block.pow_hash(&self.pow), difficulty) {
            return Err(ChainError::BadPow);
        }

        // 3. Timestamp strictly after the median of recent blocks, and not too
        //    far in the future (guards difficulty against timestamp inflation).
        if self.height() > 0 && block.header.timestamp <= self.median_time_past() {
            return Err(ChainError::BadTimestamp);
        }
        if block.header.timestamp > now_secs().saturating_add(FUTURE_TIME_LIMIT) {
            return Err(ChainError::TimestampTooFarAhead);
        }

        // 4. Coinbase height matches.
        if block.coinbase.height != self.height() {
            return Err(ChainError::BadCoinbaseHeight);
        }

        // 5. Provided transactions match the block's committed hashes.
        if txs.len() != block.tx_hashes.len() {
            return Err(ChainError::TxHashMismatch);
        }
        for (tx, expected) in txs.iter().zip(&block.tx_hashes) {
            if &tx.hash() != expected {
                return Err(ChainError::TxHashMismatch);
            }
        }

        // 6. Validate each transaction and gather its key images / fees.
        let mut total_fees: u64 = 0;
        let mut block_images: HashSet<KeyImage> = HashSet::new();
        for tx in txs {
            // Per-transaction validity against current chain state (internal
            // verify + ring membership + not-already-spent).
            self.validate_tx(rng, tx)?;

            // Additionally, no key image may repeat *within* this block.
            for image in tx.key_images() {
                if !block_images.insert(image) {
                    return Err(ChainError::DoubleSpend);
                }
            }

            total_fees = total_fees.checked_add(tx.fee).ok_or(ChainError::FeeOverflow)?;
        }

        // 7. No output this block creates may duplicate an existing one, or
        //    another in the same block.
        //
        //    Outputs are identified by `[P, C]` and indexed by that key, so two
        //    identical outputs would make the index ambiguous — and the second
        //    silently replaces the first. That is a **maturity bypass**: a miner
        //    can mine a coinbase, then publish a transaction whose output copies
        //    that coinbase's `[P, C]` (both are attacker-chosen wire values, and
        //    a coinbase commitment's opening is public — mask 1 over a public
        //    amount). The duplicate is recorded as a *non-coinbase* output, so
        //    the immature coinbase resolves to it and becomes spendable.
        //
        //    Honest transactions never collide here: one-time keys derive from a
        //    random per-transaction key, so a repeat is cryptographically
        //    negligible. Rejecting duplicates outright removes the ambiguity.
        let mut new_outputs: HashSet<[u8; 64]> = HashSet::new();
        for member in block
            .coinbase
            .output_refs()
            .into_iter()
            .chain(txs.iter().flat_map(|t| t.output_refs()))
        {
            let key = membership_key(&member);
            if self.output_membership.contains_key(&key) || !new_outputs.insert(key) {
                return Err(ChainError::DuplicateOutput);
            }
        }

        // 8. Coinbase claims exactly subsidy + fees.
        let subsidy = base_reward(self.emitted);
        let allowed = subsidy.checked_add(total_fees).ok_or(ChainError::FeeOverflow)?;
        if !block.coinbase.is_valid(allowed) {
            return Err(ChainError::BadCoinbaseReward);
        }

        // --- All checks passed; commit state. ---
        // Capture what we cannot re-derive later, so this block can be undone.
        let undo = Undo { outputs_len_before: self.outputs.len(), emitted_before: self.emitted };
        let height = self.height();
        for member in block.coinbase.output_refs() {
            self.push_output(member, height, true);
        }
        for tx in txs {
            for member in tx.output_refs() {
                self.push_output(member, height, false);
            }
            for image in tx.key_images() {
                self.spent_key_images.insert(image);
            }
        }

        self.emitted = self.emitted.saturating_add(subsidy);
        self.blocks.push(StoredBlock { block: block.clone(), txs: txs.to_vec() });
        self.undos.push(undo);
        self.block_ids.push(block.id());
        self.timestamps.push(block.header.timestamp);
        self.cumulative_difficulties.push(self.cumulative_difficulty() + difficulty as u128);
        Ok(())
    }

    fn push_output(&mut self, member: RingMember, height: u64, coinbase: bool) {
        let index = self.outputs.len() as u64;
        self.output_membership.insert(membership_key(&member), index);
        self.outputs.push(member);
        self.output_meta.push(OutputMeta { height, coinbase });
    }

    /// Is the output at global `index` spendable — i.e. referenceable in a ring —
    /// given a chain of height `at_height`? Non-coinbase outputs always are;
    /// coinbase outputs must be [`COINBASE_MATURITY`] blocks deep.
    fn output_spendable_at(&self, index: u64, at_height: u64) -> bool {
        match self.output_meta.get(index as usize) {
            Some(meta) if meta.coinbase => at_height >= meta.height.saturating_add(self.maturity),
            Some(_) => true,
            None => false,
        }
    }

    // --- reorganisation ---------------------------------------------------

    /// Undo the tip block, returning it. Reverses exactly what `add_block`
    /// committed: its outputs leave the set, its key images become unspent, and
    /// emission/work/timestamps rewind.
    fn pop_block(&mut self) -> Option<StoredBlock> {
        let stored = self.blocks.pop()?;
        let undo = self.undos.pop()?;

        // Its inputs are no longer spent.
        for tx in &stored.txs {
            for image in tx.key_images() {
                self.spent_key_images.remove(&image);
            }
        }
        // Its outputs no longer exist. (Outputs are only ever appended, so the
        // block's outputs are exactly the tail past `outputs_len_before`.)
        for member in self.outputs.drain(undo.outputs_len_before..) {
            self.output_membership.remove(&membership_key(&member));
        }
        self.output_meta.truncate(undo.outputs_len_before);

        self.emitted = undo.emitted_before;
        self.block_ids.pop();
        self.timestamps.pop();
        self.cumulative_difficulties.pop();
        Some(stored)
    }

    /// Roll the chain back to `height`, returning the removed blocks oldest-first.
    /// A no-op if already at or below `height`.
    ///
    /// Genesis is never removed: the target is clamped to height 1, so a chain
    /// always remains rooted at block 0.
    pub fn rollback_to(&mut self, height: u64) -> Vec<StoredBlock> {
        let height = height.max(1);
        let mut removed = Vec::new();
        while self.height() > height {
            match self.pop_block() {
                Some(stored) => removed.push(stored),
                None => break,
            }
        }
        removed.reverse();
        removed
    }

    /// Switch to `branch` if it is heavier than the current chain.
    ///
    /// `branch` is a run of blocks starting at the fork height (its first block's
    /// `coinbase.height`), oldest first. It is validated in full, and a branch
    /// that turns out to be invalid *or* merely lighter leaves this chain
    /// exactly as it was.
    ///
    /// That guarantee used to come from validating against `self.clone()` — a
    /// copy of every block with its decoded transactions, the output set and the
    /// spent key images. It made **peak memory twice the chain state for every
    /// reorg considered**, including the one-block reorgs that are routine when
    /// miners race, and including the ones that are rejected. Measured on the
    /// testnet: a node stepped +263 MB on a reorg and stayed there. A peer can
    /// also induce the evaluation by offering a branch, so it was a cheap remote
    /// lever on double a node's memory, bounded by nothing the peer sends.
    ///
    /// Instead the branch is applied in place and undone if it does not win.
    /// Rolling back is exact — `pop_block` removes the key images, drains the
    /// outputs it added, and restores `emitted` — and the blocks put back are
    /// ones this chain already accepted, so the work is bounded by the depth of
    /// the reorg rather than by the length of the chain.
    ///
    /// On success returns the discarded blocks so a caller can put their
    /// transactions back in a mempool.
    pub fn try_reorg<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        branch: &[(Block, Vec<Transaction>)],
    ) -> Result<Reorg, ChainError>
    where
        P: Clone,
    {
        let first = branch.first().ok_or(ChainError::EmptyBranch)?;
        let fork_height = first.0.coinbase.height;
        if fork_height > self.height() {
            return Err(ChainError::BadPrevId); // gap: nothing to attach to
        }
        // A branch may never replace genesis. This is what makes the chain's
        // identity immutable: any candidate must descend from *our* block 0, so a
        // foreign chain cannot be adopted no matter how much work it carries.
        if fork_height == 0 {
            return Err(ChainError::CannotReplaceGenesis);
        }

        let work_before = self.cumulative_difficulty();
        let discarded = self.rollback_to(fork_height);

        let mut failure = None;
        for (block, txs) in branch {
            if let Err(e) = self.add_block(rng, block, txs) {
                failure = Some(e);
                break;
            }
        }
        if failure.is_none() && self.cumulative_difficulty() <= work_before {
            failure = Some(ChainError::NotHeavier);
        }

        if let Some(e) = failure {
            // Put back exactly what was here. These blocks were on this chain a
            // moment ago, so they are valid against the same predecessors under
            // rules that depend only on the chain — the same reason `replay`
            // can rebuild from the log.
            self.rollback_to(fork_height);
            for stored in &discarded {
                self.add_block(rng, &stored.block, &stored.txs).expect(
                    "a block this chain already accepted must re-apply after a                      rejected reorg; if it does not, the chain is corrupt and                      continuing would hide it",
                );
            }
            return Err(e);
        }

        Ok(Reorg { discarded, applied: branch.len() })
    }

    /// Is `member` a real output in the global set? (Used for ring validation.)
    pub fn contains_output(&self, member: &RingMember) -> bool {
        self.output_membership.contains_key(&membership_key(member))
    }

    /// The global index of `member`, if it is in the output set.
    pub fn output_index(&self, member: &RingMember) -> Option<u64> {
        self.output_membership.get(&membership_key(member)).copied()
    }

    /// Can `member` be spent (or used as a decoy) right now — i.e. is it a real
    /// output that is not an immature coinbase? Wallets use this to avoid
    /// selecting an unspendable output as an input.
    pub fn is_spendable(&self, member: &RingMember) -> bool {
        match self.output_index(member) {
            Some(index) => self.output_spendable_at(index, self.height()),
            None => false,
        }
    }

    /// Validate a single transaction against current chain state, independent of
    /// any block: internal [`Transaction::verify`], every ring member exists in
    /// the output set, and no key image is already spent on-chain.
    ///
    /// Shared by [`Self::add_block`] and the mempool ([`crate::mempool`]). Does
    /// **not** check for conflicts against other unconfirmed transactions — that
    /// is the mempool's responsibility.
    pub fn validate_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        tx: &Transaction,
    ) -> Result<(), ChainError> {
        // Cheap, structural rejections first; the signature check last.
        //
        // Verification is a CLSAG over a ring of 16 plus a Bulletproofs+ range
        // proof — milliseconds. Everything below it here is a length comparison
        // or a hash lookup. A peer may send 5000 messages a second, and a
        // transaction rejected here is never stored, so it never becomes
        // "already known": one pre-signed transaction spending an output that
        // is already spent on-chain could be replayed forever, buying an
        // attacker unbounded verification work for the cost of the bandwidth.
        //
        // Rejecting early is safe in a way that admitting early would not be:
        // nothing is recorded, and a transaction still has to verify before it
        // is accepted anywhere.
        let height = self.height();
        for input in &tx.inputs {
            // Exactly, not at least — see `RING_SIZE`. A larger ring is no more
            // private than the uniform one and marks its author.
            if input.ring.len() != RING_SIZE {
                return Err(ChainError::BadRingSize);
            }
            for member in &input.ring {
                // Every ring member must be a real output, and — because ring
                // signatures hide which member is real — no member may be an
                // immature coinbase (else an immature coinbase could be spent
                // by hiding it among decoys).
                let index = self.output_index(member).ok_or(ChainError::UnknownRingMember)?;
                if !self.output_spendable_at(index, height) {
                    return Err(ChainError::ImmatureCoinbase);
                }
            }
        }
        for image in tx.key_images() {
            if self.spent_key_images.contains(&image) {
                return Err(ChainError::DoubleSpend);
            }
        }
        tx.verify(rng).map_err(ChainError::InvalidTx)?;
        Ok(())
    }

    // --- decoy selection -------------------------------------------------

    /// Select a ring of `ring_size` members for the real output at
    /// `real_index`, choosing decoys **uniformly** from the output set. Returns
    /// the ring (real member placed at the returned signer index) and that index.
    ///
    /// `None` if the set is too small for the requested ring size.
    pub fn select_ring_uniform<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
    ) -> Option<(Vec<RingMember>, usize)> {
        self.assemble_ring(rng, ring_size, real_index, |rng, n| {
            (rng.next_u64() % n as u64) as usize
        })
    }

    /// Like [`Self::select_ring_uniform`] but biased toward **recent** outputs
    /// via a gamma-shaped age distribution (a simplification of Monero's
    /// output-time gamma; see the module note).
    pub fn select_ring_recency_biased<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
    ) -> Option<(Vec<RingMember>, usize)> {
        let height = self.height();
        let meta = &self.output_meta;
        self.assemble_ring(rng, ring_size, real_index, move |rng, n| {
            // Sample log(age in seconds), exponentiate to an age, and convert
            // that to a block height. Mapping through *height* rather than
            // straight to an index matters: outputs are not spread evenly over
            // blocks, so treating an index as a proxy for age would skew the
            // distribution by however much transaction volume has varied.
            let age_secs = sample_gamma(rng, GAMMA_SHAPE, GAMMA_SCALE).exp();
            let age_blocks = (age_secs / crate::pow::TARGET_BLOCK_TIME as f64) as u64;

            // The distribution has a tail reaching years back, which on a young
            // chain is older than the chain itself. Clamping those samples to
            // height 0 would pile them onto the very first outputs — on this
            // chain, the premine — so it would appear in rings far more often
            // than any other output and become a marker rather than a decoy.
            //
            // A sample older than the chain carries no information about where
            // a real spend sits, so fall back to a uniform draw instead of
            // pretending it points at the genesis end.
            if age_blocks >= height {
                return (rng.next_u64() as usize) % n;
            }
            let target_height = height - age_blocks;

            // First output at or after that height. Heights are non-decreasing
            // in index, so this is a binary search.
            let lo = meta.partition_point(|m| m.height < target_height);
            if lo >= n {
                // Age fell inside the newest block: take from the tip.
                return n - 1;
            }
            // Outputs sharing that height are interchangeable in age, so pick
            // among them uniformly rather than always taking the first — which
            // would make the earliest output in a block a permanent favourite.
            let hi = meta.partition_point(|m| m.height <= meta[lo].height).min(n);
            if hi > lo + 1 {
                lo + (rng.next_u64() as usize) % (hi - lo)
            } else {
                lo
            }
        })
    }

    // Shared ring assembly: draw distinct decoy indices via `pick`, place the
    // real member at a random position.
    fn assemble_ring<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        ring_size: usize,
        real_index: u64,
        mut pick: impl FnMut(&mut R, usize) -> usize,
    ) -> Option<(Vec<RingMember>, usize)> {
        let n = self.outputs.len();
        if ring_size == 0 || ring_size > n {
            return None;
        }
        let real = self.output(real_index)?;

        // Only outputs a transaction may legally reference are eligible decoys:
        // an immature coinbase would make the ring invalid under the
        // coinbase-maturity rule.
        //
        // Outputs are appended in block order, so their heights are
        // non-decreasing in index — which means the outputs too recent to be
        // mature are exactly a **suffix**. Everything before `mature_boundary`
        // is spendable outright, and only that suffix (at most `maturity`
        // blocks' worth of outputs) needs examining. Scanning the whole output
        // set here instead would make every ring assembly cost O(chain size).
        let height = self.height();
        let cutoff = height.saturating_sub(self.maturity);
        let mature_boundary = self.output_meta.partition_point(|m| m.height <= cutoff);
        debug_assert!(
            self.output_meta.windows(2).all(|w| w[0].height <= w[1].height),
            "output heights must be non-decreasing for the suffix bound to hold"
        );
        // Spendable = the whole mature prefix, plus non-coinbase outputs in the
        // recent suffix.
        let recent_spendable: Vec<usize> =
            (mature_boundary..n).filter(|&i| !self.output_meta[i].coinbase).collect();
        let spendable_count = mature_boundary + recent_spendable.len();
        if spendable_count < ring_size {
            return None;
        }

        // Distinct decoy indices (drawn from the spendable set), excluding the
        // real one.
        let mut chosen: HashSet<usize> = HashSet::new();
        chosen.insert(real_index as usize);
        let mut attempts = 0usize;
        while chosen.len() < ring_size {
            let idx = pick(rng, n);
            if self.output_spendable_at(idx as u64, height) {
                chosen.insert(idx);
            }
            attempts += 1;
            if attempts > ring_size * 100 {
                // Degenerate distribution; top up uniformly from the spendable
                // set to guarantee progress. Index `k` addresses the mature
                // prefix first, then the eligible outputs of the recent suffix.
                let k = (rng.next_u64() % spendable_count as u64) as usize;
                let idx = if k < mature_boundary { k } else { recent_spendable[k - mature_boundary] };
                chosen.insert(idx);
            }
        }

        let mut decoys: Vec<usize> = chosen.into_iter().filter(|&i| i != real_index as usize).collect();
        decoys.sort_unstable();

        let signer_index = (rng.next_u64() as usize) % ring_size;
        let mut ring = Vec::with_capacity(ring_size);
        let mut d = decoys.into_iter();
        for pos in 0..ring_size {
            if pos == signer_index {
                ring.push(real);
            } else {
                ring.push(self.outputs[d.next().unwrap()]);
            }
        }
        Some((ring, signer_index))
    }
}

/// A gamma sample via the Marsaglia–Tsang method, using `rng` for randomness.
pub fn sample_gamma<R: rand_core::RngCore>(rng: &mut R, shape: f64, scale: f64) -> f64 {
    if shape < 1.0 {
        let u = uniform(rng).max(f64::MIN_POSITIVE);
        return sample_gamma(rng, shape + 1.0, scale) * u.powf(1.0 / shape);
    }
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = normal(rng);
        let v = (1.0 + c * x).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u = uniform(rng);
        if u < 1.0 - 0.0331 * x * x * x * x {
            return d * v * scale;
        }
        if u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
            return d * v * scale;
        }
    }
}

// A uniform double in [0, 1) from 53 random bits.
fn uniform<R: rand_core::RngCore>(rng: &mut R) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

// A standard normal via Box–Muller.
fn normal<R: rand_core::RngCore>(rng: &mut R) -> f64 {
    let u1 = uniform(rng).max(f64::MIN_POSITIVE);
    let u2 = uniform(rng);
    (-2.0 * u1.ln()).sqrt() * (2.0 * core::f64::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};
    use crate::block::{Block, BlockHeader, Coinbase};
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::Account;
    use crate::pow::KeccakPow;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    // Assemble a block: coinbase to `miner` (subsidy + fees) plus `txs`, mined at
    // the chain's current difficulty. Returns the block and the miner's recovered
    // coinbase output.
    //
    // `timestamp` is an offset from the genesis timestamp, so tests can use small
    // readable numbers while still producing blocks that sit after genesis (a
    // block must beat median-time-past).
    fn make_block(
        chain: &Blockchain<KeccakPow>,
        miner: &Account,
        txs: &[Transaction],
        timestamp: u64,
    ) -> (Block, ReceivedOutput) {
        let timestamp = crate::block::GENESIS_TIMESTAMP + timestamp;
        let subsidy = base_reward(chain.emitted());
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let coinbase = Coinbase::create(&mut OsRng, chain.height(), &address(miner), subsidy + fees);
        let received = coinbase.scan(miner).expect("miner owns its coinbase");
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: txs.iter().map(|t| t.hash()).collect(),
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        (block, received)
    }

    // Mine a coinbase-only block to `miner` and append it; return the miner's
    // recovered coinbase output and its global index.
    fn mine_coinbase(
        chain: &mut Blockchain<KeccakPow>,
        miner: &Account,
        timestamp: u64,
    ) -> (ReceivedOutput, u64) {
        let cb_index = chain.num_outputs();
        let (block, received) = make_block(chain, miner, &[], timestamp);
        chain.add_block(&mut OsRng, &block, &[]).expect("valid coinbase block");
        (received, cb_index)
    }

    // Populate the chain with `n` coinbase-only blocks so the output set has
    // decoys to draw from.
    fn warm_up(chain: &mut Blockchain<KeccakPow>, n: usize, start_ts: u64) {
        let filler = Account::random(&mut OsRng);
        for i in 0..n {
            mine_coinbase(chain, &filler, start_ts + i as u64 * 130);
        }
    }

    fn build_spend(
        chain: &Blockchain<KeccakPow>,
        source: &ReceivedOutput,
        source_index: u64,
        payments: Vec<Payment>,
        fee: u64,
    ) -> Transaction {
        let (ring, signer_index) =
            chain.select_ring_uniform(&mut OsRng, crate::chain::RING_SIZE, source_index).expect("enough outputs");
        let input = source.to_input(ring, signer_index);
        Transaction::build(&mut OsRng, &[input], &payments, fee, &TxKeypair::random(&mut OsRng))
            .unwrap()
    }

    #[test]
    fn genesis_and_growth() {
        use crate::block::PREMINE_AMOUNT;
        let chain = Blockchain::with_maturity(KeccakPow, 1);
        // A new chain is not empty: it is rooted at the canonical genesis.
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_id(), Block::genesis().id());
        assert_eq!(chain.genesis_id(), Block::genesis().id());
        // Genesis carries the premine: one spendable output, counted as emitted.
        assert_eq!(chain.num_outputs(), 1);
        assert_eq!(chain.emitted(), PREMINE_AMOUNT);

        let mut chain = chain;
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.num_outputs(), 2);
        // Block 1's subsidy continues the curve from the premined baseline.
        assert_eq!(chain.emitted(), PREMINE_AMOUNT + base_reward(PREMINE_AMOUNT));
        assert!(chain.cumulative_difficulty() >= 2);
    }

    /// Every node's chain starts at the same block — that is what makes a foreign
    /// chain unadoptable no matter how much work it carries.
    #[test]
    fn genesis_is_identical_everywhere_and_immutable() {
        let a = Blockchain::with_maturity(KeccakPow, 1);
        let b = Blockchain::with_maturity(KeccakPow, 1);
        assert_eq!(a.genesis_id(), b.genesis_id());

        // Genesis cannot be rolled back.
        let mut chain = a;
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        let removed = chain.rollback_to(0); // asks to drop everything
        assert_eq!(removed.len(), 1, "only the mined block may be removed");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_id(), Block::genesis().id());

        // And a branch may not replace it.
        let branch = vec![(Block::genesis(), Vec::new())];
        assert_eq!(
            chain.try_reorg(&mut OsRng, &branch).unwrap_err(),
            ChainError::CannotReplaceGenesis
        );
    }

    #[test]
    fn spend_a_coinbase_across_blocks() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );

        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 5_000);
        let height_before = chain.height();
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();
        assert_eq!(chain.height(), height_before + 1);
        assert!(chain.is_spent(&received.key_image));
        // Bob can find his payment in the newly-added transaction.
        assert_eq!(tx.scan(&bob)[0].amount, reward - fee);
    }

    #[test]
    fn double_spend_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        // First spend accepted.
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 5_000);
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        // A different transaction spending the same output → same key image.
        let tx2 = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let (block2, _) = make_block(&chain, &miner, std::slice::from_ref(&tx2), 9_000);
        assert_eq!(
            chain.add_block(&mut OsRng, &block2, std::slice::from_ref(&tx2)),
            Err(ChainError::DoubleSpend)
        );
    }

    #[test]
    fn wrong_prev_id_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);

        let (mut block, _) = make_block(&chain, &miner, &[], 2_000);
        block.header.prev_id = [42u8; 32]; // not the tip
        block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(chain.add_block(&mut OsRng, &block, &[]), Err(ChainError::BadPrevId));
    }

    #[test]
    fn coinbase_over_claim_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        // Claim one atomic unit too much (block 1, the first after genesis).
        // The allowed subsidy continues the curve from the premined baseline.
        let coinbase =
            Coinbase::create(&mut OsRng, chain.height(), &address(&miner), base_reward(chain.emitted()) + 1);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 1_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: vec![],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(
            chain.add_block(&mut OsRng, &block, &[]),
            Err(ChainError::BadCoinbaseReward)
        );
    }

    #[test]
    fn far_future_timestamp_is_rejected() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        // A block dated a day ahead of the validator's clock is rejected.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (block, _) = make_block(&chain, &miner, &[], now + 24 * 60 * 60);
        assert_eq!(
            chain.add_block(&mut OsRng, &block, &[]),
            Err(ChainError::TimestampTooFarAhead),
            "a future block is *not yet* valid, which is a different verdict from invalid"
        );
    }

    /// A timestamp at or below the median of recent blocks is permanently
    /// invalid — chain-derived, so every node agrees and no amount of waiting
    /// makes it acceptable. The contrast with the test above is the point: the
    /// two rejections must not be conflated, because only one of them is
    /// evidence that the sender did something wrong.
    #[test]
    fn a_stale_timestamp_is_permanently_invalid_not_merely_early() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 12, 2_000);

        // Exactly the median — the rule requires *strictly* greater.
        let stale = chain.median_time_past() - crate::block::GENESIS_TIMESTAMP;
        let (block, _) = make_block(&chain, &miner, &[], stale);
        assert_eq!(chain.add_block(&mut OsRng, &block, &[]), Err(ChainError::BadTimestamp));
    }

    /// The ring size is **exact**, so a wrong count is rejected in either
    /// direction.
    ///
    /// Too small is the obvious harm — a ring of one names the spender. Too
    /// large is subtler and is why a floor is not enough: an oversized ring is
    /// no more private than the uniform one, and it *marks* its author, cutting
    /// their anonymity set down to whoever else made the same unusual choice.
    /// Uniformity is the property being defended, not merely "enough decoys".
    #[test]
    fn a_ring_of_the_wrong_size_is_rejected_in_either_direction() {
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        for wrong in [1usize, 5, RING_SIZE - 1, RING_SIZE + 1] {
            let mut chain = Blockchain::with_maturity(KeccakPow, 1);
            let miner = Account::random(&mut OsRng);
            let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
            // Enough outputs that even the oversized ring can be assembled —
            // otherwise the test would pass for the wrong reason (no decoys)
            // rather than because consensus refused the size.
            warm_up(&mut chain, 40, 1_200);

            let (ring, signer) =
                chain.select_ring_uniform(&mut OsRng, wrong, cb_index).expect("ring assembles");
            assert_eq!(ring.len(), wrong, "the test must actually build a {wrong}-member ring");

            let input = received.to_input(ring, signer);
            let tx = Transaction::build(
                &mut OsRng,
                &[input],
                &[Payment { destination: address(&bob), amount: received.amount - fee }],
                fee,
                &TxKeypair::random(&mut OsRng),
            )
            .unwrap();
            // `make_block` takes an OFFSET from the genesis timestamp, not an
            // absolute time. It must clear the warm-up's last block (offset
            // 1_200 + 39*130) or the block is refused on its timestamp and the
            // ring rule is never reached — which would make this test pass for
            // entirely the wrong reason.
            let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 20_000);
            assert_eq!(
                chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)),
                Err(ChainError::BadRingSize),
                "a ring of {wrong} must be refused (consensus requires exactly {RING_SIZE})"
            );
        }
    }

    /// ...and the exact size is accepted, so the rule above is not simply
    /// rejecting everything.
    #[test]
    fn a_ring_of_exactly_the_consensus_size_is_accepted() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 40, 1_200);

        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let (ring, signer) =
            chain.select_ring_uniform(&mut OsRng, RING_SIZE, cb_index).expect("ring assembles");
        let input = received.to_input(ring, signer);
        let tx = Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(&bob), amount: received.amount - fee }],
            fee,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap();
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 20_000);
        assert_eq!(chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)), Ok(()));
    }

    #[test]
    fn ring_member_must_exist_in_output_set() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;

        let mut tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        // Replace a non-signer ring member with an output not on the chain.
        let signer_is = tx.inputs[0]
            .ring
            .iter()
            .position(|m| m.key == received.one_time_key)
            .unwrap();
        let victim = (signer_is + 1) % tx.inputs[0].ring.len();
        let fake_key = crate::keys::PrivateKey(curve25519_dalek::scalar::Scalar::random(&mut OsRng))
            .public_key();
        tx.inputs[0].ring[victim] =
            RingMember::new(fake_key, crate::amounts::Opening::random(1, &mut OsRng).commit());

        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 9_000);
        // The corrupted ring breaks the signature (the message changed); had it
        // verified it would still be caught as an unknown ring member.
        let err = chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap_err();
        assert!(matches!(err, ChainError::UnknownRingMember | ChainError::InvalidTx(_)));
    }

    #[test]
    fn fees_flow_to_the_miner() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);
        let reward = received.amount;
        let bob = Account::random(&mut OsRng);
        let fee = 3 * (ATOMIC_UNITS / 100);

        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: reward - fee }],
            fee,
        );
        let subsidy = base_reward(chain.emitted());

        // A coinbase that forgets the fee is rejected (add_block does not mutate
        // on error, so we can then submit the correct one).
        let bad = Coinbase::create(&mut OsRng, chain.height(), &address(&miner), subsidy);
        let mut bad_block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 9_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: bad,
            tx_hashes: vec![tx.hash()],
        };
        bad_block.mine(&KeccakPow, chain.next_difficulty());
        assert_eq!(
            chain.add_block(&mut OsRng, &bad_block, std::slice::from_ref(&tx)),
            Err(ChainError::BadCoinbaseReward)
        );

        // The correct coinbase (subsidy + fee) is accepted.
        let (good_block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 9_000);
        assert!(chain.add_block(&mut OsRng, &good_block, std::slice::from_ref(&tx)).is_ok());
    }

    // Mine `n` blocks onto `chain` from `miner`, returning them as a branch.
    fn extend(
        chain: &mut Blockchain<KeccakPow>,
        miner: &Account,
        n: usize,
        start_ts: u64,
    ) -> Vec<(Block, Vec<Transaction>)> {
        let mut branch = Vec::new();
        for i in 0..n {
            let (block, _) = make_block(chain, miner, &[], start_ts + i as u64 * 130);
            chain.add_block(&mut OsRng, &block, &[]).unwrap();
            branch.push((block, Vec::new()));
        }
        branch
    }

    #[test]
    fn reorg_switches_to_a_heavier_branch() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 3, 1_000); // blocks 1,2,3 (genesis is 0)
        let original_tip = chain.tip_id();
        assert_eq!(chain.height(), 4);

        // A competing branch forking after block 1, two blocks longer.
        let mut fork = chain.clone();
        fork.rollback_to(2); // keep genesis + block 1
        let branch = extend(&mut fork, &miner, 4, 50_000); // blocks 2,3,4,5

        let reorg = chain.try_reorg(&mut OsRng, &branch).expect("heavier branch wins");
        assert_eq!(chain.height(), 6);
        assert_ne!(chain.tip_id(), original_tip);
        assert_eq!(chain.tip_id(), fork.tip_id());
        assert_eq!(reorg.applied, 4);
        // The old blocks 2 and 3 were dropped, oldest first.
        assert_eq!(reorg.discarded.len(), 2);
        assert_eq!(reorg.discarded[0].block.coinbase.height, 2);
        assert_eq!(reorg.discarded[1].block.coinbase.height, 3);
        // Genesis is still the root.
        assert_eq!(chain.genesis_id(), Block::genesis().id());
    }

    #[test]
    /// A rejected reorg must leave a chain that still *works*, not one that
    /// merely looks right in its summary fields.
    ///
    /// The branch is applied in place and undone now, so the restore is real
    /// code rather than dropping a copy. Extending afterwards is what catches an
    /// inconsistency between the blocks, the output set, the timestamps and the
    /// cumulative difficulties — a mismatch a height check would sail past.
    #[test]
    fn a_rejected_reorg_leaves_a_chain_that_still_extends() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 4, 1_000);
        let tip = chain.tip_id();
        let work = chain.cumulative_difficulty();
        let outputs = chain.num_outputs();
        let emitted = chain.emitted();

        let mut fork = chain.clone();
        fork.rollback_to(2);
        let lighter = extend(&mut fork, &miner, 1, 50_000);
        assert_eq!(chain.try_reorg(&mut OsRng, &lighter).unwrap_err(), ChainError::NotHeavier);

        assert_eq!(chain.tip_id(), tip, "tip must be restored");
        assert_eq!(chain.cumulative_difficulty(), work);
        assert_eq!(chain.num_outputs(), outputs);
        assert_eq!(chain.emitted(), emitted, "emission must be restored, not double counted");

        // The real check: it can still take blocks.
        extend(&mut chain, &miner, 2, 90_000);
        assert_eq!(chain.height(), 7);
    }

    /// The same, for a branch that is rejected as *invalid* rather than lighter.
    /// That exits from a different point, part-way through applying the branch.
    #[test]
    fn a_reorg_rejected_as_invalid_restores_the_chain() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 4, 1_000);
        let tip = chain.tip_id();
        let outputs = chain.num_outputs();
        let emitted = chain.emitted();

        // A longer branch whose second block has had its proof of work broken,
        // so it fails part-way in rather than at the first block.
        let mut fork = chain.clone();
        fork.rollback_to(2);
        let mut branch = extend(&mut fork, &miner, 4, 2_000);
        branch[1].0.header.nonce = branch[1].0.header.nonce.wrapping_add(1);

        assert!(chain.try_reorg(&mut OsRng, &branch).is_err());
        assert_eq!(chain.tip_id(), tip, "a part-applied branch must be undone");
        assert_eq!(chain.num_outputs(), outputs);
        assert_eq!(chain.emitted(), emitted);
        extend(&mut chain, &miner, 1, 90_000);
        assert_eq!(chain.height(), 6);
    }

    #[test]
    fn reorg_rejects_a_lighter_branch_and_changes_nothing() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        extend(&mut chain, &miner, 4, 1_000); // blocks 1..4
        let tip = chain.tip_id();
        let work = chain.cumulative_difficulty();
        let outputs = chain.num_outputs();
        assert_eq!(chain.height(), 5);

        // A one-block branch forking after block 1 has strictly less work.
        let mut fork = chain.clone();
        fork.rollback_to(2);
        let branch = extend(&mut fork, &miner, 1, 50_000);

        assert_eq!(chain.try_reorg(&mut OsRng, &branch).unwrap_err(), ChainError::NotHeavier);
        // Untouched.
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.tip_id(), tip);
        assert_eq!(chain.cumulative_difficulty(), work);
        assert_eq!(chain.num_outputs(), outputs);
    }

    /// Rolling back a spend must un-spend its key image and remove its outputs —
    /// otherwise the coins would be permanently frozen (image still marked spent)
    /// or phantom outputs would linger in the ring set.
    #[test]
    fn rollback_restores_spent_images_and_outputs() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let height_before = chain.height();
        let outputs_before = chain.num_outputs();
        let emitted_before = chain.emitted();

        // Spend the coinbase in a block.
        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: received.amount - fee }],
            fee,
        );
        let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 60_000);
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        assert!(chain.is_spent(&received.key_image));
        assert!(chain.num_outputs() > outputs_before);

        // Roll it back.
        let removed = chain.rollback_to(height_before);
        assert_eq!(removed.len(), 1);
        assert_eq!(chain.height(), height_before);
        assert_eq!(chain.num_outputs(), outputs_before, "block's outputs must be gone");
        assert_eq!(chain.emitted(), emitted_before, "emission must rewind");
        assert!(!chain.is_spent(&received.key_image), "key image must be spendable again");

        // The rolled-back outputs are really gone from the ring set.
        for member in removed[0].block.coinbase.output_refs() {
            assert!(!chain.contains_output(&member));
        }
        // And the same transaction can be mined again onto the restored chain.
        let (block2, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 61_000);
        assert!(chain.add_block(&mut OsRng, &block2, std::slice::from_ref(&tx)).is_ok());
    }

    /// Every piece of mutable chain state, in a deterministic form.
    ///
    /// The point is that it is **exhaustive rather than selective**. The test
    /// above checks a hand-picked list — height, output count, emission, one key
    /// image — which is precisely how a *newly added* field gets forgotten in
    /// `pop_block`: nothing fails, because nothing looks at it.
    ///
    /// **The destructuring below is load-bearing, not style.** An earlier version
    /// of this comment claimed that hashing everything meant the next field added
    /// to `Blockchain` would "either get undone or break this test" — which was
    /// false, and an independent review caught it. A new field simply would not
    /// appear here, and the test would pass while `pop_block` silently failed to
    /// restore it. Binding every field by name makes that impossible: adding one
    /// to the struct stops this file compiling until someone decides, explicitly,
    /// whether it belongs in the fingerprint.
    ///
    /// Hash maps and sets are sorted first: their iteration order is not stable,
    /// and a fingerprint that changed run to run would be worthless.
    fn state_fingerprint<P: ProofOfWork>(c: &Blockchain<P>) -> Vec<u8> {
        // Exhaustive on purpose — see above. `..` must never be added here.
        let Blockchain {
            // Immutable configuration: fixed at construction, so `pop_block` has
            // nothing to restore and they are deliberately not fingerprinted.
            pow: _,
            network: _,
            maturity: _,
            // Everything below is mutable state that `add_block` writes and
            // `pop_block` must reverse exactly.
            blocks,
            undos,
            block_ids,
            timestamps,
            cumulative_difficulties,
            outputs,
            output_membership,
            output_meta,
            spent_key_images,
            emitted,
        } = c;

        let mut f = Vec::new();
        f.extend_from_slice(&(blocks.len() as u64).to_le_bytes());
        for b in blocks {
            f.extend_from_slice(&b.block.id());
            f.extend_from_slice(&(b.txs.len() as u64).to_le_bytes());
            for t in &b.txs {
                f.extend_from_slice(&t.hash());
            }
        }
        f.extend_from_slice(&(undos.len() as u64).to_le_bytes());
        for u in undos {
            f.extend_from_slice(&u.outputs_len_before.to_le_bytes());
            f.extend_from_slice(&u.emitted_before.to_le_bytes());
        }
        for id in block_ids {
            f.extend_from_slice(id);
        }
        for t in timestamps {
            f.extend_from_slice(&t.to_le_bytes());
        }
        for d in cumulative_difficulties {
            f.extend_from_slice(&d.to_le_bytes());
        }
        for m in outputs {
            f.extend_from_slice(&membership_key(m));
        }
        let mut membership: Vec<([u8; 64], u64)> =
            output_membership.iter().map(|(k, v)| (*k, *v)).collect();
        membership.sort();
        for (k, v) in membership {
            f.extend_from_slice(&k);
            f.extend_from_slice(&v.to_le_bytes());
        }
        for m in output_meta {
            f.extend_from_slice(&m.height.to_le_bytes());
            f.push(m.coinbase as u8);
        }
        let mut images: Vec<[u8; 32]> = spent_key_images.iter().map(|i| i.to_bytes()).collect();
        images.sort();
        for i in images {
            f.extend_from_slice(&i);
        }
        f.extend_from_slice(&emitted.to_le_bytes());
        f
    }

    /// **Applying a block and undoing it must leave the chain exactly as it was.**
    ///
    /// This is the property a reorg depends on. If `pop_block` misses any part of
    /// what `add_block` wrote, the node carries silent corruption forward: a key
    /// image still marked spent locks an honest user out of their own coins
    /// forever, an output left in the ring set can be drawn as a decoy that no
    /// longer exists, and stale emission miscounts the subsidy from then on.
    /// None of that announces itself — the node keeps running and simply
    /// disagrees with the network.
    ///
    /// Checked over a block with a real spend (so key images, outputs, emission
    /// and the membership index all move), and repeatedly, since an undo that
    /// merely *looks* idempotent once may not be.
    #[test]
    fn applying_and_undoing_a_block_restores_the_chain_exactly() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index) = mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 15, 1_200);

        let before = state_fingerprint(&chain);

        let bob = Account::random(&mut OsRng);
        let fee = ATOMIC_UNITS / 100;
        let tx = build_spend(
            &chain,
            &received,
            cb_index,
            vec![Payment { destination: address(&bob), amount: received.amount - fee }],
            fee,
        );

        for round in 0..3 {
            let (block, _) = make_block(&chain, &miner, std::slice::from_ref(&tx), 60_000 + round);
            chain
                .add_block(&mut OsRng, &block, std::slice::from_ref(&tx))
                .expect("block should apply");

            let after_apply = state_fingerprint(&chain);
            assert_ne!(after_apply, before, "round {round}: applying a block must change state");

            assert_eq!(chain.rollback_to(chain.height() - 1).len(), 1);
            assert_eq!(
                state_fingerprint(&chain),
                before,
                "round {round}: undoing the block left the chain in a different state"
            );
        }
    }

    /// The same property across a multi-block branch, which is what a real reorg
    /// actually rolls back — and it must hold whether the branch spent anything
    /// or not.
    #[test]
    fn rolling_back_a_whole_branch_restores_the_chain_exactly() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 10, 1_200);

        let fork_height = chain.height();
        let before = state_fingerprint(&chain);

        for i in 0..6 {
            let (block, _) = make_block(&chain, &miner, &[], 70_000 + i);
            chain.add_block(&mut OsRng, &block, &[]).unwrap();
        }
        assert_eq!(chain.height(), fork_height + 6);

        let removed = chain.rollback_to(fork_height);
        assert_eq!(removed.len(), 6, "every block on the branch comes back");
        assert_eq!(
            state_fingerprint(&chain),
            before,
            "rolling back a branch left the chain in a different state"
        );

        // Genesis is never removable, or a chain could be left with no root.
        let removed = chain.rollback_to(0);
        assert_eq!(chain.height(), 1, "rollback must clamp at genesis");
        assert!(!removed.is_empty() || chain.height() == 1);
    }

    // --- decoy selection on a real chain ---------------------------------
    //
    // The broken "recency-biased" selector clustered every decoy in the middle
    // of the output set and put none near the tip. Wired up, a recent real
    // spend would have been the only ring member near the tip — identified by
    // the very mechanism meant to hide it. These pin the shape on a real chain.

    /// Map a ring member back to its output index, for inspecting a ring.
    fn index_of(chain: &Blockchain<KeccakPow>, m: &RingMember) -> Option<u64> {
        (0..chain.num_outputs()).find(|&i| chain.output(i).as_ref() == Some(m))
    }

    fn chain_with_history() -> Blockchain<KeccakPow> {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 300, 1_200);
        chain
    }

    /// Count decoys landing in the newest quarter of the output set, for a
    /// given selector.
    fn near_tip_fraction(
        chain: &Blockchain<KeccakPow>,
        real: u64,
        recency: bool,
    ) -> f64 {
        let n = chain.num_outputs();
        let (mut near, mut total) = (0usize, 0usize);
        for _ in 0..120 {
            let (ring, signer) = if recency {
                chain.select_ring_recency_biased(&mut OsRng, RING_SIZE, real)
            } else {
                chain.select_ring_uniform(&mut OsRng, RING_SIZE, real)
            }
            .expect("assembles");
            for (i, m) in ring.iter().enumerate() {
                if i == signer {
                    continue;
                }
                if let Some(idx) = index_of(chain, m) {
                    total += 1;
                    if idx >= n * 3 / 4 {
                        near += 1;
                    }
                }
            }
        }
        near as f64 / total as f64
    }

    /// The property that matters, tested as a *comparison* on one chain so the
    /// result does not depend on how long the test chain happens to be.
    ///
    /// Absolute numbers here are muted for a reason worth recording: the gamma's
    /// median age is ~1.5 days, so on a chain younger than that most samples are
    /// older than the chain itself and fall back to a uniform draw. The bias is
    /// real but only fully expressed once a chain has months of history — which
    /// is exactly when it starts to matter.
    #[test]
    fn recency_biased_beats_uniform_at_covering_recent_outputs() {
        let chain = chain_with_history();
        let real = chain.num_outputs() - 5;
        let biased = near_tip_fraction(&chain, real, true);
        let uniform = near_tip_fraction(&chain, real, false);
        assert!(
            biased > uniform,
            "recency-biased ({biased:.3}) must put more decoys near the tip than uniform              ({uniform:.3}) — the old selector managed ~0, which would have exposed every              recent real spend"
        );
    }

    /// No single output may dominate. The premine sits at index 0, and a tail
    /// clamping to the genesis end would put it in nearly every ring — turning
    /// the one output everybody can identify into a beacon.
    #[test]
    fn the_first_output_is_not_over_selected() {
        let chain = chain_with_history();
        let n = chain.num_outputs();
        let real = n - 5;
        let (mut zero_hits, mut rings) = (0usize, 0usize);
        for _ in 0..120 {
            let (ring, signer) =
                chain.select_ring_recency_biased(&mut OsRng, RING_SIZE, real).expect("assembles");
            rings += 1;
            for (i, m) in ring.iter().enumerate() {
                if i != signer && index_of(&chain, m) == Some(0) {
                    zero_hits += 1;
                }
            }
        }
        let per_ring = zero_hits as f64 / rings as f64;
        assert!(
            per_ring < 0.5,
            "output 0 appeared {per_ring:.3} times per ring — a tail clamping to genesis would              make it a marker rather than a decoy"
        );
    }

    #[test]
    fn fork_choice_prefers_more_work() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        let here = chain.cumulative_difficulty();
        assert!(chain.would_reorg_to(here + 1));
        assert!(!chain.would_reorg_to(here));
        assert!(!chain.would_reorg_to(here.saturating_sub(1)));
    }

    #[test]
    fn gamma_sampler_is_sane_and_ring_is_valid() {
        // Gamma samples are positive and finite, with a mean near shape*scale.
        let mut sum = 0.0;
        for _ in 0..2000 {
            let g = sample_gamma(&mut OsRng, GAMMA_SHAPE, GAMMA_SCALE);
            assert!(g.is_finite() && g > 0.0);
            sum += g;
        }
        let mean = sum / 2000.0;
        let expected = GAMMA_SHAPE * GAMMA_SCALE;
        assert!((mean - expected).abs() < expected * 0.2, "mean {mean} vs {expected}");

        // Recency-biased selection yields a valid, distinct ring of real outputs.
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        mine_coinbase(&mut chain, &miner, 1_000);
        warm_up(&mut chain, 20, 1_200);
        let (ring, signer) =
            chain.select_ring_recency_biased(&mut OsRng, 11, 0).expect("enough outputs");
        assert_eq!(ring.len(), 11);
        assert!(signer < 11);
        for m in &ring {
            assert!(chain.output_membership.contains_key(&membership_key(m)));
        }
    }

    #[test]
    fn decoy_selection_never_picks_an_immature_coinbase() {
        // Decoy selection skips the recent, still-immature coinbase outputs. It
        // finds them via a bounded suffix scan (heights are non-decreasing), so
        // this also guards that optimisation: with a maturity window in force,
        // every member of every ring must be legally referenceable.
        let maturity = 4u64;
        let mut chain = Blockchain::with_maturity(KeccakPow, maturity);
        warm_up(&mut chain, 30, 1_000);

        let height = chain.height();
        let immature: Vec<u64> = (0..chain.num_outputs())
            .filter(|&i| !chain.output_spendable_at(i, height))
            .collect();
        assert!(!immature.is_empty(), "the tail of the chain must still be immature");

        // Draw many rings; none may contain an immature output.
        for _ in 0..25 {
            let (ring, _signer) =
                chain.select_ring_uniform(&mut OsRng, crate::chain::RING_SIZE, 0).expect("enough mature outputs");
            for member in &ring {
                let index = chain.output_index(member).expect("member is a real output");
                assert!(
                    chain.output_spendable_at(index, height),
                    "ring member {index} is an immature coinbase"
                );
            }
        }
    }

    #[test]
    fn duplicate_output_is_rejected_closing_the_maturity_bypass() {
        // A block may not create an output identical to one that already exists.
        // Without this, a miner could mine a coinbase and then publish an output
        // copying its `[P, C]`; the duplicate would be indexed as a *non-coinbase*
        // output and the immature coinbase would resolve to it, becoming
        // spendable — a coinbase-maturity bypass.
        let mut chain = Blockchain::with_maturity(KeccakPow, 60);
        let miner = Account::random(&mut OsRng);
        warm_up(&mut chain, 5, 1_000);

        // Take an existing output and try to mint it a second time, by handing a
        // coinbase the very same `[P, C]`.
        let victim = chain.output(1).expect("an output exists");
        let mut block = make_block(&mut chain, &miner, &[], 1_000 + 6 * 130).0;
        block.coinbase.outputs[0].one_time_key = victim.key;
        block.coinbase.outputs[0].commitment = victim.commitment;
        block.mine(&KeccakPow, chain.next_difficulty());

        assert_eq!(
            chain.add_block(&mut OsRng, &block, &[]).err(),
            Some(ChainError::DuplicateOutput),
            "a block re-creating an existing output must be rejected"
        );
    }

    #[test]
    fn coinbase_maturity_locks_then_unlocks() {
        let maturity = 5u64;
        let mut chain = Blockchain::with_maturity(KeccakPow, maturity);
        // Enough mature history that rings can be formed.
        warm_up(&mut chain, 20, 1_000);

        // Mine the coinbase we will try to spend.
        let ts = 1_000 + 20 * 130;
        let (target, target_index) = mine_coinbase(&mut chain, &Account::random(&mut OsRng), ts);
        let recipient = Account::random(&mut OsRng);
        let pay = vec![Payment { destination: address(&recipient), amount: target.amount - 1 }];

        // Immature: a transaction referencing the fresh coinbase is rejected,
        // even though it is internally valid.
        let tx = build_spend(&chain, &target, target_index, pay.clone(), 1);
        assert!(tx.verify(&mut OsRng).is_ok());
        assert_eq!(chain.validate_tx(&mut OsRng, &tx), Err(ChainError::ImmatureCoinbase));

        // After `maturity` more blocks the same output is spendable.
        warm_up(&mut chain, maturity as usize, ts + 130);
        let tx2 = build_spend(&chain, &target, target_index, pay, 1);
        assert!(chain.validate_tx(&mut OsRng, &tx2).is_ok());
    }
}

/// Decoy selection must put most of the ring where real spends actually are —
/// near the tip. The original "recency-biased" selector did the exact opposite:
/// it clustered every decoy between 35% and 62% back through the output set and
/// put **none** in the newest 1%. Wired up, that would have made a recent real
/// spend the only ring member near the tip, and identified it.
///
/// These tests pin the shape of the distribution, not just that it runs.
#[cfg(test)]
mod decoy_distribution_tests {
    use super::*;
    use rand_core::OsRng;

    /// Sample ages the way the selector does, in blocks back from the tip.
    fn sample_ages_in_blocks(n: usize) -> Vec<f64> {
        let mut v: Vec<f64> = (0..n)
            .map(|_| {
                let secs = sample_gamma(&mut OsRng, GAMMA_SHAPE, GAMMA_SCALE).exp();
                secs / crate::pow::TARGET_BLOCK_TIME as f64
            })
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    }

    fn pct(v: &[f64], p: f64) -> f64 {
        v[((v.len() as f64 - 1.0) * p) as usize]
    }

    /// The headline property: the median decoy should be days old, not months —
    /// matching how people actually spend.
    #[test]
    fn the_median_decoy_is_days_old_not_half_the_chain() {
        let ages = sample_ages_in_blocks(20_000);
        let median_blocks = pct(&ages, 0.50);
        let median_days = median_blocks * crate::pow::TARGET_BLOCK_TIME as f64 / 86_400.0;
        assert!(
            (0.2..14.0).contains(&median_days),
            "median decoy age should be on the order of days, got {median_days:.2} days"
        );
    }

    /// A large share must be genuinely recent. This is the assertion the broken
    /// selector failed outright — it produced zero recent decoys.
    #[test]
    fn a_real_share_of_decoys_are_recent() {
        let ages = sample_ages_in_blocks(20_000);
        let day_in_blocks = 86_400.0 / crate::pow::TARGET_BLOCK_TIME as f64;
        let within_a_day = ages.iter().filter(|a| **a <= day_in_blocks).count() as f64 / ages.len() as f64;
        assert!(
            within_a_day > 0.15,
            "at least a sixth of decoys should be under a day old, got {within_a_day:.3}"
        );
    }

    /// And it must keep a long tail: if every decoy were recent, an *old* real
    /// spend would stand out just as badly in the other direction.
    #[test]
    fn the_tail_still_reaches_old_outputs() {
        let ages = sample_ages_in_blocks(20_000);
        let week_in_blocks = 7.0 * 86_400.0 / crate::pow::TARGET_BLOCK_TIME as f64;
        let older_than_a_week = ages.iter().filter(|a| **a > week_in_blocks).count() as f64 / ages.len() as f64;
        assert!(
            older_than_a_week > 0.02,
            "the distribution needs a real tail, got {older_than_a_week:.3} older than a week"
        );
    }

    /// Print the shape, so a human can sanity-check it rather than trusting the
    /// thresholds above.
    #[test]
    fn show_the_decoy_age_distribution() {
        let ages = sample_ages_in_blocks(20_000);
        let d = |b: f64| b * crate::pow::TARGET_BLOCK_TIME as f64 / 86_400.0;
        println!("decoy age (days back from the tip):");
        for q in [0.01, 0.10, 0.25, 0.50, 0.75, 0.90, 0.99] {
            println!("  p{:02.0} = {:.3} days", q * 100.0, d(pct(&ages, q)));
        }
    }
}

