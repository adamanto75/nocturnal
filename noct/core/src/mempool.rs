//! Layer 9 — mempool.
//!
//! The mempool holds validated but not-yet-mined transactions. Its two jobs:
//!
//! * **Admission control** — only accept transactions that are internally valid,
//!   whose ring members are real chain outputs, and whose key images are neither
//!   already spent on-chain nor claimed by another transaction *already in the
//!   pool* (an unconfirmed double-spend).
//! * **Block feedstock & upkeep** — offer transactions to miners
//!   ([`Mempool::select`]) and drop them once a block spends their inputs
//!   ([`Mempool::on_block`]).
//!
//! Chain-level validity is delegated to [`Blockchain::validate_tx`]; the mempool
//! adds only the pool-conflict check on top.

use std::collections::{HashMap, HashSet};

use crate::chain::{Blockchain, ChainError};
use crate::pow::ProofOfWork;
use crate::ring::KeyImage;
use crate::tx::Transaction;

/// Why a transaction was not admitted to the pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MempoolError {
    /// The transaction is already in the pool.
    AlreadyKnown,
    /// A key image conflicts with another unconfirmed transaction.
    PoolConflict,
    /// The transaction is invalid against the chain.
    Invalid(ChainError),
    /// The pool is full and this transaction does not pay enough to displace
    /// anything already in it.
    PoolFull,
    /// The fee is below the relay floor. Carries what this transaction's size
    /// required, so a wallet can be told the number instead of guessing it.
    FeeTooLow { required: u64 },
}

/// Fee per byte, the measure of what a transaction is worth to a miner and so
/// what it should cost to keep a slot. Scaled to keep integer resolution on
/// small fees.
fn fee_rate(fee: u64, size: usize) -> u64 {
    fee.saturating_mul(1000) / (size.max(1) as u64)
}

/// The least a transaction may pay per 1000 bytes and still be relayed or held.
///
/// **This is policy, not consensus.** A block carrying a transaction below this
/// floor is perfectly valid and every node must accept it; all this does is stop
/// a node relaying or storing one. That distinction is the whole reason the check
/// lives here and not in [`Blockchain::validate_tx`] — putting a fee rule into
/// validation would fork the chain the moment two nodes disagreed about the
/// number, and the number is exactly the kind of thing that gets tuned.
///
/// **Why per byte, and only per byte.** The obvious alternative was to surcharge
/// Orchard actions, on the theory that a proof costs more to check than the bytes
/// it occupies. Measured, that theory is backwards. Warm verification cost per
/// kilobyte, on the transactions the wallet actually builds:
///
/// | transaction | size | verify | µs/KB |
/// |---|---|---|---|
/// | ring, 1 recipient | 2,507 B | 4.7 ms | 1,876 |
/// | ring, 8 recipients | 3,203 B | 17.7 ms | **5,540** |
/// | shielding, 1 action | 10,035 B | 11.1 ms | 1,106 |
/// | shielded-only, 2 actions | 9,205 B | 5.9 ms | 637 |
/// | unshielding, 1 action | 8,503 B | 9.4 ms | 1,102 |
///
/// The shielded pool is the *cheapest* per byte to verify: Orchard proofs are
/// large but fast. The expensive shape is a many-output ring transaction, where
/// an aggregate Bulletproofs+ range proof costs 17.7 ms inside 3.2 KB. An
/// action surcharge would have taxed the cheap case and left the dear one alone.
///
/// Bytes are also what this pool actually rations — [`MAX_MEMPOOL_BYTES`] is a
/// byte cap, and [`fee_rate`] already prices eviction per 1000 bytes. Charging
/// in the same unit means the floor and the eviction rule tell one story: the
/// pool never holds anything below this rate, and under pressure it never gets
/// cheaper than what is already in it.
///
/// **The value, and how it was chosen.** A floor is only safe if legitimate
/// traffic is nowhere near it, so it is set from the *cheapest rate this
/// software itself ever pays*, not from a round number.
///
/// That rate is not the small transaction — it is the big one. Every tool here
/// sends a flat 0.01 NOCT, so the larger the transaction the lower its rate, and
/// the largest the fleet builds is a pool payout to eight shielded recipients:
/// **30,459 bytes**, eight Orchard actions, paying 0.01 NOCT — about 0.00033
/// NOCT per 1000 bytes. Everything else pays several times more per byte; an
/// ordinary ring send is 2.5 KB and pays 0.004 NOCT per 1000 bytes, twelve times
/// that rate.
///
/// 0.00005 NOCT per 1000 bytes sits about six times below that worst case, which
/// is the margin `wallet/tests/fee_floor.rs` asserts and prints. Filling the
/// whole 32 MB pool costs about 1.6 NOCT, roughly two blocks of subsidy.
///
/// An earlier draft used 0.0002 and looked fine against every shape measured by
/// hand — the eight-recipient shielded payout was estimated at 17 KB and is
/// really 30 KB, which left the pool paying only 1.6× the floor. The test
/// caught it; the estimate would not have.
pub const MIN_FEE_PER_KB: u64 = 50_000_000;

/// What a transaction of `size` bytes must pay to be relayed or pooled.
///
/// Rounded **up**, so that no size is free. Saturating rather than wrapping: a
/// size absurd enough to overflow should price itself out, not wrap to nothing.
pub fn min_fee(size: usize) -> u64 {
    MIN_FEE_PER_KB.saturating_mul(size as u64).saturating_add(999) / 1000
}

/// Most bytes of transactions the pool will hold.
///
/// An unbounded pool is a free denial of service. A transaction waiting to be
/// mined costs its sender **nothing** — fees are only paid when it is included —
/// so an attacker can push transactions until the node runs out of memory and
/// never pay for any of it. A cap converts that into a competition the attacker
/// has to keep winning.
pub const MAX_MEMPOOL_BYTES: usize = 32 * 1024 * 1024;

/// A pool of unconfirmed transactions.
#[derive(Default)]
pub struct Mempool {
    txs: HashMap<[u8; 32], Transaction>,
    /// Key images claimed by pooled transactions → the tx that claims each.
    claimed_images: HashMap<KeyImage, [u8; 32]>,
    /// Encoded size of each pooled transaction, and the running total, so the
    /// cap does not require re-encoding the pool on every admission.
    sizes: HashMap<[u8; 32], usize>,
    bytes: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::default()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.txs.contains_key(tx_hash)
    }

    /// Validate `tx` against `chain` and the pool, and admit it if it is new,
    /// valid, and conflict-free. Returns the transaction hash on success.
    pub fn add<P: ProofOfWork, R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        chain: &Blockchain<P>,
        tx: Transaction,
    ) -> Result<[u8; 32], MempoolError> {
        let hash = tx.hash();
        if self.txs.contains_key(&hash) {
            return Err(MempoolError::AlreadyKnown);
        }

        // No key image may collide with another unconfirmed transaction.
        //
        // This runs BEFORE signature verification, and the order is the whole
        // point. A rejected transaction is never stored, so it never reaches the
        // `AlreadyKnown` check above: an attacker signs a single double-spend
        // once and replays it forever, and every copy would otherwise cost a
        // full CLSAG-over-16 plus Bulletproofs+ verification to throw away.
        // Peers may send 5000 messages a second, so that is several CPU-seconds
        // of work per second of wall clock, for free, per connection.
        //
        // Checking the images first makes the replay as cheap to refuse as it
        // is to send. Nothing here depends on the transaction being valid — it
        // is a lookup of images we have already accepted.
        let images = tx.key_images();
        if images.iter().any(|i| self.claimed_images.contains_key(i)) {
            return Err(MempoolError::PoolConflict);
        }

        // The relay floor, checked BEFORE verification, for the same reason the
        // key-image check above is: verification is the expensive part, and an
        // attacker who can make us spend it for nothing has a free denial of
        // service. The measurements in [`MIN_FEE_PER_KB`] put that between 4.7
        // and 17.7 ms per transaction; encoding one to measure it costs
        // microseconds. Refusing the cheap way round is the point.
        //
        // This is where the floor actually defends CPU. The size of the number
        // rations bytes; the *position* of the check rations verification.
        let size = crate::wire::encode_transaction(&tx).len();
        let required = min_fee(size);
        if tx.fee < required {
            return Err(MempoolError::FeeTooLow { required });
        }

        // Chain-level validity (also rejects images already spent on-chain).
        chain.validate_tx(rng, &tx).map_err(MempoolError::Invalid)?;

        // Admit under a byte cap, evicting the worst-paying transactions to make
        // room — but only for a transaction that pays better than what it
        // displaces. Without that condition an attacker refills the pool with
        // cheap transactions and evicts everyone else's, which is the same
        // denial of service wearing a different hat.
        if size > MAX_MEMPOOL_BYTES {
            return Err(MempoolError::PoolFull);
        }
        if self.bytes + size > MAX_MEMPOOL_BYTES {
            let incoming_rate = fee_rate(tx.fee, size);
            // Cheapest first: those are the ones worth losing.
            let mut victims: Vec<([u8; 32], u64)> = self
                .txs
                .iter()
                .map(|(h, t)| (*h, fee_rate(t.fee, self.sizes.get(h).copied().unwrap_or(1))))
                .collect();
            victims.sort_by_key(|(_, rate)| *rate);

            let mut freed = 0usize;
            let mut evict: Vec<[u8; 32]> = Vec::new();
            for (h, rate) in victims {
                if self.bytes + size - freed <= MAX_MEMPOOL_BYTES {
                    break;
                }
                // Never evict something that pays at least as well as the
                // newcomer: the pool should not get cheaper under pressure.
                if rate >= incoming_rate {
                    break;
                }
                freed += self.sizes.get(&h).copied().unwrap_or(0);
                evict.push(h);
            }
            if self.bytes + size - freed > MAX_MEMPOOL_BYTES {
                return Err(MempoolError::PoolFull);
            }
            for h in evict {
                self.remove(&h);
            }
        }

        for image in images {
            self.claimed_images.insert(image, hash);
        }
        self.bytes += size;
        self.sizes.insert(hash, size);
        self.txs.insert(hash, tx);
        Ok(hash)
    }

    /// Bytes currently held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }



    /// Prune the pool after `block` is added to the chain: remove any transaction
    /// whose key images were spent by the block (whether the block included that
    /// exact transaction or a conflicting one).
    pub fn on_block(&mut self, block_txs: &[Transaction]) {
        let spent: HashSet<KeyImage> =
            block_txs.iter().flat_map(|t| t.key_images()).collect();

        let doomed: Vec<[u8; 32]> = self
            .txs
            .iter()
            .filter(|(_, tx)| tx.key_images().iter().any(|i| spent.contains(i)))
            .map(|(h, _)| *h)
            .collect();

        for hash in doomed {
            self.remove(&hash);
        }
    }

    fn remove(&mut self, hash: &[u8; 32]) {
        if let Some(tx) = self.txs.remove(hash) {
            for image in tx.key_images() {
                self.claimed_images.remove(&image);
            }
        }
        // Every removal path runs through here, including pruning after a
        // block. If the byte accounting were updated only on eviction it would
        // drift upward until the pool believed itself permanently full.
        if let Some(n) = self.sizes.remove(hash) {
            self.bytes = self.bytes.saturating_sub(n);
        }
    }

    /// Up to `max` transactions to include in a block. (No fee-ordering yet; a
    /// fee-priority selector is a straightforward extension.)
    pub fn select(&self, max: usize) -> Vec<Transaction> {
        self.txs.values().take(max).cloned().collect()
    }

    /// Get a pooled transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.txs.get(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};
    use crate::chain::OutputSet;
    use crate::amounts::Opening;
    use crate::block::{Block, BlockHeader, Coinbase};
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::Account;
    use crate::pow::KeccakPow;
    use crate::ring::RingMember;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    // Minimal chain harness: mine coinbase blocks so we have spendable outputs.
    fn mine(chain: &mut Blockchain<KeccakPow>, miner: &Account, ts: u64) -> (ReceivedOutput, u64) {
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(miner), subsidy);
        let received = cb.scan(miner).unwrap();
        let index = chain.num_outputs();
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + ts,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, &[]).unwrap();
        (received, index)
    }

    pub(super) fn setup() -> (Blockchain<KeccakPow>, ReceivedOutput, u64) {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, index) = mine(&mut chain, &miner, 1_000);
        let filler = Account::random(&mut OsRng);
        for i in 0..15 {
            mine(&mut chain, &filler, 1_200 + i * 130);
        }
        (chain, received, index)
    }

    pub(super) fn spend(chain: &Blockchain<KeccakPow>, src: &ReceivedOutput, idx: u64, to: &Account, amount: u64, fee: u64) -> Transaction {
        let (ring, signer) = chain.select_ring_uniform(&mut OsRng, crate::chain::RING_SIZE, idx).unwrap();
        let input = src.to_input(ring, signer);
        Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(to), amount }],
            fee,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap()
    }

    #[test]
    fn admits_a_valid_transaction() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);

        let mut pool = Mempool::new();
        let hash = pool.add(&mut OsRng, &chain, tx.clone()).unwrap();
        assert!(pool.contains(&hash));
        assert_eq!(pool.len(), 1);

        // Re-adding is rejected as already-known.
        assert_eq!(pool.add(&mut OsRng, &chain, tx), Err(MempoolError::AlreadyKnown));
    }

    /// **The floor is relay policy, and the chain must not care about it.**
    ///
    /// This is the test that stops a future refactor from quietly forking the
    /// network. A fee rule inside `validate_tx` would make every node's opinion
    /// of a block depend on a number chosen for denial-of-service reasons and
    /// tuned whenever traffic changes — two nodes on different builds would then
    /// disagree about which chain exists. So the same transaction the pool
    /// refuses has to validate, and a block carrying it has to be accepted.
    #[test]
    fn the_floor_is_policy_and_the_chain_ignores_it() {
        let (mut chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        // Pays nothing at all — as far under any floor as a transaction can be.
        let tx = spend(&chain, &src, idx, &bob, src.amount, 0);

        let mut pool = Mempool::new();
        assert!(
            matches!(pool.add(&mut OsRng, &chain, tx.clone()), Err(MempoolError::FeeTooLow { .. })),
            "the pool must refuse to relay or hold it"
        );

        // And the chain must take it anyway, both on its own and inside a block.
        chain.validate_tx(&mut OsRng, &tx).expect("a zero-fee transaction is VALID");

        let miner = Account::random(&mut OsRng);
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(&miner), subsidy);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 5_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![tx.hash()],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain
            .add_block(&mut OsRng, &block, &[tx])
            .expect("a block carrying a zero-fee transaction is VALID");
    }

    /// Refusal has to carry the number, because the only thing the sender can do
    /// about it is pay a different fee, and they cannot guess which one.
    #[test]
    fn a_transaction_below_the_floor_is_told_what_it_needed() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let tx = spend(&chain, &src, idx, &bob, src.amount - 1, 1);
        let size = crate::wire::encode_transaction(&tx).len();

        let mut pool = Mempool::new();
        assert_eq!(
            pool.add(&mut OsRng, &chain, tx),
            Err(MempoolError::FeeTooLow { required: min_fee(size) }),
        );
        assert!(pool.is_empty());
    }

    /// **Refused before it is verified** — the same argument as
    /// [`a_conflicting_transaction_is_refused_before_it_is_verified`], and the
    /// reason the floor defends CPU at all. Verification is 4.7–17.7 ms a
    /// transaction; if an underpaying one reached it, a sender who never intends
    /// to pay could buy that work indefinitely.
    ///
    /// The transaction here is *both* underpaying and unverifiable. Verifying
    /// first would report `Invalid`; checking the fee first reports `FeeTooLow`,
    /// which is what pins the order.
    #[test]
    fn an_underpaying_transaction_is_refused_before_it_is_verified() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let mut tx = spend(&chain, &src, idx, &bob, src.amount - 1, 1);
        tx.outputs[0].commitment = Opening::random(1, &mut OsRng).commit();

        let mut pool = Mempool::new();
        assert!(
            matches!(
                pool.add(&mut OsRng, &chain, tx),
                Err(MempoolError::FeeTooLow { .. })
            ),
            "the fee must be judged before any signature or range proof is touched"
        );
    }

    /// Rounded up, so that no size is free and a flood of tiny transactions
    /// cannot slip under the rate by being small.
    #[test]
    fn no_size_is_free() {
        assert_eq!(min_fee(0), 0, "nothing is nothing");
        assert!(min_fee(1) > 0, "one byte still costs something");
        assert_eq!(min_fee(1000), MIN_FEE_PER_KB, "the rate is per 1000 bytes");
        assert!(min_fee(1001) > MIN_FEE_PER_KB, "and the next byte costs more");
        // The same unit eviction already prices in, so the floor and the
        // eviction rule cannot drift apart.
        assert!(fee_rate(min_fee(4096), 4096) >= MIN_FEE_PER_KB - 1);
    }

    #[test]
    fn rejects_unconfirmed_double_spend() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        // Two different transactions spending the same coinbase output.
        let tx1 = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);
        let tx2 = spend(&chain, &src, idx, &bob, reward - 2 * (ATOMIC_UNITS / 100), 2 * (ATOMIC_UNITS / 100));

        let mut pool = Mempool::new();
        pool.add(&mut OsRng, &chain, tx1).unwrap();
        assert_eq!(pool.add(&mut OsRng, &chain, tx2), Err(MempoolError::PoolConflict));
        assert_eq!(pool.len(), 1);
    }

    /// A conflicting transaction must be refused by the key-image lookup, not
    /// by signature verification — otherwise one pre-signed double-spend,
    /// replayed, buys an attacker unbounded CLSAG and range-proof work.
    ///
    /// The transaction here is *both* conflicting and invalid. Verifying first
    /// would report `Invalid`; checking images first reports `PoolConflict`,
    /// which is what pins the order.
    #[test]
    fn a_conflicting_transaction_is_refused_before_it_is_verified() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let tx1 = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);
        let mut tx2 =
            spend(&chain, &src, idx, &bob, reward - 2 * (ATOMIC_UNITS / 100), 2 * (ATOMIC_UNITS / 100));
        // Same key image as tx1, and now unverifiable as well.
        tx2.outputs[0].commitment = Opening::random(1, &mut OsRng).commit();

        let mut pool = Mempool::new();
        pool.add(&mut OsRng, &chain, tx1).unwrap();
        assert_eq!(
            pool.add(&mut OsRng, &chain, tx2),
            Err(MempoolError::PoolConflict),
            "a replayed double-spend must cost a hash lookup, not a verification"
        );
    }

    #[test]
    fn rejects_invalid_transaction() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let mut tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);
        // Corrupt an output commitment → range proof fails.
        tx.outputs[0].commitment = Opening::random(1, &mut OsRng).commit();

        let mut pool = Mempool::new();
        assert!(matches!(pool.add(&mut OsRng, &chain, tx), Err(MempoolError::Invalid(_))));
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_ring_with_unknown_output() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let mut tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);
        // Point a decoy at an off-chain output.
        let signer = tx.inputs[0].ring.iter().position(|m| m.key == src.one_time_key).unwrap();
        let victim = (signer + 1) % tx.inputs[0].ring.len();
        let fake = crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key();
        tx.inputs[0].ring[victim] = RingMember::new(fake, Opening::random(1, &mut OsRng).commit());

        let mut pool = Mempool::new();
        assert!(matches!(pool.add(&mut OsRng, &chain, tx), Err(MempoolError::Invalid(_))));
    }

    #[test]
    fn evicts_transactions_once_mined() {
        let (mut chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);

        let mut pool = Mempool::new();
        pool.add(&mut OsRng, &chain, tx.clone()).unwrap();
        assert_eq!(pool.len(), 1);

        // Mine a block including the transaction; the pool should evict it.
        let miner = Account::random(&mut OsRng);
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(&miner), subsidy + tx.fee);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 50_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![tx.hash()],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        pool.on_block(std::slice::from_ref(&tx));
        assert!(pool.is_empty());
    }

    /// The same guarantee one level down: a transaction spending an output
    /// that is already spent on-chain must be refused by the key-image lookup,
    /// not by verifying its signature. Replaying such a transaction is free for
    /// the sender, so it must be nearly free to refuse.
    ///
    /// The replayed copy is corrupted as well, so verifying first would report
    /// `InvalidTx`; the lookup running first reports `DoubleSpend`.
    #[test]
    fn a_spent_output_is_detected_before_the_signature_is_verified() {
        let (mut chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);

        // Confirm it, so its key image is spent on-chain.
        let miner = Account::random(&mut OsRng);
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(&miner), subsidy + tx.fee);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 50_000,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![tx.hash()],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, std::slice::from_ref(&tx)).unwrap();

        // Now replay it, corrupted.
        let mut replay = tx.clone();
        replay.outputs[0].commitment = Opening::random(1, &mut OsRng).commit();
        assert!(
            matches!(chain.validate_tx(&mut OsRng, &replay), Err(ChainError::DoubleSpend)),
            "a replayed spend must cost a lookup, not a CLSAG verification"
        );
    }

    #[test]
    fn select_offers_pooled_txs() {
        let (chain, src, idx) = setup();
        let bob = Account::random(&mut OsRng);
        let reward = src.amount;
        let tx = spend(&chain, &src, idx, &bob, reward - ATOMIC_UNITS / 100, ATOMIC_UNITS / 100);
        let mut pool = Mempool::new();
        pool.add(&mut OsRng, &chain, tx.clone()).unwrap();
        let selected = pool.select(10);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].hash(), tx.hash());
    }
}

/// The pool must not be a free denial of service.
///
/// A transaction waiting to be mined costs its sender nothing — fees are paid
/// only on inclusion — so an unbounded pool lets an attacker consume memory
/// indefinitely without ever paying. These pin the cap and, just as important,
/// pin that the cap cannot itself be turned into an attack.
#[cfg(test)]
mod flooding_tests {
    use super::tests::{setup, spend};
    use super::*;
    use crate::keys::Account;
    use rand_core::OsRng;

    /// Fee-rate ordering is what decides who keeps a slot, so it has to mean
    /// what it says: more fee for the same size ranks higher, same fee for more
    /// size ranks lower.
    #[test]
    fn fee_rate_ranks_by_value_per_byte() {
        assert!(fee_rate(1000, 100) > fee_rate(1000, 200), "bigger tx, same fee → worse rate");
        assert!(fee_rate(2000, 100) > fee_rate(1000, 100), "same size, more fee → better rate");
        assert_eq!(fee_rate(1000, 100), fee_rate(2000, 200), "twice the fee for twice the size");
    }

    /// A zero-size transaction must not divide by zero. Sizes come from
    /// encoding, so this should be impossible — which is exactly why it is worth
    /// a test rather than an assumption.
    #[test]
    fn fee_rate_survives_a_zero_size() {
        assert_eq!(fee_rate(500, 0), fee_rate(500, 1));
    }

    /// A pool at capacity must not become cheaper. If an attacker could evict
    /// well-paying transactions with cheap ones, the cap would hand them a
    /// better attack than the unbounded pool did: not just memory, but everyone
    /// else's place in the queue.
    #[test]
    fn a_cheaper_transaction_cannot_displace_a_dearer_one() {
        // The rule under test, isolated from the need to mint 32 MB of real
        // transactions: eviction requires strictly better value per byte.
        let dear = fee_rate(10_000, 500);
        let cheap = fee_rate(10, 500);
        assert!(cheap < dear);
        assert!(
            !(cheap >= dear),
            "a cheaper transaction must never qualify to displace a dearer one"
        );
    }

    /// Byte accounting must return to zero once everything is gone, or the pool
    /// drifts toward believing itself permanently full.
    #[test]
    fn byte_accounting_returns_to_zero() {
        let (chain, src, idx) = setup();
        let mut pool = Mempool::new();
        let dst = Account::random(&mut OsRng);
        // Amounts must balance exactly against the source output, so spend the
        // whole reward less the fee.
        let fee = crate::emission::ATOMIC_UNITS / 100;
        let tx = spend(&chain, &src, idx, &dst, src.amount - fee, fee);
        let hash = pool.add(&mut OsRng, &chain, tx.clone()).expect("admitted");

        assert!(pool.bytes() > 0, "an admitted transaction must be accounted for");
        pool.on_block(&[tx]);
        assert!(!pool.contains(&hash), "mined transactions leave the pool");
        assert_eq!(pool.bytes(), 0, "and take their bytes with them");
        assert_eq!(pool.len(), 0);
    }
}
