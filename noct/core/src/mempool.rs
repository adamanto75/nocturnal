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
}

/// A pool of unconfirmed transactions.
#[derive(Default)]
pub struct Mempool {
    txs: HashMap<[u8; 32], Transaction>,
    /// Key images claimed by pooled transactions → the tx that claims each.
    claimed_images: HashMap<KeyImage, [u8; 32]>,
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

        // Chain-level validity (also rejects images already spent on-chain).
        chain.validate_tx(rng, &tx).map_err(MempoolError::Invalid)?;

        // No key image may collide with another unconfirmed transaction.
        let images = tx.key_images();
        if images.iter().any(|i| self.claimed_images.contains_key(i)) {
            return Err(MempoolError::PoolConflict);
        }

        for image in images {
            self.claimed_images.insert(image, hash);
        }
        self.txs.insert(hash, tx);
        Ok(hash)
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

    fn setup() -> (Blockchain<KeccakPow>, ReceivedOutput, u64) {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, index) = mine(&mut chain, &miner, 1_000);
        let filler = Account::random(&mut OsRng);
        for i in 0..15 {
            mine(&mut chain, &filler, 1_200 + i * 130);
        }
        (chain, received, index)
    }

    fn spend(chain: &Blockchain<KeccakPow>, src: &ReceivedOutput, idx: u64, to: &Account, amount: u64, fee: u64) -> Transaction {
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
