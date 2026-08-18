//! Layer 7 — blocks & coinbase.
//!
//! A [`Block`] is a [`BlockHeader`] (the PoW-bearing part), a [`Coinbase`]
//! transaction paying the miner, and the hashes of the regular transactions it
//! includes. The block's hashing-blob — header fields plus a Merkle root over
//! `[coinbase, tx_hashes…]` — is fed to the [`ProofOfWork`] function; a block is
//! valid when that hash meets the block's difficulty.
//!
//! ## Coinbase
//!
//! The coinbase has no ring inputs and no range proof: its amount is **public**
//! (the network must be able to check the miner claimed exactly the allowed
//! reward). Its output is still a normal stealth output to the miner, and its
//! commitment uses the fixed mask `1`:
//!
//! ```text
//!     C = 1·G + amount·H
//! ```
//!
//! so a miner can later spend it through the ordinary RingCT machinery
//! ([`crate::tx`]) with opening `{ amount, mask = 1 }` — exactly how Monero
//! handles cleartext-amount outputs.

use curve25519_dalek::scalar::Scalar;

use crate::address::Address;
use crate::amounts::{Commitment, Opening};
use crate::hash::keccak256;
use crate::keys::{Account, PrivateKey, PublicKey};
use crate::pow::{check_hash, Difficulty, ProofOfWork};
use crate::ring::{KeyImage, RingMember};
use crate::stealth::{self, TxKeypair};
use crate::tx::ReceivedOutput;

/// One coinbase output: a stealth key, its (public) amount, and the commitment.
#[derive(Clone, Debug)]
pub struct CoinbaseOutput {
    pub one_time_key: PublicKey,
    /// Public reward amount (coinbase amounts are not hidden).
    pub amount: u64,
    /// Commitment `1·G + amount·H` (fixed mask so it is deterministic).
    pub commitment: Commitment,
}

/// The coinbase ("miner") transaction of a block.
#[derive(Clone, Debug)]
pub struct Coinbase {
    /// Block height this coinbase belongs to (also its uniqueness nonce).
    pub height: u64,
    /// Transaction public key `R` for the miner's stealth output.
    pub tx_public: PublicKey,
    pub outputs: Vec<CoinbaseOutput>,
}

impl Coinbase {
    /// The deterministic commitment for a cleartext coinbase amount.
    fn commit(amount: u64) -> Commitment {
        Opening::new(amount, Scalar::ONE).commit()
    }

    /// Create a coinbase paying the whole `reward` to `miner` in a single output.
    pub fn create<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        height: u64,
        miner: &Address,
        reward: u64,
    ) -> Coinbase {
        let tx = TxKeypair::random(rng);
        let one_time_key = stealth::derive_output(&tx.secret, miner, 0);
        Coinbase {
            height,
            tx_public: tx.public,
            outputs: vec![CoinbaseOutput {
                one_time_key,
                amount: reward,
                commitment: Self::commit(reward),
            }],
        }
    }

    /// Total amount claimed by this coinbase, or `None` if the amounts overflow
    /// `u64`.
    ///
    /// Overflow-checked on purpose: coinbase output amounts are attacker-chosen
    /// (a peer supplies the block), and an unchecked sum that wrapped could match
    /// the allowed reward while actually minting far more — an inflation bug.
    pub fn total(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0u64, |acc, o| acc.checked_add(o.amount))
    }

    /// The coinbase outputs as ring members `[P, C]`, for adding to the global
    /// output set.
    pub fn output_refs(&self) -> Vec<RingMember> {
        self.outputs
            .iter()
            .map(|o| RingMember::new(o.one_time_key, o.commitment))
            .collect()
    }

    /// Validate coinbase structure against the reward the block is allowed to
    /// mint: the total must match, and every commitment must be the canonical
    /// `1·G + amount·H` for its stated amount.
    pub fn is_valid(&self, allowed_reward: u64) -> bool {
        self.total() == Some(allowed_reward)
            && self.outputs.iter().all(|o| o.commitment == Self::commit(o.amount))
    }

    /// Canonical bytes of the coinbase (for hashing / the Merkle tree / wire).
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.tx_public.to_bytes());
        b.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            b.extend_from_slice(&o.one_time_key.to_bytes());
            b.extend_from_slice(&o.amount.to_le_bytes());
            b.extend_from_slice(&o.commitment.to_bytes());
        }
        b
    }

    /// The coinbase hash (Merkle leaf).
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&self.to_bytes())
    }

    /// Scan the coinbase with an account's keys; if an output is addressed to it,
    /// recover it as a spendable [`ReceivedOutput`] (opening mask = 1).
    pub fn scan(&self, account: &Account) -> Option<ReceivedOutput> {
        for (i, output) in self.outputs.iter().enumerate() {
            let index = i as u32;
            if stealth::expected_output(account, &self.tx_public, index) != output.one_time_key {
                continue;
            }
            let opening = Opening::new(output.amount, Scalar::ONE);
            debug_assert_eq!(opening.commit(), output.commitment);
            let spend_secret = stealth::output_secret(account, &self.tx_public, index);
            let key_image = KeyImage::from_secret(&spend_secret);
            return Some(ReceivedOutput {
                index,
                amount: output.amount,
                opening,
                one_time_key: output.one_time_key,
                spend_secret,
                key_image,
                // Coinbase outputs pay the miner's standard address.
                subaddress: crate::subaddress::SubaddressIndex::MAIN,
            });
        }
        None
    }
}

/// A block header — the part that carries the proof of work.
#[derive(Clone, Copy, Debug)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    /// Miner-set timestamp (seconds).
    pub timestamp: u64,
    /// Hash of the previous block.
    pub prev_id: [u8; 32],
    /// PoW search nonce.
    pub nonce: u32,
}

impl BlockHeader {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 1 + 8 + 32 + 4);
        b.push(self.major_version);
        b.push(self.minor_version);
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.prev_id);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b
    }
}

/// A full block.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: Coinbase,
    /// Hashes of the regular transactions included in this block.
    pub tx_hashes: Vec<[u8; 32]>,
}

/// Binary Merkle root (Keccak-256) over the leaves; odd nodes are promoted.
/// This is Noct's own tree, not Monero's `tree_hash`.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let mut layer = leaves.to_vec();
            while layer.len() > 1 {
                let mut next = Vec::with_capacity(layer.len().div_ceil(2));
                for pair in layer.chunks(2) {
                    if let [a, b] = pair {
                        let mut buf = [0u8; 64];
                        buf[..32].copy_from_slice(a);
                        buf[32..].copy_from_slice(b);
                        next.push(keccak256(&buf));
                    } else {
                        next.push(pair[0]); // odd leaf promoted unchanged
                    }
                }
                layer = next;
            }
            layer[0]
        }
    }
}

/// Timestamp baked into the genesis block. Fixed forever — it is part of the
/// genesis hash and therefore of the chain's identity.
pub const GENESIS_TIMESTAMP: u64 = 1_750_000_000;

/// Amount minted in the genesis coinbase as the founder **premine** — 500,000
/// NOCT, half of the ~1,000,000 NOCT smooth-phase supply ([`crate::emission`]).
/// It counts toward emission, so the curve continues from this baseline and only
/// the remaining ~500,000 NOCT is mined out.
pub const PREMINE_AMOUNT: u64 = 500_000 * crate::emission::ATOMIC_UNITS;

/// Founder public **spend** key the premine output is addressed to.
pub const PREMINE_SPEND_PUBLIC: [u8; 32] = [
    0x28, 0x64, 0xde, 0xb5, 0x58, 0x55, 0x58, 0x24, 0xf4, 0xd1, 0x8b, 0x7a, 0xaa, 0xa6, 0x30, 0x2c,
    0xf9, 0x38, 0x40, 0x3e, 0x72, 0xef, 0x26, 0x3c, 0x95, 0xd0, 0x57, 0x7b, 0xce, 0x1f, 0xdc, 0x04,
];
/// Founder public **view** key (lets a scan recognise the premine output).
pub const PREMINE_VIEW_PUBLIC: [u8; 32] = [
    0x03, 0x95, 0x0d, 0x42, 0x7a, 0x16, 0x70, 0x78, 0xdc, 0x47, 0xe4, 0xca, 0xe7, 0x14, 0x60, 0x85,
    0x1e, 0xeb, 0xb3, 0x0e, 0x3b, 0xd0, 0x55, 0x63, 0xab, 0x78, 0x54, 0xd1, 0xf1, 0xad, 0x7e, 0xbb,
];
/// The one-time transaction secret `r` used to derive the premine's stealth
/// output. Published on purpose: knowing `r` only lets an observer link the
/// (already-public) premine to the founder address — **spending it still
/// requires the founder's private spend key**, which never appears here.
pub const GENESIS_TX_SECRET: [u8; 32] = [
    0xac, 0x94, 0x65, 0xe7, 0x76, 0xa9, 0x6a, 0x74, 0x44, 0x94, 0x4a, 0x8f, 0x12, 0x75, 0x16, 0x8c,
    0xfb, 0x4c, 0x12, 0x0c, 0x46, 0x39, 0x3a, 0xdd, 0x54, 0x77, 0x06, 0xf7, 0xf3, 0x23, 0x80, 0x0e,
];

impl Block {
    /// The genesis coinbase: a single premine output of [`PREMINE_AMOUNT`] to the
    /// founder address, derived deterministically from the baked constants above.
    /// Being a coinbase, its amount is public and its commitment uses mask 1, so
    /// the founder spends it through the ordinary RingCT path.
    fn genesis_coinbase(p: &crate::params::ChainParams) -> Coinbase {
        let r = PrivateKey::from_canonical_bytes(p.genesis_tx_secret)
            .expect("genesis tx secret is a canonical scalar");
        let spend = PublicKey::from_bytes(p.premine_spend_public)
            .expect("premine spend key is a valid point");
        let view = PublicKey::from_bytes(p.premine_view_public)
            .expect("premine view key is a valid point");
        let founder = Address::new(p.network, spend, view);
        Coinbase {
            height: 0,
            tx_public: r.public_key(),
            outputs: vec![CoinbaseOutput {
                one_time_key: stealth::derive_output(&r, &founder, 0),
                amount: p.premine_amount,
                commitment: Coinbase::commit(p.premine_amount),
            }],
        }
    }

    /// The canonical genesis block — the root every Noct chain descends from.
    ///
    /// Genesis is an **axiom**, not a validated block: the consensus rules are
    /// defined relative to a chain, so the first block cannot be checked against
    /// them. [`crate::chain::Blockchain::new`] therefore applies it directly, and
    /// it can never be rolled back or reorganised away. Its hash is what pins a
    /// node to *this* chain: a branch that does not descend from it is not Noct,
    /// however much work it carries.
    ///
    /// It mints the founder **premine** ([`PREMINE_AMOUNT`]) as its coinbase —
    /// this is a deliberate, transparent allocation, spendable only by the holder
    /// of the founder spend key. Every node derives the identical coinbase from
    /// the baked constants, so `genesis().id()` is the same everywhere.
    pub fn genesis() -> Block {
        Self::genesis_for(&crate::params::MAINNET)
    }

    /// The genesis block for a given network.
    ///
    /// Every network is built by this one function from its [`ChainParams`], so
    /// the testnet exercises the identical construction that mainnet launches
    /// with — only the constants differ. A testnet built by a separate code path
    /// would not be testing the thing that matters.
    ///
    /// [`ChainParams`]: crate::params::ChainParams
    pub fn genesis_for(p: &crate::params::ChainParams) -> Block {
        Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: p.genesis_timestamp,
                prev_id: [0u8; 32],
                nonce: 0,
            },
            coinbase: Self::genesis_coinbase(p),
            tx_hashes: Vec::new(),
        }
    }

    /// Merkle root over `[coinbase, tx_hashes…]`, binding all block contents.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut leaves = Vec::with_capacity(1 + self.tx_hashes.len());
        leaves.push(self.coinbase.hash());
        leaves.extend_from_slice(&self.tx_hashes);
        merkle_root(&leaves)
    }

    /// The blob fed to the PoW function: header bytes ‖ Merkle root ‖ leaf count.
    /// Depends on the nonce (in the header), so mining varies it.
    ///
    /// The leaf count is committed alongside the root on purpose. A Merkle root
    /// alone does not pin the *shape* of its tree: for any tree, a shorter leaf
    /// list whose entries are the interior nodes hashes to the same root (e.g.
    /// `root([A, H(B‖C)])` == `root([A, B, C])`). Exploiting that needs a leaf
    /// preimage, so it is not practically reachable — but binding the count makes
    /// the tree unambiguous outright and costs four bytes.
    pub fn hashing_blob(&self) -> Vec<u8> {
        let mut b = self.header.to_bytes();
        b.extend_from_slice(&self.merkle_root());
        b.extend_from_slice(&((1 + self.tx_hashes.len()) as u32).to_le_bytes());
        b
    }

    /// The block id: Keccak-256 of the hashing-blob.
    pub fn id(&self) -> [u8; 32] {
        keccak256(&self.hashing_blob())
    }

    /// The PoW hash under `pow`.
    pub fn pow_hash<P: ProofOfWork>(&self, pow: &P) -> [u8; 32] {
        pow.pow_hash(&self.hashing_blob())
    }

    /// Does this block's PoW meet `difficulty`?
    pub fn meets_difficulty<P: ProofOfWork>(&self, pow: &P, difficulty: Difficulty) -> bool {
        check_hash(&self.pow_hash(pow), difficulty)
    }

    /// Search nonces until the PoW meets `difficulty`. Returns the winning nonce
    /// (also left set in the header). With [`crate::pow::KeccakPow`] and modest
    /// difficulty this is fast; real mining uses RandomX.
    pub fn mine<P: ProofOfWork>(&mut self, pow: &P, difficulty: Difficulty) -> u32 {
        loop {
            if self.meets_difficulty(pow, difficulty) {
                return self.header.nonce;
            }
            // Wrapping search; in practice the timestamp/extra nonce would also
            // be advanced once the 32-bit space is exhausted.
            self.header.nonce = self.header.nonce.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::pow::KeccakPow;
    use crate::ring::RingMember;
    use crate::tx::{Payment, Transaction};
    use rand_core::OsRng;

    fn account() -> Account {
        Account::random(&mut OsRng)
    }
    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    #[test]
    fn coinbase_reward_and_commitment_are_valid() {
        let miner = account();
        let reward = base_reward(0);
        let cb = Coinbase::create(&mut OsRng, 0, &address(&miner), reward);
        assert_eq!(cb.total(), Some(reward));
        assert!(cb.is_valid(reward));
        // Wrong allowed reward is rejected.
        assert!(!cb.is_valid(reward - 1));
    }

    #[test]
    fn coinbase_amount_overflow_is_rejected() {
        // A crafted multi-output coinbase whose amounts overflow u64 must not
        // validate against a modest allowed reward (inflation guard).
        let miner = account();
        let allowed = base_reward(0);
        let cb = Coinbase {
            height: 0,
            tx_public: Coinbase::create(&mut OsRng, 0, &address(&miner), 0).tx_public,
            outputs: vec![
                CoinbaseOutput {
                    one_time_key: crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key(),
                    amount: 1u64 << 63,
                    commitment: Coinbase::commit(1u64 << 63),
                },
                CoinbaseOutput {
                    one_time_key: crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key(),
                    amount: (1u64 << 63).wrapping_add(allowed),
                    commitment: Coinbase::commit((1u64 << 63).wrapping_add(allowed)),
                },
            ],
        };
        // The two amounts sum to 2^64 + allowed, which wraps to `allowed` under
        // unchecked arithmetic — the overflow-checked total must return None.
        assert_eq!(cb.total(), None);
        assert!(!cb.is_valid(allowed));
    }

    #[test]
    fn coinbase_commitment_is_deterministic_open() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 7, &address(&miner), 5 * ATOMIC_UNITS);
        // Anyone can reconstruct the commitment from the public amount + mask 1.
        assert_eq!(
            cb.outputs[0].commitment,
            Opening::new(5 * ATOMIC_UNITS, Scalar::ONE).commit()
        );
    }

    #[test]
    fn miner_scans_own_coinbase_stranger_does_not() {
        let miner = account();
        let stranger = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let got = cb.scan(&miner).expect("miner finds their coinbase");
        assert_eq!(got.amount, base_reward(0));
        assert_eq!(got.spend_secret.public_key(), got.one_time_key);
        assert!(cb.scan(&stranger).is_none());
    }

    #[test]
    fn mining_meets_difficulty_and_is_verifiable() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1_700_000_000,
                prev_id: [0u8; 32],
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![],
        };
        let pow = KeccakPow;
        let difficulty = 4_000; // ~4000 hashes expected; trivial with Keccak
        block.mine(&pow, difficulty);
        assert!(block.meets_difficulty(&pow, difficulty));
        // Independent verifier recomputes the PoW from the block contents.
        assert!(check_hash(&block.pow_hash(&pow), difficulty));
    }

    #[test]
    fn changing_contents_changes_the_block_id() {
        let miner = account();
        let cb = Coinbase::create(&mut OsRng, 1, &address(&miner), base_reward(0));
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1_700_000_000,
                prev_id: [0u8; 32],
                nonce: 42,
            },
            coinbase: cb,
            tx_hashes: vec![[9u8; 32]],
        };
        let id1 = block.id();
        block.tx_hashes.push([1u8; 32]);
        assert_ne!(id1, block.id(), "adding a tx must change the block id via the Merkle root");
    }

    /// The economic loop: mine a coinbase, then spend the reward through a normal
    /// RingCT transaction. Ties layer 7 back into layers 2–6.
    #[test]
    fn coinbase_reward_is_spendable() {
        let miner = account();
        let reward = base_reward(0);
        let cb = Coinbase::create(&mut OsRng, 0, &address(&miner), reward);

        // Miner recovers the coinbase output.
        let received = cb.scan(&miner).unwrap();
        assert_eq!(received.amount, reward);

        // Spend it: pay a recipient (reward − fee), fee to the network.
        let recipient = account();
        let fee = ATOMIC_UNITS / 100; // 0.01 NOCT fee (sub-NOCT rewards)
        let ring: Vec<RingMember> = (0..11)
            .map(|_| {
                let key = crate::keys::PrivateKey(Scalar::random(&mut OsRng)).public_key();
                RingMember::new(key, Opening::random(1_000, &mut OsRng).commit())
            })
            .collect();
        let input = received.to_input(ring, 6);
        let payments = vec![Payment { destination: address(&recipient), amount: reward - fee }];
        let tx_keys = TxKeypair::random(&mut OsRng);
        let spend = Transaction::build(&mut OsRng, &[input], &payments, fee, &tx_keys).unwrap();

        assert!(spend.verify(&mut OsRng).is_ok());
        assert_eq!(spend.inputs[0].key_image(), received.key_image);
        assert_eq!(spend.scan(&recipient)[0].amount, reward - fee);
    }
}
