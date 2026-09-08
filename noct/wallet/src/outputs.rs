//! The output set a wallet keeps — and nothing else.
//!
//! A wallet needs the chain's outputs for one purpose: choosing ring members.
//! It does not need the blocks those outputs came in. Keeping them was costing
//! far more than it looked: measured on a real 88 MB wallet cache (14,345
//! blocks, 17,325 transactions), simply *decoding* the blocks took **54.6 s**,
//! almost all of it turning 32-byte wire points into the 160-byte decompressed
//! form — roughly 554,000 point decompressions on every single invocation.
//!
//! So this stores members exactly as they arrive: **compressed**. A ring needs
//! sixteen of them, so sixteen get decompressed, on demand, per input. The rest
//! are never touched. That is the whole trick, and it is why the set can be
//! held at all — 64 bytes per output against 320 decompressed.
//!
//! Ring selection itself is not reimplemented here. [`OutputSet`] carries the
//! algorithm, and a wallet that answered these questions differently from a
//! node would draw decoys from a different distribution than the one that was
//! analysed — while emitting transactions that look perfectly well-formed.

use noct_core::amounts::Commitment;
use noct_core::chain::OutputSet;
use noct_core::keys::PublicKey;
use noct_core::ring::RingMember;

/// Format tag, so a store written by an older build is rejected rather than
/// misread. A wallet that misreads its own output set builds rings out of
/// nonsense and cannot spend.
const STORE_VERSION: u8 = 1;

/// A wallet's view of the chain's outputs, in global-index order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputStore {
    /// `key || commitment`, compressed, indexed by global output index.
    members: Vec<[u8; 64]>,
    /// Height of the block that created each output, and whether it is coinbase.
    ///
    /// Heights are non-decreasing, because outputs are appended in block order.
    /// [`OutputSet`] relies on that to bound ring assembly to the immature
    /// suffix instead of scanning the whole set.
    meta: Vec<(u64, bool)>,
    height: u64,
    maturity: u64,
}

impl OutputStore {
    pub fn new(maturity: u64) -> Self {
        OutputStore { members: Vec::new(), meta: Vec::new(), height: 0, maturity }
    }

    /// Record one output, at the next global index.
    pub fn push(&mut self, member: &RingMember, height: u64, coinbase: bool) {
        debug_assert!(
            self.meta.last().map(|m| m.0 <= height).unwrap_or(true),
            "outputs must arrive in block order; heights are assumed non-decreasing"
        );
        let mut packed = [0u8; 64];
        packed[..32].copy_from_slice(&member.key.to_bytes());
        packed[32..].copy_from_slice(&member.commitment.to_bytes());
        self.members.push(packed);
        self.meta.push((height, coinbase));
    }

    /// Note the tip the set is current as of. Maturity is measured against it.
    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Serialize. Fixed-width records, so loading is a bounds check and a copy
    /// rather than a parse — the cost this whole type exists to avoid.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 * 3 + self.members.len() * 73);
        out.push(STORE_VERSION);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.maturity.to_le_bytes());
        out.extend_from_slice(&(self.members.len() as u64).to_le_bytes());
        for (m, (h, coinbase)) in self.members.iter().zip(&self.meta) {
            out.extend_from_slice(m);
            out.extend_from_slice(&h.to_le_bytes());
            out.push(u8::from(*coinbase));
        }
        out
    }

    /// Parse a store. `None` for anything it does not fully understand — a
    /// wrong version, a truncated tail, a count that does not match the bytes.
    /// The caller's remedy is to rebuild, which costs time and never
    /// correctness.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 25 || bytes[0] != STORE_VERSION {
            return None;
        }
        let height = u64::from_le_bytes(bytes[1..9].try_into().ok()?);
        let maturity = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let count = u64::from_le_bytes(bytes[17..25].try_into().ok()?) as usize;
        // Check the length before allocating: the count is read from a file
        // that may be truncated or corrupt, and reserving from it would turn a
        // damaged byte into an allocation of that size.
        let body = &bytes[25..];
        if body.len() != count.checked_mul(73)? {
            return None;
        }
        let mut members = Vec::with_capacity(count);
        let mut meta = Vec::with_capacity(count);
        for rec in body.chunks_exact(73) {
            let mut packed = [0u8; 64];
            packed.copy_from_slice(&rec[..64]);
            members.push(packed);
            meta.push((u64::from_le_bytes(rec[64..72].try_into().ok()?), rec[72] != 0));
        }
        Some(OutputStore { members, meta, height, maturity })
    }
}

impl OutputSet for OutputStore {
    fn output_count(&self) -> u64 {
        self.members.len() as u64
    }

    fn tip_height(&self) -> u64 {
        self.height
    }

    fn coinbase_maturity(&self) -> u64 {
        self.maturity
    }

    /// Decompress on demand. This is the only place a stored point becomes a
    /// curve point, and it runs sixteen times per input rather than once per
    /// output in the chain.
    fn member_at(&self, index: u64) -> Option<RingMember> {
        let packed = self.members.get(usize::try_from(index).ok()?)?;
        let key = PublicKey::from_bytes(packed[..32].try_into().ok()?)?;
        let commitment = Commitment::from_bytes(packed[32..].try_into().ok()?)?;
        Some(RingMember::new(key, commitment))
    }

    fn meta_at(&self, index: u64) -> Option<(u64, bool)> {
        self.meta.get(usize::try_from(index).ok()?).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::address::{Address, Network};
    use noct_core::block::{Block, BlockHeader, Coinbase};
    use noct_core::chain::Blockchain;
    use noct_core::emission::base_reward;
    use noct_core::keys::Account;
    use noct_core::pow::KeccakPow;
    use rand_core::OsRng;

    /// Mirror a chain's outputs into a store, the way a syncing wallet would.
    fn mirror(chain: &Blockchain<KeccakPow>) -> OutputStore {
        let mut store = OutputStore::new(chain.coinbase_maturity());
        for i in 0..chain.output_count() {
            let (h, coinbase) = chain.meta_at(i).unwrap();
            store.push(&chain.member_at(i).unwrap(), h, coinbase);
        }
        store.set_height(chain.tip_height());
        store
    }

    fn chain_with_blocks(n: u64) -> Blockchain<KeccakPow> {
        let mut chain = Blockchain::with_maturity(KeccakPow, 3);
        let miner = Account::random(&mut OsRng);
        let addr = Address::new(Network::Mainnet, miner.spend_public, miner.view_public);
        for i in 0..n {
            let subsidy = base_reward(chain.emitted());
            let cb = Coinbase::create(&mut OsRng, chain.height(), &addr, subsidy);
            let mut block = Block {
                header: BlockHeader {
                    major_version: 1,
                    minor_version: 0,
                    timestamp: noct_core::block::GENESIS_TIMESTAMP + 1_000 + i * 130,
                    prev_id: chain.tip_id(),
                    nonce: 0,
                },
                coinbase: cb,
                tx_hashes: Vec::new(),
            };
            block.mine(&KeccakPow, chain.next_difficulty());
            chain.add_block(&mut OsRng, &block, &[]).expect("valid block");
        }
        chain
    }

    /// **The contract that matters.** A wallet's store must answer every
    /// question the selector asks *exactly* as the chain would. If it drifts,
    /// the wallet draws decoys from a different distribution than the node —
    /// and nothing about the resulting transaction looks wrong.
    #[test]
    fn a_store_answers_identically_to_the_chain_it_mirrors() {
        let chain = chain_with_blocks(20);
        let store = mirror(&chain);

        assert_eq!(store.output_count(), chain.output_count());
        assert_eq!(store.tip_height(), chain.tip_height());
        assert_eq!(store.coinbase_maturity(), chain.coinbase_maturity());
        assert!(store.output_count() > 0, "the chain must actually have outputs");

        for i in 0..chain.output_count() {
            assert_eq!(store.member_at(i), chain.member_at(i), "member {i}");
            assert_eq!(store.meta_at(i), chain.meta_at(i), "meta {i}");
            assert_eq!(store.spendable_now(i), chain.spendable_now(i), "spendable {i}");
        }
        // One past the end must be absent in both, not merely equal.
        let end = chain.output_count();
        assert_eq!(store.member_at(end), None);
        assert_eq!(chain.member_at(end), None);
    }

    /// Ring selection over the store must produce rings the chain recognises —
    /// every member a real output, and the real one present.
    #[test]
    fn a_ring_chosen_from_the_store_is_valid_against_the_chain() {
        let chain = chain_with_blocks(40);
        let store = mirror(&chain);
        let real_index = 0;

        let (ring, signer) = store
            .select_ring_recency_biased(&mut OsRng, 11, real_index)
            .expect("enough outputs for a ring");
        assert_eq!(ring.len(), 11);
        assert_eq!(ring[signer], chain.member_at(real_index).unwrap());
        for m in &ring {
            assert!(
                chain.output_index(m).is_some(),
                "every ring member must be an output the chain knows"
            );
        }
    }

    #[test]
    fn a_store_survives_a_round_trip() {
        let store = mirror(&chain_with_blocks(12));
        let decoded = OutputStore::decode(&store.encode()).expect("round trip");
        assert_eq!(decoded, store);
    }

    /// A damaged store must be refused, not misread. Building rings out of
    /// nonsense would leave a wallet unable to spend, with nothing to point at.
    #[test]
    fn a_damaged_store_is_refused_rather_than_misread() {
        let good = mirror(&chain_with_blocks(6)).encode();

        assert!(OutputStore::decode(&[]).is_none(), "empty");
        assert!(OutputStore::decode(&good[..good.len() - 1]).is_none(), "truncated record");
        assert!(OutputStore::decode(&good[..20]).is_none(), "truncated header");

        let mut wrong_version = good.clone();
        wrong_version[0] = STORE_VERSION + 1;
        assert!(OutputStore::decode(&wrong_version).is_none(), "future version");

        // A count that disagrees with the bytes present must not be trusted —
        // least of all to size an allocation.
        let mut liar = good.clone();
        liar[17..25].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(OutputStore::decode(&liar).is_none(), "absurd count");
    }
}
