//! Layer 9 — peer-to-peer propagation (Dandelion++) over a pluggable transport.
//!
//! Two concerns live here:
//!
//! * **[`Node`]** — the pure propagation logic: validate what arrives, keep a
//!   mempool, and forward transactions/blocks to peers. A node never performs
//!   I/O; `receive`/`originate` take an incoming event and *return* the outgoing
//!   messages. That keeps the consensus-visible behaviour deterministic and
//!   fully testable.
//! * **[`Network`]** — an in-memory transport that shuttles those messages
//!   between nodes until the system goes quiet. Real TCP/socket wiring would
//!   implement the same "deliver an [`Envelope`]" step; nothing in [`Node`]
//!   changes when it does.
//!
//! ### Dandelion++
//!
//! To hide which node *originated* a transaction, propagation has two phases:
//!
//! * **Stem** — the transaction is relayed to a *single* pseudo-random peer (the
//!   node's per-epoch stem successor). Because fan-out is one, an observer can't
//!   tell whether a relaying node authored the transaction or merely forwarded
//!   it.
//! * **Fluff** — at each stem hop the node flips a biased coin
//!   ([`Node::fluff_probability`]); on heads (or if it has no stem successor) it
//!   switches to fluff: the transaction enters the public mempool and is flooded
//!   to *all* peers, spreading fast.
//!
//! Epoch management and adversary-resistant successor graphs are refinements for
//! the real transport; the phase state machine here is the core.

use std::collections::HashSet;

use crate::block::Block;
use crate::chain::Blockchain;
use crate::mempool::Mempool;
use crate::pow::ProofOfWork;
use crate::tx::Transaction;

/// A node identifier / index within a [`Network`].
pub type PeerId = usize;

/// Default per-hop probability of switching from stem to fluff.
pub const FLUFF_PROBABILITY: f64 = 0.1;

/// Identifies the network a peer belongs to ("NOCT" in ASCII). Advertised in
/// [`Wire::Tip`] so testnet and mainnet peers cannot sync into each other. This
/// is a fast, explicit rejection; the real guarantee is the genesis block, which
/// makes a foreign chain unattachable regardless.
pub const NETWORK_ID: u32 = 0x4E4F4354;

/// Propagation phase of a gossiped transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// Low-fan-out anonymity relay.
    Stem,
    /// Flood to all peers.
    Fluff,
}

/// A gossip / sync message.
#[derive(Clone, Debug)]
pub enum Wire {
    Tx(Transaction, Phase),
    /// A block and the transactions it contains.
    Block(Block, Vec<Transaction>),
    /// Ask a peer for its current tip (used to start initial block download).
    GetTip,
    /// Advertise our tip: `(network id, height, tip block id, cumulative
    /// difficulty)`.
    ///
    /// The **cumulative difficulty is the field fork choice is decided on** —
    /// [`Blockchain::would_reorg_to`] compares work, not length. It was missing
    /// here originally, so the network could only ever notice a *longer* chain
    /// while consensus prefers the *heavier* one; a heavier-but-shorter chain was
    /// invisible and a node could sit on a lighter chain indefinitely (security
    /// review F29). Height is retained because it drives the cheap sequential
    /// catch-up, which is the common case.
    Tip(u32, u64, [u8; 32], u128),
    /// Request the block at a given height (initial block download).
    GetBlock(u64),
    /// Response indicating we have no block at the requested height.
    NoBlock(u64),
    /// Handshake sent right after connecting: `(network id, genesis block id,
    /// our listen port, session nonce)`. The genesis id lets a peer reject a
    /// foreign chain immediately; the port gives an inbound peer a dialable
    /// address for us (an inbound socket's remote port is ephemeral); the random
    /// per-process nonce lets a peer detect a self-connection (nonce == its own)
    /// or a duplicate link to a peer it is already connected to.
    Version(u32, [u8; 32], u16, u64),
    /// Ask a peer to share addresses from its address book (peer discovery).
    GetPeers,
    /// A batch of known peer listen-addresses, in reply to [`Wire::GetPeers`].
    Peers(Vec<std::net::SocketAddr>),
}

/// A message addressed to a peer.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub to: PeerId,
    pub msg: Wire,
}

/// A network participant: a chain, a mempool, peers, and Dandelion++ state.
pub struct Node<P: ProofOfWork> {
    pub id: PeerId,
    pub chain: Blockchain<P>,
    pub mempool: Mempool,
    /// Per-hop stem→fluff probability (defaults to [`FLUFF_PROBABILITY`]).
    pub fluff_probability: f64,
    peers: Vec<PeerId>,
    stem_successor: Option<PeerId>,
    seen_txs: HashSet<[u8; 32]>,
    seen_blocks: HashSet<[u8; 32]>,
}

impl<P: ProofOfWork> Node<P> {
    pub fn new(id: PeerId, chain: Blockchain<P>) -> Self {
        Node {
            id,
            chain,
            mempool: Mempool::new(),
            fluff_probability: FLUFF_PROBABILITY,
            peers: Vec::new(),
            stem_successor: None,
            seen_txs: HashSet::new(),
            seen_blocks: HashSet::new(),
        }
    }

    pub fn add_peer(&mut self, peer: PeerId) {
        if peer != self.id && !self.peers.contains(&peer) {
            self.peers.push(peer);
        }
    }

    pub fn peers(&self) -> &[PeerId] {
        &self.peers
    }

    pub fn set_stem_successor(&mut self, successor: Option<PeerId>) {
        self.stem_successor = successor;
    }

    /// Originate a locally-created transaction: validate it, then enter the stem
    /// phase. Returns the messages to send (empty if invalid or already seen).
    pub fn originate<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
    ) -> Vec<Envelope> {
        if !self.seen_txs.insert(tx.hash()) {
            return Vec::new();
        }
        if self.chain.validate_tx(rng, &tx).is_err() {
            return Vec::new();
        }
        self.relay_stem(rng, tx)
    }

    /// Handle an incoming message and return outgoing messages.
    pub fn receive<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        msg: Wire,
    ) -> Vec<Envelope> {
        match msg {
            Wire::Tx(tx, phase) => self.receive_tx(rng, tx, phase),
            Wire::Block(block, txs) => self.receive_block(rng, block, txs),
            // Initial-block-download and peer-discovery messages are handled by
            // the real TCP transport (`noct-node`), not this in-memory simulation.
            Wire::GetTip
            | Wire::Tip(..)
            | Wire::GetBlock(_)
            | Wire::NoBlock(_)
            | Wire::Version(..)
            | Wire::GetPeers
            | Wire::Peers(_) => Vec::new(),
        }
    }

    fn receive_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
        phase: Phase,
    ) -> Vec<Envelope> {
        if !self.seen_txs.insert(tx.hash()) {
            return Vec::new(); // already processed → stops gossip loops
        }
        if self.chain.validate_tx(rng, &tx).is_err() {
            return Vec::new(); // don't relay invalid transactions
        }
        match phase {
            Phase::Stem => self.relay_stem(rng, tx),
            Phase::Fluff => self.fluff(rng, tx),
        }
    }

    // Dandelion++ stem: forward to the single stem successor, unless we flip to
    // fluff (or have no successor).
    fn relay_stem<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
    ) -> Vec<Envelope> {
        let flip = (rng.next_u64() as f64) / (u64::MAX as f64);
        match self.stem_successor {
            Some(next) if flip >= self.fluff_probability => {
                vec![Envelope { to: next, msg: Wire::Tx(tx, Phase::Stem) }]
            }
            _ => self.fluff(rng, tx),
        }
    }

    // Fluff: admit to the public mempool and flood every peer.
    fn fluff<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
    ) -> Vec<Envelope> {
        // Ignore AlreadyKnown / races; validity was checked above.
        let _ = self.mempool.add(rng, &self.chain, tx.clone());
        self.peers
            .iter()
            .map(|&peer| Envelope { to: peer, msg: Wire::Tx(tx.clone(), Phase::Fluff) })
            .collect()
    }

    fn receive_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        block: Block,
        txs: Vec<Transaction>,
    ) -> Vec<Envelope> {
        let id = block.id();
        if !self.seen_blocks.insert(id) {
            return Vec::new();
        }
        // Only relay blocks we can actually attach to our tip and that validate.
        if self.chain.add_block(rng, &block, &txs).is_err() {
            return Vec::new();
        }
        self.mempool.on_block(&txs);
        self.peers
            .iter()
            .map(|&peer| Envelope { to: peer, msg: Wire::Block(block.clone(), txs.clone()) })
            .collect()
    }
}

/// Statistics from running the transport to quiescence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Total messages delivered.
    pub delivered: usize,
    /// The largest fan-out (outgoing messages) produced by any single delivery.
    pub max_fan_out: usize,
}

/// An in-memory transport connecting a set of [`Node`]s. Stand-in for real
/// sockets; the delivery step is the seam a networked implementation replaces.
pub struct Network<P: ProofOfWork> {
    pub nodes: Vec<Node<P>>,
}

impl<P: ProofOfWork> Network<P> {
    /// Build a network from per-node starting chains (node `i` gets `chains[i]`).
    pub fn new(chains: Vec<Blockchain<P>>) -> Self {
        let nodes = chains
            .into_iter()
            .enumerate()
            .map(|(id, chain)| Node::new(id, chain))
            .collect();
        Network { nodes }
    }

    /// Connect two peers bidirectionally.
    pub fn connect(&mut self, a: PeerId, b: PeerId) {
        self.nodes[a].add_peer(b);
        self.nodes[b].add_peer(a);
    }

    /// Fully connect every pair of nodes.
    pub fn connect_all(&mut self) {
        let n = self.nodes.len();
        for a in 0..n {
            for b in (a + 1)..n {
                self.connect(a, b);
            }
        }
    }

    /// Give every node a stem successor: node `i` → node `(i+1) % n`. (A real
    /// node would choose this pseudo-randomly per epoch.)
    pub fn assign_ring_stem(&mut self) {
        let n = self.nodes.len();
        for i in 0..n {
            self.nodes[i].set_stem_successor(Some((i + 1) % n));
        }
    }

    /// Set the same fluff probability on every node (test knob).
    pub fn set_fluff_probability(&mut self, p: f64) {
        for node in &mut self.nodes {
            node.fluff_probability = p;
        }
    }

    /// Deliver `initial` messages and everything they trigger, until no messages
    /// remain.
    pub fn run<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        initial: Vec<Envelope>,
    ) -> RunStats {
        let mut queue: std::collections::VecDeque<Envelope> = initial.into_iter().collect();
        let mut stats = RunStats::default();
        while let Some(env) = queue.pop_front() {
            stats.delivered += 1;
            let out = self.nodes[env.to].receive(rng, env.msg);
            stats.max_fan_out = stats.max_fan_out.max(out.len());
            queue.extend(out);
        }
        stats
    }

    /// Originate `tx` at node `from` and propagate to quiescence.
    pub fn originate_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        from: PeerId,
        tx: Transaction,
    ) -> RunStats {
        let initial = self.nodes[from].originate(rng, tx);
        self.run(rng, initial)
    }

    /// Broadcast an already-mined `block` from node `from` to the network.
    pub fn broadcast_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        from: PeerId,
        block: Block,
        txs: Vec<Transaction>,
    ) -> RunStats {
        let initial = self.nodes[from].receive(rng, Wire::Block(block, txs));
        self.run(rng, initial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network as Net};
    use crate::block::{Block, BlockHeader, Coinbase};
    use crate::chain::Blockchain;
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::Account;
    use crate::pow::KeccakPow;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Net::Mainnet, a.spend_public, a.view_public)
    }

    // Mine a coinbase block onto `chain`; return (miner's received output, index).
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

    // A chain with a spendable coinbase for `owner` plus decoys.
    fn funded_chain(owner: &Account) -> (Blockchain<KeccakPow>, ReceivedOutput, u64) {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let (received, index) = mine(&mut chain, owner, 1_000);
        let filler = Account::random(&mut OsRng);
        for i in 0..15 {
            mine(&mut chain, &filler, 1_200 + i * 130);
        }
        (chain, received, index)
    }

    fn spend(chain: &Blockchain<KeccakPow>, src: &ReceivedOutput, idx: u64, to: &Account) -> Transaction {
        let (ring, signer) = chain.select_ring_uniform(&mut OsRng, crate::chain::RING_SIZE, idx).unwrap();
        let input = src.to_input(ring, signer);
        Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(to), amount: src.amount - ATOMIC_UNITS / 100 }],
            ATOMIC_UNITS / 100,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap()
    }

    // Build a network of `n` nodes all sharing `chain`.
    fn network_of(n: usize, chain: &Blockchain<KeccakPow>) -> Network<KeccakPow> {
        Network::new(vec![chain.clone(); n])
    }

    #[test]
    fn fluff_reaches_every_node() {
        let owner = Account::random(&mut OsRng);
        let (chain, src, idx) = funded_chain(&owner);
        let bob = Account::random(&mut OsRng);
        let tx = spend(&chain, &src, idx, &bob);
        let tx_hash = tx.hash();

        let mut net = network_of(6, &chain);
        net.connect_all();
        net.assign_ring_stem();
        net.set_fluff_probability(1.0); // force immediate fluff for determinism

        net.originate_tx(&mut OsRng, 0, tx);

        // Every node admitted the transaction to its mempool.
        for node in &net.nodes {
            assert!(node.mempool.contains(&tx_hash), "node {} missing tx", node.id);
        }
    }

    #[test]
    fn stem_phase_has_fan_out_one() {
        let owner = Account::random(&mut OsRng);
        let (chain, src, idx) = funded_chain(&owner);
        let bob = Account::random(&mut OsRng);
        let tx = spend(&chain, &src, idx, &bob);

        let mut net = network_of(6, &chain);
        net.connect_all();
        net.assign_ring_stem();
        net.set_fluff_probability(0.0); // pure stem: never fluff

        let stats = net.originate_tx(&mut OsRng, 0, tx);

        // In pure stem each hop forwards to exactly one peer — never a flood.
        assert_eq!(stats.max_fan_out, 1, "stem must not fan out");
        // And since it never fluffed, no node put it in the public mempool.
        assert!(net.nodes.iter().all(|n| n.mempool.is_empty()));
    }

    #[test]
    fn invalid_transaction_is_not_relayed() {
        let owner = Account::random(&mut OsRng);
        let (chain, src, idx) = funded_chain(&owner);
        let bob = Account::random(&mut OsRng);
        let mut tx = spend(&chain, &src, idx, &bob);
        tx.fee = tx.fee.wrapping_add(1); // break the signature binding / balance

        let mut net = network_of(4, &chain);
        net.connect_all();
        net.set_fluff_probability(1.0);

        net.originate_tx(&mut OsRng, 0, tx);
        assert!(net.nodes.iter().all(|n| n.mempool.is_empty()));
    }

    #[test]
    fn block_propagates_and_clears_mempools() {
        // All nodes share a chain and hold `tx` in their mempools; a mined block
        // then propagates and evicts it everywhere.
        let owner = Account::random(&mut OsRng);
        let (chain, src, idx) = funded_chain(&owner);
        let bob = Account::random(&mut OsRng);
        let tx = spend(&chain, &src, idx, &bob);

        let mut net = network_of(5, &chain);
        net.connect_all();
        net.set_fluff_probability(1.0);
        net.originate_tx(&mut OsRng, 0, tx.clone());
        assert!(net.nodes.iter().all(|n| n.mempool.contains(&tx.hash())));

        // Node 0 mines a block including `tx`.
        let miner = Account::random(&mut OsRng);
        let subsidy = base_reward(net.nodes[0].chain.emitted());
        let cb = Coinbase::create(
            &mut OsRng,
            net.nodes[0].chain.height(),
            &address(&miner),
            subsidy + tx.fee,
        );
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + 100_000,
                prev_id: net.nodes[0].chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![tx.hash()],
        };
        block.mine(&KeccakPow, net.nodes[0].chain.next_difficulty());

        net.broadcast_block(&mut OsRng, 0, block, vec![tx.clone()]);

        // Every node advanced its chain and dropped the now-mined transaction.
        for node in &net.nodes {
            assert!(!node.mempool.contains(&tx.hash()), "node {} kept mined tx", node.id);
            assert!(node.chain.is_spent(&tx.inputs[0].signature.key_image));
        }
    }
}
