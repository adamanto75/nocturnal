//! `noct-node` — a runnable Noct full node over `std::net` + threads.
//!
//! The design keeps all consensus-visible logic in [`NodeState`], which performs
//! **no I/O**: it validates and relays by returning a [`Relay`] action, and mines
//! by returning a block. The transport ([`transport`]) and RPC ([`rpc`]) layers
//! are thin shells that move bytes and call into `NodeState` under a lock. This
//! keeps the node testable without sockets and confines networking to the edges.
//!
//! Propagation is Dandelion++ (see [`noct_core::p2p`]): a submitted transaction
//! enters the *stem* phase (relayed to a single random peer) and flips to *fluff*
//! (mempool + flood) with probability [`NodeState::fluff_probability`] per hop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use noct_core::address::Address;
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::{Blockchain, ChainError};
use noct_core::emission::base_reward;
use noct_core::mempool::Mempool;
use noct_core::p2p::{Phase, Wire};
use noct_core::pow::ProofOfWork;
use noct_core::tx::Transaction;
use rand_core::OsRng;

use store::{AsyncStore, BlockStore};
use transport::Peers;

pub mod miner;
pub mod rpc;
pub mod store;
pub mod transport;

use miner::MiningControl;

// --- Proof of work selection ------------------------------------------------
//
// The whole node is written against `NodePow`, a single concrete type chosen at
// compile time. Default builds use the Keccak placeholder (no C++ toolchain);
// `--features randomx` swaps in real RandomX everywhere. Nothing else in the node
// changes — the entire codebase was already generic over the `ProofOfWork` trait.

/// Fixed RandomX seed (the "epoch key"). Per-epoch rotation off a past block hash
/// is a follow-up; a constant seed is correct as long as every node shares it.
#[cfg(feature = "randomx")]
pub const RANDOMX_SEED: &[u8] = b"noct/genesis/randomx/v1";

/// The proof-of-work function the node is built with.
#[cfg(not(feature = "randomx"))]
pub type NodePow = noct_core::pow::KeccakPow;
/// The proof-of-work function the node is built with.
#[cfg(feature = "randomx")]
pub type NodePow = noct_randomx::RandomXPow;

/// Construct the node's PoW instance. Public so the reference miner
/// (`noct-miner`) can grind with the same PoW the node validates against.
#[cfg(not(feature = "randomx"))]
pub fn new_pow() -> NodePow {
    noct_core::pow::KeccakPow
}
#[cfg(feature = "randomx")]
pub fn new_pow() -> NodePow {
    noct_randomx::RandomXPow::new(RANDOMX_SEED).expect("failed to initialise RandomX")
}

/// Human-readable name of the active PoW (for startup logging).
pub fn pow_name() -> &'static str {
    if cfg!(feature = "randomx") {
        "RandomX"
    } else {
        "Keccak (placeholder)"
    }
}

/// Runtime configuration for [`run`].
pub struct Config {
    /// Which network to join. Selects the genesis block and the p2p magic, so a
    /// node on one network can never merge with another. See
    /// [`noct_core::params`].
    pub network: noct_core::address::Network,
    /// Address to listen on for P2P connections.
    pub p2p_listen: SocketAddr,
    /// Address to serve the JSON-RPC on.
    pub rpc_listen: SocketAddr,
    /// Peers to dial on startup (also seeded into the address book).
    pub peers: Vec<SocketAddr>,
    /// Seed nodes: addresses added to the book for the connection manager to dial
    /// while forming the network (no immediate dial required).
    pub seeds: Vec<SocketAddr>,
    /// Target number of outbound connections the manager maintains.
    pub target_outbound: usize,
    /// Ask peers not to remember this node's address.
    ///
    /// For a node that exists briefly and will never be reachable again — a CI
    /// runner, a one-shot probe. Without it, every such node leaves a permanent
    /// dead entry in the address book of every peer it touches.
    pub ephemeral: bool,
    /// Where coinbase rewards are paid.
    pub miner_address: Address,
    /// Start with the background miner running (it can be toggled later via RPC).
    pub mine: bool,
    /// Number of mining worker threads (cores to grind on).
    pub mine_threads: usize,
    /// Retained for CLI compatibility; the multi-threaded miner self-paces via the
    /// difficulty retarget and does not use a fixed inter-block delay.
    pub mine_interval: Duration,
    /// Directory for the persistent block log. `None` keeps the chain in memory
    /// only (it is then re-synced from peers on every restart).
    pub data_dir: Option<std::path::PathBuf>,
    /// Per-source-IP RPC rate limit, in cost units per second (see
    /// [`rpc::DEFAULT_RPC_RATE`]). `0` disables limiting.
    pub rpc_rate_limit: u32,
    /// Shared secret required on every RPC request (`Authorization: Bearer …`).
    ///
    /// `None` leaves the RPC unauthenticated, which is only permitted when it is
    /// bound to a loopback address — [`run`] refuses to start otherwise, since
    /// the RPC can control mining and submit blocks and transactions.
    pub rpc_token: Option<String>,
    /// PEM certificate and key for serving the RPC over TLS.
    ///
    /// Strongly wanted for any off-box RPC: the token above travels on every
    /// request, so in plaintext a single observed request is the whole
    /// credential, and a wallet's queries reveal what it is looking for.
    pub rpc_tls: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

/// Start the node: P2P listener, outbound dials, RPC server, and (optionally) a
/// background miner. Blocks the calling thread.
pub fn run(config: Config) -> std::io::Result<()> {
    // Fail closed. The RPC is an administrative surface — it starts and stops
    // mining, and accepts blocks and transactions — so serving it off-box
    // without a token would hand those controls to anyone who can reach the
    // port. Refuse rather than silently expose it (security review F18).
    if !config.rpc_listen.ip().is_loopback() && config.rpc_token.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to serve an unauthenticated RPC on {}: that is not a loopback address.\n\
                 Either set --rpc-token-file <PATH> (preferred) / --rpc-token <TOKEN>,\n\
                 or bind the RPC to localhost with --rpc 127.0.0.1:9334.",
                config.rpc_listen
            ),
        ));
    }

    // The miner address must belong to this network, or every block mined would
    // pay an address nobody on this chain can use — and on a testnet it would
    // quietly look like a mainnet payout.
    if config.miner_address.network != config.network {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the miner address is a {:?} address, but this node is running on {:?}.\n\
                 Use an address for this network (noct-cli new --network {}).",
                config.miner_address.network,
                config.network,
                match config.network {
                    noct_core::address::Network::Mainnet => "mainnet",
                    noct_core::address::Network::Testnet => "testnet",
                }
            ),
        ));
    }

    let mut node = NodeState::for_network(config.network, config.miner_address);

    // Restore the chain from disk before serving anything, then keep appending.
    if let Some(dir) = &config.data_dir {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("blocks.dat");
        // The block log is a *cache* of chain data that peers can refill, so an
        // unreadable one must never stop the node from starting. It becomes
        // unreadable for an ordinary reason: a block-format change (a new
        // consensus rule, a new transaction field) makes previously-written
        // blocks undecodable. Treat that like the bad-log case below — warn,
        // start from genesis, and re-sync — but move the old file aside rather
        // than deleting it, so nothing the user had is destroyed.
        let stored = match BlockStore::load_all(&path) {
            Ok(blocks) => blocks,
            Err(e) => {
                eprintln!("WARNING: cannot read the stored chain at {}: {e}", path.display());
                let aside = path.with_extension("dat.unreadable");
                match std::fs::rename(&path, &aside) {
                    Ok(()) => eprintln!("         moved it to {} and starting from genesis;", aside.display()),
                    Err(e) => eprintln!("         (could not set it aside: {e}); starting from genesis;"),
                }
                eprintln!("         the chain will be re-synced from peers.");
                Vec::new()
            }
        };
        let mut log_is_stale = false;
        if !stored.is_empty() {
            eprintln!("replaying {} stored blocks from {}…", stored.len(), path.display());
            match node.replay(&mut OsRng, stored) {
                Ok(height) => eprintln!("restored chain to height {height}"),
                // A bad log leaves the valid prefix applied; peers refill the rest.
                Err(e) => {
                    eprintln!("WARNING: {e}");
                    log_is_stale = true;
                }
            }
        }
        node.attach_store(AsyncStore::open(&path)?);
        if log_is_stale {
            // The log no longer describes the chain, so it must be replaced —
            // not appended to.
            //
            // Reopening in append mode left the bad prefix in place and wrote
            // the re-synced chain after it. Every restart then hit the same bad
            // record, truncated again, and appended another copy: the file grew
            // without bound and never healed. Seen on this testnet at 14,623
            // stored blocks for a 4,931-block chain, truncating on every start.
            eprintln!("the stored log no longer matches the chain; rewriting it");
            node.rewrite_store();
        }
        eprintln!("persisting blocks to {}", path.display());
    }

    let state = Arc::new(Mutex::new(node));
    let peers = Peers::new();

    // Peer discovery: seed the address book from --peer/--seed, then let the
    // connection manager form and maintain the network. The handshake carries our
    // genesis id so a foreign chain is rejected on sight.
    let genesis = { state.lock().unwrap().chain.genesis_id() };
    let magic = { state.lock().unwrap().chain.params().p2p_magic };
    let disc = transport::Discovery::new(config.p2p_listen, genesis, magic, config.target_outbound)
        .ephemeral(config.ephemeral)
        .with_book(config.data_dir.as_ref().map(|d| d.join("peers.dat")));
    disc.learn_seeds(config.peers.iter().copied());
    disc.learn_seeds(config.seeds.iter().copied());

    let p2p = TcpListener::bind(config.p2p_listen)?;
    transport::spawn_listener(p2p, Arc::clone(&state), peers.clone(), disc.clone());
    transport::spawn_connection_manager(Arc::clone(&state), peers.clone(), disc);

    let rpc_acceptor = match &config.rpc_tls {
        Some((cert, key)) => Some(
            noct_tls::Acceptor::from_pem(cert, key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("RPC TLS: {e}")))?,
        ),
        None => None,
    };
    if let Some(a) = &rpc_acceptor {
        eprintln!("  rpc tls:      sha256:{}", noct_tls::show_fingerprint(&a.leaf_fingerprint()));
    } else if !config.rpc_listen.ip().is_loopback() {
        // Authenticated but unencrypted: the token is on the wire in the clear,
        // on every request, to anyone who can watch this link.
        eprintln!(
            "  rpc tls:      OFF — the RPC token is sent in plaintext on every request. \
             Pass --rpc-tls-cert/--rpc-tls-key."
        );
    }
    let rpc = TcpListener::bind(config.rpc_listen)?;
    rpc::serve(
        rpc,
        Arc::clone(&state),
        peers.clone(),
        config.rpc_token.clone(),
        config.rpc_rate_limit,
        rpc_acceptor,
    );

    // Multi-threaded miner: always spawned so it can be toggled on/off over RPC,
    // configured from the CLI flags for the initial state.
    let control = {
        let node = state.lock().unwrap();
        node.mining_control()
    };
    control.set_threads(config.mine_threads);
    control.set_active(config.mine);
    miner::spawn(Arc::clone(&state), peers.clone(), control);

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Maximum transactions a mined block will pull from the mempool.
pub const MAX_BLOCK_TXS: usize = 500;

/// How far back a node will re-download a peer's chain when resolving a
/// competing branch. Bounds the work an adversary can make us do, and caps how
/// deep a reorg we will consider at all.
pub const MAX_REORG_DEPTH: u64 = 100;

/// Misbehavior points for relaying an invalid transaction.
pub const MISBEHAVIOR_INVALID_TX: u32 = 20;
/// Misbehavior points for relaying an invalid block (bad PoW, bad coinbase,
/// invalid tx inside it, …). A `BadPrevId` is *not* scored — that is an ordinary
/// fork, resolved by branch collection, not an attack.
pub const MISBEHAVIOR_INVALID_BLOCK: u32 = 50;
/// A peer is banned once its accumulated misbehavior reaches this.
pub const BAN_THRESHOLD: u32 = 100;
/// How long a banned peer stays banned.
pub const BAN_DURATION: Duration = Duration::from_secs(60 * 60);

/// How far past the fork point a single branch collection will pull.
///
/// A reorg is capped at [`MAX_REORG_DEPTH`], so a branch that reaches that far
/// beyond the point where we and the peer diverged already carries enough
/// cumulative difficulty to settle the question. Collecting further buys
/// nothing.
///
/// Before this existed the upper bound was the *peer's* tip, which is not a
/// bound at all when we are behind. A node at height 630 on the testnet opened
/// two collections of 4,418 and 4,415 blocks — the entire remaining chain,
/// twice, buffered in memory before a single block of it was applied, while the
/// blocks its sequential sync had asked for were discarded as out-of-order.
/// Sync ran roughly a hundred times slower than the same node with one peer,
/// and on a long chain the memory alone would end it.
pub const MAX_COLLECT_SPAN: u64 = 2 * MAX_REORG_DEPTH;

/// How recent a block must be before we relay it onward.
///
/// Relaying used to be decided by comparing our height against
/// `peer_best_height` — a number peers tell us and nothing verifies. It is
/// taken straight from `block.coinbase.height` before the block is validated,
/// and from `Tip` messages, and it only ever rises. So a single message
/// claiming an absurd height pinned it out of reach for good, and from then on
/// the node applied every block and gossiped none of them. One cheap message,
/// one node permanently removed from block propagation, nothing in the log.
///
/// A block's own timestamp is a local signal instead, and consensus already
/// bounds it at both ends: it must beat the median of recent blocks and may not
/// run more than `FUTURE_TIME_LIMIT` ahead. A peer cannot dress an old block up
/// as a current one. Blocks near the tip are relayed; the historical ones a
/// bulk sync walks through are not.
/// Transactions that may be buffered across all open branch collections at once.
///
/// Collected blocks are held unvalidated until the branch completes, so a block
/// count alone does not bound the memory: a single block message may carry up
/// to `MAX_MESSAGE_BYTES`. This puts a ceiling on the bytes instead, at roughly
/// a hundred megabytes of transactions across every peer combined.
pub const MAX_COLLECTED_TXS: usize = 50_000;

pub const RELAY_FRESHNESS: u64 = 30 * noct_core::pow::TARGET_BLOCK_TIME;

/// Seed nodes for the **testnet**.
///
/// Two nodes on deliberately separate uplinks, so one line failing does not take
/// bootstrapping down with it. Verified reachable from four continents.
///
/// Raw addresses are acceptable here because a testnet seed is expected to churn
/// and rebuilding is cheap. **Mainnet must use hostnames** — a baked-in IP cannot
/// be changed without reissuing every binary in the world, whereas a DNS record
/// can be repointed in seconds (entries are resolved at startup, so either form
/// works).
pub const TESTNET_SEEDS: &[&str] = &[
    "seed1.nocturnalcoin.com:19333",
    "seed2.nocturnalcoin.com:19333",
];

/// **Names, not literals, on purpose.** A hardcoded IP is frozen into every copy
/// of the software the moment it ships: move the machine, change ISP, or lose the
/// address, and the seed is dead for everyone still running that binary — and a
/// node that cannot reach a seed cannot join the network at all. A name is
/// repointed in DNS in seconds and every existing binary follows.
///
/// This does not hide the addresses; DNS resolves to them and that is public.
/// It decouples *where the infrastructure lives* from *what has been released*.
///
/// The records must be **DNS-only**, never proxied: this is raw TCP on 19333,
/// and an HTTP proxy in front of it would resolve to the proxy's addresses and
/// break peering entirely.
///
/// Seed nodes for **mainnet**. Deliberately empty: mainnet has not launched, and
/// a seed list pointing at machines that are not yet running the real chain would
/// be worse than none at all. Populate with **hostnames** before launch.
pub const MAINNET_SEEDS: &[&str] = &[];

/// The baked-in seeds a fresh node dials when no `--seed` is given, for the
/// network it is running on. `--no-default-seeds` opts out.
///
/// Per-network on purpose: a shared list would have testnet nodes dialling
/// mainnet seeds and vice versa. They would be rejected on the handshake — the
/// magic and genesis differ — but it would waste connections on both sides and
/// leak which nodes belong to whom.
pub fn default_seeds(network: noct_core::address::Network) -> &'static [&'static str] {
    match network {
        noct_core::address::Network::Mainnet => MAINNET_SEEDS,
        noct_core::address::Network::Testnet => TESTNET_SEEDS,
    }
}

/// Deprecated alias kept so existing callers compile; prefer [`default_seeds`].
pub const DEFAULT_SEEDS: &[&str] = &[
    // "seed1.noct.example:9333",
    // "203.0.113.10:9333",
];

/// Cap on each gossip-dedup set, bounding memory on a long-running node.
const SEEN_CAP: usize = 100_000;

/// A hash set that remembers only its most recent [`SEEN_CAP`] insertions,
/// evicting the oldest first (FIFO). Safe for gossip dedup: a re-seen *old* block
/// sits below our tip (handled without re-broadcast) and a re-seen old tx fails
/// validation, so evicting ancient ids never reopens a gossip loop — it only
/// caps memory that an unbounded `HashSet` would leak over a node's lifetime.
#[derive(Default)]
struct BoundedSet {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl BoundedSet {
    /// Insert `id`; returns `true` if it was newly added (mirrors `HashSet`).
    fn insert(&mut self, id: [u8; 32]) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > SEEN_CAP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    fn contains(&self, id: &[u8; 32]) -> bool {
        self.set.contains(id)
    }
}

/// Branch being downloaded from one peer to evaluate as a reorg candidate.
struct Collect {
    /// Next height to request.
    next: u64,
    /// Last height to request (inclusive).
    to: u64,
    blocks: Vec<(Block, Vec<Transaction>)>,
}

/// What the transport should do with a message after [`NodeState`] processed it.
#[derive(Clone, Debug)]
pub enum Relay {
    /// Nothing to forward (already seen, or invalid).
    Drop,
    /// Stem phase: forward to exactly one random peer.
    StemToOne(Wire),
    /// Fluff / block: flood to every peer.
    FloodToAll(Wire),
}

/// The transport's marching orders after [`NodeState::react`] handles a message
/// from a specific peer.
#[derive(Clone, Debug, Default)]
pub struct Reaction {
    /// Messages to send back to the peer we received from (replies / sync pulls).
    pub reply: Vec<Wire>,
    /// Messages to flood to all peers (newly-accepted blocks/transactions).
    pub broadcast: Vec<Wire>,
    /// Messages to stem-relay to one random peer.
    pub stem: Vec<Wire>,
    /// How badly the peer misbehaved with this message (invalid block/tx). The
    /// transport accumulates this per peer and bans one that crosses
    /// [`BAN_THRESHOLD`]. Normal disagreements (a fork's `BadPrevId`, a duplicate)
    /// score zero — only genuinely invalid data is penalised.
    pub misbehavior: u32,
}

/// All consensus state for one node. Guard with a `Mutex` when shared.
pub struct NodeState {
    pub chain: Blockchain<NodePow>,
    pub mempool: Mempool,
    pub miner_address: Address,
    pub fluff_probability: f64,
    pow: NodePow,
    seen_txs: BoundedSet,
    seen_blocks: BoundedSet,
    /// Transactions currently buffered across all open branch collections, so
    /// the memory they hold has a ceiling rather than just a block count.
    collected_txs: usize,
    /// Consecutive branch collections that never reached a common ancestor.
    ///
    /// A handful of these is ordinary. A steady stream means this node has
    /// diverged from the network by more than [`MAX_REORG_DEPTH`] and can no
    /// longer rejoin by reorganising — a permanent condition whose only other
    /// symptom is being slow.
    reorgs_without_ancestor: u32,
    /// Highest height any peer has advertised — the initial-block-download target.
    peer_best_height: u64,
    /// On-disk block log (writes happen off-thread); when present, every accepted
    /// block is queued for persistence.
    store: Option<AsyncStore>,
    /// Per-peer branch downloads in flight (fork resolution).
    sync: HashMap<usize, Collect>,
    /// Live-tunable mining state, shared with the miner threads and RPC.
    mining: Arc<MiningControl>,
}

impl NodeState {
    /// A fresh node mining to `miner_address`, on mainnet.
    pub fn new(miner_address: Address) -> Self {
        Self::for_network(noct_core::address::Network::Mainnet, miner_address)
    }

    /// A fresh node on a specific network.
    ///
    /// The network selects the genesis block and the p2p magic, which together
    /// make two networks unable to merge: a peer presenting the wrong magic is
    /// dropped before anything else is read, and one presenting the right magic
    /// but a foreign genesis is dropped on the handshake.
    pub fn for_network(network: noct_core::address::Network, miner_address: Address) -> Self {
        let pow = new_pow();
        NodeState {
            chain: Blockchain::for_network(network, pow.clone()),
            mempool: Mempool::new(),
            miner_address,
            fluff_probability: noct_core::p2p::FLUFF_PROBABILITY,
            pow,
            seen_txs: BoundedSet::default(),
            seen_blocks: BoundedSet::default(),
            reorgs_without_ancestor: 0,
            collected_txs: 0,
            peer_best_height: 0,
            store: None,
            sync: HashMap::new(),
            mining: MiningControl::new(false, 1),
        }
    }

    /// The shared mining control (start/stop, thread count, hashrate). The RPC
    /// layer and the miner threads hold `Arc` clones of the same instance.
    pub fn mining_control(&self) -> Arc<MiningControl> {
        Arc::clone(&self.mining)
    }

    /// Persist every future accepted block to `store`. Call *after* replaying an
    /// existing log, so replayed blocks are not written back.
    pub fn attach_store(&mut self, store: AsyncStore) {
        self.store = Some(store);
    }

    /// Replay previously-stored blocks into the chain on startup. Each is fully
    /// re-validated (the log is treated as untrusted). Stops at the first block
    /// that fails, keeping everything valid before it — the rest is re-fetched
    /// from peers by initial block download.
    pub fn replay<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        blocks: Vec<(Block, Vec<Transaction>)>,
    ) -> Result<u64, String> {
        for (block, txs) in blocks {
            match self.chain.add_block(rng, &block, &txs) {
                Ok(()) => {
                    self.mempool.on_block(&txs);
                    self.seen_blocks.insert(block.id());
                }
                Err(e) => {
                    return Err(format!(
                        "stored block {} failed validation ({e:?}); chain truncated to height {}",
                        block.coinbase.height,
                        self.chain.height()
                    ))
                }
            }
        }
        Ok(self.chain.height())
    }

    // Queue an accepted block for persistence (returns immediately; the write
    // happens on the store's background thread, off the consensus lock).
    fn persist(&mut self, block: &Block, txs: &[Transaction]) {
        if let Some(store) = &self.store {
            store.append(block, txs);
        }
    }

    // --- read-only views (for RPC) ---------------------------------------

    pub fn height(&self) -> u64 {
        self.chain.height()
    }
    pub fn num_outputs(&self) -> u64 {
        self.chain.num_outputs()
    }
    pub fn emitted(&self) -> u64 {
        self.chain.emitted()
    }
    pub fn cumulative_difficulty(&self) -> u128 {
        self.chain.cumulative_difficulty()
    }
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }
    pub fn tip_id(&self) -> [u8; 32] {
        self.chain.tip_id()
    }

    // --- message handling (no I/O) ---------------------------------------

    /// Submit a locally-created transaction: validate and enter the stem phase.
    ///
    /// `can_stem` must be false when there is no peer to relay to — otherwise a
    /// stem-phase transaction would be handed to a transport with nowhere to send
    /// it and would never reach any mempool.
    pub fn originate_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
        can_stem: bool,
    ) -> Relay {
        self.accept_tx(rng, tx, Phase::Stem, can_stem)
    }

    /// Handle an incoming gossip transaction. See [`Self::originate_tx`] for
    /// `can_stem`.
    pub fn handle_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
        phase: Phase,
        can_stem: bool,
    ) -> Relay {
        self.accept_tx(rng, tx, phase, can_stem)
    }

    fn accept_tx<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
        phase: Phase,
        can_stem: bool,
    ) -> Relay {
        self.accept_tx_scored(rng, tx, phase, can_stem).0
    }

    /// Like [`Self::accept_tx`] but also reports misbehavior points: an invalid
    /// transaction from a peer earns [`MISBEHAVIOR_INVALID_TX`]; a duplicate
    /// (already-seen) earns nothing.
    fn accept_tx_scored<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        tx: Transaction,
        phase: Phase,
        can_stem: bool,
    ) -> (Relay, u32) {
        if !self.seen_txs.insert(tx.hash()) {
            return (Relay::Drop, 0); // already processed → stops gossip loops
        }
        match self.chain.validate_tx(rng, &tx) {
            Ok(()) => {}
            // "We cannot tell yet" is not misbehaviour.
            //
            // Both of these are judged against *our* chain: a ring member we
            // have not synced yet is unknown to us, and coinbase maturity is
            // measured from our height. A node that is behind therefore rejects
            // transactions the rest of the network considers perfectly valid,
            // and at 20 points a time it bans the peers feeding it after five of
            // them — including its only seed. It then sits at zero peers,
            // stranded at the height it stopped, having done it to itself.
            //
            // Seen while syncing a fresh node against the live testnet: it
            // scored seed1, the load node and a third peer to exactly 100 each
            // and stalled at height 5350 with no peers left.
            //
            // This is the same reasoning the block path already applies to
            // `TimestampTooFarAhead`: a verdict that depends on our own state
            // says nothing about the sender. Rejection stays — the transaction
            // is dropped and never relayed — only the penalty goes. It is also
            // cheap to reject, being a hash lookup before any signature work.
            Err(ChainError::UnknownRingMember) | Err(ChainError::ImmatureCoinbase) => {
                return (Relay::Drop, 0);
            }
            // Anything else is bad regardless of where we are: a failed
            // signature or range proof, a double spend of an image we already
            // have on chain.
            Err(_) => return (Relay::Drop, MISBEHAVIOR_INVALID_TX),
        }
        // Stay in the stem only if we can actually relay it onward; with no peer
        // to stem to we must fluff now, or the transaction is silently lost.
        let stem = can_stem
            && matches!(phase, Phase::Stem)
            && (rng.next_u64() as f64 / u64::MAX as f64) >= self.fluff_probability;
        let relay = if stem {
            Relay::StemToOne(Wire::Tx(tx, Phase::Stem))
        } else {
            let _ = self.mempool.add(rng, &self.chain, tx.clone());
            Relay::FloodToAll(Wire::Tx(tx, Phase::Fluff))
        };
        (relay, 0)
    }

    /// Handle an incoming block (with its transactions).
    pub fn handle_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        block: Block,
        txs: Vec<Transaction>,
    ) -> Relay {
        if !self.seen_blocks.insert(block.id()) {
            return Relay::Drop;
        }
        if self.chain.add_block(rng, &block, &txs).is_err() {
            return Relay::Drop;
        }
        self.mempool.on_block(&txs);
        self.persist(&block, &txs);
        Relay::FloodToAll(Wire::Block(block, txs))
    }

    /// The initial-block-download target we're aware of.
    pub fn sync_target(&self) -> u64 {
        self.peer_best_height
    }

    /// Handle a message from a specific peer, returning what to send back to it,
    /// what to broadcast, and what to stem. This is the single entry point the
    /// TCP transport uses; it folds in gossip *and* initial block download.
    pub fn react<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        peer: usize,
        msg: Wire,
        can_stem: bool,
    ) -> Reaction {
        let mut out = Reaction::default();
        match msg {
            Wire::Tx(tx, phase) => {
                let (relay, score) = self.accept_tx_scored(rng, tx, phase, can_stem);
                out.misbehavior += score;
                match relay {
                    Relay::Drop => {}
                    Relay::StemToOne(w) => out.stem.push(w),
                    Relay::FloodToAll(w) => out.broadcast.push(w),
                }
            }
            Wire::Block(block, txs) => self.react_block(rng, peer, block, txs, &mut out),
            // A peer wants our tip so it can decide whether to sync from us.
            Wire::GetTip => out.reply.push(Wire::Tip(
                noct_core::p2p::NETWORK_ID,
                self.chain.height(),
                self.chain.tip_id(),
                self.chain.cumulative_difficulty(),
            )),
            // A peer told us its tip. Decide what to do about it.
            //
            // **On work, not length** (security review F29). Fork choice is
            // `would_reorg_to`, which compares cumulative difficulty; this used
            // to compare heights, so the network implemented "longest chain"
            // while consensus implemented "heaviest". A heavier but equal-or-
            // shorter chain was therefore invisible: nothing here fired, no
            // branch was ever collected, and the node could sit on a lighter
            // chain indefinitely while every peer disagreed with it.
            Wire::Tip(network, height, tip, their_work) => {
                // Never sync from another network. (Genesis would make its blocks
                // unattachable anyway; this rejects it up front.)
                if network != noct_core::p2p::NETWORK_ID {
                    return out;
                }
                self.peer_best_height = self.peer_best_height.max(height);

                // Same tip: we already agree, whatever the heights say.
                if tip == self.chain.tip_id() {
                    return out;
                }
                // Not heavier than ours: nothing to adopt. A peer that is merely
                // *longer* is deliberately ignored here.
                if !self.chain.would_reorg_to(their_work) {
                    return out;
                }

                if height > self.chain.height() {
                    // Heavier and taller: most often a plain catch-up, so pull
                    // sequentially — far cheaper than collecting a branch. If it
                    // turns out to be a fork, the first block will fail with
                    // `BadPrevId` and `react_block` escalates to collection.
                    out.reply.push(Wire::GetBlock(self.chain.height()));
                } else {
                    // Heavier but no taller ⇒ it must have diverged from us. The
                    // sequential path cannot express that, so go straight to
                    // collecting the branch and let `try_reorg` judge it. This is
                    // the case that was previously unreachable.
                    self.begin_branch_collection(peer, &mut out);
                }
            }
            // A peer wants a historical block; serve it if we have it.
            Wire::GetBlock(height) => match self.chain.block_at(height) {
                Some(stored) => out.reply.push(Wire::Block(stored.block.clone(), stored.txs.clone())),
                None => out.reply.push(Wire::NoBlock(height)),
            },
            Wire::NoBlock(_) => {}
            // Discovery messages are handled entirely by the transport layer and
            // never reach consensus; ignore them if one slips through.
            Wire::Version(..) | Wire::GetPeers | Wire::Peers(_) => {}
        }
        out
    }

    fn react_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        peer: usize,
        block: Block,
        txs: Vec<Transaction>,
        out: &mut Reaction,
    ) {
        // A valid block at index H means the sender has at least H+1 blocks.
        let block_height = block.coinbase.height;
        self.peer_best_height = self.peer_best_height.max(block_height.saturating_add(1));

        // If we're downloading a branch from this peer, this block is part of it.
        // (Deliberately before the seen-dedup: a branch re-sends blocks we know.)
        // A collection takes only the block it actually asked for. Anything else
        // from the same peer falls through to normal handling below.
        //
        // It used to swallow everything and discard whatever did not match,
        // which meant an open collection starved the sequential sync running
        // beside it: the node would request the block it needed next, the
        // collector would drop the reply because it wanted a different height,
        // and the chain would sit still. A testnet seed managed six blocks a
        // minute this way against a network the same build syncs at five
        // hundred.
        if self.sync.get(&peer).is_some_and(|c| c.next == block_height) {
            // These blocks are buffered before anything validates them, so the
            // buffer needs a ceiling of its own.
            if self.collected_txs.saturating_add(txs.len()) > MAX_COLLECTED_TXS {
                eprintln!(
                    "peer {peer}: abandoning branch collection — it would buffer more than                      {MAX_COLLECTED_TXS} unvalidated transactions"
                );
                self.forget_peer(peer);
                return;
            }
            self.collected_txs += txs.len();
            let collect = self.sync.get_mut(&peer).expect("just checked");
            collect.blocks.push((block, txs));
            collect.next += 1;
            if collect.next > collect.to {
                let done = self.sync.remove(&peer).expect("present");
                let freed: usize = done.blocks.iter().map(|(_, t)| t.len()).sum();
                self.collected_txs = self.collected_txs.saturating_sub(freed);
                self.finish_reorg(rng, done.blocks, out);
            } else {
                let next = collect.next;
                out.reply.push(Wire::GetBlock(next));
            }
            return;
        }

        // Skip only blocks we have already *applied* — do NOT mark unseen blocks
        // seen here. A future block glimpsed via gossip while we are still behind
        // must remain re-fetchable, or the sequential download that later reaches
        // its height would discard it as a duplicate and stall forever.
        if self.seen_blocks.contains(&block.id()) {
            return;
        }

        if block_height > self.chain.height() {
            // We're behind — pull the block we actually need next. (Not marked
            // seen: we will re-fetch and apply it in order.)
            out.reply.push(Wire::GetBlock(self.chain.height()));
            return;
        }
        if block_height < self.chain.height() {
            // A block at a height we already have. If it differs from ours, the
            // peer is on a competing branch worth evaluating.
            let ours = self.chain.block_at(block_height).map(|s| s.block.id());
            if ours != Some(block.id()) {
                // Remember this trigger so a replay of the same block cannot make
                // us re-download the whole branch again (bandwidth amplification).
                self.seen_blocks.insert(block.id());
                self.begin_branch_collection(peer, out);
            }
            return;
        }

        // Same height as our tip: try to extend.
        match self.chain.add_block(rng, &block, &txs) {
            Ok(()) => {
                self.seen_blocks.insert(block.id()); // mark seen only once applied
                self.mempool.on_block(&txs);
                self.persist(&block, &txs);
                // Two separate questions, and they used to share one answer.
                // Whether to relay is decided locally, by how recent the block
                // is. Whether to keep asking for more may still lean on the
                // peer's claim: an inflated one costs a wasted request, not our
                // place in the network.
                let fresh =
                    now_secs().saturating_sub(block.header.timestamp) <= RELAY_FRESHNESS;
                let behind = self.chain.height() < self.peer_best_height;
                if fresh {
                    out.broadcast.push(Wire::Block(block, txs));
                }
                if behind {
                    out.reply.push(Wire::GetBlock(self.chain.height()));
                }
            }
            // Right height but doesn't build on our tip: the peer forked from us.
            Err(ChainError::BadPrevId) => {
                self.seen_blocks.insert(block.id()); // dedup replay of this trigger
                self.begin_branch_collection(peer, out);
            }
            // Ahead of *our* clock, not invalid. This is the only validity rule
            // that depends on local time rather than the chain, so the node with
            // the slower clock rejects a block every other node accepts. Scoring
            // it would ban honest peers for being better synchronised — and the
            // block is deliberately not marked seen, so it is re-fetched and
            // applied once our clock catches up.
            Err(ChainError::TimestampTooFarAhead) => {}
            // Anything else means the block is simply invalid — penalise the peer.
            Err(e) => {
                // Say what earned the penalty. Two of these is a ban, and a ban
                // is invisible to the peer it lands on, so a wrong one here is
                // a partition that nobody can explain from either side.
                eprintln!("peer {peer}: block {block_height} rejected as invalid ({e:?}) — penalising");
                out.misbehavior += MISBEHAVIOR_INVALID_BLOCK
            }
        }
    }

    /// Release everything held on behalf of a peer whose session has ended.
    ///
    /// A branch collection buffers blocks in memory and was only ever removed
    /// when it *completed*. A peer that started one and then went away — by
    /// disconnecting, by being dropped, or simply by never sending the last
    /// block — left its buffer behind for the life of the process. Peer ids are
    /// per connection, so reconnecting started a fresh one, and nothing ever
    /// reclaimed the old.
    ///
    /// That is unbounded growth an attacker can drive deliberately (connect,
    /// trigger a collection, send all but the last block, disconnect, repeat)
    /// and that ordinary session churn causes by accident. This node has
    /// already been OOM-killed once in production.
    pub fn forget_peer(&mut self, peer: usize) {
        if let Some(abandoned) = self.sync.remove(&peer) {
            let txs: usize = abandoned.blocks.iter().map(|(_, t)| t.len()).sum();
            self.collected_txs = self.collected_txs.saturating_sub(txs);
            eprintln!(
                "peer {peer}: released {} buffered block(s) from an unfinished branch collection",
                abandoned.blocks.len()
            );
        }
    }

    /// Start pulling a peer's chain over a bounded window so it can be evaluated
    /// as a reorg candidate. Re-downloading from `MAX_REORG_DEPTH` behind our tip
    /// guarantees we reach a height where we and the peer still agree (if the
    /// fork is shallower than that), which is what [`Blockchain::try_reorg`]
    /// needs to attach the branch.
    fn begin_branch_collection(&mut self, peer: usize, out: &mut Reaction) {
        if self.sync.contains_key(&peer) {
            return; // already collecting from this peer
        }
        // Never below 1: genesis is shared by every honest peer and cannot be
        // replaced, so a fork can only ever start at height 1 or later.
        let from = self.chain.height().saturating_sub(MAX_REORG_DEPTH).max(1);
        // Bounded: enough to decide a reorg, never the whole gap. If the peer
        // really is far ahead, each collection attaches and the next one starts
        // from the new tip, so the chain still advances — in bounded steps.
        let to = self
            .peer_best_height
            .saturating_sub(1)
            .min(from.saturating_add(MAX_COLLECT_SPAN));
        if to < from {
            return;
        }
        // Say how much this is about to pull. `to` is the *peer's* tip, so for a
        // node that is far behind this is not a small reorg window — it is the
        // whole gap, buffered in memory before any of it is applied.
        eprintln!(
            "peer {peer}: collecting branch, heights {from}..={to} ({} blocks) while our chain is at {}",
            to.saturating_sub(from).saturating_add(1),
            self.chain.height()
        );
        self.sync.insert(peer, Collect { next: from, to, blocks: Vec::new() });
        out.reply.push(Wire::GetBlock(from));
    }

    /// A branch finished downloading: switch to it if it is heavier.
    fn finish_reorg<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        branch: Vec<(Block, Vec<Transaction>)>,
        out: &mut Reaction,
    ) {
        let reorg = match self.chain.try_reorg(rng, &branch) {
            Ok(r) => {
                self.reorgs_without_ancestor = 0;
                r
            }
            // Benign outcomes — keep our chain, do not penalise the peer:
            //  * NotHeavier: a valid but lighter competing fork.
            //  * BadPrevId: the fork is deeper than MAX_REORG_DEPTH (or a gap), so
            //    the collected window never reaches a common ancestor — an honest
            //    peer with a deep fork looks exactly like this.
            //  * EmptyBranch / CannotReplaceGenesis: degenerate, not attack-worthy.
            // The collected window never reached a height where we and the
            // peer agree. Once is ordinary — an honest peer with a deep fork
            // looks exactly like this. Over and over means we are the ones who
            // are lost, and no amount of waiting will fix it.
            Err(ChainError::BadPrevId) => {
                self.reorgs_without_ancestor += 1;
                if self.reorgs_without_ancestor == 8
                    || self.reorgs_without_ancestor % 100 == 0
                {
                    eprintln!(
                        "WARNING: {} branch collections in a row never reached a block this node                          agrees with. It has probably diverged from the network by more than                          MAX_REORG_DEPTH ({}) blocks and cannot rejoin by reorganising — it will                          keep extending its own dead fork. Resync from scratch to recover.",
                        self.reorgs_without_ancestor, MAX_REORG_DEPTH
                    );
                }
                return;
            }
            Err(ChainError::NotHeavier)
            | Err(ChainError::EmptyBranch)
            | Err(ChainError::CannotReplaceGenesis) => return,
            // Anything else means the peer had us download a branch containing an
            // actually-invalid block (bad PoW, bad coinbase, invalid tx, …) —
            // wasted bandwidth on junk. Penalise it.
            Err(e) => {
                eprintln!(
                    "collected branch rejected as invalid ({e:?}) — penalising the peer that served it"
                );
                out.misbehavior += MISBEHAVIOR_INVALID_BLOCK;
                return;
            }
        };

        // Transactions from discarded blocks are unconfirmed again; give them a
        // chance to be re-mined rather than vanishing.
        for stored in &reorg.discarded {
            for tx in &stored.txs {
                let _ = self.mempool.add(rng, &self.chain, tx.clone());
            }
        }
        // Transactions the new branch confirmed leave the pool.
        for (_, txs) in &branch {
            self.mempool.on_block(txs);
        }
        for (block, _) in &branch {
            self.seen_blocks.insert(block.id());
        }
        // Disk must follow the new canonical chain, not the abandoned one.
        self.rewrite_store();

        eprintln!(
            "reorg: dropped {} block(s), applied {} → height {}",
            reorg.discarded.len(),
            reorg.applied,
            self.chain.height()
        );

        // Tell peers about our new tip.
        if let Some(stored) = self.chain.block_at(self.chain.height().saturating_sub(1)) {
            out.broadcast.push(Wire::Block(stored.block.clone(), stored.txs.clone()));
        }
    }

    // Rebuild the on-disk log from the canonical chain (after a reorg). Queued to
    // the background writer, so it does not block consensus.
    fn rewrite_store(&mut self) {
        if let Some(store) = &self.store {
            // SKIP GENESIS. `Blockchain` keeps genesis as `blocks()[0]`, but a
            // replaying node already has it: `Blockchain::new` applies genesis
            // before a single stored block is read.
            //
            // Storing it meant replay called `add_block(genesis)` against a
            // chain whose tip already *was* genesis. Genesis's prev_id is all
            // zeros, which never matches that tip, so the very first stored
            // block failed BadPrevId and replay discarded **everything after
            // it** — the whole chain, on every start.
            //
            // The append path never wrote genesis, so a store built only by
            // appends replayed fine. That is why this stayed hidden: a node was
            // healthy until its first reorg triggered a rewrite, and poisoned
            // from then on. It cost this testnet thousands of blocks across
            // several restarts before the cause was found.
            let blocks: Vec<_> = self
                .chain
                .blocks()
                .iter()
                .skip(1)
                .map(|s| (s.block.clone(), s.txs.clone()))
                .collect();
            store.rewrite(blocks);
        }
    }

    /// Mine one block onto the tip (coinbase + up to [`MAX_BLOCK_TXS`] mempool
    /// transactions), append it, and return it for broadcast. `None` only if the
    /// freshly-mined block fails to validate (should not happen).
    ///
    /// This grinds the nonce **while holding the lock**, so it is only for tests
    /// and on-demand single mining at low difficulty. A continuously-mining node
    /// must use [`Self::build_block_template`] + off-lock grinding +
    /// [`Self::submit_mined_block`] (see [`run`]) so the nonce search does not
    /// block consensus / RPC.
    pub fn mine_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Option<(Block, Vec<Transaction>)> {
        let job = self.build_block_template(rng);
        self.pow.reseed(&job.seed);
        let mut block = job.block;
        block.mine(&self.pow, job.difficulty);
        self.submit_mined_block(rng, block, job.txs)
    }

    /// A clone of the node's PoW function, for grinding a block off the lock. The
    /// clone shares the underlying (RandomX) VM cache.
    pub fn pow(&self) -> NodePow {
        self.pow.clone()
    }

    /// Assemble an unmined block template on top of the current tip: coinbase,
    /// selected mempool transactions, a valid timestamp, the target difficulty,
    /// and the epoch seed. Fast — call it under the lock, then grind the returned
    /// block off the lock.
    pub fn build_block_template<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> MiningJob {
        let miner_address = self.miner_address;
        self.build_block_template_for(rng, &miner_address)
    }

    /// Like [`Self::build_block_template`], but the coinbase pays `miner_address`
    /// instead of the node's own. This is what the `/getblocktemplate` RPC uses
    /// so an **external** miner (or a pool) can mine to its own address against
    /// this node.
    pub fn build_block_template_for<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        miner_address: &Address,
    ) -> MiningJob {
        let txs = self.mempool.select(MAX_BLOCK_TXS);
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let subsidy = base_reward(self.chain.emitted());
        let reward = subsidy.saturating_add(fees);
        let coinbase = Coinbase::create(rng, self.chain.height(), miner_address, reward);
        let timestamp = now_secs().max(self.chain.median_time_past() + 1);
        let block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp,
                prev_id: self.chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: txs.iter().map(|t| t.hash()).collect(),
        };
        MiningJob {
            block,
            txs,
            difficulty: self.chain.next_difficulty(),
            seed: self.chain.seed_for_height(self.chain.height()),
        }
    }

    /// Attach a freshly-mined block, if it still builds on the current tip (the
    /// chain may have advanced while we were grinding — then it's stale). Returns
    /// it for broadcast on success.
    pub fn submit_mined_block<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        block: Block,
        txs: Vec<Transaction>,
    ) -> Option<(Block, Vec<Transaction>)> {
        if block.header.prev_id != self.chain.tip_id() {
            return None; // a competing block extended the chain first — discard
        }
        self.chain.add_block(rng, &block, &txs).ok()?;
        self.mempool.on_block(&txs);
        self.seen_blocks.insert(block.id());
        self.persist(&block, &txs);
        Some((block, txs))
    }
}

/// An unmined block plus the parameters needed to mine it off the consensus lock.
pub struct MiningJob {
    pub block: Block,
    pub txs: Vec<Transaction>,
    pub difficulty: noct_core::pow::Difficulty,
    pub seed: [u8; 32],
}

/// Wall-clock seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    /// A peer that starts a branch collection and leaves must not keep its
    /// buffered blocks alive. Peer ids are per connection, so without this a
    /// reconnecting peer starts a fresh collection and nothing reclaims the old
    /// one — unbounded growth, drivable on purpose and reached by accident
    /// through ordinary session churn.
    #[test]
    fn an_abandoned_branch_collection_is_released_when_the_peer_goes() {
        let mut w = wallet();
        let mut node = test_node(w.address());
        mine_n(&mut node, &mut w, 3);
        node.peer_best_height = 10_000;

        node.begin_branch_collection(42, &mut Reaction::default());
        assert!(node.sync.contains_key(&42), "collection should be open");

        node.forget_peer(42); // as the transport now does when a session ends

        assert!(
            !node.sync.contains_key(&42),
            "an unfinished collection must not outlive the peer's session"
        );
    }

    /// Forgetting a peer we hold nothing for must be harmless — every session
    /// end calls it, including the many that never collect anything.
    #[test]
    fn forgetting_an_unknown_peer_is_harmless() {
        let mut w = wallet();
        let mut node = test_node(w.address());
        node.forget_peer(9999);
        assert!(node.sync.is_empty());
    }

    /// A peer must not be able to silence our block relay by claiming a height.
    ///
    /// `peer_best_height` is taken from unvalidated blocks and from `Tip`
    /// messages, and only ever rises. One message claiming an absurd height
    /// used to stop the node relaying anything, permanently.
    #[test]
    fn a_bogus_claimed_height_cannot_stop_us_relaying() {
        let mut w = wallet();
        let mut a = test_node(w.address());
        mine_n(&mut a, &mut w, 3);

        let mut b = test_node(w.address());
        // A peer claims to be astronomically far ahead.
        b.peer_best_height = 10_000_000;

        let s = a.chain.block_at(b.chain.height()).expect("next block");
        let (blk, txs) = (s.block.clone(), s.txs.clone());
        let out = b.react(&mut OsRng, 0, Wire::Block(blk, txs), false);

        assert!(
            out.broadcast.iter().any(|m| matches!(m, Wire::Block(..))),
            "a fresh block we applied must still be relayed, whatever a peer claims"
        );
    }

    /// The other half: bulk-sync blocks are old, and must not be re-gossiped.
    #[test]
    fn historical_blocks_are_not_relayed_during_a_bulk_sync() {
        let mut w = wallet();
        let mut a = test_node(w.address());
        mine_n(&mut a, &mut w, 3);

        let mut b = test_node(w.address());
        let s = a.chain.block_at(b.chain.height()).expect("next block");
        let (mut blk, txs) = (s.block.clone(), s.txs.clone());
        // Backdate it well beyond the relay window. It will not apply, which is
        // fine: what matters is that nothing is queued for broadcast.
        blk.header.timestamp = blk.header.timestamp.saturating_sub(RELAY_FRESHNESS * 10);

        let out = b.react(&mut OsRng, 0, Wire::Block(blk, txs), false);
        assert!(
            !out.broadcast.iter().any(|m| matches!(m, Wire::Block(..))),
            "a stale block must not be gossiped onward"
        );
    }

    /// An open branch collection must not starve the sequential sync beside it.
    ///
    /// The collector used to take every block from its peer and discard
    /// anything it had not asked for, including the block sequential sync had
    /// just requested — so a node with a far-ahead peer barely advanced.
    #[test]
    fn an_open_collection_does_not_starve_sequential_sync() {
        let mut w = wallet();
        let mut a = test_node(w.address());
        mine_n(&mut a, &mut w, 6);

        // A second node holding only the first few of those blocks.
        let mut b = test_node(w.address());
        for h in 1..4u64 {
            let s = a.chain.block_at(h).expect("mined block");
            let (blk, txs) = (s.block.clone(), s.txs.clone());
            b.react(&mut OsRng, 0, Wire::Block(blk, txs), false);
        }
        let before = b.chain.height();

        // Open a collection on that same peer, waiting for a different height.
        b.peer_best_height = 100;
        b.begin_branch_collection(0, &mut Reaction::default());
        let wanted = b.sync.get(&0).expect("collection should be open").next;
        assert_ne!(wanted, before, "test needs the collector to want another height");

        // Now deliver exactly the block sequential sync needs next.
        let s = a.chain.block_at(before).expect("next block");
        let (blk, txs) = (s.block.clone(), s.txs.clone());
        b.react(&mut OsRng, 0, Wire::Block(blk, txs), false);

        assert!(
            b.chain.height() > before,
            "a block extending our tip must still be applied while a collection is open"
        );
    }

    /// A node far behind must not treat the whole gap as a reorg candidate.
    ///
    /// The upper bound used to be the peer's tip, so a node at height 630 with
    /// a peer at 4948 opened a 4,418-block collection — buffered in memory,
    /// applied only at the end, and discarding its sequential-sync replies the
    /// whole time.
    #[test]
    fn a_branch_collection_is_bounded_however_far_ahead_the_peer_is() {
        let mut w = wallet();
        let mut node = test_node(w.address());
        mine_n(&mut node, &mut w, 200);
        node.peer_best_height = 500_000; // a peer claiming to be far ahead

        let mut out = Reaction::default();
        node.begin_branch_collection(7, &mut out);

        let collect = node.sync.get(&7).expect("a collection should have started");
        let span = collect.to.saturating_sub(collect.next).saturating_add(1);
        assert!(
            span <= MAX_COLLECT_SPAN + 1,
            "collection spans {span} blocks; it must be bounded by MAX_COLLECT_SPAN ({MAX_COLLECT_SPAN})"
        );
    }
    use super::*;
    use noct_core::address::Network;
    use noct_core::p2p::Wire;
    use noct_wallet::{Wallet, DEFAULT_RING_SIZE};
    use rand_core::OsRng;

    pub(super) fn wallet() -> Wallet {
        // Scan genesis, as production `sync` does, so the wallet's global-index
        // counter includes the premine (output 0) and stays aligned with the
        // node's chain.
        let mut w = Wallet::random(&mut OsRng, Network::Mainnet);
        w.scan_block(&noct_core::block::Block::genesis(), &[]);
        w
    }

    // A node whose chain uses a shallow coinbase maturity, so tests can spend
    // freshly-mined coins without mining a full maturity window (production uses
    // `COINBASE_MATURITY`).
    pub(super) fn test_node(miner_address: noct_core::address::Address) -> NodeState {
        let mut node = NodeState::new(miner_address);
        node.chain = noct_core::chain::Blockchain::with_maturity(node.pow.clone(), 1);
        node
    }

    // Mine `n` blocks on `node`, scanning each into `w` to keep indices synced.
    pub(super) fn mine_n(node: &mut NodeState, w: &mut Wallet, n: usize) {
        for _ in 0..n {
            let (block, txs) = node.mine_block(&mut OsRng).unwrap();
            w.scan_block(&block, &txs);
        }
    }

    #[test]
    /// A node that is behind must not punish peers for relaying transactions it
    /// cannot validate yet.
    ///
    /// The ring members are real; this node simply has not synced the blocks
    /// carrying them. At 20 points a time it banned the peers feeding it after
    /// five such transactions — its only seed included — and stranded itself at
    /// zero peers. Observed against the live testnet at height 5350.
    #[test]
    fn a_syncing_node_does_not_score_transactions_it_cannot_validate_yet() {
        // A node that has the whole chain, and a transaction built on it.
        let miner = wallet();
        let mut ahead = test_node(miner.address());
        let mut miner_view = miner;
        mine_n(&mut ahead, &mut miner_view, 16);

        let bob = wallet();
        let spendable = miner_view.unspent().next().cloned().unwrap();
        let fee = noct_core::emission::ATOMIC_UNITS / 100;
        let payments =
            [noct_core::tx::Payment { destination: bob.address(), amount: spendable.amount() - fee }];
        let tx = miner_view
            .build_transaction(&mut OsRng, &ahead.chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();

        // A node still near genesis: the ring members do not exist for it yet.
        let mut behind = test_node(bob.address());
        assert!(
            behind.chain.validate_tx(&mut OsRng, &tx).is_err(),
            "test needs this node to be unable to validate the transaction"
        );

        let r = behind.react(&mut OsRng, 0, Wire::Tx(tx, Phase::Fluff), false);
        assert_eq!(
            r.misbehavior, 0,
            "a peer must not be scored for a transaction we are merely too far behind to check"
        );
    }

    #[test]
    fn invalid_tx_scores_misbehavior_but_duplicates_do_not() {
        let miner = wallet();
        let mut node = test_node(miner.address());
        let mut miner_view = miner;
        mine_n(&mut node, &mut miner_view, 16);

        let bob = wallet();
        let spendable = miner_view.unspent().next().cloned().unwrap();
        let fee = noct_core::emission::ATOMIC_UNITS / 100;
        let payments =
            [noct_core::tx::Payment { destination: bob.address(), amount: spendable.amount() - fee }];
        let good = miner_view
            .build_transaction(&mut OsRng, &node.chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();

        // A valid gossip tx: no misbehavior.
        let r = node.react(&mut OsRng, 0, Wire::Tx(good.clone(), Phase::Fluff), false);
        assert_eq!(r.misbehavior, 0);
        // Re-sending the same tx is a harmless duplicate, not misbehavior.
        let r = node.react(&mut OsRng, 0, Wire::Tx(good.clone(), Phase::Fluff), false);
        assert_eq!(r.misbehavior, 0);

        // A corrupted tx (broken signature binding) scores the invalid-tx penalty.
        let mut bad = good;
        bad.fee = bad.fee.wrapping_add(1);
        let r = node.react(&mut OsRng, 0, Wire::Tx(bad, Phase::Fluff), false);
        assert_eq!(r.misbehavior, MISBEHAVIOR_INVALID_TX);
    }

    #[test]
    fn an_unreadable_block_log_does_not_stop_the_node_and_is_kept() {
        // A block-format change makes previously-stored blocks undecodable. That
        // must not brick a node on upgrade: it should start from genesis and
        // re-sync, and must not destroy the old file.
        let dir = std::env::temp_dir().join("noct_unreadable_log_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.dat");
        // A well-formed frame header whose payload cannot be decoded as a block.
        let mut bytes = 64u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xABu8; 64]);
        std::fs::write(&path, &bytes).unwrap();

        assert!(BlockStore::load_all(&path).is_err(), "fixture: the log must be unreadable");

        // The recovery `run` performs, in isolation from sockets.
        let stored = match BlockStore::load_all(&path) {
            Ok(blocks) => blocks,
            Err(_) => {
                let aside = path.with_extension("dat.unreadable");
                std::fs::rename(&path, &aside).unwrap();
                Vec::new()
            }
        };
        assert!(stored.is_empty(), "an unreadable log yields no blocks rather than an error");
        assert!(!path.exists(), "the bad log is moved out of the way");
        assert!(
            dir.join("blocks.dat.unreadable").exists(),
            "the user's old data is preserved, not deleted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn external_miner_can_mine_via_template_to_its_own_address() {
        // The node mines to its own address by default, but an external miner
        // fetches a template paying *its* address, grinds it, and submits it.
        let mut node = test_node(wallet().address());
        let mut ext = wallet();

        let mut job = node.build_block_template_for(&mut OsRng, &ext.address());
        // Grind the nonce with a PoW keyed to the template's seed (Keccak in
        // tests — trivial). This is exactly what an external miner does.
        let pow = node.pow();
        pow.reseed(&job.seed);
        job.block.mine(&pow, job.difficulty);

        // The node re-validates and accepts the externally-solved block.
        let accepted = node.submit_mined_block(&mut OsRng, job.block.clone(), job.txs.clone());
        assert!(accepted.is_some(), "node accepts the externally-solved block");
        assert_eq!(node.height(), 2);

        // The coinbase reward went to the external miner (block 1's subsidy),
        // not the node's own address.
        ext.scan_block(&job.block, &job.txs);
        assert_eq!(
            ext.balance(),
            noct_core::emission::base_reward(noct_core::block::PREMINE_AMOUNT)
        );
    }

    #[test]
    fn bounded_set_caps_memory_and_evicts_oldest() {
        let mut s = BoundedSet::default();
        let id = |i: u64| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            b
        };
        for i in 0..(SEEN_CAP as u64 + 5) {
            assert!(s.insert(id(i)));
        }
        assert!(s.set.len() <= SEEN_CAP, "size stays bounded");
        assert!(!s.contains(&id(0)), "oldest ids were evicted");
        assert!(s.contains(&id(SEEN_CAP as u64 + 4)), "recent ids retained");
        assert!(!s.insert(id(SEEN_CAP as u64 + 4)), "a present id is a duplicate");
    }

    #[test]
    fn finish_reorg_scores_invalid_branch_but_not_a_deep_fork() {
        use noct_core::block::{Block, BlockHeader, Coinbase};
        use noct_core::emission::base_reward;

        let miner = wallet();
        let mut node = test_node(miner.address());
        let mut mv = miner;
        mine_n(&mut node, &mut mv, 5); // height 6

        // (a) An INVALID branch: one block over-claiming its coinbase reward.
        let over = base_reward(node.chain.emitted()) + 1_000;
        let invalid = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: now_secs() + 100,
                prev_id: node.tip_id(),
                nonce: 0,
            },
            coinbase: Coinbase::create(&mut OsRng, node.height(), &mv.address(), over),
            tx_hashes: vec![],
        };
        let mut out = Reaction::default();
        node.finish_reorg(&mut OsRng, vec![(invalid, vec![])], &mut out);
        assert_eq!(out.misbehavior, MISBEHAVIOR_INVALID_BLOCK, "invalid branch is scored");
        assert_eq!(node.height(), 6, "chain unchanged");

        // (b) A branch forking above our height (deep fork / gap → BadPrevId) is a
        // benign outcome and must NOT be penalised.
        let future = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: now_secs() + 100,
                prev_id: [3u8; 32],
                nonce: 0,
            },
            coinbase: Coinbase::create(&mut OsRng, node.height() + 50, &mv.address(), 1),
            tx_hashes: vec![],
        };
        let mut out2 = Reaction::default();
        node.finish_reorg(&mut OsRng, vec![(future, vec![])], &mut out2);
        assert_eq!(out2.misbehavior, 0, "an honest deep fork must not be penalised");
    }

    #[test]
    fn fork_trigger_block_is_marked_seen_to_stop_replay() {
        use noct_core::block::{Block, BlockHeader, Coinbase};

        let miner = wallet();
        let mut node = test_node(miner.address());
        let mut mv = miner;
        mine_n(&mut node, &mut mv, 5); // height 6

        // A different block at a height we already hold (2) is a fork trigger.
        let fork = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: now_secs() + 7,
                prev_id: [9u8; 32],
                nonce: 12_345,
            },
            coinbase: Coinbase::create(&mut OsRng, 2, &mv.address(), 1),
            tx_hashes: vec![],
        };
        assert!(!node.seen_blocks.contains(&fork.id()));
        let mut out = Reaction::default();
        node.react_block(&mut OsRng, 0, fork.clone(), vec![], &mut out);
        // The trigger is remembered, so a replay of the same block is deduped
        // instead of re-collecting the whole branch again.
        assert!(node.seen_blocks.contains(&fork.id()));
    }

    #[test]
    fn mines_and_grows_the_chain() {
        let miner = wallet();
        let mut node = test_node(miner.address());
        // A new node already holds genesis (block 0), so height starts at 1.
        assert_eq!(node.height(), 1);
        let (b0, t0) = node.mine_block(&mut OsRng).unwrap();
        assert_eq!(node.height(), 2);
        assert!(t0.is_empty());
        // Genesis premined the founder allocation, so block 1's subsidy
        // continues the emission curve from that baseline.
        assert_eq!(b0.coinbase.height, 1);
        assert_eq!(b0.coinbase.total(), Some(base_reward(noct_core::block::PREMINE_AMOUNT)));
    }

    #[test]
    fn end_to_end_submit_mine_and_relay_action() {
        // A miner node mines a coinbase + decoys, a wallet builds a spend, the
        // node accepts it into the mempool, mines it in, and a peer accepts the
        // resulting block. fluff_probability = 1 makes submission deterministic.
        let miner = wallet();
        let mut node = test_node(miner.address());
        node.fluff_probability = 1.0;
        let mut miner_view = miner; // wallet tracking the node's chain
        mine_n(&mut node, &mut miner_view, 16); // coinbase at height 0 + decoys

        let bob = wallet();
        let spendable = miner_view.unspent().next().cloned().unwrap();
        let fee = noct_core::emission::ATOMIC_UNITS / 100;
        let payments = [noct_core::tx::Payment {
            destination: bob.address(),
            amount: spendable.amount() - fee,
        }];
        let tx = miner_view
            .build_transaction(&mut OsRng, &node.chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();

        // Submit → fluff → enters the node's mempool.
        assert!(matches!(node.originate_tx(&mut OsRng, tx.clone(), false), Relay::FloodToAll(_)));
        assert_eq!(node.mempool_len(), 1);

        // A peer with the same chain accepts it into its mempool too.
        let mut node2 = test_node(bob.address());
        node2.chain = node.chain.clone();
        assert!(matches!(
            node2.handle_tx(&mut OsRng, tx.clone(), Phase::Fluff, false),
            Relay::FloodToAll(_)
        ));
        assert_eq!(node2.mempool_len(), 1);

        // Node mines a block including the tx; the peer accepts it and evicts.
        let (block, txs) = node.mine_block(&mut OsRng).unwrap();
        assert!(txs.iter().any(|t| t.hash() == tx.hash()), "block should include the tx");
        assert!(matches!(node2.handle_block(&mut OsRng, block, txs), Relay::FloodToAll(_)));
        assert_eq!(node2.height(), node.height());
        assert_eq!(node2.mempool_len(), 0, "mined tx evicted from peer mempool");
    }

    #[test]
    fn rejects_invalid_and_duplicate_txs() {
        let miner = wallet();
        let mut node = test_node(miner.address());
        // Craft an invalid tx by corrupting a real one.
        let mut miner_view = miner;
        mine_n(&mut node, &mut miner_view, 16);
        let bob = wallet();
        let spendable = miner_view.unspent().next().cloned().unwrap();
        let fee = noct_core::emission::ATOMIC_UNITS / 100;
        let payments = [noct_core::tx::Payment { destination: bob.address(), amount: spendable.amount() - fee }];
        let mut tx = miner_view
            .build_transaction(&mut OsRng, &node.chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();
        tx.fee = tx.fee.wrapping_add(1); // break signature binding
        assert!(matches!(node.originate_tx(&mut OsRng, tx.clone(), false), Relay::Drop));

        // A valid tx accepted once is dropped on a second sight (dedup).
        tx.fee = tx.fee.wrapping_sub(1); // restore
        let first = node.originate_tx(&mut OsRng, tx.clone(), false);
        assert!(!matches!(first, Relay::Drop));
        assert!(matches!(node.originate_tx(&mut OsRng, tx, false), Relay::Drop));
    }

    /// Initial block download: a node that joins late catches up entirely from a
    /// peer's tip via the GetTip/Tip/GetBlock/Block message flow. This is the
    /// scenario that was impossible before (a fresh node rejected every block
    /// that didn't build on its genesis tip).
    #[test]
    fn initial_block_download_catches_up_a_late_node() {
        // Node A is ahead; node B starts empty.
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 6);
        assert_eq!(a.height(), 7); // genesis + 6

        let mut b = test_node(wallet().address());
        assert_eq!(b.height(), 1); // genesis only

        // Drive the message exchange to quiescence. B opens by asking for A's tip.
        let mut to_a = vec![Wire::GetTip];
        let mut to_b: Vec<Wire> = Vec::new();
        for _ in 0..10_000 {
            let mut next_to_b = Vec::new();
            for m in to_a.drain(..) {
                next_to_b.extend(a.react(&mut OsRng, 0, m, false).reply);
            }
            let mut next_to_a = Vec::new();
            for m in to_b.drain(..) {
                next_to_a.extend(b.react(&mut OsRng, 0, m, false).reply);
            }
            to_b.extend(next_to_b);
            to_a.extend(next_to_a);
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
        }

        // B fully synced to A's chain.
        assert_eq!(b.height(), a.height());
        assert_eq!(b.tip_id(), a.tip_id());
        assert_eq!(b.chain.cumulative_difficulty(), a.chain.cumulative_difficulty());
    }

    /// A node's chain survives a restart: blocks are appended to the log as they
    /// are accepted, and replaying that log rebuilds the identical chain.
    #[test]
    fn chain_is_restored_from_the_block_log() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("noct-restart-{nanos}.dat"));

        // First run: mine 5 blocks with a store attached.
        let miner = wallet();
        let (height, tip, cum) = {
            let mut node = test_node(miner.address());
            node.attach_store(store::AsyncStore::open(&path).unwrap());
            let mut view = wallet();
            mine_n(&mut node, &mut view, 5);
            (node.height(), node.tip_id(), node.chain.cumulative_difficulty())
        };
        assert_eq!(height, 6); // genesis + 5 mined

        // Second run: a fresh node replays the log.
        let mut restored = test_node(miner.address());
        let stored = store::BlockStore::load_all(&path).unwrap();
        assert_eq!(stored.len(), 5);
        let restored_height = restored.replay(&mut OsRng, stored).unwrap();

        assert_eq!(restored_height, height);
        assert_eq!(restored.tip_id(), tip);
        assert_eq!(restored.chain.cumulative_difficulty(), cum);
        // And it can keep building on the restored chain.
        assert!(restored.mine_block(&mut OsRng).is_some());
        assert_eq!(restored.height(), 7);

        let _ = std::fs::remove_file(&path);
    }

    // Drive messages between two nodes until nothing more is in flight.
    fn converse(a: &mut NodeState, b: &mut NodeState, opening: Vec<Wire>) {
        let mut to_a = opening;
        let mut to_b: Vec<Wire> = Vec::new();
        for _ in 0..10_000 {
            let mut next_to_b = Vec::new();
            for m in to_a.drain(..) {
                next_to_b.extend(a.react(&mut OsRng, 0, m, false).reply);
            }
            let mut next_to_a = Vec::new();
            for m in to_b.drain(..) {
                next_to_a.extend(b.react(&mut OsRng, 0, m, false).reply);
            }
            to_b.extend(next_to_b);
            to_a.extend(next_to_a);
            if to_a.is_empty() && to_b.is_empty() {
                return;
            }
        }
        panic!("conversation did not settle");
    }

    /// Two nodes partition, mine competing branches, then reconnect: the node on
    /// the lighter branch must discover the fork, download the competitor, and
    /// reorganise onto it. Previously the two chains would have diverged forever.
    #[test]
    fn diverged_nodes_reorg_onto_the_heavier_branch() {
        // Shared history: 3 blocks, then both nodes hold the same chain.
        let miner = wallet();
        let mut a = test_node(miner.address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 3);

        let mut b = test_node(wallet().address());
        b.chain = a.chain.clone();
        let common_tip = a.tip_id();
        assert_eq!(b.tip_id(), common_tip);

        // Partition: each mines its own blocks. A gets 1, B gets 3 (heavier).
        let mut throwaway = wallet();
        mine_n(&mut a, &mut throwaway, 1);
        mine_n(&mut b, &mut throwaway, 3);
        assert_eq!(a.height(), 5); // genesis + 3 shared + 1
        assert_eq!(b.height(), 7); // genesis + 3 shared + 3
        assert_ne!(a.tip_id(), b.tip_id(), "the nodes really did diverge");
        let heavier_tip = b.tip_id();
        let heavier_work = b.chain.cumulative_difficulty();

        // Reconnect: A asks B for its tip. A must end up on B's branch.
        converse(&mut b, &mut a, vec![Wire::GetTip]);

        assert_eq!(a.height(), 7, "A should have adopted the longer branch");
        assert_eq!(a.tip_id(), heavier_tip, "A should be on B's tip");
        assert_eq!(a.chain.cumulative_difficulty(), heavier_work);
    }

    /// The mirror case: the node that is already on the heavier branch must not
    /// be talked into abandoning it.
    #[test]
    fn node_on_heavier_branch_does_not_reorg() {
        let miner = wallet();
        let mut a = test_node(miner.address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 3);

        let mut b = test_node(wallet().address());
        b.chain = a.chain.clone();

        let mut throwaway = wallet();
        mine_n(&mut a, &mut throwaway, 3); // A heavier
        mine_n(&mut b, &mut throwaway, 1); // B lighter
        let a_tip = a.tip_id();
        let a_work = a.chain.cumulative_difficulty();

        // B (lighter) opens the conversation; A must keep its own chain.
        converse(&mut b, &mut a, vec![Wire::GetTip]);

        assert_eq!(a.height(), 7);
        assert_eq!(a.tip_id(), a_tip, "A must not abandon the heavier chain");
        assert_eq!(a.chain.cumulative_difficulty(), a_work);
    }


    /// **F29 — the case that was previously unreachable.**
    ///
    /// A peer whose chain carries **more work but is no longer** than ours. Fork
    /// choice is `would_reorg_to`, which compares cumulative difficulty, but the
    /// tip advertisement only carried *height* and the handler only acted on
    /// `height > ours`. So such a peer said nothing the node could act on: no
    /// branch was collected, `try_reorg` was never called, and the node stayed on
    /// the lighter chain while every peer disagreed with it — the network
    /// implementing "longest chain" while consensus implemented "heaviest".
    ///
    /// This asserts the **decision**, not the eventual adoption: that the node
    /// responds at all is the entire fix. What happens to the collected branch
    /// afterwards is `try_reorg`, covered by its own tests. Deliberately no
    /// "skip if we could not build the scenario" escape hatch — an equal-height
    /// heavier chain is awkward to mine on demand, and a test that quietly
    /// declines to run is worse than no test.
    #[test]
    fn a_heavier_tip_at_equal_height_starts_a_branch_download() {
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 3);

        let our_height = a.height();
        let our_work = a.chain.cumulative_difficulty();

        // Same height, different tip, strictly more work — a fork that won a
        // burst of hashrate. Under the old height-only rule this produced
        // nothing whatsoever.
        let reaction = a.react(
            &mut OsRng,
            0,
            Wire::Tip(noct_core::p2p::NETWORK_ID, our_height, [42u8; 32], our_work + 1),
            false,
        );

        assert!(
            reaction.reply.iter().any(|m| matches!(m, Wire::GetBlock(_))),
            "a heavier tip at equal height must start a branch download; got {:?}",
            reaction.reply
        );
    }

    /// A peer that is merely **longer** but carries no more work must not move
    /// us. This is the other half of the same rule, and getting it wrong is how a
    /// cheap high-block-count chain steals the network.
    #[test]
    fn a_longer_but_lighter_tip_is_ignored() {
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 3);

        let our_tip = a.tip_id();
        let our_work = a.chain.cumulative_difficulty();

        // Claim a much greater height while advertising *less* work than we hold.
        let reaction = a.react(
            &mut OsRng,
            0,
            Wire::Tip(noct_core::p2p::NETWORK_ID, a.height() + 500, [9u8; 32], our_work - 1),
            false,
        );

        assert!(
            reaction.reply.is_empty(),
            "a lighter chain must not trigger a download, however long it claims to be"
        );
        assert_eq!(a.tip_id(), our_tip, "and we must stay exactly where we were");
    }

    /// A peer advertising the tip we already hold is agreement, not a fork —
    /// it must cost nothing, whatever it claims about height.
    #[test]
    fn an_identical_tip_costs_nothing() {
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 2);

        let reaction = a.react(
            &mut OsRng,
            0,
            Wire::Tip(
                noct_core::p2p::NETWORK_ID,
                a.height() + 99,               // nonsense height
                a.tip_id(),                    // but the same tip
                a.chain.cumulative_difficulty() + 1_000_000, // and inflated work
            ),
            false,
        );
        assert!(reaction.reply.is_empty(), "agreeing peers must not start a sync");
    }

    /// A foreign network's tip is refused before any of the above is considered.
    #[test]
    fn a_foreign_networks_tip_is_refused() {
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 2);

        let reaction = a.react(
            &mut OsRng,
            0,
            Wire::Tip(0xDEADBEEF, 9_999, [7u8; 32], u128::MAX),
            false,
        );
        assert!(reaction.reply.is_empty(), "a foreign network must never start a sync");
    }


    /// A block ahead of our clock must **not** score the peer that sent it.
    ///
    /// This is the only validity rule that depends on local wall-clock time
    /// rather than on the chain, so the node with the *slower* clock rejects a
    /// block every correctly-synchronised node accepts. Scoring that as an
    /// invalid block costs `MISBEHAVIOR_INVALID_BLOCK` (50) a time — so **two
    /// such blocks reach `BAN_THRESHOLD` (100) and we ban an honest peer for
    /// having the better clock**, then lose the chain it was feeding us.
    ///
    /// The block is also deliberately left un-seen, so it is re-fetched and
    /// applied normally once our clock catches up.
    #[test]
    fn a_block_ahead_of_our_clock_does_not_score_the_peer() {
        let miner = wallet();
        let mut node = test_node(miner.address());
        let mut view = miner;
        mine_n(&mut node, &mut view, 2);

        // Built on a *peer* sharing our chain, so it arrives as a candidate for
        // our own tip height rather than as a competing branch. Mining it here
        // would apply it to our chain first and change what the test exercises.
        let mut peer_node = test_node(wallet().address());
        peer_node.chain = node.chain.clone();
        let (mut block, txs) = peer_node.mine_block(&mut OsRng).unwrap();

        // A day ahead: valid in every respect except our local clock.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.timestamp = now + 24 * 60 * 60;

        let before = node.height();
        let reaction = node.react(&mut OsRng, 0, Wire::Block(block.clone(), txs), false);

        assert_eq!(reaction.misbehavior, 0, "a peer must not be scored for our slow clock");
        assert!(reaction.misbehavior < BAN_THRESHOLD);
        assert_eq!(node.height(), before, "and the block is of course not applied yet");
        assert!(
            !node.seen_blocks.contains(&block.id()),
            "it must stay re-fetchable, or we never get it once the clock catches up"
        );
    }

    /// A peer serves a requested historical block, and reports NoBlock for a
    /// height it doesn't have.
    #[test]
    fn serves_blocks_and_reports_missing() {
        let mut a = test_node(wallet().address());
        let mut a_view = wallet();
        mine_n(&mut a, &mut a_view, 3);

        match a.react(&mut OsRng, 0, Wire::GetBlock(1), false).reply.as_slice() {
            [Wire::Block(block, _)] => assert_eq!(block.coinbase.height, 1),
            other => panic!("expected block 1, got {other:?}"),
        }
        match a.react(&mut OsRng, 0, Wire::GetBlock(99), false).reply.as_slice() {
            [Wire::NoBlock(99)] => {}
            other => panic!("expected NoBlock(99), got {other:?}"),
        }
        // Genesis is block 0, so three mined blocks put us at height 4.
        match a.react(&mut OsRng, 0, Wire::GetTip, false).reply.as_slice() {
            [Wire::Tip(net, 4, _, work)] => {
                assert_eq!(*net, noct_core::p2p::NETWORK_ID);
                // The advertised work must be our real cumulative difficulty:
                // it is what every peer's fork choice is decided on (F29).
                assert_eq!(*work, a.chain.cumulative_difficulty());
            }
            other => panic!("expected Tip(NETWORK_ID, 4, _, work), got {other:?}"),
        }
    }

    /// Regression: a node with no peers must fluff a submitted transaction
    /// immediately. Stemming with nowhere to relay silently loses it — it would
    /// never reach any mempool and never be mined.
    #[test]
    fn submission_without_peers_always_fluffs_into_the_mempool() {
        let miner = wallet();
        let mut node = test_node(miner.address());
        // Default fluff probability (0.1) would stem ~90% of the time if allowed.
        let mut miner_view = miner;
        mine_n(&mut node, &mut miner_view, 16);

        let bob = wallet();
        let spendable = miner_view.unspent().next().cloned().unwrap();
        let fee = noct_core::emission::ATOMIC_UNITS / 100;
        let payments = [noct_core::tx::Payment {
            destination: bob.address(),
            amount: spendable.amount() - fee,
        }];
        let tx = miner_view
            .build_transaction(&mut OsRng, &node.chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();

        // can_stem = false (no peers) ⇒ must fluff and land in the mempool.
        assert!(matches!(node.originate_tx(&mut OsRng, tx.clone(), false), Relay::FloodToAll(_)));
        assert_eq!(node.mempool_len(), 1, "tx must be in the mempool, not lost to the stem");

        // And it gets mined into the next block.
        let (_, txs) = node.mine_block(&mut OsRng).unwrap();
        assert!(txs.iter().any(|t| t.hash() == tx.hash()));
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;
    use noct_core::address::Network;

    /// The two networks must never advertise each other's seeds.
    #[test]
    fn seed_lists_are_per_network_and_disjoint() {
        let main = default_seeds(Network::Mainnet);
        let test = default_seeds(Network::Testnet);
        for m in main {
            assert!(!test.contains(m), "{m} appears on both networks");
        }
        assert!(main.is_empty(), "mainnet has not launched — its seed list must stay empty");
        assert!(!test.is_empty(), "the testnet needs at least one seed to bootstrap");
    }

    /// Every seed must parse as host:port, and testnet seeds must use the
    /// testnet port — a mainnet port here would dial nodes that reject us.
    #[test]
    fn testnet_seeds_are_well_formed_and_on_the_testnet_port() {
        let expected = Network::Testnet.params().default_p2p_port;
        for s in default_seeds(Network::Testnet) {
            let (host, port) = s.rsplit_once(':').unwrap_or_else(|| panic!("{s} is not host:port"));
            assert!(!host.is_empty(), "{s} has no host");
            let port: u16 = port.parse().unwrap_or_else(|_| panic!("{s} has a bad port"));
            assert_eq!(port, expected, "{s} is not on the testnet p2p port {expected}");
        }
    }

    /// Seeds are **names, not IP literals**, so a seed can move without shipping
    /// a new binary to everyone already running the network. A hardcoded address
    /// is frozen at release: change ISP or lose the address and that seed is dead
    /// for every existing install, and a node that reaches no seed cannot join at
    /// all. Putting a literal back here would silently undo that, so it fails.
    #[test]
    fn testnet_seeds_are_names_so_they_can_be_repointed() {
        for s in default_seeds(Network::Testnet) {
            let host = s.rsplit_once(':').unwrap().0;
            assert!(
                host.parse::<std::net::IpAddr>().is_err(),
                "`{host}` is a literal address — use a hostname so DNS can repoint it"
            );
        }
    }

    /// Seeds on separate uplinks are the entire point; two on one address would
    /// mean a single failure takes bootstrapping down.
    #[test]
    fn testnet_seeds_are_on_distinct_addresses() {
        let hosts: Vec<&str> = default_seeds(Network::Testnet)
            .iter()
            .map(|s| s.rsplit_once(':').unwrap().0)
            .collect();
        let mut uniq = hosts.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), hosts.len(), "two seeds share an address");
    }
}

/// A store written by a rewrite must replay.
///
/// `Blockchain` keeps genesis as `blocks()[0]`, and the rewrite copied the whole
/// vector — so the store began with genesis. A replaying node has already
/// applied genesis before reading a single stored block, so `add_block(genesis)`
/// failed `BadPrevId` on the very first record and replay discarded everything
/// after it. The entire chain, on every start.
///
/// It stayed hidden because the *append* path never wrote genesis: a node was
/// healthy until its first reorg triggered a rewrite, and poisoned from then on.
/// It cost this testnet thousands of blocks across several restarts.
#[cfg(test)]
mod store_replay_tests {
    use super::tests::*;
    use super::*;
    use noct_core::address::Network;
    use rand_core::OsRng;

    /// Mine a chain, rewrite the store from it, and replay that store into a
    /// fresh node. Every block must come back.
    #[test]
    fn a_rewritten_store_replays_completely() {
        let acct = noct_core::keys::Account::random(&mut OsRng);
        let miner = noct_core::address::Address::new(
            Network::Mainnet,
            acct.spend_public,
            acct.view_public,
        );
        let mut node = test_node(miner);
        let mut w = wallet();
        mine_n(&mut node, &mut w, 12);
        let mined_height = node.chain.height();
        assert!(mined_height >= 12, "setup mined a chain");

        // Exactly what rewrite_store persists.
        let stored: Vec<_> = node
            .chain
            .blocks()
            .iter()
            .skip(1)
            .map(|s| (s.block.clone(), s.txs.clone()))
            .collect();

        // Replay it into a fresh node, as a restart does.
        let acct2 = noct_core::keys::Account::random(&mut OsRng);
        let miner2 = noct_core::address::Address::new(
            Network::Mainnet,
            acct2.spend_public,
            acct2.view_public,
        );
        let mut fresh = test_node(miner2);
        let height = fresh
            .replay(&mut OsRng, stored)
            .expect("a store we wrote ourselves must replay without error");

        assert_eq!(
            height, mined_height,
            "replay must restore the full chain, not a truncated prefix"
        );
    }

    /// The precise regression: genesis in the store poisons the whole replay.
    /// This is what the old rewrite produced.
    #[test]
    fn genesis_in_the_store_would_destroy_the_chain() {
        let acct = noct_core::keys::Account::random(&mut OsRng);
        let miner = noct_core::address::Address::new(
            Network::Mainnet,
            acct.spend_public,
            acct.view_public,
        );
        let mut node = test_node(miner);
        let mut w = wallet();
        mine_n(&mut node, &mut w, 8);

        // The old behaviour: copy blocks() whole, genesis included.
        let with_genesis: Vec<_> =
            node.chain.blocks().iter().map(|s| (s.block.clone(), s.txs.clone())).collect();

        let acct2 = noct_core::keys::Account::random(&mut OsRng);
        let miner2 = noct_core::address::Address::new(
            Network::Mainnet,
            acct2.spend_public,
            acct2.view_public,
        );
        let mut fresh = test_node(miner2);
        let result = fresh.replay(&mut OsRng, with_genesis);

        assert!(
            result.is_err(),
            "storing genesis must fail loudly here, so nobody reintroduces it"
        );
        assert_eq!(
            fresh.chain.height(),
            1,
            "and the damage is total: the chain is left at genesis alone"
        );
    }
}
