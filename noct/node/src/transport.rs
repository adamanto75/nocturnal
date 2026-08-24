//! TCP transport: length-prefixed [`Wire`] framing, a peer registry, peer
//! discovery (handshake + address exchange + an outbound connection manager), and
//! the accept/dial/relay plumbing including initial block download. This is the
//! seam the in-memory `Network` from `noct_core::p2p` is replaced by for a real
//! process — the [`NodeState`] consensus logic is unchanged.
//!
//! Each peer socket has a single writer behind a mutex, shared between the
//! per-peer reader thread (for replies / sync pulls) and the broadcast registry,
//! so concurrent sends can never interleave and corrupt a frame.
//!
//! ## Discovery
//!
//! On every new connection the two sides exchange a [`Wire::Version`] handshake
//! carrying the network id, genesis block id, and the sender's *listen* port. A
//! peer on a different network or genesis is dropped immediately. The advertised
//! port lets us record a **dialable** address for an inbound peer (its socket's
//! source port is ephemeral). Nodes then trade address books via
//! [`Wire::GetPeers`]/[`Wire::Peers`], and a background manager dials from the
//! book to maintain a target number of outbound connections — so a network forms
//! from just a seed node or two, with no hand-wired peer list.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use noct_core::p2p::Wire;
use noct_core::wire;
use rand_core::{OsRng, RngCore};

use crate::{NodeState, Relay, BAN_DURATION, BAN_THRESHOLD};

/// A peer sending more than this many messages per second is treated as flooding
/// and dropped + banned. Set generously: normal sync is request/response bounded
/// by round-trip latency, well under this, so only egregious spam trips it.
const MAX_MSGS_PER_SEC: u32 = 5000;

/// Reject any framed message larger than this (anti-DoS on the length prefix).
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Cap on the address book, so a peer can't grow our memory without bound.
const MAX_BOOK: usize = 1024;

/// Cap on the misbehaviour score table. An attacker cycling through addresses
/// would otherwise make a defensive counter into a memory leak — the same lesson
/// as F13 and the rate limiter's client table.
const MAX_SCORED_PEERS: usize = 4096;

/// Most addresses to hand out in a single [`Wire::Peers`] reply.
const MAX_SHARE: usize = 32;

/// How often the connection manager tops up outbound connections and pulls fresh
/// addresses from peers.
const MANAGER_INTERVAL: Duration = Duration::from_secs(15);

/// A per-peer writer; the mutex serializes all sends to that socket.
type PeerWriter = Arc<Mutex<TcpStream>>;

/// Send a message to a peer, taking its write mutex. Best effort.
fn send_via(writer: &PeerWriter, msg: &Wire) {
    if let Ok(mut s) = writer.lock() {
        let _ = send_message(&mut s, msg);
    }
}

/// Send a length-prefixed wire message.
pub fn send_message(stream: &mut TcpStream, msg: &Wire) -> io::Result<()> {
    let bytes = wire::encode_message(msg);
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

/// Receive one length-prefixed wire message (blocking).
pub fn recv_message(stream: &mut TcpStream) -> io::Result<Wire> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    wire::decode_message(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
}

/// The set of connected peers we can send to. Cloneable handle over shared state.
///
/// Keyed by an id that is never reused, rather than a positional index: a peer
/// must be **removable** when its connection ends, and removing from a `Vec`
/// would renumber every peer after it — silently redirecting the ids already
/// held by other connection threads. Without removal the registry grows for the
/// lifetime of the process, holding a socket handle per dead connection, and
/// every [`Peers::flood`] pays to write to all of them. That is a resource leak
/// any peer can trigger for free, simply by connecting and disconnecting.
#[derive(Clone, Default)]
pub struct Peers {
    inner: Arc<Mutex<HashMap<usize, PeerWriter>>>,
    next_id: Arc<std::sync::atomic::AtomicUsize>,
}

impl Peers {
    pub fn new() -> Self {
        Peers::default()
    }

    fn add(&self, writer: PeerWriter) -> usize {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.lock().unwrap().insert(id, writer);
        id
    }

    /// Drop a peer from the registry. Called when its connection ends, on every
    /// exit path — including a handshake we rejected.
    pub fn remove(&self, id: usize) {
        self.inner.lock().unwrap().remove(&id);
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Flood a message to every peer (best effort). Snapshots the peer list so
    /// the registry lock is not held during the network sends.
    pub fn flood(&self, msg: &Wire) {
        let writers: Vec<PeerWriter> = self.inner.lock().unwrap().values().cloned().collect();
        for w in &writers {
            send_via(w, msg);
        }
    }

    /// Send a message to one random peer (Dandelion stem relay / discovery pull).
    pub fn send_to_one(&self, msg: &Wire) {
        let writer = {
            let peers = self.inner.lock().unwrap();
            if peers.is_empty() {
                return;
            }
            let idx = (OsRng.next_u64() as usize) % peers.len();
            match peers.values().nth(idx) {
                Some(w) => Arc::clone(w),
                None => return,
            }
        };
        send_via(&writer, msg);
    }

    /// Carry out a [`Relay`] action (used by the RPC/miner paths).
    pub fn execute(&self, relay: Relay) {
        match relay {
            Relay::Drop => {}
            Relay::StemToOne(msg) => self.send_to_one(&msg),
            Relay::FloodToAll(msg) => self.flood(&msg),
        }
    }
}

/// Peer-discovery state: the address book, the set of currently-connected peer
/// listen-addresses, and this node's own identity for the handshake. All fields
/// are shared (`Arc`), so this is cheap to clone across connection threads.
#[derive(Clone)]
pub struct Discovery {
    book: Arc<Mutex<HashSet<SocketAddr>>>,
    connected: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Our own listen address, so we never dial or advertise ourselves.
    self_addr: SocketAddr,
    genesis: [u8; 32],
    /// This network's p2p magic; a peer presenting a different one is dropped
    /// before its chain is even considered.
    magic: u32,
    target_outbound: usize,
    /// Where the address book is persisted, so peers survive a restart.
    book_path: Option<PathBuf>,
    /// Accumulated misbehavior points, per [`BanKey`].
    scores: Arc<Mutex<HashMap<BanKey, u32>>>,
    /// Banned peers → the time their ban lifts, per [`BanKey`].
    banned: Arc<Mutex<HashMap<BanKey, Instant>>>,
    /// A random per-process nonce, sent in our handshake so peers can detect a
    /// connection back to us.
    self_nonce: u64,
    /// Session nonces of peers we are currently connected to, to drop a second,
    /// duplicate link to a peer we already have.
    peer_nonces: Arc<Mutex<HashSet<u64>>>,
}

/// What a ban actually applies to (security review F12).
///
/// Bans used to be keyed on a peer's **advertised listen address** — its IP plus
/// the port it named in its own `Version` message. The port is attacker-supplied,
/// so a misbehaving peer reset its score simply by advertising a fresh port on
/// every reconnect, and a ban lasted exactly one connection.
///
/// The key is now derived from the address TCP actually connected from, which a
/// peer cannot choose. Which *prefix* is the substantive part:
///
/// * **IPv4 — the single address.** Obtaining another IPv4 address costs real
///   money, and a whole /24 routinely holds unrelated people, so banning one
///   would punish bystanders for a neighbour's behaviour.
/// * **IPv6 — the /64.** A single customer is routinely handed an entire /64,
///   which is 18 quintillion addresses. Banning one of them is not a weaker
///   measure, it is *no* measure: the next connection simply uses another. The
///   /64 is the smallest unit that corresponds to "one subscriber".
/// * **Loopback — the full address including port.** Several nodes on
///   `127.0.0.1` with different ports are distinct nodes during local testing,
///   and collapsing them would make one test node ban all the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BanKey {
    /// A local test node, kept per-port so local multi-node runs still work.
    Loopback(SocketAddr),
    /// One IPv4 address.
    V4(std::net::Ipv4Addr),
    /// An IPv6 /64 — the network an attacker cannot cheaply move out of.
    V6Prefix([u8; 8]),
}

/// Which address to score a peer under.
///
/// Off loopback the port is irrelevant — the prefix is the identity — so the
/// real connecting IP is used with the port zeroed. **On loopback the port is
/// the only thing distinguishing one node from another**, and an inbound
/// socket's source port is ephemeral (it changes on every reconnect), so the
/// peer's *advertised* listen address is used instead. That is self-declared and
/// therefore rotatable — which is precisely what F12 was about — but the threat
/// model on loopback is "my own test nodes", not an adversary, and the
/// alternative is local bans that silently never match anything.
fn ban_target(peer_ip: Option<IpAddr>, advertised: Option<SocketAddr>) -> Option<SocketAddr> {
    let ip = peer_ip?;
    if ip.is_loopback() {
        // Falls back to port 0 rather than nothing: a local peer that misbehaves
        // before its handshake should still be scored somewhere.
        return Some(advertised.unwrap_or_else(|| SocketAddr::new(ip, 0)));
    }
    Some(SocketAddr::new(ip, 0))
}

impl BanKey {
    pub fn of(addr: &SocketAddr) -> BanKey {
        if addr.ip().is_loopback() {
            return BanKey::Loopback(*addr);
        }
        match addr.ip() {
            IpAddr::V4(v4) => BanKey::V4(v4),
            IpAddr::V6(v6) => {
                // An IPv4-mapped address is really IPv4 and must not be treated
                // as a /64, or one mapped client would ban every other.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return BanKey::V4(v4);
                }
                let o = v6.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&o[..8]);
                BanKey::V6Prefix(prefix)
            }
        }
    }
}

impl Discovery {
    pub fn new(
        self_addr: SocketAddr,
        genesis: [u8; 32],
        magic: u32,
        target_outbound: usize,
    ) -> Self {
        Discovery {
            book: Arc::new(Mutex::new(HashSet::new())),
            connected: Arc::new(Mutex::new(HashSet::new())),
            self_addr,
            genesis,
            magic,
            target_outbound: target_outbound.max(1),
            book_path: None,
            scores: Arc::new(Mutex::new(HashMap::new())),
            banned: Arc::new(Mutex::new(HashMap::new())),
            self_nonce: OsRng.next_u64(),
            peer_nonces: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Is this handshake nonce our own? (I.e. we connected back to ourselves.)
    fn is_self_nonce(&self, nonce: u64) -> bool {
        nonce == self.self_nonce
    }

    /// Register a peer's session nonce; returns `false` if we are already
    /// connected to that peer (a duplicate link to drop).
    fn claim_nonce(&self, nonce: u64) -> bool {
        self.peer_nonces.lock().unwrap().insert(nonce)
    }

    fn release_nonce(&self, nonce: u64) {
        self.peer_nonces.lock().unwrap().remove(&nonce);
    }

    /// Is this peer currently banned? (Expired bans are cleared as a side effect.)
    ///
    /// Judged on the prefix the address belongs to, so a peer cannot shed a ban
    /// by changing its port or, on IPv6, by picking another address out of the
    /// same /64. See [`BanKey`].
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        let key = BanKey::of(addr);
        let mut banned = self.banned.lock().unwrap();
        match banned.get(&key) {
            Some(until) if Instant::now() < *until => true,
            Some(_) => {
                banned.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Add misbehavior points to a peer; returns `true` if it is now banned.
    ///
    /// `addr` must be the address the connection actually came from, not one the
    /// peer advertised — the whole point of F12 is that anything self-declared
    /// can be rotated to reset the score.
    fn penalize(&self, addr: SocketAddr, points: u32) -> bool {
        let key = BanKey::of(&addr);
        let mut scores = self.scores.lock().unwrap();
        // Bounded: an attacker rotating through addresses would otherwise grow
        // this table forever, turning a defence into a memory leak. Scores are
        // only ever an approximation, so dropping the smallest is safe.
        if scores.len() >= MAX_SCORED_PEERS && !scores.contains_key(&key) {
            if let Some((&worst, _)) = scores.iter().min_by_key(|(_, &v)| v) {
                scores.remove(&worst);
            }
        }
        let s = scores.entry(key).or_insert(0);
        *s = s.saturating_add(points);
        if *s >= BAN_THRESHOLD {
            scores.remove(&key);
            drop(scores);
            self.ban(addr);
            true
        } else {
            false
        }
    }

    /// Ban a peer's prefix for [`BAN_DURATION`], and forget it as a dial target.
    fn ban(&self, addr: SocketAddr) {
        self.banned.lock().unwrap().insert(BanKey::of(&addr), Instant::now() + BAN_DURATION);
        // The book is keyed by full address, so drop every entry in the banned
        // prefix rather than just this one — otherwise we keep dialling the same
        // misbehaving peer at its other advertised ports.
        let key = BanKey::of(&addr);
        self.book.lock().unwrap().retain(|a| BanKey::of(a) != key);
        self.connected.lock().unwrap().retain(|a| BanKey::of(a) != key);
    }

    /// Persist the address book at `path` and load any addresses already there.
    pub fn with_book(mut self, path: Option<PathBuf>) -> Self {
        self.book_path = path;
        self.load();
        self
    }

    /// Load persisted peer addresses (one `ip:port` per line) into the book.
    fn load(&self) {
        let Some(path) = &self.book_path else { return };
        if let Ok(text) = std::fs::read_to_string(path) {
            self.learn(text.lines().filter_map(|l| l.trim().parse().ok()));
        }
    }

    /// Write the current book to disk (best effort), one `ip:port` per line.
    fn save(&self) {
        let Some(path) = &self.book_path else { return };
        let lines: Vec<String> = self.book.lock().unwrap().iter().map(|a| a.to_string()).collect();
        let _ = std::fs::write(path, lines.join("\n"));
    }

    /// Seed the address book from **trusted** sources: operator-supplied
    /// `--seed`/`--peer`, or a peer's own just-connected address. No routability
    /// filter — an operator may legitimately point a node at a loopback/LAN peer.
    pub fn learn<I: IntoIterator<Item = SocketAddr>>(&self, addrs: I) {
        let mut book = self.book.lock().unwrap();
        for a in addrs {
            if a != self.self_addr && book.len() < MAX_BOOK {
                book.insert(a);
            }
        }
    }

    /// Learn addresses from **untrusted peer gossip** (a `Peers` message), keeping
    /// only routable ones. A node bound to a loopback address is a local/test node
    /// and accepts local peers; a node on a routable address rejects
    /// loopback/private/link-local gossip, so a remote peer can neither make it
    /// probe internal hosts (SSRF) nor flood its book with unreachable junk.
    pub fn learn_gossip<I: IntoIterator<Item = SocketAddr>>(&self, addrs: I) {
        self.learn_gossip_from(None, addrs)
    }

    /// Learn gossip, taking into account **which peer said it**.
    ///
    /// The rule above — reject private addresses unless we are loopback-bound —
    /// is right for a node on the public internet and wrong for every node on a
    /// private network, which is most nodes in most deployments. A node bound to
    /// `0.0.0.0` on a LAN is not loopback, so it discarded every private address
    /// it was told about, *including the listen address of the peer it was
    /// already talking to*. The result observed on this testnet: four nodes,
    /// three of them with exactly one peer each, all pointing at the one seed
    /// they were explicitly configured with. Discovery never happened, and the
    /// network was a star with a single point of failure.
    ///
    /// The source address is what makes this safe to relax. If we are hearing
    /// gossip over a link to a private address, we already have a route into
    /// that network — accepting more addresses from it grants no reach we did
    /// not have. A node facing the public internet still hears only from public
    /// peers, so it still refuses to be pointed at `192.168.0.1`, which is the
    /// SSRF case the filter exists for.
    pub fn learn_gossip_from<I: IntoIterator<Item = SocketAddr>>(
        &self,
        from: Option<std::net::IpAddr>,
        addrs: I,
    ) {
        let local_node = self.self_addr.ip().is_loopback()
            || from.map(Self::is_private_scope).unwrap_or(false);
        let ok = addrs.into_iter().filter(|a| Self::routable(a, local_node));
        self.learn(ok);
    }

    /// Is this address inside a private network we could already be part of?
    fn is_private_scope(ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
            // fc00::/7 (unique local) and fe80::/10 (link local).
            IpAddr::V6(v6) => {
                let o = v6.octets();
                v6.is_loopback() || (o[0] & 0xfe) == 0xfc || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
            }
        }
    }

    /// Is `addr` an address we should ever dial from gossip? `local_node` relaxes
    /// the rules for a loopback-bound (test/local) node.
    fn routable(addr: &SocketAddr, local_node: bool) -> bool {
        use std::net::IpAddr;
        if addr.port() == 0 {
            return false;
        }
        match addr.ip() {
            IpAddr::V4(v4) => {
                if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_documentation() {
                    return false;
                }
                if !local_node && (v4.is_loopback() || v4.is_private() || v4.is_link_local()) {
                    return false;
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_unspecified() || v6.is_multicast() {
                    return false;
                }
                if !local_node && v6.is_loopback() {
                    return false;
                }
            }
        }
        true
    }

    fn mark_connected(&self, addr: SocketAddr) {
        self.connected.lock().unwrap().insert(addr);
    }
    fn unmark(&self, addr: &SocketAddr) {
        self.connected.lock().unwrap().remove(addr);
    }
    fn connected_count(&self) -> usize {
        self.connected.lock().unwrap().len()
    }

    /// Addresses to try dialing: known, not ourselves, not already connected, not
    /// banned. (Ban check is a second pass to avoid holding multiple locks.)
    fn dial_candidates(&self) -> Vec<SocketAddr> {
        let candidates: Vec<SocketAddr> = {
            let connected = self.connected.lock().unwrap();
            self.book
                .lock()
                .unwrap()
                .iter()
                .filter(|a| **a != self.self_addr && !connected.contains(*a))
                .copied()
                .collect()
        };
        candidates.into_iter().filter(|a| !self.is_banned(a)).collect()
    }

    /// A sample of known addresses to share, excluding the requester's own.
    fn share(&self, exclude: Option<SocketAddr>) -> Vec<SocketAddr> {
        self.book
            .lock()
            .unwrap()
            .iter()
            .filter(|a| Some(**a) != exclude)
            .take(MAX_SHARE)
            .copied()
            .collect()
    }

    /// Our handshake message.
    fn version(&self) -> Wire {
        Wire::Version(self.magic, self.genesis, self.self_addr.port(), self.self_nonce)
    }
}

/// Register a freshly-established connection (inbound or outbound): one shared
/// writer for both replies and broadcasts, plus a reader thread that runs the
/// handshake, gossip, discovery, and initial block download. `dialed` is the
/// peer's known listen address for an *outbound* connection (`None` for inbound,
/// where we learn it from the peer's handshake).
pub fn register_connection(
    stream: TcpStream,
    state: &Arc<Mutex<NodeState>>,
    peers: &Peers,
    disc: &Discovery,
    dialed: Option<SocketAddr>,
) -> io::Result<()> {
    let socket_addr = stream.peer_addr().ok();
    // Refuse a banned prefix here, before a single message is read. Previously
    // the ban was only consulted after the peer's `Version` arrived — and
    // against the address that message advertised — so a banned peer got a free
    // connection and a fresh score every time (F12).
    if let Some(a) = socket_addr {
        if disc.is_banned(&a) {
            return Ok(());
        }
    }
    let peer_ip = socket_addr.map(|a| a.ip());
    let writer: PeerWriter = Arc::new(Mutex::new(stream.try_clone()?));
    let peer_id = peers.add(Arc::clone(&writer));
    spawn_peer_reader(stream, writer, peer_id, peer_ip, state.clone(), peers.clone(), disc.clone(), dialed);
    Ok(())
}

/// Reader loop for one peer. Sends our handshake + a tip request, then processes
/// incoming messages: discovery messages are handled here (they never touch
/// consensus), everything else goes to [`NodeState::react`].
#[allow(clippy::too_many_arguments)]
fn spawn_peer_reader(
    mut reader: TcpStream,
    writer: PeerWriter,
    peer_id: usize,
    peer_ip: Option<std::net::IpAddr>,
    state: Arc<Mutex<NodeState>>,
    peers: Peers,
    disc: Discovery,
    dialed: Option<SocketAddr>,
) {
    thread::spawn(move || {
        // The listen-address we attribute this peer (known up front if we dialed)
        // and its session nonce (learned from the handshake).
        let mut peer_listen: Option<SocketAddr> = dialed;
        let mut peer_nonce: Option<u64> = None;
        if let Some(a) = peer_listen {
            disc.mark_connected(a);
        }

        // Handshake first, then kick off initial block download.
        if let Ok(mut w) = writer.lock() {
            if send_message(&mut w, &disc.version()).is_err()
                || send_message(&mut w, &Wire::GetTip).is_err()
            {
                if let Some(a) = peer_listen {
                    disc.unmark(&a);
                }
                // This connection never got going; it must still leave the
                // registry, or it holds a socket for the life of the process.
                peers.remove(peer_id);
                return;
            }
        }

        // Per-connection rate limiting and misbehavior accumulation.
        let mut window = Instant::now();
        let mut msgs_this_second: u32 = 0;
        let mut local_score: u32 = 0;

        loop {
            let msg = match recv_message(&mut reader) {
                Ok(m) => m,
                Err(_) => break, // peer closed or sent garbage → drop the connection
            };

            // Rate limit: sustained flooding → drop and ban.
            msgs_this_second += 1;
            if window.elapsed() >= Duration::from_secs(1) {
                window = Instant::now();
                msgs_this_second = 1;
            } else if msgs_this_second > MAX_MSGS_PER_SEC {
                // Banned on the address the packets are really coming from,
                // never on the one the peer advertised for itself (except on
                // loopback — see `ban_target`).
                if let Some(t) = ban_target(peer_ip, peer_listen) {
                    disc.ban(t);
                }
                break;
            }

            // --- discovery messages: handled here, not in consensus ---
            match msg {
                Wire::Version(network, genesis, port, nonce) => {
                    if network != disc.magic || genesis != disc.genesis {
                        break; // foreign network or chain → disconnect
                    }
                    if disc.is_self_nonce(nonce) {
                        break; // we connected back to ourselves
                    }
                    if !disc.claim_nonce(nonce) {
                        break; // duplicate link to a peer we already have
                    }
                    peer_nonce = Some(nonce);
                    // Record a dialable address for this peer (its advertised
                    // listen port at the IP we see it on).
                    if let Some(ip) = peer_ip {
                        let addr = SocketAddr::new(ip, port);
                        if disc.is_banned(&addr) {
                            break; // a banned peer reconnecting → refuse it
                        }
                        peer_listen = Some(addr);
                        // The IP here is the one this connection actually came
                        // from, so it is reachable by construction — including
                        // when it is a LAN address. Only the advertised *port*
                        // is untrusted, and a wrong port merely wastes a dial.
                        disc.learn_gossip_from(Some(ip), [addr]);
                        disc.mark_connected(addr);
                    }
                    continue;
                }
                Wire::GetPeers => {
                    let reply = Wire::Peers(disc.share(peer_listen));
                    if let Ok(mut w) = writer.lock() {
                        let _ = send_message(&mut w, &reply);
                    }
                    continue;
                }
                Wire::Peers(addrs) => {
                    // Judge the addresses by the company they arrive in: gossip
                    // reaching us over a private link is about a network we can
                    // already reach.
                    disc.learn_gossip_from(peer_ip, addrs);
                    continue;
                }
                _ => {}
            }

            // --- consensus / sync messages ---
            let reaction = {
                let mut node = state.lock().unwrap();
                node.react(&mut OsRng, peer_id, msg, false)
            };

            // Penalise invalid data; drop the peer once it crosses the ban line.
            if reaction.misbehavior > 0 {
                local_score = local_score.saturating_add(reaction.misbehavior);
                let now_banned = ban_target(peer_ip, peer_listen)
                    .map(|t| disc.penalize(t, reaction.misbehavior))
                    .unwrap_or(false);
                if now_banned || local_score >= BAN_THRESHOLD {
                    break;
                }
            }

            if let Ok(mut w) = writer.lock() {
                for m in &reaction.reply {
                    if send_message(&mut w, m).is_err() {
                        if let Some(a) = peer_listen {
                            disc.unmark(&a);
                        }
                        if let Some(n) = peer_nonce {
                            disc.release_nonce(n);
                        }
                        return;
                    }
                }
            }
            for m in reaction.broadcast {
                peers.flood(&m);
            }
            for m in reaction.stem {
                peers.send_to_one(&m);
            }
        }

        // Connection closed: drop it from the send registry and free its outbound
        // slot and session nonce, so the manager can replace it.
        //
        // The registry removal matters most: every path out of the loop above
        // ends here, including the ones that reject a peer (foreign network,
        // foreign genesis, self-connection, duplicate link, flooding). Those are
        // exactly the connections an attacker can produce cheaply and endlessly,
        // so leaving them registered would let anyone exhaust the node's sockets
        // and slow every broadcast.
        peers.remove(peer_id);
        if let Some(a) = peer_listen {
            disc.unmark(&a);
        }
        if let Some(n) = peer_nonce {
            disc.release_nonce(n);
        }
    });
}

/// Start accepting inbound connections on `listener` in a background thread.
pub fn spawn_listener(listener: TcpListener, state: Arc<Mutex<NodeState>>, peers: Peers, disc: Discovery) {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = register_connection(stream, &state, &peers, &disc, None);
        }
    });
}

/// Background outbound-connection manager: keeps up to `target_outbound` live
/// connections by dialing from the address book, and periodically pulls fresh
/// addresses from a peer. Runs immediately, then every [`MANAGER_INTERVAL`].
pub fn spawn_connection_manager(state: Arc<Mutex<NodeState>>, peers: Peers, disc: Discovery) {
    thread::spawn(move || loop {
        let need = disc.target_outbound.saturating_sub(disc.connected_count());
        if need > 0 {
            for addr in disc.dial_candidates().into_iter().take(need) {
                disc.mark_connected(addr); // reserve so we don't double-dial
                let state = Arc::clone(&state);
                let peers = peers.clone();
                let disc = disc.clone();
                thread::spawn(move || {
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                        Ok(s) => {
                            if register_connection(s, &state, &peers, &disc, Some(addr)).is_err() {
                                disc.unmark(&addr);
                            }
                        }
                        Err(_) => disc.unmark(&addr),
                    }
                });
            }
        }
        // Ask a peer for more addresses to widen the book over time, and persist
        // the book so these peers are remembered across restarts.
        peers.send_to_one(&Wire::GetPeers);
        disc.save();
        thread::sleep(MANAGER_INTERVAL);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery() -> Discovery {
        Discovery::new("127.0.0.1:1".parse().unwrap(), [0u8; 32], noct_core::params::MAINNET.p2p_magic, 8)
    }

    #[test]
    fn misbehavior_accumulates_then_bans() {
        let d = discovery();
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(!d.is_banned(&peer));
        // Just under the threshold: not banned yet.
        assert!(!d.penalize(peer, BAN_THRESHOLD - 1));
        assert!(!d.is_banned(&peer));
        // Crossing it bans the peer.
        assert!(d.penalize(peer, 1));
        assert!(d.is_banned(&peer));
    }

    /// **F12.** A ban used to key on the peer's *advertised* listen address, so
    /// a misbehaving peer reset its score by naming a fresh port on every
    /// reconnect and the ban lasted exactly one connection. Scoring is now on
    /// the address TCP connected from, which the peer cannot choose.
    #[test]
    fn a_peer_cannot_shed_a_ban_by_changing_its_port() {
        let d = discovery();
        let real: SocketAddr = "203.0.113.7:30000".parse().unwrap();
        d.penalize(real, BAN_THRESHOLD);
        assert!(d.is_banned(&real));

        // The same host coming back on any other port is still banned.
        for port in [30001u16, 1, 65535, 9333] {
            let rotated = SocketAddr::new(real.ip(), port);
            assert!(d.is_banned(&rotated), "port {port} escaped the ban");
        }
        // And an unrelated host is not caught up in it.
        assert!(!d.is_banned(&"203.0.113.8:30000".parse().unwrap()));
    }

    /// The substantive half of F12 for IPv6. One subscriber is routinely handed
    /// an entire /64 — 18 quintillion addresses — so banning a single address is
    /// not a weaker measure, it is no measure at all.
    #[test]
    fn an_ipv6_peer_cannot_shed_a_ban_by_picking_another_address() {
        let d = discovery();
        let real: SocketAddr = "[2001:db8:1:2::1]:9333".parse().unwrap();
        d.penalize(real, BAN_THRESHOLD);

        // Any other address inside the same /64.
        for other in ["[2001:db8:1:2::2]:9333", "[2001:db8:1:2:ffff:ffff:ffff:ffff]:1"] {
            assert!(d.is_banned(&other.parse().unwrap()), "{other} escaped the ban");
        }
        // A different /64 is a different subscriber and must be unaffected —
        // banning wider would punish bystanders for a neighbour's behaviour.
        assert!(!d.is_banned(&"[2001:db8:1:3::1]:9333".parse().unwrap()));
    }

    /// Local multi-node testing puts several nodes on 127.0.0.1 with different
    /// ports. Collapsing those would make one misbehaving test node ban all the
    /// others, so loopback stays per-port.
    #[test]
    fn loopback_nodes_are_banned_individually() {
        let d = discovery();
        let a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        d.penalize(a, BAN_THRESHOLD);
        assert!(d.is_banned(&a));
        assert!(!d.is_banned(&b), "banning one local node must not ban the others");
    }

    /// An IPv4-mapped IPv6 address is really one IPv4 host. Treating it as a
    /// /64 would let one such client ban every other mapped client at once.
    #[test]
    fn an_ipv4_mapped_address_is_treated_as_one_host() {
        let d = discovery();
        d.penalize("[::ffff:203.0.113.7]:9333".parse().unwrap(), BAN_THRESHOLD);
        assert!(d.is_banned(&"203.0.113.7:1234".parse().unwrap()), "same host either way");
        assert!(!d.is_banned(&"203.0.113.8:1234".parse().unwrap()), "must not ban unrelated hosts");
    }

    /// The routing that decides *what* a peer is scored under, and the bug this
    /// caught: banning a loopback peer under `ip:0` would never match a check
    /// against its real address, so local bans silently did nothing.
    #[test]
    fn a_peer_is_scored_under_the_right_address() {
        let remote: IpAddr = "203.0.113.7".parse().unwrap();
        let advertised: SocketAddr = "203.0.113.7:9333".parse().unwrap();
        // Off loopback the port is irrelevant, so it is dropped — and the
        // advertised address is ignored, which is the point of F12.
        assert_eq!(ban_target(Some(remote), Some(advertised)), Some(SocketAddr::new(remote, 0)));
        assert_eq!(ban_target(Some(remote), None), Some(SocketAddr::new(remote, 0)));

        // On loopback the port is the only thing telling two test nodes apart,
        // and an inbound socket's source port is ephemeral — so the advertised
        // listen address is used, and a ban recorded that way must match.
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        assert_eq!(ban_target(Some(local), Some(listen)), Some(listen));

        let d = discovery();
        d.penalize(ban_target(Some(local), Some(listen)).unwrap(), BAN_THRESHOLD);
        assert!(d.is_banned(&listen), "a loopback ban must actually take effect");
        assert!(!d.is_banned(&"127.0.0.1:9003".parse().unwrap()));

        assert_eq!(ban_target(None, Some(listen)), None);
    }

    /// A defensive counter must not become the memory leak. An attacker cycling
    /// through addresses would otherwise grow this table forever.
    #[test]
    fn the_score_table_stays_bounded() {
        let d = discovery();
        for i in 0..(MAX_SCORED_PEERS + 500) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from((i as u32).wrapping_add(0x0b000000)));
            d.penalize(SocketAddr::new(ip, 9333), 1);
        }
        assert!(
            d.scores.lock().unwrap().len() <= MAX_SCORED_PEERS,
            "score table grew past its cap"
        );
    }

    #[test]
    fn a_banned_peer_is_dropped_as_a_dial_target() {
        let d = discovery();
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        d.learn([peer]);
        assert!(d.dial_candidates().contains(&peer));
        d.penalize(peer, BAN_THRESHOLD); // ban it
        assert!(!d.dial_candidates().contains(&peer), "banned peer must not be dialed");
    }

    #[test]
    fn we_never_learn_or_dial_ourselves() {
        let d = discovery(); // self = 127.0.0.1:1
        d.learn(["127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap()]);
        let cands = d.dial_candidates();
        assert!(!cands.contains(&"127.0.0.1:1".parse().unwrap()));
        assert!(cands.contains(&"127.0.0.1:2".parse().unwrap()));
    }

    #[test]
    fn gossip_filter_rejects_bogus_but_keeps_local_for_a_test_node() {
        // Loopback-bound node → local mode → keeps loopback peers (needed for
        // local multi-node testing) but still drops unspecified / port-0.
        let d = discovery(); // self = 127.0.0.1:1 (loopback)
        d.learn_gossip([
            "127.0.0.1:9333".parse().unwrap(),  // loopback: kept for a local node
            "0.0.0.0:9333".parse().unwrap(),    // unspecified: always rejected
            "8.8.8.8:0".parse().unwrap(),       // port 0: rejected
        ]);
        let c = d.dial_candidates();
        assert!(c.contains(&"127.0.0.1:9333".parse().unwrap()));
        assert!(!c.contains(&"0.0.0.0:9333".parse().unwrap()));
        assert!(!c.iter().any(|a| a.port() == 0));
    }

    #[test]
    fn self_and_duplicate_handshake_nonces_are_rejected() {
        let d = discovery();
        // Our own nonce → a self-connection.
        assert!(d.is_self_nonce(d.self_nonce));
        assert!(!d.is_self_nonce(d.self_nonce.wrapping_add(1)));
        // A peer nonce is claimable once; a second claim is a duplicate link.
        assert!(d.claim_nonce(42));
        assert!(!d.claim_nonce(42));
        // Once that link drops, the nonce frees up again.
        d.release_nonce(42);
        assert!(d.claim_nonce(42));
    }

    #[test]
    fn a_routable_node_rejects_private_and_loopback_gossip() {
        // Public-bound node → rejects loopback/private gossip (anti-SSRF), keeps
        // routable addresses.
        let d = Discovery::new("8.8.4.4:9333".parse().unwrap(), [0u8; 32], noct_core::params::MAINNET.p2p_magic, 8);
        d.learn_gossip([
            "127.0.0.1:9333".parse().unwrap(),    // loopback: rejected
            "192.168.1.10:9333".parse().unwrap(), // private: rejected
            "10.0.0.5:9333".parse().unwrap(),     // private: rejected
            "8.8.8.8:9333".parse().unwrap(),      // routable: kept
        ]);
        let c = d.dial_candidates();
        assert!(!c.contains(&"127.0.0.1:9333".parse().unwrap()));
        assert!(!c.contains(&"192.168.1.10:9333".parse().unwrap()));
        assert!(!c.contains(&"10.0.0.5:9333".parse().unwrap()));
        assert!(c.contains(&"8.8.8.8:9333".parse().unwrap()));
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn dummy_writer() -> PeerWriter {
        // A socket pair to a listener we immediately drop: enough to build a
        // registry entry without needing a live peer.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        Arc::new(Mutex::new(client))
    }

    /// A dropped connection must leave the registry.
    ///
    /// Regression test for a leak found by running a testnet node against a
    /// mainnet one: every rejected handshake left its entry behind, so the peer
    /// count climbed without bound. Any peer could trigger it for free by
    /// connecting and disconnecting, exhausting sockets and making every
    /// `flood` progressively more expensive.
    #[test]
    fn a_removed_peer_leaves_the_registry() {
        let peers = Peers::new();
        assert_eq!(peers.count(), 0);

        let a = peers.add(dummy_writer());
        let b = peers.add(dummy_writer());
        assert_eq!(peers.count(), 2);

        peers.remove(a);
        assert_eq!(peers.count(), 1, "removing one peer must drop exactly one entry");
        peers.remove(b);
        assert_eq!(peers.count(), 0, "the registry must return to empty");

        // Removing twice is harmless — cleanup can run on more than one path.
        peers.remove(a);
        assert_eq!(peers.count(), 0);
    }

    /// Ids must never be reused, or a late cleanup from an old connection would
    /// evict a live peer that happened to take its slot.
    #[test]
    fn peer_ids_are_never_reused() {
        let peers = Peers::new();
        let first = peers.add(dummy_writer());
        peers.remove(first);
        let second = peers.add(dummy_writer());
        assert_ne!(first, second, "a fresh peer must not inherit a retired id");

        // The stale id from the closed connection must not touch the live one.
        peers.remove(first);
        assert_eq!(peers.count(), 1, "a stale removal must not evict a live peer");
    }

    /// Churn must not accumulate: this is the shape of the attack.
    #[test]
    fn repeated_connect_disconnect_does_not_accumulate() {
        let peers = Peers::new();
        for _ in 0..200 {
            let id = peers.add(dummy_writer());
            peers.remove(id);
        }
        assert_eq!(peers.count(), 0, "churn must leave nothing behind");
    }
}

/// Peer discovery has to work on a private network without letting a public
/// peer aim a public node at private hosts.
///
/// Found by running the testnet: four nodes, three with exactly one peer each,
/// every one of them pointing at the single seed it was configured with.
/// Discovery had never worked, because a node bound to `0.0.0.0` is not
/// loopback and so discarded every private address it heard — including the
/// listen address of the peer it was already connected to.
#[cfg(test)]
mod private_network_discovery_tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};

    fn disc(self_addr: &str) -> Discovery {
        Discovery::new(self_addr.parse().unwrap(), [0u8; 32], 1, 8)
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn book_has(d: &Discovery, a: &str) -> bool {
        d.book.lock().unwrap().contains(&sa(a))
    }

    /// The bug: a LAN node bound to 0.0.0.0 must be able to learn its LAN peers.
    #[test]
    fn a_lan_node_learns_lan_peers_from_a_lan_peer() {
        let d = disc("0.0.0.0:19333");
        d.learn_gossip_from(Some(ip("10.10.10.240")), [sa("10.10.10.82:19333")]);
        assert!(
            book_has(&d, "10.10.10.82:19333"),
            "a node on a private network must be able to discover its own network"
        );
    }

    /// The protection that must survive: a public node told about private hosts
    /// by a public peer still refuses. This is the SSRF case.
    #[test]
    fn a_public_peer_cannot_aim_us_at_private_hosts() {
        let d = disc("0.0.0.0:19333");
        d.learn_gossip_from(
            Some(ip("8.8.8.8")),
            [sa("192.168.0.1:19333"), sa("10.0.0.1:19333"), sa("127.0.0.1:19333")],
        );
        for a in ["192.168.0.1:19333", "10.0.0.1:19333", "127.0.0.1:19333"] {
            assert!(!book_has(&d, a), "{a} must not be learned from a public peer");
        }
    }

    /// And a public peer telling us about public peers still works.
    ///
    /// Note the addresses: the documentation ranges (192.0.2/24, 198.51.100/24,
    /// 203.0.113/24) are rejected as unroutable, so a test written with them
    /// fails for a reason that has nothing to do with what it is testing.
    #[test]
    fn public_gossip_from_a_public_peer_is_still_accepted() {
        let d = disc("0.0.0.0:19333");
        d.learn_gossip_from(Some(ip("8.8.8.8")), [sa("93.184.216.34:19333")]);
        assert!(book_has(&d, "93.184.216.34:19333"));
    }

    /// Gossip with no known source keeps the old, strict behaviour — an unknown
    /// origin is not evidence of anything.
    #[test]
    fn gossip_from_an_unknown_source_stays_strict() {
        let d = disc("0.0.0.0:19333");
        d.learn_gossip_from(None, [sa("10.0.0.5:19333")]);
        assert!(!book_has(&d, "10.0.0.5:19333"));
    }

    /// A private peer still cannot smuggle in nonsense: unroutable is
    /// unroutable regardless of who says it.
    #[test]
    fn a_private_peer_still_cannot_gossip_junk() {
        let d = disc("0.0.0.0:19333");
        d.learn_gossip_from(
            Some(ip("10.10.10.240")),
            [sa("0.0.0.0:19333"), sa("224.0.0.1:19333"), sa("10.10.10.9:0")],
        );
        for a in ["0.0.0.0:19333", "224.0.0.1:19333", "10.10.10.9:0"] {
            assert!(!book_has(&d, a), "{a} is not a dialable address");
        }
    }
}
