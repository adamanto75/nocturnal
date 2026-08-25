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

/// Most of the address book any single gossip source may fill.
///
/// Without a per-source cap, one peer that merely talks can hand us
/// `MAX_BOOK` routable-but-useless addresses, fill the book, and — because a
/// full book refuses new entries rather than evicting honest ones — leave the
/// node permanently unable to learn a real peer. That is an eclipse for the
/// price of a connection, and an adversarial test confirmed it: 1024 junk
/// addresses in, honest address refused.
///
/// A sixteenth each means it takes sixteen distinct sources to fill the book,
/// and no one of them can shut the others out.
const MAX_BOOK_PER_SOURCE: usize = MAX_BOOK / 16;

/// Cap on the misbehaviour score table. An attacker cycling through addresses
/// would otherwise make a defensive counter into a memory leak — the same lesson
/// as F13 and the rate limiter's client table.
const MAX_SCORED_PEERS: usize = 4096;

/// Most addresses to hand out in a single [`Wire::Peers`] reply.
const MAX_SHARE: usize = 32;

/// How often the connection manager tops up outbound connections and pulls fresh
/// addresses from peers.
const MANAGER_INTERVAL: Duration = Duration::from_secs(15);

/// First wait after a failed dial; doubles per consecutive failure.
const DIAL_BACKOFF_BASE_SECS: u64 = 30;
/// Cap on the doubling exponent, so the shift cannot overflow.
const DIAL_BACKOFF_MAX_SHIFT: u32 = 10;
/// Longest we will ever hold an address back. Hosts come back; a permanent
/// write-off would be its own kind of forgetting.
const DIAL_BACKOFF_CAP_SECS: u64 = 1800;

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
    /// How many book entries each gossip source has been allowed to contribute,
    /// so no single peer can fill the book and shut everyone else out.
    gossip_quota: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
    /// Advertise port 0 instead of our real one, so peers do not remember us.
    ///
    /// For nodes that exist briefly and will never be reachable again — CI
    /// runners, one-shot probes, scanners. Peers already discard a gossiped
    /// address whose port is 0 as unroutable, so this is the existing "do not
    /// record me" signal rather than a new protocol rule.
    ///
    /// Without it every ephemeral node leaves a permanent dead entry in every
    /// peer's book. A daily CI job that dials the seeds put six such addresses
    /// into this network's books, and they filled every outbound dial slot.
    ephemeral: bool,
    /// Consecutive failed dials per address, and the time we may try it again.
    ///
    /// Without this an unreachable address is redialled every
    /// [`MANAGER_INTERVAL`] forever. Outbound slots are finite, so once enough
    /// dead addresses accumulate they occupy every slot and the node cannot
    /// reach anyone — while reachable peers sit in the book untried.
    ///
    /// Observed on the testnet: eight dials, eight slots, six of them dead
    /// GitHub Actions runners learned by gossip from the daily join test. The
    /// one peer that worked never got a slot.
    dial_backoff: Arc<Mutex<HashMap<SocketAddr, (u32, Instant)>>>,
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
            dial_backoff: Arc::new(Mutex::new(HashMap::new())),
            ephemeral: false,
            gossip_quota: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Mark this node ephemeral: advertise no listen port, so peers do not add
    /// us to their address books.
    pub fn ephemeral(mut self, yes: bool) -> Self {
        self.ephemeral = yes;
        self
    }

    /// Note that a dial to `addr` failed, and hold it back for a while.
    ///
    /// Backoff, deliberately, rather than eviction. An address that fails is
    /// not necessarily bad — a peer reboots, a link flaps — and *removing* it on
    /// failure would hand an attacker a lever: induce failures against honest
    /// addresses and watch them disappear from the book, which is the shape of
    /// an eclipse attack. Delaying is enough to free the slot, and is not
    /// something an attacker can turn into permanent exclusion.
    pub fn note_dial_failure(&self, addr: SocketAddr) {
        let mut b = self.dial_backoff.lock().unwrap();
        let entry = b.entry(addr).or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(1);
        // 30s, 1m, 2m, 4m … capped, so even a long-dead address is retried
        // occasionally: hosts do come back, and a permanent write-off would be
        // its own kind of forgetting.
        let secs = DIAL_BACKOFF_BASE_SECS.saturating_mul(1u64 << entry.0.min(DIAL_BACKOFF_MAX_SHIFT));
        entry.1 = Instant::now() + Duration::from_secs(secs.min(DIAL_BACKOFF_CAP_SECS));
    }

    /// A dial succeeded: forget its failure history entirely.
    pub fn note_dial_success(&self, addr: SocketAddr) {
        self.dial_backoff.lock().unwrap().remove(&addr);
    }

    /// Is this address currently being held back after repeated failures?
    fn in_backoff(&self, addr: &SocketAddr, now: Instant) -> bool {
        self.dial_backoff.lock().unwrap().get(addr).is_some_and(|(_, until)| *until > now)
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
        let ok: Vec<SocketAddr> =
            addrs.into_iter().filter(|a| Self::routable(a, local_node)).collect();

        // Cap what any one source may contribute. A full book refuses new
        // entries rather than evicting old ones — which stops a flood erasing
        // honest peers, but means whoever fills it first decides who we can
        // ever hear about. Quota-per-source keeps that from being one peer.
        let Some(src) = from else {
            // No known source: it cannot be attributed, so it cannot be
            // trusted with book space at all beyond the usual limit.
            self.learn(ok);
            return;
        };
        let allowed = {
            let mut counts = self.gossip_quota.lock().unwrap();
            let used = counts.entry(src).or_insert(0);
            let room = MAX_BOOK_PER_SOURCE.saturating_sub(*used);
            let take = room.min(ok.len());
            *used += take;
            take
        };
        self.learn(ok.into_iter().take(allowed));
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
    /// How many addresses we know of at all. Reported by the connection
    /// manager, because "no peers" and "no addresses" need different fixes.
    fn book_len(&self) -> usize {
        self.book.lock().unwrap().len()
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
        let now = Instant::now();
        let mut usable: Vec<SocketAddr> = candidates
            .into_iter()
            .filter(|a| !self.is_banned(a) && !self.in_backoff(a, now))
            .collect();

        // Try the addresses with the cleanest record first. Slots are scarce,
        // so spending them on a peer that has never failed beats spending them
        // on one that has failed twice and is merely out of its backoff.
        let fails = self.dial_backoff.lock().unwrap();
        usable.sort_by_key(|a| fails.get(a).map(|(n, _)| *n).unwrap_or(0));
        if !usable.is_empty() {
            return usable;
        }

        // Everything is in backoff. Waiting it out would be its own starvation:
        // a node with no peers and nothing to try does nothing at all, which is
        // exactly the state backoff was added to escape. Seen in practice — a
        // node reporting "14 known, no address to dial" while sitting idle at
        // zero peers, because a subnet fault had timed out its good LAN peers
        // alongside the genuinely dead ones.
        //
        // So always keep one candidate: whichever is closest to being eligible.
        // The backoff still does its job — dead addresses are tried rarely
        // rather than every 15s — but the node never stops trying entirely.
        drop(fails);
        let now2 = Instant::now();

        // Snapshot first, then filter. `ban()` takes `banned` before `book`, so
        // calling `is_banned` while holding `book` would invert that order and
        // invite a deadlock.
        let known: Vec<SocketAddr> = {
            let connected = self.connected.lock().unwrap();
            self.book
                .lock()
                .unwrap()
                .iter()
                .filter(|a| **a != self.self_addr && !connected.contains(*a))
                .copied()
                .collect()
        };
        let mut soonest: Option<(Instant, SocketAddr)> = None;
        for a in known {
            if self.is_banned(&a) {
                continue;
            }
            let until = {
                let b = self.dial_backoff.lock().unwrap();
                b.get(&a).map(|(_, u)| *u).unwrap_or(now2)
            };
            if soonest.as_ref().is_none_or(|(best, _)| until < *best) {
                soonest = Some((until, a));
            }
        }
        soonest.map(|(_, a)| vec![a]).unwrap_or_default()
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
        // Port 0 means "do not record me". Peers reject a gossiped address with
        // port 0 as unroutable, which is exactly the behaviour an ephemeral node
        // wants: connect, sync, disappear without leaving a dead entry behind.
        let port = if self.ephemeral { 0 } else { self.self_addr.port() };
        Wire::Version(self.magic, self.genesis, port, self.self_nonce)
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
            // Err, not Ok. The dialer releases its reservation only on an
            // error, so returning Ok here left `mark_connected(addr)` standing
            // forever: the address dropped out of the dial candidates for the
            // life of the process and was never retried, *including after the
            // ban expired*. A temporary ban became a permanent inability to
            // reconnect to that peer.
            //
            // Seen on the testnet: a node banned its only LAN seed during a
            // period of chain divergence, then sat at zero peers indefinitely,
            // still dutifully dialing two unreachable public seeds — because
            // those failed at TCP and so took the path that does unmark.
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "peer is banned"));
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
    thread::spawn(move || {
        // Say once, at startup, what this node intends to do. A node that ends
        // up with no peers otherwise gives an operator nothing at all to work
        // with: "dialing and failing" and "never dialing" look identical from
        // the outside, and the difference is the whole diagnosis.
        eprintln!(
            "connection manager: want {} outbound, {} address(es) known",
            disc.target_outbound,
            disc.book_len()
        );
        let mut quiet_rounds = 0u32;
        loop {
        let connected = disc.connected_count();
        let need = disc.target_outbound.saturating_sub(connected);
        let candidates = if need > 0 { disc.dial_candidates() } else { Vec::new() };

        // The case that cost hours: wanting peers, having none, and dialing
        // nobody — because every address we know is already reserved, banned,
        // or absent. Silence here is indistinguishable from a working node, so
        // it must not be silent.
        if need > 0 && candidates.is_empty() {
            quiet_rounds += 1;
            if quiet_rounds == 1 || quiet_rounds % 20 == 0 {
                eprintln!(
                    "connection manager: want {need} more peer(s) but have no address to dial                      ({} known, {connected} reserved/connected) — check --seed/--peer and peers.dat",
                    disc.book_len()
                );
            }
        } else {
            quiet_rounds = 0;
        }

        if need > 0 {
            for addr in candidates.into_iter().take(need) {
                disc.mark_connected(addr); // reserve so we don't double-dial
                let state = Arc::clone(&state);
                let peers = peers.clone();
                let disc = disc.clone();
                thread::spawn(move || {
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                        Ok(s) => {
                            // Reaching the host is what clears the slate. The
                            // session may still be refused (banned, wrong
                            // network); that is not the address being dead.
                            disc.note_dial_success(addr);
                            if let Err(e) = register_connection(s, &state, &peers, &disc, Some(addr)) {
                                eprintln!("dial {addr}: connected but could not register: {e}");
                                disc.unmark(&addr);
                            }
                        }
                        // A failed dial is ordinary — a peer may simply be down —
                        // but it must be *visible*, or a node that can reach
                        // nobody looks exactly like one that never tried. It
                        // also has to cost the address its place in the queue,
                        // or dead hosts occupy every slot forever.
                        Err(e) => {
                            eprintln!("dial {addr}: {e}");
                            disc.note_dial_failure(addr);
                            disc.unmark(&addr);
                        }
                    }
                });
            }
        }
        // Ask a peer for more addresses to widen the book over time, and persist
        // the book so these peers are remembered across restarts.
        peers.send_to_one(&Wire::GetPeers);
        disc.save();
        thread::sleep(MANAGER_INTERVAL);
        }
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

/// A reservation must always be released, or an address silently leaves the
/// dial set forever.
///
/// The dialer calls `mark_connected(addr)` *before* connecting, so two dials
/// cannot race for the same peer, and relies on the error path to undo it. Any
/// outcome that skips that undo removes the address from `dial_candidates` for
/// the life of the process — no retry, no log, no symptom except a peer count
/// that never rises.
///
/// Found on the testnet: a node banned its only LAN seed during a period of
/// chain divergence and then sat at zero peers indefinitely, still dialing two
/// unreachable public seeds. Those kept being retried only because they failed
/// at TCP, which does unmark; the reachable one had taken the banned path,
/// which returned `Ok` and did not.
#[cfg(test)]
mod dial_reservation_tests {
    use super::*;

    fn disc() -> Discovery {
        Discovery::new("0.0.0.0:19333".parse().unwrap(), [0u8; 32], 1, 8)
    }

    /// A reserved address is not offered again — that is the point of reserving.
    #[test]
    fn a_reservation_removes_an_address_from_the_dial_set() {
        let d = disc();
        let a: SocketAddr = "10.0.0.5:19333".parse().unwrap();
        d.learn([a]);
        assert!(d.dial_candidates().contains(&a));
        d.mark_connected(a);
        assert!(!d.dial_candidates().contains(&a), "a reserved address must not be dialed twice");
    }

    /// And releasing it puts the address back. Without this the node quietly
    /// loses the ability to ever reach that peer again.
    #[test]
    fn releasing_a_reservation_restores_the_address() {
        let d = disc();
        let a: SocketAddr = "10.0.0.5:19333".parse().unwrap();
        d.learn([a]);
        d.mark_connected(a);
        d.unmark(&a);
        assert!(
            d.dial_candidates().contains(&a),
            "an address must return to the dial set once its reservation ends"
        );
    }

    /// The specific regression: `register_connection` on a banned peer must
    /// report an error, because that is the only signal the dialer acts on to
    /// release the reservation it took.
    #[test]
    fn a_banned_peer_reports_an_error_so_its_reservation_is_released() {
        use std::net::{TcpListener, TcpStream};
        let d = disc();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");

        // Ban the address the ACCEPTED socket actually reports, which is the
        // client's ephemeral port — not the listener's. Loopback bans are keyed
        // by full address including port (so local test nodes do not ban each
        // other wholesale), and getting this wrong makes the test pass or fail
        // for reasons unrelated to what it checks.
        let seen = accepted.peer_addr().expect("peer addr");
        d.ban(seen);
        assert!(d.is_banned(&seen), "test setup: the peer must be banned");
        let acct = noct_core::keys::Account::random(&mut rand_core::OsRng);
        let miner = noct_core::address::Address::new(
            noct_core::address::Network::Testnet,
            acct.spend_public,
            acct.view_public,
        );
        let state = Arc::new(Mutex::new(NodeState::for_network(
            noct_core::address::Network::Testnet,
            miner,
        )));
        let peers = Peers::default();
        let result = register_connection(accepted, &state, &peers, &d, Some(addr));
        assert!(
            result.is_err(),
            "a banned peer must return Err — returning Ok leaks the dialer's reservation \
             and the address is never dialed again"
        );
        drop(stream);
    }
}

/// Unreachable addresses must not be able to occupy every outbound slot.
///
/// Observed on the testnet: a node dialing eight addresses on eight slots, six
/// of them dead GitHub Actions runners learned by gossip from the daily join
/// test. The one peer that actually worked never got a slot, and the node sat
/// at zero peers while the addresses it needed sat untried in its book.
#[cfg(test)]
mod dial_backoff_tests {
    use super::*;

    fn disc() -> Discovery {
        Discovery::new("0.0.0.0:19333".parse().unwrap(), [0u8; 32], 1, 8)
    }
    fn a(n: u8) -> SocketAddr {
        format!("10.0.0.{n}:19333").parse().unwrap()
    }

    /// The core property: a failing address steps aside so a working one can be
    /// tried. Slots are the scarce resource, not book entries.
    #[test]
    fn a_failed_address_frees_its_slot() {
        let d = disc();
        let dead = a(1);
        let good = a(2);
        d.learn([dead, good]);
        assert!(d.dial_candidates().contains(&dead));

        d.note_dial_failure(dead);
        let c = d.dial_candidates();
        assert!(!c.contains(&dead), "a just-failed address must not be retried immediately");
        assert!(c.contains(&good), "the working address must still be offered");
    }

    /// Backoff, not eviction. The address stays in the book, because removing
    /// addresses on failure would let an attacker induce failures against
    /// honest peers and erase them — the shape of an eclipse attack.
    #[test]
    fn a_failed_address_is_held_back_not_forgotten() {
        let d = disc();
        let dead = a(1);
        d.learn([dead]);
        for _ in 0..5 {
            d.note_dial_failure(dead);
        }
        assert!(
            d.book.lock().unwrap().contains(&dead),
            "the address must remain known; failure is not proof it is worthless"
        );
    }

    /// Reaching a host clears its history, so one bad spell does not haunt a
    /// peer that has come back. Two addresses, so the held-back one has an
    /// alternative and the backoff is actually observable.
    #[test]
    fn success_clears_the_penalty() {
        let d = disc();
        let peer = a(1);
        let other = a(2);
        d.learn([peer, other]);
        d.note_dial_failure(peer);
        assert!(!d.dial_candidates().contains(&peer), "held back while an alternative exists");
        d.note_dial_success(peer);
        assert!(
            d.dial_candidates().contains(&peer),
            "a reachable peer must be immediately eligible again"
        );
    }

    /// Backoff must never leave the node with nothing to do.
    ///
    /// A node with no peers and no address to try does nothing at all — which
    /// is the very starvation backoff was added to escape. Seen in practice: a
    /// node reporting "14 known, no address to dial" while idle at zero peers,
    /// because a subnet fault had timed out its good LAN peers alongside the
    /// genuinely dead ones. So when everything is held back, the one closest to
    /// eligible is offered anyway.
    #[test]
    fn something_is_always_offered_even_when_all_are_backed_off() {
        let d = disc();
        for n in 1..=5u8 {
            d.learn([a(n)]);
            d.note_dial_failure(a(n));
        }
        let c = d.dial_candidates();
        assert_eq!(c.len(), 1, "exactly one fallback candidate, not the whole dead book");
        assert!(c[0] >= a(1) && c[0] <= a(5));
    }

    /// And the fallback picks the one whose penalty expires soonest, not an
    /// arbitrary address — fewest failures means most likely to work.
    #[test]
    fn the_fallback_prefers_the_least_penalised_address() {
        let d = disc();
        let mild = a(1);
        let hopeless = a(2);
        d.learn([mild, hopeless]);
        d.note_dial_failure(mild);
        for _ in 0..6 {
            d.note_dial_failure(hopeless);
        }
        let c = d.dial_candidates();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], mild, "the least-penalised address should be retried first");
    }

    /// Cleanest record first: a slot spent on a never-failed address beats one
    /// spent on an address that has failed repeatedly and merely aged out.
    #[test]
    fn never_failed_addresses_are_tried_first() {
        let d = disc();
        let flaky = a(1);
        let fresh = a(2);
        d.learn([flaky, fresh]);
        // Age the flaky one out of its backoff by hand, so both are eligible.
        d.note_dial_failure(flaky);
        d.dial_backoff.lock().unwrap().insert(flaky, (3, Instant::now() - Duration::from_secs(1)));

        let c = d.dial_candidates();
        assert_eq!(c.len(), 2, "both are eligible");
        assert_eq!(c[0], fresh, "the address with no failures must be tried first");
    }

    /// And the whole point, end to end: enough dead addresses must not starve a
    /// live one of a slot.
    #[test]
    fn dead_addresses_cannot_crowd_out_a_live_peer() {
        let d = disc();
        let live = a(200);
        // Eight dead addresses — exactly the outbound target — plus one live.
        for n in 1..=8u8 {
            d.learn([a(n)]);
            d.note_dial_failure(a(n));
        }
        d.learn([live]);
        let c = d.dial_candidates();
        assert!(c.contains(&live), "the live peer must get a slot");
        assert_eq!(c.len(), 1, "the dead addresses must all be held back, got {c:?}");
    }
}

/// A node that will never be reachable again must not leave a permanent dead
/// entry in every peer's address book.
///
/// The daily CI join test dials the seeds from a fresh GitHub Actions runner.
/// Each run put that runner's address into the network's books by gossip, the
/// runner vanished minutes later, and the address stayed forever — until six of
/// them filled every outbound dial slot and a node could reach nobody.
#[cfg(test)]
mod ephemeral_node_tests {
    use super::*;

    fn disc(ephemeral: bool) -> Discovery {
        Discovery::new("0.0.0.0:19333".parse().unwrap(), [0u8; 32], 1, 8).ephemeral(ephemeral)
    }

    fn advertised_port(d: &Discovery) -> u16 {
        match d.version() {
            Wire::Version(_, _, port, _) => port,
            other => panic!("version() must produce a Version message, got {other:?}"),
        }
    }

    /// An ordinary node advertises where it can be reached.
    #[test]
    fn a_normal_node_advertises_its_listen_port() {
        assert_eq!(advertised_port(&disc(false)), 19333);
    }

    /// An ephemeral one advertises nothing.
    #[test]
    fn an_ephemeral_node_advertises_no_port() {
        assert_eq!(
            advertised_port(&disc(true)),
            0,
            "port 0 is the existing 'unroutable, do not record me' signal"
        );
    }

    /// And the receiving side must genuinely discard it — otherwise advertising
    /// 0 would just create a differently-broken entry.
    #[test]
    fn a_peer_does_not_record_an_ephemeral_address() {
        let peer = disc(false);
        let ephemeral_addr: SocketAddr = "203.0.113.9:0".parse().unwrap();
        peer.learn_gossip_from(Some("8.8.8.8".parse().unwrap()), [ephemeral_addr]);
        assert!(
            !peer.book.lock().unwrap().contains(&ephemeral_addr),
            "an address with no listen port must never enter the book"
        );
    }
}

/// Hostile traffic against a **running** node.
///
/// The unit tests elsewhere check rejection logic in isolation; the testnet has
/// exercised the cooperative path across tens of thousands of transactions.
/// Neither answers the question these do: does a live node, reachable over a
/// real socket, survive someone actively trying to break it?
///
/// Every bug found on this network so far came from an accident — a migration,
/// a restart, an OOM. Accidents found six. It would be strange if deliberate
/// hostility found none.
///
/// Each test asserts the node is **still serving afterwards**, because a node
/// that rejects an attack and then dies has not defended anything.
#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use noct_core::address::{Address, Network};
    use rand_core::OsRng;
    use std::io::Write;

    /// Start a real node on a loopback port and return its address.
    fn victim() -> SocketAddr {
        let acct = noct_core::keys::Account::random(&mut OsRng);
        let miner = Address::new(Network::Testnet, acct.spend_public, acct.view_public);
        let state = Arc::new(Mutex::new(NodeState::for_network(Network::Testnet, miner)));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let genesis = { state.lock().unwrap().chain.genesis_id() };
        let magic = { state.lock().unwrap().chain.params().p2p_magic };
        let disc = Discovery::new(addr, genesis, magic, 8);
        spawn_listener(listener, state, Peers::default(), disc);
        addr
    }

    /// Is the node still accepting connections?
    fn still_alive(addr: SocketAddr) -> bool {
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
    }

    /// Raw bytes, bypassing every encoder — an attacker is not obliged to use
    /// our framing helpers.
    fn raw(addr: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        s.set_write_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(bytes)?;
        let _ = s.flush();
        Ok(())
    }

    /// A length prefix claiming an enormous body must not make the node try to
    /// allocate it. This is the cheapest denial of service there is: four bytes.
    #[test]
    fn a_huge_length_prefix_does_not_kill_the_node() {
        let addr = victim();
        for len in [u32::MAX, u32::MAX - 1, 1 << 30, 1 << 24] {
            let _ = raw(addr, &len.to_le_bytes());
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(still_alive(addr), "a 4-byte length prefix must not take the node down");
    }

    /// A frame that promises more than it delivers, then goes silent. The node
    /// must not wait on it forever holding a connection slot.
    #[test]
    fn a_truncated_frame_does_not_wedge_the_node() {
        let addr = victim();
        for _ in 0..20 {
            let mut msg = 4096u32.to_le_bytes().to_vec();
            msg.extend_from_slice(&[0xAB; 16]); // promises 4096, sends 16
            let _ = raw(addr, &msg);
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(still_alive(addr), "truncated frames must not wedge the listener");
    }

    /// Pure garbage, at every length that might trip a parser boundary.
    #[test]
    fn random_garbage_is_survived() {
        let addr = victim();
        for n in [0usize, 1, 3, 4, 5, 63, 64, 65, 255, 256, 1023, 4096] {
            let body: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            let mut msg = (n as u32).to_le_bytes().to_vec();
            msg.extend_from_slice(&body);
            let _ = raw(addr, &msg);
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(still_alive(addr), "garbage of any length must be survived");
    }

    /// Connect and say nothing at all. Idle sockets are free for an attacker
    /// and expensive for the node — this is the shape of F31.
    #[test]
    fn many_silent_connections_do_not_exhaust_the_node() {
        let addr = victim();
        let mut held = Vec::new();
        for _ in 0..64 {
            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                held.push(s);
            }
        }
        assert!(
            still_alive(addr),
            "the node must still accept an honest peer while 64 silent sockets are held"
        );
        drop(held);
    }

    /// A peer from another network must be dropped, and dropping it must not
    /// cost the node anything lasting.
    #[test]
    fn a_foreign_network_peer_is_refused_without_damage() {
        let addr = victim();
        for _ in 0..10 {
            if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                let wrong = Wire::Version(0xDEADBEEF, [9u8; 32], 19333, 12345);
                let _ = send_message(&mut s, &wrong);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(still_alive(addr), "foreign-network handshakes must be cheap to refuse");
    }

    /// The right magic but a foreign genesis — a peer on a different chain that
    /// otherwise looks correct.
    #[test]
    fn a_foreign_genesis_peer_is_refused_without_damage() {
        let addr = victim();
        let magic = noct_core::params::TESTNET.p2p_magic;
        for _ in 0..10 {
            if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                let _ = send_message(&mut s, &Wire::Version(magic, [0x77u8; 32], 19333, 999));
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(still_alive(addr), "a foreign chain must be refused without damage");
    }

    /// Connect and immediately vanish, repeatedly. Each one costs the node a
    /// registry entry and a socket; leaking either is how a node is exhausted
    /// for free.
    #[test]
    fn connect_and_drop_storms_are_survived() {
        let addr = victim();
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                drop(s);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
        assert!(still_alive(addr), "200 connect-and-drop cycles must leave the node serving");
    }
}

/// Can a hostile peer fill our address book with junk?
///
/// This is the eclipse question. `learn()` inserts only while the book is under
/// `MAX_BOOK`, and drops new addresses once it is full. That refusal is
/// deliberate — it stops a flood *evicting* honest peers — but it has a mirror
/// image: if an attacker fills the book first, the node can never learn a real
/// peer afterwards.
#[cfg(test)]
mod book_flooding_tests {
    use super::*;

    fn disc() -> Discovery {
        Discovery::new("0.0.0.0:19333".parse().unwrap(), [0u8; 32], 1, 8)
    }

    /// Flood the book from a single hostile peer, then try to learn an honest
    /// address. If the honest one cannot get in, the node is eclipsed by a peer
    /// that only had to talk.
    #[test]
    fn a_flood_of_junk_can_shut_out_honest_addresses() {
        let d = disc();
        let attacker: std::net::IpAddr = "8.8.8.8".parse().unwrap();

        // Routable, well-formed, and entirely useless: exactly what gossip
        // accepts. Enough to exceed MAX_BOOK.
        let junk: Vec<SocketAddr> = (0..(MAX_BOOK + 200))
            .map(|i| {
                let a = 11 + (i / 65536) as u8;
                let b = ((i / 256) % 256) as u8;
                let c = (i % 256) as u8;
                format!("{a}.{b}.{c}.1:19333").parse().unwrap()
            })
            .collect();
        d.learn_gossip_from(Some(attacker), junk);

        let honest: SocketAddr = "93.184.216.34:19333".parse().unwrap();
        d.learn_gossip_from(Some("1.1.1.1".parse().unwrap()), [honest]);

        let honest_in = d.book.lock().unwrap().contains(&honest);
        println!("book_len={} honest_learned={}", d.book_len(), honest_in);

        assert!(
            d.book_len() <= MAX_BOOK_PER_SOURCE + 1,
            "one source must not exceed its quota; book holds {}",
            d.book_len()
        );
        assert!(
            honest_in,
            "an honest address must remain learnable after a flood, or one peer that              merely talks has eclipsed us"
        );
    }

    /// The quota is per source, so honest peers are not collectively punished
    /// for one attacker: many distinct sources can still fill the book.
    #[test]
    fn distinct_sources_can_still_fill_the_book() {
        let d = disc();
        for src in 1..=20u8 {
            let from: std::net::IpAddr = format!("8.8.8.{src}").parse().unwrap();
            let addrs: Vec<SocketAddr> = (0..MAX_BOOK_PER_SOURCE)
                .map(|i| {
                    let b = ((i / 256) % 256) as u8;
                    let c = (i % 256) as u8;
                    format!("{}.{b}.{c}.1:19333", 100 + src).parse().unwrap()
                })
                .collect();
            d.learn_gossip_from(Some(from), addrs);
        }
        assert!(
            d.book_len() > MAX_BOOK_PER_SOURCE * 4,
            "many honest sources must together contribute far more than one quota, got {}",
            d.book_len()
        );
    }

    /// The operator's own configuration must survive a flood. A node told
    /// explicitly where to connect should never lose that to gossip.
    #[test]
    fn a_configured_seed_survives_a_flood() {
        let d = disc();
        let seed: SocketAddr = "10.10.10.240:19333".parse().unwrap();
        d.learn([seed]); // as --seed does, at startup

        let junk: Vec<SocketAddr> = (0..(MAX_BOOK + 200))
            .map(|i| {
                let b = ((i / 256) % 256) as u8;
                let c = (i % 256) as u8;
                format!("77.{b}.{c}.1:19333").parse().unwrap()
            })
            .collect();
        d.learn_gossip_from(Some("8.8.8.8".parse().unwrap()), junk);

        assert!(
            d.book.lock().unwrap().contains(&seed),
            "a configured seed must never be displaced by gossip"
        );
    }
}
