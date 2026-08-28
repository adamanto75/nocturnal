//! Minimal HTTP/JSON-RPC for the node — no framework, no async, no serde.
//!
//! Endpoints:
//! * `GET  /info`             — chain summary
//! * `GET  /height`           — current height
//! * `POST /submit_tx`        — body = hex of a wire-encoded transaction; relays it
//! * `POST /mine`             — mine one block and broadcast it (dev/testnet convenience)
//! * `GET  /getblocktemplate` — an unmined block template for an external miner
//! * `POST /submitblock`      — body = hex of a solved wire-encoded block; accepts + relays it
//!
//! Responses are small hand-formatted JSON objects. This is deliberately tiny;
//! a production RPC would use a real HTTP stack.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;

use noct_tls::{Acceptor, Stream};
use std::time::{Duration, Instant};

use noct_core::address::Address;
use noct_core::block::Block;
use noct_core::p2p::Wire;
use noct_core::tx::Transaction;
use noct_core::wire;
use rand_core::OsRng;

use crate::transport::Peers;
use crate::NodeState;

/// Reject request bodies larger than this.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// How long a connection may sit without progress before it is dropped. Ample
/// for a slow client submitting a large block; short enough that an idle socket
/// cannot squat on a worker thread indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Default refill rate, in cost units per second (see [`request_cost`]). Sized
/// well above real load: a miner running flat out against a low-difficulty chain
/// was measured at ~28 blocks/s ≈ 56 requests/s ≈ 560 units/s, and ordinary
/// wallet polling is a couple of units per second. It still bounds a flood.
pub const DEFAULT_RPC_RATE: u32 = 2_000;

/// How many IPs the limiter tracks before it prunes. The map is keyed by
/// attacker-chosen source addresses, so it must be bounded or the limiter would
/// itself be a memory-exhaustion vector.
const MAX_TRACKED_CLIENTS: usize = 4_096;

/// Which address to hold responsible for a request.
///
/// Normally the socket's peer. But a server behind a TLS-terminating reverse
/// proxy sees *every* client as the proxy, and the per-IP rate limiter would
/// then meter everyone through a single bucket — turning a protection into an
/// outage as soon as there is more than a handful of traffic.
///
/// `X-Forwarded-For` fixes that, and is a gaping hole if believed
/// indiscriminately: any client could put a fresh fake address in the header on
/// every request and give itself an unlimited number of rate-limit buckets,
/// which is precisely the exhaustion the limiter exists to prevent. So it is
/// honoured **only** from an address the operator explicitly listed as trusted,
/// and ignored from everyone else.
///
/// The **last** entry is taken, not the first. A proxy appends the address it
/// saw; anything to the left of that was supplied by the client and is
/// unverifiable. With one proxy in front — the deployment this supports — the
/// last entry is the real peer.
///
/// Shared by every public-facing Noct server (the pool and the website), because
/// a subtly different second copy of this function is how one of them ends up
/// trusting a header it should not.
pub fn client_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted: &HashSet<IpAddr>,
) -> Option<IpAddr> {
    let peer = peer?;
    if !trusted.contains(&peer) {
        return Some(peer);
    }
    forwarded_for
        .and_then(|v| v.rsplit(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or(Some(peer))
}

/// Cost of serving a request, in rate-limit units.
///
/// Endpoints that take the consensus lock and do elliptic-curve or validation
/// work are far more expensive to serve than a status read, and are the actual
/// denial-of-service lever — so they cost proportionally more. A client can make
/// ~200 template requests per second at the default rate, but ~2000 status reads.
fn request_cost(method: &str, path: &str) -> u32 {
    // Strip any query defensively. Routing already passes a clean path, but this
    // function decides how much an endpoint costs to serve, and under-charging an
    // expensive one is a denial-of-service hole rather than a cosmetic slip. It
    // must be correct for whatever it is handed, not only for today's caller.
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        // Builds a coinbase (elliptic-curve work) and selects mempool
        // transactions, all under the consensus lock.
        (_, "/getblocktemplate") => 10,
        // Full block validation, then a flood to peers.
        ("POST", "/submitblock") | ("POST", "/mine") => 10,
        // Full transaction validation (range proof + ring signatures).
        ("POST", "/submit_tx") => 10,
        // Serialises a stored block.
        (_, p) if p.starts_with("/block/") => 2,
        // Status reads: a lock and some formatting.
        _ => 1,
    }
}

/// A refilling token bucket for one client.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-source-IP request limiting, so no single client — even an authenticated
/// one — can monopolise the consensus lock through the expensive endpoints.
pub struct RateLimiter {
    /// Units refilled per second. `0` disables limiting.
    rate: u32,
    /// Maximum units a client may bank, i.e. its burst allowance.
    burst: u32,
    clients: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// A limiter refilling `rate` units per second, allowing a burst of twice
    /// that. `rate == 0` disables limiting.
    pub fn new(rate: u32) -> Self {
        RateLimiter {
            rate,
            burst: rate.saturating_mul(2),
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Charge `cost` units to `ip`, returning false when it has run out.
    ///
    /// Public so the mining pool can reuse this limiter with its own costs —
    /// duplicating a token bucket is how two implementations drift apart, and the
    /// bounded-table behaviour here is the part that matters.
    pub fn allow(&self, ip: IpAddr, cost: u32) -> bool {
        if self.rate == 0 {
            return true;
        }
        let now = Instant::now();
        let mut clients = self.clients.lock().unwrap();

        if clients.len() >= MAX_TRACKED_CLIENTS {
            Self::prune(&mut clients, self.rate, self.burst, now);
        }

        let burst = self.burst as f64;
        let bucket = clients.entry(ip).or_insert(Bucket { tokens: burst, last: now });
        // Refill for the time elapsed since this client was last seen.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate as f64).min(burst);
        bucket.last = now;

        if bucket.tokens >= cost as f64 {
            bucket.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    /// Bound the tracking map.
    ///
    /// A bucket that has refilled to full is indistinguishable from an untracked
    /// client — both start with a full allowance — so dropping full buckets is
    /// free and cannot be used to evade the limit. Only if that is not enough do
    /// we evict the *least* rate-limited client still tracked, which is the
    /// entry with the least state worth keeping.
    fn prune(clients: &mut HashMap<IpAddr, Bucket>, rate: u32, burst: u32, now: Instant) {
        let burst_f = burst as f64;
        clients.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens + elapsed * (rate as f64) < burst_f
        });
        while clients.len() >= MAX_TRACKED_CLIENTS {
            let Some(&victim) = clients
                .iter()
                .max_by(|a, b| a.1.tokens.partial_cmp(&b.1.tokens).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(ip, _)| ip)
            else {
                break;
            };
            clients.remove(&victim);
        }
    }
}

/// Compare two byte strings without an early exit, so the number of matching
/// leading bytes cannot be recovered by timing the response. (Lengths are not
/// hidden, which is standard and harmless for a fixed-length token.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Does this request carry the configured bearer token? Always true when no
/// token is configured (only reachable on a loopback bind — see `run`).
fn authorized(token: &Option<String>, header: Option<&str>) -> bool {
    let Some(expected) = token else {
        return true;
    };
    let Some(value) = header else {
        return false;
    };
    // `Bearer <token>`, case-insensitive scheme.
    let value = value.trim();
    let Some((scheme, presented)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    constant_time_eq(presented.trim().as_bytes(), expected.as_bytes())
}

/// Serve RPC on `listener` until the process exits. When `token` is set, every
/// request must present it as `Authorization: Bearer <token>`.
///
/// With an `acceptor`, the RPC is served over TLS. That matters for any node
/// answering off-box: the bearer token above is sent on **every** request, so in
/// plaintext one observation of one request hands an attacker the node's entire
/// RPC — and a wallet's queries reveal exactly the activity Noct exists to keep
/// private.
pub fn serve(
    listener: TcpListener,
    state: Arc<Mutex<NodeState>>,
    peers: Peers,
    token: Option<String>,
    rate: u32,
    acceptor: Option<Acceptor>,
) {
    let token = Arc::new(token);
    let limiter = Arc::new(RateLimiter::new(rate));
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            // Bound how long a connection may sit without progress. The per-IP
            // rate limiter is consulted only after a full request head has been
            // read, so a client that opens a socket and never finishes its
            // request never reaches the limiter and holds a thread for free.
            let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
            let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));

            // The session is created here but its handshake runs on the worker
            // thread, on first read — doing it inline would let one slow client
            // stall everything else waiting to be accepted.
            let stream = match &acceptor {
                Some(a) => match a.accept(tcp) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                None => Stream::Plain(tcp),
            };
            let state = Arc::clone(&state);
            let peers = peers.clone();
            let token = Arc::clone(&token);
            let limiter = Arc::clone(&limiter);
            thread::spawn(move || {
                let _ = handle_client(stream, state, peers, token, limiter);
            });
        }
    });
}

fn handle_client(
    stream: Stream,
    state: Arc<Mutex<NodeState>>,
    peers: Peers,
    token: Arc<Option<String>>,
    limiter: Arc<RateLimiter>,
) -> std::io::Result<()> {
    // Identify the client before anything else, for rate limiting. An address we
    // cannot read cannot be limited, so treat it as unspecified and bill it to a
    // single shared bucket rather than exempting it.
    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    // One object for both directions: a TLS session cannot be `try_clone`d the
    // way a bare socket can, because the two halves share the connection's
    // cryptographic state. `reader.get_mut()` reaches the stream to write the
    // reply, which is safe here because every response is `Connection: close`
    // and nothing is read after it.
    let mut reader = BufReader::new(stream);

    // Request line: "METHOD PATH HTTP/1.1".
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();

    // Split the query off ONCE, and route on the path alone.
    //
    // These were previously matched together, so every arm had to remember to
    // accept its own query string. `/getblocktemplate` did; `/submitblock` did
    // not — and `noct-miner` always posts `/submitblock?address=...`, so every
    // solved block it submitted was answered with 404 and thrown away. External
    // mining had never once worked, and the symptom was a chain that simply
    // stopped advancing.
    //
    // Routing on the path makes that impossible to reintroduce for any future
    // endpoint rather than fixing the one that happened to be broken.
    let raw_target = parts.next().unwrap_or("").to_string();
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target.clone(), String::new()),
    };

    // Rate-limit before authenticating, so an unauthenticated flood is bounded
    // too — otherwise anyone able to reach the port could spend our CPU on
    // header parsing and 401s indefinitely.
    if !limiter.allow(client_ip, request_cost(&method, &path)) {
        return respond_with(
            reader.get_mut(),
            "429 Too Many Requests",
            "Retry-After: 1\r\n",
            "{\"error\":\"rate limited\"}",
        );
    }

    // Headers (Content-Length, and Authorization when a token is configured).
    let mut content_length = 0usize;
    let mut authorization: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if lower.starts_with("authorization:") {
            // Take the value from the original line — the token is case-sensitive.
            authorization = trimmed.splitn(2, ':').nth(1).map(|v| v.trim().to_string());
        }
    }
    if content_length > MAX_BODY {
        return respond(reader.get_mut(), "413 Payload Too Large", "{\"error\":\"body too large\"}");
    }

    // Authenticate before doing any work — including before reading the body, so
    // an unauthenticated client cannot make us buffer up to MAX_BODY bytes.
    if !authorized(&token, authorization.as_deref()) {
        return respond_with(
            reader.get_mut(),
            "401 Unauthorized",
            "WWW-Authenticate: Bearer\r\n",
            "{\"error\":\"unauthorized\"}",
        );
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/info") | ("GET", "/") => {
            let peer_count = peers.count();
            let node = state.lock().unwrap();
            let json = format!(
                "{{\"height\":{},\"outputs\":{},\"emitted\":{},\"cumulative_difficulty\":\"{}\",\"mempool\":{},\"peers\":{},\"tip\":\"{}\",\"pow\":\"{}\",\"stranded\":{}}}",
                node.height(),
                node.num_outputs(),
                node.emitted(),
                node.cumulative_difficulty(),
                node.mempool_len(),
                peer_count,
                hex::encode(node.tip_id()),
                // Which proof-of-work this binary was built with. A pool or miner
                // built against a different one re-hashes shares with a function
                // the chain does not use, so every share it validates is
                // meaningless — and the only symptom is "nothing gets accepted",
                // which looks like a network fault rather than a build mistake.
                // Publishing it lets a client refuse to start instead of guessing.
                crate::pow_name(),
                // Whether this node looks stranded on a fork it cannot leave.
                // The condition is permanent and its only other symptom is
                // being slow, so monitoring has to be able to see it without
                // anyone reading a log.
                node.reorgs_without_ancestor() >= 8,
            );
            respond(reader.get_mut(), "200 OK", &json)
        }
        ("GET", "/height") => {
            let node = state.lock().unwrap();
            respond(reader.get_mut(), "200 OK", &format!("{{\"height\":{}}}", node.height()))
        }
        // GET /block/{height} — hex of the wire-encoded block *and* its
        // transactions, so a syncing client can replay and validate history.
        ("GET", p) if p.starts_with("/block/") => {
            let height: u64 = match p.trim_start_matches("/block/").parse() {
                Ok(h) => h,
                Err(_) => return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"bad height\"}"),
            };
            let node = state.lock().unwrap();
            match node.chain.block_at(height) {
                Some(stored) => {
                    let msg = Wire::Block(stored.block.clone(), stored.txs.clone());
                    let data = hex::encode(wire::encode_message(&msg));
                    drop(node);
                    respond(
                        reader.get_mut(),
                        "200 OK",
                        &format!("{{\"height\":{height},\"data\":\"{data}\"}}"),
                    )
                }
                None => respond(reader.get_mut(), "404 Not Found", "{\"error\":\"no such block\"}"),
            }
        }
        ("POST", "/submit_tx") => {
            let hex_str = String::from_utf8_lossy(&body);
            let raw = match hex::decode(hex_str.trim()) {
                Ok(r) => r,
                Err(_) => return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"invalid hex\"}"),
            };
            let tx = match wire::decode_transaction(&raw) {
                Ok(tx) => tx,
                Err(_) => return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"invalid transaction\"}"),
            };
            let txid = hex::encode(tx.hash());
            // Fluff immediately (see transport.rs on deferred stem) so a locally
            // submitted transaction reliably reaches the network's mempools.
            let relay = {
                let mut node = state.lock().unwrap();
                node.originate_tx(&mut OsRng, tx, false)
            };
            let accepted = !matches!(relay, crate::Relay::Drop);
            peers.execute(relay);
            respond(
                reader.get_mut(),
                "200 OK",
                &format!("{{\"accepted\":{accepted},\"txid\":\"{txid}\"}}"),
            )
        }
        // GET /mining — current miner state for the wallet UI.
        ("GET", "/mining") => {
            let (control, height) = {
                let node = state.lock().unwrap();
                (node.mining_control(), node.height())
            };
            respond(
                reader.get_mut(),
                "200 OK",
                &format!(
                    "{{\"active\":{},\"threads\":{},\"hashrate\":{},\"blocks_found\":{},\"height\":{},\"pow\":\"{}\"}}",
                    control.is_active(),
                    control.threads(),
                    control.hashrate(),
                    control.blocks_found(),
                    height,
                    crate::pow_name(),
                ),
            )
        }
        // POST /mining/start [body: optional thread count] — begin mining.
        ("POST", "/mining/start") => {
            let control = { state.lock().unwrap().mining_control() };
            if let Ok(n) = String::from_utf8_lossy(&body).trim().parse::<usize>() {
                if n >= 1 {
                    control.set_threads(n);
                }
            }
            control.set_active(true);
            respond(
                reader.get_mut(),
                "200 OK",
                &format!("{{\"active\":true,\"threads\":{}}}", control.threads()),
            )
        }
        // POST /mining/stop — pause mining.
        ("POST", "/mining/stop") => {
            let control = { state.lock().unwrap().mining_control() };
            control.set_active(false);
            respond(reader.get_mut(), "200 OK", "{\"active\":false}")
        }
        // POST /mining/threads — body = worker thread count.
        ("POST", "/mining/threads") => {
            let control = { state.lock().unwrap().mining_control() };
            match String::from_utf8_lossy(&body).trim().parse::<usize>() {
                Ok(n) if n >= 1 => {
                    control.set_threads(n);
                    respond(reader.get_mut(), "200 OK", &format!("{{\"threads\":{}}}", control.threads()))
                }
                _ => respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"bad thread count\"}"),
            }
        }
        // GET /getblocktemplate[?address=B58] — an unmined block for an external
        // miner to grind. The coinbase pays `address` if given (else the node's
        // own miner address). The miner varies `header.nonce`, computes the PoW
        // hash (keyed to `seed_hash`), and submits the solved block to
        // /submitblock once it meets `difficulty`.
        ("GET", "/getblocktemplate") => {
            let address_param = query.split('&').find_map(|kv| kv.strip_prefix("address="));
            let address = match address_param {
                Some(a) => match Address::decode(a) {
                    Ok(addr) => Some(addr),
                    Err(_) => {
                        return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"invalid address\"}")
                    }
                },
                None => None,
            };
            let job = {
                let mut node = state.lock().unwrap();
                match &address {
                    Some(addr) => node.build_block_template_for(&mut OsRng, addr),
                    None => node.build_block_template(&mut OsRng),
                }
            };
            let height = job.block.coinbase.height;
            let reward = job.block.coinbase.total().unwrap_or(0);
            let seed = hex::encode(job.seed);
            let template = hex::encode(wire::encode_message(&Wire::Block(job.block, job.txs)));
            // `pow` is advertised so a miner can tell immediately that it is
            // hashing the same function we validate with. Without it, a
            // mismatched miner grinds forever and every submission comes back
            // "does not meet the target", which points at difficulty rather than
            // the real cause.
            respond(
                reader.get_mut(),
                "200 OK",
                &format!(
                    "{{\"height\":{height},\"difficulty\":{},\"seed_hash\":\"{seed}\",\"reward\":{reward},\"pow\":\"{}\",\"template\":\"{template}\"}}",
                    job.difficulty,
                    crate::pow_name(),
                ),
            )
        }
        // POST /submitblock — body = hex of a solved wire-encoded block (a
        // `Wire::Block` with the winning nonce). The node re-validates the PoW and
        // everything else, appends it, and relays it to peers.
        ("POST", "/submitblock") => {
            let hex_str = String::from_utf8_lossy(&body);
            let raw = match hex::decode(hex_str.trim()) {
                Ok(r) => r,
                Err(_) => return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"invalid hex\"}"),
            };
            let (block, txs) = match wire::decode_message(&raw) {
                Ok(Wire::Block(b, t)) => (b, t),
                _ => return respond(reader.get_mut(), "400 Bad Request", "{\"error\":\"invalid block\"}"),
            };
            let outcome: Result<(Block, Vec<Transaction>), &str> = {
                let mut node = state.lock().unwrap();
                if block.header.prev_id != node.tip_id() {
                    Err("stale") // the chain advanced while grinding
                } else {
                    node.submit_mined_block(&mut OsRng, block, txs).ok_or("invalid")
                }
            };
            match outcome {
                Ok((block, txs)) => {
                    let id = hex::encode(block.id());
                    let height = { state.lock().unwrap().height() };
                    peers.flood(&Wire::Block(block, txs));
                    respond(
                        reader.get_mut(),
                        "200 OK",
                        &format!("{{\"status\":\"accepted\",\"height\":{height},\"block\":\"{id}\"}}"),
                    )
                }
                Err(reason) => respond(
                    reader.get_mut(),
                    "200 OK",
                    &format!("{{\"status\":\"rejected\",\"reason\":\"{reason}\"}}"),
                ),
            }
        }
        ("POST", "/mine") => {
            let mined = {
                let mut node = state.lock().unwrap();
                node.mine_block(&mut OsRng)
            };
            match mined {
                Some((block, txs)) => {
                    let id = hex::encode(block.id());
                    let height = { state.lock().unwrap().height() };
                    peers.flood(&Wire::Block(block, txs));
                    respond(
                        reader.get_mut(),
                        "200 OK",
                        &format!("{{\"mined\":true,\"height\":{height},\"block\":\"{id}\"}}"),
                    )
                }
                None => respond(reader.get_mut(), "500 Internal Server Error", "{\"error\":\"mining failed\"}"),
            }
        }
        _ => respond(reader.get_mut(), "404 Not Found", "{\"error\":\"not found\"}"),
    }
}

fn respond(writer: &mut Stream, status: &str, body: &str) -> std::io::Result<()> {
    respond_with(writer, status, "", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_is_required_and_matched_exactly() {
        let token = Some("s3cret-token".to_string());

        // The exact token, in either header-scheme casing.
        assert!(authorized(&token, Some("Bearer s3cret-token")));
        assert!(authorized(&token, Some("bearer s3cret-token")));
        assert!(authorized(&token, Some("  Bearer   s3cret-token  ")));

        // Anything else is refused.
        assert!(!authorized(&token, None), "missing header");
        assert!(!authorized(&token, Some("")), "empty header");
        assert!(!authorized(&token, Some("s3cret-token")), "no scheme");
        assert!(!authorized(&token, Some("Basic s3cret-token")), "wrong scheme");
        assert!(!authorized(&token, Some("Bearer s3cret-toke")), "prefix of the token");
        assert!(!authorized(&token, Some("Bearer s3cret-token-extra")), "superstring");
        assert!(!authorized(&token, Some("Bearer S3CRET-TOKEN")), "token is case-sensitive");

        // With no token configured the RPC is open (only reachable on a
        // loopback bind — `run` refuses any other binding without a token).
        assert!(authorized(&None, None));
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn rate_limiter_allows_a_burst_then_refuses() {
        // rate 10/s ⇒ burst 20 units.
        let limiter = RateLimiter::new(10);
        let client = ip(1);
        for i in 0..20 {
            assert!(limiter.allow(client, 1), "unit {i} within the burst");
        }
        assert!(!limiter.allow(client, 1), "burst exhausted");

        // Buckets are per client: another IP is unaffected.
        assert!(limiter.allow(ip(2), 1), "a different client has its own bucket");
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new(1_000); // burst 2000
        let client = ip(3);
        assert!(limiter.allow(client, 2_000), "spend the whole burst at once");
        assert!(!limiter.allow(client, 1), "nothing left");

        std::thread::sleep(std::time::Duration::from_millis(50));
        // ~50 units should have refilled; ask for fewer to stay clear of timer slop.
        assert!(limiter.allow(client, 10), "bucket refills as time passes");
    }

    /// A query string must not change which endpoint is reached.
    ///
    /// `noct-miner` posts `/submitblock?address=...`. That used to miss the
    /// `("POST", "/submitblock")` arm entirely and 404, so every block it solved
    /// was discarded and external mining silently did nothing at all. Routing now
    /// happens on the path alone; this pins that.
    #[test]
    fn a_query_string_does_not_change_the_route() {
        let split = |t: &str| -> (String, String) {
            match t.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (t.to_string(), String::new()),
            }
        };

        for (target, expect_path) in [
            ("/submitblock?address=Xabc&worker=rig1", "/submitblock"),
            ("/submitblock", "/submitblock"),
            ("/getblocktemplate?address=Xabc", "/getblocktemplate"),
            ("/getblocktemplate", "/getblocktemplate"),
            ("/info?x=1", "/info"),
        ] {
            let (path, _q) = split(target);
            assert_eq!(path, expect_path, "`{target}` routed to `{path}`");
        }

        // And the query must still be readable where an endpoint needs it.
        let (_, q) = split("/getblocktemplate?address=Xabc&worker=rig1");
        assert_eq!(
            q.split('&').find_map(|kv| kv.strip_prefix("address=")),
            Some("Xabc")
        );

        // Cost must not collapse to the cheap default just because a query was
        // appended — that would make the expensive endpoints unmetered.
        assert_eq!(request_cost("POST", "/submitblock"), 10);
        assert_eq!(request_cost("GET", "/getblocktemplate"), 10);
    }

    #[test]
    fn expensive_endpoints_cost_more_than_status_reads() {
        assert!(request_cost("GET", "/getblocktemplate?address=x") > request_cost("GET", "/info"));
        assert_eq!(request_cost("POST", "/submitblock"), request_cost("POST", "/submit_tx"));
        assert_eq!(request_cost("GET", "/info"), 1);

        // A costly call drains proportionally more of the same bucket.
        let limiter = RateLimiter::new(10); // burst 20
        let client = ip(4);
        assert!(limiter.allow(client, request_cost("GET", "/getblocktemplate")));
        assert!(limiter.allow(client, request_cost("GET", "/getblocktemplate")));
        assert!(!limiter.allow(client, request_cost("GET", "/getblocktemplate")), "10+10 = the burst");
    }

    #[test]
    fn rate_limiter_is_disabled_when_rate_is_zero() {
        let limiter = RateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(limiter.allow(ip(5), 10));
        }
        assert!(limiter.clients.lock().unwrap().is_empty(), "disabled limiter tracks nothing");
    }

    #[test]
    fn client_table_stays_bounded_without_letting_limited_clients_escape() {
        // The map is keyed by attacker-chosen source addresses, so it must not
        // grow without bound — but pruning must not hand a rate-limited client a
        // fresh allowance either.
        let limiter = RateLimiter::new(1_000);
        let victim = ip(200);
        // Drain the victim so it is genuinely limited.
        assert!(limiter.allow(victim, 2_000));
        assert!(!limiter.allow(victim, 1_000), "victim is out of allowance");

        // Flood the table with many one-shot clients.
        for i in 0..(MAX_TRACKED_CLIENTS + 500) {
            let a = ((i >> 8) & 0xff) as u8;
            let b = (i & 0xff) as u8;
            limiter.allow(IpAddr::V4(std::net::Ipv4Addr::new(172, 16, a, b)), 1);
        }

        let tracked = limiter.clients.lock().unwrap().len();
        assert!(tracked <= MAX_TRACKED_CLIENTS, "table bounded (was {tracked})");
        // The still-limited client must not have been reset by pruning.
        assert!(!limiter.allow(victim, 1_000), "pruning must not restore a drained bucket");
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"), "length mismatch");
        assert!(constant_time_eq(b"", b""));
    }
}

/// `respond`, plus any extra headers (each `Name: value\r\n`-terminated).
fn respond_with(
    writer: &mut Stream,
    status: &str,
    extra_headers: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    writer.write_all(response.as_bytes())?;
    writer.flush()?;
    // Ends the TLS session properly, so the client can tell a complete reply
    // from a cut one instead of having to guess.
    writer.close();
    Ok(())
}
