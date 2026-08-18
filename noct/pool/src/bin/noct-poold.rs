//! `noct-poold` — a Noct mining pool daemon.
//!
//! It sits between miners and a node:
//!
//! * it polls the node for block templates paying the **pool's** address, and
//!   republishes them to miners at a much lower **share difficulty**;
//! * it validates every share by re-hashing it ([`noct_pool`]), crediting the
//!   miner's work in a PPLNS window;
//! * when a share also meets the real network difficulty it *is* a block, and
//!   the pool submits it to the node.
//!
//! ## It speaks the node's own miner API
//!
//! `/getblocktemplate` and `/submitblock` are deliberately the same shape the
//! node exposes, with `difficulty` set to the share target. An unmodified
//! [`noct-miner`] pointed at the pool therefore just works — the only difference
//! it sees is an easier target and a coinbase it doesn't own.
//!
//! ```text
//! noct-poold --address <POOL_B58> [--node URL] [--node-token-file PATH]
//!            [--listen HOST:PORT] [--share-difficulty N]
//!            [--tls-cert PATH --tls-key PATH] [--trusted-proxy IP,IP]
//! ```
//!
//! ## Transport security
//!
//! A public pool must not run in the clear. Everything a miner sends carries its
//! **payout address**, so plaintext hands any observer a map of who is mining
//! what — and hands anyone who can *modify* the traffic the ability to rewrite
//! that address and take the income, invisibly: the miner sees its shares
//! accepted and simply never gets paid.
//!
//! Two supported deployments:
//!
//! * `--tls-cert` / `--tls-key` — the pool terminates TLS itself. Use an
//!   ordinary certificate if the pool has a domain name; `--tls-generate` makes
//!   a self-signed one and prints the fingerprint for miners to pin.
//! * A TLS-terminating reverse proxy in front, with the pool bound to localhost.
//!   This needs `--trusted-proxy`, or the per-IP rate limiter sees every miner as
//!   the proxy and lumps them into one bucket.
//!
//! ## Scope
//!
//! Payouts are implemented (`--wallet`): matured rounds are credited to a
//! persistent ledger and settled in batched transactions once a miner clears the
//! payout threshold. A round is only credited once the chain has buried it by
//! `COINBASE_MATURITY`, since pool income is a coinbase output. Miner identity is
//! provisional: a miner is recognised by the payout address it supplies with its
//! work, which is right for *paying* it but is not authentication — a public pool
//! still wants per-miner credentials so one miner cannot claim another's name.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use noct_core::address::{Address, Network};
use noct_core::chain::COINBASE_MATURITY;
use noct_core::p2p::Wire;
use noct_core::pow::Difficulty;
use noct_core::tx::Payment;
use noct_core::wire;
use noct_node::rpc::{client_ip, RateLimiter};
use noct_node::{new_pow, pow_name, NodePow};
use noct_tls::{Acceptor, Endpoint, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};
use noct_pool::auth::{self, MinerAuth};
use noct_pool::payout::{self, PayoutLedger, FeeBps, FEE_BPS_MAX};
use noct_pool::vardiff::{self, VardiffParams};
use noct_pool::window_log::WindowLog;
use noct_pool::{JobId, Pool, ShareOutcome, DEFAULT_WINDOW};
use noct_wallet::client::{format_noct, load_account, load_synced_wallet, parse_noct, NodeClient};
use noct_wallet::DEFAULT_RING_SIZE;

/// How often to ask the node for a fresh template, so miners work on the
/// current tip and newly-arrived transactions.
const TEMPLATE_REFRESH: Duration = Duration::from_secs(5);

/// Default share target. Low enough that a modest miner produces shares
/// steadily (which is the point of a pool), far below any real network target.
const DEFAULT_SHARE_DIFFICULTY: Difficulty = 1_000;

const MAX_BODY: usize = 8 * 1024 * 1024;

// --- facing the internet ----------------------------------------------------
//
// A pool's miner port is unauthenticated by design — anonymous miners are the
// norm — which makes it the cheapest DoS surface in the system. The asymmetry is
// what matters: **the pool re-hashes every share it is sent**, and with RandomX
// that is on the order of a millisecond of CPU, while producing a bogus share
// costs the sender nothing. A few thousand junk submissions a second will
// saturate the pool while legitimate miners are starved of it.
//
// Two bounds close that: price a submission far above a cheap read, and cap how
// many connections can be in flight at once.

/// Default per-IP budget, in cost units per second. Sized so an honest miner at
/// a sane share rate never notices: a share costs [`COST_SUBMIT`], so this allows
/// roughly 20 shares/second/IP sustained, twice that in burst.
const DEFAULT_POOL_RATE: u32 = 1_000;

/// Submitting a share forces a proof-of-work verification — by far the most
/// expensive thing an anonymous caller can ask for.
const COST_SUBMIT: u32 = 50;
/// Handing out a template is cheap but not free (it clones the job).
const COST_TEMPLATE: u32 = 10;
/// Reads are nearly free.
const COST_READ: u32 = 1;

/// Maximum simultaneous miner connections. Each is a thread; without a cap an
/// attacker opens sockets until the process runs out of threads or memory.
/// Generous for a real pool, fatal for a socket flood.
const MAX_CONNECTIONS: usize = 512;

/// How long a connection may sit without progress before it is dropped. Ample
/// for a miner on a slow link submitting a share; short enough that an idle
/// socket cannot squat on a connection slot indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How often to mature rounds and pay out.
const PAYOUT_INTERVAL: Duration = Duration::from_secs(30);

/// Miners paid per transaction. One transaction pays many miners, so they share
/// a single fee — but a transaction's outputs are capped by the aggregate range
/// proof, and one slot must be left for change.
const MAX_PAYOUTS_PER_TX: usize = 8;

/// The node this pool mines against, and how it verifies it.
#[derive(Clone)]
struct NodeLink {
    endpoint: Endpoint,
    /// Certificate to accept, for a node with a self-signed one.
    pin: Option<[u8; 32]>,
}

/// A miner's current share target and the timing behind it.
///
/// `previous` exists for a race the miner cannot avoid: it may already be
/// grinding on the target it was last issued when we retune. Rejecting that work
/// would punish a miner for our own adjustment, so a share is accepted if it
/// meets **either** target, and credited at whichever it actually met.
struct Assignment {
    current: Difficulty,
    previous: Difficulty,
    /// When this miner's last accepted share arrived, for measuring its rate.
    last_share: Option<std::time::Instant>,
    /// Smoothed interval between its shares, in seconds.
    ewma_secs: f64,
    /// Rejections in a row, reset by any accepted share.
    ///
    /// A rig whose every submission is refused is burning real electricity for
    /// no credit, and it cannot tell: from the miner's side the pool is
    /// answering normally. Observed live — two rigs at ~99% CPU for 45 minutes
    /// with every share rejected, while the only outward sign was a share count
    /// that had quietly stopped moving.
    rejected_streak: u32,
    /// Why the run of rejections is happening, so the warning can say.
    last_rejection: &'static str,
}

struct Shared {
    pool: Pool<NodePow>,
    /// Per-miner share targets ("vardiff"). A single fixed target either floods
    /// the pool with a fast rig's shares — spending its rate-limit budget while
    /// behaving honestly — or leaves a slow rig unable to find one at all.
    assignments: HashMap<String, Assignment>,
    /// Payout address each source IP last asked to be paid at. Provisional
    /// identity — see the module note.
    miners: HashMap<IpAddr, String>,
    /// Blocks this pool has found.
    blocks_found: u64,
    /// Most recent job, so miners fetching work all get the current one.
    current_job: Option<JobId>,
    /// Height the current job builds on, for reporting.
    height: u64,
    /// Who is owed what, and what has already been sent.
    ledger: PayoutLedger,
    /// Durable record of the PPLNS window, so a restart does not forfeit
    /// credit miners have already earned.
    window_log: WindowLog,
    /// Work per *session* (payout address plus worker name), for `/stats` only.
    /// Payment is decided entirely by `pool.weights()`; this exists so someone
    /// running several rigs under one address can tell them apart.
    worker_work: HashMap<String, u128>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // A one-shot utility, handled before anything else needs configuring: an
    // operator with no domain name has no other easy way to obtain a PEM pair,
    // and "no easy way" reliably turns into "runs without TLS".
    if let Some(dir) = flag(&args, "--tls-generate") {
        generate_tls(&args, &dir);
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        help();
        return;
    }

    if let Some(address) = flag(&args, "--add-miner") {
        add_miner(&args, &address);
        return;
    }

    let node = flag(&args, "--node").unwrap_or_else(|| "127.0.0.1:9334".to_string());
    // The node may itself be behind TLS (`https://…`), which matters whenever the
    // pool and the node are not on the same machine: the RPC token travels in
    // that header on every single request.
    let node = Endpoint::parse(&node, 9334).unwrap_or_else(|e| fail(&format!("--node: {e}")));
    // A node with a self-signed certificate — the normal case when the operator
    // runs both and there is no domain name involved.
    let node_pin = flag(&args, "--node-fingerprint")
        .map(|f| noct_tls::parse_fingerprint(&f).unwrap_or_else(|e| fail(&e)));
    let node = NodeLink { endpoint: node, pin: node_pin };
    let listen = flag(&args, "--listen").unwrap_or_else(|| "127.0.0.1:9500".to_string());

    // TLS for the miner-facing port.
    let acceptor = match (flag(&args, "--tls-cert"), flag(&args, "--tls-key")) {
        (Some(cert), Some(key)) => Some(
            Acceptor::from_pem(Path::new(&cert), Path::new(&key))
                .unwrap_or_else(|e| fail(&format!("TLS: {e}"))),
        ),
        (None, None) => None,
        // Half a configuration would otherwise start happily in plaintext, which
        // is the one outcome the operator definitely did not intend.
        _ => fail("--tls-cert and --tls-key must be given together"),
    };

    // Per-miner credentials, if the operator registered any. Absent, the pool is
    // open to anonymous miners — the ordinary public-pool model.
    let miner_auth = flag(&args, "--miner-auth").map(|path| {
        MinerAuth::load(Path::new(&path)).unwrap_or_else(|e| fail(&format!("miner credentials: {e}")))
    });

    // Addresses whose `X-Forwarded-For` we believe. See `client_ip`.
    let trusted_proxies: HashSet<IpAddr> = flag(&args, "--trusted-proxy")
        .map(|s| {
            s.split(',')
                .filter(|p| !p.trim().is_empty())
                .map(|p| {
                    p.trim()
                        .parse()
                        .unwrap_or_else(|_| fail(&format!("--trusted-proxy: `{p}` is not an IP address")))
                })
                .collect()
        })
        .unwrap_or_default();
    let pool_address_str = flag(&args, "--address")
        .unwrap_or_else(|| fail("noct-poold needs --address <POOL_B58> (where block rewards are paid)"));
    // Validate at startup rather than discovering a typo later: every block this
    // pool finds pays this address, and an unspendable one would be found only
    // after the rewards were already mined.
    //
    // The address also *decides the network*. Every block reward is paid to it,
    // so the chain the pool is working on is by definition the one this address
    // belongs to. Taking the network from here rather than from a separate flag
    // means the two cannot disagree — there is no second value to set wrong.
    let pool_network = match Address::decode(pool_address_str.trim()) {
        Ok(a) => a.network,
        Err(_) => fail("invalid --address (must be a Noct address the pool controls)"),
    };
    let share_difficulty = flag(&args, "--share-difficulty")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SHARE_DIFFICULTY);
    let window = flag(&args, "--window").and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_WINDOW);
    // Per-IP budget for the miner-facing port. 0 disables it, which is only sane
    // on a private LAN.
    let rate_limit: u32 = flag(&args, "--rate-limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_POOL_RATE);
    // Vardiff aims every miner at one share per this many seconds. 0 disables
    // retuning and keeps the single fixed target for everyone.
    let vardiff_secs: f64 = flag(&args, "--vardiff-target-secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(15.0);
    let vardiff_params = VardiffParams {
        target_secs: vardiff_secs,
        min: share_difficulty.max(1),
        ..VardiffParams::default()
    };
    // The node's RPC is authenticated; a pool is exactly the case that needs a token.
    let token = flag(&args, "--node-token").or_else(|| {
        flag(&args, "--node-token-file").map(|p| {
            std::fs::read_to_string(&p)
                .unwrap_or_else(|e| fail(&format!("reading {p}: {e}")))
                .trim()
                .to_string()
        })
    });

    // Paying miners means spending the pool's own coinbase, so the pool runs a
    // wallet. Without a key it still serves work and keeps books — it just
    // cannot settle them.
    let wallet_key = flag(&args, "--wallet");
    let ledger_path = flag(&args, "--ledger").unwrap_or_else(|| "pool-ledger.txt".to_string());
    let threshold = flag(&args, "--payout-threshold")
        .and_then(|v| parse_noct(&v))
        .unwrap_or(noct_core::emission::ATOMIC_UNITS); // 1 NOCT
    // The operator's cut of each block, in percent. Zero by default: a pool that
    // took money without being told to would be indefensible.
    let fee_bps: FeeBps = match flag(&args, "--fee-percent") {
        None => 0,
        Some(v) => {
            let pct: f64 = v.parse().unwrap_or_else(|_| fail("--fee-percent needs a number, e.g. 1 or 0.5"));
            if !pct.is_finite() || pct < 0.0 {
                fail("--fee-percent cannot be negative");
            }
            // Refused rather than clamped. Someone typing `--fee-percent 100`
            // has almost certainly confused percent with basis points, and
            // silently keeping every miner's entire reward is not a mistake to
            // discover from the payouts.
            if pct >= 100.0 {
                fail("--fee-percent must be below 100 — at 100 the miners get nothing (did you mean basis points?)");
            }
            let bps = (pct * 100.0).round() as FeeBps;
            if pct > 10.0 {
                eprintln!("WARNING: a {pct}% pool fee is far above what miners will accept");
            }
            bps.min(FEE_BPS_MAX)
        }
    };
    let fee = flag(&args, "--payout-fee")
        .and_then(|v| parse_noct(&v))
        .unwrap_or(noct_core::emission::ATOMIC_UNITS / 100); // 0.01 NOCT

    let ledger = PayoutLedger::open(&ledger_path)
        .unwrap_or_else(|e| fail(&format!("opening the payout ledger {ledger_path}: {e}")));
    let unresolved = ledger.unresolved().len();

    // Recover the PPLNS window. Unpaid shares are credit miners have earned but
    // not yet been paid for; losing them on a restart quietly transfers that work
    // to whoever mines next.
    let window_log_path =
        flag(&args, "--window-log").unwrap_or_else(|| "pool-window.log".to_string());
    let (window_log, recovered_shares) = WindowLog::open(&window_log_path, window)
        .unwrap_or_else(|e| fail(&format!("opening the window log {window_log_path}: {e}")));
    let recovered = recovered_shares.len();

    // Refuse to run against a chain using a different proof-of-work.
    //
    // The pool re-hashes every share to validate it. If this binary was built
    // with a different PoW than the node's — the default build uses the Keccak
    // placeholder, and mainnet uses RandomX — then every hash it computes is of
    // the wrong function: valid shares get rejected, and anything it did accept
    // would credit work that was never done. Observed live: a pool started
    // without `--features randomx` against a RandomX testnet, whose only symptom
    // was miners connecting and nothing ever being accepted, which reads as a
    // network problem rather than a build one.
    //
    // Checked against the node rather than assumed from a build flag, because
    // the flag only tells us what WE are; the mismatch is what actually breaks.
    // A node too old to report its PoW is allowed through with a warning — this
    // must not stop a pool working against an older node.
    match http_get(&node, "/info", &token) {
        Ok(info) => match json_str(&info, "pow") {
            Some(node_pow) if node_pow != pow_name() => {
                fail(&format!(
                    "proof-of-work mismatch: this pool validates shares with {}, but the node at {} runs {}.
       Every share would be hashed with the wrong function, so valid shares are rejected and
       anything accepted would credit work that was never done.
       Rebuild with: cargo build --release -p noct-pool --bins --features randomx",
                    pow_name(),
                    node.endpoint.display(),
                    node_pow
                ));
            }
            Some(_) => {}
            None => eprintln!(
                "  warning:          node did not report its proof-of-work; cannot verify it                  matches this build ({})",
                pow_name()
            ),
        },
        Err(e) => eprintln!("  warning:          could not reach the node to check its proof-of-work: {e}"),
    }

    eprintln!("noct-poold starting");
    eprintln!("  pow:              {}", pow_name());
    eprintln!("  node:             {}{}", node.endpoint.display(), if node.pin.is_some() { " (pinned certificate)" } else { "" });
    eprintln!("  listen:           {listen}");
    match &acceptor {
        Some(a) => {
            eprintln!("  transport:        TLS");
            // Printed every start, not just at generation: it is what miners
            // pin, and an operator who rotates a certificate needs the new value
            // without hunting for the file.
            eprintln!(
                "  certificate:      sha256:{}",
                noct_tls::show_fingerprint(&a.leaf_fingerprint())
            );
            if a.chain_len() == 1 {
                // Self-signed: expected. CA-issued with the intermediate left
                // out: verifies on the operator's machine and fails on everyone
                // else's, so say which one this looks like.
                eprintln!(
                    "  note:             the chain holds one certificate — correct if self-signed \
                     (miners pin the fingerprint above); if this came from a CA, its intermediate \
                     is missing and fresh clients will reject it"
                );
            }
        }
        None => eprintln!(
            "  transport:        PLAINTEXT — miners' payout addresses are on the wire in the \
             clear. Pass --tls-cert/--tls-key, or terminate TLS in front and use --trusted-proxy."
        ),
    }
    if !trusted_proxies.is_empty() {
        eprintln!("  trusted proxies:  {} address(es)", trusted_proxies.len());
    }
    match &miner_auth {
        Some(a) => {
            eprintln!("  miners:           {} registered (anonymous miners refused)", a.len());
            if acceptor.is_none() {
                // The token is a credential sent on every request. Without TLS
                // one observation of one request is the whole thing.
                eprintln!(
                    "  WARNING:          miner tokens are sent in PLAINTEXT on every request —                      anyone watching this link can steal one. Serve TLS (--tls-cert/--tls-key)                      or terminate it in front."
                );
            }
        }
        None => eprintln!("  miners:           open (anonymous; --miner-auth <FILE> to register them)"),
    }
    eprintln!("  pool address:     {}", &pool_address_str[..pool_address_str.len().min(16)]);
    eprintln!(
        "  network:          {} (from the pool address)",
        match pool_network {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet — coins here are worthless",
        }
    );
    eprintln!("  share difficulty: {share_difficulty}");
    eprintln!("  ledger:           {ledger_path}");
    eprintln!(
        "  window log:       {window_log_path}{}",
        if recovered > 0 {
            format!(" ({recovered} share(s) recovered from an earlier run)")
        } else {
            String::new()
        }
    );
    match &wallet_key {
        Some(k) => eprintln!(
            "  payouts:          on (wallet {k}, threshold {} NOCT, fee {} NOCT)",
            format_noct(threshold),
            format_noct(fee)
        ),
        None => eprintln!("  payouts:          OFF (pass --wallet <KEYFILE> to enable)"),
    }
    // Stated on every start whether or not one is set. A fee a miner cannot see
    // is the thing that makes people distrust pools.
    if fee_bps == 0 {
        eprintln!("  operator fee:     none — miners receive the whole reward");
    } else {
        eprintln!("  operator fee:     {}% of each block", fee_bps as f64 / 100.0);
    }
    if unresolved > 0 {
        // Loud, because these are payments whose fate is genuinely unknown and
        // only a human comparing against the chain can settle them.
        eprintln!(
            "  WARNING:          {unresolved} payment(s) are UNRESOLVED from an earlier run — \
             check them against the chain before assuming they were not sent"
        );
    }

    let shared = Arc::new(Mutex::new(Shared {
        pool: {
            let mut p = Pool::new(new_pow(), share_difficulty, window);
            p.restore_window(recovered_shares);
            p
        },
        miners: HashMap::new(),
        assignments: HashMap::new(),
        blocks_found: 0,
        current_job: None,
        height: 0,
        ledger,
        window_log,
        worker_work: HashMap::new(),
    }));

    // Keep a current job available at all times.
    {
        let shared = Arc::clone(&shared);
        let node = node.clone();
        let token = token.clone();
        thread::spawn(move || loop {
            refresh_template(&shared, &node, &token, &pool_address_str);
            thread::sleep(TEMPLATE_REFRESH);
        });
    }

    // Settle the books: mature buried rounds, then pay anyone over the threshold.
    if let Some(key_path) = wallet_key {
        let shared = Arc::clone(&shared);
        let node = node.clone();
        let token = token.clone();
        thread::spawn(move || loop {
            thread::sleep(PAYOUT_INTERVAL);
            run_payouts(&shared, &node, &token, &key_path, threshold, fee, pool_network);
        });
    }

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| fail(&format!("bind {listen}: {e}")));
    let limiter = Arc::new(RateLimiter::new(rate_limit));
    let live = Arc::new(AtomicUsize::new(0));
    let trusted_proxies = Arc::new(trusted_proxies);
    let miner_auth = Arc::new(miner_auth);
    for tcp in listener.incoming().flatten() {
        // Refuse past the connection cap rather than spawning a thread we cannot
        // afford. Done before any work — before the TLS handshake in particular,
        // which is the most expensive thing an anonymous caller can make us do
        // before it has said anything at all.
        if live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            let mut s = Stream::Plain(tcp);
            let _ = respond(&mut s, "503 Service Unavailable", "{\"error\":\"pool busy\"}");
            continue;
        }
        // Bound how long a connection may sit without progress. The per-IP rate
        // limiter cannot substitute for this: it is consulted only after a full
        // request head has been read, so a client that opens a socket and never
        // finishes its request never reaches the limiter at all, and occupies a
        // connection slot for free until it chooses to leave.
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));

        // A TLS session is created here but its handshake runs on the worker
        // thread, on first read: doing it inline would let one slow client stall
        // every other connection waiting to be accepted.
        let stream = match &acceptor {
            Some(a) => match a.accept(tcp) {
                Ok(s) => s,
                Err(_) => continue,
            },
            None => Stream::Plain(tcp),
        };
        live.fetch_add(1, Ordering::Relaxed);

        let shared = Arc::clone(&shared);
        let node = node.clone();
        let token = token.clone();
        let limiter = Arc::clone(&limiter);
        let vardiff_params = vardiff_params;
        let live_guard = Arc::clone(&live);
        let proxies = Arc::clone(&trusted_proxies);
        let miner_auth = Arc::clone(&miner_auth);
        thread::spawn(move || {
            let _ = handle(stream, shared, &node, &token, &limiter, &vardiff_params, &proxies, (*miner_auth).as_ref(), fee_bps);
            // Always released, including on an error path — a leak here would
            // wedge the pool shut after MAX_CONNECTIONS failures.
            live_guard.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Write a self-signed certificate and key, and print the fingerprint miners pin.
fn generate_tls(args: &[String], dir: &str) {
    // Whatever miners will actually type after `--pool`. Not checked by a
    // pinning client, but wrong here means the certificate cannot later be
    // installed as trusted without regenerating it.
    let names: Vec<String> = flag(args, "--tls-names")
        .unwrap_or_else(|| "localhost,127.0.0.1".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let gen = noct_tls::selfsigned(&names).unwrap_or_else(|e| fail(&e));

    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(&format!("creating {}: {e}", dir.display())));
    let cert_path = dir.join("pool-cert.pem");
    let key_path = dir.join("pool-key.pem");
    // Refuse to overwrite: silently replacing a certificate would break every
    // miner that had pinned the old one, for no reason the operator asked for.
    for p in [&cert_path, &key_path] {
        if p.exists() {
            fail(&format!("{} already exists — move it aside first", p.display()));
        }
    }
    std::fs::write(&cert_path, &gen.cert_pem).unwrap_or_else(|e| fail(&format!("writing {}: {e}", cert_path.display())));
    std::fs::write(&key_path, &gen.key_pem).unwrap_or_else(|e| fail(&format!("writing {}: {e}", key_path.display())));

    println!("wrote {}", cert_path.display());
    println!("wrote {}  (KEEP THIS PRIVATE)", key_path.display());
    println!("names: {}", names.join(", "));
    println!();
    println!("Start the pool with:");
    println!("  noct-poold --address <POOL_B58> --tls-cert {} --tls-key {}", cert_path.display(), key_path.display());
    println!();
    println!("Publish this fingerprint; miners verify against it:");
    println!("  {}", noct_tls::show_fingerprint(&gen.fingerprint));
    println!();
    println!("Miners then connect with:");
    println!("  noct-miner --pool https://<host>:9500 --pool-fingerprint {}", noct_tls::show_fingerprint(&gen.fingerprint));
}

/// Decide which miner a share belongs to.
///
/// **Why an address on the submission, and not just the per-IP map.** The pool
/// used to attribute every share by source IP alone: whichever payout address
/// that IP last registered when fetching work. Two rigs behind one router share
/// a source IP, so the second one to ask for work silently overwrote the first,
/// and from then on *both* miners' shares were credited — and paid — to whichever
/// address registered most recently. Several rigs behind one NAT is the ordinary
/// home-mining setup, so this was not an edge case; it paid real money to the
/// wrong person, and neither miner could tell.
///
/// A submission that carries its own payout address is attributed to it directly,
/// with no shared state to collide over. The per-IP map remains only as a
/// fallback, so miners that predate this still work — they are just still exposed
/// to the collision, which is why the miner was updated to send it.
///
/// Falling back to the raw IP as a last resort keeps work from being silently
/// uncredited; an operator can still see it in `/stats` and sort it out.
fn attribute_miner(
    explicit: Option<&str>,
    peer: Option<IpAddr>,
    registered: &HashMap<IpAddr, String>,
) -> String {
    // Only trust an address that actually decodes — an unspendable one would
    // strand the payout at settlement time, long after the work was done.
    if let Some(addr) = explicit {
        let addr = addr.trim();
        if !addr.is_empty() && Address::decode(addr).is_ok() {
            return addr.to_string();
        }
    }
    peer.and_then(|ip| registered.get(&ip).cloned())
        .unwrap_or_else(|| peer.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".into()))
}

/// Who a request is from: who gets paid, and which session is metered.
///
/// These are deliberately two different things. **Money is accounted per payout
/// address** and nothing about worker names or sessions touches that. The
/// session only decides whose share rate is averaged together for vardiff and
/// what `/stats` reports per rig — so a mistake in this half cannot misdirect a
/// payment, only mis-tune a difficulty.
#[derive(Debug)]
struct Who {
    payout: String,
    session: String,
}

/// Resolve a request to a miner, enforcing credentials when they are configured.
///
/// Without credentials this is the public-pool behaviour unchanged: the payout
/// address is whatever the request says (validated), which is how every
/// Monero-family pool works.
///
/// With credentials, the **token decides the payout address and the request
/// cannot override it**. That is the whole point: a miner cannot mine to an
/// address the operator never registered, and cannot be confused with — or
/// impersonate — another miner, because nothing about the identity is
/// self-declared any more.
fn identify(
    miner_auth: Option<&MinerAuth>,
    bearer: Option<&str>,
    explicit_address: Option<&str>,
    worker: Option<&str>,
    peer: Option<IpAddr>,
    registered: &HashMap<IpAddr, String>,
) -> Result<Who, String> {
    let worker = auth::clean_worker(worker);
    match miner_auth {
        Some(auth) => {
            let token = bearer.unwrap_or("").trim();
            let reg = auth.lookup(token).ok_or_else(|| {
                // Deliberately says nothing about *why*. Distinguishing "no
                // token" from "wrong token" from "revoked" would confirm to a
                // guesser which of those they achieved.
                "this pool requires a registered miner token (Authorization: Bearer …)".to_string()
            })?;
            // The worker name is still the miner's to choose — it names a rig,
            // not an identity, and it cannot affect payment.
            let session = auth::session_id(&reg.payout, worker.as_deref());
            Ok(Who { payout: reg.payout.clone(), session })
        }
        None => {
            let payout = attribute_miner(explicit_address, peer, registered);
            let session = auth::session_id(&payout, worker.as_deref());
            Ok(Who { payout, session })
        }
    }
}

/// The share target to issue this miner now, retuning it from its recent rate.
///
/// Called when work is handed out, not when a share arrives: changing a miner's
/// target while it is mid-grind is what `Assignment::previous` exists to forgive,
/// and doing it here keeps those moments rare and predictable.
fn issue_difficulty(
    assignments: &mut HashMap<String, Assignment>,
    miner: &str,
    base: Difficulty,
    params: &VardiffParams,
) -> Difficulty {
    let a = assignments.entry(miner.to_string()).or_insert_with(|| Assignment {
        current: base,
        previous: base,
        last_share: None,
        ewma_secs: f64::NAN, // no measurement yet
        rejected_streak: 0,
        last_rejection: "",
    });
    // Nothing measured yet — a new miner keeps the starting target until it has
    // actually produced a share to time.
    if !a.ewma_secs.is_finite() {
        return a.current;
    }
    let next = vardiff::retarget(a.current, a.ewma_secs, params);
    if next != a.current {
        a.previous = a.current;
        a.current = next;
    }
    a.current
}

/// Fold one accepted share into a miner's measured rate.
///
/// Exponentially weighted, because share intervals are Poisson-distributed and
/// wildly variable even at a well-tuned target; averaging over several keeps the
/// controller from chasing noise.
fn record_share_timing(a: &mut Assignment, now: std::time::Instant) {
    if let Some(prev) = a.last_share {
        let gap = now.duration_since(prev).as_secs_f64();
        a.ewma_secs = if a.ewma_secs.is_finite() {
            // 0.3 favours recent behaviour without letting one sample dominate.
            0.7 * a.ewma_secs + 0.3 * gap
        } else {
            gap
        };
    }
    a.last_share = Some(now);
}

/// Fetch a template paying the pool and publish it as the current job.
fn refresh_template(shared: &Arc<Mutex<Shared>>, node: &NodeLink, token: &Option<String>, pool_address: &str) {
    let resp = match http_get(node, &format!("/getblocktemplate?address={pool_address}"), token) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("template fetch failed: {e}");
            return;
        }
    };
    let (Some(difficulty), Some(seed), Some(template)) = (
        json_u64(&resp, "difficulty"),
        json_hex(&resp, "seed_hash"),
        json_hex(&resp, "template"),
    ) else {
        eprintln!("malformed template response from the node");
        return;
    };
    let Ok(Wire::Block(block, txs)) = wire::decode_message(&template) else {
        eprintln!("could not decode the node's template");
        return;
    };
    let Ok(seed) = <[u8; 32]>::try_from(seed) else { return };
    let height = block.coinbase.height;

    let mut s = shared.lock().unwrap();
    // Only republish when the tip moved; otherwise miners would be handed a new
    // job id every few seconds and lose their in-flight work for nothing.
    if s.height == height && s.current_job.is_some() {
        return;
    }
    let id = s.pool.add_job(block, txs, difficulty, seed);
    s.current_job = Some(id);
    s.height = height;
    eprintln!("new job {id} at height {height} (network difficulty {difficulty})");
}

fn handle(
    stream: Stream,
    shared: Arc<Mutex<Shared>>,
    node: &NodeLink,
    token: &Option<String>,
    limiter: &RateLimiter,
    vardiff_params: &VardiffParams,
    trusted_proxies: &HashSet<IpAddr>,
    miner_auth: Option<&MinerAuth>,
    fee_bps: FeeBps,
) -> std::io::Result<()> {
    // One object for both directions now: a TLS session cannot be `try_clone`d
    // the way a socket can, since the two halves share the connection's
    // cryptographic state. Everything is read first, then the reader is unwrapped
    // to write the reply — which suits `Connection: close` exactly.
    let socket_peer = stream.peer_addr().map(|a| a.ip()).ok();
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    // On a TLS connection this is where the handshake actually happens, so a
    // failure here is normal (a probe, a wrong pin, a port scanner) and simply
    // ends the connection.
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    let mut forwarded_for: Option<String> = None;
    let mut bearer: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim_end().is_empty() {
            break;
        }
        let lower = line.trim_end().to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = lower.strip_prefix("x-forwarded-for:") {
            forwarded_for = Some(v.trim().to_string());
        } else if lower.starts_with("authorization:") {
            // Taken from the original line, not the lowercased copy: a token is
            // case-sensitive and folding it would reject every valid one.
            if let Some(v) = line.trim_end().split_once(':') {
                bearer = v.1.trim().strip_prefix("Bearer ").map(|t| t.trim().to_string());
            }
        }
    }
    // Who this request is actually from — the proxy's word for it only when the
    // proxy is one we were told to trust.
    let peer = client_ip(socket_peer, forwarded_for.as_deref(), trusted_proxies);

    if content_length > MAX_BODY {
        let mut writer = reader.into_inner();
        return respond(&mut writer, "413 Payload Too Large", "{\"error\":\"too large\"}");
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let mut writer = reader.into_inner();

    // Charge before doing the work, so an over-budget caller is rejected before
    // it can cost us a proof-of-work verification.
    let cost = match (method.as_str(), path.as_str()) {
        ("POST", p) if p.starts_with("/submitblock") => COST_SUBMIT,
        (_, p) if p.starts_with("/getblocktemplate") => COST_TEMPLATE,
        _ => COST_READ,
    };
    if let Some(ip) = peer {
        if !limiter.allow(ip, cost) {
            return respond(
                &mut writer,
                "429 Too Many Requests",
                "{\"error\":\"rate limited — slow down; shares are expensive to verify\"}",
            );
        }
    }

    match (method.as_str(), path.as_str()) {
        // Same shape as the node's, but `difficulty` is the *share* target. The
        // `address` a miner supplies is where it wants to be paid.
        (_, p) if p.starts_with("/getblocktemplate") => {
            // Only remember an address that decodes. An unspendable string
            // registered here becomes a miner identity that accrues real weight
            // in the PPLNS window and can never be paid — so every reward split
            // hands it a slice that is then simply lost, diluting everyone who
            // *can* be paid. F24 validated the address on submission but not
            // here, and a client with a typo'd `--address` was enough to do it.
            //
            // Skipped entirely when credentials are in use: the token already
            // says who this is, and honouring a self-declared address would
            // quietly reopen exactly what the credential closes.
            if miner_auth.is_none() {
                if let (Some(ip), Some(addr)) = (peer, query_param(p, "address")) {
                    if Address::decode(addr.trim()).is_ok() {
                        shared.lock().unwrap().miners.insert(ip, addr);
                    }
                }
            }
            let json = {
                let mut s = shared.lock().unwrap();
                // Each miner is given its own target, retuned from its measured
                // share rate.
                let who = match identify(
                    miner_auth,
                    bearer.as_deref(),
                    query_param(p, "address").as_deref(),
                    query_param(p, "worker").as_deref(),
                    peer,
                    &s.miners,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        drop(s);
                        return respond(&mut writer, "401 Unauthorized", &err(&e));
                    }
                };
                let who = who.session;
                let base = s.pool.share_difficulty();
                let issued = issue_difficulty(&mut s.assignments, &who, base, &vardiff_params);
                match s.current_job.and_then(|id| s.pool.job(id).map(|j| (id, j))) {
                    Some((id, job)) => {
                        let template = hex::encode(wire::encode_message(&Wire::Block(
                            job.block.clone(),
                            job.txs.clone(),
                        )));
                        // Advertise the proof of work, so a miner built against a
                        // different one fails loudly instead of having every
                        // share rejected as "does not meet the target".
                        format!(
                            "{{\"job_id\":{id},\"height\":{},\"difficulty\":{},\"seed_hash\":\"{}\",\"pow\":\"{}\",\"template\":\"{template}\"}}",
                            job.block.coinbase.height,
                            issued,
                            hex::encode(job.seed),
                            pow_name(),
                        )
                    }
                    None => "{\"error\":\"no job yet — the pool is still fetching work\"}".to_string(),
                }
            };
            respond(&mut writer, "200 OK", &json)
        }
        // A miner's solution: credited as a share, and submitted upstream when it
        // is also a block.
        ("POST", p) if p.starts_with("/submitblock") => {
            let who = {
                let s = shared.lock().unwrap();
                identify(
                    miner_auth,
                    bearer.as_deref(),
                    query_param(p, "address").as_deref(),
                    query_param(p, "worker").as_deref(),
                    peer,
                    &s.miners,
                )
            };
            let who = match who {
                Ok(w) => w,
                Err(e) => return respond(&mut writer, "401 Unauthorized", &err(&e)),
            };
            let json = submit_share(
                &shared,
                &who,
                &String::from_utf8_lossy(&body),
                node,
                token,
                fee_bps,
            );
            respond(&mut writer, "200 OK", &json)
        }
        ("GET", "/stats") => {
            // A public pool publishes its stats; that is the point of them. But
            // a pool that registers its miners is a private one, and its stats
            // list who is mining, to which address, and how much they earn —
            // which is exactly what a privacy coin's users would not want
            // published. So when credentials are configured, reading requires
            // one too. Monitoring can hold a token like anyone else.
            if let Some(auth) = miner_auth {
                if auth.lookup(bearer.as_deref().unwrap_or("").trim()).is_none() {
                    return respond(
                        &mut writer,
                        "401 Unauthorized",
                        &err("this pool's stats require a registered miner token"),
                    );
                }
            }
            let json = stats(&shared, fee_bps);
            respond(&mut writer, "200 OK", &json)
        }
        _ => respond(&mut writer, "404 Not Found", "{\"error\":\"not found\"}"),
    }
}

/// Validate a submission as a share; on a block, forward it to the node.
fn submit_share(
    shared: &Arc<Mutex<Shared>>,
    who: &Who,
    body: &str,
    node: &NodeLink,
    token: &Option<String>,
    fee_bps: FeeBps,
) -> String {
    let Ok(raw) = hex::decode(body.trim()) else {
        return err("invalid hex");
    };
    let Ok(Wire::Block(block, _txs)) = wire::decode_message(&raw) else {
        return err("invalid block");
    };
    let nonce = block.header.nonce;

    // Credit goes to the payout address; the difficulty this is judged against
    // comes from the session. See `Who` for why those are separate.
    let miner = &who.payout;

    let (outcome, job_id) = {
        let mut s = shared.lock().unwrap();
        let Some(job_id) = s.current_job else {
            return err("no active job");
        };
        // Judge the share against the target this miner was actually issued.
        //
        // Try the current target first; if it does not meet that, fall back to the
        // one issued before the last retune. A miner may well have been grinding
        // on the old target when we raised it, and rejecting that work would
        // punish it for our adjustment. Whichever it meets is also what it is
        // weighted at, so nobody is over- or under-paid for the ambiguity.
        let (current, previous) = s
            .assignments
            .get(&who.session)
            .map(|a| (a.current, a.previous))
            .unwrap_or((s.pool.share_difficulty(), s.pool.share_difficulty()));

        let mut outcome = s.pool.submit_share_at(miner, job_id, nonce, current);
        if matches!(outcome, ShareOutcome::TooEasy) && previous < current {
            outcome = s.pool.submit_share_at(miner, job_id, nonce, previous);
        }

        // Time accepted shares, so the next retarget has something to go on.
        if matches!(outcome, ShareOutcome::Accepted | ShareOutcome::Block(_)) {
            if let Some(a) = s.assignments.get_mut(&who.session) {
                record_share_timing(a, std::time::Instant::now());
                // Work is being credited again: whatever the run of refusals
                // was, it is over.
                a.rejected_streak = 0;
                a.last_rejection = "";
            }
            // Display-only, so an operator (and a miner running several rigs)
            // can see them apart. Never consulted for payment.
            *s.worker_work.entry(who.session.clone()).or_insert(0) += current as u128;
        }

        // Persist credit BEFORE the miner is told the share was accepted. A
        // restart or crash between acknowledging and recording would otherwise
        // lose work the miner has every reason to believe is banked.
        if matches!(outcome, ShareOutcome::Accepted | ShareOutcome::Block(_)) {
            if let Some(share) = s.pool.window().back().cloned() {
                let window = s.pool.window().clone();
                if let Err(e) = s.window_log.append(&share, &window) {
                    // Not fatal: refusing the share would cost the miner work it
                    // genuinely did. Loud, because the durability guarantee is
                    // now broken and the operator needs to know.
                    eprintln!("WARNING: could not record share to the window log: {e}");
                }
            }
        }
        (outcome, job_id)
    };

    match outcome {
        ShareOutcome::Accepted => {
            format!("{{\"status\":\"accepted\",\"share\":true,\"job_id\":{job_id}}}")
        }
        ShareOutcome::Block(found) => {
            let (solved, txs) = *found;
            let id = hex::encode(solved.id());
            let height = solved.coinbase.height;
            let reward = solved.coinbase.total().unwrap_or(0);
            let payload = hex::encode(wire::encode_message(&Wire::Block(solved, txs)));
            let reply = http_post(node, "/submitblock", &payload, token);
            let accepted = matches!(&reply, Ok(r) if r.contains("\"accepted\""));
            if accepted {
                let mut s = shared.lock().unwrap();
                s.blocks_found += 1;
                // Record what this block owes whom, from the share window as it
                // stands right now. Nothing is credited yet — the reward is a
                // coinbase output, so it is held until the chain buries it
                // (a reorg before then would erase it).
                // The operator's cut comes off first; the two sum to exactly
                // the reward, and `split_reward` divides the rest exactly, so
                // every atomic unit of the block is accounted for.
                //
                // No transfer is needed for the fee: the whole coinbase already
                // pays the pool's own address, so the operator's share is simply
                // the part never credited to a miner.
                let (_operator, to_miners) = payout::apply_fee(reward, fee_bps);
                let splits = s.pool.split_reward(to_miners);
                s.ledger.record_block(height, reward, splits);
                if let Err(e) = s.ledger.save() {
                    eprintln!("WARNING: could not persist the payout ledger: {e}");
                }
                // Force a fresh job: this template is spent.
                s.current_job = None;
                s.height = 0;
                eprintln!("✔ BLOCK found by {miner} — {id}");
            } else {
                eprintln!("block found but the node refused it: {reply:?}");
            }
            format!(
                "{{\"status\":\"accepted\",\"share\":true,\"block\":true,\"submitted\":{accepted},\"id\":\"{id}\"}}"
            )
        }
        ShareOutcome::TooEasy => {
            note_rejection(shared, &who.session, "share does not meet the target");
            err("share does not meet the target")
        }
        ShareOutcome::Duplicate => {
            note_rejection(shared, &who.session, "duplicate share");
            err("duplicate share")
        }
        ShareOutcome::UnknownJob => {
            note_rejection(shared, &who.session, "stale job");
            err("stale job")
        }
    }
}

/// Warn after this many refusals in a row from one session.
///
/// Occasional rejections are ordinary — a share found just as the tip moves is
/// stale through nobody's fault. An unbroken *run* is not: it means the rig has
/// been working for nothing since the run began.
const REJECTION_STREAK_WARN: u32 = 25;

/// Record a rejection, and say something once the run is long enough to mean
/// the miner is earning nothing.
///
/// This exists because the failure it reports was invisible for 45 minutes on
/// the live testnet. Two rigs sat at ~99% CPU with every submission refused;
/// `/stats` showed a share count that had simply stopped rising, which looks
/// identical to nobody mining. The pool knew the reason on every single
/// request and never said it.
fn note_rejection(shared: &Arc<Mutex<Shared>>, session: &str, reason: &'static str) {
    let mut s = shared.lock().unwrap();
    let Some(a) = s.assignments.get_mut(session) else { return };
    if a.last_rejection != reason {
        a.rejected_streak = 0;
        a.last_rejection = reason;
    }
    a.rejected_streak += 1;
    // Once at the threshold, then once per further threshold's worth, so a
    // stuck rig keeps reminding the operator without flooding the log.
    if a.rejected_streak % REJECTION_STREAK_WARN == 0 {
        let n = a.rejected_streak;
        eprintln!(
            "WARNING: {session} has had {n} submissions refused in a row ({reason}). \
             It is doing work it is not being paid for — check that it is on the current job."
        );
    }
}

/// Mature buried rounds, then settle anyone over the threshold.
///
/// Ordering here is the whole safety argument: the ledger reserves a miner's
/// balance and persists that intent *before* a transaction is built, so a crash
/// can never leave the pool thinking it still owes money it may already have
/// sent. Failures are then classified by whether the transaction could possibly
/// have reached the network — refunded when definitely not, held for
/// reconciliation when unknown.
fn run_payouts(
    shared: &Arc<Mutex<Shared>>,
    node: &NodeLink,
    token: &Option<String>,
    key_path: &str,
    threshold: u64,
    fee: u64,
    network: Network,
) {
    let client = NodeClient::with_token(node.endpoint.clone(), token.clone()).with_pin(node.pin);
    let Ok(height) = client.height() else { return };

    // Credit rounds the chain has now buried, then see who is payable.
    let batch = {
        let mut s = shared.lock().unwrap();
        let matured = s.ledger.mature(height, COINBASE_MATURITY);
        if matured > 0 {
            eprintln!("credited {matured} matured round(s) at height {height}");
            if let Err(e) = s.ledger.save() {
                eprintln!("WARNING: could not persist the payout ledger: {e}");
            }
        }
        s.ledger.payable(threshold).into_iter().take(MAX_PAYOUTS_PER_TX).collect::<Vec<_>>()
    };
    if batch.is_empty() {
        return;
    }

    // The pool's own wallet, synced so it can spend its (now mature) coinbase.
    let Ok(contents) = std::fs::read_to_string(key_path) else {
        eprintln!("payout skipped: cannot read the wallet key at {key_path}");
        return;
    };
    let Ok(account) = load_account(contents.trim()) else {
        eprintln!("payout skipped: the wallet key at {key_path} is not valid");
        return;
    };
    let cache = format!("{key_path}.cache");
    // NOT a constant: syncing with the wrong network builds the wrong genesis,
    // so the very first block the wallet validates fails with BadPrevId and the
    // pool can never pay anyone. Hardcoding Mainnet here meant a testnet pool
    // credited miners forever and paid out nothing — it fails safe, but it fails
    // totally, and only on the network you would test payouts on.
    let (chain, wallet, _h) = match load_synced_wallet(&client, account, network, cache) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("payout skipped: wallet sync failed: {e}");
            return;
        }
    };

    // Resolve destinations first: a miner id that is not a valid address cannot
    // be paid, and must not consume a slot or a reservation.
    let mut resolved = Vec::new();
    for (miner, amount) in batch {
        match Address::decode(&miner) {
            Ok(destination) => resolved.push((miner, amount, destination)),
            Err(_) => eprintln!("cannot pay {miner}: not a valid address (work stays credited)"),
        }
    }
    if resolved.is_empty() {
        return;
    }

    // The pool owes miners the whole block reward, so it holds nothing extra to
    // pay the transaction fee with — the fee comes out of the payment, split in
    // proportion to each miner's amount. Without this the wallet is asked to
    // spend more than it has and every payout fails with InsufficientFunds.
    let owed_list: Vec<(String, u64)> =
        resolved.iter().map(|(m, a, _)| (m.clone(), *a)).collect();
    let after_fee = noct_pool::payout::deduct_fee(&owed_list, fee);
    let mut payments = Vec::new();
    let mut payees = Vec::new();
    for (miner, gross, net) in after_fee {
        let Some((_, _, destination)) = resolved.iter().find(|(m, _, _)| *m == miner) else {
            continue;
        };
        payments.push(Payment { destination: *destination, amount: net });
        // The miner is settled for the full amount owed; the fee share is a cost
        // they bear, as with any withdrawal.
        payees.push((miner, gross));
    }
    if payments.is_empty() {
        eprintln!("payout skipped: the fee would consume every payment");
        return;
    }

    // Reserve every balance and persist that intent BEFORE building anything.
    let ids: Vec<u64> = {
        let mut s = shared.lock().unwrap();
        let mut ids = Vec::new();
        for (miner, amount) in &payees {
            match s.ledger.begin_payment(miner, *amount) {
                Ok(id) => ids.push(id),
                Err(e) => {
                    eprintln!("WARNING: could not record a payment intent: {e} — stopping this round");
                    break;
                }
            }
        }
        ids
    };
    if ids.len() != payments.len() {
        // We could not durably record every intent, so do not send a partial
        // batch we cannot account for.
        let mut s = shared.lock().unwrap();
        for id in ids {
            let _ = s.ledger.fail_payment(id);
        }
        return;
    }

    let total_net: u64 = payments.iter().map(|p| p.amount).sum();
    let tx = match wallet.build_transaction(&mut rand_core::OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE) {
        Ok(tx) => tx,
        Err(e) => {
            // Nothing was sent — the transaction does not exist. Safe to refund.
            eprintln!("payout failed to build ({e:?}); balances returned");
            let mut s = shared.lock().unwrap();
            for id in ids {
                let _ = s.ledger.fail_payment(id);
            }
            return;
        }
    };
    let txid = hex::encode(tx.hash());

    match client.submit_tx(&tx) {
        Ok(reply) if reply.contains("\"accepted\":true") => {
            let mut s = shared.lock().unwrap();
            for id in ids {
                let _ = s.ledger.complete_payment(id, &txid);
            }
            eprintln!(
                "paid {} miner(s) {} NOCT after a shared {} NOCT fee — {txid}",
                payees.len(),
                format_noct(total_net),
                format_noct(fee)
            );
        }
        Ok(reply) => {
            // The node answered and refused it, so it is not in any mempool.
            eprintln!("payout rejected by the node ({}); balances returned", reply.trim());
            let mut s = shared.lock().unwrap();
            for id in ids {
                let _ = s.ledger.fail_payment(id);
            }
        }
        Err(e) => {
            // We never heard back. The transaction may or may not have been
            // relayed, so refunding could pay twice: hold for reconciliation.
            eprintln!(
                "PAYOUT OUTCOME UNKNOWN ({e}) — txid {txid} held as unresolved; \
                 check the chain before re-paying"
            );
            let mut s = shared.lock().unwrap();
            for id in ids {
                let _ = s.ledger.mark_unresolved(id);
            }
        }
    }
}

/// Pool status, including what each miner is owed from the current window.
fn stats(shared: &Arc<Mutex<Shared>>, fee_bps: FeeBps) -> String {
    let s = shared.lock().unwrap();
    let weights = s.pool.weights();
    let total: u128 = weights.values().sum();
    let mut miners: Vec<(String, u128)> = weights.into_iter().collect();
    miners.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let entries: Vec<String> = miners
        .iter()
        .map(|(m, w)| {
            let share = if total == 0 { 0.0 } else { (*w as f64) * 100.0 / (total as f64) };
            format!("{{\"miner\":\"{}\",\"work\":{w},\"percent\":{share:.4}}}", escape(m))
        })
        .collect();
    // Display only. Sorted and capped so one miner with many rigs cannot make
    // every stats response enormous.
    let mut workers: Vec<(&String, &u128)> = s.worker_work.iter().collect();
    workers.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let worker_entries: Vec<String> = workers
        .iter()
        .take(200)
        // `rejected_streak` is published because a rig earning nothing looks
        // exactly like a rig that stopped: both show work that stops rising.
        // The streak tells the two apart without reading the log.
        .map(|(id, w)| {
            let streak = s.assignments.get(*id).map(|a| a.rejected_streak).unwrap_or(0);
            format!("{{\"session\":\"{}\",\"work\":{w},\"rejected_streak\":{streak}}}", escape(id))
        })
        .collect();
    let owed: Vec<String> = s
        .ledger
        .all_owed()
        .iter()
        .map(|(m, a)| format!("{{\"miner\":\"{}\",\"owed\":\"{}\"}}", escape(m), format_noct(*a)))
        .collect();
    format!(
        "{{\"height\":{},\"share_difficulty\":{},\"shares_in_window\":{},\"blocks_found\":{},\"pending_rounds\":{},\"unresolved_payments\":{},\"fee_percent\":{},\"operator_earned\":\"{}\",\"operator_pending\":\"{}\",\"miners\":[{}],\"workers\":[{}],\"owed\":[{}]}}",
        s.height,
        s.pool.share_difficulty(),
        s.pool.window().len(),
        s.blocks_found,
        s.ledger.pending_rounds().len(),
        s.ledger.unresolved().len(),
        // Published, not buried: a miner should be able to read the rate it is
        // being charged and the total taken straight off the same endpoint that
        // reports its own work.
        fee_bps as f64 / 100.0,
        format_noct(s.ledger.operator_total().min(u64::MAX as u128) as u64),
        format_noct(s.ledger.operator_pending().min(u64::MAX as u128) as u64),
        entries.join(","),
        worker_entries.join(","),
        owed.join(",")
    )
}

// --- helpers ----------------------------------------------------------------

fn respond(writer: &mut Stream, status: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    writer.write_all(response.as_bytes())?;
    writer.flush()?;
    // Closes the TLS session properly, so the miner can tell a finished reply
    // from a cut one rather than having to guess.
    writer.close();
    Ok(())
}

fn err(msg: &str) -> String {
    format!("{{\"status\":\"rejected\",\"reason\":\"{}\"}}", escape(msg))
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(|v| v.to_string())
}

fn auth_header(token: &Option<String>) -> String {
    match token {
        Some(t) => format!("Authorization: Bearer {t}\r\n"),
        None => String::new(),
    }
}

fn http_get(node: &NodeLink, path: &str, token: &Option<String>) -> Result<String, String> {
    request(
        node,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            node.endpoint.authority(),
            auth_header(token)
        ),
    )
}

fn http_post(node: &NodeLink, path: &str, body: &str, token: &Option<String>) -> Result<String, String> {
    request(
        node,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            node.endpoint.authority(),
            auth_header(token),
            body.len()
        ),
    )
}

fn request(node: &NodeLink, raw: &str) -> Result<String, String> {
    let mut stream = noct_tls::connect_pinned(&node.endpoint, node.pin)?;
    stream.write_all(raw.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let resp = noct_tls::read_response(&mut stream)?;
    if resp.status == 401 {
        return Err("unauthorized: the node needs --node-token / --node-token-file".to_string());
    }
    Ok(resp.body)
}

fn json_u64(s: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = &s[s.find(&needle)? + needle.len()..];
    rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
}

fn json_str(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let rest = &s[s.find(&needle)? + needle.len()..];
    Some(rest.chars().take_while(|&c| c != '"').collect())
}

fn json_hex(s: &str, key: &str) -> Option<Vec<u8>> {
    hex::decode(json_str(s, key)?).ok()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Register a new miner: mint a token, append it to the credentials file, and
/// print what to hand the miner.
///
/// A generator rather than "edit this file yourself" for the same reason
/// `--tls-generate` exists: the alternative to an easy path is not a careful
/// operator, it is a weak hand-picked token, or the feature going unused.
fn add_miner(args: &[String], address: &str) {
    let path = flag(args, "--miner-auth")
        .unwrap_or_else(|| fail("--add-miner also needs --miner-auth <FILE> (the credentials file)"));
    let path = Path::new(&path);
    // Checked here rather than at the next startup: an address that does not
    // decode would take work and never be payable (cf. F27).
    if Address::decode(address.trim()).is_err() {
        fail("that is not a valid Noct address");
    }
    let label = flag(args, "--label").unwrap_or_default();

    // Read what is already there so a duplicate address is a warning, not a
    // silent second identity that splits someone's earnings in two.
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing.lines().any(|l| l.split_whitespace().nth(1) == Some(address.trim())) {
            eprintln!("note: {address} is already registered; adding a second token for it");
        }
    }

    let token = auth::new_token();
    let line = if label.is_empty() {
        format!("{token} {}
", address.trim())
    } else {
        format!("{token} {} {label}
", address.trim())
    };
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| fail(&format!("opening {}: {e}", path.display())));
    f.write_all(line.as_bytes())
        .unwrap_or_else(|e| fail(&format!("writing {}: {e}", path.display())));

    // Re-read it, so a file this command has just corrupted is caught now rather
    // than at the next restart — when the pool would refuse to start.
    match MinerAuth::load(path) {
        Ok(a) => println!("{} now registers {} miner(s)", path.display(), a.len()),
        Err(e) => fail(&format!("the credentials file is now invalid: {e}")),
    }
    println!();
    println!("Give this miner its token (it is a secret — send it over something private):");
    println!("  {token}");
    println!();
    println!("They run:");
    println!("  noct-miner --address <ignored> --pool https://<pool>:9500 \\");
    println!("             --token-file <file containing the token above> --worker rig-1");
    println!();
    println!("Their payout address is fixed by this registration; nothing they send can change it.");
}

/// Every flag, grouped by what an operator is trying to do.
///
/// Worth having as more than a usage line: the daemon has grown enough knobs
/// that "which flag turns TLS on" is a real question, and a flag nobody can find
/// is a feature nobody uses.
fn help() {
    println!("noct-poold — a Noct mining pool daemon
");
    println!("USAGE");
    println!("  noct-poold --address <POOL_B58> [options]
");
    println!("REQUIRED");
    println!("  --address <B58>            where block rewards are paid (validated at startup)
");
    println!("THE NODE IT MINES AGAINST");
    println!("  --node <URL>               default 127.0.0.1:9334; https:// to encrypt the link");
    println!("  --node-token-file <PATH>   the node's RPC token (prefer this to --node-token)");
    println!("  --node-token <TOKEN>       visible in the process list — prefer the file form");
    println!("  --node-fingerprint <HEX>   pin a self-signed node certificate
");
    println!("SERVING MINERS");
    println!("  --listen <ADDR>            default 127.0.0.1:9500");
    println!("  --share-difficulty <N>     starting share target (default 1000)");
    println!("  --vardiff-target-secs <N>  aim each miner at one share per N seconds (default 15)");
    println!("  --window <N>               PPLNS window size in shares (default 8192)");
    println!("  --window-log <PATH>        durable record of the window (default pool-window.log)");
    println!("  --rate-limit <N>           per-IP budget, units/s (default 1000; 0 disables)
");
    println!("TRANSPORT SECURITY  — a public pool should not run without this");
    println!("  --tls-cert <PATH> --tls-key <PATH>   serve HTTPS");
    println!("  --tls-generate <DIR>       write a self-signed certificate and print its fingerprint");
    println!("  --tls-names <A,B>          names/IPs it covers (with --tls-generate)");
    println!("  --trusted-proxy <IP,IP>    believe X-Forwarded-For from these, and only these
");
    println!("MINER CREDENTIALS  — optional; makes the pool private");
    println!("  --miner-auth <FILE>        registered miners; anonymous ones are then refused");
    println!("  --add-miner <B58>          mint a token for this address and append it to that file");
    println!("  --label <NAME>             operator's name for the miner being added
");
    println!("PAYOUTS");
    println!("  --wallet <KEYFILE>         the pool's own key; without it, books are kept but not settled");
    println!("  --ledger <PATH>            payout ledger (default pool-ledger.txt)");
    println!("  --payout-threshold <NOCT>  minimum balance before paying out (default 1)");
    println!("  --payout-fee <NOCT>        transaction fee per payout batch (default 0.01)");
    println!("  --fee-percent <N>          operator's cut of each block (default 0 — miners get all of it)");
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    /// A share must cost far more than a read. The pool re-hashes every
    /// submission, so if the two were priced alike an attacker could spend a
    /// trivial budget forcing thousands of proof-of-work verifications.
    #[test]
    fn a_share_is_priced_above_a_read() {
        assert!(COST_SUBMIT > COST_TEMPLATE, "a share must cost more than a template");
        assert!(COST_TEMPLATE > COST_READ, "a template must cost more than a stat read");
        assert!(
            COST_SUBMIT >= 10 * COST_READ,
            "the gap must be an order of magnitude, or the expensive path is effectively free"
        );
    }

    /// The default budget has to leave an honest miner unaffected, or operators
    /// will simply disable it — which is worse than a loose limit.
    #[test]
    fn the_default_budget_suits_an_honest_miner() {
        let shares_per_second = DEFAULT_POOL_RATE / COST_SUBMIT;
        assert!(
            shares_per_second >= 15,
            "only {shares_per_second} shares/s allowed — too tight for a real miner"
        );
        assert!(
            shares_per_second <= 100,
            "{shares_per_second} shares/s is so loose it stops being a limit"
        );
    }

    /// The connection cap must be generous enough for a real pool but finite.
    #[test]
    fn the_connection_cap_is_finite_and_sane() {
        assert!(MAX_CONNECTIONS >= 128, "too small for a pool with real miners");
        assert!(MAX_CONNECTIONS <= 4096, "large enough to exhaust threads");
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    const ALICE: &str = "XpFhRq1RhDJBzFz2LTvKXJUPJaMruVS7iLHWPKPiJNwYJE2387xqiEH1gD9F3U74Poxc7tWNifGhNmTZxDKS5RJh6hb17i";
    const BOB: &str = "CTWi92gyQjPBRFzuyck69w7Zfvg7USJMLQTh1sipSHYD9dW3uxfWYdBzrVt3pQRUJYtRHScT9EAEA5BGWE7o7tHp7wAUCY";

    /// Named by the caller, not derived from the content: two tests whose files
    /// happen to be the same length would otherwise share a path and race, which
    /// is exactly what happened.
    fn auth_with(name: &str, lines: &str) -> (MinerAuth, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("noct-cred-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("miners.txt");
        std::fs::write(&p, lines).unwrap();
        (MinerAuth::load(&p).unwrap(), p)
    }

    /// The property the whole feature exists for. With credentials on, a miner
    /// cannot choose where it is paid: the token decides, and an address on the
    /// request is ignored rather than merged, preferred, or fallen back to.
    #[test]
    fn a_credential_fixes_the_payout_address_and_the_request_cannot_override_it() {
        let alice_token = auth::new_token();
        let (auth, _) = auth_with("fixes-payout", &format!("{alice_token} {ALICE} alice\n"));
        let none = HashMap::new();

        // Alice asks to be paid at Bob's address. She is paid at her own.
        let who = identify(Some(&auth), Some(&alice_token), Some(BOB), None, None, &none).unwrap();
        assert_eq!(who.payout, ALICE, "the token, not the request, decides the payee");

        // And with no address at all, it still resolves — there is nothing left
        // for a miner to get wrong.
        let who = identify(Some(&auth), Some(&alice_token), None, None, None, &none).unwrap();
        assert_eq!(who.payout, ALICE);
    }

    /// An unregistered miner is refused outright — that is what "private pool"
    /// has to mean. The message must not distinguish absent from wrong from
    /// revoked, or it tells a guesser how far they got.
    #[test]
    fn an_unregistered_miner_is_refused() {
        let good = auth::new_token();
        let (auth, _) = auth_with("unregistered", &format!("{good} {ALICE}\n"));
        let none = HashMap::new();

        let mut messages = Vec::new();
        for bad in [None, Some(""), Some("hunter2"), Some(auth::new_token().as_str())] {
            let e = identify(Some(&auth), bad, Some(ALICE), None, None, &none)
                .expect_err("must be refused");
            messages.push(e);
        }
        assert!(
            messages.windows(2).all(|w| w[0] == w[1]),
            "every refusal must read identically: {messages:?}"
        );
    }

    /// With no credentials configured the pool is a public one and behaves
    /// exactly as before — this feature must not quietly close an open pool.
    #[test]
    fn without_credentials_the_pool_stays_open() {
        let none = HashMap::new();
        let who = identify(None, None, Some(ALICE), None, None, &none).unwrap();
        assert_eq!(who.payout, ALICE);
        assert_eq!(who.session, ALICE, "no worker name means the session is just the payee");
    }

    /// Worker names separate *sessions*, never *payees*. Two rigs are metered
    /// apart for vardiff and stats, and both are paid to the one address —
    /// getting this backwards would split someone's earnings in two.
    #[test]
    fn worker_names_split_the_session_but_never_the_payout() {
        let token = auth::new_token();
        let (auth, _) = auth_with("workers", &format!("{token} {ALICE}\n"));
        let none = HashMap::new();

        let a = identify(Some(&auth), Some(&token), None, Some("rig-1"), None, &none).unwrap();
        let b = identify(Some(&auth), Some(&token), None, Some("rig-2"), None, &none).unwrap();

        assert_eq!(a.payout, b.payout, "both rigs are paid to the same address");
        assert_eq!(a.payout, ALICE);
        assert_ne!(a.session, b.session, "but they are metered apart");

        // A hostile worker name cannot escape into the stats JSON, and cannot
        // cost the miner its identity either.
        let ugly = identify(Some(&auth), Some(&token), None, Some("a\"b\\c\nd"), None, &none).unwrap();
        assert_eq!(ugly.payout, ALICE);
        assert!(!ugly.session.contains('"') && !ugly.session.contains('\\') && !ugly.session.contains('\n'));
    }

    /// A revoked miner is one deleted line away, and revoking one must not
    /// disturb anyone else — the thing IP bans cannot do.
    #[test]
    fn revoking_one_miner_leaves_the_others_working() {
        let t1 = auth::new_token();
        let t2 = auth::new_token();
        let (before, path) = auth_with("revoke", &format!("{t1} {ALICE}\n{t2} {BOB}\n"));
        assert!(before.lookup(&t1).is_some() && before.lookup(&t2).is_some());

        std::fs::write(&path, format!("{t2} {BOB}\n")).unwrap();
        let after = MinerAuth::load(&path).unwrap();
        assert!(after.lookup(&t1).is_none(), "the revoked token must stop working");
        assert_eq!(after.lookup(&t2).unwrap().payout, BOB, "everyone else is untouched");
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The attack the trust list exists to stop. If `X-Forwarded-For` were
    /// believed from anyone, a single miner could put a different fake address
    /// in the header on every request and give itself an unbounded number of
    /// rate-limit buckets — which is exactly the CPU exhaustion the limiter was
    /// added to prevent (F22). An untrusted sender is billed to its real socket
    /// address, header or no header.
    #[test]
    fn a_forwarded_header_from_an_untrusted_peer_is_ignored() {
        let trusted = HashSet::new();
        let real = ip("203.0.113.9");
        for claim in ["198.51.100.1", "10.0.0.1", "not-an-ip", ""] {
            assert_eq!(
                client_ip(Some(real), Some(claim), &trusted),
                Some(real),
                "claim {claim:?} must not change who is billed"
            );
        }
    }

    /// And the reason it exists at all: behind a TLS-terminating proxy every
    /// miner arrives from the proxy's address, so without this the whole pool
    /// shares one bucket and the limiter throttles everybody at once.
    #[test]
    fn a_trusted_proxy_can_name_the_real_client() {
        let proxy = ip("127.0.0.1");
        let trusted: HashSet<IpAddr> = [proxy].into_iter().collect();

        let a = client_ip(Some(proxy), Some("198.51.100.7"), &trusted);
        let b = client_ip(Some(proxy), Some("198.51.100.8"), &trusted);
        assert_eq!(a, Some(ip("198.51.100.7")));
        assert_eq!(b, Some(ip("198.51.100.8")));
        assert_ne!(a, b, "two miners behind one proxy must not share a bucket");
    }

    /// A proxy appends the address *it* saw; anything further left was supplied
    /// by the client and is unverifiable. Taking the last entry means a miner
    /// cannot prepend a forged address and be billed as someone else.
    #[test]
    fn only_the_entry_the_proxy_appended_is_used() {
        let proxy = ip("127.0.0.1");
        let trusted: HashSet<IpAddr> = [proxy].into_iter().collect();
        assert_eq!(
            client_ip(Some(proxy), Some("198.51.100.1, 203.0.113.4"), &trusted),
            Some(ip("203.0.113.4")),
            "the client-supplied left-hand entry must not win"
        );
    }

    /// A trusted proxy that sends nothing usable must fall back to its own
    /// address, not to "unbilled". Anything else is a free pass.
    #[test]
    fn a_trusted_proxy_with_no_usable_header_still_gets_billed() {
        let proxy = ip("127.0.0.1");
        let trusted: HashSet<IpAddr> = [proxy].into_iter().collect();
        assert_eq!(client_ip(Some(proxy), None, &trusted), Some(proxy));
        assert_eq!(client_ip(Some(proxy), Some("garbage"), &trusted), Some(proxy));
        assert_eq!(client_ip(Some(proxy), Some(""), &trusted), Some(proxy));
    }
}

#[cfg(test)]
mod attribution_tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ALICE: &str = "XpFhRq1RhDJBzFz2LTvKXJUPJaMruVS7iLHWPKPiJNwYJE2387xqiEH1gD9F3U74Poxc7tWNifGhNmTZxDKS5RJh6hb17i";

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    /// THE BUG THIS FIXES. Two rigs behind one router share a source IP. Keyed
    /// only by IP, the second to fetch work overwrote the first, and from then on
    /// *both* miners' shares were paid to whichever address registered last.
    /// Several rigs behind one NAT is the ordinary home setup, so this paid real
    /// money to the wrong person — silently, to both of them.
    #[test]
    fn two_rigs_behind_one_nat_are_not_confused() {
        let shared_ip = ip(7);
        let mut registered = HashMap::new();
        // Rig B asked for work most recently, so the per-IP map names B.
        registered.insert(shared_ip, "rig-b-address".to_string());

        // A share that carries its own address is credited to *that* miner,
        // regardless of what the shared IP last registered.
        assert_eq!(
            attribute_miner(Some(ALICE), Some(shared_ip), &registered),
            ALICE,
            "a submission's own address must win over the shared per-IP entry"
        );

        // Without one, we still fall back — and this is exactly the case that was
        // silently wrong, which is why the miner now always sends it.
        assert_eq!(attribute_miner(None, Some(shared_ip), &registered), "rig-b-address");
    }

    /// Found by running a client with a junk `--address` against a live pool: it
    /// was registered as a miner identity, accrued 2% of the PPLNS window, and
    /// could never be paid — so that 2% of every reward was allocated and then
    /// lost, diluting every miner who *could* be paid.
    ///
    /// The registration path now validates like the submission path does. This
    /// test pins the invariant it protects: nothing that fails to decode may end
    /// up carrying weight.
    #[test]
    fn an_undecodable_address_never_becomes_a_paid_identity() {
        let from = ip(9);
        // What the registration path now allows into the map.
        let admit = |addr: &str| Address::decode(addr.trim()).is_ok();
        for junk in ["x", "", "   ", "not-an-address", &"z".repeat(95)] {
            assert!(!admit(junk), "{junk:?} must never be registered");
        }
        assert!(admit(ALICE), "a real address must still be accepted");

        // With nothing valid ever registered, work falls back to the source IP —
        // visible to the operator in /stats, and not mistakable for a payee.
        let empty = HashMap::new();
        assert_eq!(attribute_miner(Some("x"), Some(from), &empty), from.to_string());
    }

    /// An address that cannot be decoded must not be trusted: it would be
    /// unspendable, and the failure would surface at settlement, long after the
    /// work was done and the miner had gone.
    #[test]
    fn an_undecodable_address_is_refused_and_falls_back() {
        let mut registered = HashMap::new();
        registered.insert(ip(1), "registered-address".to_string());
        for bad in ["", "   ", "not-an-address", "C0000000000000000000"] {
            assert_eq!(
                attribute_miner(Some(bad), Some(ip(1)), &registered),
                "registered-address",
                "garbage address {bad:?} must not be credited"
            );
        }
    }

    /// Work must never be silently uncredited — an operator has to be able to see
    /// it in `/stats` and sort it out.
    #[test]
    fn unknown_miners_still_get_attributed_to_something() {
        let empty = HashMap::new();
        assert_eq!(attribute_miner(None, Some(ip(9)), &empty), "10.0.0.9");
        assert_eq!(attribute_miner(None, None, &empty), "unknown");
    }

    /// Distinct IPs were always fine; make sure the fix did not regress them.
    #[test]
    fn separate_miners_on_separate_ips_are_unaffected() {
        let mut registered = HashMap::new();
        registered.insert(ip(1), "miner-one".to_string());
        registered.insert(ip(2), "miner-two".to_string());
        assert_eq!(attribute_miner(None, Some(ip(1)), &registered), "miner-one");
        assert_eq!(attribute_miner(None, Some(ip(2)), &registered), "miner-two");
    }
}

#[cfg(test)]
mod vardiff_daemon_tests {
    use super::*;

    fn params() -> VardiffParams {
        VardiffParams { target_secs: 15.0, min: 100, max: 1_000_000, max_step: 4.0 }
    }

    /// A miner that has never submitted anything keeps the starting target.
    /// Retuning on no evidence would be guessing.
    #[test]
    fn a_new_miner_keeps_the_base_target() {
        let mut a = HashMap::new();
        assert_eq!(issue_difficulty(&mut a, "fresh", 1_000, &params()), 1_000);
        // Asking again changes nothing while there is still no measurement.
        assert_eq!(issue_difficulty(&mut a, "fresh", 1_000, &params()), 1_000);
    }

    /// The case vardiff exists for: a rig submitting far too fast is moved up,
    /// so it stops spending its rate-limit budget on needless shares.
    #[test]
    fn a_flooding_miner_is_moved_up_and_its_old_target_remembered() {
        let mut a = HashMap::new();
        issue_difficulty(&mut a, "fast", 1_000, &params());
        // Pretend it has been finding a share every second — 15x too fast.
        a.get_mut("fast").unwrap().ewma_secs = 1.0;

        let issued = issue_difficulty(&mut a, "fast", 1_000, &params());
        assert_eq!(issued, 4_000, "clamped to one max_step up");
        let entry = &a["fast"];
        assert_eq!(entry.current, 4_000);
        assert_eq!(
            entry.previous, 1_000,
            "the old target must be remembered, or work already in flight is lost"
        );
    }

    /// A slow miner gets an easier target, so it can earn inside the window.
    #[test]
    fn a_slow_miner_is_moved_down() {
        let mut a = HashMap::new();
        issue_difficulty(&mut a, "slow", 10_000, &params());
        a.get_mut("slow").unwrap().ewma_secs = 120.0; // 8x too slow
        assert_eq!(issue_difficulty(&mut a, "slow", 10_000, &params()), 2_500);
    }

    /// Timing must smooth rather than track the last sample, or the controller
    /// chases Poisson noise and oscillates.
    #[test]
    fn share_timing_is_smoothed() {
        let mut a = Assignment {
            current: 1_000,
            previous: 1_000,
            last_share: None,
            ewma_secs: f64::NAN,
            rejected_streak: 0,
            last_rejection: "",
        };
        let t0 = std::time::Instant::now();
        // First share: nothing to measure against yet.
        record_share_timing(&mut a, t0);
        assert!(!a.ewma_secs.is_finite(), "one share is not an interval");

        // Second share 10s later seeds the average.
        record_share_timing(&mut a, t0 + Duration::from_secs(10));
        let first = a.ewma_secs;
        assert!((first - 10.0).abs() < 0.5, "seeded from the first real gap, got {first}");

        // A wildly different third sample must move it, but not all the way.
        record_share_timing(&mut a, t0 + Duration::from_secs(10) + Duration::from_secs(100));
        assert!(a.ewma_secs > first, "it moved toward the new sample");
        assert!(a.ewma_secs < 100.0, "but did not jump straight to it ({})", a.ewma_secs);
    }

    /// The floor must hold even when the base target is below it.
    #[test]
    fn the_configured_floor_is_respected() {
        let p = VardiffParams { min: 500, ..params() };
        let mut a = HashMap::new();
        issue_difficulty(&mut a, "m", 100, &p);
        a.get_mut("m").unwrap().ewma_secs = 10_000.0; // absurdly slow
        assert!(issue_difficulty(&mut a, "m", 100, &p) >= 500);
    }
}

/// The pool must sync its own wallet against the network it is actually mining
/// on. This was hardcoded to mainnet, which is invisible on mainnet and fatal
/// on testnet: the wallet builds the wrong genesis, the first block it
/// validates fails `BadPrevId`, and every payout is skipped forever while the
/// ledger keeps crediting miners. Found on the live testnet, where the pool had
/// booked 53 NOCT to two miners and sent nothing.
#[cfg(test)]
mod payout_network_tests {
    use noct_core::address::{Address, Network};
    use noct_wallet::Wallet;
    use rand_core::OsRng;

    /// The property that makes the bug unrepresentable: the network is read off
    /// the pool's own payout address, so it cannot disagree with the chain whose
    /// rewards are being paid to that address.
    fn network_of(addr: &str) -> Network {
        Address::decode(addr.trim()).expect("valid address").network
    }

    #[test]
    fn the_network_comes_from_the_pool_address_not_a_constant() {
        let m = Wallet::random(&mut OsRng, Network::Mainnet).address().encode();
        let t = Wallet::random(&mut OsRng, Network::Testnet).address().encode();

        assert_eq!(network_of(&m), Network::Mainnet);
        assert_eq!(
            network_of(&t),
            Network::Testnet,
            "a testnet pool must resolve to Testnet; resolving to Mainnet is the payout bug"
        );
    }

    /// The tags stay distinguishable across many keys. If they ever collided,
    /// deriving the network from the address would silently break.
    #[test]
    fn mainnet_and_testnet_addresses_are_never_confusable() {
        for _ in 0..32 {
            let m = Wallet::random(&mut OsRng, Network::Mainnet).address().encode();
            let t = Wallet::random(&mut OsRng, Network::Testnet).address().encode();
            assert_eq!(network_of(&m), Network::Mainnet);
            assert_eq!(network_of(&t), Network::Testnet);
            assert_ne!(m, t);
        }
    }
}

/// A rig whose every submission is refused earns nothing while spending real
/// electricity, and cannot tell — the pool answers each request normally, and
/// `/stats` just shows work that stopped rising, which is what an idle rig also
/// looks like. Observed live: two rigs at ~99% CPU for 45 minutes, every share
/// rejected, no warning anywhere.
#[cfg(test)]
mod rejection_streak_tests {
    use super::*;

    fn assignment() -> Assignment {
        Assignment {
            current: 200,
            previous: 200,
            last_share: None,
            ewma_secs: f64::NAN,
            rejected_streak: 0,
            last_rejection: "",
        }
    }

    /// Isolated model of the streak rules, so the thresholds are pinned without
    /// standing up a pool: count runs, reset on success, restart on a new reason.
    fn reject(a: &mut Assignment, reason: &'static str) -> bool {
        if a.last_rejection != reason {
            a.rejected_streak = 0;
            a.last_rejection = reason;
        }
        a.rejected_streak += 1;
        a.rejected_streak % REJECTION_STREAK_WARN == 0
    }
    fn accept(a: &mut Assignment) {
        a.rejected_streak = 0;
        a.last_rejection = "";
    }

    /// The point of the threshold: ordinary life must stay silent. A share found
    /// just as the tip moves is stale through nobody's fault, and warning on it
    /// would train the operator to ignore the message that matters.
    #[test]
    fn occasional_rejections_never_warn() {
        let mut a = assignment();
        for _ in 0..200 {
            for _ in 0..(REJECTION_STREAK_WARN - 1) {
                assert!(!reject(&mut a, "stale job"), "a short run must stay quiet");
            }
            accept(&mut a);
        }
        assert_eq!(a.rejected_streak, 0);
    }

    #[test]
    fn an_unbroken_run_warns_and_keeps_reminding() {
        let mut a = assignment();
        let mut warned = 0;
        for _ in 0..(REJECTION_STREAK_WARN * 4) {
            if reject(&mut a, "duplicate share") {
                warned += 1;
            }
        }
        assert_eq!(warned, 4, "once at the threshold, then once per threshold after");
    }

    /// An accepted share means work is being credited again, whatever came
    /// before — so the run is genuinely over, not merely paused.
    #[test]
    fn one_accepted_share_clears_the_run() {
        let mut a = assignment();
        for _ in 0..(REJECTION_STREAK_WARN - 1) {
            reject(&mut a, "duplicate share");
        }
        accept(&mut a);
        assert_eq!(a.rejected_streak, 0);
        assert!(!reject(&mut a, "duplicate share"), "the count starts over");
    }

    /// A changed reason is a different fault, and counting them together would
    /// hide both: 24 stale + 24 duplicate is not one run of 48.
    #[test]
    fn a_different_reason_starts_a_new_run() {
        let mut a = assignment();
        for _ in 0..(REJECTION_STREAK_WARN - 1) {
            reject(&mut a, "stale job");
        }
        assert!(!reject(&mut a, "duplicate share"), "a new reason restarts the count");
        assert_eq!(a.rejected_streak, 1);
        assert_eq!(a.last_rejection, "duplicate share");
    }
}
