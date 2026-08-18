//! `noct-miner` — a reference **external** miner.
//!
//! It mines against a `noctd` node over the node's HTTP RPC, computing the same
//! proof-of-work the node validates:
//!
//!   1. `GET  /getblocktemplate?address=<yours>` — fetch an unmined block that
//!      pays your address, plus the target difficulty and the epoch seed.
//!   2. grind `header.nonce` locally until `pow_hash` meets the difficulty.
//!   3. `POST /submitblock` — submit the solved block; the node re-validates and
//!      relays it.
//!
//! This decouples mining from the node binary: anyone can point this (or a pool)
//! at a public node. The default build mines the Keccak placeholder; build with
//! `--features randomx` to mine a RandomX node (needs the RandomX toolchain).
//!
//! ```text
//! noct-miner --address <B58> [--node URL] [--token TOKEN | --token-file PATH]
//!            [--pool-fingerprint SHA256] [--worker NAME]
//! ```
//!
//! `--worker` names this rig. A pool uses it to meter several machines under one
//! payout address separately; without it they share one difficulty assignment,
//! and a target averaged across a fast rig and a slow one suits neither.
//!
//! Against a pool that registers its miners, `--token-file` carries the
//! credential the operator issued. The payout address is then fixed by that
//! registration and `--address` is ignored.
//!
//! `--token` is required when the node's RPC is authenticated (any node serving
//! its RPC off-box must be). Prefer `--token-file`: a token passed on the command
//! line is visible in the process list and shell history.
//!
//! ## Mining to something across the internet
//!
//! Give `--node` an `https://` address. It matters more than it looks: every
//! request carries the address the reward should be paid to, so on a plaintext
//! connection anyone in the middle can **replace that address with their own**.
//! The miner would see its work accepted exactly as before and simply never be
//! paid — a failure with no visible symptom until the money does not arrive.
//!
//! A pool with an ordinary certificate needs nothing further. A pool using a
//! self-signed certificate publishes a fingerprint; pass it as
//! `--pool-fingerprint` and only that certificate is accepted.

use std::io::Write;
use std::time::Duration;

use noct_core::p2p::Wire;
use noct_core::pow::{check_hash, Difficulty, ProofOfWork};
use noct_core::wire;
use noct_node::{new_pow, pow_name};
use noct_tls::Endpoint;
use rand_core::{OsRng, RngCore};

/// Nonces to try between template refreshes, so we stay near the tip and pick up
/// new transactions / a raised difficulty.
const BATCH: u32 = 250_000;

/// Marker on errors that are worth retrying (see `request`).
const RATE_LIMITED: &str = "rate limited";

/// How many times to re-attempt submitting a *solved* block before giving up.
const SUBMIT_RETRIES: u32 = 3;

/// What we mine against, and how we verify it is really that.
struct Node {
    endpoint: Endpoint,
    /// Certificate to accept, when the pool or node is self-signed.
    pin: Option<[u8; 32]>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // `--pool` is the same thing said the way a miner thinks about it.
    let node = flag(&args, "--node")
        .or_else(|| flag(&args, "--pool"))
        .unwrap_or_else(|| "127.0.0.1:9334".to_string());
    let endpoint = Endpoint::parse(&node, 9334).unwrap_or_else(|e| fail(&format!("--node: {e}")));
    let pin = flag(&args, "--pool-fingerprint")
        .or_else(|| flag(&args, "--node-fingerprint"))
        .map(|f| noct_tls::parse_fingerprint(&f).unwrap_or_else(|e| fail(&e)));
    let node = Node { endpoint, pin };
    // Names this rig so a pool can meter several machines under one payout
    // address separately. Without it they share a vardiff assignment, and a
    // target blended across a fast rig and a slow one suits neither.
    let worker = flag(&args, "--worker")
        .map(|w| format!("&worker={}", w.trim()))
        .unwrap_or_default();
    let address = flag(&args, "--address")
        .unwrap_or_else(|| fail("usage: noct-miner --address <B58> [--pool URL | --node URL] [--token TOKEN | --token-file PATH] [--pool-fingerprint SHA256] [--worker NAME]"));
    let token = flag(&args, "--token").or_else(|| {
        flag(&args, "--token-file").map(|path| {
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| fail(&format!("reading {path}: {e}")))
                .trim()
                .to_string()
        })
    });

    eprintln!("noct-miner — mining {} to {}…", pow_name(), &address[..address.len().min(12)]);
    eprintln!("  node: {}{}", node.endpoint.display(), if node.pin.is_some() { " (pinned certificate)" } else { "" });

    let pow = new_pow();
    let mut current_seed = [0u8; 32];
    let mut seeded = false;
    let mut found: u64 = 0;

    loop {
        // 1. Fetch a template paying our address.
        let resp = match http_get(&node, &format!("/getblocktemplate?address={address}{worker}"), &token) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("template fetch failed: {e} (retrying)");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        // If the server tells us which proof of work it validates with, insist it
        // is the one we compute. Otherwise we would grind indefinitely while every
        // submission came back "does not meet the target" — a message that points
        // at difficulty and hides the real cause.
        if let Some(theirs) = json_str(&resp, "pow") {
            if theirs != pow_name() {
                fail(&format!(
                    "proof-of-work mismatch: this miner computes {}, but {} validates {theirs}.\n\
                     Rebuild the miner to match (the RandomX build needs --features randomx).",
                    pow_name(),
                    node.endpoint.display()
                ));
            }
        }
        let (Some(difficulty), Some(seed), Some(template)) = (
            json_u64(&resp, "difficulty"),
            json_hex(&resp, "seed_hash"),
            json_hex(&resp, "template"),
        ) else {
            // A pool legitimately has no work for a moment after it finds a block,
            // while it fetches the next template. Reporting that as "malformed"
            // trains an operator to ignore the message — and then a genuinely
            // malformed response goes unnoticed. Say which one it is.
            if let Some(reason) = json_str(&resp, "error") {
                eprintln!("waiting for work: {reason}");
            } else {
                eprintln!("malformed template response (retrying)");
            }
            std::thread::sleep(Duration::from_secs(2));
            continue;
        };
        let (mut block, txs) = match wire::decode_message(&template) {
            Ok(Wire::Block(b, t)) => (b, t),
            _ => {
                eprintln!("could not decode template (retrying)");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let height = block.coinbase.height;

        // 2. Key the PoW to this template's epoch seed. Only on change: RandomX
        //    rebuilds a VM here (~seconds); Keccak ignores the seed entirely.
        let seed: [u8; 32] = match seed.try_into() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !seeded || seed != current_seed {
            pow.reseed(&seed);
            current_seed = seed;
            seeded = true;
        }

        // 3. Grind a batch of nonces from a random start (so parallel miners to
        //    the same address don't all try the same nonces first).
        let start = OsRng.next_u32();
        let mut solved = None;
        for i in 0..BATCH {
            block.header.nonce = start.wrapping_add(i);
            if check_hash(&block.pow_hash(&pow), difficulty as Difficulty) {
                solved = Some(block.header.nonce);
                break;
            }
        }

        // 4. Submit any solution.
        //
        // A solved block cost real work, so a *transient* refusal (rate limiting,
        // a dropped connection) is retried with a short backoff rather than
        // throwing the solution away. Retries are few and brief: once the chain
        // moves on, the block is stale and worth nothing anyway.
        let Some(nonce) = solved else { continue };
        block.header.nonce = nonce;
        let body = hex::encode(wire::encode_message(&Wire::Block(block, txs)));
        for attempt in 0..=SUBMIT_RETRIES {
            // Carry our payout address on the submission itself. A pool that
            // attributes shares only by source IP credits the wrong miner when
            // several rigs share one router; the node ignores the parameter.
            let submit_path = format!("/submitblock?address={address}{worker}");
            match http_post(&node, &submit_path, &body, &token) {
                Ok(reply) if reply.contains("\"accepted\"") => {
                    found += 1;
                    eprintln!("✔ block at height {height} accepted (total {found}) — {}", reply.trim());
                    break;
                }
                // The node understood us and said no (stale/invalid) — retrying
                // cannot help.
                Ok(reply) => {
                    eprintln!("submit rejected: {}", reply.trim());
                    break;
                }
                Err(e) if attempt < SUBMIT_RETRIES => {
                    let backoff = Duration::from_millis(200 * (1 << attempt));
                    eprintln!("submit failed ({e}); retrying in {backoff:?}");
                    std::thread::sleep(backoff);
                }
                Err(e) => eprintln!("submit failed after {SUBMIT_RETRIES} retries: {e}"),
            }
        }
    }
}

// --- tiny HTTP + JSON (the node RPC is a flat JSON object) -------------------

/// `Authorization: Bearer …` line for an authenticated node, or nothing.
fn auth_header(token: &Option<String>) -> String {
    match token {
        Some(t) => format!("Authorization: Bearer {t}\r\n"),
        None => String::new(),
    }
}

fn http_get(node: &Node, path: &str, token: &Option<String>) -> Result<String, String> {
    request(
        node,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            node.endpoint.authority(),
            auth_header(token)
        ),
    )
}

fn http_post(node: &Node, path: &str, body: &str, token: &Option<String>) -> Result<String, String> {
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

fn request(node: &Node, raw: &str) -> Result<String, String> {
    let mut stream = noct_tls::connect_pinned(&node.endpoint, node.pin)?;
    stream.write_all(raw.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let response = noct_tls::read_response(&mut stream)?;
    // Report an auth failure as such — otherwise the caller only sees a body it
    // cannot parse and reports a misleading "malformed response".
    if response.status == 401 {
        return Err(
            "unauthorized: this node's RPC requires a token — pass --token / --token-file".to_string(),
        );
    }
    // Marked so callers can distinguish a *transient* refusal worth retrying
    // from a permanent one.
    if response.status == 429 {
        return Err(format!("{RATE_LIMITED}: the node is rate-limiting us"));
    }
    Ok(response.body)
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
