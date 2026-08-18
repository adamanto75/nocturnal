//! `noct-web` — the public website and block explorer.
//!
//! ## Why this exists instead of pointing a browser at the node
//!
//! A node's RPC is an **administrative** surface: `/mine`, `/submitblock`,
//! `/submit_tx`, `/mining/start|stop|threads`. Exposing it to the internet so a
//! web page could read the chain height would hand every visitor the ability to
//! start and stop mining and to inject blocks and transactions. Putting a
//! read-only reverse proxy in front is not enough either, because then the
//! *proxy configuration* is the only thing standing between the public and those
//! endpoints, and a proxy rule is easy to get subtly wrong.
//!
//! So this serves the site and answers a **fixed, whitelisted set of read-only
//! questions** by asking the node itself:
//!
//! * the node's RPC token lives here and is never sent to a browser;
//! * there is **no POST handler at all** — not a rejected one, none;
//! * a path that is not explicitly matched below is a 404. The admin endpoints
//!   are not blocked, they are **unreachable by construction**, which is the
//!   difference between a deny-list and a design.
//!
//! The node it reads from should still bind its RPC to loopback. This process
//! talks to it locally and is the only thing that faces the network.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use noct_node::rpc::{client_ip, RateLimiter};
use noct_tls::{Acceptor, Endpoint, Stream};
use noct_wallet::client::NodeClient;

/// The whole site, compiled in. One binary to deploy, and no directory of
/// assets that can be served by accident or go missing.
const INDEX_HTML: &str = include_str!("ui/index.html");

/// Per-IP request budget, in cost units per second. Explorer reads are cheap but
/// they each cost the node a round trip, so an unmetered page could be used to
/// hammer the node through us.
const DEFAULT_RATE: u32 = 120;
const COST_PAGE: u32 = 1;
const COST_API: u32 = 4;

/// Most recent blocks the explorer's front page will list. Bounded because each
/// one is a separate request to the node.
const RECENT_BLOCKS: u64 = 15;

const MAX_CONNECTIONS: usize = 256;

/// Caps on the request head. Generous for any real browser — a heavy request
/// with cookies is a few KiB — and small enough that neither a thread nor the
/// line buffer can be held open indefinitely by a client that simply never
/// finishes sending.
const MAX_HEAD_BYTES: u64 = 16 * 1024;
const MAX_HEADERS: usize = 64;

/// How long a connection may sit without progress before it is dropped. Ample
/// for a request over a slow link; short enough that a connection slot cannot be
/// squatted on for free.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// The literal in `index.html` that selects where chain data comes from.
/// Rewritten when emitting a static site. See `emit_static`.
const SOURCE_MARKER: &str = "const CHAIN_SOURCE = \"live\";";
const SOURCE_SNAPSHOT: &str = "const CHAIN_SOURCE = \"snapshot\";";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        help();
        return;
    }

    let listen = flag(&args, "--listen").unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let node = flag(&args, "--node").unwrap_or_else(|| "127.0.0.1:19334".to_string());
    let node = Endpoint::parse(&node, 19334).unwrap_or_else(|e| fail(&format!("--node: {e}")));
    let emit_static = flag(&args, "--emit-static");
    let node_pin = flag(&args, "--node-fingerprint")
        .map(|f| noct_tls::parse_fingerprint(&f).unwrap_or_else(|e| fail(&e)));
    // Read from a file by preference: a token on the command line is visible in
    // the process list to every user on the box.
    let token = flag(&args, "--node-token").or_else(|| {
        flag(&args, "--node-token-file").map(|p| {
            std::fs::read_to_string(&p)
                .unwrap_or_else(|e| fail(&format!("reading {p}: {e}")))
                .trim()
                .to_string()
        })
    });
    let rate: u32 = flag(&args, "--rate-limit").and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_RATE);

    // Addresses whose `X-Forwarded-For` we believe. See `client_ip`. Behind a
    // reverse proxy this is not optional: without it every visitor is metered as
    // the proxy, and one busy minute rate-limits the entire site.
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

    let acceptor = match (flag(&args, "--tls-cert"), flag(&args, "--tls-key")) {
        (Some(c), Some(k)) => Some(
            Acceptor::from_pem(Path::new(&c), Path::new(&k))
                .unwrap_or_else(|e| fail(&format!("TLS: {e}"))),
        ),
        (None, None) => None,
        _ => fail("--tls-cert and --tls-key must be given together"),
    };

    // Publishing mode: write the site to a directory and exit. No listener is
    // opened, so this is safe to run anywhere the node is reachable.
    if let Some(dir) = emit_static {
        let ctx = Ctx { node, token, node_pin, trusted_proxies: HashSet::new() };
        match emit_static_site(&ctx, Path::new(&dir)) {
            Ok(n) => {
                eprintln!("wrote {dir}/index.html and {dir}/chain.json ({n} blocks)");
                return;
            }
            Err(e) => fail(&format!("--emit-static: {e}")),
        }
    }

    eprintln!("noct-web starting");
    eprintln!("  listen:    {listen}");
    eprintln!("  node:      {}", node.display());
    eprintln!("  transport: {}", if acceptor.is_some() { "TLS" } else { "PLAINTEXT (fine behind a TLS proxy; otherwise pass --tls-cert/--tls-key)" });
    eprintln!("  api:       read-only whitelist; no POST handler exists");

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| fail(&format!("bind {listen}: {e}")));
    let limiter = Arc::new(RateLimiter::new(rate));
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ctx = Arc::new(Ctx { node, token, node_pin, trusted_proxies });

    for tcp in listener.incoming().flatten() {
        use std::sync::atomic::Ordering;
        if live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            let mut s = Stream::Plain(tcp);
            let _ = respond(&mut s, "503 Service Unavailable", "text/plain", "busy");
            continue;
        }
        // Before the TLS handshake, so a peer that opens a socket and then says
        // nothing cannot stall in the handshake either.
        //
        // Without these, a client can hold a connection open forever by simply
        // never finishing its request, and the rate limiter cannot help: it is
        // consulted *after* the head is read, so a request that never completes
        // never reaches it. Measured on this server, 256 silent half-open
        // connections — no bandwidth, no completed requests — put every real
        // visitor on a 503.
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));

        let stream = match &acceptor {
            Some(a) => match a.accept(tcp) {
                Ok(s) => s,
                Err(_) => continue,
            },
            None => Stream::Plain(tcp),
        };
        live.fetch_add(1, Ordering::Relaxed);
        let limiter = Arc::clone(&limiter);
        let ctx = Arc::clone(&ctx);
        let guard = Arc::clone(&live);
        thread::spawn(move || {
            let _ = handle(stream, &ctx, &limiter);
            guard.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

struct Ctx {
    node: Endpoint,
    token: Option<String>,
    node_pin: Option<[u8; 32]>,
    /// Addresses whose `X-Forwarded-For` is believed. Empty unless the operator
    /// names a proxy, so the header is inert by default.
    trusted_proxies: HashSet<IpAddr>,
}

impl Ctx {
    fn client(&self) -> NodeClient {
        NodeClient::with_token(self.node.clone(), self.token.clone()).with_pin(self.node_pin)
    }
}

fn handle(stream: Stream, ctx: &Ctx, limiter: &RateLimiter) -> std::io::Result<()> {
    let socket_peer = stream.peer_addr().map(|a| a.ip()).ok();

    // The whole request head is capped. Without this, `read_line` in the loop
    // below is unbounded in both directions: a client that never sends a blank
    // line loops forever holding a thread, and one that never sends a newline
    // grows the line buffer without limit. Neither needs a large or fast client,
    // which is what makes it worth bounding rather than policing.
    let mut reader = BufReader::new(stream.take(MAX_HEAD_BYTES));

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    // Headers are otherwise read and discarded — no route accepts a body, so one
    // is never consumed. `X-Forwarded-For` is kept only to attribute rate limiting.
    let mut forwarded_for: Option<String> = None;
    let mut complete = false;
    for _ in 0..MAX_HEADERS {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        if h.trim_end().is_empty() {
            complete = true;
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("x-forwarded-for:") {
            forwarded_for = Some(v.trim().to_string());
        }
    }
    let mut out = reader.into_inner().into_inner();

    // A head that hit either cap is refused outright rather than served from
    // whatever was parsed before the limit — a truncated request line is not a
    // request, and guessing at one is how a router ends up matching something
    // the client never sent.
    if !complete {
        return respond(&mut out, "431 Request Header Fields Too Large", "text/plain", "request head too large");
    }

    // Only GET exists. POST, PUT, DELETE and anything else are refused before a
    // route is even considered, so no amount of path trickery reaches a mutating
    // node endpoint — there is nothing here that mutates.
    if method != "GET" {
        return respond(&mut out, "405 Method Not Allowed", "text/plain", "this server is read-only");
    }

    let cost = if path.starts_with("/api/") { COST_API } else { COST_PAGE };
    if let Some(ip) = client_ip(socket_peer, forwarded_for.as_deref(), &ctx.trusted_proxies) {
        if !limiter.allow(ip, cost) {
            return respond(&mut out, "429 Too Many Requests", "application/json", "{\"error\":\"slow down\"}");
        }
    }

    // The whitelist. Everything not named here 404s.
    match route(&path) {
        Route::Index => respond(&mut out, "200 OK", "text/html; charset=utf-8", INDEX_HTML),
        Route::Info => {
            let body = ctx.client().info().unwrap_or_else(|e| err_json(&e));
            respond(&mut out, "200 OK", "application/json", &body)
        }
        Route::Recent => {
            let body = recent_blocks(ctx);
            respond(&mut out, "200 OK", "application/json", &body)
        }
        Route::Block(h) => {
            let body = block_summary(ctx, h);
            respond(&mut out, "200 OK", "application/json", &body)
        }
        Route::NotFound => respond(&mut out, "404 Not Found", "text/plain", "not found"),
    }
}

enum Route {
    Index,
    Info,
    Recent,
    Block(u64),
    NotFound,
}

/// Map a request path to one of a fixed set of read-only actions.
///
/// Deliberately exhaustive and literal. There is no pass-through case, no
/// "forward whatever follows /api/ to the node", and no string concatenation
/// into a node URL — which is what would turn a path like
/// `/api/../mining/start` into a real problem.
fn route(path: &str) -> Route {
    let path = path.split('?').next().unwrap_or("");
    match path {
        "/" | "/index.html" => Route::Index,
        "/api/info" => Route::Info,
        "/api/blocks" => Route::Recent,
        _ => match path.strip_prefix("/api/block/") {
            // Parsed as a number, so nothing but digits can ever reach the node.
            Some(rest) => match rest.parse::<u64>() {
                Ok(h) => Route::Block(h),
                Err(_) => Route::NotFound,
            },
            None => Route::NotFound,
        },
    }
}

/// The most recent blocks, newest first.
fn recent_blocks(ctx: &Ctx) -> String {
    let client = ctx.client();
    let height = match client.height() {
        Ok(h) => h,
        Err(e) => return err_json(&e),
    };
    // `height` is the count of blocks, so the tip index is height-1.
    let tip = height.saturating_sub(1);
    let mut items = Vec::new();
    for h in (0..=tip).rev().take(RECENT_BLOCKS as usize) {
        match client.block(h) {
            Ok((block, txs)) => items.push(format!(
                "{{\"height\":{},\"id\":\"{}\",\"timestamp\":{},\"txs\":{},\"reward\":{}}}",
                block.coinbase.height,
                hex::encode(block.id()),
                block.header.timestamp,
                txs.len(),
                block.coinbase.total().unwrap_or(0)
            )),
            Err(_) => break,
        }
    }
    format!("{{\"blocks\":[{}]}}", items.join(","))
}

/// One block, decoded into the fields an explorer shows.
fn block_summary(ctx: &Ctx, height: u64) -> String {
    match ctx.client().block(height) {
        Ok((block, txs)) => {
            let tx_ids: Vec<String> =
                txs.iter().map(|t| format!("\"{}\"", hex::encode(t.hash()))).collect();
            format!(
                "{{\"height\":{},\"id\":\"{}\",\"prev\":\"{}\",\"timestamp\":{},\"nonce\":{},\
                 \"reward\":{},\"outputs\":{},\"txs\":[{}]}}",
                block.coinbase.height,
                hex::encode(block.id()),
                hex::encode(block.header.prev_id),
                block.header.timestamp,
                block.header.nonce,
                block.coinbase.total().unwrap_or(0),
                block.coinbase.outputs.len(),
                tx_ids.join(",")
            )
        }
        Err(e) => err_json(&e),
    }
}

/// Write the site as plain files for a network that has no server: Autonomi,
/// IPFS, a file share. Returns how many blocks the snapshot covers.
///
/// **Why a snapshot rather than an API URL.** The obvious alternative is to
/// leave the live explorer in place and point it at a public gateway. That
/// works, and it quietly undoes the reason for publishing here: every visitor's
/// browser would connect to whoever runs that gateway, handing them an IP for
/// each reader of a privacy coin's website. A file published inside the same
/// archive is read the same way the page itself is read, by whatever the visitor
/// already trusts to fetch it.
///
/// The cost is that the numbers are fixed at publication. That is stated on the
/// page rather than hidden — on an immutable network this file may still be
/// readable years from now, and a stale height presented as current is worse
/// than showing none.
fn emit_static_site(ctx: &Ctx, dir: &Path) -> Result<usize, String> {
    let client = ctx.client();
    let info = client.info().map_err(|e| format!("reading node info: {e}"))?;
    if info.contains("\"error\"") {
        return Err(format!("node returned an error: {info}"));
    }

    let height = client.height().map_err(|e| format!("reading height: {e}"))?;
    let tip = height.saturating_sub(1);
    let mut blocks = Vec::new();
    for h in (0..=tip).rev().take(RECENT_BLOCKS as usize) {
        match client.block(h) {
            Ok((block, txs)) => blocks.push(format!(
                "{{\"height\":{},\"id\":\"{}\",\"timestamp\":{},\"txs\":{},\"reward\":{}}}",
                block.coinbase.height,
                hex::encode(block.id()),
                block.header.timestamp,
                txs.len(),
                block.coinbase.total().unwrap_or(0)
            )),
            Err(e) => return Err(format!("reading block {h}: {e}")),
        }
    }

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_secs();

    // The marker must be rewritten exactly once. If the page is edited and the
    // literal drifts, this fails loudly — publishing a page that silently still
    // says "live" while carrying frozen numbers is the failure worth preventing,
    // and on an immutable network it cannot be taken back.
    let occurrences = INDEX_HTML.matches(SOURCE_MARKER).count();
    if occurrences != 1 {
        return Err(format!(
            "expected exactly one `{SOURCE_MARKER}` in index.html, found {occurrences} — \
             the page and the emitter have drifted apart"
        ));
    }
    let page = INDEX_HTML.replace(SOURCE_MARKER, SOURCE_SNAPSHOT);

    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let chain_json =
        format!("{{\"generated_at\":{generated_at},\"info\":{info},\"blocks\":[{}]}}", blocks.join(","));
    std::fs::write(dir.join("index.html"), page).map_err(|e| format!("writing index.html: {e}"))?;
    std::fs::write(dir.join("chain.json"), chain_json).map_err(|e| format!("writing chain.json: {e}"))?;
    Ok(blocks.len())
}

/// A deliberately uninformative error for the client, with the real one logged.
///
/// The node's errors name the node: `cannot reach http://10.10.10.75:19334`.
/// This server is the public face of a private node, so echoing that back would
/// publish the internal topology to every visitor. The operator gets the detail
/// on stderr; the visitor gets "the node is unreachable".
fn err_json(msg: &str) -> String {
    eprintln!("noct-web: upstream node error: {msg}");
    "{\"error\":\"upstream node unavailable\"}".to_string()
}

fn respond(out: &mut Stream, status: &str, content_type: &str, body: &str) -> std::io::Result<()> {
    // A static, restrictive CSP: the page is self-contained, so nothing should
    // ever be fetched from another origin. For a privacy coin's site that is not
    // decoration — a third-party font or script would report every visitor to
    // whoever serves it.
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    out.write_all(response.as_bytes())?;
    out.flush()?;
    out.close();
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn help() {
    println!("noct-web — the Noct website and block explorer\n");
    println!("USAGE\n  noct-web [options]\n");
    println!("OPTIONS");
    println!("  --listen <ADDR>            default 0.0.0.0:8080");
    println!("  --node <URL>               the node to read from (default 127.0.0.1:19334)");
    println!("  --node-token-file <PATH>   its RPC token — stays server-side, never sent to a browser");
    println!("  --node-token <TOKEN>       visible in the process list; prefer the file form");
    println!("  --node-fingerprint <HEX>   pin a self-signed node certificate");
    println!("  --tls-cert <PATH> --tls-key <PATH>   serve HTTPS directly");
    println!("  --rate-limit <N>           per-IP units/s (default 120; 0 disables)");
    println!("  --emit-static <DIR>        write the site + a chain.json snapshot and exit,");
    println!("                             for a network with no server (Autonomi, IPFS).");
    println!("                             No listener is opened.");
    println!("  --trusted-proxy <IP,IP>    believe X-Forwarded-For from these, and only these.");
    println!("                             Required behind a reverse proxy, or every visitor");
    println!("                             is rate-limited as the proxy.\n");
    println!("The node's RPC should stay bound to loopback. This process is the only");
    println!("thing that faces the network, and it exposes read-only routes only.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The security property of this whole binary.** The node's mutating
    /// endpoints must be unreachable — not blocked by a rule that could be
    /// mis-ordered, but absent from the routing table entirely.
    #[test]
    fn no_path_reaches_a_mutating_node_endpoint() {
        let dangerous = [
            "/mine",
            "/submitblock",
            "/submit_tx",
            "/mining/start",
            "/mining/stop",
            "/mining/threads",
            "/getblocktemplate",
            "/api/mine",
            "/api/submitblock",
            "/api/mining/start",
            // Traversal and encoding tricks against the one prefixed route.
            "/api/block/../mining/start",
            "/api/block/..%2Fmining%2Fstart",
            "/api/block/1/../../mine",
            "/api//mining/start",
            "/api/block/abc",
            "/api/",
            "/api",
            "/../../etc/passwd",
        ];
        for p in dangerous {
            assert!(
                matches!(route(p), Route::NotFound),
                "`{p}` must not route anywhere"
            );
        }
    }

    /// And the routes that should exist, do — so the test above is not passing
    /// because everything 404s.
    #[test]
    fn the_read_only_routes_resolve() {
        assert!(matches!(route("/"), Route::Index));
        assert!(matches!(route("/index.html"), Route::Index));
        assert!(matches!(route("/api/info"), Route::Info));
        assert!(matches!(route("/api/blocks"), Route::Recent));
        assert!(matches!(route("/api/block/0"), Route::Block(0)));
        assert!(matches!(route("/api/block/237"), Route::Block(237)));
        // A query string is ignored rather than defeating the match.
        assert!(matches!(route("/api/info?x=1"), Route::Info));
    }

    /// A height is parsed as a number, so no path component can smuggle
    /// anything through to the node client.
    #[test]
    fn a_block_height_is_a_number_or_nothing() {
        for bad in ["/api/block/1e9", "/api/block/-1", "/api/block/0x10", "/api/block/1%20"] {
            assert!(matches!(route(bad), Route::NotFound), "`{bad}` should not parse");
        }
        // u64::MAX parses fine and is simply a height the node does not have.
        assert!(matches!(route("/api/block/18446744073709551615"), Route::Block(u64::MAX)));
    }

    /// The static emitter rewrites one literal in the page. If an edit to
    /// `index.html` changes or duplicates it, publishing must fail rather than
    /// ship a page that claims to be live while carrying frozen numbers — an
    /// immutable network gives no second chance to correct that.
    #[test]
    fn the_page_carries_exactly_one_rewritable_source_marker() {
        assert_eq!(INDEX_HTML.matches(SOURCE_MARKER).count(), 1, "index.html marker drifted");
        assert_eq!(INDEX_HTML.matches(SOURCE_SNAPSHOT).count(), 0, "page already says snapshot");

        let published = INDEX_HTML.replace(SOURCE_MARKER, SOURCE_SNAPSHOT);
        assert!(published.contains(SOURCE_SNAPSHOT));
        assert!(!published.contains(SOURCE_MARKER));
    }

    /// A published page must not reach off its own origin. The whole point of
    /// publishing to a decentralised network is that reading the site tells
    /// nobody you read it; an absolute URL to an API would undo that silently.
    #[test]
    fn the_page_fetches_only_relative_paths() {
        // Without this the loop below passes by finding nothing, which is how a
        // test quietly stops testing after a refactor renames the call.
        let calls = INDEX_HTML.matches("fetch(").count();
        assert!(calls >= 3, "expected the page to still fetch chain data, found {calls} call(s)");

        for (i, rest) in INDEX_HTML.match_indices("fetch(").map(|(i, _)| (i, &INDEX_HTML[i..])) {
            let arg = rest.trim_start_matches("fetch(").trim_start();
            assert!(
                arg.starts_with('"') || arg.starts_with('\''),
                "fetch() at byte {i} takes a computed URL; it must be a literal relative path"
            );
            let url = &arg[1..];
            assert!(
                !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("//"),
                "fetch() at byte {i} names an absolute origin: {}",
                &url[..url.len().min(40)]
            );
        }
    }

    /// The public site must not republish the private node's address. The node
    /// puts its own URL in its errors, and this server is reachable by strangers
    /// while the node is not, so passing the text through would map the operator's
    /// internal network for them.
    #[test]
    fn an_upstream_error_does_not_leak_the_node_address() {
        let real = "cannot reach http://10.10.10.75:19334: connection refused";
        let out = err_json(real);
        for secret in ["10.10.10.75", "19334", "http://"] {
            assert!(!out.contains(secret), "`{secret}` leaked to the client in `{out}`");
        }
        // Still valid JSON with an `error` key, which is what the page reads.
        assert!(out.starts_with("{\"error\":\"") && out.ends_with("\"}"), "{out}");
    }

    /// `X-Forwarded-For` is inert unless the operator names the proxy. If it
    /// were believed from anyone, a client could mint a fresh rate-limit bucket
    /// per request and the limiter would protect nothing.
    #[test]
    fn a_forwarded_header_is_ignored_unless_the_peer_is_a_named_proxy() {
        let attacker: IpAddr = "203.0.113.9".parse().unwrap();
        let claimed = "198.51.100.7";

        // Nobody trusted: the socket peer is billed, not the header.
        let none = HashSet::new();
        assert_eq!(client_ip(Some(attacker), Some(claimed), &none), Some(attacker));

        // The operator's proxy: the header is believed.
        let trusted: HashSet<IpAddr> = [attacker].into_iter().collect();
        assert_eq!(client_ip(Some(attacker), Some(claimed), &trusted), Some(claimed.parse().unwrap()));
    }

    /// The request-head caps must leave room for a real browser. A cap that a
    /// normal request trips would turn this into a broken site rather than a
    /// hardened one.
    #[test]
    fn the_head_caps_are_bounded_but_roomy() {
        assert!(MAX_HEAD_BYTES >= 8 * 1024, "too tight for a request with cookies");
        assert!(MAX_HEAD_BYTES <= 64 * 1024, "large enough to be worth capping at all");
        assert!(MAX_HEADERS >= 32 && MAX_HEADERS <= 256);
    }
}
