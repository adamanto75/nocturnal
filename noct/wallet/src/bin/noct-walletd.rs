//! `noct-walletd` — a local web wallet. Serves a single-page UI plus a small
//! JSON API, syncing from a `noctd` node.
//!
//! ```text
//! noct-walletd [--wallet FILE] [--node HOST:PORT] [--listen HOST:PORT]
//! ```
//!
//! Open the printed URL in a browser. The daemon holds the spend key and binds to
//! localhost only. Chain state is kept in memory and synced incrementally, so it
//! only downloads blocks it hasn't seen.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use noct_core::address::{Address, AnyAddress, Network};
use noct_core::chain::Blockchain;
use noct_core::keys::Account;
use noct_tls::Endpoint;
use noct_wallet::client::{
    format_noct, load_account, parse_noct, replay_cache, rpc_token_from_args, save_state, state_path,
    sync_both, BlockCache,
    NodeClient, TrustedPow,
};
use noct_wallet::shielded::ShieldedWallet;
use noct_wallet::{Direction, SpendFrom, Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

const INDEX_HTML: &str = include_str!("../ui/wallet.html");
const MAX_BODY: usize = 1 << 20;

struct App {
    chain: Blockchain<TrustedPow>,
    wallet: Wallet,
    /// The shielded half of the same account. Synced and saved alongside the ring
    /// half whether or not anything asks about it: leaving it behind would leave
    /// its commitment tree behind the chain, and then every note witness it holds
    /// is stale and every note it owns unspendable.
    shielded: ShieldedWallet,
    client: NodeClient,
    /// On-disk cache of validated blocks, so a restart resumes from the last
    /// synced height instead of re-downloading the whole chain.
    cache: BlockCache,
    /// Kept so the wallet + chain can be rebuilt from genesis if the node
    /// reorgs below our cached tip.
    account: Account,
    network: Network,
    /// Next subaddress index to hand out (account 0), persisted to `subaddr_path`
    /// so a restart doesn't reissue the same ones.
    next_subaddress: u32,
    subaddr_path: String,
    /// Saved chain + wallet state, so a restart resumes without replaying the
    /// block cache. See `noct_wallet::state`.
    state_path: std::path::PathBuf,
    /// Tip the state file was last saved at, so an idle poll does not rewrite it.
    saved_tip: [u8; 32],
}

/// Sync the app's chain from the node, extending the block cache. If a block
/// fails to apply — a stale cache, or the node reorged below our cached tip —
/// the cache is discarded and the wallet is rebuilt from genesis so the next
/// poll recovers.
fn sync_app(app: &mut App) -> Result<u64, String> {
    let height = match sync_both(
        &app.client,
        &mut app.chain,
        &mut app.wallet,
        Some(&mut app.shielded),
        Some(&app.cache),
    ) {
        Ok(height) => height,
        Err(_) => {
            app.cache.clear();
            // Must be rebuilt on *this* wallet's network: `Blockchain::new` is
            // mainnet, so recovering a testnet wallet through it would root the
            // chain at the wrong genesis and reject every block the node sends.
            app.chain = Blockchain::for_network(app.network, TrustedPow);
            app.wallet = Wallet::new(app.account, app.network);
            // Everything issued has to be registered before the rescan, exactly
            // as at startup, or funds at addresses past the lookahead window
            // vanish from the rebuilt wallet.
            app.wallet.register_issued((0..app.next_subaddress).map(|i| (0, i)));
            sync_both(
                &app.client,
                &mut app.chain,
                &mut app.wallet,
                Some(&mut app.shielded),
                Some(&app.cache),
            )?
        }
    };
    // Keyed on the tip, not the height: a rebuild onto another branch can land
    // at the height already saved.
    if app.chain.tip_id() != app.saved_tip {
        match save_state(&app.state_path, &app.chain, &app.wallet, &app.shielded) {
            Ok(()) => app.saved_tip = app.chain.tip_id(),
            Err(e) => eprintln!("warning: could not save wallet state to {}: {e}", app.state_path.display()),
        }
    }
    Ok(height)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Read the network first: it decides the default node/listen ports, so both
    // networks can be served side by side, and an explicit flag still wins.
    let network = match flag(&args, "--network").as_deref() {
        None | Some("mainnet") => Network::Mainnet,
        Some("testnet") => Network::Testnet,
        Some(other) => fail(&format!("unknown network {other:?} (expected mainnet or testnet)")),
    };
    let params = network.params();
    // The UI port is the node's RPC port + 6, keeping the existing 9334 → 9340
    // relationship on mainnet and giving testnet 19334 → 19340.
    let default_listen = format!("127.0.0.1:{}", params.default_rpc_port + 6);

    let wallet_path = flag(&args, "--wallet").unwrap_or_else(|| "noct-wallet.key".to_string());
    let node = flag(&args, "--node")
        .unwrap_or_else(|| format!("127.0.0.1:{}", params.default_rpc_port));
    // `https://…` here encrypts the wallet's traffic to the node; it matters
    // whenever the node is not on this machine.
    let node = Endpoint::parse(&node, params.default_rpc_port)
        .unwrap_or_else(|e| fail(&format!("--node: {e}")));
    let listen = flag(&args, "--listen").unwrap_or(default_listen);
    let node_token = rpc_token_from_args(&args);

    let key = std::fs::read_to_string(&wallet_path)
        .unwrap_or_else(|_| fail(&format!("no wallet at {wallet_path} — run `noct-cli new --wallet {wallet_path}` first")));
    let account = load_account(key.trim()).unwrap_or_else(|e| fail(&e));
    if noct_wallet::secure_file::is_exposed(std::path::Path::new(&wallet_path)) {
        eprintln!("warning: {wallet_path} is readable by other users on this machine. Fix it with:  chmod 600 {wallet_path}");
    }

    // The wallet's 24-word BIP39 backup phrase, for the UI's "reveal seed" feature.
    let seed_phrase = {
        let bytes: [u8; 32] = hex::decode(key.trim())
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or_else(|| fail("wallet key is not 32-byte hex"));
        Arc::new(noct_wallet::mnemonic::to_phrase(&bytes))
    };

    // Resume from the on-disk block cache (offline; new blocks pulled lazily on
    // the first request), so a restart doesn't re-download the whole chain.
    let cache_path = format!("{wallet_path}.cache");

    // Next subaddress index to issue, resumed from disk (min 1; 0 is the main
    // address). Read *before* the wallet is built, because everything already
    // issued has to be registered before the first scan.
    let subaddr_path = format!("{wallet_path}.subaddr");
    let next_subaddress = std::fs::read_to_string(&subaddr_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);

    // `Wallet::new` pre-derives a lookahead window on account 0. This daemon
    // issues sequentially, so once it has handed out more than that window it
    // was scanning without the keys for the newest ones registered — and
    // reported no funds for addresses it had itself given out. Resuming the
    // counter alone was never enough.
    let issued: Vec<(u32, u32)> = (0..next_subaddress).map(|i| (0, i)).collect();
    let state_path = state_path(std::path::Path::new(&cache_path));
    let (chain, wallet, shielded, cache) =
        replay_cache(account, network, &cache_path, &issued);

    let app = Arc::new(Mutex::new(App {
        shielded,
        chain,
        wallet,
        client: NodeClient::with_token(node.clone(), node_token.clone()),
        cache,
        account,
        network,
        state_path,
        // Nothing saved yet this run, so the first successful sync writes one.
        saved_tip: [0u8; 32],
        next_subaddress,
        subaddr_path,
    }));

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| fail(&format!("bind {listen}: {e}")));
    eprintln!("noct-walletd — open http://{listen} in your browser");
    eprintln!("  node:   {}", node.display());
    eprintln!("  wallet: {wallet_path}");

    // A lock-free handle to the node for mining control, so the UI's frequent
    // hashrate polls never wait behind a wallet sync holding the App mutex.
    let node_addr = Arc::new(node.clone());
    let node_token = Arc::new(node_token);

    for stream in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        let node_addr = Arc::clone(&node_addr);
        let seed_phrase = Arc::clone(&seed_phrase);
        let node_token = Arc::clone(&node_token);
        thread::spawn(move || {
            let _ = handle(stream, app, node_addr, seed_phrase, node_token);
        });
    }
}

fn handle(
    stream: TcpStream,
    app: Arc<Mutex<App>>,
    node_addr: Arc<Endpoint>,
    seed_phrase: Arc<String>,
    node_token: Arc<Option<String>>,
) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim_end().is_empty() {
            break;
        }
        if let Some(v) = line.trim_end().to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if content_length > MAX_BODY {
        return http(&mut writer, "413 Payload Too Large", "text/plain", "too large");
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/") => http(&mut writer, "200 OK", "text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/api/state") => {
            let json = api_state(&app);
            http(&mut writer, "200 OK", "application/json", &json)
        }
        ("POST", "/api/send") => {
            let json = api_send(&app, &String::from_utf8_lossy(&body));
            http(&mut writer, "200 OK", "application/json", &json)
        }
        // Hand out a fresh subaddress (a new unlinkable receiving address).
        ("POST", "/api/subaddress") => {
            let json = api_subaddress(&app);
            http(&mut writer, "200 OK", "application/json", &json)
        }
        // The wallet's seed phrase, for the UI backup feature. Localhost-only,
        // same trust boundary as /api/send (which can already spend).
        ("GET", "/api/seed") => {
            let json = format!("{{\"phrase\":\"{}\"}}", seed_phrase.as_str());
            http(&mut writer, "200 OK", "application/json", &json)
        }
        // Check a phrase the person transcribed against this wallet, without
        // writing anything or revealing the real one.
        //
        // A backup is only worth what it restores. A single mis-copied or
        // transposed word produces a phrase that is often still *valid* — it just
        // opens a different, empty wallet — and that is discovered at recovery
        // time, when the original is gone. This lets it be discovered now.
        ("POST", "/api/verify-seed") => {
            let json = api_verify_seed(&app, &seed_phrase, &String::from_utf8_lossy(&body));
            http(&mut writer, "200 OK", "application/json", &json)
        }
        // Mining control — proxied straight to the node (no App lock), so polling
        // the hashrate never blocks on a wallet sync.
        ("GET", "/api/mining") => {
            let json = mining_proxy(&node_addr, &node_token, |c| c.mining_state());
            http(&mut writer, "200 OK", "application/json", &json)
        }
        ("POST", "/api/mining/start") => {
            let threads = String::from_utf8_lossy(&body).trim().parse::<usize>().ok();
            let json = mining_proxy(&node_addr, &node_token, |c| c.mining_start(threads));
            http(&mut writer, "200 OK", "application/json", &json)
        }
        ("POST", "/api/mining/stop") => {
            let json = mining_proxy(&node_addr, &node_token, |c| c.mining_stop());
            http(&mut writer, "200 OK", "application/json", &json)
        }
        ("POST", "/api/mining/threads") => {
            let n = String::from_utf8_lossy(&body).trim().parse::<usize>().unwrap_or(1);
            let json = mining_proxy(&node_addr, &node_token, |c| c.mining_set_threads(n));
            http(&mut writer, "200 OK", "application/json", &json)
        }
        _ => http(&mut writer, "404 Not Found", "application/json", "{\"ok\":false,\"error\":\"not found\"}"),
    }
}

/// Sync and report balance + address.
fn api_state(app: &Arc<Mutex<App>>) -> String {
    let mut app = app.lock().unwrap();
    let address = app.wallet.address().encode();
    // Reported on every poll so the UI can label the network permanently. A
    // balance shown without saying which chain it is on is exactly how a testnet
    // wallet gets mistaken for an empty mainnet one.
    let net = match app.network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };
    let shielded_address = app.shielded.address().encode();
    match sync_app(&mut app) {
        Ok(height) => {
            // **`balance` is both pools.** It used to be the ring balance alone,
            // which meant that the moment a user shielded anything the headline
            // number fell and the difference was nowhere on screen. A wallet that
            // understates what somebody owns is the "my coins are gone" report
            // this project has already had once, and it would have been right.
            let ring = app.wallet.balance();
            let shielded = app.shielded.balance();
            let pending = app.shielded.pending_balance();
            format!(
                "{{\"ok\":true,\"network\":\"{}\",\"height\":{},\"address\":\"{}\",\"shielded_address\":\"{}\",\"balance\":\"{}\",\"ring\":\"{}\",\"shielded\":\"{}\",\"shielded_pending\":\"{}\",\"notes\":{},\"outputs\":{},\"unspent\":{},\"history\":{}}}",
                net,
                height,
                address,
                shielded_address,
                format_noct(ring + shielded),
                format_noct(ring),
                format_noct(shielded),
                // Shielded rewards that exist but cannot be moved yet, kept out of
                // the spendable figures rather than folded in: a balance including
                // a note no anchor can reach promises money that cannot be spent.
                format_noct(pending),
                app.shielded.unspent().count(),
                app.wallet.outputs().len(),
                app.wallet.unspent().count(),
                history_json(&app.wallet),
            )
        }
        Err(e) => format!("{{\"ok\":false,\"network\":\"{}\",\"address\":\"{}\",\"error\":\"{}\"}}", net, address, escape(&e)),
    }
}

/// Render the wallet's transaction history as a JSON array, most recent first
/// (capped so the payload stays small on long-lived wallets).
fn history_json(wallet: &Wallet) -> String {
    const MAX_ENTRIES: usize = 200;
    let entries: Vec<String> = wallet
        .history()
        .iter()
        .rev()
        .take(MAX_ENTRIES)
        .map(|e| {
            format!(
                "{{\"height\":{},\"direction\":\"{}\",\"amount\":\"{}\",\"fee\":\"{}\",\"coinbase\":{}}}",
                e.height,
                match e.direction {
                    Direction::Received => "received",
                    Direction::Sent => "sent",
                },
                format_noct(e.amount),
                format_noct(e.fee),
                e.coinbase,
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// Build and submit a payment from a form-encoded body (`to=..&amount=..&fee=..`).
/// Check a transcribed recovery phrase against this wallet.
///
/// Answers one question — "would what I wrote down actually restore this
/// wallet?" — and deliberately nothing more:
///
/// * **Nothing is written.** No key file, no state change. It is a comparison.
/// * **The real phrase is never returned**, and neither is the submitted one.
///   A mismatch reports only *that* it differs, plus which word position first
///   diverges when both are the same length, which is enough to find a
///   transcription slip without handing back the answer.
/// * **A valid-but-different phrase is the dangerous case**, not an invalid one.
///   A transposed pair usually still passes the BIP39 checksum and simply opens
///   a different, empty wallet — which at recovery time looks exactly like funds
///   having vanished. So the comparison is against *this wallet's* phrase, not
///   merely against "is this well-formed".
fn api_verify_seed(app: &Arc<Mutex<App>>, real_phrase: &str, body: &str) -> String {
    let form = parse_form(body);
    let submitted = form
        .iter()
        .find(|(k, _)| k == "phrase")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let submitted = normalize_phrase(&submitted);
    if submitted.is_empty() {
        return "{\"ok\":false,\"error\":\"Enter the phrase you wrote down.\"}".to_string();
    }

    let real = normalize_phrase(real_phrase);
    if submitted == real {
        // Also confirm it genuinely derives this wallet, rather than trusting the
        // string compare alone.
        let derived_matches = match noct_wallet::mnemonic::from_phrase(&submitted) {
            Ok(secret) => match load_account(&hex::encode(secret)) {
                Ok(acct) => {
                    let app = app.lock().unwrap();
                    Address::new(app.network, acct.spend_public, acct.view_public).encode()
                        == app.wallet.address().encode()
                }
                Err(_) => false,
            },
            Err(_) => false,
        };
        return format!(
            "{{\"ok\":true,\"matches\":{derived_matches},\"message\":\"{}\"}}",
            if derived_matches {
                "This is the correct phrase for this wallet. Your backup is good."
            } else {
                "The words match, but they do not derive this wallet — please report this."
            }
        );
    }

    // Different. Locate the first differing word when the lengths agree; that is
    // almost always a single mis-copied or transposed word.
    let (a, b): (Vec<&str>, Vec<&str>) = (submitted.split(' ').collect(), real.split(' ').collect());
    let detail = if a.len() != b.len() {
        format!("You entered {} words; this wallet's phrase has {}.", a.len(), b.len())
    } else {
        match a.iter().zip(&b).position(|(x, y)| x != y) {
            Some(i) => format!("The first difference is at word {}.", i + 1),
            None => "The phrases differ.".to_string(),
        }
    };
    format!(
        "{{\"ok\":true,\"matches\":false,\"message\":\"This does NOT match this wallet. {} \
         Check your written copy against the phrase above — restoring from what you wrote \
         would open a different, empty wallet.\"}}",
        escape(&detail)
    )
}

/// Lowercase, collapse whitespace, drop anything that is not a word — so a copy
/// written as a numbered list still compares equal.
fn normalize_phrase(s: &str) -> String {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty() && !w.chars().all(|c| c.is_ascii_digit()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn api_send(app: &Arc<Mutex<App>>, body: &str) -> String {
    let form = parse_form(body);
    let to = form.iter().find(|(k, _)| k == "to").map(|(_, v)| v.clone()).unwrap_or_default();
    let amount_s = form.iter().find(|(k, _)| k == "amount").map(|(_, v)| v.clone()).unwrap_or_default();
    let fee_s = form.iter().find(|(k, _)| k == "fee").map(|(_, v)| v.clone()).unwrap_or_else(|| "0.01".into());

    // **Either kind of address.** Which pool a payment lands in is the
    // recipient's choice, already expressed in the address they handed over, so
    // the sender does not get a second button for it — and could not, without
    // knowing something the address already says. Before this, pasting a
    // shielded address here answered "invalid destination address", which is
    // both wrong and the least helpful way to be wrong.
    let destination = match AnyAddress::decode(to.trim()) {
        Ok(a) => a,
        Err(_) => return err_json("invalid destination address"),
    };
    let amount = match parse_noct(&amount_s) {
        Some(a) if a > 0 => a,
        _ => return err_json("invalid amount"),
    };
    let fee = match parse_noct(&fee_s) {
        Some(f) => f,
        None => return err_json("invalid fee"),
    };
    // Which pool the money comes FROM — the sender's own choice, separate from
    // the destination pool the address fixes. An unrecognised value is refused
    // rather than treated as `auto`, because the difference between them is
    // whether an amount gets published.
    let from_s = form.iter().find(|(k, _)| k == "from").map(|(_, v)| v.clone()).unwrap_or_else(|| "auto".into());
    let from = match SpendFrom::parse(&from_s) {
        Some(f) => f,
        None => return err_json("source pool must be ring, shielded or auto"),
    };

    let mut app = app.lock().unwrap();
    if destination.network() != app.network {
        return err_json(&format!(
            "that address belongs to {:?} and this wallet is on {:?} — refusing to send",
            destination.network(),
            app.network
        ));
    }
    if let Err(e) = sync_app(&mut app) {
        return err_json(&format!("sync failed: {e}"));
    }

    let App { wallet, shielded, chain, .. } = &mut *app;
    let tx = match wallet.build_send(
        &mut OsRng,
        chain,
        shielded,
        destination,
        amount,
        fee,
        DEFAULT_RING_SIZE,
        from,
    ) {
        Ok(tx) => tx,
        Err(e) => return err_json(&format!("{e:?}")),
    };

    // The relay floor, checked before anything is sent rather than after the
    // node refuses. The node publishes its own as `min_fee_per_kb`; this catches
    // the ordinary case and names the number to use.
    let size = noct_core::wire::encode_transaction(&tx).len();
    let required = noct_core::mempool::min_fee(size);
    if tx.fee < required {
        return err_json(&format!(
            "fee {} NOCT is below the relay floor for this {size}-byte transaction, which needs {} NOCT. Nothing was sent.",
            format_noct(tx.fee),
            format_noct(required),
        ));
    }

    // What this publishes, said before it is sent. A crossing's amount is the one
    // thing the two-pool design cannot hide, and somebody shielding an unusual
    // number should learn that from their wallet rather than from an analyst.
    let crossing = if tx.cross > 0 {
        format!(
            " Note: {} NOCT moved into the shielded pool, and that amount is public.",
            format_noct(tx.cross as u64)
        )
    } else if tx.cross < 0 && (-tx.cross) as u64 > tx.fee {
        // Only when value is genuinely leaving: when the sole crossing IS the
        // fee, calling it a disclosure is noise, and noise teaches people to
        // ignore the warning that matters.
        format!(
            " Note: {} NOCT came out of the shielded pool, and that amount is public.",
            format_noct((-tx.cross) as u64)
        )
    } else {
        String::new()
    };
    // Worth saying when they got the private shape, because `auto` would not have
    // built it: no ring inputs, outputs or range proof to correlate.
    let shape = if tx.inputs.is_empty() && tx.outputs.is_empty() {
        " This one stayed inside the shielded pool — no ring side at all, and only the fee is public."
    } else {
        ""
    };
    let pool = if destination.is_shielded() { "shielded" } else { "ring" };

    let txid = hex::encode(tx.hash());
    // **The node's answer decides, not the transport's.** This used to report
    // success whenever `submit_tx` returned `Ok`, which is true even when the
    // node answered `accepted: false` — so a refused transaction was shown to
    // the user as sent. See the same fix in `noct-cli`.
    match app.client.submit_tx(&tx) {
        Ok(reply) if reply.contains("\"accepted\":true") => {
            // Reserve the inputs so the next send does not select them again
            // before this transaction is mined, and persist that: the chain will
            // not mark them spent until it is, and a restart would otherwise
            // forget. See `Wallet::note_submitted`.
            let h = app.chain.height();
            app.wallet.note_submitted(&tx, h);
            app.shielded.note_submitted(&tx, h);
            if let Err(e) = save_state(&app.state_path, &app.chain, &app.wallet, &app.shielded) {
                eprintln!("warning: could not record the pending spend: {e}");
            }
            format!(
            "{{\"ok\":true,\"txid\":\"{}\",\"message\":\"sent {} NOCT to the {} pool (fee {} NOCT); it will confirm when a block is mined.{}\"}}",
            txid,
            format_noct(amount),
            pool,
            format_noct(fee),
            format!("{crossing}{shape}"),
            )
        }
        Ok(reply) => {
            let reason = reply
                .split("\"reason\":\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .map(|r| r.to_string())
                .unwrap_or_else(|| reply.trim().to_string());
            err_json(&format!("not sent — the node refused it: {reason}"))
        }
        // No reply at all: it may have been relayed before the connection broke,
        // or never have arrived. Calling it "not sent" would be a guess that
        // invites sending it twice.
        Err(e) => err_json(&format!(
            "outcome unknown ({e}) — it may or may not have been relayed. Check the chain for {txid} before sending again"
        )),
    }
}

/// Issue the next fresh subaddress (account 0), advancing and persisting the
/// counter so it is not handed out again.
fn api_subaddress(app: &Arc<Mutex<App>>) -> String {
    let mut app = app.lock().unwrap();
    let index = app.next_subaddress.max(1);
    let address = app.wallet.subaddress(0, index).encode();
    app.next_subaddress = index.saturating_add(1);
    let _ = std::fs::write(&app.subaddr_path, app.next_subaddress.to_string());
    format!("{{\"ok\":true,\"index\":{index},\"address\":\"{address}\"}}")
}

// --- helpers ----------------------------------------------------------------

/// Run a mining-control call against a fresh (lock-free) node client and return
/// the node's JSON reply verbatim, or an error object if the node is unreachable.
fn mining_proxy(
    node_addr: &Arc<Endpoint>,
    node_token: &Arc<Option<String>>,
    f: impl FnOnce(&NodeClient) -> Result<String, String>,
) -> String {
    let client = NodeClient::with_token((**node_addr).clone(), (**node_token).clone());
    match f(&client) {
        Ok(body) => body,
        Err(e) => err_json(&format!("node unreachable: {e}")),
    }
}

fn http(writer: &mut TcpStream, status: &str, content_type: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    writer.write_all(response.as_bytes())?;
    writer.flush()
}

fn err_json(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":\"{}\"}}", escape(msg))
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 2;
                } else {
                    out.push(bytes[i]);
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
