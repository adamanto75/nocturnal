//! Talking to a `noctd` node over its JSON-RPC, and syncing the wallet.
//!
//! Shared by `noct-cli` and `noct-walletd`. All functions return `Result` (no
//! process exits) so a GUI can surface errors instead of dying.

use std::io::Write;
use std::path::PathBuf;

use curve25519_dalek::scalar::Scalar;
use noct_core::address::Network;
use noct_core::block::Block;
use noct_core::chain::Blockchain;
use noct_core::emission::ATOMIC_UNITS;
use noct_core::keys::Account;
use noct_core::p2p::Wire;
use noct_core::pow::ProofOfWork;
use noct_core::tx::Transaction;
use noct_core::wire;
use noct_tls::Endpoint;

use crate::Wallet;

/// Proof-of-work stand-in for the wallet's local validation chain: it accepts
/// any block's PoW (a hash of all zeros trivially meets every difficulty).
///
/// The wallet still **fully** validates each downloaded block — transactions,
/// range proofs, ring membership, key images, coinbase emission — it simply does
/// not re-run the node's proof-of-work. That keeps the wallet independent of
/// which PoW the node runs (Keccak or the ~256 MB-per-VM RandomX), so it never
/// needs the RandomX toolchain. It suits a wallet talking to its **own local**
/// node, which it launched and trusts for consensus; a wallet pointed at an
/// untrusted remote node would instead want to verify PoW itself.
#[derive(Clone, Copy, Default)]
pub struct TrustedPow;

impl ProofOfWork for TrustedPow {
    fn pow_hash(&self, _blob: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }
}

/// Resolve an RPC token from `--node-token VALUE` or `--node-token-file PATH`.
///
/// Prefer the file form: a token on the command line is visible in the process
/// list and shell history.
pub fn rpc_token_from_args(args: &[String]) -> Option<String> {
    fn flag(args: &[String], name: &str) -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        args.get(i + 1).cloned()
    }
    flag(args, "--node-token").or_else(|| {
        flag(args, "--node-token-file").and_then(|path| {
            std::fs::read_to_string(&path)
                .map(|t| t.trim().to_string())
                .map_err(|e| eprintln!("warning: reading {path}: {e}"))
                .ok()
        })
    })
}

/// Load an account from a 32-byte spend-secret hex string (the keyfile format).
pub fn load_account(spend_secret_hex: &str) -> Result<Account, String> {
    let bytes = hex::decode(spend_secret_hex.trim()).map_err(|_| "wallet key is not valid hex".to_string())?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "wallet key must be 32 bytes".to_string())?;
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| "wallet key is not a canonical scalar".to_string())?;
    Ok(Account::from_spend_secret(scalar))
}

/// Load a wallet from a 32-byte spend-secret hex string (the keyfile format).
pub fn load_wallet(spend_secret_hex: &str) -> Result<Wallet, String> {
    load_wallet_for(spend_secret_hex, Network::Mainnet)
}

/// Load a wallet whose addresses belong to `network`.
pub fn load_wallet_for(spend_secret_hex: &str, network: Network) -> Result<Wallet, String> {
    Ok(Wallet::new(load_account(spend_secret_hex)?, network))
}

/// A thin client for a node's HTTP RPC.
///
/// A wallet talking to a node it does not host is sending exactly the things
/// Noct exists to keep private — which blocks it wants, which outputs it is
/// checking — and, if the RPC is authenticated, a bearer token on every request.
/// The endpoint therefore carries whether the connection is encrypted, rather
/// than that being a separate setting somebody can forget.
pub struct NodeClient {
    endpoint: Endpoint,
    /// Bearer token, when the node's RPC is authenticated. Required for any node
    /// serving its RPC off-box.
    token: Option<String>,
    /// Certificate to pin, for a node with a self-signed certificate.
    pin: Option<[u8; 32]>,
}

impl NodeClient {
    pub fn new(endpoint: Endpoint) -> Self {
        NodeClient { endpoint, token: None, pin: None }
    }

    /// Authenticate every request with `token` (`Authorization: Bearer …`).
    pub fn with_token(endpoint: Endpoint, token: Option<String>) -> Self {
        NodeClient { endpoint, token, pin: None }
    }

    /// Verify the node's certificate against this fingerprint instead of the
    /// system trust store — for a node whose certificate is self-signed.
    pub fn with_pin(mut self, pin: Option<[u8; 32]>) -> Self {
        self.pin = pin;
        self
    }

    /// The node this client talks to.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The `Authorization` header line, or nothing when unauthenticated.
    fn auth_header(&self) -> String {
        match &self.token {
            Some(t) => format!("Authorization: Bearer {t}\r\n"),
            None => String::new(),
        }
    }

    /// The node's `/info` document, verbatim.
    ///
    /// Returned as the raw body rather than parsed: the caller is a display
    /// surface (the explorer) that wants whatever the node reports, and parsing
    /// here would mean this client had to be edited every time a field is added.
    pub fn info(&self) -> Result<String, String> {
        self.get("/info")
    }

    /// The node's current chain height.
    pub fn height(&self) -> Result<u64, String> {
        let body = self.get("/info")?;
        json_u64(&body, "height").ok_or_else(|| "node returned no height".to_string())
    }

    /// Fetch and decode the block at `height` (with its transactions).
    pub fn block(&self, height: u64) -> Result<(noct_core::block::Block, Vec<Transaction>), String> {
        let body = self.get(&format!("/block/{height}"))?;
        let data = json_str(&body, "data").ok_or_else(|| format!("block {height}: no data"))?;
        let raw = hex::decode(data).map_err(|_| format!("block {height}: bad hex"))?;
        match wire::decode_message(&raw) {
            Ok(Wire::Block(block, txs)) => Ok((block, txs)),
            Ok(_) => Err(format!("block {height}: unexpected message type")),
            Err(e) => Err(format!("block {height}: malformed ({e:?})")),
        }
    }

    /// Submit a wire-encoded transaction; returns the node's raw reply body.
    pub fn submit_tx(&self, tx: &Transaction) -> Result<String, String> {
        let hex_tx = hex::encode(wire::encode_transaction(tx));
        self.post("/submit_tx", &hex_tx)
    }

    /// Ask the node to mine a block (dev convenience).
    pub fn mine(&self) -> Result<String, String> {
        self.post("/mine", "")
    }

    /// The node's current mining state (raw JSON: active, threads, hashrate, …).
    pub fn mining_state(&self) -> Result<String, String> {
        self.get("/mining")
    }

    /// Start the node's background miner, optionally setting the thread count.
    pub fn mining_start(&self, threads: Option<usize>) -> Result<String, String> {
        self.post("/mining/start", &threads.map(|n| n.to_string()).unwrap_or_default())
    }

    /// Stop the node's background miner.
    pub fn mining_stop(&self) -> Result<String, String> {
        self.post("/mining/stop", "")
    }

    /// Set the miner's worker-thread count.
    pub fn mining_set_threads(&self, n: usize) -> Result<String, String> {
        self.post("/mining/threads", &n.to_string())
    }

    fn get(&self, path: &str) -> Result<String, String> {
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            self.endpoint.authority(),
            self.auth_header()
        ))
    }

    fn post(&self, path: &str, body: &str) -> Result<String, String> {
        self.request(&format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.endpoint.authority(),
            self.auth_header(),
            body.len()
        ))
    }

    fn request(&self, raw: &str) -> Result<String, String> {
        let mut stream = noct_tls::connect_pinned(&self.endpoint, self.pin)?;
        stream.write_all(raw.as_bytes()).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
        let response = noct_tls::read_response(&mut stream)?;
        // Surface an auth failure plainly; otherwise the caller would just see a
        // body it cannot parse and report a confusing error.
        if response.status == 401 {
            return Err(if self.token.is_some() {
                "node rejected our RPC token (check --node-token)".to_string()
            } else {
                "node requires an RPC token — pass --node-token / --node-token-file".to_string()
            });
        }
        Ok(response.body)
    }
}

/// An on-disk cache of the blocks the wallet has already downloaded and
/// validated, so a fresh process (`noct-cli`) or a restarted daemon can replay
/// them locally instead of re-fetching the whole chain from the node.
///
/// The format is a flat append-only log: for each block, a little-endian `u32`
/// length followed by that many bytes of a wire-encoded [`Wire::Block`] record.
/// Only blocks that passed `add_block` validation are ever written, and replay
/// re-validates them, so a corrupt or stale cache can never poison wallet state
/// — the worst case is a full re-sync (see [`load_synced_wallet`]).
pub struct BlockCache {
    path: PathBuf,
}

impl BlockCache {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        BlockCache { path: path.into() }
    }

    /// Discard the cache file (used when it is stale or the node reorged below
    /// our cached tip).
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// Append one validated block record to the log.
    fn append(&self, block: &Block, txs: &[Transaction]) -> std::io::Result<()> {
        let bytes = wire::encode_message(&Wire::Block(block.clone(), txs.to_vec()));
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(&(bytes.len() as u32).to_le_bytes())?;
        f.write_all(&bytes)
    }

    /// Load every cached block record, in the order they were appended, together
    /// with the byte length of the cleanly-decoded prefix. A record that is
    /// truncated (an interrupted append) or fails to decode (corruption) ends
    /// the scan; the returned length lets the caller trim that bad tail with
    /// [`truncate_to`](Self::truncate_to) so later appends stay contiguous.
    fn load_all(&self) -> (Vec<(Block, Vec<Transaction>)>, u64) {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(_) => return (Vec::new(), 0),
        };
        let mut out = Vec::new();
        let mut consumed = 0usize;
        let mut cur = &data[..];
        while cur.len() >= 4 {
            let len = u32::from_le_bytes(cur[..4].try_into().unwrap()) as usize;
            if cur.len() < 4 + len {
                break;
            }
            match wire::decode_message(&cur[4..4 + len]) {
                Ok(Wire::Block(block, txs)) => out.push((block, txs)),
                _ => break,
            }
            consumed += 4 + len;
            cur = &cur[4 + len..];
        }
        (out, consumed as u64)
    }

    /// Trim the cache file to `len` bytes, dropping any corrupt or half-written
    /// tail so the next append lands on a clean record boundary. Trimming to `0`
    /// effectively discards a cache whose very first record is unreadable.
    fn truncate_to(&self, len: u64) {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
            let _ = f.set_len(len);
        }
    }

    /// Load the cache and trim any unreadable tail, returning the usable records.
    /// After this, the file holds exactly these records, so appending is safe.
    fn load_clean(&self) -> Vec<(Block, Vec<Transaction>)> {
        let (records, valid_len) = self.load_all();
        self.truncate_to(valid_len);
        records
    }
}

/// Refuse to sync from a node that is shorter than we have already scanned.
///
/// A node behind us is not a node with nothing to send: it no longer has the
/// chain we scanned. `sync` only ever moves forward, so without this it returns
/// `Ok` having done nothing and the wallet keeps answering with balances from a
/// branch that no longer exists — until the node grows past our height and the
/// next block fails to extend, which may be a long time on a chain that reorged
/// deeply.
///
/// Reporting it lets the caller rebuild, the same trade the block cache already
/// makes: this can cost time, never correctness.
fn node_must_still_have_our_chain(node_height: u64, scanned_height: u64) -> Result<(), String> {
    if node_height < scanned_height {
        return Err(format!(
            "node is at height {node_height} but we have scanned to              {scanned_height}; it has reorganised below our tip"
        ));
    }
    Ok(())
}

/// Download every block the wallet is missing, **validate** each into `chain`
/// (the node is untrusted), and scan it into `wallet`. Returns the height
/// reached. When a `cache` is given, each newly validated block is appended to
/// it so a later process can resume without re-downloading.
pub fn sync<P: ProofOfWork>(
    client: &NodeClient,
    chain: &mut Blockchain<P>,
    wallet: &mut Wallet,
    cache: Option<&BlockCache>,
) -> Result<u64, String> {
    let target = client.height()?;
    // A node shorter than us is not a node with nothing to send: it is a node
    // that no longer has the chain we scanned. The loop below only ever moves
    // forward, so without this it returns Ok having done nothing, and the wallet
    // keeps answering with balances from a branch that no longer exists — until
    // the node grows past our height and the next block fails to extend.
    //
    // Report it instead and let the caller rebuild. That is the same trade the
    // cache already makes: this can cost time, never correctness.
    node_must_still_have_our_chain(target, chain.height())?;
    let mut rng = rand_core::OsRng;
    // Genesis (height 0) is applied locally by `Blockchain::new`, never
    // downloaded, so scan it once up front: it records the founder premine (if
    // this wallet owns it) and keeps the wallet's global-index counter aligned
    // with the chain, whose output 0 is that premine.
    if wallet.scanned_outputs() == 0 {
        wallet.scan_block(&Block::genesis_for(wallet.address().network.params()), &[]);
    }
    while chain.height() < target {
        let h = chain.height();
        let (block, txs) = client.block(h)?;
        chain
            .add_block(&mut rng, &block, &txs)
            .map_err(|e| format!("block {h} failed validation: {e:?}"))?;
        wallet.scan_block(&block, &txs);
        if let Some(cache) = cache {
            cache.append(&block, &txs).map_err(|e| format!("writing block cache: {e}"))?;
        }
    }
    Ok(chain.height())
}

/// Build a fully-synced wallet + validation chain, using an on-disk block cache
/// so repeated runs don't re-download the chain from genesis.
///
/// On the fast path it replays the cache locally, then pulls only the blocks
/// mined since. If the cache is stale or corrupt, or the node has reorged below
/// our cached tip (a replayed or freshly-pulled block fails to extend the
/// chain), the cache is discarded and the wallet is rebuilt from genesis — so
/// caching can only ever cost time, never correctness. Returns the chain, the
/// scanned wallet, and the height reached.
pub fn load_synced_wallet(
    client: &NodeClient,
    account: Account,
    network: Network,
    cache_path: impl Into<PathBuf>,
    issued: &[(u32, u32)],
) -> Result<(Blockchain<TrustedPow>, Wallet, u64), String> {
    let cache = BlockCache::new(cache_path);
    match build_synced(client, account, network, &cache, true, issued) {
        Ok(result) => Ok(result),
        Err(_) => {
            cache.clear();
            build_synced(client, account, network, &cache, false, issued)
        }
    }
}

/// Build a wallet + validation chain from the on-disk cache **alone**, without
/// contacting the node. Used at daemon startup so it can come up immediately
/// (even if the node is not yet reachable) and sync new blocks lazily on the
/// first request. A corrupt or partial cache is discarded and rebuilt on the
/// first sync. Returns the chain, wallet, and the cache handle to keep syncing
/// into.
pub fn replay_cache(
    account: Account,
    network: Network,
    cache_path: impl Into<PathBuf>,
    issued: &[(u32, u32)],
) -> (Blockchain<TrustedPow>, Wallet, BlockCache) {
    let cache = BlockCache::new(cache_path);
    let genesis = |chain: &mut Blockchain<TrustedPow>, wallet: &mut Wallet| {
        *chain = Blockchain::for_network(network, TrustedPow);
        *wallet = Wallet::new(account, network);
        wallet.register_issued(issued.iter().copied());
        wallet.scan_block(&Block::genesis_for(network.params()), &[]);
    };
    let mut chain = Blockchain::for_network(network, TrustedPow);
    let mut wallet = Wallet::new(account, network);
    let mut rng = rand_core::OsRng;
    wallet.scan_block(&Block::genesis_for(network.params()), &[]);
    for (block, txs) in cache.load_clean() {
        if chain.add_block(&mut rng, &block, &txs).is_err() {
            cache.clear();
            genesis(&mut chain, &mut wallet);
            break;
        }
        wallet.scan_block(&block, &txs);
    }
    (chain, wallet, cache)
}

fn build_synced(
    client: &NodeClient,
    account: Account,
    network: Network,
    cache: &BlockCache,
    use_cache: bool,
    issued: &[(u32, u32)],
) -> Result<(Blockchain<TrustedPow>, Wallet, u64), String> {
    let mut chain = Blockchain::for_network(network, TrustedPow);
    let mut wallet = Wallet::new(account, network);
    // Before anything is scanned: a subaddress outside the lookahead window is
    // only known to whatever issued it, and a scan without its keys registered
    // silently reports no funds.
    wallet.register_issued(issued.iter().copied());
    let mut rng = rand_core::OsRng;
    // Genesis first, so global-index assignment lines up before any cached or
    // downloaded block is scanned.
    wallet.scan_block(&Block::genesis_for(network.params()), &[]);
    if use_cache {
        for (block, txs) in cache.load_clean() {
            let h = chain.height();
            chain
                .add_block(&mut rng, &block, &txs)
                .map_err(|e| format!("cached block {h} failed validation: {e:?}"))?;
            wallet.scan_block(&block, &txs);
        }
    }
    let height = sync(client, &mut chain, &mut wallet, Some(cache))?;
    Ok((chain, wallet, height))
}

/// Parse a decimal NOCT amount ("1.5") into atomic units.
pub fn parse_noct(s: &str) -> Option<u64> {
    let s = s.trim();
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    if frac_part.len() > 12 || !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let int: u64 = if int_part.is_empty() { 0 } else { int_part.parse().ok()? };
    let mut frac = frac_part.to_string();
    while frac.len() < 12 {
        frac.push('0');
    }
    let frac: u64 = frac.parse().ok()?;
    int.checked_mul(ATOMIC_UNITS)?.checked_add(frac)
}

/// Render atomic units as a decimal NOCT string.
pub fn format_noct(atomic: u64) -> String {
    let int = atomic / ATOMIC_UNITS;
    let frac = atomic % ATOMIC_UNITS;
    if frac == 0 {
        int.to_string()
    } else {
        format!("{int}.{frac:012}").trim_end_matches('0').to_string()
    }
}

// --- minimal JSON field extraction (node replies are flat objects) -----------

pub fn json_u64(s: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = &s[s.find(&needle)? + needle.len()..];
    let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn json_str(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let rest = &s[s.find(&needle)? + needle.len()..];
    Some(rest.chars().take_while(|&c| c != '"').collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_shorter_than_our_scan_is_refused() {
        // Equal or ahead is ordinary.
        assert!(node_must_still_have_our_chain(100, 100).is_ok());
        assert!(node_must_still_have_our_chain(101, 100).is_ok());

        // Behind means it no longer has what we scanned. Returning Ok here left
        // the wallet reporting balances from an abandoned branch.
        let e = node_must_still_have_our_chain(99, 100).unwrap_err();
        assert!(e.contains("reorganised"), "the error should say why: {e}");
    }

    #[test]
    fn noct_amount_roundtrips() {
        assert_eq!(parse_noct("5"), Some(5 * ATOMIC_UNITS));
        assert_eq!(parse_noct("0.01"), Some(ATOMIC_UNITS / 100));
        assert_eq!(parse_noct("1.5"), Some(ATOMIC_UNITS + ATOMIC_UNITS / 2));
        assert_eq!(parse_noct("1.2345"), Some(ATOMIC_UNITS + 234_500_000_000));
        assert_eq!(parse_noct(""), Some(0));
        assert_eq!(parse_noct("1.0000000000000"), None); // > 12 frac digits
        assert_eq!(parse_noct("abc"), None);

        assert_eq!(format_noct(5 * ATOMIC_UNITS), "5");
        assert_eq!(format_noct(ATOMIC_UNITS / 100), "0.01");
        assert_eq!(format_noct(ATOMIC_UNITS + ATOMIC_UNITS / 2), "1.5");
        assert_eq!(format_noct(0), "0");
    }

    #[test]
    fn block_cache_roundtrips_and_heals_corruption() {
        let path = std::env::temp_dir().join("noct_blockcache_roundtrip.test");
        let cache = BlockCache::new(&path);
        cache.clear();

        // Two records in, two records out, in order.
        let genesis = Block::genesis();
        cache.append(&genesis, &[]).unwrap();
        cache.append(&genesis, &[]).unwrap();
        assert_eq!(cache.load_all().0.len(), 2);
        let good_len = cache.load_all().1;

        // A truncated tail (an interrupted append) drops just that record, and
        // `load_clean` trims the file back to the last intact boundary so the
        // next append stays contiguous.
        let mut raw = std::fs::read(&path).unwrap();
        raw.truncate(raw.len() - 5);
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(cache.load_clean().len(), 1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), good_len / 2);
        // Appending after the heal yields a clean two-record file again.
        cache.append(&genesis, &[]).unwrap();
        assert_eq!(cache.load_all().0.len(), 2);

        // Leading garbage (first record unreadable) trims to empty, so a fresh
        // sync rebuilds from scratch instead of appending onto junk forever.
        std::fs::write(&path, vec![0xffu8; 500]).unwrap();
        assert!(cache.load_clean().is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        cache.clear();
        assert!(cache.load_all().0.is_empty());
    }

    #[test]
    fn json_extraction() {
        let s = "{\"height\":42,\"tip\":\"deadbeef\",\"mempool\":3}";
        assert_eq!(json_u64(s, "height"), Some(42));
        assert_eq!(json_u64(s, "mempool"), Some(3));
        assert_eq!(json_str(s, "tip").as_deref(), Some("deadbeef"));
        assert_eq!(json_u64(s, "missing"), None);
    }
}
