//! `noct-cli` — a command-line Noct wallet that syncs from a `noctd` node.
//!
//! ```text
//! noct-cli new      [--wallet FILE]
//! noct-cli address  [--wallet FILE]
//! noct-cli balance  [--wallet FILE] [--node HOST:PORT]
//! noct-cli send --to ADDR --amount NOCT [--from ring|shielded|auto] [--fee NOCT] [--wallet FILE] [--node HOST:PORT]
//! ```
//!
//! Syncing downloads every block from the node and **validates** it locally into
//! the wallet's own chain (the node is untrusted); that local chain also supplies
//! ring decoys for spending. The key file (owner-only) is the wallet. Next to
//! it, `FILE.cache.state` holds the chain state and the wallet's bookkeeping,
//! so repeat commands pull only newly-mined blocks. It holds nothing that can
//! spend, and is re-checked against the chain on load. `FILE.cache` keeps the
//! validated blocks as a fallback for when that state cannot be used.

use noct_core::address::{Address, AnyAddress, Network};
use noct_core::keys::Account;
use noct_core::tx::Payment;
use noct_tls::Endpoint;
use noct_wallet::client::{
    self, format_noct, load_synced_wallet, load_synced_wallets, parse_noct, rpc_token_from_args,
    NodeClient,
};
use noct_wallet::shielded::ShieldedKeys;
use noct_wallet::{mnemonic, Direction, SpendFrom, Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

/// Refuse to send a transaction the network will not relay, and say by how much.
///
/// The node would answer this too — `/submit_tx` returns `required_fee` — but
/// only after the transaction has been built, signed and handed over. Checking
/// here means the refusal arrives before anything leaves the machine, and with
/// the command to fix it rather than a JSON body to interpret.
///
/// The floor is the *local* binary's. A node may legitimately run a different
/// one, and publishes it as `min_fee_per_kb` on `/info`; this catches the common
/// case cheaply, and the node's own answer remains authoritative.
fn refuse_below_the_floor(tx: &noct_core::tx::Transaction) {
    let size = noct_core::wire::encode_transaction(tx).len();
    let required = noct_core::mempool::min_fee(size);
    if tx.fee < required {
        fail(&format!(
            "fee {} NOCT is below the relay floor for this {size}-byte transaction, which needs {} NOCT.
Nothing was sent. Re-run with --fee {}",
            format_noct(tx.fee),
            format_noct(required),
            format_noct(required),
        ));
    }
}

/// Submit `tx` and report what the node actually decided.
///
/// **The reply has to be read before anything is called sent.** This used to print
/// `sent N NOCT` and only then print the node's answer, so a refused transaction
/// was announced as a success and contradicted on the next line. Worse, it exited
/// zero, so a script could not tell the difference at all.
///
/// Three outcomes, and they are genuinely different:
///
/// * **Accepted** — say so, with the txid to look it up by.
/// * **Refused** — the node answered, so the transaction is in nobody's mempool.
///   Nothing was sent, said plainly, and the exit status is non-zero.
/// Returns `true` when the node took it, so the caller can reserve the inputs
/// against a second spend. The other arms exit the process.
///
/// * **No reply** — the one case that cannot be resolved here. The transaction may
///   have been relayed before the connection broke, or may never have arrived.
///   Calling it "not sent" would be a guess, and a guess that invites re-sending
///   something already in flight, so it reports the txid and asks the caller to
///   check the chain. `noct-poold` treats the same ambiguity the same way, holding
///   such a payment as unresolved rather than refunding it.
fn submit_and_report(client: &NodeClient, tx: &noct_core::tx::Transaction, success: &str) -> bool {
    let txid = hex::encode(tx.hash());
    match client.submit_tx(tx) {
        Ok(reply) if reply.contains("\"accepted\":true") => {
            println!("{success}");
            println!("txid: {txid}");
            // Accepted does not always mean the node kept it: a full mempool
            // relays without storing. Worth saying, because it changes how likely
            // the transaction is to be mined.
            if reply.contains("\"outcome\":\"relayed-not-pooled\"") {
                if let Some(reason) = field_str(&reply, "reason") {
                    eprintln!("warning: {reason}");
                }
            }
            return true;
        }
        Ok(reply) => {
            eprintln!("NOT SENT — the node refused this transaction.");
            // The node says why in one sentence; show that rather than a JSON
            // body, and keep the raw reply only when it did not say.
            match field_str(&reply, "reason") {
                Some(reason) => eprintln!("  {reason}"),
                None => eprintln!("  node replied: {}", reply.trim()),
            }
            // A node may run a higher relay floor than this binary; it publishes
            // its own as `min_fee_per_kb` on /info, and quotes the figure for THIS
            // transaction when it refuses one. Repeat it as an actionable number
            // rather than leaving the caller to read it out of the JSON.
            if let Some(required) = field_u64(&reply, "required_fee") {
                eprintln!(
                    "  that node wants at least {} NOCT for this transaction — re-run with --fee {}",
                    format_noct(required),
                    format_noct(required),
                );
            }
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("OUTCOME UNKNOWN — no reply from the node ({e}).");
            eprintln!("  It may or may not have been relayed, so this is NOT a refusal.");
            eprintln!("  Check the chain for txid {txid} before sending it again.");
            std::process::exit(2);
        }
    }
}

/// Pull a quoted string field out of the node's JSON reply. See [`field_u64`] on
/// why this is not a JSON parser. Returns `None` rather than an empty string when
/// the field is absent, so the caller can fall back to showing the raw reply.
fn field_str(reply: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let rest = &reply[reply.find(&needle)? + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Pull an unquoted integer field out of the node's JSON reply.
///
/// Deliberately not a JSON parser: this reads one number out of one small reply
/// whose shape the node controls, and taking on a dependency for that would be the
/// tail wagging the dog. A missing or malformed field yields `None`, which the
/// caller treats as "the node did not say".
fn field_u64(reply: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let rest = &reply[reply.find(&needle)? + needle.len()..];
    let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

const DEFAULT_WALLET: &str = "noct-wallet.key";
const DEFAULT_NODE: &str = "127.0.0.1:9334";
const DEFAULT_FEE_NOCT: &str = "0.01";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return help();
    }
    let command = args[1].clone();
    let wallet_path = flag(&args, "--wallet").unwrap_or_else(|| DEFAULT_WALLET.to_string());
    // The scheme decides whether this connection is encrypted: a wallet syncing
    // from a node it does not host is sending its own transaction history over
    // the wire, so `https://` is the right default for anything remote.
    let node = flag(&args, "--node").unwrap_or_else(|| DEFAULT_NODE.to_string());
    let node = Endpoint::parse(&node, 9334).unwrap_or_else(|e| fail(&format!("--node: {e}")));
    let token = rpc_token_from_args(&args);
    let network = network_from_args(&args);

    match command.as_str() {
        "new" => cmd_new(&wallet_path, network),
        "restore" => cmd_restore(&args, &wallet_path, network),
        "seed" => cmd_seed(&wallet_path),
        "address" => println!("{}", load(&wallet_path, network).address().encode()),
        "shielded-address" => cmd_shielded_address(&wallet_path, network),
        "unshield" => cmd_unshield(&args, &wallet_path, &node, &token, network),
        "subaddress" => cmd_subaddress(&args, &wallet_path, network),
        "balance" => cmd_balance(&wallet_path, &node, &token, network),
        "history" => cmd_history(&wallet_path, &node, &token, network),
        "send" => cmd_send(&args, &wallet_path, &node, &token, network),
        "premine-key-image" => cmd_premine_key_image(&wallet_path),
        "-h" | "--help" | "help" => help(),
        other => fail(&format!("unknown command: {other}")),
    }
}

fn help() {
    eprintln!("  every command takes [--network mainnet|testnet] (default mainnet)");
    eprintln!("noct-cli new       [--wallet FILE]");
    eprintln!("noct-cli restore --mnemonic-stdin [--wallet FILE] [--dry-run]");
    eprintln!("  reads the 24-word phrase from stdin; --dry-run only prints the address it opens");
    eprintln!("  (--mnemonic \"word1 ... word24\" also works, but is visible in the process list)");
    eprintln!("noct-cli seed      [--wallet FILE]   # show this wallet's seed phrase");
    eprintln!("noct-cli address   [--wallet FILE]                 # your RING address");
    eprintln!("noct-cli shielded-address [--wallet FILE]           # your SHIELDED address (offline)");
    eprintln!("noct-cli subaddress --index N [--account N] [--wallet FILE]  # a fresh receiving address");
    eprintln!("noct-cli balance   [--wallet FILE] [--node HOST:PORT]");
    eprintln!("noct-cli history   [--wallet FILE] [--node HOST:PORT]");
    eprintln!("noct-cli send --to ADDR --amount NOCT [--from ring|shielded|auto] [--fee NOCT] [--wallet FILE] [--node HOST:PORT]");
    eprintln!("  --to takes EITHER kind of address. A shielded one moves the value into the");
    eprintln!("  shielded pool, and that amount is public; a payment inside one pool is not.");
    eprintln!("  --from ring|shielded|auto picks which pool YOUR money comes from (default auto).");
    eprintln!("  --from shielded --to <shielded addr> is the most private: no ring side at all.");
    eprintln!("noct-cli unshield --amount NOCT [--to RING_ADDR] [--fee NOCT] [--wallet FILE]");
    eprintln!("  moves value out of the shielded pool. The amount is public. Defaults --to your");
    eprintln!("  own ring address.");
    eprintln!("  --fee defaults to 0.01 NOCT. Nodes will not relay below a per-byte floor, so a");
    eprintln!("  large transaction needs more; the exact figure is printed if yours is short.");
    eprintln!("noct-cli premine-key-image --wallet FILE   # publishable proof-of-movement value");
    eprintln!("  offline. Prints ONLY the mainnet genesis premine output's key image.");
    eprintln!("  add --node-token TOKEN or --node-token-file PATH when the node's RPC is authenticated");
}

fn cmd_new(path: &str, network: Network) {
    if std::path::Path::new(path).exists() {
        fail(&format!("{path} already exists — refusing to overwrite a key"));
    }
    let account = Account::random(&mut OsRng);
    let secret = hex::encode(account.spend_secret.to_bytes());
    write_key_file(path, &secret);
    let address = Address::new(network, account.spend_public, account.view_public);
    println!("created wallet: {path}");
    println!("address: {}", address.encode());
    println!();
    println!("SEED PHRASE — write these 24 words down and keep them safe. They are the");
    println!("ONLY backup of this wallet; anyone who has them can spend your funds.");
    println!();
    println!("  {}", mnemonic::phrase_for(&account.spend_secret));
}

/// Read the seed phrase for `restore`.
///
/// `--mnemonic -` (and plain `--mnemonic-stdin`) take the phrase on **stdin**,
/// which is the only safe way to hand one to this process: a phrase passed as an
/// argument is visible in the process list to every other program on the machine
/// for as long as the command runs. The literal form is kept for interactive use
/// and warns loudly.
fn read_phrase(args: &[String]) -> String {
    let inline = flag(args, "--mnemonic");
    let from_stdin = args.iter().any(|a| a == "--mnemonic-stdin")
        || inline.as_deref() == Some("-");

    if from_stdin {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| fail(&format!("reading the seed phrase from stdin: {e}")));
        return buf;
    }
    match inline {
        Some(p) => {
            eprintln!(
                "warning: a seed phrase given as a command-line argument is visible to other\n\
                 programs on this machine. Prefer:  noct-cli restore --mnemonic-stdin"
            );
            p
        }
        None => fail("restore needs --mnemonic-stdin (or --mnemonic \"word1 ... word24\")"),
    }
}

fn cmd_restore(args: &[String], path: &str, network: Network) {
    // A preview validates the phrase and reports the wallet it opens without
    // writing anything, so a GUI can ask "is this your wallet?" before it commits
    // to a key file.
    let dry_run = args.iter().any(|a| a == "--dry-run");

    if !dry_run && std::path::Path::new(path).exists() {
        fail(&format!("{path} already exists — refusing to overwrite a key"));
    }
    let phrase = read_phrase(args);
    let secret = mnemonic::from_phrase(phrase.trim()).unwrap_or_else(|e| {
        fail(match e {
            mnemonic::MnemonicError::Invalid => "invalid seed phrase (a word is misspelled, out of order, or the checksum failed)",
            mnemonic::MnemonicError::WrongLength => "seed phrase must be 24 words",
            mnemonic::MnemonicError::NotCanonical => "seed phrase does not encode a valid NOCT key",
        })
    });

    // Derive through the same loader the wallet itself uses, rather than a second
    // path that could disagree about what a key file means.
    let encoded = hex::encode(secret);
    let account = client::load_account(&encoded).unwrap_or_else(|e| fail(&e));
    let address = Address::new(network, account.spend_public, account.view_public);
    if dry_run {
        println!("address: {}", address.encode());
        return;
    }
    write_key_file(path, &hex::encode(secret));
    println!("restored wallet: {path}");
    println!("address: {}", address.encode());
}

fn cmd_seed(path: &str) {
    let contents = read_key_file(path);
    let bytes: [u8; 32] = hex::decode(contents.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .unwrap_or_else(|| fail("wallet key is not 32-byte hex"));
    println!("{}", mnemonic::to_phrase(&bytes));
}

fn cmd_balance(path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let account = load_account(path);
    let (_chain, wallet, shielded, height) = load_synced_wallets(
        &NodeClient::with_token(node.clone(), token.clone()),
        account,
        network,
        cache_path(path),
        &load_issued(path),
    )
    .unwrap_or_else(|e| fail(&e));
    println!("synced to height {height}");

    // Both pools, always, and named — a single "balance" line would have to pick
    // one pool to mean, and whichever it picked would be wrong for somebody.
    let ring = wallet.balance();
    let notes = shielded.balance();
    println!("balance: {} NOCT", format_noct(ring + notes));
    println!("  ring pool:     {} NOCT ({} unspent outputs)", format_noct(ring), wallet.unspent().count());
    println!("  shielded pool: {} NOCT ({} unspent notes)", format_noct(notes), shielded.unspent().count());

    // Value that exists and cannot be moved yet, reported separately rather than
    // folded in. A balance that includes a note no anchor can reach is a balance
    // that promises money the wallet cannot spend.
    let pending = shielded.pending_balance();
    if pending > 0 {
        println!("  (plus {} NOCT of shielded rewards still maturing)", format_noct(pending));
    }
}

/// Where the CLI records the subaddresses it has handed out.
///
/// `Wallet::new` pre-derives a lookahead window on account 0 and nothing else.
/// This command will issue any `(account, index)` asked of it, so without a
/// record the next command reconstructs a wallet that has never heard of it,
/// scans without its keys, and reports no funds for an address this very tool
/// printed. The seed still derives the money; the wallet simply cannot see it,
/// which looks the same from outside.
fn issued_path(wallet_path: &str) -> String {
    format!("{wallet_path}.subaddr-issued")
}

/// Read the recorded pairs. A malformed line is skipped rather than fatal: a
/// corrupt record should cost visibility of one address, not use of the wallet.
fn load_issued(wallet_path: &str) -> Vec<(u32, u32)> {
    let Ok(text) = std::fs::read_to_string(issued_path(wallet_path)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let a = parts.next()?.parse().ok()?;
            let i = parts.next()?.parse().ok()?;
            Some((a, i))
        })
        .collect()
}

/// Record a pair, if it is not already there.
fn record_issued(wallet_path: &str, account: u32, index: u32) {
    if load_issued(wallet_path).contains(&(account, index)) {
        return;
    }
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(issued_path(wallet_path)) {
        Ok(mut f) => {
            if writeln!(f, "{account} {index}").is_err() {
                eprintln!("warning: could not record subaddress ({account}, {index});");
                eprintln!("         funds sent to it may not show up after this command.");
            }
        }
        // Worth saying out loud rather than failing: the address is still valid
        // and still receives, but this wallet will not see it again.
        Err(e) => {
            eprintln!("warning: could not open {}: {e}", issued_path(wallet_path));
            eprintln!("         funds sent to ({account}, {index}) may not show up later.");
        }
    }
}

fn cmd_subaddress(args: &[String], path: &str, network: Network) {
    let mut wallet = load(path, network);
    let account = flag(args, "--account").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let index = flag(args, "--index")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| fail("subaddress needs --index N (1 or higher; 0 is your main address)"));
    record_issued(path, account, index);
    let addr = wallet.subaddress(account, index);
    println!("subaddress ({account}, {index}):");
    println!("{}", addr.encode());
}

fn cmd_history(path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let account = load_account(path);
    let (_chain, wallet, height) =
        load_synced_wallet(&NodeClient::with_token(node.clone(), token.clone()), account, network, cache_path(path), &load_issued(path))
            .unwrap_or_else(|e| fail(&e));
    println!("synced to height {height}");
    if wallet.history().is_empty() {
        println!("(no transactions yet)");
        return;
    }
    for e in wallet.history() {
        match e.direction {
            Direction::Received => {
                let kind = if e.coinbase { "reward " } else { "received" };
                println!("  block {:>6}  {kind}  +{} NOCT", e.height, format_noct(e.amount));
            }
            Direction::Sent => println!(
                "  block {:>6}  sent      -{} NOCT  (fee {} NOCT)",
                e.height,
                format_noct(e.amount),
                format_noct(e.fee)
            ),
        }
    }
}

/// Reserve the inputs of a transaction the node accepted, and write that down.
///
/// **The writing down is the whole point.** Every `noct-cli` run is a new
/// process that re-syncs from the chain, and the chain does not mark an output
/// spent until the spending transaction is mined. Without this, a second send a
/// minute later selects the same output and builds a double-spend of our own,
/// which the node refuses. Keeping it in memory would help nobody: this process
/// is about to exit.
///
/// A failure to save is a warning rather than an error. The transaction is
/// already away, and saying nothing would leave the next run to rediscover the
/// problem with no clue why.
fn reserve_and_save(
    accepted: bool,
    wallet: &mut Wallet,
    tx: &noct_core::tx::Transaction,
    height: u64,
    chain: &noct_core::chain::Blockchain<noct_wallet::client::TrustedPow>,
    shielded: &mut noct_wallet::shielded::ShieldedWallet,
    wallet_path: &str,
) {
    if !accepted {
        return;
    }
    wallet.note_submitted(tx, height);
    shielded.note_submitted(tx, height);
    let state = client::state_path(std::path::Path::new(&cache_path(wallet_path)));
    if let Err(e) = client::save_state(&state, chain, wallet, shielded) {
        eprintln!("warning: could not record this spend as pending ({e}).");
        eprintln!("         A send in the next few minutes may reuse the same output");
        eprintln!("         and be refused as a double-spend; waiting for a block avoids it.");
    }
}

fn cmd_send(args: &[String], path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let to = flag(args, "--to").unwrap_or_else(|| fail("send needs --to ADDR"));
    let amount = parse_noct(&flag(args, "--amount").unwrap_or_else(|| fail("send needs --amount NOCT")))
        .unwrap_or_else(|| fail("invalid --amount"));
    let fee = parse_noct(&flag(args, "--fee").unwrap_or_else(|| DEFAULT_FEE_NOCT.to_string()))
        .unwrap_or_else(|| fail("invalid --fee"));
    // **Either kind of address, one verb.** Which pool a payment lands in is the
    // recipient's choice, expressed in the address they gave you, so the sender
    // should not have to pick a different command for it — and could not, without
    // knowing something about the recipient that the address already says.
    let destination = AnyAddress::decode(&to).unwrap_or_else(|_| fail("invalid --to address"));
    // **Which pool the money comes FROM** — the sender's own choice, separate
    // from the destination pool the address already fixes. Refused by name when
    // it is not understood: a typo that silently meant `auto` could publish an
    // amount somebody was deliberately keeping inside the pool.
    let from = match flag(args, "--from") {
        Some(v) => SpendFrom::parse(&v)
            .unwrap_or_else(|| fail(&format!("--from must be ring, shielded or auto (got {v:?})"))),
        None => SpendFrom::Auto,
    };
    if destination.network() != network {
        fail(&format!(
            "that is a {:?} address and this wallet is on {network:?} — refusing to send",
            destination.network()
        ));
    }

    let account = load_account(path);
    let client = NodeClient::with_token(node.clone(), token.clone());
    let (chain, mut wallet, mut shielded, height) =
        load_synced_wallets(&client, account, network, cache_path(path), &load_issued(path))
            .unwrap_or_else(|e| fail(&e));
    println!(
        "synced to height {height}; ring {} NOCT, shielded {} NOCT",
        format_noct(wallet.balance()),
        format_noct(shielded.balance())
    );

    let tx = wallet
        .build_send(
            &mut OsRng,
            &chain,
            &shielded,
            destination,
            amount,
            fee,
            DEFAULT_RING_SIZE,
            from,
        )
        .unwrap_or_else(|e| fail(&format!("building transaction: {e:?}")));

    // Say what this publishes before it is sent, not after. A crossing's amount
    // is the one thing the two-pool design cannot hide, and somebody shielding an
    // unusual number should learn that from the tool rather than from a chain
    // analyst later.
    if tx.cross > 0 {
        println!(
            "note: this moves {} NOCT into the shielded pool, and that amount is PUBLIC.",
            format_noct(tx.cross as u64)
        );
    } else if tx.cross < 0 && (-tx.cross) as u64 > tx.fee {
        // Only when value is genuinely leaving. When the sole crossing IS the
        // fee, calling it a public disclosure is noise: every fee is public on
        // every chain, and dressing it as a leak teaches people to ignore the
        // warning that matters.
        println!(
            "note: this takes {} NOCT out of the shielded pool, and that amount is PUBLIC.",
            format_noct((-tx.cross) as u64)
        );
    }
    // A payment with no ring side is the most private shape this chain has, and
    // it is worth telling somebody they got it — particularly since `--from auto`
    // would not have built it.
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        println!("this payment stays inside the shielded pool: no ring inputs, outputs or range proof, and only the fee is public.");
    }

    refuse_below_the_floor(&tx);
    let accepted = submit_and_report(
        &client,
        &tx,
        &format!(
            "sent {} NOCT to the {} pool (fee {} NOCT)",
            format_noct(amount),
            if destination.is_shielded() { "shielded" } else { "ring" },
            format_noct(fee)
        ),
    );
    reserve_and_save(accepted, &mut wallet, &tx, height, &chain, &mut shielded, path);
}

fn load(path: &str, network: Network) -> Wallet {
    let contents = read_key_file(path);
    client::load_wallet_for(contents.trim(), network).unwrap_or_else(|e| fail(&e))
}

fn load_account(path: &str) -> Account {
    let contents = read_key_file(path);
    client::load_account(contents.trim()).unwrap_or_else(|e| fail(&e))
}

/// Write a new key file, owner-only. It is the whole wallet: a plain
/// `std::fs::write` left it readable by every account on the machine.
fn write_key_file(path: &str, secret_hex: &str) {
    noct_wallet::secure_file::create_private(std::path::Path::new(path), secret_hex.as_bytes())
        .unwrap_or_else(|e| fail(&format!("writing {path}: {e}")));
}

/// Read a key file, warning if other accounts on this machine can read it too.
/// Keys written before `write_key_file` existed were.
fn read_key_file(path: &str) -> String {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| fail(&format!("no wallet at {path} — run `noct-cli new` first")));
    if noct_wallet::secure_file::is_exposed(std::path::Path::new(path)) {
        eprintln!("warning: {path} is readable by other users on this machine. Fix it with:  chmod 600 {path}");
    }
    contents
}

/// Where a wallet's validated-block cache lives (next to its key file).
fn cache_path(path: &str) -> String {
    format!("{path}.cache")
}

/// The network to operate on (`--network mainnet|testnet`, default mainnet).
///
/// This decides the address tag a new wallet gets and which genesis the local
/// validating chain is rooted at, so a testnet wallet cannot be used on mainnet
/// or the reverse.
fn network_from_args(args: &[String]) -> Network {
    match flag(args, "--network").as_deref() {
        None | Some("mainnet") => Network::Mainnet,
        Some("testnet") => Network::Testnet,
        Some(other) => fail(&format!("unknown network {other:?} (expected mainnet or testnet)")),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Print the mainnet genesis premine output's **key image**, and nothing else.
///
/// # Why this exists
///
/// The whitepaper promises that the premine allocation should be checkable
/// rather than merely asserted. Publishing the *address* does not achieve that
/// on a ring-signature chain: a spend is signed against sixteen possible inputs
/// and hides which one was real, so an observer watching the address learns
/// nothing about when the money moves.
///
/// A key image does achieve it. `I = x·H_p(P)` is a one-way function of the
/// output's one-time secret: it cannot be reversed, cannot be forged by anyone
/// without the key, and **cannot spend anything**. But it is exactly what a
/// spend must reveal — the network rejects a second appearance of the same
/// image, which is how double spends are prevented. So the instant this value
/// appears in a block, everyone knows the premine has moved; and for as long as
/// it does not, everyone knows it has not.
///
/// # Why it is safe to run on the founder wallet
///
/// It touches the network not at all, reads no chain, and writes nothing. It
/// prints one 32-byte public value. It never prints, logs or derives anything
/// from which the spend key could be recovered — and the derivation is one-way,
/// so the printed value cannot be worked backwards.
///
/// It also refuses to run on a wallet that is not the founder: an unrelated
/// wallet would silently produce a meaningless image, which someone might then
/// publish as a commitment it cannot honour.
/// The wallet's shielded receiving address.
///
/// Offline: it is derived from the same seed as the ring address, so there is
/// nothing to sync and no node to ask.
fn cmd_shielded_address(path: &str, network: Network) {
    let account = load_account(path);
    let keys = ShieldedKeys::for_account(&account, network)
        .unwrap_or_else(|e| fail(&format!("deriving shielded keys: {e}")));
    println!("{}", keys.address().encode());
}

/// Move value out of the shielded pool, onto the ring side.
///
/// The amount is public — that is what leaving the pool costs — and it is said
/// plainly rather than discovered afterwards.
fn cmd_unshield(args: &[String], path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let amount = parse_noct(&flag(args, "--amount").unwrap_or_else(|| fail("unshield needs --amount NOCT")))
        .unwrap_or_else(|| fail("invalid --amount"));
    let fee = parse_noct(&flag(args, "--fee").unwrap_or_else(|| DEFAULT_FEE_NOCT.to_string()))
        .unwrap_or_else(|| fail("invalid --fee"));

    let account = load_account(path);
    let client = NodeClient::with_token(node.clone(), token.clone());
    let (chain, mut wallet, mut shielded, height) =
        load_synced_wallets(&client, account, network, cache_path(path), &load_issued(path))
            .unwrap_or_else(|e| fail(&e));

    // Default to this wallet's own ring address: unshielding to somebody else in
    // one step is expressible, but the common case is moving your own money
    // across, and defaulting to a stranger's address would be a poor default.
    let destination = match flag(args, "--to") {
        Some(to) => Address::decode(&to).unwrap_or_else(|_| {
            fail("invalid --to address — unshielding pays a RING address, not a shielded one")
        }),
        None => wallet.address(),
    };

    println!(
        "synced to height {height}; shielded {} NOCT spendable",
        format_noct(shielded.spendable_value())
    );
    println!("note: unshielding {} NOCT publishes that amount.", format_noct(amount));

    let payments = [Payment { destination, amount }];
    let tx = wallet
        .build_unshielding(&mut OsRng, &chain, &shielded, &payments, amount, fee, DEFAULT_RING_SIZE)
        .unwrap_or_else(|e| fail(&format!("building transaction: {e:?}")));
    refuse_below_the_floor(&tx);
    let accepted = submit_and_report(
        &client,
        &tx,
        &format!(
            "unshielded {} NOCT (fee {} NOCT)",
            format_noct(amount),
            format_noct(fee)
        ),
    );
    reserve_and_save(accepted, &mut wallet, &tx, height, &chain, &mut shielded, path);
}

fn cmd_premine_key_image(wallet_path: &str) {
    use noct_core::address::{Address, Network};
    use noct_core::block::{PREMINE_AMOUNT, PREMINE_SPEND_PUBLIC, PREMINE_VIEW_PUBLIC};
    use noct_core::keys::{PrivateKey, PublicKey};
    use noct_core::ring::KeyImage;
    use noct_core::stealth;

    // Mainnet deliberately, whatever --network says: this is a statement about
    // the real allocation, and a testnet key image would commit to nothing.
    let account = load_account(wallet_path);

    // Refuse unless this really is the founder wallet.
    let spend_ok = account.spend_public.to_bytes() == PREMINE_SPEND_PUBLIC;
    let view_ok = account.view_public.to_bytes() == PREMINE_VIEW_PUBLIC;
    if !spend_ok || !view_ok {
        fail(
            "this wallet is not the founder wallet — its keys do not match the genesis premine.\n\
             Refusing: a key image from an unrelated wallet would be a commitment that cannot be\n\
             honoured, published as though it could.",
        );
    }

    // Re-derive the genesis output exactly as every node does, from published
    // constants, then recover our one-time secret for it and image that.
    let r = PrivateKey::from_canonical_bytes(noct_core::params::MAINNET.genesis_tx_secret)
        .unwrap_or_else(|| fail("genesis transaction secret is not a canonical scalar"));
    let tx_public = r.public_key();
    let spend = PublicKey::from_bytes(PREMINE_SPEND_PUBLIC)
        .unwrap_or_else(|| fail("premine spend key is not a valid point"));
    let view = PublicKey::from_bytes(PREMINE_VIEW_PUBLIC)
        .unwrap_or_else(|| fail("premine view key is not a valid point"));
    let founder = Address::new(Network::Mainnet, spend, view);

    // Sanity: the secret we are about to image must actually open the genesis
    // output. If it does not, something is wrong and publishing would mislead.
    let one_time = stealth::derive_output(&r, &founder, 0);
    let secret = stealth::output_secret(&account, &tx_public, 0);
    if secret.public_key().to_bytes() != one_time.to_bytes() {
        fail("derived secret does not open the genesis premine output — refusing to print");
    }

    let image = KeyImage::from_secret(&secret);

    eprintln!("Mainnet genesis premine — {} NOCT", format_noct(PREMINE_AMOUNT));
    eprintln!("address: {}", founder.encode());
    eprintln!();
    eprintln!("Key image (safe to publish; reveals nothing and cannot spend):");
    println!("{}", hex::encode(image.to_bytes()));
    eprintln!();
    eprintln!("Publishing this commits you to something checkable: the moment it appears");
    eprintln!("in a block, anyone can see the premine has moved. Until then, anyone can");
    eprintln!("see it has not.");
}

/// The key image `premine-key-image` prints must be **exactly** the one a real
/// spend of that output would reveal — otherwise publishing it commits to
/// something that will never appear on-chain, and the promise it is supposed to
/// make quietly fails to bind.
///
/// The mainnet founder key is not available here and must never be, so this
/// proves the mechanism against the **testnet** genesis instead, whose seed
/// phrase is published in `docs/TESTNET.md` precisely because that wallet holds
/// nothing. Mainnet and testnet share one genesis construction and one premine
/// mechanism — only the constants differ — so a derivation correct for one is
/// correct for the other.
#[cfg(test)]
mod premine_key_image_tests {
    use noct_core::block::Block;
    use noct_core::keys::PrivateKey;
    use noct_core::params::TESTNET;
    use noct_core::ring::KeyImage;
    use noct_core::stealth;
    use noct_wallet::mnemonic;

    /// The published testnet faucet phrase — worthless by design.
    const FAUCET_PHRASE: &str = "solve leave enact inform twin bleak picture swarm slim animal \
        spell evidence memory share index lemon soft drama hire utility scorpion tool expand digital";

    #[test]
    fn the_printed_image_is_the_one_a_spend_would_reveal() {
        let secret = mnemonic::from_phrase(FAUCET_PHRASE).expect("the published phrase is valid");
        let account = noct_wallet::client::load_account(&hex::encode(secret)).expect("loads");

        // What the wallet gets by scanning the real genesis block — the same
        // path a spend later uses to build its ring signature.
        let genesis = Block::genesis_for(&TESTNET);
        let received = genesis
            .coinbase
            .scan(&account)
            .expect("the testnet genesis premine belongs to the faucet wallet");

        // What `premine-key-image` derives, from published constants alone.
        let r = PrivateKey::from_canonical_bytes(TESTNET.genesis_tx_secret).expect("canonical");
        let derived_secret = stealth::output_secret(&account, &r.public_key(), 0);
        let derived_image = KeyImage::from_secret(&derived_secret);

        assert_eq!(
            derived_image.to_bytes(),
            received.key_image.to_bytes(),
            "the published image must match what spending the premine actually reveals"
        );
    }

    /// And the guard that stops a wrong wallet producing a plausible-looking
    /// value: the recovered secret must genuinely open the genesis output.
    #[test]
    fn a_stranger_cannot_open_the_genesis_output() {
        use rand_core::OsRng;
        let stranger = noct_core::keys::Account::random(&mut OsRng);
        let genesis = Block::genesis_for(&TESTNET);
        assert!(
            genesis.coinbase.scan(&stranger).is_none(),
            "only the premine wallet may open the genesis output"
        );
    }
}

#[cfg(test)]
mod submit_reply_tests {
    use super::field_u64;

    /// The node's reply is the only source of truth about whether a transaction
    /// was sent, so the two answers must not be confusable. `"accepted":true` is
    /// what [`submit_and_report`] keys on, and a refusal reply must not contain it
    /// — including the refusal that carries the most fields.
    #[test]
    fn a_refusal_is_never_mistaken_for_an_acceptance() {
        let accepted = r#"{"accepted":true,"txid":"ab12"}"#;
        let refused = r#"{"accepted":false,"txid":"ab12"}"#;
        let refused_fee = r#"{"accepted":false,"txid":"ab12","error":"fee below the relay floor","fee":100000,"required_fee":125350000}"#;

        assert!(accepted.contains("\"accepted\":true"));
        assert!(!refused.contains("\"accepted\":true"));
        assert!(
            !refused_fee.contains("\"accepted\":true"),
            "the fee refusal carries the most fields and is the likeliest to be misread"
        );
    }

    /// The figure quoted back to the user comes out of that reply, so reading the
    /// wrong number would send them to a fee that still fails.
    #[test]
    fn the_required_fee_is_read_out_of_the_reply() {
        let refused_fee = r#"{"accepted":false,"txid":"ab12","error":"fee below the relay floor","fee":100000,"required_fee":125350000}"#;
        assert_eq!(field_u64(refused_fee, "required_fee"), Some(125_350_000));
        // `fee` is a prefix of nothing here, but `required_fee` ENDS with `fee`:
        // searching for the shorter key must not land inside the longer one.
        assert_eq!(field_u64(refused_fee, "fee"), Some(100_000));
    }

    /// A field the node did not send means "it did not say", never a zero. A zero
    /// would be printed as `re-run with --fee 0`, which is advice that cannot work.
    #[test]
    fn a_missing_or_malformed_field_says_nothing_rather_than_zero() {
        assert_eq!(field_u64(r#"{"accepted":false}"#, "required_fee"), None);
        assert_eq!(field_u64("", "required_fee"), None);
        // Quoted, so not the unquoted integer this reads; better None than 0.
        assert_eq!(field_u64(r#"{"required_fee":"125350000"}"#, "required_fee"), None);
        // Truncated mid-reply, as a dropped connection would leave it.
        assert_eq!(field_u64(r#"{"accepted":false,"required_fee":"#, "required_fee"), None);
    }
}
