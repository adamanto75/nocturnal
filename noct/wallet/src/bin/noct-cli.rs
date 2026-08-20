//! `noct-cli` — a command-line Noct wallet that syncs from a `noctd` node.
//!
//! ```text
//! noct-cli new      [--wallet FILE]
//! noct-cli address  [--wallet FILE]
//! noct-cli balance  [--wallet FILE] [--node HOST:PORT]
//! noct-cli send --to ADDR --amount NOCT [--fee NOCT] [--wallet FILE] [--node HOST:PORT]
//! ```
//!
//! Syncing downloads every block from the node and **validates** it locally into
//! the wallet's own chain (the node is untrusted); that local chain also supplies
//! ring decoys for spending. Only the spend key is persisted, but validated
//! blocks are cached next to it (`FILE.cache`), so repeat commands replay the
//! cache locally and pull only newly-mined blocks instead of re-syncing from
//! genesis.

use noct_core::address::{Address, Network};
use noct_core::keys::Account;
use noct_core::tx::Payment;
use noct_tls::Endpoint;
use noct_wallet::client::{self, format_noct, load_synced_wallet, parse_noct, rpc_token_from_args, NodeClient};
use noct_wallet::{mnemonic, Direction, Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

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
    eprintln!("noct-cli address   [--wallet FILE]");
    eprintln!("noct-cli subaddress --index N [--account N] [--wallet FILE]  # a fresh receiving address");
    eprintln!("noct-cli balance   [--wallet FILE] [--node HOST:PORT]");
    eprintln!("noct-cli history   [--wallet FILE] [--node HOST:PORT]");
    eprintln!("noct-cli send --to ADDR --amount NOCT [--fee NOCT] [--wallet FILE] [--node HOST:PORT]");
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
    std::fs::write(path, &secret).unwrap_or_else(|e| fail(&format!("writing {path}: {e}")));
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
    std::fs::write(path, hex::encode(secret)).unwrap_or_else(|e| fail(&format!("writing {path}: {e}")));
    println!("restored wallet: {path}");
    println!("address: {}", address.encode());
}

fn cmd_seed(path: &str) {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| fail(&format!("no wallet at {path} — run `noct-cli new` first")));
    let bytes: [u8; 32] = hex::decode(contents.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .unwrap_or_else(|| fail("wallet key is not 32-byte hex"));
    println!("{}", mnemonic::to_phrase(&bytes));
}

fn cmd_balance(path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let account = load_account(path);
    let (_chain, wallet, height) =
        load_synced_wallet(&NodeClient::with_token(node.clone(), token.clone()), account, network, cache_path(path))
            .unwrap_or_else(|e| fail(&e));
    println!("synced to height {height}");
    println!("balance: {} NOCT", format_noct(wallet.balance()));
    println!("outputs: {} ({} unspent)", wallet.outputs().len(), wallet.unspent().count());
}

fn cmd_subaddress(args: &[String], path: &str, network: Network) {
    let mut wallet = load(path, network);
    let account = flag(args, "--account").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let index = flag(args, "--index")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| fail("subaddress needs --index N (1 or higher; 0 is your main address)"));
    let addr = wallet.subaddress(account, index);
    println!("subaddress ({account}, {index}):");
    println!("{}", addr.encode());
}

fn cmd_history(path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let account = load_account(path);
    let (_chain, wallet, height) =
        load_synced_wallet(&NodeClient::with_token(node.clone(), token.clone()), account, network, cache_path(path))
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

fn cmd_send(args: &[String], path: &str, node: &Endpoint, token: &Option<String>, network: Network) {
    let to = flag(args, "--to").unwrap_or_else(|| fail("send needs --to ADDR"));
    let amount = parse_noct(&flag(args, "--amount").unwrap_or_else(|| fail("send needs --amount NOCT")))
        .unwrap_or_else(|| fail("invalid --amount"));
    let fee = parse_noct(&flag(args, "--fee").unwrap_or_else(|| DEFAULT_FEE_NOCT.to_string()))
        .unwrap_or_else(|| fail("invalid --fee"));
    let destination = Address::decode(&to).unwrap_or_else(|_| fail("invalid --to address"));

    let account = load_account(path);
    let client = NodeClient::with_token(node.clone(), token.clone());
    let (chain, wallet, height) =
        load_synced_wallet(&client, account, network, cache_path(path)).unwrap_or_else(|e| fail(&e));
    println!("synced to height {height}; balance {} NOCT", format_noct(wallet.balance()));

    let payments = [Payment { destination, amount }];
    let tx = wallet
        .build_transaction(&mut OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE)
        .unwrap_or_else(|e| fail(&format!("building transaction: {e:?}")));
    let reply = client.submit_tx(&tx).unwrap_or_else(|e| fail(&e));
    println!("sent {} NOCT (fee {} NOCT)", format_noct(amount), format_noct(fee));
    println!("node replied: {}", reply.trim());
}

fn load(path: &str, network: Network) -> Wallet {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| fail(&format!("no wallet at {path} — run `noct-cli new` first")));
    client::load_wallet_for(contents.trim(), network).unwrap_or_else(|e| fail(&e))
}

fn load_account(path: &str) -> Account {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|_| fail(&format!("no wallet at {path} — run `noct-cli new` first")));
    client::load_account(contents.trim()).unwrap_or_else(|e| fail(&e))
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
