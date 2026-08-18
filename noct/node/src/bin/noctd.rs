//! `noctd` — the Noct full-node daemon.
//!
//! ```text
//! noctd [--p2p ADDR] [--rpc ADDR] [--peer ADDR]... [--mine] [--miner-address B58]
//! ```
//!
//! Defaults: P2P on 127.0.0.1:9333, RPC on 127.0.0.1:9334. If no `--miner-address`
//! is given, a fresh account is generated and its address + spend secret are
//! printed (ephemeral — for testnet/dev only).

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use noct_core::address::{Address, Network};
use noct_core::keys::Account;
use noct_node::{run, Config};
use rand_core::OsRng;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The network is read first: it sets the default ports, so an explicit
    // --p2p/--rpc later on still wins, but the defaults follow the network.
    let mut network = noct_core::address::Network::Mainnet;
    if let Some(i) = args.iter().position(|a| a == "--network") {
        network = match args.get(i + 1).map(|s| s.as_str()) {
            Some("mainnet") => noct_core::address::Network::Mainnet,
            Some("testnet") => noct_core::address::Network::Testnet,
            Some(other) => fail(&format!("unknown network {other:?} (expected mainnet or testnet)")),
            None => fail("--network needs a value (mainnet or testnet)"),
        };
    }
    let params = network.params();

    let mut p2p: SocketAddr = format!("127.0.0.1:{}", params.default_p2p_port).parse().unwrap();
    let mut rpc: SocketAddr = format!("127.0.0.1:{}", params.default_rpc_port).parse().unwrap();
    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut seeds: Vec<SocketAddr> = Vec::new();
    let mut target_outbound: usize = 8;
    let mut use_default_seeds = true;
    let mut mine = false;
    let mut miner_address: Option<Address> = None;
    let mut rpc_token: Option<String> = None;
    let mut rpc_rate_limit: u32 = noct_node::rpc::DEFAULT_RPC_RATE;
    let mut rpc_tls_cert: Option<std::path::PathBuf> = None;
    let mut rpc_tls_key: Option<std::path::PathBuf> = None;
    let mut data_dir: Option<std::path::PathBuf> = None;
    let mut mine_interval_ms: u64 = 2000;
    // Default to all cores but one, so the machine stays usable while mining.
    let mut mine_threads: usize = std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1).max(1))
        .unwrap_or(1);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--p2p" => {
                i += 1;
                p2p = parse_addr(&args, i, "--p2p");
            }
            "--rpc" => {
                i += 1;
                rpc = parse_addr(&args, i, "--rpc");
            }
            "--peer" => {
                i += 1;
                peers.extend(parse_dial_addrs(&args, i, "--peer"));
            }
            "--seed" => {
                i += 1;
                seeds.extend(parse_dial_addrs(&args, i, "--seed"));
            }
            "--max-outbound" => {
                i += 1;
                target_outbound = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .filter(|&n| n >= 1)
                    .unwrap_or_else(|| fail("--max-outbound needs a positive number"));
            }
            "--network" => i += 1, // already parsed above; skip its value
            "--no-default-seeds" => use_default_seeds = false,
            "--mine" => mine = true,
            "--mine-threads" => {
                i += 1;
                mine_threads = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .filter(|&n| n >= 1)
                    .unwrap_or_else(|| fail("--mine-threads needs a positive number"));
            }
            "--mine-interval-ms" => {
                i += 1;
                mine_interval_ms = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fail("--mine-interval-ms needs a number"));
            }
            "--rpc-rate-limit" => {
                i += 1;
                rpc_rate_limit = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fail("--rpc-rate-limit needs a number (0 disables)"));
            }
            "--rpc-tls-cert" => {
                i += 1;
                rpc_tls_cert = Some(args.get(i).unwrap_or_else(|| fail("--rpc-tls-cert needs a path")).into());
            }
            "--rpc-tls-key" => {
                i += 1;
                rpc_tls_key = Some(args.get(i).unwrap_or_else(|| fail("--rpc-tls-key needs a path")).into());
            }
            "--rpc-token" => {
                i += 1;
                let t = args.get(i).unwrap_or_else(|| fail("--rpc-token needs a value"));
                rpc_token = Some(t.clone());
            }
            "--rpc-token-file" => {
                i += 1;
                let path = args.get(i).unwrap_or_else(|| fail("--rpc-token-file needs a path"));
                let t = std::fs::read_to_string(path)
                    .unwrap_or_else(|e| fail(&format!("reading {path}: {e}")));
                let t = t.trim().to_string();
                if t.is_empty() {
                    fail(&format!("{path} is empty — it must contain the RPC token"));
                }
                rpc_token = Some(t);
            }
            "--data-dir" => {
                i += 1;
                let s = args.get(i).unwrap_or_else(|| fail("--data-dir needs a path"));
                data_dir = Some(std::path::PathBuf::from(s));
            }
            "--miner-address" => {
                i += 1;
                let s = args.get(i).unwrap_or_else(|| fail("--miner-address needs a value"));
                miner_address = Some(
                    Address::decode(s).unwrap_or_else(|_| fail("invalid --miner-address")),
                );
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => fail(&format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let miner_address = miner_address.unwrap_or_else(|| {
        let account = Account::random(&mut OsRng);
        // Must be an address for *this* network, or the node refuses to start.
        let address = Address::new(network, account.spend_public, account.view_public);
        eprintln!("generated ephemeral miner account (NOT persisted):");
        eprintln!("  address:      {}", address.encode());
        eprintln!("  spend secret: {}", hex::encode(account.spend_secret.to_bytes()));
        address
    });

    // Fold in the baked-in seed nodes (unless opted out), resolving any hostnames.
    if use_default_seeds {
        for s in noct_node::default_seeds(network) {
            match s.to_socket_addrs() {
                Ok(addrs) => seeds.extend(addrs),
                Err(e) => eprintln!("could not resolve default seed {s}: {e}"),
            }
        }
    }

    eprintln!("noctd starting");
    eprintln!(
        "  network: {} (p2p magic {:#010x})",
        match network {
            Network::Mainnet => "MAINNET — real value",
            Network::Testnet => "testnet — coins here are worthless",
        },
        params.p2p_magic
    );
    eprintln!("  pow:  {}", noct_node::pow_name());
    eprintln!("  p2p:  {p2p}");
    eprintln!("  rpc:  {rpc}");
    eprintln!("  peers: {peers:?}");
    eprintln!("  seeds: {seeds:?} (target {target_outbound} outbound)");
    eprintln!("  mining: {mine} ({mine_threads} threads)");
    match &data_dir {
        Some(d) => eprintln!("  data:  {}", d.display()),
        None => eprintln!("  data:  (in-memory only — chain is lost on exit)"),
    }

    if let Err(e) = run(Config {
        network,
        p2p_listen: p2p,
        rpc_listen: rpc,
        peers,
        seeds,
        target_outbound,
        miner_address,
        mine,
        mine_threads,
        mine_interval: Duration::from_millis(mine_interval_ms),
        data_dir,
        rpc_token,
        rpc_rate_limit,
        // Half a TLS configuration would otherwise start happily in plaintext,
        // which is the one outcome the operator definitely did not intend.
        rpc_tls: match (rpc_tls_cert, rpc_tls_key) {
            (Some(c), Some(k)) => Some((c, k)),
            (None, None) => None,
            _ => fail("--rpc-tls-cert and --rpc-tls-key must be given together"),
        },
    }) {
        fail(&format!("fatal: {e}"));
    }
}

/// Resolve a **dial** target, which may be a hostname.
///
/// `--p2p` and `--rpc` are bind addresses and stay IP literals — you bind to an
/// interface you hold, not to a name. But `--peer` and `--seed` name someone
/// else's machine, and an operator should be able to write
/// `seed1.nocturnalcoin.com:19333` there. The baked-in default seeds already go
/// through `to_socket_addrs`, so without this the flag was stricter than the
/// constant it overrides — the same address worked compiled in and failed on the
/// command line.
///
/// A name may resolve to several addresses (A and AAAA); all are kept, so a
/// seed reachable over either family is dialled over whichever works.
fn parse_dial_addrs(args: &[String], i: usize, flag: &str) -> Vec<SocketAddr> {
    let raw = args
        .get(i)
        .unwrap_or_else(|| fail(&format!("{flag} needs an address")));
    match raw.to_socket_addrs() {
        Ok(addrs) => {
            let v: Vec<SocketAddr> = addrs.collect();
            if v.is_empty() {
                fail(&format!("{flag}: `{raw}` resolved to no addresses"));
            }
            v
        }
        Err(e) => fail(&format!("{flag}: could not resolve `{raw}`: {e}")),
    }
}

fn parse_addr(args: &[String], i: usize, flag: &str) -> SocketAddr {
    args.get(i)
        .unwrap_or_else(|| fail(&format!("{flag} needs an address")))
        .parse()
        .unwrap_or_else(|_| fail(&format!("invalid address for {flag}")))
}

fn print_help() {
    eprintln!(
        "noctd [--network mainnet|testnet] [--p2p ADDR] [--rpc ADDR] [--peer ADDR]... [--seed ADDR]... [--no-default-seeds] [--max-outbound N] [--mine] [--mine-threads N] [--mine-interval-ms N] [--miner-address B58] [--data-dir DIR] [--rpc-token TOKEN | --rpc-token-file PATH] [--rpc-rate-limit N] [--rpc-tls-cert PATH --rpc-tls-key PATH]"
    );
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
