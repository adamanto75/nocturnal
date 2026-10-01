//! **A wallet must not spend an output it has already spent.**
//!
//! Nothing on chain marks an output spent until the spending transaction is
//! *mined*. A wallet that trusts only the chain therefore re-selects an output it
//! sent a minute ago, builds a double-spend of its own, and gets refused — and
//! because each `noct-cli` run is a fresh process that re-syncs from scratch,
//! "a minute ago" includes the previous invocation.
//!
//! This was not hypothetical. The testnet load bots did it **1,352 times against
//! 108,732 accepted sends**, about one in eighty, and every one of them was
//! reported to the user as a success until the node learned to answer honestly.
//!
//! So the wallet reserves the inputs of anything it submitted, until it either
//! sees the spend confirmed or decides the transaction is never coming.

use noct_core::address::{Address, Network};
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::Blockchain;
use noct_core::emission::base_reward;
use noct_core::keys::Account;
use noct_core::pow::KeccakPow;
use noct_core::tx::{Payment, Transaction};
use noct_wallet::{Wallet, DEFAULT_RING_SIZE, PENDING_SPEND_BLOCKS};
use rand_core::OsRng;

const FEE: u64 = 10_000_000_000; // 0.01 NOCT

fn address(a: &Account) -> Address {
    Address::new(Network::Mainnet, a.spend_public, a.view_public)
}

struct Fixture {
    chain: Blockchain<KeccakPow>,
    ts: u64,
}

impl Fixture {
    fn new() -> Self {
        Fixture { chain: Blockchain::with_maturity(KeccakPow, 1), ts: 1_000 }
    }

    fn mine(&mut self, miner: &Address, txs: &[Transaction], w: &mut Wallet) {
        let subsidy = base_reward(self.chain.emitted());
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let coinbase = Coinbase::create(&mut OsRng, self.chain.height(), miner, subsidy + fees);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: noct_core::block::GENESIS_TIMESTAMP + self.ts,
                prev_id: self.chain.tip_id(),
                nonce: 0,
            },
            coinbase,
            tx_hashes: txs.iter().map(|t| t.hash()).collect(),
        };
        block.mine(&KeccakPow, self.chain.next_difficulty());
        self.chain.add_block(&mut OsRng, &block, txs).expect("a valid block");
        self.ts += 130;
        w.scan_block(&block, txs);
    }
}

/// A wallet with exactly two spendable outputs, which is the smallest fixture
/// that can tell "picked something else" apart from "could not build at all".
fn two_output_wallet() -> (Fixture, Wallet, Address) {
    let mut f = Fixture::new();
    let account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();

    f.mine(&alice_addr, &[], &mut alice);
    f.mine(&alice_addr, &[], &mut alice);
    let filler = address(&Account::random(&mut OsRng));
    for _ in 0..20 {
        f.mine(&filler, &[], &mut alice);
    }
    assert_eq!(alice.unspent().count(), 2, "exactly two outputs to choose between");
    (f, alice, filler)
}

/// **The bug, and that it is gone.** Two sends with no block mined between them
/// must not spend the same output twice.
#[test]
fn a_second_send_does_not_reuse_an_unconfirmed_input() {
    let (f, mut alice, _filler) = two_output_wallet();
    let bob = address(&Account::random(&mut OsRng));
    let amount = 1_000_000u64;

    let first = alice
        .build_transaction(
            &mut OsRng,
            &f.chain,
            &[Payment { destination: bob, amount }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");
    // Only now, with the node's acceptance, are the inputs reserved.
    alice.note_submitted(&first, f.chain.height());

    let second = alice
        .build_transaction(
            &mut OsRng,
            &f.chain,
            &[Payment { destination: bob, amount }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("the other output is still available, so this must build");

    // The real assertion: no key image in common. Comparing hashes would pass
    // even for two transactions spending the same output, since each build draws
    // fresh randomness.
    for image in first.key_images() {
        assert!(
            !second.key_images().contains(&image),
            "the second transaction re-spent an input of the first — this is the bug"
        );
    }
    f.chain.validate_tx(&mut OsRng, &second).expect("and the chain accepts it");
}

/// Without the reservation the collision really does happen, so the test above
/// is testing something. Same fixture, same two sends, minus `note_submitted`.
#[test]
fn without_the_reservation_the_same_input_is_picked_again() {
    let (f, alice, _filler) = two_output_wallet();
    let bob = address(&Account::random(&mut OsRng));
    let amount = 1_000_000u64;

    let build = || {
        alice
            .build_transaction(
                &mut OsRng,
                &f.chain,
                &[Payment { destination: bob, amount }],
                FEE,
                DEFAULT_RING_SIZE,
            )
            .expect("builds")
    };
    let first = build();
    let second = build();
    assert_eq!(
        first.key_images(),
        second.key_images(),
        "selection is deterministic, so without a reservation both spend the same output \
         — which is precisely the double-spend the node refuses"
    );
}

/// A reservation must not outlive its usefulness. If the transaction is never
/// mined, the output has to come back, or the balance is stuck with no remedy.
#[test]
fn a_reservation_lapses_so_a_dropped_transaction_cannot_strand_funds() {
    let (mut f, mut alice, filler) = two_output_wallet();
    let bob = address(&Account::random(&mut OsRng));

    let tx = alice
        .build_transaction(
            &mut OsRng,
            &f.chain,
            &[Payment { destination: bob, amount: 1_000_000 }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");
    let at = f.chain.height();
    alice.note_submitted(&tx, at);
    assert!(alice.pending_spend_value(at) > 0, "something is reserved");

    // Mine past the window WITHOUT ever including the transaction.
    for _ in 0..(PENDING_SPEND_BLOCKS + 1) {
        f.mine(&filler, &[], &mut alice);
    }

    assert_eq!(
        alice.pending_spend_value(f.chain.height()),
        0,
        "the reservation must lapse, or a dropped transaction strands its inputs for ever"
    );
    // And the output is usable again.
    let again = alice
        .build_transaction(
            &mut OsRng,
            &f.chain,
            &[Payment { destination: bob, amount: 1_000_000 }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");
    assert_eq!(
        again.key_images(),
        tx.key_images(),
        "and it is the very output that was reserved, now free again"
    );
}

/// Confirmation releases the reservation immediately, rather than leaving it to
/// time out: the output is spent for real now, and the wallet knows it.
#[test]
fn confirmation_releases_the_reservation_at_once() {
    let (mut f, mut alice, filler) = two_output_wallet();
    let bob = address(&Account::random(&mut OsRng));

    let tx = alice
        .build_transaction(
            &mut OsRng,
            &f.chain,
            &[Payment { destination: bob, amount: 1_000_000 }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");
    let at = f.chain.height();
    alice.note_submitted(&tx, at);
    assert!(alice.pending_spend_value(at) > 0);

    // One block, containing it.
    f.mine(&filler, &[tx], &mut alice);

    assert_eq!(
        alice.pending_spend_value(f.chain.height()),
        0,
        "a confirmed spend is not a pending one"
    );
    // The window runs from the height the spend was recorded at, not from zero,
    // so this is what shows the release was the confirmation rather than the
    // reservation timing out.
    assert!(
        f.chain.height() < at + PENDING_SPEND_BLOCKS,
        "released at height {} with the window open until {}, so it was the confirmation",
        f.chain.height(),
        at + PENDING_SPEND_BLOCKS
    );
}

/// Reserving the inputs of a transaction the node *refused* would strand them
/// for nothing, so `note_submitted` is only ever called on acceptance. This pins
/// the contract that makes that safe: it reserves by key image, so a transaction
/// spending outputs this wallet does not own reserves nothing.
#[test]
fn a_transaction_spending_nothing_of_ours_reserves_nothing() {
    let (f, mut alice, _filler) = two_output_wallet();

    let stranger_account = Account::random(&mut OsRng);
    let mut stranger = Wallet::new(stranger_account, Network::Mainnet);
    stranger.scan_block(&Block::genesis(), &[]);
    let mut f2 = Fixture::new();
    let stranger_addr = stranger.address();
    f2.mine(&stranger_addr, &[], &mut stranger);
    let filler2 = address(&Account::random(&mut OsRng));
    for _ in 0..20 {
        f2.mine(&filler2, &[], &mut stranger);
    }
    let theirs = stranger
        .build_transaction(
            &mut OsRng,
            &f2.chain,
            &[Payment { destination: stranger_addr, amount: 1_000 }],
            FEE,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");

    alice.note_submitted(&theirs, f.chain.height());
    assert_eq!(
        alice.pending_spend_value(f.chain.height()),
        0,
        "somebody else's transaction must not reserve our outputs"
    );
}
