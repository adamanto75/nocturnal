//! Money going into the shielded pool, moving inside it, and coming back out —
//! on a real chain, through real block validation.
//!
//! The unit tests in `wallet::shielded` cover keys, addresses and derivation.
//! What they cannot cover is the thing most likely to be wrong: whether the
//! wallet's idea of where its notes are matches the chain's. That is a property
//! of two pieces of code agreeing, so it needs both of them running.
//!
//! Every block here is scanned with the chain's shielded state from either side
//! of it, so `scan_block` checks its own tree against the chain's root at every
//! step. A position that drifted by one would fail at the block that drifted it.

use noct_core::address::{Address, AnyAddress, Network};
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::Blockchain;
use noct_core::emission::base_reward;
use noct_core::keys::Account;
use noct_core::pow::KeccakPow;
use noct_core::shielded_state::ShieldedState;
use noct_core::tx::{Payment, Transaction};
use noct_wallet::shielded::{
    ShieldedKeys, ShieldedStateFileError, ShieldedWallet,
};
use noct_wallet::{Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

/// Maturity 1 throughout: these tests are about positions and paths, not about
/// how long a reward takes to ripen. The delayed-insertion rule has its own tests
/// in core, where it can be checked without proving anything.
const MATURITY: u64 = 1;

fn address(a: &Account) -> Address {
    Address::new(Network::Mainnet, a.spend_public, a.view_public)
}

struct Fixture {
    chain: Blockchain<KeccakPow>,
    ts: u64,
}

impl Fixture {
    fn new() -> Self {
        Fixture { chain: Blockchain::with_maturity(KeccakPow, MATURITY), ts: 1_000 }
    }

    /// Mine one block and hand it to every wallet, in the order the chain saw it.
    fn mine(
        &mut self,
        miner: &Address,
        txs: &[Transaction],
        ring: &mut [&mut Wallet],
        shielded: &mut [&mut ShieldedWallet],
    ) {
        let subsidy = base_reward(self.chain.emitted());
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let coinbase =
            Coinbase::create(&mut OsRng, self.chain.height(), miner, subsidy + fees);
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

        // The state from *before* the block is what decides leaf order, so it is
        // captured before the chain moves on.
        let before: ShieldedState = self.chain.shielded().clone();
        self.chain.add_block(&mut OsRng, &block, txs).expect("a valid block");
        self.ts += 130;

        for w in ring.iter_mut() {
            w.scan_block(&block, txs);
        }
        for w in shielded.iter_mut() {
            w.scan_block(&block, txs, &before, self.chain.shielded(), MATURITY)
                .expect("the wallet's tree must agree with the chain's");
        }
    }

    /// Blocks paying nobody in particular, so there are decoys to sign against.
    fn warm_up(&mut self, n: usize, ring: &mut [&mut Wallet], shielded: &mut [&mut ShieldedWallet]) {
        let filler = address(&Account::random(&mut OsRng));
        for _ in 0..n {
            self.mine(&filler, &[], ring, shielded);
        }
    }
}

fn shielded_wallet(seed: u8) -> ShieldedWallet {
    ShieldedWallet::new(
        ShieldedKeys::from_spend_secret(&[seed; 32], 0, Network::Mainnet)
            .expect("a fixed seed derives keys"),
    )
}

/// **The whole round trip.** Ring value crosses into the pool, moves inside it
/// with no ring side at all, and comes back out.
///
/// It is one test rather than three because each stage depends on the last: a
/// transfer needs a note to spend, and an unshield needs the transfer's output.
/// Splitting them would mean three copies of the setup and three chances for the
/// copies to drift.
#[test]
fn value_crosses_in_moves_privately_and_crosses_out() {
    let mut f = Fixture::new();
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();

    let mut alice_sh = shielded_wallet(1);
    let mut bob_sh = shielded_wallet(2);
    let bob_shielded_addr = bob_sh.address();

    // Fund Alice on the ring side, and give the chain decoys.
    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    assert!(alice.balance() > 0, "Alice has ring funds to shield");

    // --- 1. Shield: ring -> pool, to Alice's own shielded address ------------
    let shielding_amount = alice.balance() / 4;
    let fee = 10;
    let shield_tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            &alice_sh.address(),
            shielding_amount,
            fee,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("a shielding transaction builds");
    assert_eq!(shield_tx.cross, shielding_amount as i64, "value leaves the ring pool");
    assert!(shield_tx.shielded.is_some());
    f.chain.validate_tx(&mut OsRng, &shield_tx).expect("the chain accepts it");

    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[shield_tx], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);

    // Maturity 1, so the note is in the tree on the next block; one filler block
    // makes an anchor that contains it.
    f.warm_up(1, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    assert_eq!(alice_sh.balance(), shielding_amount, "the note arrived, and is spendable");
    assert_eq!(bob_sh.balance(), 0, "and is not visible to anyone else");
    assert_eq!(
        f.chain.shielded().totals().shielded(),
        shielding_amount,
        "the turnstile agrees with the wallet"
    );

    // --- 2. Transfer inside the pool: no ring side at all --------------------
    let send = shielding_amount / 2;
    let transfer_fee = 5;
    let plan = alice_sh
        .plan_transfer(&bob_shielded_addr, send, transfer_fee, f.chain.shielded())
        .expect("a transfer plans");
    assert_eq!(plan.cross(), -(transfer_fee as i64), "only the fee leaves the pool");

    let transfer = Transaction::build_with_shielded(
        &mut OsRng,
        &[],
        &[],
        transfer_fee,
        &noct_core::stealth::TxKeypair::random(&mut OsRng),
        plan.cross(),
        Some(|sighash: &[u8; 32]| {
            plan.authorize(sighash).map_err(|_| noct_core::tx::TxError::BundleUnavailable)
        }),
    )
    .expect("a transfer with no ring side builds");

    assert!(transfer.inputs.is_empty(), "no ring inputs");
    assert!(transfer.outputs.is_empty(), "no ring outputs");
    assert!(transfer.range_proof.is_none(), "and nothing to range-prove");
    f.chain.validate_tx(&mut OsRng, &transfer).expect("the chain accepts it");

    f.mine(&miner, &[transfer], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    f.warm_up(1, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);

    assert_eq!(bob_sh.balance(), send, "Bob received it, inside the pool");
    assert_eq!(
        alice_sh.balance(),
        shielding_amount - send - transfer_fee,
        "and Alice has her change, less the fee"
    );
    assert_eq!(
        f.chain.shielded().totals().shielded(),
        shielding_amount - transfer_fee,
        "the fee is the only thing that left the pool"
    );

    // --- 3. Unshield: pool -> ring ------------------------------------------
    let out = send / 2;
    let carol = Account::random(&mut OsRng);
    let unshield = alice
        .build_unshielding(
            &mut OsRng,
            &f.chain,
            &bob_sh,
            &[Payment { destination: address(&carol), amount: out }],
            out,
            fee,
            DEFAULT_RING_SIZE,
        )
        .expect("an unshielding transaction builds");
    assert_eq!(unshield.cross, -(out as i64), "value arrives from the shielded pool");
    f.chain.validate_tx(&mut OsRng, &unshield).expect("the chain accepts it");

    let shielded_before = f.chain.shielded().totals().shielded();
    f.mine(&miner, &[unshield], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    assert_eq!(
        f.chain.shielded().totals().shielded(),
        shielded_before - out,
        "and the pool is lighter by exactly that"
    );

    // Bob's note is spent and his change is back, which is the wallet noticing a
    // spend of its own from the nullifier alone.
    f.warm_up(1, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    assert_eq!(bob_sh.balance(), send - out, "Bob's remainder came back as change");
    assert!(bob_sh.notes().iter().any(|n| n.spent), "and the spent note is marked spent");
}

/// The wallet's tree must track the chain's leaf for leaf. Asserted directly
/// rather than only as a side effect of `scan_block`'s own check, because this is
/// the invariant every Merkle path depends on.
#[test]
fn the_wallets_tree_tracks_the_chains() {
    let mut f = Fixture::new();
    let mut sh = shielded_wallet(3);
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();

    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut sh]);
    assert_eq!(sh.root(), f.chain.shielded().root(), "empty pool, same root");
    assert_eq!(sh.leaves(), 0);

    // Shield to somebody else, so the wallet's tree has to track a leaf that is
    // not its own. This is the case a wallet that only tracked its own notes
    // would get wrong, and it is the common case.
    let stranger = shielded_wallet(4).address();
    let tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &sh,
            &stranger,
            1_000,
            10,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("builds");
    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[tx], &mut [&mut alice], &mut [&mut sh]);

    assert_eq!(sh.leaves(), f.chain.shielded().notes(), "same number of leaves");
    assert_eq!(sh.root(), f.chain.shielded().root(), "and the same root");
    assert_eq!(sh.balance(), 0, "none of it is ours");
}

/// A wallet cannot spend a note it has only seen created: a shielded reward is
/// withheld from the tree until it matures, so until then there is no path to it
/// and the balance must say so rather than promising money that cannot move.
#[test]
fn value_not_yet_in_the_tree_is_not_spendable() {
    let mut f = Fixture::new();
    let mut sh = shielded_wallet(5);
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();

    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut sh]);

    let tx = alice
        .build_shielding(&mut OsRng, &f.chain, &sh, &sh.address(), 5_000, 10, DEFAULT_RING_SIZE, true)
        .expect("builds");
    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[tx], &mut [&mut alice], &mut [&mut sh]);

    // The note is in the tree — a transaction's notes are not delayed — but no
    // anchor containing it has been published yet, so the wallet has a path only
    // against the root the chain now holds.
    assert_eq!(sh.balance(), 5_000);
    assert!(sh.path(0, f.chain.shielded()).is_ok(), "there is a path to it");
    assert_eq!(sh.pending_balance(), 0, "and nothing is waiting");
}

/// **A reload must be able to spend.** Saving and loading is only worth anything
/// if the witnesses survive it, and a witness is the one piece of wallet state
/// that cannot be recovered from the note or the chain — so this checks it by
/// building a real transfer from the reloaded wallet, not by comparing fields.
#[test]
fn a_reloaded_wallet_can_still_spend() {
    let mut f = Fixture::new();
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();
    let mut sh = shielded_wallet(6);

    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut sh]);
    let tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &sh,
            &sh.address(),
            50_000,
            10,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("builds");
    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[tx], &mut [&mut alice], &mut [&mut sh]);

    let saved = sh.to_bytes();
    let reloaded = ShieldedWallet::from_bytes(
        ShieldedKeys::from_spend_secret(&[6u8; 32], 0, Network::Mainnet).unwrap(),
        &saved,
        f.chain.shielded(),
    )
    .expect("the file describes this chain");

    assert_eq!(reloaded.balance(), sh.balance());
    assert_eq!(reloaded.root(), sh.root());
    assert_eq!(reloaded.leaves(), sh.leaves());

    // The proof of the thing: a spend built from the reloaded wallet's witnesses.
    let bob = shielded_wallet(7).address();
    let plan = reloaded
        .plan_transfer(&bob, 1_000, 5, f.chain.shielded())
        .expect("the reloaded witnesses still make a path");
    let transfer = Transaction::build_with_shielded(
        &mut OsRng,
        &[],
        &[],
        5,
        &noct_core::stealth::TxKeypair::random(&mut OsRng),
        plan.cross(),
        Some(|sighash: &[u8; 32]| {
            plan.authorize(sighash).map_err(|_| noct_core::tx::TxError::BundleUnavailable)
        }),
    )
    .expect("and a bundle that proves against them");
    f.chain.validate_tx(&mut OsRng, &transfer).expect("which the chain accepts");
}

/// A file must be refused rather than half-believed. Each of these would
/// otherwise load into a wallet that shows a balance it cannot spend.
#[test]
fn a_file_that_does_not_match_is_refused() {
    let mut f = Fixture::new();
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();
    let mut sh = shielded_wallet(8);

    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut sh]);
    let tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &sh,
            &sh.address(),
            50_000,
            10,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("builds");
    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[tx], &mut [&mut alice], &mut [&mut sh]);
    let saved = sh.to_bytes();
    let keys = || ShieldedKeys::from_spend_secret(&[8u8; 32], 0, Network::Mainnet).unwrap();

    // Another account's file: the notes are not addressed to these keys.
    let stranger = ShieldedKeys::from_spend_secret(&[9u8; 32], 0, Network::Mainnet).unwrap();
    assert_eq!(
        ShieldedWallet::from_bytes(stranger, &saved, f.chain.shielded()).err(),
        Some(ShieldedStateFileError::WrongAccount),
    );

    // The right file, one block too late: the chain has moved and the tree in the
    // file is no longer the chain's.
    let stale = saved.clone();
    f.warm_up(1, &mut [&mut alice], &mut [&mut sh]);
    let another = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &sh,
            &shielded_wallet(10).address(),
            1_000,
            10,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("builds");
    f.mine(&miner, &[another], &mut [&mut alice], &mut [&mut sh]);
    assert_eq!(
        ShieldedWallet::from_bytes(keys(), &stale, f.chain.shielded()).err(),
        Some(ShieldedStateFileError::OutOfStep),
        "a tree from an earlier height is not this chain's tree",
    );

    // Truncated, and with a byte appended: both are malformed, not "close enough".
    let current = sh.to_bytes();
    assert_eq!(
        ShieldedWallet::from_bytes(keys(), &current[..current.len() - 1], f.chain.shielded()).err(),
        Some(ShieldedStateFileError::Malformed),
    );
    let mut longer = current.clone();
    longer.push(0);
    assert_eq!(
        ShieldedWallet::from_bytes(keys(), &longer, f.chain.shielded()).err(),
        Some(ShieldedStateFileError::Malformed),
    );
    // And the unmodified one still loads, so the three above failed for their own
    // reasons rather than because nothing loads.
    assert!(ShieldedWallet::from_bytes(keys(), &current, f.chain.shielded()).is_ok());
}

/// Saving is deterministic. A file that differed run to run for no reason is one
/// nobody can compare, diff or check into anything.
#[test]
fn saving_the_same_wallet_twice_gives_the_same_bytes() {
    let mut f = Fixture::new();
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();
    let mut sh = shielded_wallet(11);

    f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut sh]);
    f.warm_up(20, &mut [&mut alice], &mut [&mut sh]);
    // Two notes, so the pending map has something to order.
    for to in [shielded_wallet(11).address(), shielded_wallet(11).keys().address_at(3)] {
        let tx = alice
            .build_shielding(&mut OsRng, &f.chain, &sh, &to, 5_000, 10, DEFAULT_RING_SIZE, true)
            .expect("builds");
        let miner = address(&Account::random(&mut OsRng));
        f.mine(&miner, &[tx], &mut [&mut alice], &mut [&mut sh]);
    }
    assert_eq!(sh.notes().len(), 2);
    assert_eq!(sh.to_bytes(), sh.to_bytes());
}

/// **A pool payout: some miners paid as ring outputs, some as notes, in one
/// transaction.** This is what the shielded pool is for from a miner's side —
/// choosing to be paid privately — and it has to work in the same batch as
/// everyone else, or a pool would need one transaction per pool and pay two fees.
#[test]
fn one_transaction_pays_both_kinds_of_address() {
    let mut f = Fixture::new();
    let pool_account = Account::random(&mut OsRng);
    let mut pool = Wallet::new(pool_account, Network::Mainnet);
    pool.scan_block(&Block::genesis(), &[]);
    let pool_addr = pool.address();
    // The pool's own shielded half. It holds nothing here — the pool's income is
    // a ring coinbase — so every shielded payment has to cross in.
    let mut pool_sh = shielded_wallet(20);
    // The note payees, created before any note exists and scanned from here on —
    // a wallet cannot join the commitment tree in the middle.
    let mut note_miner_a = shielded_wallet(21);
    let mut note_miner_b = shielded_wallet(22);
    let ring_miner_a = Account::random(&mut OsRng);
    let ring_miner_b = Account::random(&mut OsRng);

    f.mine(
        &pool_addr,
        &[],
        &mut [&mut pool],
        &mut [&mut pool_sh, &mut note_miner_a, &mut note_miner_b],
    );
    f.warm_up(20, &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner_a, &mut note_miner_b]);
    assert_eq!(pool_sh.spendable_value(), 0, "no notes, so the payment must cross in");
    let destinations = vec![
        (AnyAddress::Ring(address(&ring_miner_a)), 11_000u64),
        (AnyAddress::Shielded(note_miner_a.address()), 12_000),
        (AnyAddress::Ring(address(&ring_miner_b)), 13_000),
        (AnyAddress::Shielded(note_miner_b.address()), 14_000),
    ];
    let fee = 100;
    let tx = pool
        .build_payout(&mut OsRng, &f.chain, &pool_sh, &destinations, fee, DEFAULT_RING_SIZE)
        .expect("a mixed payout builds");

    assert_eq!(tx.cross, 12_000 + 14_000, "only the shielded side's total crosses");
    assert!(tx.shielded.is_some());
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");

    let miner = address(&Account::random(&mut OsRng));
    let mut miner_a_ring = Wallet::new(ring_miner_a, Network::Mainnet);
    let mut miner_b_ring = Wallet::new(ring_miner_b, Network::Mainnet);
    miner_a_ring.scan_block(&Block::genesis(), &[]);
    miner_b_ring.scan_block(&Block::genesis(), &[]);
    // These two only start scanning here, so they see the payment but not the
    // history before it — which is all a payee needs.
    f.mine(
        &miner,
        &[tx],
        &mut [&mut pool],
        &mut [&mut pool_sh, &mut note_miner_a, &mut note_miner_b],
    );
    f.warm_up(1, &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner_a, &mut note_miner_b]);

    assert_eq!(note_miner_a.balance(), 12_000, "paid as a note");
    assert_eq!(note_miner_b.balance(), 14_000, "and so was the other one");
    assert_eq!(
        f.chain.shielded().totals().shielded(),
        12_000 + 14_000,
        "the turnstile saw exactly the crossing the transaction declared"
    );
}

/// An all-ring batch must still be the transaction the pool has always built: a
/// version 1 one, with no bundle and nothing crossing. A pool that grew a
/// shielded bundle on every payout would be paying for proofs nobody asked for.
#[test]
fn an_all_ring_payout_is_still_a_version_one_transaction() {
    let mut f = Fixture::new();
    let pool_account = Account::random(&mut OsRng);
    let mut pool = Wallet::new(pool_account, Network::Mainnet);
    pool.scan_block(&Block::genesis(), &[]);
    let pool_addr = pool.address();
    let mut pool_sh = shielded_wallet(23);

    f.mine(&pool_addr, &[], &mut [&mut pool], &mut [&mut pool_sh]);
    f.warm_up(20, &mut [&mut pool], &mut [&mut pool_sh]);

    let miner_account = Account::random(&mut OsRng);
    let destinations = vec![(AnyAddress::Ring(address(&miner_account)), 5_000u64)];
    let tx = pool
        .build_payout(&mut OsRng, &f.chain, &pool_sh, &destinations, 100, DEFAULT_RING_SIZE)
        .expect("builds");

    assert_eq!(tx.version, noct_core::tx::TX_VERSION);
    assert_eq!(tx.cross, 0);
    assert!(tx.shielded.is_none());
    assert!(tx.range_proof.is_some());
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");
}

/// Once the pool holds notes, a shielded payout spends them and **nothing
/// crosses**: no public amount at all beyond the fee. That is the behaviour the
/// pool gets for free the day its own rewards are notes.
#[test]
fn a_pool_holding_notes_pays_shielded_miners_without_crossing() {
    let mut f = Fixture::new();
    let pool_account = Account::random(&mut OsRng);
    let mut pool = Wallet::new(pool_account, Network::Mainnet);
    pool.scan_block(&Block::genesis(), &[]);
    let pool_addr = pool.address();
    let mut pool_sh = shielded_wallet(24);
    // Created before the chain holds any note, and scanned from here on. A note's
    // position is its index among every note the chain ever made, so a wallet
    // cannot join in the middle — the same rule the ring side has for global
    // output indices.
    let mut note_miner = shielded_wallet(25);

    f.mine(&pool_addr, &[], &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);
    f.warm_up(20, &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);

    // Give the pool a note to pay out of, by shielding to itself.
    let shield = pool
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &pool_sh,
            &pool_sh.address(),
            60_000,
            100,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("builds");
    let miner = address(&Account::random(&mut OsRng));
    f.mine(&miner, &[shield], &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);
    f.warm_up(1, &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);
    assert_eq!(pool_sh.spendable_value(), 60_000);

    let destinations = vec![(AnyAddress::Shielded(note_miner.address()), 20_000u64)];
    let tx = pool
        .build_payout(&mut OsRng, &f.chain, &pool_sh, &destinations, 100, DEFAULT_RING_SIZE)
        .expect("builds");

    assert_eq!(tx.cross, 0, "the notes covered it, so nothing crossed");
    assert!(tx.shielded.is_some());
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");

    let pool_shielded_before = f.chain.shielded().totals().shielded();
    f.mine(&miner, &[tx], &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);
    f.warm_up(1, &mut [&mut pool], &mut [&mut pool_sh, &mut note_miner]);

    assert_eq!(note_miner.balance(), 20_000, "the miner was paid a note");
    assert_eq!(pool_sh.balance(), 40_000, "and the pool kept its change as a note");
    assert_eq!(
        f.chain.shielded().totals().shielded(),
        pool_shielded_before,
        "the pool's total did not move: nothing entered or left it"
    );
}
