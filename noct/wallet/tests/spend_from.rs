//! **The sender's choice of which pool to spend from.**
//!
//! The destination pool is the recipient's choice, carried in the address. This
//! is the other half: where the money comes from. It is a privacy decision, not
//! a routing detail — a payment that stays inside one pool publishes only its
//! fee, and one that crosses publishes the amount that crossed — so the four
//! combinations are pinned here by what each one puts on the chain, not merely
//! by whether it builds.
//!
//! The case worth the most attention is `Shielded → Shielded`, which is *not*
//! `Auto` with the choice forced: `Auto` still raises the fee from a ring input,
//! so it leaves a ring side behind. Choosing shielded builds the pure in-pool
//! form, which has none. That shape was unreachable from either wallet before.

use noct_core::address::{Address, AnyAddress, Network};
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::Blockchain;
use noct_core::emission::base_reward;
use noct_core::keys::Account;
use noct_core::pow::KeccakPow;
use noct_core::shielded_state::ShieldedState;
use noct_core::tx::Transaction;
use noct_wallet::shielded::{ShieldedKeys, ShieldedWallet};
use noct_wallet::{SpendFrom, Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

/// Maturity 1: this is about which pool funds a payment, not about how long a
/// reward takes to ripen. The delayed-insertion rule has its own tests in core.
const MATURITY: u64 = 1;
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
        Fixture { chain: Blockchain::with_maturity(KeccakPow, MATURITY), ts: 1_000 }
    }

    fn mine(
        &mut self,
        miner: &Address,
        txs: &[Transaction],
        ring: &mut Wallet,
        shielded: &mut ShieldedWallet,
    ) {
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
        let before: ShieldedState = self.chain.shielded().clone();
        self.chain.add_block(&mut OsRng, &block, txs).expect("a valid block");
        self.ts += 130;
        ring.scan_block(&block, txs);
        shielded
            .scan_block(&block, txs, &before, self.chain.shielded(), MATURITY)
            .expect("the wallet's tree must agree with the chain's");
    }
}

fn shielded_wallet(seed: u8) -> ShieldedWallet {
    ShieldedWallet::new(
        ShieldedKeys::from_spend_secret(&[seed; 32], 0, Network::Mainnet).expect("derives"),
    )
}

/// Fund a wallet on both sides: ring outputs from mining, and notes from one
/// shielding, so every `from`/`to` combination has something to spend.
fn funded() -> (Fixture, Wallet, ShieldedWallet, ShieldedWallet) {
    let mut f = Fixture::new();
    let account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let mut alice_sh = shielded_wallet(1);
    let bob_sh = shielded_wallet(2);
    let alice_addr = alice.address();

    for _ in 0..6 {
        f.mine(&alice_addr, &[], &mut alice, &mut alice_sh);
    }
    let filler = address(&Account::random(&mut OsRng));
    for _ in 0..20 {
        f.mine(&filler, &[], &mut alice, &mut alice_sh);
    }

    // Put some value in the pool so `Shielded` has notes to spend.
    let seed_amount = alice.balance() / 3;
    let tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            &alice_sh.address(),
            seed_amount,
            FEE,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("seeds the pool");
    f.mine(&filler, &[tx], &mut alice, &mut alice_sh);
    f.mine(&filler, &[], &mut alice, &mut alice_sh);
    assert!(alice_sh.spendable_value() > 0, "the fixture must actually hold notes");
    assert!(alice.balance() > 0, "and ring outputs too");

    // bob_sh is only ever a destination here, so it is handed back unscanned;
    // its address is all these tests need from it.
    (f, alice, alice_sh, bob_sh)
}

/// `Ring → Ring`: an ordinary payment. Nothing crosses, so nothing about the
/// amount is published.
#[test]
fn ring_to_ring_stays_in_the_ring_pool() {
    let (f, alice, alice_sh, _bob_sh) = funded();
    let carol = address(&Account::random(&mut OsRng));
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Ring(carol),
            1_000_000,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Ring,
        )
        .expect("builds");
    assert_eq!(tx.cross, 0, "nothing crosses, so no amount is published");
    assert!(tx.shielded.is_none(), "and there is no bundle at all");
    assert!(!tx.inputs.is_empty());
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");
}

/// `Ring → Shielded`: a shielding. The amount crosses and is public; the change
/// stays behind rather than crossing more than was asked for.
#[test]
fn ring_to_shielded_crosses_exactly_the_payment() {
    let (f, alice, alice_sh, bob_sh) = funded();
    let amount = 1_000_000u64;
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Ring,
        )
        .expect("builds");
    assert_eq!(
        tx.cross, amount as i64,
        "exactly the payment crosses — not the change as well"
    );
    assert!(tx.shielded.is_some());
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");
}

/// **`Shielded → Shielded`: no ring side at all.**
///
/// This is the shape the choice exists for. `Auto` would have raised the fee
/// from a ring input and left inputs, an output and a range proof on the chain;
/// choosing shielded leaves none of them, and the fee crosses out of the pool
/// instead. Asserting the *absence* of the ring side is the whole point — a test
/// that only checked it built would pass for `Auto` too.
#[test]
fn shielded_to_shielded_has_no_ring_side() {
    let (f, alice, alice_sh, bob_sh) = funded();
    let amount = alice_sh.spendable_value() / 4;
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("builds");

    assert!(tx.inputs.is_empty(), "no ring inputs");
    assert!(tx.outputs.is_empty(), "no ring outputs");
    assert!(tx.range_proof.is_none(), "and nothing to range-prove");
    assert_eq!(
        tx.cross, -(FEE as i64),
        "only the fee leaves the pool — the payment itself never becomes public"
    );
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");

    // And the contrast that makes the choice worth having: Auto, same payment,
    // does leave a ring side behind.
    let auto = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Auto,
        )
        .expect("builds");
    assert!(
        !auto.inputs.is_empty(),
        "Auto raises the fee from a ring input, so choosing shielded is not the same transaction"
    );
}

/// `Shielded → Ring`: an unshielding. Value arrives from the pool, and that
/// amount is public.
#[test]
fn shielded_to_ring_unshields() {
    let (f, alice, alice_sh, _bob_sh) = funded();
    let carol = address(&Account::random(&mut OsRng));
    let amount = alice_sh.spendable_value() / 4;
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Ring(carol),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("builds");
    assert_eq!(tx.cross, -(amount as i64), "value arrives from the shielded pool");
    assert!(tx.shielded.is_some());
    // One ring input is unavoidable here: ring outputs' masks must cancel against
    // a pseudo-out, and only a real input supplies one.
    assert!(!tx.inputs.is_empty(), "paying a ring address needs a ring input");
    f.chain.validate_tx(&mut OsRng, &tx).expect("the chain accepts it");
}

/// `Auto` must keep doing exactly what it did before the choice existed, or this
/// change quietly alters what every existing caller sends.
#[test]
fn auto_is_unchanged() {
    let (f, alice, alice_sh, bob_sh) = funded();
    let amount = 1_000_000u64;
    let dest = AnyAddress::Shielded(bob_sh.address());

    let via_send = alice
        .build_send(&mut OsRng, &f.chain, &alice_sh, dest, amount, FEE, DEFAULT_RING_SIZE, SpendFrom::Auto)
        .expect("builds");
    let via_payout = alice
        .build_payout(&mut OsRng, &f.chain, &alice_sh, &[(dest, amount)], FEE, DEFAULT_RING_SIZE)
        .expect("builds");

    // Not hash equality — each build draws fresh randomness — but the shape and
    // the public consequences must match.
    assert_eq!(via_send.cross, via_payout.cross);
    assert_eq!(via_send.inputs.len(), via_payout.inputs.len());
    assert_eq!(via_send.outputs.len(), via_payout.outputs.len());
    assert_eq!(via_send.shielded.is_some(), via_payout.shielded.is_some());
}

/// The parser refuses what it does not understand rather than picking for the
/// user: a typo that silently meant `Auto` could publish an amount they were
/// deliberately trying to keep inside the pool.
#[test]
fn an_unknown_from_value_is_refused_rather_than_guessed() {
    assert_eq!(SpendFrom::parse("auto"), Some(SpendFrom::Auto));
    assert_eq!(SpendFrom::parse("ring"), Some(SpendFrom::Ring));
    assert_eq!(SpendFrom::parse("shielded"), Some(SpendFrom::Shielded));
    assert_eq!(SpendFrom::parse("  SHIELDED "), Some(SpendFrom::Shielded));
    assert_eq!(SpendFrom::parse("zk"), Some(SpendFrom::Shielded));
    assert_eq!(SpendFrom::parse("shiel"), None, "a truncation is not a choice");
    assert_eq!(SpendFrom::parse(""), None);
    assert_eq!(SpendFrom::parse("orchard"), None);
    assert_eq!(SpendFrom::default(), SpendFrom::Auto);
}

/// **A second in-pool send must not reuse an unconfirmed note.**
///
/// The shielded mirror of the ring side's defect: a note is not spent as far as
/// the chain is concerned until its nullifier is published in a block, so a
/// wallet that trusts only the chain picks the same note again. Nullifiers stand
/// in for key images, and the remedy is the same reservation.
#[test]
fn a_second_in_pool_send_does_not_reuse_an_unconfirmed_note() {
    let (mut f, mut alice, mut alice_sh, bob_sh) = funded();
    let filler = address(&Account::random(&mut OsRng));

    // Two notes, so "picked the other one" is distinguishable from "could not
    // build at all". The fixture seeds one; this adds a second.
    let tx = alice
        .build_shielding(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            &alice_sh.address(),
            alice.balance() / 4,
            FEE,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("seeds a second note");
    f.mine(&filler, &[tx], &mut alice, &mut alice_sh);
    f.mine(&filler, &[], &mut alice, &mut alice_sh);
    assert!(alice_sh.spendable().len() >= 2, "two notes to choose between");

    let amount = alice_sh.spendable().last().expect("a note").value() / 2;
    let first = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("builds");
    alice_sh.note_submitted(&first, f.chain.height());

    let second = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("the other note is free, so this must build");

    let a: Vec<_> = first.shielded.as_ref().expect("bundle").nullifiers().collect::<Vec<_>>();
    let b: Vec<_> = second.shielded.as_ref().expect("bundle").nullifiers().collect::<Vec<_>>();
    for n in &a {
        assert!(
            !b.contains(n),
            "the second bundle re-spent a note of the first — this is the bug"
        );
    }
    f.chain.validate_tx(&mut OsRng, &second).expect("and the chain accepts it");
}

/// And that the reservation is what prevents it, not luck in note ordering.
#[test]
fn without_the_reservation_the_same_note_is_picked_again() {
    let (f, alice, alice_sh, bob_sh) = funded();
    let amount = alice_sh.spendable_value() / 8;
    let build = || {
        alice
            .build_send(
                &mut OsRng,
                &f.chain,
                &alice_sh,
                AnyAddress::Shielded(bob_sh.address()),
                amount,
                FEE,
                DEFAULT_RING_SIZE,
                SpendFrom::Shielded,
            )
            .expect("builds")
    };
    let first = build();
    let second = build();
    let a: Vec<_> = first.shielded.as_ref().expect("bundle").nullifiers().collect::<Vec<_>>();
    let b: Vec<_> = second.shielded.as_ref().expect("bundle").nullifiers().collect::<Vec<_>>();
    assert!(
        a.iter().any(|n| b.contains(n)),
        "selection is largest-first, so without a reservation both spend the same note"
    );
}

/// **The pool must be able to account for itself.**
///
/// A payment received into the shielded pool raises the balance and, before this,
/// appeared in no history at all — the ring half has nothing to show, because
/// nothing of the ring was involved. The same for a payment sent inside the pool.
/// The most private shape this chain produces was the one its owner could not
/// reconcile.
#[test]
fn shielded_activity_appears_in_the_shielded_history() {
    let (mut f, mut alice, mut alice_sh, bob_sh) = funded();
    let filler = address(&Account::random(&mut OsRng));

    // The fixture already shielded once, so an arrival must be on record.
    let received: Vec<_> = alice_sh.history().into_iter().filter(|e| e.received).collect();
    assert!(
        !received.is_empty(),
        "a note arrived during setup and the history has to show it"
    );
    let arrived = received.iter().map(|e| e.amount).sum::<u64>();
    assert_eq!(
        arrived,
        alice_sh.balance(),
        "and the arrivals must account for every NOCT the wallet says it holds"
    );

    // Now spend one, inside the pool, and let it confirm.
    let before = alice_sh.history().len();
    let amount = alice_sh.spendable_value() / 4;
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            amount,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("builds");
    assert!(tx.inputs.is_empty(), "no ring side, so the ring history will show nothing");
    f.mine(&filler, &[tx], &mut alice, &mut alice_sh);

    let after = alice_sh.history();
    assert!(
        after.len() > before,
        "spending a note has to appear somewhere, and the ring half is not somewhere"
    );
    let spends: Vec<_> = after.iter().filter(|e| !e.received).collect();
    assert_eq!(spends.len(), 1, "exactly one note left");
    assert_eq!(
        spends[0].height,
        f.chain.height() - 1,
        "dated by the block its nullifier appeared in, not by when the note arrived"
    );

    // Newest first, so a UI can render it without re-sorting.
    let heights: Vec<u64> = after.iter().map(|e| e.height).collect();
    let mut sorted = heights.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(heights, sorted, "history must come back newest first");
}

/// The spend entry needs the height the note *left* at, which is the one thing a
/// shielded history cannot derive from the notes alone. Without `spent_height` it
/// would be dated by when the note arrived — plausible-looking and wrong.
#[test]
fn a_spend_is_dated_by_when_it_was_spent_not_when_it_arrived() {
    let (mut f, mut alice, mut alice_sh, bob_sh) = funded();
    let filler = address(&Account::random(&mut OsRng));

    let arrival = alice_sh
        .history()
        .into_iter()
        .filter(|e| e.received)
        .map(|e| e.height)
        .max()
        .expect("a note arrived");

    // Several blocks between arrival and spend, so the two heights cannot coincide.
    for _ in 0..5 {
        f.mine(&filler, &[], &mut alice, &mut alice_sh);
    }
    let tx = alice
        .build_send(
            &mut OsRng,
            &f.chain,
            &alice_sh,
            AnyAddress::Shielded(bob_sh.address()),
            alice_sh.spendable_value() / 4,
            FEE,
            DEFAULT_RING_SIZE,
            SpendFrom::Shielded,
        )
        .expect("builds");
    f.mine(&filler, &[tx], &mut alice, &mut alice_sh);

    let spend = alice_sh
        .history()
        .into_iter()
        .find(|e| !e.received)
        .expect("the spend is on record");
    assert!(
        spend.height > arrival + 4,
        "spent at {} but the note arrived at {} — a spend dated by arrival is the bug",
        spend.height,
        arrival
    );
}
