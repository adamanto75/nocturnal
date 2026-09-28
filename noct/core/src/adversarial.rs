//! The shielded pool's adversarial pass: the attacks of the design's §13, written
//! as code that runs.
//!
//! Test-only, and kept in one file on purpose. The checklist was written before the
//! implementation existed so it could not be tailored to it, and having the attacks
//! together means the list can be read against the code rather than trusted. Each
//! section names the item it covers, and the last section holds what this pass
//! found that the list did not ask for.
//!
//! **What these are for.** Not to show a valid thing is accepted — the rest of the
//! suite does that — but that a *specific* invalid thing is refused, for the stated
//! reason, and leaves nothing behind. Several of these attacks turn out to be
//! unrepresentable rather than rejected; that is a stronger result and is said so
//! where it happens.

use crate::address::{Address, Network, ShieldedAddress};
use crate::block::{coinbase_sighash, Block, BlockHeader, Coinbase};
use crate::chain::{Blockchain, ChainError};
use crate::emission::base_reward;
use crate::keys::Account;
use crate::pools::{Pool, TurnstileError};
use crate::pow::KeccakPow;
use crate::shielded::tests::{built_bundle_signed, built_coinbase_notes};
use crate::shielded::{ShieldedBundle, ACTION_BYTES};
use crate::shielded_state::{CoinbaseCredit, ShieldedState, ShieldedStateError, ANCHOR_DEPTH};
use rand_core::OsRng;

fn ring_address() -> Address {
    let a = Account::random(&mut OsRng);
    Address::new(Network::Mainnet, a.spend_public, a.view_public)
}

fn shielded_address(seed: u8) -> ShieldedAddress {
    let sk = orchard::keys::SpendingKey::from_bytes([seed; 32]).unwrap();
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    ShieldedAddress::new(Network::Mainnet, fvk.address_at(0u32, orchard::keys::Scope::External))
}

/// A state holding `amount` in `pool`, for attacks about the turnstile.
fn holding(pool: Pool, amount: u64) -> ShieldedState {
    let mut s = ShieldedState::new();
    s.credit_for_test(pool, amount);
    s
}

fn ring_block(chain: &Blockchain<KeccakPow>, miner: &Address, ts: u64) -> Block {
    let reward = base_reward(chain.emitted());
    let mut block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: crate::block::GENESIS_TIMESTAMP + ts,
            prev_id: chain.tip_id(),
            nonce: 0,
        },
        coinbase: Coinbase::create(&mut OsRng, chain.height(), miner, reward),
        tx_hashes: Vec::new(),
    };
    block.mine(&KeccakPow, chain.next_difficulty());
    block
}

/// A chain with `n` ring-coinbase blocks on top of genesis.
fn chain_with(n: usize) -> Blockchain<KeccakPow> {
    let mut chain = Blockchain::with_maturity(KeccakPow, 5);
    let miner = ring_address();
    for i in 0..n {
        let block = ring_block(&chain, &miner, 1_000 + (i as u64) * 130);
        chain.add_block(&mut OsRng, &block, &[]).expect("a valid ring block");
    }
    chain
}

// --- §13: a proof padded with trailing data, and an identity `epk` -----------
//
// The padded proof is covered by `shielded::wire_tests::
// a_proof_padded_with_extra_bytes_cannot_be_expressed`: the proof's length is
// derived from the action count, so padding has nowhere to go. This is the other
// half.

/// **An identity `epk` is refused at the boundary.**
///
/// An action's ephemeral public key is a curve point the recipient needs in order
/// to decrypt, and it sits *outside* the proof — so the circuit does not catch a
/// useless one. `orchard`'s `Action::from_parts` rejects the identity point, and
/// the wire decoder goes through that constructor rather than
/// `from_parts_unchecked`. This pins that choice: switching to the unchecked
/// constructor would compile, pass every other test, and admit this.
#[test]
fn an_identity_epk_is_refused() {
    let honest =
        ShieldedBundle::new(built_bundle_signed(5_000, false, [1u8; 32])).expect("fixed circuit");

    // `epk` sits inside the first action, after cv_net, nullifier, rk and cmx.
    let epk_at = 2 + 32 * 4;
    let mut attacked = honest.to_bytes();
    attacked[epk_at..epk_at + 32].copy_from_slice(&[0u8; 32]);
    // The exact error matters: `Refused` is the crate rejecting the assembled
    // action. Anything else would mean this decoded for some unrelated reason and
    // the test was measuring nothing.
    assert_eq!(
        ShieldedBundle::from_bytes(&attacked).unwrap_err(),
        crate::shielded::BundleWireError::Refused,
        "an identity epk must be refused by the action constructor"
    );

    // The buffer is otherwise fine: the same kind of edit to a byte the decoder
    // does not inspect still decodes. So the refusal above is about `epk` and not
    // about having touched the bytes at all.
    let mut elsewhere = honest.to_bytes();
    elsewhere[2 + 32 * 5 + 100] ^= 0xff;
    assert!(
        ShieldedBundle::from_bytes(&elsewhere).is_ok(),
        "a ciphertext byte is not the decoder's business, so this must still decode"
    );
}

// --- §13: a bundle using the yanked circuit, or `orchard_insecure_v1` --------

/// **Another circuit is not rejected; it is unrepresentable.**
///
/// Every `orchard` release up to 0.13.1 is yanked because the original Action
/// circuit was unsound, and `orchard_insecure_v1` still exists in the crate. The
/// wire format carries no circuit field: the decoder supplies this chain's version
/// itself, so there is nothing for a sender to name.
///
/// Worth a test rather than a comment, because the natural way to write that
/// decoder — read a version from the bytes, then check it — would have been a
/// rejection instead of an impossibility, and rejections can be forgotten.
#[test]
fn a_bundle_cannot_name_another_circuit() {
    let honest =
        ShieldedBundle::new(built_bundle_signed(5_000, false, [1u8; 32])).expect("fixed circuit");
    let bytes = honest.to_bytes();

    // Every byte is accounted for by a field whose size the action count fixes, so
    // there is no room left to name a circuit in.
    let expected = 2
        + honest.actions() * ACTION_BYTES
        + 1
        + 8
        + 32
        + orchard::circuit::Proof::expected_proof_size(honest.actions())
        + 64;
    assert_eq!(bytes.len(), expected);

    // And what comes back is this chain's circuit, whatever the sender intended.
    let back = ShieldedBundle::from_bytes(&bytes).expect("decodes");
    assert_eq!(back.circuit(), crate::shielded::CIRCUIT);
}

// --- §13: the same nullifier twice -----------------------------------------
//
// Covered, both within one block and across two, by
// `shielded_state::tests::a_nullifier_cannot_be_spent_twice`. Not repeated here.

// --- §13: turnstile underflow, in one transaction and across a block --------

/// **A block cannot move more value than a pool holds, however it is split up.**
///
/// One transaction taking too much is the obvious attack and the easy one to stop.
/// The one worth a test is several transactions that are each affordable and
/// together are not: the check has to be against a running total for the block, not
/// against the total as it stood before it.
#[test]
fn the_turnstile_cannot_be_drained_by_splitting_the_movement() {
    let a = ShieldedBundle::new(built_bundle_signed(4_000, false, [2u8; 32])).unwrap();
    let b = ShieldedBundle::new(built_bundle_signed(4_000, false, [3u8; 32])).unwrap();

    // Each bundle moves 4,000 out of the ring pool. One is affordable against
    // 6,000.
    let mut single = holding(Pool::Ring, 6_000);
    single.apply_block([&a], CoinbaseCredit::none(), 0, 1).expect("4,000 is affordable");
    assert_eq!(single.totals().ring(), 2_000);
    assert_eq!(single.totals().shielded(), 4_000);

    // Two in one block are not, and the refusal leaves the state exactly as it was.
    let mut both = holding(Pool::Ring, 6_000);
    let before = both.totals();
    let root_before = both.root();
    let err = both
        .apply_block([&a, &b], CoinbaseCredit::none(), 0, 1)
        .expect_err("8,000 cannot leave a pool holding 6,000");
    assert!(matches!(err, ShieldedStateError::Turnstile(TurnstileError::Underflow { .. })));
    assert_eq!(both.totals(), before, "the refused block changed no total");
    assert_eq!(both.root(), root_before, "and appended no note");
    assert!(!both.is_spent(&a.nullifiers().next().unwrap()), "and spent no nullifier");

    // The same overdraft in one transaction, for completeness: an empty pool.
    let mut empty = ShieldedState::new();
    let err = empty
        .apply_block([&a], CoinbaseCredit::none(), 0, 1)
        .expect_err("nothing can leave an empty pool");
    assert!(matches!(err, ShieldedStateError::Turnstile(TurnstileError::Underflow { .. })));
    assert_eq!(empty.totals(), Default::default());
}

// --- §13: a stale anchor, one from an abandoned branch, one past the window ---

/// **An anchor from a branch the chain abandoned is not an anchor.**
///
/// The anchor history is truncated on rollback, so a root that existed only on the
/// losing side of a reorg is gone. That matters more than a merely old anchor: a
/// stale one was at least real, while this one describes a tree that never happened
/// on the chain that survived. A node that kept it would accept proofs of
/// membership in a tree the rest of the network never had.
#[test]
fn an_anchor_from_an_abandoned_branch_is_refused() {
    let mut s = holding(Pool::Ring, 100_000);
    let anchors_before: Vec<[u8; 32]> = s.accepted_anchors_for_test();

    let doomed = ShieldedBundle::new(built_bundle_signed(1_000, false, [4u8; 32])).unwrap();
    let undo = s.apply_block([&doomed], CoinbaseCredit::none(), 0, 1).expect("applies");
    let branch_root = s.root();
    assert!(s.accepts_anchor(&branch_root), "it was an anchor while the branch stood");

    s.undo_block(undo);
    assert!(
        !s.accepts_anchor(&branch_root),
        "a root that existed only on the abandoned branch must not be accepted"
    );
    assert_eq!(
        s.accepted_anchors_for_test(),
        anchors_before,
        "and the anchor set is exactly what it was before the branch"
    );
}

/// **The anchor window is exact at both edges.**
///
/// Off by one here is the difference between refusing valid transactions and
/// accepting proofs against trees older than the deepest reorg the chain will undo,
/// so both sides of the boundary are asserted rather than just one, and both through
/// `apply_block` rather than through the predicate alone.
///
/// The roots have to be *distinct* for the boundary to be observable at all: a run
/// of empty blocks republishes the same root, so ageing one out of the window
/// changes nothing anyone can see. That is why a note is appended first — and it is
/// the reason a test that used only empty blocks would have passed while measuring
/// nothing.
#[test]
fn the_anchor_window_is_exact_at_both_edges() {
    let mut s = holding(Pool::Ring, 1_000_000);
    let empty_root = s.root();

    // One real note, so the empty-tree root becomes a distinct older entry.
    let first = ShieldedBundle::new(built_bundle_signed(1_000, false, [11u8; 32])).unwrap();
    s.apply_block([&first], CoinbaseCredit::none(), 0, 1).expect("applies");
    assert_ne!(s.root(), empty_root);
    assert_eq!(s.accepted_anchors_for_test().len(), 2);

    // Fill the window to exactly `ANCHOR_DEPTH`, with the empty-tree root as its
    // oldest member.
    for h in 0..ANCHOR_DEPTH as u64 - 2 {
        s.apply_block(std::iter::empty(), CoinbaseCredit::none(), h, 1).expect("an empty block");
    }
    assert_eq!(s.accepted_anchors_for_test().len(), ANCHOR_DEPTH);
    assert!(s.accepts_anchor(&empty_root), "the oldest root is still inside the window");
    // And usable, not merely present: the test bundles all anchor to the empty tree.
    let inside = ShieldedBundle::new(built_bundle_signed(1_000, false, [12u8; 32])).unwrap();
    assert_eq!(inside.anchor(), empty_root);
    s.apply_block([&inside], CoinbaseCredit::none(), 0, 1).expect("the last block it is valid on");

    // One block past the edge. The note just appended pushed a new root in, so the
    // window now holds `ANCHOR_DEPTH` roots ending at that one.
    assert!(!s.accepts_anchor(&empty_root), "and one block later the oldest is gone");
    let outside = ShieldedBundle::new(built_bundle_signed(1_000, false, [13u8; 32])).unwrap();
    assert_eq!(
        s.apply_block([&outside], CoinbaseCredit::none(), 0, 1).unwrap_err(),
        ShieldedStateError::UnknownAnchor(empty_root),
        "a spend against a root past the window must be refused by apply_block itself"
    );
    assert_eq!(
        s.accepted_anchors_for_test().len(),
        ANCHOR_DEPTH,
        "and the window never grows past its depth"
    );
}

// --- §13: a coinbase note spent before it matures ---------------------------

/// **A coinbase note is in no anchor until it matures.**
///
/// This is the whole of the delayed-insertion design, stated as the attack it
/// exists to stop. There is nothing to check at spend time — an Orchard spend names
/// nothing a validator could age — so the defence has to be that the note is in no
/// tree whose root the chain will accept. The note exists and the supply counts it;
/// every anchor published during the window excludes it.
#[test]
fn a_coinbase_note_is_in_no_anchor_until_it_matures() {
    let maturity = 10u64;
    let mut s = ShieldedState::new();
    let reward = 9_000_000_000u64;
    let bundle = ShieldedBundle::new(built_coinbase_notes(&[reward], [0u8; 32])).unwrap();
    let note = bundle.commitments().next().unwrap().to_bytes();

    let empty_root = s.root();
    s.apply_block(std::iter::empty(), CoinbaseCredit::shielded(reward, 0, note), 0, maturity)
        .expect("the reward mints");
    assert_eq!(s.totals().shielded(), reward, "minted: the supply has it");

    // Withheld until it is due. Queued at height 0, a note is due on the block
    // where `height + 1 >= queued_at + maturity` — so the last block that must not
    // contain it is `maturity - 2`, and `maturity - 1` is the block it enters on.
    // Spelling that out rather than looping to `maturity` is the difference between
    // testing the boundary and testing one block past it.
    for h in 1..maturity - 1 {
        assert_eq!(s.root(), empty_root, "the tree must not move at height {h}");
        s.apply_block(std::iter::empty(), CoinbaseCredit::none(), h, maturity)
            .expect("an empty block");
    }
    assert_eq!(s.root(), empty_root, "still withheld on the last block of the window");
    assert!(
        s.accepted_anchors_for_test().iter().all(|a| *a == empty_root),
        "so no anchor published during the window contains the note"
    );

    // And on the block it is due, it enters — this was a delay, not a loss.
    s.apply_block(std::iter::empty(), CoinbaseCredit::none(), maturity - 1, maturity)
        .expect("the block it is due on");
    assert_ne!(s.root(), empty_root, "and then it is in the tree");
}

// --- §13: a reorg that crosses the pool boundary ----------------------------

/// **A reorg that abandons a crossing leaves a state byte-identical to one that
/// never saw it.**
///
/// The only statement of the rollback property that matters: a tree that is merely
/// self-consistent after a reorg still forks the network. Two states are built from
/// the same start — one that accepts a block carrying a crossing and then reorgs it
/// away, one that never sees it — and their roots, totals, note counts and anchor
/// sets are compared. Then both go forward the same way, so the equality is not
/// just a snapshot.
#[test]
fn a_reorg_across_the_pool_boundary_leaves_no_trace() {
    let mut reorged = holding(Pool::Ring, 500_000);
    let start_totals = reorged.totals();
    let start_root = reorged.root();

    let crossing = ShieldedBundle::new(built_bundle_signed(70_000, false, [7u8; 32])).unwrap();
    let undo = reorged
        .apply_block([&crossing], CoinbaseCredit::ring(0, 0), 0, 1)
        .expect("the crossing applies");
    assert_ne!(reorged.root(), start_root, "the note entered the tree");
    assert_eq!(reorged.totals().shielded(), 70_000, "and value crossed");

    reorged.undo_block(undo);

    let mut clean = holding(Pool::Ring, 500_000);
    assert_eq!(reorged.root(), clean.root(), "the roots must be byte-identical");
    assert_eq!(reorged.totals(), start_totals, "the supply is back where it was");
    assert_eq!(reorged.notes(), clean.notes(), "the note is out of the tree");
    assert_eq!(reorged.accepted_anchors_for_test(), clean.accepted_anchors_for_test());
    assert!(
        !reorged.is_spent(&crossing.nullifiers().next().unwrap()),
        "and the nullifier it published is spendable again"
    );

    let next = ShieldedBundle::new(built_bundle_signed(1_000, false, [8u8; 32])).unwrap();
    reorged.apply_block([&next], CoinbaseCredit::ring(0, 0), 1, 1).expect("applies");
    clean.apply_block([&next], CoinbaseCredit::ring(0, 0), 1, 1).expect("applies");
    assert_eq!(reorged.root(), clean.root(), "and they stay identical afterwards");
    assert_eq!(reorged.totals(), clean.totals());
}

// --- §13: a v2 transaction presented to a v1 node ---------------------------

/// **An unknown transaction version is refused outright, not parsed in part.**
///
/// A literal "v1 node" is a build without this code and cannot be instantiated
/// here. What is testable is the property that makes this a hard fork rather than a
/// silent split: the version is an allow-list, so a node refuses one it does not
/// implement instead of reading the fields it recognises. A node that ignored the
/// bundle would see a ring side that does not balance, and could be convinced value
/// had appeared from nowhere.
#[test]
fn an_unknown_transaction_version_is_refused_outright() {
    let (tx, _) = crate::tx::tests::sample_tx();

    let mut future = tx.clone();
    future.version = 3;
    assert_eq!(
        future.verify(&mut OsRng),
        Err(crate::tx::TxError::BadVersion),
        "an unknown version is refused before any of its fields are trusted"
    );

    // On the wire the version is the first byte, and an unknown one is refused
    // before any field after it is decoded — so nothing about the transaction's
    // shape is even assumed.
    let mut bytes = crate::wire::encode_transaction(&tx);
    bytes[0] = 3;
    assert!(matches!(
        crate::wire::decode_transaction(&bytes),
        Err(crate::wire::WireError::BadTag)
    ));
}

// --- beyond the checklist ---------------------------------------------------

/// **A reward split across two notes must be refused.**
///
/// Found by this pass, not by the checklist, and it was a real hole.
/// `Coinbase::credit` queues **one** note — the first — while `Coinbase::total`
/// counts the bundle's whole value balance. So a two-note shielded coinbase minted
/// the full reward into the supply and delivered only the first note into the tree:
/// the rest was counted as emitted and could never be spent by anybody. Silent
/// value destruction, and a supply that disagrees with the tree about what exists.
///
/// The fix is a consensus rule rather than more bookkeeping: a shielded reward is
/// **exactly one note**. It costs a miner nothing, because a coinbase's amount is
/// public anyway and there is no padding to buy, and it makes the single-note
/// pending queue correct by construction instead of by luck.
#[test]
fn a_shielded_reward_must_be_exactly_one_note() {
    let reward = base_reward(0);
    let half = reward / 2;
    let prev_id = [9u8; 32];
    let sighash = coinbase_sighash(7, &prev_id);

    let one = ShieldedBundle::new(built_coinbase_notes(&[reward], sighash)).unwrap();
    let two = ShieldedBundle::new(built_coinbase_notes(&[half, reward - half], sighash)).unwrap();
    assert_eq!(one.actions(), 1);
    assert_eq!(two.actions(), 2, "the split reward really is two notes");
    // Both are worth the whole reward, so the amount check alone cannot tell them
    // apart — which is exactly why the hole was invisible.
    assert_eq!(one.cross(), Ok(reward as i64));
    assert_eq!(two.cross(), Ok(reward as i64));

    let single = Coinbase {
        height: 7,
        tx_public: crate::stealth::TxKeypair::random(&mut OsRng).public,
        outputs: Vec::new(),
        shielded: Some(one),
    };
    let split = Coinbase { shielded: Some(two), ..single.clone() };

    assert!(single.is_valid(reward, &prev_id), "one note is the shape");
    assert!(
        !split.is_valid(reward, &prev_id),
        "a split reward must be refused: only the first note would reach the tree"
    );
}

/// **The root a block creates is not an anchor that block may use.**
///
/// Not on the checklist, and correct by accident until somebody reorders two lines.
/// If the anchor were checked against the state *after* this block's appends, a
/// transaction could prove membership for a note created in the same block — and
/// that note is one no other node had seen when it validated the block, so whether
/// it was accepted would depend on ordering.
#[test]
fn the_root_a_block_creates_is_not_an_anchor_for_that_block() {
    let mut s = holding(Pool::Ring, 100_000);
    let anchors_during = s.accepted_anchors_for_test();

    let b = ShieldedBundle::new(built_bundle_signed(1_000, false, [10u8; 32])).unwrap();
    s.apply_block([&b], CoinbaseCredit::none(), 0, 1).expect("applies");
    let created = s.root();

    assert!(
        !anchors_during.contains(&created),
        "the root this block produced was not in the set it was allowed to prove against"
    );
    assert!(s.accepts_anchor(&created), "though it is an anchor for every later block");
}

/// **A mined shielded reward cannot be replayed into another block.**
///
/// The replay this stops: lifting an authorized coinbase bundle out of its block
/// and into another claiming the same reward. The same note commitment would then be
/// appended to the tree twice, giving two leaves one nullifier, so the wallet
/// holding it could spend only one of them.
///
/// Mined and submitted through `add_block`, so the refusal is consensus rather than
/// a shape check restated here.
#[test]
fn a_mined_shielded_reward_cannot_be_replayed_into_another_block() {
    let mut chain = chain_with(2);
    let miner = shielded_address(21);
    let reward = base_reward(chain.emitted());
    let coinbase = Coinbase::create_shielded(
        &mut OsRng,
        chain.height(),
        &chain.tip_id(),
        &miner,
        reward,
    )
    .expect("builds");
    let mut block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: crate::block::GENESIS_TIMESTAMP + 1_000 + 2 * 130,
            prev_id: chain.tip_id(),
            nonce: 0,
        },
        coinbase,
        tx_hashes: Vec::new(),
    };
    block.mine(&KeccakPow, chain.next_difficulty());
    assert!(block.coinbase.is_valid(reward, &chain.tip_id()), "valid where it was built");
    chain.add_block(&mut OsRng, &block, &[]).expect("accepted");

    // Lift it onto the next block: same bundle, new parent. The height is corrected
    // so a cheaper check does not refuse it first — the only thing wrong with this
    // block is the coinbase's signatures.
    let mut replay = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: crate::block::GENESIS_TIMESTAMP + 1_000 + 3 * 130,
            prev_id: chain.tip_id(),
            nonce: 0,
        },
        coinbase: Coinbase { height: chain.height(), ..block.coinbase.clone() },
        tx_hashes: Vec::new(),
    };
    replay.mine(&KeccakPow, chain.next_difficulty());
    assert_eq!(
        chain.add_block(&mut OsRng, &replay, &[]),
        Err(ChainError::BadCoinbaseReward),
        "a reward bound to one block must not be valid in another"
    );
}
