//! End-to-end walkthrough of layers 1–7: mine a coinbase, then move the money
//! privately through RingCT transactions.
//!
//! Run with: `cargo run --example demo`

use curve25519_dalek::scalar::Scalar;
use noct_core::address::{Address, Network};
use noct_core::amounts::Opening;
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::emission::{base_reward, ATOMIC_UNITS};
use noct_core::keys::{Account, PrivateKey};
use noct_core::pow::KeccakPow;
use noct_core::ring::RingMember;
use noct_core::stealth::TxKeypair;
use noct_core::tx::{Payment, Transaction};
use rand_core::OsRng;

fn address_of(acct: &Account) -> Address {
    Address::new(Network::Mainnet, acct.spend_public, acct.view_public)
}

// A ring of random decoys; the real member is filled in by `to_input`.
fn decoy_ring(size: usize) -> Vec<RingMember> {
    (0..size)
        .map(|_| {
            let key = PrivateKey(Scalar::random(&mut OsRng)).public_key();
            RingMember::new(key, Opening::random(1_000, &mut OsRng).commit())
        })
        .collect()
}

fn main() {
    let alice = Account::random(&mut OsRng);
    let bob = Account::random(&mut OsRng);
    println!("alice: {}", address_of(&alice).encode());
    println!("bob:   {}\n", address_of(&bob).encode());

    // --- Layer 7: mine a block whose coinbase pays Alice --------------------
    let reward = base_reward(0);
    let coinbase = Coinbase::create(&mut OsRng, 0, &address_of(&alice), reward);
    let mut block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000,
            prev_id: [0u8; 32],
            nonce: 0,
        },
        coinbase,
        tx_hashes: vec![],
    };
    let pow = KeccakPow;
    let difficulty = 4_000;
    let nonce = block.mine(&pow, difficulty);
    assert!(block.meets_difficulty(&pow, difficulty));
    println!(
        "mined block 0: reward {} atomic to Alice, nonce {}, id {}… ✓",
        reward,
        nonce,
        hex::encode(&block.id()[..8])
    );

    // Alice recovers her coinbase output (opening mask = 1).
    let coinbase_output = block.coinbase.scan(&alice).expect("coinbase is Alice's");
    println!("Alice scanned coinbase: {} atomic ✓", coinbase_output.amount);

    // --- Layer 6: Alice spends the coinbase → pays Bob, keeps change --------
    // Per-block rewards are sub-NOCT under the 1M supply, so amounts here are
    // fractions of the coinbase.
    let fee = ATOMIC_UNITS / 100; // 0.01 NOCT
    let to_bob = reward / 2; // half the coinbase to Bob
    let change = reward - to_bob - fee;
    let tx = Transaction::build(
        &mut OsRng,
        &[coinbase_output.to_input(decoy_ring(11), 5)],
        &[
            Payment { destination: address_of(&bob), amount: to_bob },
            Payment { destination: address_of(&alice), amount: change }, // change back to Alice
        ],
        fee,
        &TxKeypair::random(&mut OsRng),
    )
    .unwrap();
    assert!(tx.verify(&mut OsRng).is_ok());
    println!(
        "TX built & verified: Alice → Bob {} atomic, {} atomic change, fee {} atomic ✓",
        to_bob, change, fee
    );

    // The published key image links this spend to the coinbase output.
    assert_eq!(tx.inputs[0].key_image(), coinbase_output.key_image);
    println!(
        "key image {}… published — double-spend would be rejected ✓",
        hex::encode(&tx.inputs[0].key_image().to_bytes()[..8])
    );

    // --- Recipients scan; amounts stay hidden from everyone else ------------
    let bob_got = tx.scan(&bob);
    let alice_got = tx.scan(&alice);
    assert_eq!(bob_got[0].amount, to_bob);
    assert_eq!(alice_got[0].amount, change);
    println!(
        "Bob scanned: {} atomic · Alice scanned change: {} atomic ✓",
        bob_got[0].amount, alice_got[0].amount
    );

    println!("\nall layers OK");
}
