//! **Can the genesis premine actually reach the shielded pool?**
//!
//! The premine is a transparent ring output in genesis, and it stays one. The
//! alternative — minting it as an Orchard note inside genesis — was considered
//! and rejected: genesis must be byte-identical on every node, so the bundle
//! would have to be a baked constant blob that could never be corrected, and at
//! genesis the shielded pool holds exactly one note, so spending it identifies
//! it as the premine anyway. The privacy only arrives as the pool grows, which is
//! equally true if the founder simply shields it afterwards.
//!
//! That decision rests entirely on one claim: **the founder can move the premine
//! into the shielded pool with an ordinary transaction.** If that were not true,
//! leaving genesis alone would have quietly closed the door. So it is asserted
//! here, against the real genesis, under the real `COINBASE_MATURITY`, through
//! the same builder a wallet uses.
//!
//! It runs on **testnet**, whose premine seed is published in `docs/TESTNET.md`
//! precisely because that wallet holds nothing. The mainnet founder key is not
//! here and must never be. Both networks share one genesis construction and one
//! premine mechanism, differing only in constants, so what holds for one holds
//! for the other.

use noct_core::address::{Address, Network};
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::Blockchain;
use noct_core::emission::base_reward;
use noct_core::keys::Account;
use noct_core::params::TESTNET;
use noct_core::pow::KeccakPow;
use noct_core::shielded_state::ShieldedState;
use noct_core::tx::Transaction;
use noct_wallet::shielded::{ShieldedKeys, ShieldedWallet};
use noct_wallet::{Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

/// The published testnet faucet phrase — worthless by design, and the reason
/// this test can open a real genesis premine at all.
const FAUCET_PHRASE: &str = "solve leave enact inform twin bleak picture swarm slim animal \
    spell evidence memory share index lemon soft drama hire utility scorpion tool expand digital";

fn address(a: &Account) -> Address {
    Address::new(Network::Testnet, a.spend_public, a.view_public)
}

/// Mine one block on the testnet chain, handing it to both halves of the wallet
/// in the order the chain saw it.
fn mine(
    chain: &mut Blockchain<KeccakPow>,
    ts: &mut u64,
    miner: &Address,
    txs: &[Transaction],
    ring: &mut Wallet,
    shielded: &mut ShieldedWallet,
) {
    let subsidy = base_reward(chain.emitted());
    let fees: u64 = txs.iter().map(|t| t.fee).sum();
    let coinbase = Coinbase::create(&mut OsRng, chain.height(), miner, subsidy + fees);
    let mut block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: TESTNET.genesis_timestamp + *ts,
            prev_id: chain.tip_id(),
            nonce: 0,
        },
        coinbase,
        tx_hashes: txs.iter().map(|t| t.hash()).collect(),
    };
    block.mine(&KeccakPow, chain.next_difficulty());
    // Captured before the chain moves on: the pre-block state is what decides
    // leaf order, so the wallet checks its own tree against the chain's.
    let before: ShieldedState = chain.shielded().clone();
    chain.add_block(&mut OsRng, &block, txs).expect("a valid block");
    *ts += 130;
    ring.scan_block(&block, txs);
    shielded
        .scan_block(&block, txs, &before, chain.shielded(), noct_core::chain::COINBASE_MATURITY)
        .expect("the wallet's tree must agree with the chain's");
}

#[test]
fn the_genesis_premine_can_be_moved_into_the_shielded_pool() {
    // The real testnet chain, with the real maturity depth. Not `with_maturity`:
    // a shortened window would prove the premine is spendable under a rule the
    // network does not use, which is the one thing this must not do.
    let mut chain = Blockchain::for_network(Network::Testnet, KeccakPow);
    let maturity = noct_core::chain::COINBASE_MATURITY;
    assert_eq!(maturity, 100, "if this changed, the mining below must too");

    let secret = noct_wallet::mnemonic::from_phrase(FAUCET_PHRASE).expect("published phrase");
    let account = noct_wallet::client::load_account(&hex::encode(secret)).expect("loads");
    let mut founder = Wallet::new(account, Network::Testnet);
    let mut founder_sh = ShieldedWallet::new(
        ShieldedKeys::for_account(&account, Network::Testnet).expect("derives"),
    );

    // Scanning genesis is how the founder finds the premine in the first place.
    founder.scan_block(&Block::genesis_for(&TESTNET), &[]);
    assert_eq!(
        founder.balance(),
        TESTNET.premine_amount,
        "the published phrase must open the testnet genesis premine"
    );
    assert_eq!(
        chain.shielded().totals().shielded(),
        0,
        "and the shielded pool starts empty, which is the premise of this test"
    );

    // Enough blocks that the premine is mature AND there are 16 mature outputs
    // to build a ring from. Both are consequences of the real maturity rule.
    let mut ts = 1_000u64;
    let filler = address(&Account::random(&mut OsRng));
    for _ in 0..(maturity + 20) {
        mine(&mut chain, &mut ts, &filler, &[], &mut founder, &mut founder_sh);
    }

    // Every other block above paid `filler`, so the founder owns exactly one
    // output and it is the premine. Without this the test could pass while
    // shielding something else entirely, and prove nothing about the premine.
    assert_eq!(founder.unspent().count(), 1, "the premine is the only output in play");
    assert_eq!(
        founder.unspent().next().expect("one output").amount(),
        TESTNET.premine_amount,
        "and it is the premine itself"
    );

    // The move itself: an ordinary shielding transaction, built by the ordinary
    // wallet path, spending the premine output.
    let amount = TESTNET.premine_amount / 4;
    let fee = noct_core::mempool::min_fee(3_000);
    let tx = founder
        .build_shielding(
            &mut OsRng,
            &chain,
            &founder_sh,
            &founder_sh.address(),
            amount,
            fee,
            DEFAULT_RING_SIZE,
            true,
        )
        .expect("the founder can shield the premine");
    assert_eq!(tx.cross, amount as i64, "exactly the payment leaves the ring pool");
    chain.validate_tx(&mut OsRng, &tx).expect("and the chain accepts it");

    let emitted_before = chain.emitted();
    mine(&mut chain, &mut ts, &filler, &[tx], &mut founder, &mut founder_sh);

    // The turnstile is the whole argument for two pools: value moved between
    // them and none was created or destroyed doing it.
    let totals = chain.shielded().totals();
    assert_eq!(totals.shielded(), amount, "the premine's value is in the shielded pool");
    assert_eq!(
        totals.total(),
        Some(chain.emitted()),
        "ring + shielded == emitted, across the crossing"
    );
    assert!(chain.emitted() > emitted_before, "the block's own subsidy was minted too");

    // A shielding's output is not a coinbase, so it enters the tree at once and
    // becomes spendable as soon as an anchor contains it.
    mine(&mut chain, &mut ts, &filler, &[], &mut founder, &mut founder_sh);
    assert_eq!(founder_sh.balance(), amount, "and the founder can see it");
    assert_eq!(
        founder_sh.spendable_value(),
        amount,
        "and spend it — which is what makes leaving genesis alone a real option"
    );

    // What was left behind on the ring side is the premine less what crossed and
    // the fee. Nothing vanished.
    assert_eq!(
        founder.balance() + amount + fee,
        TESTNET.premine_amount,
        "the ring side kept exactly the remainder"
    );
}
