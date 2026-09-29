//! **Can the wallet afford its own floor?**
//!
//! `MIN_FEE_PER_KB` is a number chosen against measurements, and measurements
//! go stale. A change that makes transactions bigger — a larger ring, another
//! Orchard action, a new field — or a change that raises the floor, could price
//! out the transactions this software itself builds, and the symptom would not
//! be a failing test. It would be the fleet quietly ceasing to relay: bots whose
//! sends vanish, a pool whose payouts are refused every round.
//!
//! So this builds one of every shape that exists — ring, pool payout, shielding,
//! shielded-only, unshielding — at the CLI's default fee, and asserts each clears
//! the floor with room. It prints the margins, because the number that matters
//! when this eventually fails is *how much* room was left, not merely that some
//! was.

use noct_core::address::{Address, AnyAddress, Network};
use noct_core::block::{Block, BlockHeader, Coinbase};
use noct_core::chain::Blockchain;
use noct_core::emission::base_reward;
use noct_core::keys::Account;
use noct_core::pow::KeccakPow;
use noct_core::shielded_state::ShieldedState;
use noct_core::tx::{Payment, Transaction};
use noct_wallet::shielded::{ShieldedKeys, ShieldedWallet};
use noct_wallet::{Wallet, DEFAULT_RING_SIZE};
use rand_core::OsRng;

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

    fn mine(
        &mut self,
        miner: &Address,
        txs: &[Transaction],
        ring: &mut [&mut Wallet],
        shielded: &mut [&mut ShieldedWallet],
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
        for w in ring.iter_mut() {
            w.scan_block(&block, txs);
        }
        for w in shielded.iter_mut() {
            w.scan_block(&block, txs, &before, self.chain.shielded(), MATURITY).expect("agrees");
        }
    }

    fn warm_up(&mut self, n: usize, ring: &mut [&mut Wallet], shielded: &mut [&mut ShieldedWallet]) {
        let filler = address(&Account::random(&mut OsRng));
        for _ in 0..n {
            self.mine(&filler, &[], ring, shielded);
        }
    }
}

/// The fee the CLI sends by default. Everything the fleet runs today pays this.
const DEFAULT_FEE: u64 = 10_000_000_000; // 0.01 NOCT

/// The smallest margin any shape is allowed to have over the floor.
///
/// Three, not one. A floor a transaction clears by a hair is a floor that the
/// next added field breaks, and the breakage shows up in production rather than
/// here. The binding case is the eight-recipient shielded payout, which clears
/// by about six; three means transactions could double in size before anyone
/// has to think about this again, and that they cannot triple without being
/// told.
const MIN_MARGIN: f64 = 3.0;

fn check(label: &str, tx: &Transaction) {
    let size = noct_core::wire::encode_transaction(tx).len();
    let actions = tx.shielded.as_ref().map(|b| b.actions()).unwrap_or(0);
    let required = noct_core::mempool::min_fee(size);
    let margin = tx.fee as f64 / required as f64;
    println!(
        "{label:<34} size={size:>6} actions={actions}  needs={required:>12}  pays={:>12}  margin={margin:>5.1}x",
        tx.fee
    );
    assert!(
        tx.fee >= required,
        "{label}: the wallet's own transaction cannot pay the wallet's own floor          ({size} bytes needs {required}, the default fee is {})",
        tx.fee
    );
    assert!(
        margin >= MIN_MARGIN,
        "{label}: only {margin:.1}x over the floor ({size} bytes needs {required}).          Either transactions grew or MIN_FEE_PER_KB rose; re-measure before shipping it."
    );
}

#[test]
fn every_transaction_the_wallet_builds_clears_the_relay_floor() {
    let mut f = Fixture::new();
    let alice_account = Account::random(&mut OsRng);
    let mut alice = Wallet::new(alice_account, Network::Mainnet);
    alice.scan_block(&Block::genesis(), &[]);
    let alice_addr = alice.address();
    let mut alice_sh = ShieldedWallet::new(
        ShieldedKeys::from_spend_secret(&[1u8; 32], 0, Network::Mainnet).unwrap(),
    );
    let mut bob_sh = ShieldedWallet::new(
        ShieldedKeys::from_spend_secret(&[2u8; 32], 0, Network::Mainnet).unwrap(),
    );

    for _ in 0..4 {
        f.mine(&alice_addr, &[], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    }
    f.warm_up(24, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);

    let fee = DEFAULT_FEE;
    let carol = address(&Account::random(&mut OsRng));

    // 1. plain ring payment, 1 recipient + change
    let t = alice
        .build_transaction(&mut OsRng, &f.chain, &[Payment { destination: carol, amount: 1_000 }], fee, DEFAULT_RING_SIZE)
        .expect("builds");
    check("ring 1-recipient", &t);

    // 2. pool payout shape: 8 recipients + change
    let many: Vec<Payment> = (0..8)
        .map(|_| Payment { destination: address(&Account::random(&mut OsRng)), amount: 1_000 })
        .collect();
    let t = alice
        .build_transaction(&mut OsRng, &f.chain, &many, fee, DEFAULT_RING_SIZE)
        .expect("builds");
    check("ring 8-recipient (pool payout)", &t);

    // 3. the pool's worst case: 8 shielded recipients in one payout, which is
    //    8 Orchard output actions plus a ring side to fund them. `MAX_PAYOUTS_PER_TX`
    //    in noct-poold is 8, so this is the largest transaction the fleet builds
    //    — and the one whose failure would look like "the pool stopped paying".
    let shielded_payees: Vec<(AnyAddress, u64)> = (0..8)
        .map(|i| {
            let keys =
                ShieldedKeys::from_spend_secret(&[100 + i as u8; 32], 0, Network::Mainnet).unwrap();
            (AnyAddress::Shielded(keys.address()), 1_000_000_000u64)
        })
        .collect();
    let t = alice
        .build_payout(&mut OsRng, &f.chain, &alice_sh, &shielded_payees, fee, DEFAULT_RING_SIZE)
        .expect("builds");
    check("payout, 8 shielded recipients", &t);

    // 4. shielding
    let shield = alice
        .build_shielding(&mut OsRng, &f.chain, &alice_sh, &alice_sh.address(), 500_000_000_000, fee, DEFAULT_RING_SIZE, true)
        .expect("builds");
    check("shielding (ring -> pool)", &shield);

    f.mine(&carol, &[shield], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    f.warm_up(1, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);

    // 5. shielded-only transfer
    let plan = alice_sh
        .plan_transfer(&bob_sh.address(), 100_000_000_000, fee, f.chain.shielded())
        .expect("plans");
    let transfer = Transaction::build_with_shielded(
        &mut OsRng,
        &[],
        &[],
        fee,
        &noct_core::stealth::TxKeypair::random(&mut OsRng),
        plan.cross(),
        Some(|sighash: &[u8; 32]| {
            plan.authorize(sighash).map_err(|_| noct_core::tx::TxError::BundleUnavailable)
        }),
    )
    .expect("builds");
    check("shielded-only transfer", &transfer);

    f.mine(&carol, &[transfer], &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);
    f.warm_up(1, &mut [&mut alice], &mut [&mut alice_sh, &mut bob_sh]);

    // 6. unshielding
    let un = alice
        .build_unshielding(
            &mut OsRng,
            &f.chain,
            &bob_sh,
            &[Payment { destination: carol, amount: 50_000_000_000 }],
            50_000_000_000,
            fee,
            DEFAULT_RING_SIZE,
        )
        .expect("builds");
    check("unshielding (pool -> ring)", &un);
}
