//! `noct-wallet` — a light wallet over [`noct_core`].
//!
//! The wallet turns the raw scanning primitives of `noct-core` into stateful
//! bookkeeping a user actually needs:
//!
//! * it **scans every block** with the account's view key, recording outputs
//!   addressed to it — and, crucially, the **global output index** each one was
//!   assigned by the chain (the value rings reference). It derives those indices
//!   by replaying the chain's assignment order (coinbase outputs first, then each
//!   transaction's outputs), so it must see the same blocks the chain did, in
//!   order;
//! * it **marks outputs spent** when one of its key images appears in a block;
//! * it reports **balance** and builds **transactions** — selecting inputs,
//!   pulling decoys from the chain, and paying change back to itself.
//!
//! This is the bookkeeping the earlier layers' tests did by hand. It stays pure
//! Rust and `cargo test`-able; a node RPC and GUI build on top of it.

use std::collections::HashMap;

use curve25519_dalek::scalar::Scalar;
use noct_core::address::{Address, Network};
use noct_core::block::Block;
use noct_core::chain::Blockchain;
use noct_core::keys::Account;
use noct_core::pow::ProofOfWork;
use noct_core::ring::{KeyImage, RingMember};
use noct_core::stealth::TxKeypair;
use noct_core::subaddress::{self, SubaddressIndex};
use noct_core::tx::{InputSecret, Payment, ReceivedOutput, Transaction, TxError};

/// How many subaddresses (of account 0) the wallet pre-derives so it can detect
/// funds sent to them even after a restart. Indices at or beyond this window are
/// only detected once explicitly generated in the current session.
pub const SUBADDRESS_LOOKAHEAD: u32 = 200;

pub mod client;
pub mod joint;
pub mod mnemonic;

/// The ring size every transaction uses: 1 real member + N−1 decoys.
///
/// Deliberately re-exported from consensus rather than declared here. Consensus
/// requires an **exact** count ([`noct_core::chain::RING_SIZE`]), so a wallet
/// with its own opinion would not merely be less private — every transaction it
/// built would be rejected. One definition means the two cannot drift apart.
pub const DEFAULT_RING_SIZE: usize = noct_core::chain::RING_SIZE;

/// Which way value moved in a [`HistoryEntry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Value arrived in the wallet (a coinbase reward or an incoming payment).
    Received,
    /// Value left the wallet (a spend we authored).
    Sent,
}

/// One entry in the wallet's transaction history, derived from scanning blocks.
///
/// A `Sent` entry's `amount` is what actually left the wallet — the inputs we
/// spent, minus the change that came back, minus the `fee` — i.e. the amount
/// delivered to the recipient(s). Ring signatures hide other parties' amounts,
/// so this is the most the wallet can attribute; `fee` is public and reported
/// alongside. A `Received` entry has `fee == 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Height of the block this activity was confirmed in.
    pub height: u64,
    pub direction: Direction,
    /// Amount received, or (for `Sent`) amount delivered to recipients.
    pub amount: u64,
    /// Fee paid (`Sent` only; `0` for `Received`).
    pub fee: u64,
    /// True when this is a mined coinbase reward.
    pub coinbase: bool,
}

/// An output owned by the wallet, with the chain bookkeeping it needs to spend.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    /// Global index in the chain's output set (what rings reference).
    pub global_index: u64,
    /// The recovered output (amount, opening, one-time secret, key image).
    pub output: ReceivedOutput,
    /// Set once a block spends this output.
    pub spent: bool,
}

impl OwnedOutput {
    pub fn amount(&self) -> u64 {
        self.output.amount
    }
    pub fn key_image(&self) -> KeyImage {
        self.output.key_image
    }
}

/// Errors from building a spend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WalletError {
    /// Unspent balance does not cover the requested amount plus fee.
    InsufficientFunds,
    /// The chain has too few outputs to form a ring of the requested size.
    NotEnoughDecoys,
    /// Value overflow while summing amounts.
    Overflow,
    /// Transaction assembly failed.
    Tx(TxError),
}

impl From<TxError> for WalletError {
    fn from(e: TxError) -> Self {
        WalletError::Tx(e)
    }
}

/// A view/spend wallet for a single [`Account`].
pub struct Wallet {
    account: Account,
    network: Network,
    /// Next global output index the wallet expects to assign while scanning.
    next_global_index: u64,
    owned: Vec<OwnedOutput>,
    /// Confirmed activity, in block order, built up while scanning.
    history: Vec<HistoryEntry>,
    /// Recognised receiving addresses: recovered spend key `D` → the subaddress
    /// it identifies and that subaddress's offset `m`. Includes the main address
    /// (`D = B`, `m = 0`) so scanning is uniform. Used to detect which of the
    /// wallet's addresses an output was paid to.
    subaddresses: HashMap<[u8; 32], (SubaddressIndex, Scalar)>,
}

impl Wallet {
    /// Create a wallet for `account` on `network`.
    pub fn new(account: Account, network: Network) -> Self {
        let mut wallet = Wallet {
            account,
            network,
            next_global_index: 0,
            owned: Vec::new(),
            history: Vec::new(),
            subaddresses: HashMap::new(),
        };
        // Pre-derive the main address and a lookahead window of subaddresses so
        // funds sent to them are detected on the next scan without extra state.
        for index in 0..SUBADDRESS_LOOKAHEAD {
            wallet.register_subaddress(SubaddressIndex::new(0, index));
        }
        wallet
    }

    /// Register subaddresses this wallet has handed out before, so a scan sees
    /// the funds paid to them.
    ///
    /// `new` pre-derives a lookahead window of [`SUBADDRESS_LOOKAHEAD`]
    /// addresses on account 0, and anything outside it is only known to the
    /// wallet that issued it. A reconstructed wallet does not know it ever
    /// issued `(7, 5000)` — or `(0, 250)`, one past the window — so it scans
    /// without those keys registered and reports no funds. The money is not
    /// lost, since the seed still derives it, but the wallet will neither show
    /// nor spend it, which is indistinguishable from lost to whoever is looking.
    ///
    /// So whatever issued them has to remember, and hand them back here before
    /// the scan. Registering an address twice is harmless.
    pub fn register_issued(&mut self, issued: impl IntoIterator<Item = (u32, u32)>) {
        for (account, index) in issued {
            let sub = SubaddressIndex::new(account, index);
            if !sub.is_main() {
                self.register_subaddress(sub);
            }
        }
    }

    /// Derive and remember the subaddress at `sub`, so outputs paid to it are
    /// recognised when scanning.
    fn register_subaddress(&mut self, sub: SubaddressIndex) {
        let d = subaddress::spend_public(&self.account, sub);
        let m = subaddress::offset(&self.account.view_secret, sub);
        self.subaddresses.insert(d.to_bytes(), (sub, m));
    }

    /// The receiving [`Address`] for subaddress `(account, index)`, registering
    /// it so incoming funds are detected. `(0, 0)` is the main address.
    pub fn subaddress(&mut self, account: u32, index: u32) -> Address {
        let sub = SubaddressIndex::new(account, index);
        if sub.is_main() {
            return self.address();
        }
        self.register_subaddress(sub);
        Address::new_subaddress(
            self.network,
            subaddress::spend_public(&self.account, sub),
            subaddress::view_public(&self.account, sub),
        )
    }

    /// A fresh random wallet.
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R, network: Network) -> Self {
        Wallet::new(Account::random(rng), network)
    }

    /// This wallet's public address.
    pub fn address(&self) -> Address {
        Address::new(self.network, self.account.spend_public, self.account.view_public)
    }

    /// Number of outputs the wallet has scanned past (its view of the chain's
    /// output-set size). Must stay in lock-step with the chain.
    pub fn scanned_outputs(&self) -> u64 {
        self.next_global_index
    }

    /// Scan a block (with its transactions) into the wallet, in the chain's
    /// order. Records owned outputs with their global indices and marks owned
    /// outputs spent when their key images appear.
    ///
    /// Call this for **every** block the chain accepts, in order — even blocks
    /// with nothing for us — so the global-index counter stays correct.
    pub fn scan_block(&mut self, block: &Block, txs: &[Transaction]) {
        let height = block.coinbase.height;

        // Coinbase outputs come first in the chain's index assignment.
        let coinbase_base = self.next_global_index;
        if let Some(received) = block.coinbase.scan(&self.account) {
            let amount = received.amount;
            self.record(coinbase_base, received);
            self.history.push(HistoryEntry {
                height,
                direction: Direction::Received,
                amount,
                fee: 0,
                coinbase: true,
            });
        }
        self.next_global_index += block.coinbase.outputs.len() as u64;

        // Then each transaction's outputs, in order.
        for tx in txs {
            let tx_base = self.next_global_index;
            // Resolve each output's recovered spend key against our address table
            // (main address + subaddresses), so funds to any of them are found.
            let received = {
                let table = &self.subaddresses;
                tx.scan_with(&self.account, |d| table.get(&d.to_bytes()).copied())
            };
            let mut received_here: u64 = 0;
            for received in received {
                received_here = received_here.saturating_add(received.amount);
                self.record(tx_base, received);
            }
            self.next_global_index += tx.outputs.len() as u64;

            // Value of our outputs this transaction spends (summed before we
            // mark them, so a spend still sees them unspent).
            let spent_here: u64 = tx
                .inputs
                .iter()
                .flat_map(|input| {
                    self.owned
                        .iter()
                        .filter(move |o| o.output.key_image == input.signature.key_image)
                })
                .map(|o| o.output.amount)
                .sum();
            for input in &tx.inputs {
                self.mark_spent(&input.signature.key_image);
            }

            // Classify this transaction's effect on us. Spending any of our
            // outputs makes it outgoing (the received value is our change);
            // otherwise any received value is an incoming payment.
            if spent_here > 0 {
                let net_out = spent_here.saturating_sub(received_here);
                self.history.push(HistoryEntry {
                    height,
                    direction: Direction::Sent,
                    amount: net_out.saturating_sub(tx.fee),
                    fee: tx.fee,
                    coinbase: false,
                });
            } else if received_here > 0 {
                self.history.push(HistoryEntry {
                    height,
                    direction: Direction::Received,
                    amount: received_here,
                    fee: 0,
                    coinbase: false,
                });
            }
        }
    }

    fn record(&mut self, base_index: u64, received: ReceivedOutput) {
        let global_index = base_index + u64::from(received.index);
        // Avoid double-recording if a block is (re)scanned.
        if self.owned.iter().any(|o| o.global_index == global_index) {
            return;
        }
        self.owned.push(OwnedOutput { global_index, output: received, spent: false });
    }

    fn mark_spent(&mut self, image: &KeyImage) {
        for owned in &mut self.owned {
            if &owned.output.key_image == image {
                owned.spent = true;
            }
        }
    }

    /// All outputs the wallet has ever received.
    pub fn outputs(&self) -> &[OwnedOutput] {
        &self.owned
    }

    /// Confirmed transaction history, oldest first.
    pub fn history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Currently-unspent outputs.
    pub fn unspent(&self) -> impl Iterator<Item = &OwnedOutput> {
        self.owned.iter().filter(|o| !o.spent)
    }

    /// Total unspent balance (sum of unspent outputs), including coinbase
    /// outputs that are not yet mature. See [`Wallet::spendable_balance`] for the
    /// amount actually spendable right now.
    pub fn balance(&self) -> u64 {
        self.unspent().map(OwnedOutput::amount).sum()
    }

    /// The ring member `[P, C]` for an owned output (its entry in the chain's
    /// output set).
    fn owned_member(owned: &OwnedOutput) -> RingMember {
        RingMember::new(owned.output.one_time_key, owned.output.opening.commit())
    }

    /// Balance that can be spent against `chain` right now — excludes coinbase
    /// outputs still within the maturity window.
    pub fn spendable_balance<P: ProofOfWork>(&self, chain: &Blockchain<P>) -> u64 {
        self.unspent()
            .filter(|o| chain.is_spendable(&Self::owned_member(o)))
            .map(OwnedOutput::amount)
            .sum()
    }

    /// Build a signed transaction paying `payments`, with `fee`, drawing decoys
    /// of ring size `ring_size` from `chain`. Change (if any) is paid back to
    /// this wallet.
    ///
    /// This does not mutate the wallet; the inputs are marked spent only when the
    /// resulting transaction is mined and [`Wallet::scan_block`] observes it.
    pub fn build_transaction<P: ProofOfWork, R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        chain: &Blockchain<P>,
        payments: &[Payment],
        fee: u64,
        ring_size: usize,
    ) -> Result<Transaction, WalletError> {
        let out_total = payments
            .iter()
            .try_fold(0u64, |acc, p| acc.checked_add(p.amount))
            .and_then(|s| s.checked_add(fee))
            .ok_or(WalletError::Overflow)?;

        // Greedy input selection over unspent outputs. Skip outputs that cannot
        // be spent yet (immature coinbase) — including them would build a
        // transaction the chain rejects with `ImmatureCoinbase`.
        let mut selected: Vec<&OwnedOutput> = Vec::new();
        let mut in_total: u64 = 0;
        for owned in self.unspent() {
            if in_total >= out_total {
                break;
            }
            if !chain.is_spendable(&Self::owned_member(owned)) {
                continue;
            }
            in_total = in_total.checked_add(owned.amount()).ok_or(WalletError::Overflow)?;
            selected.push(owned);
        }
        if in_total < out_total {
            return Err(WalletError::InsufficientFunds);
        }

        // Resolve each selected output into a ring of decoys from the chain.
        //
        // Recency-biased, not uniform. People overwhelmingly spend outputs they
        // received recently, so uniform decoys are drawn from a population that
        // looks nothing like the real spend: the newest member of the ring is
        // the real one far more often than chance, and that is a statistical
        // handle on every transaction the wallet makes. Matching the decoy ages
        // to observed spending removes it.
        let mut inputs: Vec<InputSecret> = Vec::with_capacity(selected.len());
        for owned in &selected {
            let (ring, signer_index) = chain
                .select_ring_recency_biased(rng, ring_size, owned.global_index)
                .ok_or(WalletError::NotEnoughDecoys)?;
            inputs.push(owned.output.to_input(ring, signer_index));
        }

        // Append a change output back to ourselves.
        let mut all_payments = payments.to_vec();
        let change = in_total - out_total;
        if change > 0 {
            all_payments.push(Payment { destination: self.address(), amount: change });
        }

        let tx_keys = TxKeypair::random(rng);
        let tx = Transaction::build(rng, &inputs, &all_payments, fee, &tx_keys)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::block::{Block, BlockHeader, Coinbase, PREMINE_AMOUNT};
    use noct_core::emission::{base_reward, ATOMIC_UNITS};
    use noct_core::keys::Account;
    use noct_core::pow::KeccakPow;
    use rand_core::OsRng;

    // A wallet that has already scanned genesis, exactly as production `sync`
    // does — so its global-index counter includes the premine at index 0. Tests
    // that check indices or spend must start from here to stay chain-aligned.
    fn fresh_wallet() -> Wallet {
        let mut w = Wallet::random(&mut OsRng, Network::Mainnet);
        w.scan_block(&Block::genesis(), &[]);
        w
    }

    // Mine a block: coinbase to `miner_addr` plus `txs`, at the chain's
    // difficulty. Returns the block. Does not scan any wallet.
    fn mine_block(
        chain: &mut Blockchain<KeccakPow>,
        miner_addr: &Address,
        txs: &[Transaction],
        ts: u64,
    ) -> Block {
        let subsidy = base_reward(chain.emitted());
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let cb = Coinbase::create(&mut OsRng, chain.height(), miner_addr, subsidy + fees);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                // `ts` is an offset from genesis, so blocks land after it.
                timestamp: noct_core::block::GENESIS_TIMESTAMP + ts,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: txs.iter().map(|t| t.hash()).collect(),
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, txs).expect("valid block");
        block
    }

    // Mine a block and scan it into all `wallets` (keeping their indices synced).
    fn mine_and_scan(
        chain: &mut Blockchain<KeccakPow>,
        wallets: &mut [&mut Wallet],
        miner_addr: &Address,
        txs: &[Transaction],
        ts: u64,
    ) {
        let block = mine_block(chain, miner_addr, txs, ts);
        for w in wallets.iter_mut() {
            w.scan_block(&block, txs);
        }
    }

    /// Funds paid to a subaddress outside the lookahead window are invisible to
    /// a wallet that does not know it issued it — which is every wallet
    /// reconstructed from the seed, since `new` only pre-derives the window.
    ///
    /// The money is not lost: the same seed derives it, and registering the
    /// address makes it appear. But a wallet that cannot see funds cannot spend
    /// them either, and from outside that is indistinguishable from losing them.
    #[test]
    fn a_subaddress_beyond_the_lookahead_needs_registering_after_a_restart() {
        // Maturity 1: this is about which keys a scan knows, not about how long
        // a coinbase takes to ripen.
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let alice_account = Account::random(&mut OsRng);
        let mut alice = Wallet::new(alice_account, Network::Mainnet);
        alice.scan_block(&Block::genesis(), &[]);
        let mut bob = fresh_wallet();
        let bob_addr = bob.address();

        // Well outside the window `new` pre-derives, and on another account.
        let far = (7, SUBADDRESS_LOOKAHEAD + 4_800);
        let alice_sub = alice.subaddress(far.0, far.1);

        // Fund Bob and warm the chain so there are decoys to sign against.
        mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &bob_addr, &[], 1_000);
        let filler = Account::random(&mut OsRng);
        let filler_addr = Address::new(Network::Mainnet, filler.spend_public, filler.view_public);
        for i in 0..15 {
            mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &filler_addr, &[], 1_200 + i * 130);
        }

        // Bob pays the far subaddress.
        let amount = ATOMIC_UNITS / 10;
        let fee = ATOMIC_UNITS / 100;
        let payments = [Payment { destination: alice_sub, amount }];
        let tx = bob.build_transaction(&mut OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE).unwrap();
        mine_and_scan(
            &mut chain,
            &mut [&mut alice, &mut bob],
            &filler_addr,
            std::slice::from_ref(&tx),
            50_000,
        );
        assert_eq!(alice.balance(), amount, "the issuer must see what it was paid");

        // Rescan the whole chain with a wallet rebuilt from the same seed, as a
        // later command or a restart does. It has never heard of that address.
        let rescan = |w: &mut Wallet| {
            w.scan_block(&Block::genesis(), &[]);
            for h in 1..chain.height() {
                let stored = chain.block_at(h).expect("mined");
                w.scan_block(&stored.block, &stored.txs);
            }
        };

        let mut restarted = Wallet::new(alice_account, Network::Mainnet);
        rescan(&mut restarted);
        assert_eq!(
            restarted.balance(),
            0,
            "this is the bug: a scan without the issued key reports nothing"
        );

        // Handing the record back before scanning is what fixes it.
        let mut recovered = Wallet::new(alice_account, Network::Mainnet);
        recovered.register_issued([far]);
        rescan(&mut recovered);
        assert_eq!(recovered.balance(), amount, "registering it recovers the funds");
    }

    #[test]
    fn receives_and_tracks_coinbase() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let mut alice = fresh_wallet();
        let alice_addr = alice.address();

        assert_eq!(alice.balance(), 0);
        mine_and_scan(&mut chain, &mut [&mut alice], &alice_addr, &[], 1_000);

        // Block 1's subsidy continues the curve from the premined baseline.
        assert_eq!(alice.balance(), base_reward(PREMINE_AMOUNT));
        assert_eq!(alice.outputs().len(), 1);
        // Global index 0 is the genesis premine; Alice's coinbase is index 1.
        assert_eq!(alice.outputs()[0].global_index, 1);
        // The wallet's output count matches the chain's (premine + this block).
        assert_eq!(alice.scanned_outputs(), chain.num_outputs());
    }

    #[test]
    fn global_index_stays_in_sync_through_filler_blocks() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let mut alice = fresh_wallet();
        let alice_addr = alice.address();
        let stranger = Account::random(&mut OsRng);
        let stranger_addr = Address::new(Network::Mainnet, stranger.spend_public, stranger.view_public);

        // A few blocks to a stranger, then one to Alice.
        mine_and_scan(&mut chain, &mut [&mut alice], &stranger_addr, &[], 1_000);
        mine_and_scan(&mut chain, &mut [&mut alice], &stranger_addr, &[], 1_130);
        mine_and_scan(&mut chain, &mut [&mut alice], &alice_addr, &[], 1_260);

        // Indices: premine 0, two stranger coinbases 1 and 2, Alice's is 3.
        assert_eq!(alice.outputs().len(), 1);
        assert_eq!(alice.outputs()[0].global_index, 3);
        assert_eq!(alice.scanned_outputs(), chain.num_outputs());
    }

    #[test]
    fn insufficient_funds_is_reported() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let alice = Wallet::random(&mut OsRng, Network::Mainnet);
        // Empty wallet cannot pay anything.
        let bob = Wallet::random(&mut OsRng, Network::Mainnet);
        let payments = [Payment { destination: bob.address(), amount: 1 }];
        // Warm the chain so decoys exist, then attempt to spend with no funds.
        let miner = Account::random(&mut OsRng);
        let miner_addr = Address::new(Network::Mainnet, miner.spend_public, miner.view_public);
        for i in 0..12 {
            mine_block(&mut chain, &miner_addr, &[], 1_000 + i * 130);
        }
        assert!(matches!(
            alice.build_transaction(&mut OsRng, &chain, &payments, 1, DEFAULT_RING_SIZE),
            Err(WalletError::InsufficientFunds)
        ));
    }

    #[test]
    fn spend_with_change_and_spent_marking() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let mut alice = fresh_wallet();
        let mut bob = fresh_wallet();
        let alice_addr = alice.address();

        // Alice mines block 1 (gets the reward); warm the chain for decoys.
        mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &alice_addr, &[], 1_000);
        let filler = Account::random(&mut OsRng);
        let filler_addr = Address::new(Network::Mainnet, filler.spend_public, filler.view_public);
        for i in 0..15 {
            mine_and_scan(
                &mut chain,
                &mut [&mut alice, &mut bob],
                &filler_addr,
                &[],
                1_200 + i * 130,
            );
        }

        // First mined block continues emission from the premined baseline.
        let reward = base_reward(PREMINE_AMOUNT);
        assert_eq!(alice.balance(), reward);

        // Alice pays Bob 0.1 NOCT with a 0.01 NOCT fee; the rest is change.
        // (Per-block rewards are sub-NOCT under the 1M supply.)
        let to_bob = ATOMIC_UNITS / 10;
        let fee = ATOMIC_UNITS / 100;
        let payments = [Payment { destination: bob.address(), amount: to_bob }];
        let tx = alice
            .build_transaction(&mut OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();

        // Before mining, the wallet still counts the input as spendable.
        assert_eq!(alice.balance(), reward);

        // Mine the transaction; both wallets scan the block.
        mine_and_scan(
            &mut chain,
            &mut [&mut alice, &mut bob],
            &filler_addr,
            std::slice::from_ref(&tx),
            50_000,
        );

        // Bob received his payment.
        assert_eq!(bob.balance(), to_bob);
        // Alice's original output is spent; she now holds only the change.
        assert_eq!(alice.balance(), reward - to_bob - fee);
        assert!(alice.outputs().iter().any(|o| o.spent), "input should be marked spent");
        assert_eq!(alice.unspent().count(), 1, "only the change remains unspent");

        // History: Alice logged one coinbase receipt (block 1) and one send;
        // Bob logged one incoming payment.
        let alice_hist = alice.history();
        assert_eq!(alice_hist[0].direction, Direction::Received);
        assert!(alice_hist[0].coinbase);
        assert_eq!(alice_hist[0].amount, reward);
        let sent = alice_hist.last().unwrap();
        assert_eq!(sent.direction, Direction::Sent);
        assert!(!sent.coinbase);
        assert_eq!(sent.amount, to_bob, "sent amount excludes change and fee");
        assert_eq!(sent.fee, fee);
        // Alice mined block 1 only; the rest were filler to a stranger, so she
        // has exactly the coinbase receipt plus the send.
        assert_eq!(alice_hist.len(), 2);

        let bob_recv = bob.history().last().unwrap();
        assert_eq!(bob_recv.direction, Direction::Received);
        assert!(!bob_recv.coinbase);
        assert_eq!(bob_recv.amount, to_bob);
        assert_eq!(bob_recv.fee, 0);
        assert_eq!(bob.history().len(), 1, "Bob only ever received the one payment");
    }

    #[test]
    fn receives_to_subaddress_and_spends_it() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let mut alice = fresh_wallet();
        let mut bob = fresh_wallet();
        let bob_addr = bob.address();

        // A subaddress of Alice's, unlinkable to her main address.
        let alice_sub = alice.subaddress(0, 1);
        assert!(alice_sub.is_subaddress);
        assert_ne!(alice_sub.encode(), alice.address().encode());

        // Bob mines block 1 and warms the chain with filler for decoys.
        mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &bob_addr, &[], 1_000);
        let filler = Account::random(&mut OsRng);
        let filler_addr = Address::new(Network::Mainnet, filler.spend_public, filler.view_public);
        for i in 0..15 {
            mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &filler_addr, &[], 1_200 + i * 130);
        }
        assert_eq!(alice.balance(), 0);

        // Bob pays Alice's subaddress.
        let amount = ATOMIC_UNITS / 10;
        let fee = ATOMIC_UNITS / 100;
        let payments = [Payment { destination: alice_sub, amount }];
        let tx = bob.build_transaction(&mut OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE).unwrap();
        // A subaddress destination forces per-output transaction keys.
        assert_eq!(tx.additional_tx_public.len(), tx.outputs.len());

        mine_and_scan(
            &mut chain,
            &mut [&mut alice, &mut bob],
            &filler_addr,
            std::slice::from_ref(&tx),
            50_000,
        );

        // Alice received it, credited to subaddress (0, 1).
        assert_eq!(alice.balance(), amount);
        assert!(alice
            .outputs()
            .iter()
            .any(|o| o.output.subaddress == SubaddressIndex::new(0, 1)));
        // It shows in her history as an incoming payment.
        assert!(alice.history().iter().any(|e| e.direction == Direction::Received && e.amount == amount));

        // And she can spend the subaddress-received output like any other.
        let carol = Account::random(&mut OsRng);
        let carol_addr = Address::new(Network::Mainnet, carol.spend_public, carol.view_public);
        let spend = [Payment { destination: carol_addr, amount: amount / 2 }];
        let tx2 = alice.build_transaction(&mut OsRng, &chain, &spend, fee / 2, DEFAULT_RING_SIZE).unwrap();
        assert!(tx2.verify(&mut OsRng).is_ok());
    }

    #[test]
    fn multi_input_spend() {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let mut alice = fresh_wallet();
        let mut bob = fresh_wallet();
        let alice_addr = alice.address();

        // Alice mines two blocks → two coinbase outputs.
        mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &alice_addr, &[], 1_000);
        mine_and_scan(&mut chain, &mut [&mut alice, &mut bob], &alice_addr, &[], 1_130);
        let filler = Account::random(&mut OsRng);
        let filler_addr = Address::new(Network::Mainnet, filler.spend_public, filler.view_public);
        for i in 0..15 {
            mine_and_scan(
                &mut chain,
                &mut [&mut alice, &mut bob],
                &filler_addr,
                &[],
                1_300 + i * 130,
            );
        }

        // The two coinbase rewards differ slightly (emission decreases), both
        // continuing the curve from the premined baseline.
        let reward0 = base_reward(PREMINE_AMOUNT);
        let reward1 = base_reward(PREMINE_AMOUNT + reward0);
        let total = reward0 + reward1;
        assert_eq!(alice.balance(), total);
        assert_eq!(alice.unspent().count(), 2);

        // Pay Bob more than a single coinbase output holds → forces 2 inputs.
        let to_bob = reward0 + ATOMIC_UNITS / 100;
        let fee = ATOMIC_UNITS / 100;
        let payments = [Payment { destination: bob.address(), amount: to_bob }];
        let tx = alice
            .build_transaction(&mut OsRng, &chain, &payments, fee, DEFAULT_RING_SIZE)
            .unwrap();
        assert_eq!(tx.inputs.len(), 2, "should spend two inputs");

        mine_and_scan(
            &mut chain,
            &mut [&mut alice, &mut bob],
            &filler_addr,
            std::slice::from_ref(&tx),
            80_000,
        );

        assert_eq!(bob.balance(), to_bob);
        assert_eq!(alice.balance(), total - to_bob - fee);
    }

    #[test]
    fn joint_account_locks_funds_spendable_only_with_both_halves() {
        use crate::joint::{reconstruct_spend_secret, JointAccount, JointContribution};

        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        // Funder accrues coinbase funds and warms the chain with decoys.
        let mut funder = fresh_wallet();
        let funder_addr = funder.address();
        mine_and_scan(&mut chain, &mut [&mut funder], &funder_addr, &[], 1_000);
        let filler = Account::random(&mut OsRng);
        let filler_addr = Address::new(Network::Mainnet, filler.spend_public, filler.view_public);
        for i in 0..15 {
            mine_and_scan(&mut chain, &mut [&mut funder], &filler_addr, &[], 1_200 + i * 130);
        }

        // Alice and Bob independently assemble the same joint account.
        let alice = JointContribution::random(&mut OsRng);
        let bob = JointContribution::random(&mut OsRng);
        let joint =
            JointAccount::assemble(Network::Mainnet, &alice, bob.spend_public(), bob.view_secret);
        let mirror =
            JointAccount::assemble(Network::Mainnet, &bob, alice.spend_public(), alice.view_secret);
        assert_eq!(joint.address().encode(), mirror.address().encode());

        // Funder locks 0.1 NOCT into the joint account.
        let lock = ATOMIC_UNITS / 10;
        let fee = ATOMIC_UNITS / 100;
        let pay = [Payment { destination: joint.address(), amount: lock }];
        let lock_tx =
            funder.build_transaction(&mut OsRng, &chain, &pay, fee, DEFAULT_RING_SIZE).unwrap();
        mine_and_scan(
            &mut chain,
            &mut [&mut funder],
            &filler_addr,
            std::slice::from_ref(&lock_tx),
            50_000,
        );

        // Neither half alone can build a spendable account.
        assert!(joint.into_account(alice.spend_secret).is_none());
        assert!(joint.into_account(bob.spend_secret).is_none());

        // Reconstruct s_a + s_b (as the ETH-side reveal enables) → spendable.
        let joint_secret = reconstruct_spend_secret(&alice.spend_secret, &bob.spend_secret);
        let joint_account = joint.into_account(joint_secret).expect("full secret is spendable");
        let mut jw = Wallet::new(joint_account, Network::Mainnet);
        for stored in chain.blocks() {
            jw.scan_block(&stored.block, &stored.txs);
        }
        assert_eq!(jw.balance(), lock, "joint account holds exactly the locked amount");

        // Sweep it — the chain accepting the block proves a valid CLSAG spend of
        // the jointly-held output.
        let recipient = fresh_wallet();
        let sweep = jw
            .build_transaction(
                &mut OsRng,
                &chain,
                &[Payment { destination: recipient.address(), amount: lock - fee }],
                fee,
                DEFAULT_RING_SIZE,
            )
            .unwrap();
        assert!(sweep.verify(&mut OsRng).is_ok());
        let swept_block = mine_block(&mut chain, &filler_addr, std::slice::from_ref(&sweep), 60_000);
        jw.scan_block(&swept_block, std::slice::from_ref(&sweep));
        assert_eq!(jw.balance(), 0, "the locked output is now spent");
    }
}
