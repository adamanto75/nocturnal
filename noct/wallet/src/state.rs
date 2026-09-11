//! A wallet's state between runs, with nothing on disk that can spend.
//!
//! Rebuilding a wallet by replaying every block is correct, and slow. On a real
//! 88 MB block cache it cost most of a minute on every command, and it held a
//! whole private copy of the chain in memory while it ran. What a wallet has to
//! carry forward is much smaller: the state that validates the next block
//! ([`ChainState`]), and its own bookkeeping.
//!
//! **What is deliberately left out.** An owned output is stored as the public
//! data it was found with: which transaction key applies to it, its position,
//! and its amount field as it appeared on chain. Nothing derived from the spend
//! key is stored. The one-time spend secret and key image are re-derived from
//! the account on load, by the same function a scan uses. So this file reveals
//! which outputs are the wallet's and what they were worth, and is written
//! owner-only for that reason. But whoever reads it cannot spend them, and
//! cannot recognise an unspent one when it is later spent.
//!
//! **What is checked on load.** First a checksum over the whole file, so
//! accidental damage is refused before anything is read. That matters because
//! the chain state's points stay compressed and are only decompressed when
//! used; without it, a damaged point would surface at some later spend as a
//! ring that cannot be built. The checksum is no defence against deliberate
//! edits, since whoever rewrites the file can recompute it. That is what the
//! rest is for. Every record is re-derived against the chain state stored
//! beside it:
//! - the output must exist at the recorded global index;
//! - the account must recover it there;
//! - the recovered opening must open the chain's commitment;
//! - its coinbase flag, and its spent flag, must agree with the chain's.
//!
//! A file that fails any of this is refused, and the caller rebuilds, which
//! costs time and never correctness. That covers a damaged file, one from
//! another build, and one from another account or network.
//!
//! The chain state itself is not re-validated. It was validated block by
//! block when it was built, and a file is trusted as far as the key file
//! beside it: whoever can write one can replace the other.

use noct_core::address::Network;
use noct_core::block::{recover_coinbase_output, Block, CoinbaseOutput};
use noct_core::chain::{Blockchain, ChainState, OutputSet};
use noct_core::hash::keccak256;
use noct_core::keys::{Account, PublicKey};
use noct_core::pow::ProofOfWork;
use noct_core::subaddress::{self, SubaddressIndex};
use noct_core::tx::{recover_output, Output};

use crate::{Direction, HistoryEntry, OutputSource, OwnedOutput, Wallet};

const MAGIC: &[u8; 8] = b"NOCTWLST";
/// Bumped whenever the layout changes. An older file is refused and rebuilt
/// rather than misread. Version 2 added the trailing checksum.
const STATE_VERSION: u8 = 2;
/// Trailing Keccak-256 over everything before it.
const CHECKSUM: usize = 32;

/// Global index 8, kind 1, tx key 32, output index 4, amount field 8,
/// subaddress 4 + 4, spent 1.
const OWNED_RECORD: usize = 62;
/// Height 8, direction 1, amount 8, fee 8, coinbase 1.
const HISTORY_RECORD: usize = 26;

const KIND_COINBASE: u8 = 0;
const KIND_TRANSACTION: u8 = 1;

/// Why a saved state was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// Not a state file this build fully understands: wrong magic or version,
    /// a truncated or overlong body, a count that disagrees with the bytes
    /// present, or a stored point that does not decompress.
    Malformed,
    /// Written for a different account.
    WrongAccount,
    /// The chain state is rooted at another network's genesis.
    WrongNetwork,
    /// The wallet's output counter disagrees with the chain's output set.
    OutOfStep,
    /// A recorded output does not re-derive against the chain: it is absent,
    /// this account does not recover it, or the chain disagrees about whether
    /// it is a coinbase or whether it is spent.
    Inconsistent { global_index: u64 },
}

/// Identifies the account a file belongs to, without storing its keys.
fn account_tag(account: &Account) -> [u8; 32] {
    let mut b = Vec::with_capacity(17 + 64);
    b.extend_from_slice(b"noct_wallet_state");
    b.extend_from_slice(&account.spend_public.to_bytes());
    b.extend_from_slice(&account.view_public.to_bytes());
    keccak256(&b)
}

/// Serialize `wallet` together with the chain it was scanned against.
///
/// The two must be in step: every block `chain` accepted, `wallet` scanned.
/// [`decode`] checks that, so a mismatched pair is refused rather than loaded.
pub fn encode<P: ProofOfWork>(chain: &Blockchain<P>, wallet: &Wallet) -> Vec<u8> {
    let chain_bytes = chain.snapshot().encode();
    let mut o = Vec::with_capacity(
        8 + 1
            + 32
            + 8 * 4
            + wallet.owned.len() * OWNED_RECORD
            + wallet.history.len() * HISTORY_RECORD
            + chain_bytes.len(),
    );
    o.extend_from_slice(MAGIC);
    o.push(STATE_VERSION);
    o.extend_from_slice(&account_tag(&wallet.account));
    o.extend_from_slice(&wallet.next_global_index.to_le_bytes());

    o.extend_from_slice(&(wallet.owned.len() as u64).to_le_bytes());
    for owned in &wallet.owned {
        let (kind, tx_public, amount_field) = match owned.source {
            OutputSource::Coinbase { tx_public } => {
                (KIND_COINBASE, tx_public, owned.output.amount.to_le_bytes())
            }
            OutputSource::Transaction { tx_public, encrypted_amount } => {
                (KIND_TRANSACTION, tx_public, encrypted_amount)
            }
        };
        o.extend_from_slice(&owned.global_index.to_le_bytes());
        o.push(kind);
        o.extend_from_slice(&tx_public.to_bytes());
        o.extend_from_slice(&owned.output.index.to_le_bytes());
        o.extend_from_slice(&amount_field);
        o.extend_from_slice(&owned.output.subaddress.account.to_le_bytes());
        o.extend_from_slice(&owned.output.subaddress.index.to_le_bytes());
        o.push(u8::from(owned.spent));
    }

    o.extend_from_slice(&(wallet.history.len() as u64).to_le_bytes());
    for h in &wallet.history {
        o.extend_from_slice(&h.height.to_le_bytes());
        o.push(match h.direction {
            Direction::Received => 0,
            Direction::Sent => 1,
        });
        o.extend_from_slice(&h.amount.to_le_bytes());
        o.extend_from_slice(&h.fee.to_le_bytes());
        o.push(u8::from(h.coinbase));
    }

    o.extend_from_slice(&(chain_bytes.len() as u64).to_le_bytes());
    o.extend_from_slice(&chain_bytes);
    let sum = keccak256(&o);
    o.extend_from_slice(&sum);
    o
}

/// Restore a chain and wallet from [`encode`]d bytes, for `account` on
/// `network`, re-deriving and checking every owned output as described in the
/// module docs.
///
/// `issued` are subaddresses handed out beyond the lookahead window, exactly
/// as for [`Wallet::register_issued`]. Any subaddress that has received funds
/// is also recovered from the records themselves, so later payments to it are
/// still seen even if the list passed here is incomplete.
pub fn decode<P: ProofOfWork>(
    pow: P,
    account: Account,
    network: Network,
    bytes: &[u8],
    issued: &[(u32, u32)],
) -> Result<(Blockchain<P>, Wallet), StateError> {
    use StateError::Malformed;

    let body_len = bytes.len().checked_sub(CHECKSUM).ok_or(Malformed)?;
    let (body, sum) = bytes.split_at(body_len);
    if keccak256(body)[..] != *sum {
        return Err(Malformed);
    }

    let mut c = body;
    if take(&mut c, 8)? != &MAGIC[..] || take(&mut c, 1)?[0] != STATE_VERSION {
        return Err(Malformed);
    }
    if take(&mut c, 32)? != &account_tag(&account)[..] {
        return Err(StateError::WrongAccount);
    }
    let next_global_index = read_u64(&mut c)?;
    let owned_bytes = take_records(&mut c, OWNED_RECORD)?;
    let history_bytes = take_records(&mut c, HISTORY_RECORD)?;
    let chain_len = usize::try_from(read_u64(&mut c)?).map_err(|_| Malformed)?;
    let chain_bytes = take(&mut c, chain_len)?;
    // Trailing bytes mean this is not the file we think it is.
    if !c.is_empty() {
        return Err(Malformed);
    }

    let chain_state = ChainState::decode(chain_bytes).ok_or(Malformed)?;
    if chain_state.genesis_id() != Block::genesis_for(network.params()).id() {
        return Err(StateError::WrongNetwork);
    }
    let chain = Blockchain::from_state(pow, network, &chain_state).ok_or(Malformed)?;
    if next_global_index != chain.num_outputs() {
        return Err(StateError::OutOfStep);
    }

    let mut wallet = Wallet::new(account, network);
    wallet.register_issued(issued.iter().copied());
    wallet.next_global_index = next_global_index;

    wallet.owned.reserve(owned_bytes.len() / OWNED_RECORD);
    for record in owned_bytes.chunks_exact(OWNED_RECORD) {
        let owned = restore_output(&account, &chain, &mut wallet, record)?;
        // Scanning records outputs in chain order, once each. Anything else
        // was not written by a scan.
        if wallet.owned.last().is_some_and(|prev| prev.global_index >= owned.global_index) {
            return Err(Malformed);
        }
        wallet.owned.push(owned);
    }

    for r in history_bytes.chunks_exact(HISTORY_RECORD) {
        let height = le_u64(&r[0..8]);
        let direction = match r[8] {
            0 => Direction::Received,
            1 => Direction::Sent,
            _ => return Err(Malformed),
        };
        let coinbase = flag(r[25])?;
        if height >= chain.height() {
            return Err(Malformed);
        }
        wallet.history.push(HistoryEntry {
            height,
            direction,
            amount: le_u64(&r[9..17]),
            fee: le_u64(&r[17..25]),
            coinbase,
        });
    }
    Ok((chain, wallet))
}

/// Re-derive one owned output from its record, checking it against `chain`.
fn restore_output<P: ProofOfWork>(
    account: &Account,
    chain: &Blockchain<P>,
    wallet: &mut Wallet,
    r: &[u8],
) -> Result<OwnedOutput, StateError> {
    let global_index = le_u64(&r[0..8]);
    let kind = r[8];
    let tx_public =
        PublicKey::from_bytes(r[9..41].try_into().expect("32 bytes")).ok_or(StateError::Malformed)?;
    let index = u32::from_le_bytes(r[41..45].try_into().expect("4 bytes"));
    let amount_field: [u8; 8] = r[45..53].try_into().expect("8 bytes");
    let sub = SubaddressIndex::new(
        u32::from_le_bytes(r[53..57].try_into().expect("4 bytes")),
        u32::from_le_bytes(r[57..61].try_into().expect("4 bytes")),
    );
    let spent = flag(r[61])?;

    let inconsistent = StateError::Inconsistent { global_index };
    // The one-time key and commitment come from the chain, not the file: the
    // output has to be where the record says it is.
    let member = chain.member_at(global_index).ok_or(inconsistent)?;
    let (_, is_coinbase) = chain.meta_at(global_index).ok_or(inconsistent)?;

    let (received, source) = match kind {
        KIND_COINBASE => {
            if !is_coinbase || !sub.is_main() {
                return Err(inconsistent);
            }
            let output = CoinbaseOutput {
                one_time_key: member.key,
                amount: u64::from_le_bytes(amount_field),
                commitment: member.commitment,
            };
            (
                recover_coinbase_output(account, &tx_public, index, &output),
                OutputSource::Coinbase { tx_public },
            )
        }
        KIND_TRANSACTION => {
            if is_coinbase {
                return Err(inconsistent);
            }
            // The address it was paid to, re-derived from its index alone.
            let d = subaddress::spend_public(account, sub);
            let m = subaddress::offset(&account.view_secret, sub);
            // An address that has been paid once can be paid again. Keep
            // watching it even if the caller's issued list has lost it.
            wallet.subaddresses.insert(d.to_bytes(), (sub, m));
            let output = Output {
                one_time_key: member.key,
                commitment: member.commitment,
                encrypted_amount: amount_field,
            };
            (
                recover_output(account, &tx_public, index, &output, |r: &PublicKey| {
                    (*r == d).then_some((sub, m))
                }),
                OutputSource::Transaction { tx_public, encrypted_amount: amount_field },
            )
        }
        _ => return Err(StateError::Malformed),
    };
    let received = received.ok_or(inconsistent)?;
    // An owned output is spent exactly when its key image is in the chain's
    // spent set. A flag that disagrees was not written by a scan of this chain.
    if chain.is_spent(&received.key_image) != spent {
        return Err(inconsistent);
    }
    Ok(OwnedOutput { global_index, output: received, spent, source })
}

fn take<'a>(c: &mut &'a [u8], n: usize) -> Result<&'a [u8], StateError> {
    if c.len() < n {
        return Err(StateError::Malformed);
    }
    let (head, tail) = c.split_at(n);
    *c = tail;
    Ok(head)
}

/// A count followed by that many fixed-width records. The count is read from a
/// file that may be damaged, so it is checked against the bytes present before
/// anything is sized from it.
fn take_records<'a>(c: &mut &'a [u8], width: usize) -> Result<&'a [u8], StateError> {
    let count = usize::try_from(read_u64(c)?).map_err(|_| StateError::Malformed)?;
    take(c, count.checked_mul(width).ok_or(StateError::Malformed)?)
}

fn read_u64(c: &mut &[u8]) -> Result<u64, StateError> {
    Ok(le_u64(take(c, 8)?))
}

fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8 bytes"))
}

fn flag(b: u8) -> Result<bool, StateError> {
    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StateError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_RING_SIZE;
    use noct_core::address::Address;
    use noct_core::block::{BlockHeader, Coinbase};
    use noct_core::emission::{base_reward, ATOMIC_UNITS};
    use noct_core::pow::KeccakPow;
    use noct_core::tx::{Payment, Transaction};
    use rand_core::OsRng;

    /// Where the owned-output records start: magic, version, tag, output
    /// counter, record count.
    const OWNED_AT: usize = 8 + 1 + 32 + 8 + 8;

    /// Append a valid checksum to `body`.
    fn seal(mut body: Vec<u8>) -> Vec<u8> {
        let sum = keccak256(&body);
        body.extend_from_slice(&sum);
        body
    }

    /// Recompute the checksum after an edit, as someone deliberately tampering
    /// with the file would. The checks behind it are the real defence, and
    /// these tests are about those.
    fn reseal(bytes: &mut Vec<u8>) {
        let body = bytes.len() - CHECKSUM;
        bytes.truncate(body);
        *bytes = seal(std::mem::take(bytes));
    }

    fn mine(chain: &mut Blockchain<KeccakPow>, to: &Address, txs: &[Transaction], ts: u64) -> Block {
        let fees: u64 = txs.iter().map(|t| t.fee).sum();
        let cb = Coinbase::create(&mut OsRng, chain.height(), to, base_reward(chain.emitted()) + fees);
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
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

    struct Scenario {
        chain: Blockchain<KeccakPow>,
        alice_account: Account,
        alice: Wallet,
        /// A subaddress outside the lookahead window, which only the wallet
        /// that issued it knows about.
        far: (u32, u32),
        filler: Address,
        ts: u64,
    }

    impl Scenario {
        fn mine(&mut self, wallets: &mut [&mut Wallet], to: Option<Address>, txs: &[Transaction]) {
            self.ts += 130;
            let to = to.unwrap_or(self.filler);
            let block = mine(&mut self.chain, &to, txs, self.ts);
            self.alice.scan_block(&block, txs);
            for w in wallets.iter_mut() {
                w.scan_block(&block, txs);
            }
        }
    }

    /// A wallet that has done everything a wallet does. It has mined a
    /// coinbase, been paid at a lookahead subaddress and at one far outside
    /// the window, spent its coinbase, and received change.
    fn scenario() -> Scenario {
        let filler_account = Account::random(&mut OsRng);
        let alice_account = Account::random(&mut OsRng);
        let mut s = Scenario {
            chain: Blockchain::with_maturity(KeccakPow, 1),
            alice_account,
            alice: Wallet::new(alice_account, Network::Mainnet),
            far: (3, crate::SUBADDRESS_LOOKAHEAD + 700),
            filler: Address::new(Network::Mainnet, filler_account.spend_public, filler_account.view_public),
            ts: 1_000,
        };
        s.alice.scan_block(&Block::genesis(), &[]);
        let mut bob = Wallet::random(&mut OsRng, Network::Mainnet);
        bob.scan_block(&Block::genesis(), &[]);

        let near = s.alice.subaddress(0, 5);
        let far = s.alice.subaddress(s.far.0, s.far.1);
        let alice_main = s.alice.address();
        let bob_main = bob.address();

        s.mine(&mut [&mut bob], Some(bob_main), &[]);
        s.mine(&mut [&mut bob], Some(alice_main), &[]);
        for _ in 0..16 {
            s.mine(&mut [&mut bob], None, &[]);
        }

        // Bob pays both of Alice's subaddresses in one transaction.
        let fee = ATOMIC_UNITS / 100;
        let payments = [
            Payment { destination: near, amount: ATOMIC_UNITS / 10 },
            Payment { destination: far, amount: ATOMIC_UNITS / 5 },
        ];
        let tx = bob.build_transaction(&mut OsRng, &s.chain, &payments, fee, DEFAULT_RING_SIZE).unwrap();
        s.mine(&mut [&mut bob], None, std::slice::from_ref(&tx));

        // Alice spends her coinbase to a stranger and takes change.
        let stranger = Account::random(&mut OsRng);
        let stranger = Address::new(Network::Mainnet, stranger.spend_public, stranger.view_public);
        let pay = [Payment { destination: stranger, amount: ATOMIC_UNITS / 3 }];
        let tx = s.alice.build_transaction(&mut OsRng, &s.chain, &pay, fee, DEFAULT_RING_SIZE).unwrap();
        s.mine(&mut [&mut bob], None, std::slice::from_ref(&tx));

        let kinds: Vec<_> = s.alice.outputs().iter().map(|o| (o.output.subaddress, o.spent)).collect();
        assert!(kinds.iter().any(|&(sub, spent)| sub.is_main() && spent), "a spent coinbase");
        assert!(kinds.contains(&(SubaddressIndex::new(0, 5), false)), "a lookahead receipt");
        assert!(kinds.contains(&(SubaddressIndex::new(s.far.0, s.far.1), false)), "a far receipt");
        assert!(kinds.iter().any(|&(sub, spent)| sub.is_main() && !spent), "change");
        s
    }

    fn restore(s: &Scenario, bytes: &[u8]) -> Result<(Blockchain<KeccakPow>, Wallet), StateError> {
        decode(KeccakPow, s.alice_account, Network::Mainnet, bytes, &[s.far])
    }

    /// Everything a replay would produce, field by field. The secrets and key
    /// images included: they were re-derived rather than loaded, and a wrong
    /// one would make an output unspendable, or its spend invisible.
    fn assert_same_wallet(restored: &Wallet, replayed: &Wallet) {
        assert_eq!(restored.scanned_outputs(), replayed.scanned_outputs());
        assert_eq!(restored.history(), replayed.history());
        assert_eq!(restored.balance(), replayed.balance());
        assert_eq!(restored.outputs().len(), replayed.outputs().len());
        for (a, b) in restored.outputs().iter().zip(replayed.outputs()) {
            assert_eq!(a.global_index, b.global_index);
            assert_eq!(a.spent, b.spent);
            assert_eq!(a.source, b.source);
            assert_eq!(a.output.index, b.output.index);
            assert_eq!(a.output.amount, b.output.amount);
            assert_eq!(a.output.opening.commit(), b.output.opening.commit());
            assert_eq!(a.output.one_time_key, b.output.one_time_key);
            assert_eq!(a.output.spend_secret, b.output.spend_secret);
            assert_eq!(a.output.key_image, b.output.key_image);
            assert_eq!(a.output.subaddress, b.output.subaddress);
        }
    }

    #[test]
    fn a_restored_wallet_is_the_wallet_a_replay_builds() {
        let s = scenario();
        let bytes = encode(&s.chain, &s.alice);
        let (chain, wallet) = restore(&s, &bytes).expect("restores");
        assert_same_wallet(&wallet, &s.alice);
        assert_eq!(chain.snapshot(), s.chain.snapshot());
        // And it survives being saved again unchanged.
        assert_eq!(encode(&chain, &wallet), bytes);
    }

    /// Restoring is only useful if the pair carries on working: the chain
    /// validates the next block, the wallet scans it, and the wallet can build
    /// a spend the chain accepts.
    #[test]
    fn a_restored_wallet_keeps_scanning_and_can_spend() {
        let mut s = scenario();
        let (mut chain, mut wallet) = restore(&s, &encode(&s.chain, &s.alice)).expect("restores");

        let alice_main = s.alice.address();
        s.ts += 130;
        let block = mine(&mut s.chain, &alice_main, &[], s.ts);
        chain.add_block(&mut OsRng, &block, &[]).expect("the restored chain validates forward");
        wallet.scan_block(&block, &[]);
        s.alice.scan_block(&block, &[]);
        assert_same_wallet(&wallet, &s.alice);

        let to = Wallet::random(&mut OsRng, Network::Mainnet).address();
        let pay = [Payment { destination: to, amount: ATOMIC_UNITS / 7 }];
        let tx = wallet
            .build_transaction(&mut OsRng, &chain, &pay, ATOMIC_UNITS / 100, DEFAULT_RING_SIZE)
            .expect("builds a spend");
        s.ts += 130;
        let filler = s.filler;
        mine(&mut chain, &filler, std::slice::from_ref(&tx), s.ts);
    }

    /// Funds at a far subaddress must survive a restore even when the issued
    /// list is lost, and later payments to it must still be seen.
    #[test]
    fn a_paid_subaddress_is_remembered_without_the_issued_list() {
        let s = scenario();
        let bytes = encode(&s.chain, &s.alice);
        let (_, wallet) = decode(KeccakPow, s.alice_account, Network::Mainnet, &bytes, &[]).expect("restores");
        assert_same_wallet(&wallet, &s.alice);
        let far = SubaddressIndex::new(s.far.0, s.far.1);
        let d = subaddress::spend_public(&s.alice_account, far);
        assert!(wallet.subaddresses.contains_key(&d.to_bytes()), "still watching it");
    }

    /// **The security property.** Nothing in the file can spend: no account
    /// secret, no one-time spend secret, and no key image for an output that
    /// is still unspent. The key images of spent outputs are unavoidably
    /// present, because they are in the chain's public spent set.
    #[test]
    fn nothing_that_can_spend_is_written() {
        let s = scenario();
        let bytes = encode(&s.chain, &s.alice);
        let contains = |needle: [u8; 32]| bytes.windows(32).any(|w| w == needle);

        assert!(!contains(s.alice_account.spend_secret.to_bytes()), "account spend secret");
        assert!(!contains(s.alice_account.view_secret.to_bytes()), "account view secret");
        for o in s.alice.outputs() {
            assert!(!contains(o.output.spend_secret.to_bytes()), "one-time secret of {}", o.global_index);
            if !o.spent {
                assert!(!contains(o.output.key_image.to_bytes()), "key image of unspent {}", o.global_index);
            }
        }
    }

    fn record_of(s: &Scenario, pick: impl Fn(&OwnedOutput) -> bool) -> usize {
        let i = s.alice.outputs().iter().position(pick).expect("such an output");
        OWNED_AT + i * OWNED_RECORD
    }

    /// Records are re-derived against the chain, so an edited one is refused
    /// rather than believed.
    #[test]
    fn a_tampered_record_is_refused() {
        let s = scenario();
        let good = encode(&s.chain, &s.alice);
        let tx_rec = record_of(&s, |o| matches!(o.source, OutputSource::Transaction { .. }));
        let cb_rec = record_of(&s, |o| matches!(o.source, OutputSource::Coinbase { .. }));
        let refused = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            reseal(&mut bytes);
            restore(&s, &bytes).err()
        };
        let at = |rec: usize| Some(StateError::Inconsistent { global_index: le_u64(&good[rec..rec + 8]) });

        // An inflated amount no longer opens the chain's commitment.
        assert_eq!(refused(&|b| b[tx_rec + 45] ^= 1), at(tx_rec), "encrypted amount");
        assert_eq!(refused(&|b| b[cb_rec + 45] ^= 1), at(cb_rec), "coinbase amount");
        // A flipped spent flag disagrees with the chain's key images.
        assert_eq!(refused(&|b| b[tx_rec + 61] ^= 1), at(tx_rec), "spent flag");
        assert_eq!(refused(&|b| b[cb_rec + 61] ^= 1), at(cb_rec), "spent flag");
        // Claiming to be the other kind of output.
        assert_eq!(refused(&|b| b[tx_rec + 8] = KIND_COINBASE), at(tx_rec), "kind");
        // A different output index derives a different one-time key.
        assert_eq!(refused(&|b| b[tx_rec + 41] ^= 1), at(tx_rec), "output index");
        // Pointing the record at an output that is not ours.
        let moved = refused(&|b| {
            let gi = le_u64(&b[tx_rec..tx_rec + 8]) - 2;
            b[tx_rec..tx_rec + 8].copy_from_slice(&gi.to_le_bytes());
        });
        assert!(matches!(moved, Some(StateError::Inconsistent { .. }) | Some(StateError::Malformed)));
    }

    #[test]
    fn a_state_for_someone_else_is_refused() {
        let s = scenario();
        let bytes = encode(&s.chain, &s.alice);
        let other = Account::random(&mut OsRng);
        assert_eq!(
            decode(KeccakPow, other, Network::Mainnet, &bytes, &[]).err(),
            Some(StateError::WrongAccount)
        );
        assert_eq!(
            decode(KeccakPow, s.alice_account, Network::Testnet, &bytes, &[]).err(),
            Some(StateError::WrongNetwork)
        );
    }

    /// A wallet and chain out of step would assign the wrong global index to
    /// every output it finds from here on.
    #[test]
    fn a_wallet_out_of_step_with_its_chain_is_refused() {
        let s = scenario();
        let mut bytes = encode(&s.chain, &s.alice);
        let counter = 8 + 1 + 32;
        let n = le_u64(&bytes[counter..counter + 8]) + 1;
        bytes[counter..counter + 8].copy_from_slice(&n.to_le_bytes());
        reseal(&mut bytes);
        assert_eq!(restore(&s, &bytes).err(), Some(StateError::OutOfStep));
    }

    /// Damage anywhere is refused at load, before any of it is believed. The
    /// chain state's points are only decompressed when used, so this is what
    /// stops a damaged one reaching a spend.
    #[test]
    fn accidental_damage_anywhere_is_refused() {
        let s = scenario();
        let good = encode(&s.chain, &s.alice);
        for at in [0, OWNED_AT + 3, good.len() / 2, good.len() - CHECKSUM - 1, good.len() - 1] {
            let mut bad = good.clone();
            bad[at] ^= 0x10;
            assert_eq!(restore(&s, &bad).err(), Some(StateError::Malformed), "byte {at}");
        }
    }

    #[test]
    fn a_damaged_state_is_refused_rather_than_misread() {
        let s = scenario();
        let good = encode(&s.chain, &s.alice);

        assert_eq!(restore(&s, &[]).err(), Some(StateError::Malformed), "empty");
        assert_eq!(restore(&s, &good[..good.len() - 1]).err(), Some(StateError::Malformed), "truncated");
        assert_eq!(restore(&s, &good[..40]).err(), Some(StateError::Malformed), "truncated header");

        // The rest are sealed, so they reach the parser rather than stopping
        // at the checksum.
        let mut trailing = good[..good.len() - CHECKSUM].to_vec();
        trailing.push(0);
        let trailing = seal(trailing);
        assert_eq!(restore(&s, &trailing).err(), Some(StateError::Malformed), "trailing byte");

        let mut version = good.clone();
        version[8] = STATE_VERSION + 1;
        reseal(&mut version);
        assert_eq!(restore(&s, &version).err(), Some(StateError::Malformed), "future version");

        // A count that disagrees with the bytes must not be trusted, least of
        // all to size an allocation.
        let mut liar = good.clone();
        liar[OWNED_AT - 8..OWNED_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        reseal(&mut liar);
        assert_eq!(restore(&s, &liar).err(), Some(StateError::Malformed), "absurd count");

        let mut bad_flag = good.clone();
        bad_flag[OWNED_AT + 61] = 2;
        reseal(&mut bad_flag);
        assert_eq!(restore(&s, &bad_flag).err(), Some(StateError::Malformed), "non-boolean flag");
    }
}
