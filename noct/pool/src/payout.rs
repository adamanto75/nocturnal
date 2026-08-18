//! The pool's payout ledger: who is owed what, and what has already been sent.
//!
//! This is the part of a pool where mistakes cost real money, so it is written
//! to make the dangerous outcomes structurally hard:
//!
//! * **Credit only at maturity.** A block's reward is not owed to anyone the
//!   moment it is found — a reorg can erase it, and pool income is a coinbase
//!   output that cannot be spent until [`COINBASE_MATURITY`] blocks deep
//!   anyway. Rounds are held until the chain has buried them, then credited.
//! * **Never pay twice.** Sending money and recording that you sent it cannot be
//!   made atomic. So the ledger writes its *intent* to pay before sending, and
//!   on restart any payment still marked in-flight becomes
//!   [`PaymentState::Unresolved`] — never refunded, never automatically retried.
//!   An operator reconciles it against the chain. Paying a miner twice is worse
//!   than paying late, so the ambiguous case fails toward *not* sending.
//! * **Conserve value.** Everything credited is either still owed or accounted
//!   for by a payment record; [`PayoutLedger::audit`] asserts that.
//!
//! [`COINBASE_MATURITY`]: noct_core::chain::COINBASE_MATURITY

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::MinerId;

/// The operator's fee, in hundredths of a percent.
///
/// Basis points rather than a percentage float, for two reasons. Money should
/// never be divided by a value that cannot represent 0.1 exactly. And a fee is
/// something an operator publishes and a miner checks — an integer is
/// unambiguous in a config file, a log line and an argument, where `0.1` read
/// back as `0.09999999` is not.
pub type FeeBps = u32;

/// One hundred percent.
pub const FEE_BPS_MAX: FeeBps = 10_000;

/// Split a block reward into the operator's fee and what miners share.
///
/// **The two always sum to exactly `reward`.** No atomic unit is created or
/// lost, at any reward and any fee, which is the property the whole pool's
/// accounting rests on — `split_reward` then divides the miners' portion with
/// its own exactness guarantee, so the chain of custody from block to payout is
/// exact end to end.
///
/// The fee is **floored**, so the rounding remainder always goes to the miners.
/// That is a deliberate choice about who benefits from an ambiguity: the
/// operator writes the code and sets the rate, so the party without that power
/// gets the sub-unit.
pub fn apply_fee(reward: u64, fee_bps: FeeBps) -> (u64, u64) {
    let bps = fee_bps.min(FEE_BPS_MAX) as u128;
    // Through u128: `reward * 10_000` overflows u64 for rewards above ~1.8e15
    // atomic units, which is well inside the range a real block can carry.
    let fee = ((reward as u128) * bps / (FEE_BPS_MAX as u128)) as u64;
    // Cannot underflow — `fee <= reward` for any bps <= FEE_BPS_MAX — but said
    // saturating anyway, because a silent wrap here would mint money.
    (fee, reward.saturating_sub(fee))
}

/// A block the pool found, waiting to be buried deep enough to credit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    /// Height of the block that produced the reward.
    pub height: u64,
    /// Total the pool earned (subsidy + fees).
    pub reward: u64,
    /// How that reward divides between miners, from the share window.
    pub splits: Vec<(MinerId, u64)>,
}

/// Where a payment got to. The unhappy state is deliberately sticky.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentState {
    /// Recorded, and being sent right now. Only ever seen within one run.
    InFlight,
    /// Confirmed away: we have a transaction id.
    Sent,
    /// The process stopped while a payment was in flight, so we cannot tell
    /// whether it reached the network. Held for a human to reconcile — never
    /// re-sent automatically, because a duplicate payment cannot be undone.
    Unresolved,
}

impl PaymentState {
    fn as_str(self) -> &'static str {
        match self {
            PaymentState::InFlight => "inflight",
            PaymentState::Sent => "sent",
            PaymentState::Unresolved => "unresolved",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "inflight" => Some(PaymentState::InFlight),
            "sent" => Some(PaymentState::Sent),
            "unresolved" => Some(PaymentState::Unresolved),
            _ => None,
        }
    }
}

/// One outgoing payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub id: u64,
    pub miner: MinerId,
    pub amount: u64,
    pub state: PaymentState,
    /// Transaction id, once known.
    pub txid: Option<String>,
}

/// The pool's books.
#[derive(Debug, Default)]
pub struct PayoutLedger {
    /// Found blocks not yet buried deep enough to credit.
    rounds: Vec<Round>,
    /// Credited but not yet sent, per miner.
    owed: BTreeMap<MinerId, u64>,
    payments: Vec<Payment>,
    next_payment_id: u64,
    /// Running total ever credited, so [`Self::audit`] can prove nothing leaked.
    credited_total: u128,
    /// Running total the operator has kept from matured rounds.
    operator_total: u128,
    path: Option<PathBuf>,
}

impl PayoutLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger backed by `path`, loading it if it exists.
    ///
    /// Any payment left `InFlight` by an earlier run is promoted to
    /// `Unresolved`: the process died between "about to send" and "sent", so
    /// whether the miner got the money is unknown, and only the chain can say.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let mut ledger = if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            Self::parse(&text)
        } else {
            Self::default()
        };
        for p in &mut ledger.payments {
            if p.state == PaymentState::InFlight {
                p.state = PaymentState::Unresolved;
            }
        }
        ledger.path = Some(path);
        Ok(ledger)
    }

    /// Record a block the pool found. Nothing is owed yet — see `mature`.
    ///
    /// `reward` is the block's **whole** reward and `splits` is what miners get
    /// from it; the difference is the operator's fee, which is recorded so the
    /// ledger accounts for every atomic unit of every block rather than leaving
    /// an unexplained gap for whoever reads it later.
    pub fn record_block(&mut self, height: u64, reward: u64, splits: Vec<(MinerId, u64)>) {
        self.rounds.push(Round { height, reward, splits });
    }

    /// What the operator has kept from rounds the chain has buried — money it
    /// has actually realised.
    ///
    /// Mirrors `credited_total` deliberately: a round that has not matured can
    /// still be erased by a reorg, so counting its fee as earned would be the
    /// same mistake as crediting a miner early.
    pub fn operator_total(&self) -> u128 {
        self.operator_total
    }

    /// The fee from rounds still waiting to mature — expected, not earned.
    pub fn operator_pending(&self) -> u128 {
        self.rounds.iter().map(Self::round_fee).sum()
    }

    /// A round's operator fee: what the block paid, less what miners were
    /// credited from it. Derived from the record rather than stored separately,
    /// so the two can never disagree.
    fn round_fee(r: &Round) -> u128 {
        let to_miners: u128 = r.splits.iter().map(|(_, a)| *a as u128).sum();
        (r.reward as u128).saturating_sub(to_miners)
    }

    /// Credit every round the chain has now buried by `maturity` blocks,
    /// returning how many were credited.
    pub fn mature(&mut self, chain_height: u64, maturity: u64) -> usize {
        let (ready, waiting): (Vec<Round>, Vec<Round>) = std::mem::take(&mut self.rounds)
            .into_iter()
            .partition(|r| chain_height >= r.height.saturating_add(maturity));
        self.rounds = waiting;
        for round in &ready {
            for (miner, amount) in &round.splits {
                *self.owed.entry(miner.clone()).or_insert(0) += *amount;
                self.credited_total += *amount as u128;
            }
            // The operator's cut is realised at exactly the same moment the
            // miners' is, and for the same reason: before maturity a reorg can
            // still erase the block.
            self.operator_total += Self::round_fee(round);
        }
        ready.len()
    }

    /// Miners owed at least `threshold`, largest first.
    ///
    /// A threshold matters: every payment costs a fee, so sending dust would
    /// burn more than it delivers.
    pub fn payable(&self, threshold: u64) -> Vec<(MinerId, u64)> {
        let mut out: Vec<(MinerId, u64)> = self
            .owed
            .iter()
            .filter(|(_, &amount)| amount >= threshold && amount > 0)
            .map(|(m, &a)| (m.clone(), a))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// What `miner` is owed right now.
    pub fn owed(&self, miner: &str) -> u64 {
        self.owed.get(miner).copied().unwrap_or(0)
    }

    /// All outstanding balances.
    pub fn all_owed(&self) -> &BTreeMap<MinerId, u64> {
        &self.owed
    }

    pub fn payments(&self) -> &[Payment] {
        &self.payments
    }

    /// Rounds still waiting on maturity.
    pub fn pending_rounds(&self) -> &[Round] {
        &self.rounds
    }

    /// Reserve `amount` for `miner` and record the intent to send it.
    ///
    /// **Call this — and let it persist — before sending anything.** The balance
    /// leaves `owed` here, so a crash cannot leave the pool believing it still
    /// owes money it may already have paid.
    pub fn begin_payment(&mut self, miner: &str, amount: u64) -> std::io::Result<u64> {
        let owed = self.owed.get(miner).copied().unwrap_or(0);
        let amount = amount.min(owed);
        let id = self.next_payment_id;
        self.next_payment_id += 1;
        if amount == owed {
            self.owed.remove(miner);
        } else {
            self.owed.insert(miner.to_string(), owed - amount);
        }
        self.payments.push(Payment {
            id,
            miner: miner.to_string(),
            amount,
            state: PaymentState::InFlight,
            txid: None,
        });
        self.save()?;
        Ok(id)
    }

    /// The payment reached the network.
    pub fn complete_payment(&mut self, id: u64, txid: &str) -> std::io::Result<()> {
        if let Some(p) = self.payments.iter_mut().find(|p| p.id == id) {
            p.state = PaymentState::Sent;
            p.txid = Some(txid.to_string());
        }
        self.save()
    }

    /// The send failed *before* reaching the network, so the money is still
    /// ours: give it back to the miner's balance.
    ///
    /// Only call this when the failure is unambiguous (e.g. the wallet refused
    /// to build the transaction). If it is not certain the transaction never
    /// went out, leave the payment in flight and let it become `Unresolved`.
    pub fn fail_payment(&mut self, id: u64) -> std::io::Result<()> {
        if let Some(p) = self.payments.iter_mut().find(|p| p.id == id) {
            if p.state == PaymentState::InFlight {
                let (miner, amount) = (p.miner.clone(), p.amount);
                self.payments.retain(|p| p.id != id);
                *self.owed.entry(miner).or_insert(0) += amount;
            }
        }
        self.save()
    }

    /// The send failed in a way that leaves it *unknown* whether the
    /// transaction reached the network — a timeout, a dropped connection after
    /// the request went out. The balance is not returned and the payment is not
    /// retried; it is held for reconciliation, exactly as a crash would be.
    pub fn mark_unresolved(&mut self, id: u64) -> std::io::Result<()> {
        if let Some(p) = self.payments.iter_mut().find(|p| p.id == id) {
            if p.state == PaymentState::InFlight {
                p.state = PaymentState::Unresolved;
            }
        }
        self.save()
    }

    /// Payments needing human attention.
    pub fn unresolved(&self) -> Vec<&Payment> {
        self.payments.iter().filter(|p| p.state == PaymentState::Unresolved).collect()
    }

    /// Every credited unit is either still owed or covered by a payment record.
    ///
    /// This is the ledger's core invariant: value can move between "owed" and
    /// "paid", but none may appear or vanish.
    pub fn audit(&self) -> bool {
        let owed: u128 = self.owed.values().map(|&v| v as u128).sum();
        let recorded: u128 = self.payments.iter().map(|p| p.amount as u128).sum();
        owed + recorded == self.credited_total
    }

    // --- persistence ---------------------------------------------------------

    /// Write the ledger out, replacing the file atomically so a crash mid-write
    /// cannot leave a half-file that loses balances.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(self.serialize().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    fn serialize(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("credited {}\n", self.credited_total));
        out.push_str(&format!("operator {}\n", self.operator_total));
        out.push_str(&format!("next_payment {}\n", self.next_payment_id));
        for r in &self.rounds {
            let splits: Vec<String> =
                r.splits.iter().map(|(m, a)| format!("{m}={a}")).collect();
            out.push_str(&format!("round {} {} {}\n", r.height, r.reward, splits.join(",")));
        }
        for (miner, amount) in &self.owed {
            out.push_str(&format!("owed {miner} {amount}\n"));
        }
        for p in &self.payments {
            out.push_str(&format!(
                "payment {} {} {} {} {}\n",
                p.id,
                p.miner,
                p.amount,
                p.state.as_str(),
                p.txid.as_deref().unwrap_or("-")
            ));
        }
        out
    }

    fn parse(text: &str) -> Self {
        let mut l = Self::default();
        for line in text.lines() {
            let mut f = line.split_whitespace();
            match f.next() {
                Some("credited") => l.credited_total = f.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                // Absent from ledgers written before fees existed, which is
                // exactly right for them: those pools kept nothing.
                Some("operator") => l.operator_total = f.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                Some("next_payment") => {
                    l.next_payment_id = f.next().and_then(|v| v.parse().ok()).unwrap_or(0)
                }
                Some("round") => {
                    let (Some(h), Some(r), Some(s)) = (f.next(), f.next(), f.next()) else { continue };
                    let (Ok(height), Ok(reward)) = (h.parse(), r.parse()) else { continue };
                    let splits = s
                        .split(',')
                        .filter_map(|kv| {
                            let (m, a) = kv.split_once('=')?;
                            Some((m.to_string(), a.parse().ok()?))
                        })
                        .collect();
                    l.rounds.push(Round { height, reward, splits });
                }
                Some("owed") => {
                    let (Some(m), Some(a)) = (f.next(), f.next()) else { continue };
                    if let Ok(amount) = a.parse() {
                        l.owed.insert(m.to_string(), amount);
                    }
                }
                Some("payment") => {
                    let (Some(id), Some(m), Some(a), Some(st)) =
                        (f.next(), f.next(), f.next(), f.next())
                    else {
                        continue;
                    };
                    let (Ok(id), Ok(amount)) = (id.parse(), a.parse()) else { continue };
                    let Some(state) = PaymentState::parse(st) else { continue };
                    let txid = f.next().filter(|t| *t != "-").map(|t| t.to_string());
                    l.payments.push(Payment { id, miner: m.to_string(), amount, state, txid });
                }
                _ => {}
            }
        }
        l
    }

    /// Path this ledger persists to, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// Share a transaction fee across the miners being paid, and return what each
/// actually receives.
///
/// A pool earns exactly the block reward and owes all of it to miners, so it has
/// nothing of its own left to pay the transaction fee with — the fee has to come
/// out of the payment. Splitting it in proportion to each miner's amount is the
/// fair division, and it is exact: the shares sum to precisely `fee` (largest
/// remainder), so `Σ net + fee == Σ owed` and the pool neither over- nor
/// under-spends.
///
/// Returns `(miner, owed, net)`. A miner whose share of the fee would swallow
/// the whole payment is dropped — paying them nothing while marking them settled
/// would quietly confiscate their work.
pub fn deduct_fee(payees: &[(MinerId, u64)], fee: u64) -> Vec<(MinerId, u64, u64)> {
    let total: u128 = payees.iter().map(|(_, a)| *a as u128).sum();
    if total == 0 {
        return Vec::new();
    }
    // Proportional share of the fee, floored, then the remainder handed out
    // largest-first so the shares add up to exactly `fee`.
    let mut shares: Vec<(usize, u64, u128)> = payees
        .iter()
        .enumerate()
        .map(|(i, (_, amount))| {
            let exact = (fee as u128) * (*amount as u128);
            ((i), (exact / total) as u64, exact % total)
        })
        .collect();
    let assigned: u64 = shares.iter().map(|(_, s, _)| *s).sum();
    let mut leftover = fee.saturating_sub(assigned);
    shares.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    for entry in shares.iter_mut() {
        if leftover == 0 {
            break;
        }
        entry.1 += 1;
        leftover -= 1;
    }
    shares.sort_by_key(|(i, _, _)| *i);

    payees
        .iter()
        .zip(shares)
        .filter_map(|((miner, owed), (_, share, _))| {
            let net = owed.checked_sub(share)?;
            (net > 0).then(|| (miner.clone(), *owed, net))
        })
        .collect()
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    /// The property everything else rests on: the operator's cut and the
    /// miners' pool sum to **exactly** the reward. Not approximately, not within
    /// a unit — a pool that loses one atomic unit per block loses it forever,
    /// and one that gains one is minting.
    #[test]
    fn a_fee_never_creates_or_loses_a_single_atomic_unit() {
        let rewards = [
            0u64,
            1,
            2,
            3,
            7,
            9_999,
            10_000,
            10_001,
            1_000_000_000_000,
            u64::MAX / 10_000,
            u64::MAX,
        ];
        // Includes the awkward ones: rates that do not divide the reward, and
        // the extremes at both ends.
        let rates: [FeeBps; 10] = [0, 1, 7, 33, 100, 250, 999, 5_000, 9_999, FEE_BPS_MAX];
        for &reward in &rewards {
            for &bps in &rates {
                let (fee, miners) = apply_fee(reward, bps);
                assert_eq!(
                    fee.checked_add(miners),
                    Some(reward),
                    "reward {reward} at {bps}bps split to {fee} + {miners}"
                );
            }
        }
    }

    /// A fee has to actually be the rate advertised, or the whole mechanism is a
    /// lie told to miners.
    #[test]
    fn the_fee_is_the_rate_that_was_advertised() {
        // 1% of a round number is exact and easy to check by eye.
        assert_eq!(apply_fee(1_000_000, 100), (10_000, 990_000));
        // 0.5%.
        assert_eq!(apply_fee(1_000_000, 50), (5_000, 995_000));
        // 2.5%.
        assert_eq!(apply_fee(1_000_000, 250), (25_000, 975_000));
        // No fee configured means no fee taken.
        assert_eq!(apply_fee(1_000_000, 0), (0, 1_000_000));
    }

    /// Rounding goes to the miners, deliberately. The operator writes the code
    /// and picks the rate; the party without that power gets the sub-unit.
    #[test]
    fn rounding_favours_the_miners() {
        // 1% of 99 is 0.99 — floors to nothing for the operator.
        assert_eq!(apply_fee(99, 100), (0, 99));
        // 33.33% of 10 is 3.333.
        let (fee, miners) = apply_fee(10, 3_333);
        assert_eq!((fee, miners), (3, 7));
        // Over many blocks the operator is never ahead of its stated rate.
        let mut taken = 0u128;
        for reward in 1..500u64 {
            taken += apply_fee(reward, 100).0 as u128;
        }
        let exact: u128 = (1..500u64).map(|r| r as u128).sum::<u128>() / 100;
        assert!(taken <= exact, "took {taken}, exact would be {exact}");
    }

    /// A fee above 100% must not invert the split and hand the operator more
    /// than the block was worth. The daemon refuses such a rate, but the
    /// function is the last line and must be safe on its own.
    #[test]
    fn an_absurd_rate_cannot_take_more_than_the_block() {
        for bps in [FEE_BPS_MAX, FEE_BPS_MAX + 1, u32::MAX] {
            let (fee, miners) = apply_fee(1_000_000, bps);
            assert!(fee <= 1_000_000, "{bps}bps took {fee} from 1000000");
            assert_eq!(fee + miners, 1_000_000);
        }
    }

    /// The operator's cut is realised at maturity, the same moment the miners'
    /// is — before that a reorg can still erase the block, and counting it early
    /// would be the same mistake as crediting a miner early.
    #[test]
    fn the_operator_earns_only_once_the_block_matures() {
        let mut l = PayoutLedger::new();
        let (fee, to_miners) = apply_fee(1_000_000, 100);
        l.record_block(10, 1_000_000, vec![("alice".to_string(), to_miners)]);

        assert_eq!(l.operator_total(), 0, "nothing is earned before maturity");
        assert_eq!(l.operator_pending(), fee as u128, "but it is visible as pending");

        // Not yet buried.
        assert_eq!(l.mature(60, 60), 0);
        assert_eq!(l.operator_total(), 0);

        assert_eq!(l.mature(70, 60), 1);
        assert_eq!(l.operator_total(), fee as u128);
        assert_eq!(l.operator_pending(), 0);
        assert_eq!(l.owed("alice"), to_miners);
        // And the miners' books still balance — the fee is outside them.
        assert!(l.audit());
    }

    /// A ledger written before fees existed has no `operator` line. It must load
    /// as "kept nothing", which is exactly what those pools did.
    #[test]
    fn an_older_ledger_loads_as_having_taken_no_fee() {
        let old = "credited 500\nnext_payment 1\nowed alice 500\n";
        let l = PayoutLedger::parse(old);
        assert_eq!(l.operator_total(), 0);
        assert_eq!(l.owed("alice"), 500);

        // And a ledger with fees round-trips.
        let mut fresh = PayoutLedger::new();
        fresh.record_block(1, 1_000, vec![("bob".to_string(), 990)]);
        fresh.mature(100, 60);
        let round_tripped = PayoutLedger::parse(&fresh.serialize());
        assert_eq!(round_tripped.operator_total(), 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn splits() -> Vec<(MinerId, u64)> {
        vec![("alice".into(), 700), ("bob".into(), 300)]
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("noct_payout_{name}"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_block_owes_nobody_until_the_chain_buries_it() {
        // Pool income is a coinbase output: it cannot be spent for `maturity`
        // blocks, and until then a reorg could erase it entirely.
        let mut l = PayoutLedger::new();
        l.record_block(100, 1_000, splits());
        assert_eq!(l.owed("alice"), 0, "nothing is owed the moment a block is found");

        assert_eq!(l.mature(159, 60), 0, "one block short of maturity");
        assert_eq!(l.owed("alice"), 0);

        assert_eq!(l.mature(160, 60), 1, "buried deep enough");
        assert_eq!(l.owed("alice"), 700);
        assert_eq!(l.owed("bob"), 300);
        assert!(l.pending_rounds().is_empty());
        assert!(l.audit());
    }

    #[test]
    fn dust_is_held_back_until_it_is_worth_a_fee() {
        let mut l = PayoutLedger::new();
        l.record_block(1, 1_000, splits());
        l.mature(1_000, 60);

        let payable = l.payable(500);
        assert_eq!(payable, vec![("alice".to_string(), 700)], "only alice clears the threshold");
        // Bob keeps his balance; it accrues rather than being lost.
        assert_eq!(l.owed("bob"), 300);
    }

    #[test]
    fn a_completed_payment_moves_the_balance_and_conserves_value() {
        let mut l = PayoutLedger::new();
        l.record_block(1, 1_000, splits());
        l.mature(1_000, 60);

        let id = l.begin_payment("alice", 700).unwrap();
        assert_eq!(l.owed("alice"), 0, "reserved out of the balance before sending");
        assert!(l.audit(), "value is conserved while in flight");

        l.complete_payment(id, "deadbeef").unwrap();
        let p = &l.payments()[0];
        assert_eq!(p.state, PaymentState::Sent);
        assert_eq!(p.txid.as_deref(), Some("deadbeef"));
        assert!(l.audit());
    }

    #[test]
    fn a_send_that_never_left_is_refunded() {
        let mut l = PayoutLedger::new();
        l.record_block(1, 1_000, splits());
        l.mature(1_000, 60);

        let id = l.begin_payment("alice", 700).unwrap();
        l.fail_payment(id).unwrap();
        assert_eq!(l.owed("alice"), 700, "an unambiguous failure returns the balance");
        assert!(l.payments().is_empty());
        assert!(l.audit());
    }

    #[test]
    fn a_crash_mid_payment_is_never_silently_repaid() {
        // THE property: sending money and recording it cannot be atomic. If we
        // die in between, the money must NOT be handed out again — a duplicate
        // payment is unrecoverable, while a late one is merely annoying.
        let path = tmp("crash");
        let id;
        {
            let mut l = PayoutLedger::open(&path).unwrap();
            l.record_block(1, 1_000, splits());
            l.mature(1_000, 60);
            l.save().unwrap();
            id = l.begin_payment("alice", 700).unwrap();
            // …process dies here, after `begin_payment` persisted, before we
            // could learn whether the transaction went out.
        }

        let reloaded = PayoutLedger::open(&path).unwrap();
        let p = reloaded.payments().iter().find(|p| p.id == id).unwrap();
        assert_eq!(p.state, PaymentState::Unresolved, "in-flight becomes unresolved on restart");
        assert_eq!(reloaded.owed("alice"), 0, "the balance is NOT restored — that would risk paying twice");
        assert!(
            !reloaded.payable(1).iter().any(|(m, _)| m == "alice"),
            "alice is not queued for payment again"
        );
        // Other miners are unaffected: one ambiguous payment must not freeze the
        // whole pool's payouts.
        assert_eq!(reloaded.payable(1), vec![("bob".to_string(), 300)]);
        assert_eq!(reloaded.unresolved().len(), 1, "it is surfaced for reconciliation");
        assert!(reloaded.audit(), "value is still accounted for");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_ledger_survives_a_restart_intact() {
        let path = tmp("roundtrip");
        {
            let mut l = PayoutLedger::open(&path).unwrap();
            l.record_block(10, 1_000, splits());
            l.record_block(500, 2_000, vec![("carol".into(), 2_000)]);
            l.mature(100, 60); // only the first round matures
            let id = l.begin_payment("alice", 700).unwrap();
            l.complete_payment(id, "abc123").unwrap();
        }

        let l = PayoutLedger::open(&path).unwrap();
        assert_eq!(l.owed("bob"), 300);
        assert_eq!(l.owed("alice"), 0);
        assert_eq!(l.pending_rounds().len(), 1, "the immature round is still waiting");
        assert_eq!(l.pending_rounds()[0].height, 500);
        let p = &l.payments()[0];
        assert_eq!((p.state, p.txid.as_deref()), (PaymentState::Sent, Some("abc123")));
        assert!(l.audit());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_fee_comes_out_of_the_payment_and_balances_exactly() {
        // A pool owes miners the entire block reward, so it has nothing of its
        // own to pay the transaction fee with. The fee must come out of the
        // payment — and the arithmetic has to be exact, or the wallet is asked
        // to spend more than it holds (which is how the first live payout ran
        // straight into InsufficientFunds).
        let payees = vec![("alice".to_string(), 700u64), ("bob".to_string(), 300u64)];
        let fee = 10;
        let out = deduct_fee(&payees, fee);

        let gross: u64 = out.iter().map(|(_, g, _)| *g).sum();
        let net: u64 = out.iter().map(|(_, _, n)| *n).sum();
        assert_eq!(gross, 1_000);
        assert_eq!(net + fee, gross, "spend exactly what the pool holds");
        // Proportional: alice covers 70% of the fee, bob 30%.
        assert_eq!(out[0], ("alice".to_string(), 700, 693));
        assert_eq!(out[1], ("bob".to_string(), 300, 297));
    }

    #[test]
    fn fee_splitting_is_exact_for_awkward_divisions() {
        for miners in [1usize, 3, 7, 11] {
            for fee in [1u64, 7, 999, 100_000] {
                let payees: Vec<(MinerId, u64)> =
                    (0..miners).map(|i| (format!("m{i}"), 1_000_000 + i as u64)).collect();
                let out = deduct_fee(&payees, fee);
                let gross: u64 = out.iter().map(|(_, g, _)| *g).sum();
                let net: u64 = out.iter().map(|(_, _, n)| *n).sum();
                assert_eq!(net + fee, gross, "{miners} miners, fee {fee}");
            }
        }
    }

    #[test]
    fn a_payment_the_fee_would_swallow_is_left_for_later() {
        // Sending nothing while marking the balance settled would quietly
        // confiscate a miner's work, so a payment that the fee consumes entirely
        // is dropped instead — the balance stays owed until it is worth sending.
        // (Reachable only on a misconfigured fee; `payable(threshold)` normally
        // keeps small balances out of the batch.)
        let payees = vec![("a".to_string(), 10u64), ("b".to_string(), 5u64)];
        assert!(deduct_fee(&payees, 15).is_empty(), "a fee equal to the total pays nobody");
        assert!(deduct_fee(&payees, 999).is_empty(), "a fee beyond the total pays nobody");

        // A proportional share that rounds down to nothing still pays: the
        // larger payee absorbs the rounding, which is why a tiny balance is not
        // dropped here.
        let mixed = vec![("whale".to_string(), 1_000_000u64), ("small".to_string(), 1u64)];
        let out = deduct_fee(&mixed, 1_000);
        assert_eq!(out.len(), 2);
        let net: u64 = out.iter().map(|(_, _, n)| *n).sum();
        let gross: u64 = out.iter().map(|(_, g, _)| *g).sum();
        assert_eq!(net + 1_000, gross, "still exact");
    }

    #[test]
    fn paying_more_than_is_owed_is_clamped() {
        let mut l = PayoutLedger::new();
        l.record_block(1, 1_000, splits());
        l.mature(1_000, 60);
        let id = l.begin_payment("alice", 999_999).unwrap();
        assert_eq!(l.payments()[0].amount, 700, "a payment can never exceed the balance");
        assert_eq!(l.owed("alice"), 0);
        l.complete_payment(id, "x").unwrap();
        assert!(l.audit());
    }
}
