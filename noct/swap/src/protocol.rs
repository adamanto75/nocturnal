//! The atomic-swap protocol state machine — the core of `noct-swapd`.
//!
//! Pure logic, no I/O (mirrors `noct_node::NodeState`): it consumes observed
//! **events** (both-chain observations + timeouts + local abort) and returns the
//! **action** to perform. The daemon wraps it with the two chain clients (an
//! Ethereum JSON-RPC client for `NoctSwap.sol`, and a Noct node/wallet client for
//! the joint account), a timer, and a persisted copy of this state so a restart
//! never misses a refund window.
//!
//! Roles mirror `NoctSwap.sol`: **Alice** provides ETH and wants NOCT (deploys the
//! contract, can refund); **Bob** provides NOCT and wants ETH (locks the joint
//! account, can claim).
//!
//! ## Where safety lives
//!
//! This FSM is safe *given correctly-formed events*, which is the I/O layer's job:
//! * `NoctLocked` must fire only once Bob's lock is buried at a safe **depth**
//!   (Noct reorg safety — a young chain is reorg-prone).
//! * `EthFunded` must fire only after Bob has **verified** the contract's
//!   commitments, amount, and timeouts match what was agreed.
//! * The timeout events must be driven off the *contract's* `timeout1`/`timeout2`
//!   with margin, never raced.
//!
//! Under those conditions no honest party can lose funds: every committed state
//! has a recovery path (Alice refunds → Bob reclaims via the revealed secret, or
//! vice versa), and `claim`/`refund` are mutually exclusive on-chain.

/// Which side of the swap this daemon runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Holds ETH, wants NOCT. Deploys + funds the contract; can refund.
    Alice,
    /// Holds NOCT, wants ETH. Locks the joint account; can claim.
    Bob,
}

/// Protocol state. Terminals record *how* the swap ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Off-chain key + DLEQ exchange (joint account assembled, commitments agreed).
    Exchanging,
    /// (Alice) contract deployed + funded; awaiting Bob's NOCT lock.
    EthFunded,
    /// (Alice) `setReady` done; awaiting Bob's claim.
    Ready,
    /// (Bob) awaiting Alice's funded, verified contract.
    AwaitingEth,
    /// (Bob) NOCT locked; awaiting the claim window (ready / timeout1) or a refund.
    NoctLocked,
    /// (Alice, success) read Bob's secret and swept the NOCT.
    SweptNoct,
    /// (Bob, success) claimed the ETH.
    GotEth,
    /// (Alice, recovered) refunded her ETH after an abort/timeout.
    RefundedEth,
    /// (Bob, recovered) reclaimed his NOCT after Alice refunded.
    ReclaimedNoct,
    /// Aborted before committing any funds — nothing at risk.
    Cancelled,
}

/// Something the daemon observed (from a chain, a timer, or a local decision).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// Off-chain setup complete: DLEQ proofs verified, joint account assembled.
    KeysExchanged,
    /// Bob: Alice's contract is deployed, funded, and matches the agreed terms.
    EthFunded,
    /// Alice: Bob's NOCT lock is confirmed at a safe depth.
    NoctLocked,
    /// Bob: Alice called `setReady`.
    ReadySet,
    /// Alice: Bob called `claim`, revealing his secret `s_b` on-chain.
    Claimed([u8; 32]),
    /// Bob: Alice called `refund`, revealing her secret `s_a` on-chain.
    Refunded([u8; 32]),
    /// The contract's `timeout1` passed.
    Timeout1,
    /// The contract's `timeout2` passed.
    Timeout2,
    /// Local decision to abort (only safe before committing funds, or via refund).
    Abort,
}

/// What the daemon must do next. The secret-bearing actions carry the
/// counterparty's revealed half; the daemon combines it with its own to
/// reconstruct the joint NOCT spend key (`noct_wallet::joint`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Nothing to do (waiting on an external event).
    None,
    /// Alice: deploy + fund `NoctSwap.sol`.
    FundEth,
    /// Bob: lock NOCT to the joint account.
    LockNoct,
    /// Alice: call `setReady`.
    SetReady,
    /// Bob: call `claim`, revealing our secret on-chain.
    ClaimEth,
    /// Alice: call `refund`, revealing our secret on-chain.
    RefundEth,
    /// Alice: reconstruct `s_a + s_b` and sweep the joint NOCT account.
    SweepNoct { counterparty_secret: [u8; 32] },
    /// Bob: reconstruct `s_a + s_b` and reclaim the joint NOCT account.
    ReclaimNoct { counterparty_secret: [u8; 32] },
}

/// The swap state machine for one party.
#[derive(Clone, Copy, Debug)]
pub struct Swap {
    role: Role,
    state: State,
}

impl Swap {
    pub fn new(role: Role) -> Self {
        Swap { role, state: State::Exchanging }
    }

    pub fn role(&self) -> Role {
        self.role
    }
    pub fn state(&self) -> State {
        self.state
    }

    /// Apply `event`, transition, and return the action to perform. An event that
    /// doesn't apply to the current (role, state) is a harmless no-op — the daemon
    /// may observe irrelevant or duplicate events.
    pub fn step(&mut self, event: Event) -> Action {
        use Action as A;
        use Event as E;
        use Role::{Alice, Bob};
        use State as S;

        let (next, action) = match (self.role, self.state, event) {
            // --- off-chain setup ---
            (Alice, S::Exchanging, E::KeysExchanged) => (S::EthFunded, A::FundEth),
            (Bob, S::Exchanging, E::KeysExchanged) => (S::AwaitingEth, A::None),
            (_, S::Exchanging, E::Abort) => (S::Cancelled, A::None),

            // --- Alice (ETH provider) ---
            // Bob's NOCT lock confirmed → enable his claim.
            (Alice, S::EthFunded, E::NoctLocked) => (S::Ready, A::SetReady),
            // Bob never locked, or we abort → refund before timeout1 (allowed
            // while not yet READY).
            (Alice, S::EthFunded, E::Abort) | (Alice, S::EthFunded, E::Timeout1) => {
                (S::RefundedEth, A::RefundEth)
            }
            // Bob claimed → his secret is on-chain → reconstruct + sweep the NOCT.
            (Alice, S::Ready, E::Claimed(s)) => (S::SweptNoct, A::SweepNoct { counterparty_secret: s }),
            // Bob never claimed → refund after timeout2.
            (Alice, S::Ready, E::Timeout2) => (S::RefundedEth, A::RefundEth),

            // --- Bob (NOCT provider) ---
            // Verified funded contract → lock the NOCT.
            (Bob, S::AwaitingEth, E::EthFunded) => (S::NoctLocked, A::LockNoct),
            // Nothing committed yet → abort cleanly.
            (Bob, S::AwaitingEth, E::Abort) => (S::Cancelled, A::None),
            // READY set, or timeout1 passed → claim the ETH (contract allows both).
            (Bob, S::NoctLocked, E::ReadySet) | (Bob, S::NoctLocked, E::Timeout1) => {
                (S::GotEth, A::ClaimEth)
            }
            // Alice refunded (revealing s_a) → reconstruct + reclaim the NOCT.
            (Bob, S::NoctLocked, E::Refunded(s)) => {
                (S::ReclaimedNoct, A::ReclaimNoct { counterparty_secret: s })
            }

            // Everything else (terminal state, or an event that doesn't apply): no-op.
            _ => (self.state, A::None),
        };
        self.state = next;
        action
    }

    /// Has the swap reached any terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            State::SweptNoct
                | State::GotEth
                | State::RefundedEth
                | State::ReclaimedNoct
                | State::Cancelled
        )
    }

    /// Did our side get the asset it wanted?
    pub fn succeeded(&self) -> bool {
        matches!(self.state, State::SweptNoct | State::GotEth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S_A: [u8; 32] = [0xa5; 32];
    const S_B: [u8; 32] = [0xb6; 32];

    #[test]
    fn alice_happy_path_ends_in_swept_noct() {
        let mut a = Swap::new(Role::Alice);
        assert_eq!(a.step(Event::KeysExchanged), Action::FundEth);
        assert_eq!(a.state(), State::EthFunded);
        assert_eq!(a.step(Event::NoctLocked), Action::SetReady);
        assert_eq!(a.state(), State::Ready);
        assert_eq!(a.step(Event::Claimed(S_B)), Action::SweepNoct { counterparty_secret: S_B });
        assert!(a.succeeded());
        assert_eq!(a.state(), State::SweptNoct);
    }

    #[test]
    fn bob_happy_path_ends_in_got_eth() {
        let mut b = Swap::new(Role::Bob);
        assert_eq!(b.step(Event::KeysExchanged), Action::None);
        assert_eq!(b.state(), State::AwaitingEth);
        assert_eq!(b.step(Event::EthFunded), Action::LockNoct);
        assert_eq!(b.state(), State::NoctLocked);
        assert_eq!(b.step(Event::ReadySet), Action::ClaimEth);
        assert!(b.succeeded());
        assert_eq!(b.state(), State::GotEth);
    }

    #[test]
    fn bob_can_claim_after_timeout1_if_alice_never_readied() {
        let mut b = Swap::new(Role::Bob);
        b.step(Event::KeysExchanged);
        b.step(Event::EthFunded);
        assert_eq!(b.step(Event::Timeout1), Action::ClaimEth);
        assert!(b.succeeded());
    }

    #[test]
    fn alice_refunds_before_ready_if_bob_never_locks() {
        let mut a = Swap::new(Role::Alice);
        a.step(Event::KeysExchanged); // EthFunded
        assert_eq!(a.step(Event::Timeout1), Action::RefundEth);
        assert_eq!(a.state(), State::RefundedEth);
        assert!(a.is_terminal() && !a.succeeded());
    }

    #[test]
    fn alice_refunds_after_timeout2_if_bob_never_claims() {
        let mut a = Swap::new(Role::Alice);
        a.step(Event::KeysExchanged);
        a.step(Event::NoctLocked); // Ready
        assert_eq!(a.step(Event::Timeout2), Action::RefundEth);
        assert_eq!(a.state(), State::RefundedEth);
    }

    #[test]
    fn bob_reclaims_noct_when_alice_refunds() {
        let mut b = Swap::new(Role::Bob);
        b.step(Event::KeysExchanged);
        b.step(Event::EthFunded); // NoctLocked
        assert_eq!(
            b.step(Event::Refunded(S_A)),
            Action::ReclaimNoct { counterparty_secret: S_A }
        );
        assert_eq!(b.state(), State::ReclaimedNoct);
        assert!(b.is_terminal() && !b.succeeded());
    }

    #[test]
    fn aborting_before_commitment_cancels_cleanly() {
        let mut b = Swap::new(Role::Bob);
        b.step(Event::KeysExchanged); // AwaitingEth
        assert_eq!(b.step(Event::Abort), Action::None);
        assert_eq!(b.state(), State::Cancelled);
    }

    #[test]
    fn alice_never_sweeps_noct_without_bobs_revealed_secret() {
        // In Ready, only a `Claimed` event (which carries s_b) can trigger a sweep;
        // any other event must NOT produce a SweepNoct action.
        for ev in [Event::Timeout1, Event::ReadySet, Event::NoctLocked, Event::EthFunded] {
            let mut a = Swap::new(Role::Alice);
            a.step(Event::KeysExchanged);
            a.step(Event::NoctLocked); // Ready
            let action = a.step(ev);
            assert!(
                !matches!(action, Action::SweepNoct { .. }),
                "no sweep without a Claimed event (got {action:?})"
            );
            assert_ne!(a.state(), State::SweptNoct);
        }
    }

    #[test]
    fn terminal_states_ignore_further_events() {
        let mut a = Swap::new(Role::Alice);
        a.step(Event::KeysExchanged);
        a.step(Event::NoctLocked);
        a.step(Event::Claimed(S_B)); // SweptNoct (terminal)
        // Later, stray events change nothing.
        assert_eq!(a.step(Event::Timeout2), Action::None);
        assert_eq!(a.step(Event::Refunded(S_A)), Action::None);
        assert_eq!(a.state(), State::SweptNoct);
    }
}
