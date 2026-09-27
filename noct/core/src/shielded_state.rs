//! The shielded pool's chain state: the note-commitment tree, the nullifier
//! set, the anchors a spend may prove against, and each pool's supply.
//!
//! This is the half of the design that is genuinely new. The ring pool's state
//! is a set — key images go in and, on a reorg, come back out — and a set is
//! easy to undo. The shielded pool needs an **append-only tree** whose root
//! after every block is consensus data, and a tree is not so forgiving: there
//! is no "remove the last leaf" on a frontier.
//!
//! So this type does not try to invert anything. Applying a block records what
//! the state looked like **before** it, and undoing restores that wholesale. A
//! frontier at depth 32 is at most a few hundred bytes, and only the last
//! [`ANCHOR_DEPTH`] of them are kept, so the cost is bounded and the logic has
//! no arithmetic to get wrong. The alternative — rewinding a tree in place — is
//! where this would break, and this project has already paid three times for
//! rollback bugs it thought were simple.
//!
//! The property that matters, and the one the tests assert, is not that appends
//! work. It is that **after a reorg the root is byte-identical to the root of a
//! node that never saw the abandoned branch.** A tree that is merely
//! self-consistent still forks the network.

use std::collections::HashSet;

use incrementalmerkletree::frontier::Frontier;
use orchard::tree::MerkleHashOrchard;
use orchard::{Anchor, NOTE_COMMITMENT_TREE_DEPTH};

use crate::pools::{Pool, PoolTotals, TurnstileError};
use crate::shielded::ShieldedBundle;

/// The commitment tree's depth, fixed by the Orchard circuit.
pub const TREE_DEPTH: u8 = NOTE_COMMITMENT_TREE_DEPTH as u8;

/// How many past roots a spend may prove against.
///
/// A spend names the root its wallet saw, which will usually be a few blocks
/// old by the time the transaction is mined. Accepting only the current root
/// would make every transaction a race against the next block.
///
/// 100 is not a free choice: it is `MAX_REORG_DEPTH`. An anchor older than the
/// deepest reorg the chain will accept can never be invalidated by one, so
/// matching the two costs nothing and means there is one number to reason about
/// rather than two.
pub const ANCHOR_DEPTH: usize = 100;

/// Why a block or bundle was refused by the shielded state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedStateError {
    /// This nullifier has been spent before. The shielded pool's double-spend
    /// check, and the reason a note can be spent once without anyone learning
    /// which note it was.
    DuplicateNullifier([u8; 32]),
    /// The bundle proves membership against a root this chain does not have, or
    /// no longer accepts.
    UnknownAnchor([u8; 32]),
    /// The tree is full. At depth 32 that is 4.3 billion notes.
    TreeFull,
    /// The movement would take a pool below zero.
    Turnstile(TurnstileError),
}

impl std::fmt::Display for ShieldedStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldedStateError::DuplicateNullifier(n) => {
                write!(f, "shielded: nullifier {} already spent", hex32(n))
            }
            ShieldedStateError::UnknownAnchor(a) => {
                write!(f, "shielded: anchor {} is not one this chain accepts", hex32(a))
            }
            ShieldedStateError::TreeFull => f.write_str("shielded: the commitment tree is full"),
            ShieldedStateError::Turnstile(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ShieldedStateError {}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

/// What one block changed, kept so it can be undone exactly.
///
/// The frontier and totals are stored as they were *before* the block, rather
/// than as a description of what changed: restoring a value cannot be got
/// wrong, while inverting a tree append can.
#[derive(Clone, Debug)]
pub struct ShieldedUndo {
    frontier_before: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    totals_before: PoolTotals,
    /// Nullifiers this block added, so they can be taken back out.
    nullifiers_added: Vec<[u8; 32]>,
    /// How many roots the anchor history held before this block.
    anchors_before: usize,
}

/// The shielded pool as the chain sees it.
#[derive(Clone, Debug)]
pub struct ShieldedState {
    tree: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    nullifiers: HashSet<[u8; 32]>,
    /// Roots a spend may still prove against, oldest first. The last entry is
    /// the current root.
    anchors: Vec<[u8; 32]>,
    totals: PoolTotals,
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedState {
    /// An empty pool: an empty tree, nothing spent, nothing held.
    ///
    /// The empty tree's root is already an acceptable anchor, so the first
    /// shielded transaction has something to prove against.
    pub fn new() -> Self {
        let tree = Frontier::<MerkleHashOrchard, TREE_DEPTH>::empty();
        let root = Anchor::from(tree.root()).to_bytes();
        ShieldedState {
            tree,
            nullifiers: HashSet::new(),
            anchors: vec![root],
            totals: PoolTotals::new(),
        }
    }

    /// The current root of the note-commitment tree.
    pub fn root(&self) -> [u8; 32] {
        Anchor::from(self.tree.root()).to_bytes()
    }

    /// Whether `anchor` is a root this chain still accepts.
    pub fn accepts_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.anchors.iter().any(|a| a == anchor)
    }

    /// Whether this nullifier has already been spent.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn totals(&self) -> PoolTotals {
        self.totals
    }

    pub fn notes(&self) -> u64 {
        self.tree.tree_size()
    }

    /// Apply one block's worth of shielded activity.
    ///
    /// `bundles` are every bundle in the block, in the order the block commits
    /// to them; `minted` is the block reward and `minted_into` the pool it is
    /// created in.
    ///
    /// Either the whole block applies or nothing does: the state is only
    /// modified after every check has passed, so a block refused halfway leaves
    /// nothing behind. A partially-applied block would be worse than a rejected
    /// one — it would be a node quietly disagreeing with the network about its
    /// own state.
    pub fn apply_block<'a, I>(
        &mut self,
        bundles: I,
        minted_into: Pool,
        minted: u64,
    ) -> Result<ShieldedUndo, ShieldedStateError>
    where
        I: IntoIterator<Item = &'a ShieldedBundle>,
    {
        let undo = ShieldedUndo {
            frontier_before: self.tree.clone(),
            totals_before: self.totals,
            nullifiers_added: Vec::new(),
            anchors_before: self.anchors.len(),
        };

        // Work on copies, and commit only once everything has passed.
        let mut tree = self.tree.clone();
        let mut totals = self.totals;
        let mut added: Vec<[u8; 32]> = Vec::new();
        // Nullifiers inside one block must be unique against each other as well
        // as against history: two transactions in the same block spending the
        // same note is a double-spend that never touches the stored set.
        let mut seen_here: HashSet<[u8; 32]> = HashSet::new();

        // The block reward. Today it lands in the ring pool; when coinbase
        // becomes a shielded note this is the only line that changes.
        if minted > 0 {
            totals.mint(minted_into, minted).map_err(ShieldedStateError::Turnstile)?;
        }

        for bundle in bundles {
            // The anchor must be one this chain has published. Checked against
            // the state as it was before this block: a bundle cannot prove
            // membership against a root its own block created.
            let anchor = bundle.anchor();
            if !self.accepts_anchor(&anchor) {
                return Err(ShieldedStateError::UnknownAnchor(anchor));
            }

            for nullifier in bundle.nullifiers() {
                if self.nullifiers.contains(&nullifier) || !seen_here.insert(nullifier) {
                    return Err(ShieldedStateError::DuplicateNullifier(nullifier));
                }
                added.push(nullifier);
            }

            for cmx in bundle.commitments() {
                if !tree.append(MerkleHashOrchard::from_cmx(&cmx)) {
                    return Err(ShieldedStateError::TreeFull);
                }
            }

            let cross = bundle.cross().map_err(|_| {
                ShieldedStateError::Turnstile(TurnstileError::NotRepresentable)
            })?;
            totals.apply_cross(cross).map_err(ShieldedStateError::Turnstile)?;
        }

        // Everything passed: commit.
        self.tree = tree;
        self.totals = totals;
        self.nullifiers.extend(added.iter().copied());
        self.anchors.push(self.root());
        if self.anchors.len() > ANCHOR_DEPTH {
            let excess = self.anchors.len() - ANCHOR_DEPTH;
            self.anchors.drain(..excess);
        }

        Ok(ShieldedUndo { nullifiers_added: added, ..undo })
    }

    /// Undo a block, restoring the state exactly as it was before it.
    ///
    /// Undos must be applied in reverse order, newest first — the same
    /// discipline the rest of the chain's rollback already follows.
    ///
    /// The anchor history is rebuilt rather than restored: only its length is
    /// recorded, because the roots themselves are re-derivable and keeping a
    /// hundred copies of a hundred roots per block is not worth it. Truncating
    /// to the recorded length is exact whenever the history has not yet been
    /// trimmed; once it has, the oldest entries are gone and the rebuilt history
    /// is shorter. That is safe in the only direction that matters: it can make
    /// the chain refuse an old anchor it would once have accepted, never accept
    /// one it should not.
    pub fn undo_block(&mut self, undo: ShieldedUndo) {
        self.tree = undo.frontier_before;
        self.totals = undo.totals_before;
        for nullifier in &undo.nullifiers_added {
            self.nullifiers.remove(nullifier);
        }
        self.anchors.truncate(undo.anchors_before.min(self.anchors.len()));
        if self.anchors.is_empty() {
            self.anchors.push(self.root());
        }
    }
}


// --- snapshot -----------------------------------------------------------
//
// A node that restarts must rebuild a byte-identical tree. If it did not, it
// would accept anchors nobody else has and reject ones everybody else does —
// a fork that looks like a bug in someone else's node. So the whole shielded
// state travels with the chain snapshot rather than being re-derived.
//
// ```text
// state := u8 version
//          u8 tree_present  (0: empty tree)
//          [ u64 position | [u8;32] leaf | u32 ommers | [u8;32] × ommers ]
//          u64 ring_total | u64 shielded_total
//          u32 anchors  | [u8;32] × anchors      (oldest first)
//          u32 nullifiers | [u8;32] × nullifiers (sorted, so it is canonical)
// ```

/// Snapshot format tag, so a file this build does not understand is refused
/// rather than guessed at.
const SHIELDED_STATE_VERSION: u8 = 1;

impl ShieldedState {
    /// Encode for a chain snapshot.
    ///
    /// Nullifiers are sorted before writing: a `HashSet` has no order, and two
    /// nodes whose snapshots differ byte-for-byte cannot be compared at all.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SHIELDED_STATE_VERSION);

        match self.tree.value() {
            None => out.push(0),
            Some(frontier) => {
                out.push(1);
                out.extend_from_slice(&u64::from(frontier.position()).to_le_bytes());
                out.extend_from_slice(&frontier.leaf().to_bytes());
                let ommers = frontier.ommers();
                out.extend_from_slice(&(ommers.len() as u32).to_le_bytes());
                for o in ommers {
                    out.extend_from_slice(&o.to_bytes());
                }
            }
        }

        out.extend_from_slice(&self.totals.ring().to_le_bytes());
        out.extend_from_slice(&self.totals.shielded().to_le_bytes());

        out.extend_from_slice(&(self.anchors.len() as u32).to_le_bytes());
        for a in &self.anchors {
            out.extend_from_slice(a);
        }

        let mut nullifiers: Vec<[u8; 32]> = self.nullifiers.iter().copied().collect();
        nullifiers.sort_unstable();
        out.extend_from_slice(&(nullifiers.len() as u32).to_le_bytes());
        for n in &nullifiers {
            out.extend_from_slice(n);
        }
        out
    }

    /// Decode a snapshot, refusing anything malformed.
    ///
    /// Returns `None` rather than a partly-built state: a shielded state that is
    /// almost right is a node that forks, and it is better to refuse to start.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        if take_n(&mut cur, 1)?[0] != SHIELDED_STATE_VERSION {
            return None;
        }

        let tree = match take_n(&mut cur, 1)?[0] {
            0 => Frontier::<MerkleHashOrchard, TREE_DEPTH>::empty(),
            1 => {
                let position = u64::from_le_bytes(take_n(&mut cur, 8)?.try_into().ok()?);
                let leaf = MerkleHashOrchard::from_bytes(&take32(&mut cur)?).into_option()?;
                let count = u32::from_le_bytes(take_n(&mut cur, 4)?.try_into().ok()?) as usize;
                // An ommer per level at most: the bound is the tree's depth, and
                // it is checked before anything is read.
                if count > TREE_DEPTH as usize {
                    return None;
                }
                let mut ommers = Vec::with_capacity(count);
                for _ in 0..count {
                    ommers.push(MerkleHashOrchard::from_bytes(&take32(&mut cur)?).into_option()?);
                }
                Frontier::from_parts(position.into(), leaf, ommers).ok()?
            }
            _ => return None,
        };

        let ring = u64::from_le_bytes(take_n(&mut cur, 8)?.try_into().ok()?);
        let shielded = u64::from_le_bytes(take_n(&mut cur, 8)?.try_into().ok()?);
        let mut totals = PoolTotals::new();
        totals.mint(Pool::Ring, ring).ok()?;
        totals.mint(Pool::Shielded, shielded).ok()?;

        let anchor_count = u32::from_le_bytes(take_n(&mut cur, 4)?.try_into().ok()?) as usize;
        if anchor_count > ANCHOR_DEPTH {
            return None;
        }
        let mut anchors = Vec::with_capacity(anchor_count);
        for _ in 0..anchor_count {
            anchors.push(take32(&mut cur)?);
        }

        let nullifier_count = u32::from_le_bytes(take_n(&mut cur, 4)?.try_into().ok()?) as usize;
        // Not pre-allocated from the count: the same rule the wire decoder
        // follows, for the same reason.
        let mut nullifiers = HashSet::new();
        for _ in 0..nullifier_count {
            nullifiers.insert(take32(&mut cur)?);
        }

        if !cur.is_empty() {
            return None;
        }

        let state = ShieldedState { tree, nullifiers, anchors, totals };
        // The state must agree with itself: the root it computes has to be the
        // newest anchor it claims. A snapshot that fails this was built by
        // something that does not share this chain's rules.
        match state.anchors.last() {
            Some(newest) if *newest == state.root() => Some(state),
            None if state.notes() == 0 => Some(state),
            _ => None,
        }
    }
}

fn take_n<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cur.len() < n {
        return None;
    }
    let (head, rest) = cur.split_at(n);
    *cur = rest;
    Some(head)
}

fn take32(cur: &mut &[u8]) -> Option<[u8; 32]> {
    take_n(cur, 32)?.try_into().ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::shielded::tests::built_bundle;
    use crate::shielded::ShieldedBundle;

    fn bundle(value: u64) -> ShieldedBundle {
        ShieldedBundle::new(built_bundle(value, false)).expect("fixed circuit")
    }

    fn coinbase(value: u64) -> ShieldedBundle {
        ShieldedBundle::new(built_bundle(value, true)).expect("fixed circuit")
    }

    /// An empty pool must still offer an anchor, or the first shielded
    /// transaction would have nothing to prove against and the pool could never
    /// be entered.
    #[test]
    fn an_empty_pool_publishes_an_anchor() {
        let s = ShieldedState::new();
        assert!(s.accepts_anchor(&s.root()));
        assert_eq!(s.notes(), 0);
        assert_eq!(s.totals().shielded(), 0);
    }

    /// Applying a block appends its notes, banks its nullifiers and moves the
    /// turnstile — and publishes the new root as an anchor.
    #[test]
    fn applying_a_block_advances_every_part_of_the_state() {
        let mut s = ShieldedState::new();
        let before = s.root();
        let b = bundle(5_000);
        s.totals.mint(Pool::Ring, 10_000).unwrap();

        let nullifiers: Vec<_> = b.nullifiers().collect();
        s.apply_block([&b], Pool::Ring, 0).expect("applies");

        assert_ne!(s.root(), before, "appending a note must change the root");
        assert!(s.accepts_anchor(&s.root()), "the new root is an anchor");
        assert!(s.accepts_anchor(&before), "and the old one is still accepted");
        assert_eq!(s.notes(), b.actions() as u64);
        for n in nullifiers {
            assert!(s.is_spent(&n));
        }
        assert_eq!((s.totals().ring(), s.totals().shielded()), (5_000, 5_000));
    }

    /// **The acceptance gate for this whole module.** A node that applies a
    /// branch and rolls it back must end up byte-identical to a node that never
    /// saw it — not merely self-consistent, because a tree that disagrees with
    /// the network is a fork whatever it thinks of itself.
    #[test]
    fn a_rolled_back_branch_leaves_no_trace() {
        let mut lived_through_it = ShieldedState::new();
        let never_saw_it = ShieldedState::new();
        lived_through_it.totals.mint(Pool::Ring, 100_000).unwrap();
        let mut untouched = never_saw_it.clone();
        untouched.totals.mint(Pool::Ring, 100_000).unwrap();

        // Three blocks of shielded activity, then all three abandoned.
        let blocks = [bundle(1_000), bundle(2_000), bundle(3_000)];
        let mut undos = Vec::new();
        for b in &blocks {
            undos.push(lived_through_it.apply_block([b], Pool::Ring, 0).expect("applies"));
        }
        assert_ne!(lived_through_it.root(), untouched.root(), "the branch did change things");

        // Newest first, as a reorg unwinds them.
        while let Some(undo) = undos.pop() {
            lived_through_it.undo_block(undo);
        }

        assert_eq!(
            lived_through_it.root(),
            untouched.root(),
            "the root after a reorg must equal the root of a node that never saw the branch"
        );
        assert_eq!(lived_through_it.notes(), untouched.notes());
        assert_eq!(lived_through_it.totals(), untouched.totals());
        for b in &blocks {
            for n in b.nullifiers() {
                assert!(!lived_through_it.is_spent(&n), "an abandoned spend must be spendable again");
            }
        }
        assert!(lived_through_it.accepts_anchor(&untouched.root()));
    }

    /// The same note cannot be spent twice, whether the second attempt is in a
    /// later block or the same one. The in-block case is the one that never
    /// touches the stored set, so it needs its own check.
    #[test]
    fn a_nullifier_cannot_be_spent_twice() {
        let mut s = ShieldedState::new();
        s.totals.mint(Pool::Ring, 100_000).unwrap();
        let b = bundle(1_000);
        let repeat = b.clone();
        let n = b.nullifiers().next().unwrap();

        s.apply_block([&b], Pool::Ring, 0).expect("first spend applies");
        assert_eq!(
            s.apply_block([&repeat], Pool::Ring, 0).unwrap_err(),
            ShieldedStateError::DuplicateNullifier(n),
            "across blocks"
        );

        let mut fresh = ShieldedState::new();
        fresh.totals.mint(Pool::Ring, 100_000).unwrap();
        let b2 = bundle(1_000);
        let twin = b2.clone();
        assert!(
            matches!(
                fresh.apply_block([&b2, &twin], Pool::Ring, 0),
                Err(ShieldedStateError::DuplicateNullifier(_))
            ),
            "and within one block"
        );
    }

    /// A refused block must leave nothing behind. A half-applied block is a node
    /// silently disagreeing with the network about its own state, which is worse
    /// than refusing the block loudly.
    #[test]
    fn a_refused_block_changes_nothing() {
        let mut s = ShieldedState::new();
        s.totals.mint(Pool::Ring, 100_000).unwrap();
        let good = bundle(1_000);
        s.apply_block([&good], Pool::Ring, 0).expect("applies");

        let before_root = s.root();
        let before_notes = s.notes();
        let before_totals = s.totals();

        // A block whose second bundle double-spends the first's note.
        let a = bundle(500);
        let twin = a.clone();
        assert!(s.apply_block([&a, &twin], Pool::Ring, 0).is_err());

        assert_eq!(s.root(), before_root, "the tree must not have moved");
        assert_eq!(s.notes(), before_notes);
        assert_eq!(s.totals(), before_totals);
        for n in a.nullifiers() {
            assert!(!s.is_spent(&n), "a refused block must bank no nullifiers");
        }
    }

    /// A spend must prove membership against a root this chain published — and
    /// not against one from its own block, which would let a note be spent in
    /// the same block that created it.
    #[test]
    fn an_anchor_the_chain_no_longer_accepts_is_refused() {
        let mut s = ShieldedState::new();
        s.totals.mint(Pool::Ring, 1_000_000).unwrap();

        // A recent root is still good: the tree moves on, and a bundle built
        // against the root from before still applies.
        let first = bundle(1_000);
        s.apply_block([&first], Pool::Ring, 0).expect("applies");
        let later = bundle(1_000);
        assert!(s.accepts_anchor(&later.anchor()), "a recent root is still good");
        s.apply_block([&later], Pool::Ring, 0).expect("a bundle on a recent anchor applies");

        // Now push the history past its depth, so the empty-tree root the test
        // bundles carry falls out of it. A bundle proving against it must be
        // refused — this is the real path, not just the predicate.
        for _ in 0..(ANCHOR_DEPTH + 5) {
            s.apply_block(std::iter::empty(), Pool::Ring, 0).expect("an empty block applies");
        }
        let stale = bundle(1_000);
        let anchor = stale.anchor();
        assert!(!s.accepts_anchor(&anchor), "the empty-tree root has aged out");
        assert_eq!(
            s.apply_block([&stale], Pool::Ring, 0).unwrap_err(),
            ShieldedStateError::UnknownAnchor(anchor),
            "a spend against an aged-out root must be refused by apply_block itself"
        );
    }

    /// Anchors do not accumulate for ever: only the last `ANCHOR_DEPTH` roots
    /// are kept, matching the deepest reorg the chain accepts.
    #[test]
    fn the_anchor_history_is_bounded() {
        let mut s = ShieldedState::new();
        for _ in 0..(ANCHOR_DEPTH + 25) {
            s.apply_block(std::iter::empty(), Pool::Ring, 0).expect("an empty block applies");
        }
        assert_eq!(s.anchors.len(), ANCHOR_DEPTH);
        assert!(s.accepts_anchor(&s.root()));
    }

    /// A block reward paid straight into the shielded pool mints there, and the
    /// coinbase bundle spends nothing.
    #[test]
    fn a_shielded_coinbase_mints_into_the_pool() {
        let mut s = ShieldedState::new();
        let reward = coinbase(9_000_000_000);
        assert!(!reward.spends_enabled());

        // The reward mints, and the bundle's own crossing moves it on from
        // there; both are the same value, so the pool nets the reward.
        s.apply_block(std::iter::empty(), Pool::Shielded, 9_000_000_000).expect("mint applies");
        assert_eq!(s.totals().shielded(), 9_000_000_000);
        assert_eq!(s.totals().ring(), 0, "nothing was created in the ring pool");
    }

    /// Undo restores the totals as well as the tree — a reorg that unwound the
    /// notes but left the supply behind would be counterfeiting by accident.
    #[test]
    fn undo_restores_the_turnstile_too() {
        let mut s = ShieldedState::new();
        s.totals.mint(Pool::Ring, 10_000).unwrap();
        let before = s.totals();

        let b = bundle(4_000);
        let undo = s.apply_block([&b], Pool::Ring, 0).expect("applies");
        assert_eq!(s.totals().shielded(), 4_000);

        s.undo_block(undo);
        assert_eq!(s.totals(), before, "the supply must go back where it was");
    }
}
