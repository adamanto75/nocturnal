//! The shielded half of the wallet: Orchard keys, note scanning, and witnesses.
//!
//! This is a second wallet living inside the same wallet, and almost nothing it
//! does resembles the ring side. Three differences drive the whole design.
//!
//! **Finding your money is trial decryption, not tagging.** A ring output can be
//! recognised cheaply: the wallet derives the one-time key the sender would have
//! used and compares. An Orchard action gives away nothing, so the only way to
//! know whether a note is yours is to attempt to decrypt it with your incoming
//! viewing key and see whether it works. Every action, every block. That cost is
//! the price of the anonymity set being every note ever created rather than
//! sixteen, and it is the thing that decides whether a light wallet is possible.
//!
//! **A note's position matters, and it is not where you found it.** A note's
//! Merkle path is what a spend proves against, so the wallet has to know exactly
//! which leaf its note is. Leaf order is consensus, and a coinbase note does not
//! enter the tree in the block that created it — it is withheld until it matures
//! (`noct_core::shielded_state`). So the wallet does not decide positions: it
//! asks [`ShieldedState::block_commitments`] for the order and matches its own
//! commitments against it. There is exactly one statement of that ordering, in
//! core, and this module is a consumer of it.
//!
//! **A witness has to be maintained, not derived.** The node keeps only a
//! frontier, which is enough to append and to state a root. A path to a
//! *particular* leaf cannot be recovered from a frontier afterwards, so the
//! wallet must start a witness at the moment its note is appended and feed every
//! subsequent leaf into it, for as long as the note is unspent. That is new state
//! and it is why this module keeps its own copy of the tree.
//!
//! ## Reorgs
//!
//! This wallet does not roll back, and that is deliberate. The ring side already
//! settled the policy: a node shorter than the wallet has scanned is reported and
//! the caller rebuilds, because that "can cost time, never correctness"
//! ([`crate::client`]). Inverting a witness is exactly the kind of arithmetic the
//! node refused to do to its own tree — it restores a frontier rather than
//! un-appending — and a wallet doing it would be doing something harder with less
//! to check it against.
//!
//! So instead every block is checked: [`ShieldedWallet::scan_block`] compares its
//! tree against the chain's root and refuses to continue if they differ, and
//! [`ShieldedWallet::path`] refuses to hand out a path from a tree that has
//! drifted. A reorg surfaces as an error at the block that caused it, not as a
//! transaction rejected for no visible reason a week later.
//!
//! ## What is on disk
//!
//! The rule the ring side follows — nothing that can spend is written down —
//! holds here too, and means something slightly different. An Orchard note
//! plaintext does not let its reader spend: spending needs the spend authorizing
//! key, which comes from the seed and is never stored. So a saved note reveals
//! *what* the wallet holds, exactly as the ring records already reveal which
//! outputs are the wallet's and what they were worth, and the file is owner-only
//! for that reason. See [`crate::state`], which persists these records.

use std::collections::{HashMap, HashSet};

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use noct_core::address::{Network, ShieldedAddress};
use noct_core::block::Block;
use noct_core::hash::keccak256;
use noct_core::shielded::ShieldedBundle;
use noct_core::shielded_state::{ShieldedState, TREE_DEPTH};
use noct_core::tx::Transaction;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::Flags;
use orchard::keys::{
    FullViewingKey, IncomingViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey,
    SpendingKey,
};
use orchard::note::{ExtractedNoteCommitment, Note};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::Anchor;
use rand_core::OsRng;
use zip32::AccountId;

/// The wallet's own tree, mirroring the chain's leaf for leaf.
pub type Tree = CommitmentTree<MerkleHashOrchard, TREE_DEPTH>;
/// A live path to one owned note, kept current as the tree grows.
pub type Witness = IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>;

/// Noct's coin type in the ZIP-32 path `m/32'/coin_type'/account'`.
///
/// Noct has no registered SLIP-44 number, so this is a placeholder chosen once
/// and pinned by a test. **Changing it changes every address the wallet derives**,
/// which for anyone already holding notes is indistinguishable from losing them,
/// so it changes only with a migration.
const COIN_TYPE: u32 = 1_337;

/// Why a shielded operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedWalletError {
    /// The seed does not derive a usable Orchard key. ZIP-32 rejects a vanishing
    /// fraction of seeds; the caller should not see this in practice.
    BadSeed,
    /// This wallet holds no note at that position, or it is already spent.
    UnknownNote { position: u64 },
    /// A note's witness has no path. Only possible for a witness that was never
    /// fed the leaf it witnesses, which this module does not construct.
    NoPath { position: u64 },
    /// The wallet's tree has drifted from the chain's: same number of leaves,
    /// different root. Every path it produced would be worthless, so it refuses to
    /// produce more.
    TreeDiverged,
    /// The wallet has taken in fewer notes than the chain holds, which means it
    /// did not start scanning at genesis.
    ///
    /// A distinct error from [`Self::TreeDiverged`] because it is a distinct
    /// mistake with a distinct remedy: nothing has drifted, the wallet simply
    /// began in the middle. A note's position is its index among *every* note the
    /// chain has ever created, so there is no way to join late — the wallet has to
    /// see them all, exactly as the ring side has to see every output to know its
    /// global indices.
    BehindTheChain { scanned: u64, chain: u64 },
    /// A send of nothing. Refused rather than built, because a bundle with no
    /// value is a proof made and verified for no reason.
    NothingToDo,
    /// Not enough spendable value. A note that exists but is not yet in the tree
    /// does not count towards `have` — see [`ShieldedWallet::pending_balance`].
    Insufficient { have: u64, need: u64 },
    /// An amount that does not fit the signed crossing. Noct's whole supply fits
    /// with room to spare, so this is not reachable with real money.
    AmountTooLarge,
    /// The bundle builder refused the plan, or proving failed.
    Build,
    /// The bundle does not move what the plan said it would. Caught here rather
    /// than by the transaction builder, where the proof has already been paid for.
    CrossMismatch { planned: i64, bundle: i64 },
    /// The bundle itself was refused by core.
    Shielded(noct_core::shielded::ShieldedError),
}

impl std::fmt::Display for ShieldedWalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldedWalletError::BadSeed => f.write_str("shielded: seed derives no Orchard key"),
            ShieldedWalletError::UnknownNote { position } => {
                write!(f, "shielded: no unspent note at position {position}")
            }
            ShieldedWalletError::NoPath { position } => {
                write!(f, "shielded: no Merkle path for the note at position {position}")
            }
            ShieldedWalletError::TreeDiverged => {
                f.write_str("shielded: the wallet's commitment tree disagrees with the chain's")
            }
            ShieldedWalletError::BehindTheChain { scanned, chain } => write!(
                f,
                "shielded: {scanned} notes scanned but the chain holds {chain};                  scanning must start at genesis"
            ),
            ShieldedWalletError::NothingToDo => f.write_str("shielded: nothing to send"),
            ShieldedWalletError::Insufficient { have, need } => {
                write!(f, "shielded: {have} spendable, {need} needed")
            }
            ShieldedWalletError::AmountTooLarge => {
                f.write_str("shielded: amount does not fit a crossing")
            }
            ShieldedWalletError::Build => f.write_str("shielded: the bundle could not be built"),
            ShieldedWalletError::CrossMismatch { planned, bundle } => {
                write!(f, "shielded: planned a crossing of {planned}, bundle states {bundle}")
            }
            ShieldedWalletError::Shielded(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ShieldedWalletError {}

/// The wallet's Orchard keys, all derived from the one seed it already has.
///
/// **One seed, both pools.** A Noct wallet is a single 32-byte spend secret, and
/// the 24-word phrase encodes it directly ([`crate::mnemonic`]). The Orchard key
/// is derived from those same bytes, so an existing backup restores the shielded
/// side too and there is no second thing to write down and lose.
///
/// The seed bytes are hashed with a domain tag before ZIP-32 sees them, so the
/// Orchard seed is not the ed25519 spend secret itself. Two systems sharing one
/// secret verbatim is the kind of coupling that is fine until one of them has a
/// flaw that leaks its input.
pub struct ShieldedKeys {
    spending: SpendingKey,
    fvk: FullViewingKey,
    network: Network,
}

impl ShieldedKeys {
    /// Derive the Orchard keys for `account` from a wallet's spend secret.
    ///
    /// `account` is a ZIP-32 account number, so it must be below 2^31.
    pub fn from_spend_secret(
        spend_secret: &[u8; 32],
        account: u32,
        network: Network,
    ) -> Result<Self, ShieldedWalletError> {
        let mut seed = Vec::with_capacity(24 + 32);
        seed.extend_from_slice(b"noct.orchard.seed.v1");
        seed.extend_from_slice(spend_secret);
        let seed = keccak256(&seed);

        // ZIP-32's own entry point, rather than the path spelled out here: the
        // derivation is the standard's to define, and restating it would be one
        // more thing that can quietly stop matching.
        let account =
            AccountId::try_from(account).map_err(|_| ShieldedWalletError::BadSeed)?;
        let spending = SpendingKey::from_zip32_seed(&seed, COIN_TYPE, account)
            .map_err(|_| ShieldedWalletError::BadSeed)?;
        let fvk = FullViewingKey::from(&spending);
        Ok(ShieldedKeys { spending, fvk, network })
    }

    /// The Orchard keys belonging to the same [`Account`] as a wallet's ring keys.
    ///
    /// The point of this existing at all: an account **is** its spend secret, and
    /// both pools' keys come from it. A caller that had to remember to pass the
    /// right 32 bytes could pass the wrong ones and get a wallet that quietly
    /// scans for somebody else's notes.
    ///
    /// [`Account`]: noct_core::keys::Account
    pub fn for_account(
        account: &noct_core::keys::Account,
        network: Network,
    ) -> Result<Self, ShieldedWalletError> {
        Self::from_spend_secret(&account.spend_secret.to_bytes(), 0, network)
    }

    /// The spending key. Held in memory only, never written down by this crate.
    pub fn spending_key(&self) -> &SpendingKey {
        &self.spending
    }

    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// The incoming viewing key scanning uses.
    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        self.fvk.to_ivk(Scope::External)
    }

    /// The outgoing viewing key, which recovers notes this wallet *sent*.
    ///
    /// Without it a wallet cannot see its own outgoing payments after the fact —
    /// it would know a note of its own was spent but not what it paid to whom.
    pub fn outgoing_viewing_key(&self) -> OutgoingViewingKey {
        self.fvk.to_ovk(Scope::External)
    }

    /// The wallet's default shielded receiving address.
    pub fn address(&self) -> ShieldedAddress {
        self.address_at(0)
    }

    /// A shielded address at diversifier index `j`.
    ///
    /// Orchard diversifies addresses at no cost and with no extra scanning: every
    /// address of one account shares one incoming viewing key, so handing out a
    /// fresh one per payer is free. That is unlike the ring side, where each
    /// subaddress is another key to check.
    pub fn address_at(&self, j: u32) -> ShieldedAddress {
        ShieldedAddress::new(self.network, self.fvk.address_at(j, Scope::External))
    }

    /// Whether `address` is one of this wallet's.
    pub fn owns(&self, address: &ShieldedAddress) -> bool {
        address.network == self.network
            && self.incoming_viewing_key().diversifier_index(&address.inner()).is_some()
    }
}

/// One note the wallet owns, with everything needed to spend it.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    /// The note plaintext, recovered by trial decryption.
    pub note: Note,
    /// Which leaf of the commitment tree this note is. Consensus assigns it; the
    /// wallet only observes it.
    pub position: u64,
    /// The height of the block in which the note *entered the tree* — which for a
    /// coinbase note is not the block that created it.
    pub height: u64,
    /// True once the note's nullifier has appeared on chain.
    pub spent: bool,
    /// The height at which that nullifier appeared, when it has.
    ///
    /// Kept because it is the one thing a shielded history needs that cannot be
    /// derived from the notes themselves: a note's own `height` says when it
    /// *entered* the tree, which tells you nothing about when it left.
    pub spent_height: Option<u64>,
    /// True if this note was a block reward. Kept because a wallet should be able
    /// to say where money came from, and because a reward is the one note whose
    /// arrival is delayed.
    pub coinbase: bool,
}

impl OwnedNote {
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }

    /// The note's commitment, as the tree holds it.
    pub fn commitment(&self) -> [u8; 32] {
        ExtractedNoteCommitment::from(self.note.commitment()).to_bytes()
    }
}

/// The shielded wallet: keys, the notes it has found, and the tree they live in.
pub struct ShieldedWallet {
    keys: ShieldedKeys,
    notes: Vec<OwnedNote>,
    /// Live paths for unspent notes, by position. A spent note's witness is
    /// dropped: keeping it would cost work on every block for a path nothing can
    /// use.
    witnesses: HashMap<u64, Witness>,
    /// The wallet's mirror of the chain's tree, leaf for leaf. Its root must equal
    /// the chain's, and if it ever does not, every path this wallet makes is
    /// worthless — so that is checked rather than assumed.
    tree: Tree,
    /// How many leaves the wallet has appended. The position the next one takes.
    leaves: u64,
    /// Nullifiers of notes this wallet owns, so a spend of one is recognised when
    /// it appears in a block. A nullifier reveals nothing until it is published,
    /// which is why this can be computed in advance and kept privately.
    own_nullifiers: HashMap<[u8; 32], u64>,
    /// Commitments the wallet is waiting to see appended, mapped to the note that
    /// will claim that position. A coinbase note is created in one block and
    /// appended maturity blocks later, so this is how the two are joined up.
    expected: HashMap<[u8; 32], PendingNote>,
    /// Notes spent by a bundle this wallet submitted and has **not yet seen
    /// confirmed**: tree position → the height the spend was recorded at.
    ///
    /// The same defect the ring side had, with nullifiers in place of key images:
    /// a note is not spent as far as the chain is concerned until its nullifier is
    /// published in a block, so a second `--from shielded` send a minute later
    /// selects the same note and builds a double-spend of its own. See
    /// [`crate::PENDING_SPEND_BLOCKS`].
    pending_spends: HashMap<u64, u64>,
    /// The height of the last block scanned. Needed because reservations expire,
    /// and note selection — unlike the ring side's — has no chain to ask.
    synced_height: u64,
}

/// One thing that happened to a note: it arrived, or it was spent.
///
/// Deliberately not [`crate::HistoryEntry`]. That type carries a fee, which a
/// note does not have on its own — a shielded spend's fee is a property of the
/// transaction, not of any one note — and reusing it would mean inventing a
/// value for a field that has no meaning here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedHistoryEntry {
    /// Height the note entered the tree (received) or its nullifier appeared (spent).
    pub height: u64,
    /// True for an arrival, false for a spend.
    pub received: bool,
    /// The note's value. Not the payment's: a spend of a larger note returns
    /// change as a second note, which appears as its own arrival.
    pub amount: u64,
    /// True when the arrival was a mined reward.
    pub coinbase: bool,
}

/// A note found by decryption but not yet in the tree.
#[derive(Clone, Debug)]
struct PendingNote {
    note: Note,
    coinbase: bool,
}

impl ShieldedWallet {
    /// A wallet for these keys, having seen nothing.
    pub fn new(keys: ShieldedKeys) -> Self {
        ShieldedWallet {
            keys,
            notes: Vec::new(),
            witnesses: HashMap::new(),
            tree: Tree::empty(),
            leaves: 0,
            own_nullifiers: HashMap::new(),
            pending_spends: HashMap::new(),
            synced_height: 0,
            expected: HashMap::new(),
        }
    }

    pub fn keys(&self) -> &ShieldedKeys {
        &self.keys
    }

    pub fn address(&self) -> ShieldedAddress {
        self.keys.address()
    }

    /// Every note the wallet has found, spent or not.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Notes that are in the tree and not yet spent.
    pub fn unspent(&self) -> impl Iterator<Item = &OwnedNote> {
        self.notes.iter().filter(|n| !n.spent)
    }

    /// Total value of unspent notes.
    pub fn balance(&self) -> u64 {
        self.unspent().map(|n| n.value()).sum()
    }

    /// Value of notes that can actually be spent right now: unspent, in the tree,
    /// and with a live witness.
    ///
    /// Not the same as [`Self::balance`], and the difference matters to a caller
    /// deciding whether to cross value in: a note with no witness is money the
    /// wallet can see and cannot move.
    pub fn spendable_value(&self) -> u64 {
        self.spendable().iter().map(|n| n.value()).sum()
    }

    /// Value the wallet has found but which is not yet in the tree, so not yet
    /// spendable — a shielded block reward waiting out its maturity.
    ///
    /// Reported separately rather than folded into the balance, because a balance
    /// that includes money no anchor can reach is a balance that lies.
    pub fn pending_balance(&self) -> u64 {
        self.expected.values().map(|p| p.note.value().inner()).sum()
    }

    /// How many leaves the wallet has taken in. Must equal the chain's note count.
    pub fn leaves(&self) -> u64 {
        self.leaves
    }

    /// The root of the wallet's tree, for comparing against the chain's.
    pub fn root(&self) -> [u8; 32] {
        orchard::Anchor::from(self.tree.root()).to_bytes()
    }

    /// Take in one block, in chain order.
    ///
    /// `before` and `after` are the chain's shielded state either side of this
    /// block. `before` is the one that carries information — it decides which
    /// coinbase notes are now due, and so what order the leaves take — and
    /// `after` is there to be checked against: this returns
    /// [`ShieldedWalletError::TreeDiverged`] if the wallet's tree does not end up
    /// with the chain's root.
    ///
    /// That check is the point of taking both. Scanning out of order, or with the
    /// state from the wrong side of the block, produces positions that are wrong
    /// and nothing that looks wrong: every balance still adds up, and the failure
    /// surfaces much later as a spend the network rejects for no visible reason.
    /// Comparing roots turns that into an error at the block that caused it.
    ///
    /// Call it for every block the chain accepts, in order, even blocks with
    /// nothing shielded in them — the leaf counter has to stay in step.
    pub fn scan_block(
        &mut self,
        block: &Block,
        txs: &[Transaction],
        before: &ShieldedState,
        after: &ShieldedState,
        maturity: u64,
    ) -> Result<(), ShieldedWalletError> {
        let shielded = before;
        let height = block.coinbase.height;

        // Decrypt first: a note has to be recognised in the block that created it
        // even when it will not enter the tree for another hundred blocks.
        if let Some(bundle) = &block.coinbase.shielded {
            for note in self.decrypt(bundle) {
                self.expect(note, true);
            }
        }
        let bundles: Vec<&ShieldedBundle> = txs.iter().filter_map(|t| t.shielded.as_ref()).collect();
        for bundle in &bundles {
            for note in self.decrypt(bundle) {
                self.expect(note, false);
            }
        }

        // Then the tree, in the one order that is consensus. Asking core rather
        // than restating it is the whole point: a wallet that computed its own
        // order would assign a wrong position the first time the two disagreed,
        // and a proof against a wrong position is money that looks gone.
        for commitment in shielded.block_commitments(bundles.iter().copied(), height, maturity) {
            self.append(commitment, height);
        }

        // And spends. Done after appending so that a note created and spent in the
        // same block is recorded in that order.
        for bundle in &bundles {
            for nullifier in bundle.nullifiers() {
                if let Some(position) = self.own_nullifiers.remove(&nullifier) {
                    if let Some(note) = self.notes.iter_mut().find(|n| n.position == position) {
                        note.spent = true;
                        note.spent_height = Some(height);
                    }
                    self.witnesses.remove(&position);
                    // The spend is on chain: the reservation has done its job.
                    self.pending_spends.remove(&position);
                }
            }
        }

        // Scanning is the only place the wallet learns how far it has synced, and
        // reservations expire against that height.
        self.synced_height = height;
        self.pending_spends
            .retain(|_, at| height < at.saturating_add(crate::PENDING_SPEND_BLOCKS));

        // Two different failures, kept apart because they mean different things.
        // A different leaf count is a wallet that started late. The same count with
        // a different root is a wallet that saw the same notes in another order,
        // which is the one that would silently produce bad paths.
        if self.leaves != after.notes() {
            return Err(ShieldedWalletError::BehindTheChain {
                scanned: self.leaves,
                chain: after.notes(),
            });
        }
        if self.root() != after.root() {
            return Err(ShieldedWalletError::TreeDiverged);
        }
        Ok(())
    }

    /// Trial-decrypt every action of a bundle with this wallet's incoming viewing
    /// key. This is the expensive part of a shielded wallet.
    fn decrypt(&self, bundle: &ShieldedBundle) -> Vec<Note> {
        bundle
            .inner()
            .decrypt_outputs_with_keys(&[self.keys.incoming_viewing_key()])
            .into_iter()
            .map(|(_, _, note, _, _)| note)
            .collect()
    }

    /// Record a note found by decryption, to be claimed when its commitment is
    /// appended.
    fn expect(&mut self, note: Note, coinbase: bool) {
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        self.expected.insert(cmx, PendingNote { note, coinbase });
    }

    /// Append one leaf, claiming it if it is ours.
    fn append(&mut self, commitment: [u8; 32], height: u64) {
        let position = self.leaves;
        self.leaves += 1;

        let Some(cmx) =
            ExtractedNoteCommitment::from_bytes(&commitment).into_option()
        else {
            // Consensus would have refused the block, so this cannot happen from a
            // chain the wallet is following. Counting the leaf anyway keeps the
            // position in step with the chain rather than silently sliding by one.
            return;
        };
        let leaf = MerkleHashOrchard::from_cmx(&cmx);

        // Every live witness sees every subsequent leaf. This is the cost the node
        // does not pay, and it is per unspent note.
        for witness in self.witnesses.values_mut() {
            let _ = witness.append(leaf);
        }
        // `append` on a depth-32 tree only fails when it is full, which is 4.3
        // billion notes away; the chain would have refused the block first.
        let _ = self.tree.append(leaf);

        if let Some(pending) = self.expected.remove(&commitment) {
            // The witness starts from the tree *including* this leaf, which is
            // what makes it a witness to this position rather than the one before.
            if let Some(witness) = Witness::from_tree(self.tree.clone()) {
                self.witnesses.insert(position, witness);
            }
            let nullifier = pending.note.nullifier(self.keys.full_viewing_key());
            self.own_nullifiers.insert(nullifier.to_bytes(), position);
            self.notes.push(OwnedNote {
                note: pending.note,
                position,
                height,
                spent: false,
                spent_height: None,
                coinbase: pending.coinbase,
            });
        }
    }

    /// The Merkle path for an unspent note, for proving it into a spend.
    ///
    /// Refuses if the wallet's tree does not agree with the chain's. A path from a
    /// drifted tree verifies against nothing, and the failure would surface as a
    /// rejected transaction with no explanation — so it is caught here, where the
    /// cause is still visible.
    pub fn path(
        &self,
        position: u64,
        shielded: &ShieldedState,
    ) -> Result<MerklePath, ShieldedWalletError> {
        if self.root() != shielded.root() {
            return Err(ShieldedWalletError::TreeDiverged);
        }
        let witness =
            self.witnesses.get(&position).ok_or(ShieldedWalletError::UnknownNote { position })?;
        witness
            .path()
            .map(MerklePath::from)
            .ok_or(ShieldedWalletError::NoPath { position })
    }

    /// Notes the wallet could spend, largest first, and their paths.
    ///
    /// Largest first is the ordinary choice: it minimises the number of actions,
    /// and each action is a proof to make and a proof for every node to verify.
    pub fn spendable(&self) -> Vec<&OwnedNote> {
        let mut notes: Vec<&OwnedNote> = self
            .unspent()
            .filter(|n| self.witnesses.contains_key(&n.position))
            // Not a note we have already spent in a bundle the chain has not seen
            // yet. Selecting it again builds a double-spend of our own, which the
            // node refuses — the same rule the ring side applies to its outputs.
            .filter(|n| !self.is_pending(n.position))
            .collect();
        notes.sort_by_key(|n| std::cmp::Reverse(n.value()));
        notes
    }

    /// Whether this note is reserved by a submitted bundle that has not confirmed.
    fn is_pending(&self, position: u64) -> bool {
        match self.pending_spends.get(&position) {
            Some(&at) => self.synced_height < at.saturating_add(crate::PENDING_SPEND_BLOCKS),
            None => false,
        }
    }

    /// Record that `tx`'s bundle was submitted at `height`, so the notes it spends
    /// are not spent again before it confirms.
    ///
    /// Call this only once the node has accepted the transaction. Matching is by
    /// nullifier, which is the shielded analogue of a key image: the bundle
    /// publishes them, and the wallet already knows which of its notes each one
    /// belongs to.
    pub fn note_submitted(&mut self, tx: &Transaction, height: u64) {
        let Some(bundle) = tx.shielded.as_ref() else { return };
        for nullifier in bundle.nullifiers() {
            if let Some(&position) = self.own_nullifiers.get(&nullifier) {
                self.pending_spends.insert(position, height);
            }
        }
    }

    /// Value held in notes reserved by unconfirmed spends.
    ///
    /// Reported separately rather than deducted: the money has not left yet, but
    /// it cannot be spent again either.
    pub fn pending_spend_value(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.spent && self.is_pending(n.position))
            .map(|n| n.value())
            .sum()
    }


    /// What has happened to this wallet's notes, newest first.
    ///
    /// **Without this the pool is invisible to its own owner.** A payment received
    /// into the shielded pool raises the balance and appears in no activity list;
    /// a payment sent *inside* the pool has no ring side at all, so the ring
    /// half's history has nothing to show either. The most private shape this
    /// chain can produce was also the one its owner could not account for.
    ///
    /// Derived rather than stored, except for the spend heights: every note the
    /// wallet holds already knows its value, when it entered the tree, and whether
    /// it is a reward. Keeping a second copy of that would be two things to get
    /// out of step.
    ///
    /// One honesty note on heights. A received entry is dated by when the note
    /// **entered the tree**, which for an ordinary payment is the block carrying
    /// it — but for a mined reward is `maturity` blocks after it was earned,
    /// because that is when the note becomes real as far as any anchor is
    /// concerned. The alternative would be to date it from a block the wallet does
    /// not record, so this says which height it is rather than pretending.
    pub fn history(&self) -> Vec<ShieldedHistoryEntry> {
        let mut out: Vec<ShieldedHistoryEntry> = Vec::new();
        for note in &self.notes {
            out.push(ShieldedHistoryEntry {
                height: note.height,
                received: true,
                amount: note.value(),
                coinbase: note.coinbase,
            });
            if let (true, Some(height)) = (note.spent, note.spent_height) {
                out.push(ShieldedHistoryEntry {
                    height,
                    received: false,
                    amount: note.value(),
                    coinbase: false,
                });
            }
        }
        // Newest first, and within a block the receipt before the spend: a note
        // cannot leave before it arrives, and showing it the other way round reads
        // like a mistake.
        out.sort_by(|a, b| b.height.cmp(&a.height).then(a.received.cmp(&b.received)));
        out
    }

    /// Nullifiers of the notes this wallet owns and has not seen spent.
    ///
    /// Useful to a caller that wants to know whether a pending transaction of its
    /// own has landed without waiting for a rescan.
    pub fn watched_nullifiers(&self) -> HashSet<[u8; 32]> {
        self.own_nullifiers.keys().copied().collect()
    }
}


// --- spending ---------------------------------------------------------------

/// What a plan makes public.
///
/// Every shielded send hides its inputs, outputs and amounts inside the proof.
/// What it cannot hide is value *moving between the pools*, because the two pools
/// commit to value in different groups and the only quantity both sides can agree
/// on is a plain integer (see the design doc's §1 and §11). So this is the whole
/// of what a caller has to warn about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revealed {
    /// Nothing but the fee. A move inside the pool.
    Nothing,
    /// This much value entered the shielded pool, publicly.
    AmountEnteringPool(u64),
    /// This much value left it, publicly. For a move inside the pool this is the
    /// fee, which is public in any transaction.
    AmountLeavingPool(u64),
}

/// What a shielded send is asked to do, before any bundle exists.
///
/// Stated as a plan rather than built directly because the bundle's signatures
/// cover the transaction's ring side, which does not exist until the ring builder
/// is part-way through. So the wallet describes the bundle here, hands
/// [`Plan::authorize`] to `Transaction::build_with_shielded`, and the bundle is
/// proved and signed at the moment the sighash is known.
pub struct Plan<'a> {
    keys: &'a ShieldedKeys,
    /// Notes being spent, with the path each proves membership by.
    spends: Vec<(Note, MerklePath)>,
    /// Where value is going inside the pool.
    outputs: Vec<(orchard::Address, u64)>,
    /// The root every spend proves against. One anchor per bundle, by
    /// construction: `Builder::add_spend` refuses a path that does not match it.
    anchor: Anchor,
    /// What the bundle moves, from the ring pool's point of view. Positive means
    /// value is arriving from the ring pool.
    cross: i64,
}

impl Plan<'_> {
    /// The crossing the ring side must declare for this plan.
    pub fn cross(&self) -> i64 {
        self.cross
    }

    /// How many actions the bundle will have, and so what it will cost to make
    /// and to verify. One proof each, about 9 ms to verify and far more to make.
    pub fn actions(&self) -> usize {
        self.spends.len().max(self.outputs.len()).max(1)
    }

    /// What this plan makes public, in words, so a caller can show it rather than
    /// discover it.
    ///
    /// The design's §11 is blunt about the cost and this is the same statement in
    /// code: a crossing publishes its amount, and a move inside the pool publishes
    /// only the fee. A wallet that offers the choice without saying what it costs
    /// is not really offering a choice.
    pub fn reveals(&self) -> Revealed {
        match self.cross {
            0 => Revealed::Nothing,
            c if c > 0 => Revealed::AmountEnteringPool(c as u64),
            c => Revealed::AmountLeavingPool(c.unsigned_abs()),
        }
    }

    /// Prove and sign the bundle over `sighash`.
    ///
    /// Suitable to hand straight to [`noct_core::tx::Transaction::build_with_shielded`],
    /// which is the only thing that knows the sighash.
    pub fn authorize(self, sighash: &[u8; 32]) -> Result<ShieldedBundle, ShieldedWalletError> {
        let mut rng = OsRng;
        // `UNPADDED` rather than the default two-action padding. The design doc's
        // §8 reasoning: padding buys indistinguishability, and the shapes this
        // wallet builds that cross pools are already public in their value
        // balance, so the second proof would buy nothing. A shielded-to-shielded
        // send has no public balance, but it is also the shape the pool is full
        // of, so it is not padding that hides it.
        let mut builder = Builder::new(
            BundleType::UNPADDED,
            noct_core::shielded::bundle_version(),
            Flags::ENABLED,
            self.anchor,
        )
        .map_err(|_| ShieldedWalletError::Build)?;

        for (note, path) in self.spends {
            builder
                .add_spend(self.keys.full_viewing_key().clone(), note, path)
                .map_err(|_| ShieldedWalletError::Build)?;
        }
        for (recipient, value) in self.outputs {
            builder
                // The outgoing viewing key is attached so this wallet can later
                // recover what it sent and to whom. Without it a wallet sees its
                // own note disappear and cannot say where the money went.
                .add_output(
                    Some(self.keys.outgoing_viewing_key()),
                    recipient,
                    NoteValue::from_raw(value),
                    [0u8; 512],
                )
                .map_err(|_| ShieldedWalletError::Build)?;
        }

        let (bundle, _meta) = builder
            .build::<i64>(&mut rng)
            .map_err(|_| ShieldedWalletError::Build)?
            .ok_or(ShieldedWalletError::Build)?;

        let ask = SpendAuthorizingKey::from(self.keys.spending_key());
        let bundle = bundle
            .create_proof(noct_core::shielded::proving_key(), &mut rng)
            .map_err(|_| ShieldedWalletError::Build)?
            .apply_signatures(rng, *sighash, &[ask])
            .map_err(|_| ShieldedWalletError::Build)?;

        let bundle = ShieldedBundle::new(bundle).map_err(ShieldedWalletError::Shielded)?;
        // The two sides must already agree here, not later. `build_with_shielded`
        // checks it too, but by then the proof has been made and the failure is
        // expensive and confusing; this is the same rule where it is cheap.
        let stated = bundle.cross().map_err(ShieldedWalletError::Shielded)?;
        if stated != self.cross {
            return Err(ShieldedWalletError::CrossMismatch { planned: self.cross, bundle: stated });
        }
        Ok(bundle)
    }
}

impl ShieldedWallet {
    /// Plan a move of `amount` **into** the pool, to `to`.
    ///
    /// Nothing is spent — value arrives from the ring side of the same
    /// transaction, whose `cross` must be `+amount`. The bundle's own value
    /// balance is `-amount`, and the two being negations of each other is what
    /// [`ShieldedBundle::cross`] exists to keep straight.
    pub fn plan_shield(
        &self,
        to: &ShieldedAddress,
        amount: u64,
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        if amount == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        Ok(Plan {
            keys: &self.keys,
            spends: Vec::new(),
            outputs: vec![(to.inner(), amount)],
            // No real spends, but Orchard still pads the bundle with dummy spends
            // that prove against this anchor. It must be an anchor the chain still
            // accepts: the empty-tree root is only accepted for the first
            // ~ANCHOR_DEPTH blocks and then ages out of the node's recent-roots
            // window, so a shield built against it on a mature chain is rejected
            // as an UnknownAnchor. Prove against the current tree root instead,
            // which the node always keeps (and tolerates minor sync lag within the
            // window). See `anchor_of`.
            anchor: Anchor::from(self.tree.root()),
            cross: i64::try_from(amount).map_err(|_| ShieldedWalletError::AmountTooLarge)?,
        })
    }

    /// Plan a shield that also sends the ring change into the pool, as a second
    /// note back to this wallet.
    ///
    /// The point is that the transaction then has **no ring output at all**: no
    /// change output to tie the payment back to the sender, and the public
    /// crossing is the whole input rather than the payment. It costs one more
    /// action.
    pub fn plan_shield_with_change(
        &self,
        to: &ShieldedAddress,
        amount: u64,
        change: u64,
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        if amount == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        let crossing = amount.checked_add(change).ok_or(ShieldedWalletError::AmountTooLarge)?;
        let mut outputs = vec![(to.inner(), amount)];
        if change > 0 {
            outputs.push((self.keys.address_at(0).inner(), change));
        }
        Ok(Plan {
            keys: &self.keys,
            spends: Vec::new(),
            outputs,
            anchor: Anchor::from(self.tree.root()),
            cross: i64::try_from(crossing).map_err(|_| ShieldedWalletError::AmountTooLarge)?,
        })
    }

    /// Plan a shield paying **several** recipients inside the pool at once.
    ///
    /// One action per recipient, one public crossing for the total. A pool paying
    /// a batch of shielded miners builds this; splitting it into one transaction
    /// per miner would publish one crossing each and pay a fee each.
    pub fn plan_shield_many(
        &self,
        payments: &[(ShieldedAddress, u64)],
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        let total = payments
            .iter()
            .try_fold(0u64, |acc, (_, a)| acc.checked_add(*a))
            .ok_or(ShieldedWalletError::AmountTooLarge)?;
        if total == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        Ok(Plan {
            keys: &self.keys,
            spends: Vec::new(),
            outputs: payments.iter().map(|(a, v)| (a.inner(), *v)).collect(),
            anchor: Anchor::from(self.tree.root()),
            cross: i64::try_from(total).map_err(|_| ShieldedWalletError::AmountTooLarge)?,
        })
    }

    /// Plan a payout to **several** recipients inside the pool, spending this
    /// wallet's own notes and crossing nothing.
    ///
    /// The fee is not paid here: this is the shielded half of a transaction whose
    /// ring half pays it. A wallet paying purely inside the pool with no ring side
    /// wants [`Self::plan_transfer`], which crosses the fee out.
    pub fn plan_payout(
        &self,
        payments: &[(ShieldedAddress, u64)],
        shielded: &ShieldedState,
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        let total = payments
            .iter()
            .try_fold(0u64, |acc, (_, a)| acc.checked_add(*a))
            .ok_or(ShieldedWalletError::AmountTooLarge)?;
        if total == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        let (spends, change) = self.select(total, shielded)?;
        let mut outputs: Vec<(orchard::Address, u64)> =
            payments.iter().map(|(a, v)| (a.inner(), *v)).collect();
        if change > 0 {
            outputs.push((self.keys.address_at(0).inner(), change));
        }
        let anchor = self.anchor_of(&spends)?;
        Ok(Plan { keys: &self.keys, spends, outputs, anchor, cross: 0 })
    }

    /// Plan a move of `amount` **inside** the pool, to `to`, paying `fee`.
    ///
    /// Notes are selected largest first, and any remainder comes back as change to
    /// this wallet. The fee leaves the pool — that is what `cross = -fee` says —
    /// and the block's coinbase collects it like any other fee. So the transaction
    /// that carries this has **no ring side at all**: no inputs, no outputs, no
    /// range proof, and `0 == 0 + (fee + (-fee))·H` balances.
    pub fn plan_transfer(
        &self,
        to: &ShieldedAddress,
        amount: u64,
        fee: u64,
        shielded: &ShieldedState,
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        if amount == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        let needed = amount.checked_add(fee).ok_or(ShieldedWalletError::AmountTooLarge)?;
        let (spends, change) = self.select(needed, shielded)?;

        let mut outputs = vec![(to.inner(), amount)];
        if change > 0 {
            // Change to a fresh diversified address rather than the default one.
            // Every address of the account shares one incoming viewing key, so
            // this costs no extra scanning and does not put the wallet's public
            // address into a second action.
            outputs.push((self.keys.address_at(0).inner(), change));
        }

        let anchor = self.anchor_of(&spends)?;
        Ok(Plan {
            keys: &self.keys,
            spends,
            outputs,
            anchor,
            // Fee value leaves the pool for the ring side, where fees live.
            cross: -i64::try_from(fee).map_err(|_| ShieldedWalletError::AmountTooLarge)?,
        })
    }

    /// Plan a move of `amount` **out of** the pool, onto the ring side.
    ///
    /// The ring side of the transaction pays it out, and declares `cross =
    /// -amount`. The amount is public — it is the one thing a crossing cannot
    /// hide, see the design's §11 — and that is the cost of leaving.
    pub fn plan_unshield(
        &self,
        amount: u64,
        shielded: &ShieldedState,
    ) -> Result<Plan<'_>, ShieldedWalletError> {
        if amount == 0 {
            return Err(ShieldedWalletError::NothingToDo);
        }
        let (spends, change) = self.select(amount, shielded)?;
        let mut outputs = Vec::new();
        if change > 0 {
            outputs.push((self.keys.address_at(0).inner(), change));
        }
        let anchor = self.anchor_of(&spends)?;
        Ok(Plan {
            keys: &self.keys,
            spends,
            outputs,
            anchor,
            cross: -i64::try_from(amount).map_err(|_| ShieldedWalletError::AmountTooLarge)?,
        })
    }

    /// Notes worth at least `needed`, largest first, with their paths, and the
    /// change left over.
    ///
    /// Largest first minimises the action count, and each action is a proof to
    /// make and a proof every node must verify.
    fn select(
        &self,
        needed: u64,
        shielded: &ShieldedState,
    ) -> Result<(Vec<(Note, MerklePath)>, u64), ShieldedWalletError> {
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for note in self.spendable() {
            if total >= needed {
                break;
            }
            let path = self.path(note.position, shielded)?;
            total = total.saturating_add(note.value());
            chosen.push((note.note, path));
        }
        if total < needed {
            return Err(ShieldedWalletError::Insufficient { have: total, need: needed });
        }
        Ok((chosen, total - needed))
    }

    /// The anchor a set of spends proves against: the chain's current root, which
    /// is what every witness in this wallet is current to.
    fn anchor_of(
        &self,
        spends: &[(Note, MerklePath)],
    ) -> Result<Anchor, ShieldedWalletError> {
        match spends.first() {
            // Every path came from the same tree at the same moment, so taking the
            // root of the first is taking the root of all of them — and
            // `Builder::add_spend` refuses any that disagrees, so this is checked
            // rather than trusted.
            Some((note, path)) => {
                Ok(path.root(ExtractedNoteCommitment::from(note.commitment())))
            }
            None => Ok(Anchor::from(self.tree.root())),
        }
    }
}

// --- persistence ------------------------------------------------------------
//
// What is written and what is deliberately not.
//
// **Written:** the note plaintexts, each note's position and witness, the
// wallet's copy of the tree, and the notes found but not yet in the tree. A note
// plaintext does not let its reader spend — spending needs the spend authorizing
// key, which comes from the seed and is never written — but it does reveal the
// value and the recipient, exactly as the ring records already reveal which
// outputs are the wallet's and what they were worth. The file is owner-only for
// that reason.
//
// **Not written:** anything derived from the spending key. The nullifiers, which
// a scan needs in order to notice its own notes being spent, are *recomputed* on
// load from the notes and the full viewing key, by the same call a scan uses.
// Storing them would add nothing and would hand a reader the ability to watch the
// wallet's spends as they happen.
//
// **Rebuilding by rescanning is always an option** and is never wrong; a file
// that fails any check below is refused so the caller does that instead. What is
// not an option is a file that loads and is subtly wrong, so the checks are
// against the chain rather than against the file itself: the wallet's root must
// be the chain's root, its leaf count the chain's note count, and every unspent
// note's witness must produce a root the chain still accepts. A checksum would
// only catch damage; these catch a file that belongs to another chain, another
// account, or an earlier point in this one.

/// Layout version. An older file is refused and rescanned rather than misread.
const SHIELDED_VERSION: u8 = 3;
/// `recipient 43 ‖ value 8 ‖ rho 32 ‖ rseed 32 ‖ version 1`.
const NOTE_BYTES: usize = 43 + 8 + 32 + 32 + 1;

/// Why a saved shielded wallet was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedStateFileError {
    /// Not a file this build understands, or it does not decode: wrong version, a
    /// truncated body, trailing bytes, a count that disagrees with the bytes
    /// present, or a stored value that is not a valid note, point or tree.
    Malformed,
    /// The file belongs to another account: a note in it is not addressed to this
    /// wallet.
    WrongAccount,
    /// The tree in the file is not the chain's tree. Either the file is from a
    /// different chain, or from an earlier point on this one.
    OutOfStep,
    /// An unspent note's witness does not produce a root this chain accepts, so
    /// the path it would give is worthless.
    StaleWitness { position: u64 },
}

impl std::fmt::Display for ShieldedStateFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldedStateFileError::Malformed => f.write_str("shielded state: malformed"),
            ShieldedStateFileError::WrongAccount => {
                f.write_str("shielded state: written for another account")
            }
            ShieldedStateFileError::OutOfStep => {
                f.write_str("shielded state: its tree is not this chain's tree")
            }
            ShieldedStateFileError::StaleWitness { position } => {
                write!(f, "shielded state: the witness for position {position} is stale")
            }
        }
    }
}

impl std::error::Error for ShieldedStateFileError {}

fn put_opt_hash(out: &mut Vec<u8>, h: &Option<MerkleHashOrchard>) {
    match h {
        Some(h) => {
            out.push(1);
            out.extend_from_slice(&h.to_bytes());
        }
        None => out.extend_from_slice(&[0u8; 33]),
    }
}

fn put_tree(out: &mut Vec<u8>, tree: &Tree) {
    put_opt_hash(out, tree.left());
    put_opt_hash(out, tree.right());
    out.push(tree.parents().len() as u8);
    for p in tree.parents() {
        put_opt_hash(out, p);
    }
}

fn put_witness(out: &mut Vec<u8>, witness: &Witness) {
    put_tree(out, witness.tree());
    out.push(witness.filled().len() as u8);
    for h in witness.filled() {
        out.extend_from_slice(&h.to_bytes());
    }
    match witness.cursor() {
        Some(cursor) => {
            out.push(1);
            put_tree(out, cursor);
        }
        None => out.push(0),
    }
}

/// A cursor that refuses to read past its end, so every `from_bytes` below is a
/// sequence of reads and one length check rather than arithmetic at each step.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ShieldedStateFileError> {
        if self.0.len() < n {
            return Err(ShieldedStateFileError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ShieldedStateFileError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, ShieldedStateFileError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    /// A 32-bit count, refused before anything is allocated if the bytes left
    /// cannot possibly hold that many records of `record` bytes each.
    ///
    /// The length is never used to reserve capacity. A count claiming four billion
    /// records is rejected for the bytes it does not have, not after a four-billion
    /// element allocation.
    fn u32_len(&mut self, record: usize) -> Result<usize, ShieldedStateFileError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        if n.saturating_mul(record) > self.0.len() {
            return Err(ShieldedStateFileError::Malformed);
        }
        Ok(n)
    }

    fn array32(&mut self) -> Result<[u8; 32], ShieldedStateFileError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn hash(&mut self) -> Result<MerkleHashOrchard, ShieldedStateFileError> {
        MerkleHashOrchard::from_bytes(&self.array32()?)
            .into_option()
            .ok_or(ShieldedStateFileError::Malformed)
    }

    fn opt_hash(&mut self) -> Result<Option<MerkleHashOrchard>, ShieldedStateFileError> {
        match self.u8()? {
            0 => {
                // The 32 bytes are still there, so the field is fixed width.
                self.take(32)?;
                Ok(None)
            }
            1 => Ok(Some(self.hash()?)),
            _ => Err(ShieldedStateFileError::Malformed),
        }
    }

    fn tree(&mut self) -> Result<Tree, ShieldedStateFileError> {
        let left = self.opt_hash()?;
        let right = self.opt_hash()?;
        let count = self.u8()? as usize;
        // Bounded before anything is allocated, and by the only bound that can be
        // right: a tree of depth 32 has fewer than 32 parents by construction, so
        // `CommitmentTree::from_parts` refuses more anyway.
        if count >= TREE_DEPTH as usize {
            return Err(ShieldedStateFileError::Malformed);
        }
        let mut parents = Vec::new();
        for _ in 0..count {
            parents.push(self.opt_hash()?);
        }
        Tree::from_parts(left, right, parents).map_err(|_| ShieldedStateFileError::Malformed)
    }

    fn witness(&mut self) -> Result<Witness, ShieldedStateFileError> {
        let tree = self.tree()?;
        let filled_len = self.u8()? as usize;
        if filled_len > TREE_DEPTH as usize {
            return Err(ShieldedStateFileError::Malformed);
        }
        let mut filled = Vec::new();
        for _ in 0..filled_len {
            filled.push(self.hash()?);
        }
        let cursor = match self.u8()? {
            0 => None,
            1 => Some(self.tree()?),
            _ => return Err(ShieldedStateFileError::Malformed),
        };
        Witness::from_parts(tree, filled, cursor).ok_or(ShieldedStateFileError::Malformed)
    }

    fn note(&mut self) -> Result<Note, ShieldedStateFileError> {
        let recipient: [u8; 43] = self.take(43)?.try_into().expect("43 bytes");
        let recipient = orchard::Address::from_raw_address_bytes(&recipient)
            .into_option()
            .ok_or(ShieldedStateFileError::Malformed)?;
        let value = NoteValue::from_raw(self.u64()?);
        let rho = orchard::note::Rho::from_bytes(&self.array32()?)
            .into_option()
            .ok_or(ShieldedStateFileError::Malformed)?;
        let rseed = orchard::note::RandomSeed::from_bytes(self.array32()?, &rho)
            .into_option()
            .ok_or(ShieldedStateFileError::Malformed)?;
        let version = match self.u8()? {
            2 => orchard::NoteVersion::V2,
            3 => orchard::NoteVersion::V3,
            _ => return Err(ShieldedStateFileError::Malformed),
        };
        Note::from_parts(recipient, value, rho, rseed, version)
            .into_option()
            .ok_or(ShieldedStateFileError::Malformed)
    }
}

fn put_note(out: &mut Vec<u8>, note: &Note) {
    out.extend_from_slice(&note.recipient().to_raw_address_bytes());
    out.extend_from_slice(&note.value().inner().to_le_bytes());
    out.extend_from_slice(&note.rho().to_bytes());
    out.extend_from_slice(note.rseed().as_bytes());
    out.push(match note.version() {
        orchard::NoteVersion::V2 => 2,
        orchard::NoteVersion::V3 => 3,
    });
}

impl ShieldedWallet {
    /// Everything this wallet would otherwise have to rescan for.
    ///
    /// See the comment above this section for what is in it and what is not.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SHIELDED_VERSION);
        out.extend_from_slice(&self.leaves.to_le_bytes());
        put_tree(&mut out, &self.tree);

        out.extend_from_slice(&(self.notes.len() as u32).to_le_bytes());
        for note in &self.notes {
            put_note(&mut out, &note.note);
            out.extend_from_slice(&note.position.to_le_bytes());
            out.extend_from_slice(&note.height.to_le_bytes());
            out.push(u8::from(note.spent) | (u8::from(note.coinbase) << 1));
            // A spent note keeps no witness — nothing can use a path to it — so
            // the flag above says whether one follows.
            if !note.spent {
                match self.witnesses.get(&note.position) {
                    Some(witness) => {
                        out.push(1);
                        put_witness(&mut out, witness);
                    }
                    None => out.push(0),
                }
            } else {
                // Only a spent note needs this, and 0 stands for "we do not know"
                // — a note cannot be spent in the genesis block, so the value is
                // free to mean absent.
                out.extend_from_slice(&note.spent_height.unwrap_or(0).to_le_bytes());
            }
        }

        // Notes found but not yet in the tree: a shielded reward waiting out its
        // maturity. Without these a reload would never claim its position, and the
        // money would stay invisible until a full rescan.
        out.extend_from_slice(&(self.expected.len() as u32).to_le_bytes());
        // Sorted, so the same wallet always writes the same bytes. A `HashMap`'s
        // order is not stable across runs and a file that differs for no reason is
        // a file nobody can compare.
        let mut pending: Vec<_> = self.expected.iter().collect();
        pending.sort_by_key(|(cmx, _)| **cmx);
        for (_, p) in pending {
            put_note(&mut out, &p.note);
            out.push(u8::from(p.coinbase));
        }

        // Notes reserved by a bundle we submitted and have not seen confirmed,
        // plus the height we have scanned to, which is what their expiry is
        // measured against. Both have to persist: every `noct-cli` run is a new
        // process, and the chain does not publish a nullifier until the spend is
        // mined — so forgetting these is how a wallet double-spends itself between
        // two runs. Sorted, so identical state always writes identical bytes.
        out.extend_from_slice(&self.synced_height.to_le_bytes());
        let mut reserved: Vec<(u64, u64)> =
            self.pending_spends.iter().map(|(k, v)| (*k, *v)).collect();
        reserved.sort_unstable();
        out.extend_from_slice(&(reserved.len() as u32).to_le_bytes());
        for (position, at) in &reserved {
            out.extend_from_slice(&position.to_le_bytes());
            out.extend_from_slice(&at.to_le_bytes());
        }
        out
    }

    /// Load a wallet, checking it against the chain it claims to be in step with.
    ///
    /// Refusing is cheap — the caller rescans — so every check here is one this
    /// would rather fail than pass wrongly.
    pub fn from_bytes(
        keys: ShieldedKeys,
        bytes: &[u8],
        shielded: &ShieldedState,
    ) -> Result<Self, ShieldedStateFileError> {
        let mut cur = Cursor(bytes);
        if cur.u8()? != SHIELDED_VERSION {
            return Err(ShieldedStateFileError::Malformed);
        }
        let leaves = cur.u64()?;
        let tree = cur.tree()?;

        let count = cur.u32_len(NOTE_BYTES + 8 + 8 + 1)?;
        let mut notes = Vec::new();
        let mut witnesses = HashMap::new();
        for _ in 0..count {
            let note = cur.note()?;
            let position = cur.u64()?;
            let height = cur.u64()?;
            let flags = cur.u8()?;
            if flags & !0b11 != 0 {
                return Err(ShieldedStateFileError::Malformed);
            }
            let spent = flags & 1 != 0;
            let coinbase = flags & 2 != 0;
            if !spent {
                match cur.u8()? {
                    0 => {}
                    1 => {
                        witnesses.insert(position, cur.witness()?);
                    }
                    _ => return Err(ShieldedStateFileError::Malformed),
                }
            }
            // A spent note carries the height it was spent at; an unspent one has
            // nothing to say. Written only when `spent`, so the record stays the
            // same size for the common case.
            let spent_height = if spent {
                match cur.u64()? {
                    0 => None,
                    h => Some(h),
                }
            } else {
                None
            };
            notes.push(OwnedNote { note, position, height, spent, coinbase, spent_height });
        }

        let pending_count = cur.u32_len(NOTE_BYTES + 1)?;
        let mut expected = HashMap::new();
        for _ in 0..pending_count {
            let note = cur.note()?;
            let coinbase = cur.u8()? != 0;
            let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
            expected.insert(cmx, PendingNote { note, coinbase });
        }

        // The reservations, and the height they expire against. These must be read
        // BEFORE the "nothing left over" check below — that check is what makes a
        // file with trailing bytes a file we refuse, and appending a section
        // without reading it here turns every valid file into a rejected one.
        let synced_height = cur.u64()?;
        // `u32_len`, not a bare count: it refuses a number the remaining bytes
        // cannot possibly hold, before anything is allocated.
        let reserved_count = cur.u32_len(16)?;
        let mut pending_spends = HashMap::new();
        for _ in 0..reserved_count {
            let position = cur.u64()?;
            let at = cur.u64()?;
            // Only what still reserves anything. A lapsed entry would reserve a
            // note this very load is about to decide is free.
            if synced_height < at.saturating_add(crate::PENDING_SPEND_BLOCKS) {
                pending_spends.insert(position, at);
            }
        }

        if !cur.0.is_empty() {
            return Err(ShieldedStateFileError::Malformed);
        }

        // Nullifiers are recomputed, never read: they are a function of the note
        // and the viewing key, and the key is not in the file.
        let mut own_nullifiers = HashMap::new();
        for owned in &notes {
            if owned.spent {
                continue;
            }
            // Every note must be addressed to this wallet. A file from another
            // account would otherwise load, show a balance, and be unable to
            // spend any of it.
            if keys.incoming_viewing_key().diversifier_index(&owned.note.recipient()).is_none() {
                return Err(ShieldedStateFileError::WrongAccount);
            }
            let nullifier = owned.note.nullifier(keys.full_viewing_key());
            own_nullifiers.insert(nullifier.to_bytes(), owned.position);
        }

        let wallet = ShieldedWallet {
            keys,
            notes,
            witnesses,
            tree,
            leaves,
            own_nullifiers,
            expected,
            pending_spends,
            synced_height,
        };

        // And the checks that matter: the file has to describe *this* chain, at
        // *this* height.
        if wallet.root() != shielded.root() || wallet.leaves != shielded.notes() {
            return Err(ShieldedStateFileError::OutOfStep);
        }
        for owned in wallet.unspent() {
            let Some(witness) = wallet.witnesses.get(&owned.position) else { continue };
            let cmx = ExtractedNoteCommitment::from_bytes(&owned.commitment())
                .into_option()
                .ok_or(ShieldedStateFileError::Malformed)?;
            let root = orchard::Anchor::from(witness.root()).to_bytes();
            let path = witness.path().ok_or(ShieldedStateFileError::StaleWitness {
                position: owned.position,
            })?;
            // Two separate things, and both have to hold: the witness must be
            // current to a root the chain accepts, and the path it gives must be a
            // path to *this note* at *that* root. A witness of the right shape
            // pointing at somebody else's leaf would pass the first check alone.
            if !shielded.accepts_anchor(&root) {
                return Err(ShieldedStateFileError::StaleWitness { position: owned.position });
            }
            if MerklePath::from(path).root(cmx).to_bytes() != root {
                return Err(ShieldedStateFileError::StaleWitness { position: owned.position });
            }
        }
        Ok(wallet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::address::Address;

    fn keys(seed: u8) -> ShieldedKeys {
        ShieldedKeys::from_spend_secret(&[seed; 32], 0, Network::Mainnet)
            .expect("a fixed seed derives keys")
    }

    /// One seed, both pools: the same 32 bytes that make the ring account also
    /// make the Orchard one, so an existing 24-word backup restores everything.
    /// Deterministically — a wallet that derived a different address on restore
    /// would have lost every note ever sent to the first one.
    #[test]
    fn the_same_seed_always_derives_the_same_shielded_address() {
        let a = keys(9).address().encode();
        let b = keys(9).address().encode();
        assert_eq!(a, b);
        assert_ne!(a, keys(10).address().encode(), "and a different seed a different one");
    }

    /// The derivation is pinned. It is a function of the seed, the domain tag, the
    /// ZIP-32 path and the coin type, and changing any of them silently changes
    /// every address the wallet has ever handed out.
    #[test]
    fn the_derivation_is_pinned() {
        assert_eq!(COIN_TYPE, 1_337, "changing the coin type changes every address");
        assert_eq!(
            keys(1).address().encode(),
            "nueRwbZiQDqBNAwyrymvaAc8Ce3KsXXqiQufApCNqx5PZNo2zMDukqBNyN9NbLafd",
        );
    }

    /// A shielded address is not a ring address and must not be mistakable for
    /// one in either direction.
    #[test]
    fn the_two_kinds_of_address_stay_apart() {
        let shielded = keys(3).address();
        assert!(Address::decode(&shielded.encode()).is_err());
        assert_eq!(ShieldedAddress::decode(&shielded.encode()).unwrap(), shielded);
    }

    /// Diversified addresses all belong to the same wallet and cost nothing extra
    /// to scan for — unlike a ring subaddress, which is another key to check.
    #[test]
    fn every_diversified_address_is_recognised_as_ours() {
        let k = keys(4);
        for j in [0u32, 1, 2, 500, u32::MAX] {
            assert!(k.owns(&k.address_at(j)), "diversifier {j} should be ours");
        }
        assert!(!k.owns(&keys(5).address()), "and another wallet's is not");
        // Same wallet, another network: not ours to receive on.
        let other_network = ShieldedKeys::from_spend_secret(&[4u8; 32], 0, Network::Testnet)
            .unwrap()
            .address();
        assert!(!k.owns(&other_network));
    }
}
