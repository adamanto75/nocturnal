# Nocturnal Protocol Specification

**Status:** draft, pre-mainnet. This document is the normative description of the
Nocturnal protocol as implemented in this repository. It is written to be read
alongside the code and to serve as the reference an external auditor diffs the
implementation against.

Nocturnal is a CryptoNote/Monero-style privacy coin: confidential amounts (RingCT),
sender ambiguity (ring signatures), and unlinkable one-time recipient keys
(stealth addresses), on a Nakamoto-consensus proof-of-work chain. The
cryptographic construction deliberately mirrors Monero's so that it can be
audited by comparison; where Nocturnal diverges, this document says so explicitly.

**Naming.** The project is **Nocturnal** and its unit is **NOCT**. Every crate,
binary, identifier and on-disk path is spelled `noct*` — `noct-core`, `noctd`,
`noct-cli`, `noct_subaddress`, `/var/lib/noct` — and the p2p network magic is the
ASCII `NOCT`. These are the same thing abbreviated, not a second project or a
leftover: the short form was chosen first and deliberately kept, because renaming
identifiers would change consensus-visible constants (address tags, domain
separators, network magic) for no benefit. **An auditor should expect the
mismatch and treat `noct*` as authoritative in code.**

Parameters marked *placeholder* are stable within this repository but expected to
be finalized before mainnet.

---

## 1. Conventions and primitives

### 1.1 Group

All public-key cryptography is on the Ed25519 curve (Twisted Edwards form of
Curve25519), via `curve25519-dalek` 4.1.x. Let:

- `G` — the Ed25519 base point.
- `H` — a second, independent generator used for amount commitments (a
  "nothing-up-my-sleeve" point with no known discrete log relative to `G`;
  see §6).
- `ℓ` — the prime order of the base-point subgroup.
- Scalars are integers mod `ℓ`; points are group elements.

Public keys are always produced as `x·G` (or as sums/derivations of such
points), and therefore live in the prime-order subgroup. Point encodings are the
32-byte compressed Edwards-Y form. **Decoding rejects non-canonical `y ≥ p` and
any point with torsion** (`PublicKey::from_bytes`), which removes address/key
malleability and keeps keys in the prime-order subgroup.

### 1.2 Hashing

- `Keccak256(x)` — **original Keccak-256** (pre-standardization padding, as used
  by Monero and Ethereum, via `tiny_keccak::Keccak::v256`). This is **not** NIST
  SHA3-256.
- `H_s(x)` — hash to scalar, defined as `Scalar::from_bytes_mod_order(Keccak256(x))`.
  The modular reduction gives a negligibly non-uniform scalar, matching the
  CryptoNote convention.

All domain separation is by explicit ASCII prefixes inside the hashed buffer
(e.g. `"noct_subaddress"`, `"noct_output_mask"`, `"noct_amount"`).

### 1.3 Atomic units

The smallest unit is `1e-12` NOCT. `ATOMIC_UNITS = 1_000_000_000_000` atomic
units per NOCT. All on-chain amounts are unsigned integers of atomic units.

---

## 2. Keys and accounts

A wallet is a single 32-byte **spend secret** `b`. Everything else derives from
it (`keys.rs`):

- view secret `a = H_s(b)`
- spend public `B = b·G`
- view public `A = a·G`

Deriving the view secret from the spend secret (`a = H_s(b)`) means the whole
wallet is recoverable from the 32-byte spend secret alone (and hence from a
24-word BIP-39 phrase encoding it, §14). Revealing `(a, B)` yields a **view-only**
capability: the holder can detect incoming outputs but cannot spend.

Secret scalars are validated as canonical (`Scalar::from_canonical_bytes`) on
import, so non-reduced encodings are never accepted.

---

## 3. Addresses

An address is the Base58 encoding (Bitcoin alphabet, no block chunking — a
deliberate, self-consistent choice; Monero-tooling interop is a non-goal) of:

```
[ tag (1) ‖ spend_pub (32) ‖ view_pub (32) ‖ checksum (4) ]     (69 bytes)
checksum = Keccak256(tag ‖ spend_pub ‖ view_pub)[..4]
```

The `tag` byte encodes both the network and the address kind:

| tag  | network | kind        |
|------|---------|-------------|
| 0x13 | mainnet | standard    |
| 0x14 | mainnet | subaddress  |
| 0x35 | testnet | standard    |
| 0x36 | testnet | subaddress  |

(Mainnet tags are *placeholder* values.) Decoding validates the checksum and
that both keys are canonical prime-order points.

For a **standard** address the two keys are `(B, A)`. For a **subaddress** they
are `(D, C)` per §4.

---

## 4. Subaddresses

Subaddresses give one wallet an unbounded family of unlinkable receiving
addresses under a single view key (Monero's scheme, adapted to Nocturnal's
`a = H_s(b)` convention). A subaddress is indexed by `(account i, index j)`;
`(0, 0)` is the main address.

Definitions (`subaddress.rs`), for `(i, j) ≠ (0, 0)`:

- offset `m = H_s("noct_subaddress" ‖ a ‖ i_le32 ‖ j_le32)`
- spend public `D = B + m·G`
- view public `C = a·D`
- spend secret `d = b + m`  (so `d·G = D`)

`(0, 0)` is special-cased to the standard address `(B, A)` with `m = 0`, so a
wallet's primary address is unchanged.

Because `m` binds to the view secret `a`, two wallets produce unrelated
subaddresses at the same index, and an observer cannot link a subaddress to the
main address or to sibling subaddresses without `a`.

---

## 5. Stealth (one-time) outputs

Every output has a fresh **one-time public key** `P` that only the recipient can
link to their address and only the recipient can spend (`stealth.rs`). Locked-in
conventions:

- Each transaction has a secret `r` and publishes `R = r·G` (the transaction
  public key). When any output pays a subaddress, per-output keys are published
  instead (§5.1).
- Shared secret is **cofactor-cleared**: the ×8 (`mul_by_cofactor`) is applied
  before hashing, killing any small-subgroup component.
- derivation scalar `k = H_s( (8·shared).compress() ‖ index_le32 )`
- one-time key `P = k·G + S`, where `S` is the destination's spend public
  (`B` for a standard address, `D` for a subaddress).
- Sender computes `shared = r·V` (V = destination view public); recipient
  recomputes `shared = a·R` (both equal `r·a·G` for a standard address).
- one-time **spend secret** `x = k + s`, where `s` is the destination's spend
  secret (`b`, or `d = b + m` for a subaddress). `x·G = P`.

`index` is the output's position within its transaction, `u32` little-endian.

### 5.1 Subaddress outputs and additional keys

Output derivation is **address-agnostic** — it uses the destination's view/spend
publics directly — so paying a subaddress needs no change to how `P`, the
commitment, or the encrypted amount are formed. The only difference is the
**published transaction key**: a subaddress output must publish `R_i = r·D_i`
(so the recipient's `a·R_i = r·a·D_i` reproduces the shared secret), not `r·G`.

Therefore a transaction carries an optional **additional transaction key vector**
`additional_tx_public` (`tx.rs`):

- **Empty** when every output pays a standard address — every output uses the
  single `tx_public = r·G`. Ordinary transactions are byte-for-byte unchanged.
- **Length = number of outputs** when any output pays a subaddress. Output `i`'s
  key is `additional_tx_public[i] = r·D_i` for a subaddress destination, or
  `r·G` for a standard destination.

The transaction key applying to output `i` is `additional_tx_public[i]` when the
vector is present, else `tx_public`.

### 5.2 Scanning

To detect ownership of output `i` with one-time key `P_i`, the recipient computes
`k` from the applicable transaction key and forms the **recovered spend key**
`D' = P_i − k·G`, then matches `D'` against the addresses it controls:

- `D' = B` ⇒ the main address.
- `D' = D_{i,j}` ⇒ subaddress `(i, j)`.

This inversion is what lets a single view key recognize arbitrarily many
subaddresses. On a match the recipient recovers the amount (§6), derives the
one-time spend secret `x = k + b + m` (with `m = 0` for the main address), and
computes the key image (§8). Because `x` folds in the subaddress offset,
subaddress-received outputs are spent exactly like any other.

Wallets scan with a lookahead table of the main address plus a window of
subaddresses (§14).

---

## 6. Amounts (confidential values)

Amounts are hidden with Pedersen commitments and proven in range with
Bulletproofs+ (`amounts.rs`, on the serai `monero-bulletproofs` construction;
see §17):

- Commitment `C = y·G + amount·H`, where `y` is the blinding mask.
- Output mask `y = H_s("noct_output_mask" ‖ k)` — deterministic from the shared
  scalar `k`, so the recipient reconstructs it.
- The 8-byte amount is transmitted XOR-encrypted with a one-time pad
  `Keccak256("noct_amount" ‖ k)[..8]`, so only the recipient learns it.
- One aggregate Bulletproofs+ range proof covers all of a transaction's output
  commitments, proving each `amount ∈ [0, 2^64)`.

Coinbase outputs commit with mask `1` and a cleartext amount (§9), since the
subsidy is public and fixed by consensus.

On scan, the recipient recomputes the commitment from the recovered
`(amount, mask)` and rejects the output unless it matches the on-chain
commitment — so a malformed or mis-encrypted amount cannot be accepted.

---

## 7. Transactions

### 7.1 Structure

A transaction (`Transaction`, `tx.rs`; `TX_VERSION = 1`) is:

- `version : u8`
- `tx_public : Point` — `R = r·G`
- `additional_tx_public : Vec<Point>` — §5.1 (empty or one per output)
- `fee : u64` — public, in the clear
- `inputs : Vec<Input>` — each a ring of members plus a CLSAG signature
- `outputs : Vec<Output>` — each `{ one_time_key P, commitment C, encrypted_amount[8] }`
- `range_proof : RangeProof` — aggregate Bulletproofs+ over all output commitments

Each `Input` is `{ ring : Vec<RingMember>, signature : InputSignature }`, where a
`RingMember` is `[key P, commitment C]` and the signature carries the key image
and the pseudo-out commitment (§8).

### 7.2 Signing message

Every ring signature binds the 32-byte message

```
Keccak256( version ‖ tx_public ‖ |additional| ‖ additional[…]
           ‖ fee ‖ |inputs| ‖ (key_image ‖ |ring| ‖ ring[…]) per input
           ‖ |outputs| ‖ (P ‖ C ‖ encrypted_amount) per output
           ‖ range_proof )
```

i.e. everything except the signatures themselves. Any tampering with keys,
amounts, fee, or the range proof invalidates the signatures.

### 7.3 Verification

`Transaction::verify` checks, with no secret knowledge:

1. at least one input and one output;
2. no duplicate key image *within* the transaction;
3. the aggregate range proof verifies against the output commitments;
4. every CLSAG verifies against the signing message and its ring;
5. balance: `Σ pseudo-outs = Σ output commitments + fee·H`.

This establishes internal consistency. It does **not** check that ring members
are real chain outputs or that key images are globally unspent — those are the
chain's responsibility (§11).

### 7.4 Wire encoding

`wire.rs` provides a canonical byte encoding that is **byte-identical to**
`Transaction::to_bytes`, so the transaction hash (`Keccak256(to_bytes)`) is
independent of transport. The `additional_tx_public` vector is length-prefixed
(`u32`) directly after `tx_public`. The decoder rejects trailing bytes and
bounds all length prefixes against the remaining input, so malformed input
cannot allocate unboundedly or panic (validated by an adversarial fuzz test).

---

## 8. Ring signatures and key images

Inputs spend prior outputs ambiguously with CLSAG ring signatures (`ring.rs`, on
the serai `monero-clsag` construction; §17):

- A ring is a set of `[P, C]` members; exactly one (at a secret index) is the
  real output being spent, the rest are decoys drawn from the chain's output set.
- The signature publishes a **key image** `I = x·H_p(P)` (with `H_p` a
  hash-to-point of the one-time key `P`, and `x` the one-time spend secret). The
  key image is deterministic in the spent output, so the same output spent twice
  produces the same image — this is how double-spends are detected — while
  revealing nothing about which ring member is real.
- Each input also publishes a **pseudo-out commitment** to the input's amount;
  the balance check (§7.3.5) is over pseudo-outs and output commitments, so
  amounts are proven equal without being revealed.

Ring size is **exactly** `RING_SIZE = 16` (1 real + 15 decoys), enforced by
consensus: an input whose ring is any other length is invalid, in either
direction.

Exact rather than a minimum, and the distinction matters. A floor prevents the
obvious harm — a ring of one names the spender outright and pollutes the
anonymity set of everyone who later draws that output as a decoy. But a
*variable* size is itself an identifying mark: if transactions may carry 11, 16
or 24 members, the count partitions users by whichever wallet or setting produced
them, and the real anonymity set becomes the group sharing that choice rather
than the ring. Uniformity is the property being defended. Monero mandates an
exact size for the same reason.

The wallet does not hold its own opinion of the size — `DEFAULT_RING_SIZE`
re-exports the consensus constant, so the two cannot drift apart and a wallet
cannot build a transaction the network will reject.

Decoys are drawn uniformly from the global output set (`select_ring_uniform`); a
gamma/recency-weighted selection like Monero's is a candidate refinement before
mainnet (§17).

---

## 9. Emission and premine

Total supply cap `MONEY_SUPPLY = 1_000_000 NOCT`. Per-block subsidy
(`emission.rs`):

```
base_reward(emitted) = max( (MONEY_SUPPLY − emitted) >> EMISSION_SPEED_FACTOR,
                            TAIL_EMISSION )
```

with `EMISSION_SPEED_FACTOR = 20` and `TAIL_EMISSION = 0.03 NOCT`
(`30_000_000_000` atomic units). This is Monero's smooth-emission shape: the
reward is a fixed fraction of the remaining supply until it reaches the constant
tail, which then continues indefinitely to fund security. Fees are **not** new
coins — they are paid from existing supply and claimed by the miner, so they do
not affect the cap.

**Premine.** The genesis block's coinbase mints `PREMINE_AMOUNT = 500_000 NOCT`
(50% of supply) to the founder address as a single stealth output at global
index 0, derived with a baked-in genesis transaction key. The chain initializes
`emitted = 500_000 NOCT`, so subsequent subsidies continue the curve from that
baseline. The premine secret is the project's most sensitive key and is held
offline (see project notes).

`GENESIS_TIMESTAMP = 1_750_000_000` (*placeholder*).

---

## 10. Proof of work

Nocturnal is PoW-agnostic at the type level (`ProofOfWork` trait), with two
implementations:

- **RandomX** (`noct-randomx`, mainnet PoW) — the ASIC-resistant, CPU-friendly
  VM PoW, via `randomx-rs`. A block's PoW hash is RandomX over the block's
  PoW blob; verification uses a light-mode VM (~256 MB), mining optionally builds
  a full-memory dataset (~2 GB) shared across threads for speed.
- **Keccak** (`KeccakPow`, placeholder) — a trivial hash PoW used for tests and
  toolchain-free wallet builds. **Not** for mainnet.

Wallets use a third, non-mining stand-in (`TrustedPow`) that accepts any block's
PoW: a wallet validates every transaction, ring, key image, and the emission,
but trusts its own local node for PoW, so it needs no RandomX toolchain.

### 10.1 RandomX seed epochs

RandomX is keyed by a seed that rotates on epochs (`pow.rs`), matching Monero's
`rx_seedheight`:

- `RANDOMX_EPOCH_BLOCKS = 2048` (power of two), `RANDOMX_EPOCH_LAG = 64`.
- seed height `= 0` while `height ≤ EPOCH + LAG`, else
  `(height − LAG − 1) & ¬(EPOCH − 1)`.
- The seed is the block id at the seed height (or the genesis id for early
  blocks). A block is validated with the VM keyed to its height's seed; mining
  keys the VM to the same seed. Crossing an epoch boundary rebuilds one VM
  (~1 s), which is cached; returning to a known seed is free.

For chains shorter than one epoch the seed is always the genesis id (one VM).

---

## 11. Difficulty

Retarget (`pow::next_difficulty`) targets `TARGET_BLOCK_TIME = 120` seconds. It
is the Monero-style windowed average with three defences against
miner-chosen (adversarial) timestamps:

1. **Lag** — the newest `DIFFICULTY_LAG = 15` blocks are excluded from the
   window, so the retarget never leans on the least-settled tips.
2. **Outlier trim** — over a window of `DIFFICULTY_WINDOW = 720` blocks, the
   timestamps are sorted and `DIFFICULTY_CUT = 60` are discarded from each end
   (once the window is large enough), so a miner who lies high or low lands in a
   discarded tail.
3. **Step clamp** — the next difficulty may change by at most
   `MAX_DIFFICULTY_STEP = 2×` per block in either direction, damping volatility
   and preventing a run of near-instant timestamps from compounding difficulty
   to an unmineable value.

The estimate is `next = trimmed_work · TARGET_BLOCK_TIME / trimmed_time_span`,
clamped to the step bound and to `MIN_DIFFICULTY = 1`. As in Monero, the work is
summed over the index span of the trimmed timestamps even though the timestamp
series was sorted — a deliberate robustness/precision trade.

Fork choice is by **cumulative difficulty**: a competing chain replaces the
incumbent only on strictly greater total work (ties keep the incumbent).

**The gossip layer advertises that same quantity.** A tip announcement carries
`(network id, height, tip block id, cumulative difficulty)`, and a peer's chain is
evaluated on the *work* it claims, never on its length. This is not incidental:
advertising only height would make the network implement "longest chain" while
consensus implements "heaviest", so a heavier but equal-or-shorter branch could
never be discovered and a node could remain on a lighter chain indefinitely
(security review F29). Height is still carried, but only to choose the cheap
sequential catch-up over a full branch download; it never decides a reorg.

---

## 12. Blocks

A block is `{ header, coinbase, tx_hashes }` (`block.rs`):

- **Header** — `{ major_version, minor_version, timestamp, prev_id, nonce }`.
- **Coinbase** — the miner transaction: `{ height, tx_public, outputs }`, each
  output a public-amount stealth output to the miner. Its committed value must
  equal exactly `base_reward(emitted) + Σ fees`.
- **`tx_hashes`** — the ordered hashes of the block's transactions.

The block id and the PoW blob are formed over the header plus a Merkle root over
`[coinbase, tx_hashes…]`, binding all block contents to the proof of work.

---

## 13. Chain and consensus rules

`Blockchain::add_block` accepts a block only if all hold (`chain.rs`):

1. `header.prev_id` equals the current tip id;
2. the PoW hash meets the required difficulty (§11), with the VM keyed to the
   block height's seed (§10.1);
3. `header.timestamp` is strictly greater than the **median of the last
   `MTP_WINDOW = 11`** block timestamps, and not more than
   `FUTURE_TIME_LIMIT = 2 hours` ahead of local time;
4. the coinbase height equals the block height;
5. each provided transaction matches its committed `tx_hash`;
6. every transaction verifies internally (§7.3), **and** against chain state:
   each ring member is a real output in the set, no ring member is an immature
   coinbase (§13.1), and no key image is already spent; no key image repeats
   within the block;
7. no output the block creates duplicates an existing output, or another output
   in the same block (§13.2);
8. the coinbase claims exactly `base_reward(emitted) + Σ fees`.

### 13.1 Coinbase maturity

A coinbase output (mined reward or the genesis premine) may not be referenced by
any transaction — as the real spend *or* as a decoy — until it is
`COINBASE_MATURITY = 60` blocks deep. Because ring signatures hide which member
is real, the rule is enforced over **every** ring member; a transaction whose
ring contains an immature coinbase is rejected (`ImmatureCoinbase`). This mirrors
the intent of Monero's `unlock_time` on coinbase outputs and prevents a short
reorg (which most easily erases recent coinbase outputs) from unspending an
already-spent freshly-mined coin. Non-coinbase outputs have no maturity
requirement. The premine, being a coinbase output at height 0, is therefore
spendable only once the chain is 60 blocks deep. Wallets exclude immature
coinbase from spendable balance and input selection.

### 13.2 Output uniqueness

No block may create an output whose `[P, C]` already exists in the output set, or
which repeats within the same block (`DuplicateOutput`). Outputs are *identified*
by `[P, C]` — that key resolves a ring member back to its global index and hence
to its metadata — so a duplicate would make the output set ambiguous and let the
second occurrence's metadata shadow the first's. That is a maturity bypass: a
miner could publish an output copying its own immature coinbase's `[P, C]`, and
the coinbase would resolve to the new *non-coinbase* entry and become spendable
(security review F17). Honest transactions never collide, since one-time keys
derive from a random per-transaction key.

On success the chain appends the block, adds its outputs to the global set (with
their global indices), records spent key images, and advances emission,
timestamps, cumulative difficulty, and the block id. Each application stores an
undo record so the tip can be rolled back for reorgs.

**Reorganization.** A heavier competing branch (by cumulative difficulty) is
adopted by rolling the tip back to the fork point and replaying the new branch;
if the new branch fails validation, the original is restored. Reorg depth is
bounded by `MAX_REORG_DEPTH = 100`.

---

## 14. Wallet behavior

The wallet (`noct-wallet`) is a light wallet over the node:

- **Scanning.** It scans every block in chain order with the view key, recording
  owned outputs and the **global output index** each was assigned (coinbase
  outputs first, then each transaction's outputs) — the index rings reference.
  Ownership is decided by the recovered-spend-key match of §5.2 against the
  wallet's address table.
- **Subaddress lookahead.** On creation the wallet pre-derives the main address
  plus account-0 subaddresses `0..SUBADDRESS_LOOKAHEAD` (200), so funds sent to
  those are detected even after a restart with no persisted wallet state.
  Subaddresses beyond the window (or in other accounts) are detected once
  generated in-session. *(Limitation — §16.)*
- **Spending.** Greedy input selection over unspent outputs; each selected output
  is placed in a ring of uniform decoys from the chain; change returns to the
  wallet. A transaction that pays a subaddress automatically carries additional
  keys (§5.1).
- **Balance and history.** Balance is the sum of unspent outputs. A per-block
  transaction history classifies each event as received (with coinbase flag) or
  sent; a sent entry's amount is what left the wallet (inputs − change − fee),
  with the fee reported separately.
- **State cache.** Validated blocks are cached on disk and replayed locally on
  the next run, so repeat commands and restarts pull only new blocks rather than
  re-downloading from genesis. A corrupt or reorged cache is discarded and
  rebuilt; caching never affects correctness.
- **Seed backup.** The 32-byte spend secret is backed up as a 24-word BIP-39
  phrase (the entropy *is* the spend secret; no PBKDF2 stretch). Restoring
  validates the checksum and that the result is a canonical scalar.

---

## 15. P2P networking

Nodes speak a length-prefixed binary protocol over TCP (`p2p.rs`, `wire.rs`,
node `transport.rs`):

- **Network id** `NETWORK_ID = 0x4E4F4354` ("NOCT"); peers on a different id are
  rejected at handshake.
- **Handshake** — a `Version` exchange carrying the network id, the genesis id, a
  listen port, and a random nonce; a node drops connections whose nonce matches
  its own (self-connect) or a live peer (duplicate).
- **Sync** — a node compares tips and downloads missing blocks in order,
  validating each into its chain; a heavier branch triggers a reorg (§13).
- **Gossip** — new blocks and transactions are relayed; transactions use
  **Dandelion++** (a stem phase of single-peer relays before fluffing) to
  decorrelate origin from broadcast.
- **Peer discovery** — `GetPeers`/`Peers` exchange, a persisted address book,
  and outbound connection management toward a target peer count; gossiped
  addresses are filtered for routability.
- **Abuse resistance** — per-peer misbehavior scoring with temporary bans for
  invalid blocks/transactions, message rate limiting, and bounded de-dup sets for
  seen blocks/transactions. Scoring keys on the address a peer actually connected
  from — never one it advertised, which it could rotate to reset its score — at
  the granularity of a single IPv4 address or a whole IPv6 **/64**, since one
  subscriber is routinely handed an entire /64 and banning a single address out
  of it would achieve nothing. Loopback is scored per-port so local multi-node
  testing is unaffected.

---

## 15.1 External mining interface

Mining is not confined to the node binary. A node exposes two RPCs that let an
**external** miner (or a pool) mine against it:

- **`GET /getblocktemplate[?address=<B58>]`** — returns an unmined block:
  `{ height, difficulty, seed_hash, reward, pow, template }`, where `template` is
  the hex of a wire-encoded `Wire::Block` (the block plus the transactions it
  commits to). The coinbase pays `address` if supplied, else the node's own miner
  address. `seed_hash` is the RandomX epoch seed (§10.1) the PoW must be keyed
  to; `difficulty` is the target the solution must meet. `pow` names the
  proof-of-work function the node validates with, so a miner computing a
  different one fails immediately instead of having every share rejected as
  "does not meet the target" — a symptom that otherwise points at difficulty and
  hides the real cause.
- **`POST /submitblock`** — body is the hex of a solved wire-encoded block. The
  node **re-validates it in full** (PoW, coinbase reward, every transaction, the
  maturity rule) before appending and relaying it. It replies
  `{"status":"accepted",…}`, or `{"status":"rejected","reason":"stale"}` if the
  chain advanced while the miner was grinding, or `"invalid"` if validation
  failed.

The miner's loop is: fetch a template → vary `header.nonce` until
`pow_hash` meets `difficulty` → submit. Nothing is trusted: a submitted block
passes exactly the same consensus checks as one arriving from a peer, so a
malicious miner can only waste its own work. `noct-miner` is the reference
implementation of this loop.

### 15.2 RPC authentication

The RPC is an administrative surface — it starts and stops mining and accepts
blocks and transactions — so it is authenticated by a shared **bearer token**:

- `noctd --rpc-token-file <PATH>` (preferred) or `--rpc-token <TOKEN>` sets it.
- Every request must then carry `Authorization: Bearer <token>`; anything else
  gets `401 Unauthorized`. The comparison is constant-time, so the token cannot
  be recovered byte-by-byte from response timing.
- **Fail-closed binding:** a node refuses to start if its RPC is bound to a
  non-loopback address without a token, so an unauthenticated RPC cannot be
  exposed by accident. Leaving the token unset is permitted only on loopback.

Clients pass it with `noct-miner --token-file`, and `noct-cli` /
`noct-walletd --node-token-file`. The token is a bearer credential over
cleartext HTTP: across an untrusted network it needs a TLS proxy or a tunnel.

### 15.3 RPC rate limiting

Authentication says *who* may call; it does not stop an authenticated client from
monopolising the node. Each source IP therefore gets a refilling token bucket,
and requests are charged by how expensive they are to serve:

| endpoint | cost |
|---|---|
| `/getblocktemplate`, `/submitblock`, `/mine`, `/submit_tx` | 10 |
| `/block/{height}` | 2 |
| status reads (`/info`, `/height`, `/mining`) | 1 |

The expensive endpoints take the consensus lock and do elliptic-curve or
validation work, so charging them proportionally bounds the real denial-of-service
lever rather than just the request count. The default refill is
`--rpc-rate-limit 2000` units/second with a burst of twice that (`0` disables
limiting); over-quota requests get `429 Too Many Requests` with `Retry-After`.

Two details keep this from causing its own problems:

- **The limiter is bounded.** Its table is keyed by attacker-chosen source
  addresses, so it prunes. A bucket that has refilled to full is indistinguishable
  from an untracked client, so dropping full buckets is free and cannot be used to
  evade the limit.
- **Limiting runs before authentication**, so an unauthenticated flood is bounded
  too — otherwise anyone reaching the port could spend CPU on parsing and 401s.

Clients must treat `429` as transient: `noct-miner` retries a *solved* block with
a short backoff rather than discarding work that cost real hashing.

## 16. Known limitations (pre-mainnet)

These are the gaps to close, or decisions to ratify, before mainnet. They are
called out here so an audit covers them explicitly. Items marked **CLOSED** are
recorded so a reviewer can check the resolution rather than rediscover the gap.

1. **CLOSED — coinbase maturity.** `COINBASE_MATURITY = 100` (§13.1), raised from
   60 so that it is never shallower than `MAX_REORG_DEPTH` (100). Below that
   depth a reorg between the two values could invalidate a coinbase that had
   already matured and been spent. The invariant `COINBASE_MATURITY >=
   MAX_REORG_DEPTH` is pinned by a test, because the two constants live in
   different crates. Worth an auditor's attention: the rule is enforced over
   *every ring member*, not just the real spend, and the premine is subject to it.
2. **CLOSED — decoy selection is recency-weighted**, not uniform. Wallets call
   `select_ring_recency_biased`, which samples ages from a gamma distribution in
   log space (`GAMMA_SHAPE`/`GAMMA_SCALE`) and maps them to heights, following
   Monero. `select_ring_uniform` is retained for tests and as a fallback when the
   sampled age exceeds the chain. The *shape* of the distribution is what carries
   the privacy, so it is worth checking against Monero's rather than assuming.
3. **CLOSED — proof-of-work gating.** The PoW was a build-time feature with
   nothing in the protocol checking it, so a Keccak-built node could handshake
   and then disagree with every block on the network. `network_requires_randomx`
   now states what each network needs and the node refuses to start otherwise.
   Mainnet has no override; `--allow-pow-mismatch` exists for local Keccak
   networks and is ignored on mainnet.
4. **OPEN — genesis and network parameters are placeholders.** Mainnet address
   tags, the genesis timestamp and the RandomX genesis seed must be finalised.
   These are immutable once mainnet genesis exists.
5. **OPEN — wallet state is not persisted.** Subaddress lookahead is bounded
   (account 0, indices < 200, no persisted counter beyond the daemon's issue
   file) and the CLI re-scans from genesis on every command. Both are workable at
   testnet length and neither is at mainnet length.
6. **OPEN by decision — deep-partition resync.** A node that diverges by more
   than `MAX_REORG_DEPTH` cannot rejoin by reorganising and must be resynced.
   Automatic recovery was considered and rejected: a node that discarded its
   chain on seeing a heavier one would surrender exactly the protection
   `MAX_REORG_DEPTH` provides, letting an attacker with a heavier chain capture
   an established node. The node reports the condition instead — repeated
   failures to reach a common ancestor are logged, and `/info` carries a
   `stranded` flag for monitoring.
7. **REVIEWED — difficulty.** The retarget is Monero-style: a 720-block window,
   15-block lag, 60 outlier timestamps trimmed from each end, and a 2x per-block
   step clamp. Sorted timestamps are paired with chronologically-ordered
   cumulative difficulties, as in Monero's implementation. Short-chain and
   epoch-boundary behaviour are covered by tests. Retained here so an auditor
   confirms the pairing rather than assuming it is a bug.
8. **OPEN — node memory holds the whole chain.** Every block is retained with its
   decoded transactions, so resident memory grows with chain length (~23 KB per
   block measured on testnet). The validation state proper — the output set and
   spent key images — is a small fraction of it. Serving blocks from the on-disk
   log instead would bound this; it dictates node hardware requirements, so it
   belongs before mainnet.

## 17. Dependency and audit notes

- **RingCT crypto is built on serai's Monero crates** (`monero-bulletproofs`,
  `monero-clsag`) so Nocturnal reuses Monero's reviewed construction and an auditor
  can diff against Monero. serai's canonical crates.io versions are empty
  placeholder stubs; the build uses community `-mirror` republishes pinned by
  version. **Before mainnet, repin every serai dependency to a specific upstream
  serai revision (or the audited crates once released) and include the pinning in
  the audit** — the mirror is a third-party republish.
- Toolchain is pinned to Rust 1.82 (edition 2021, resolver 2); several transitive
  crates must be version-pinned to avoid pulling edition-2024 requirements.
- **Never hand-roll cryptographic primitives** — all primitives come from
  audited/maintained crates (`curve25519-dalek`, the serai mirrors, `randomx-rs`,
  `bip39`, `tiny_keccak`).

---

## Appendix A — Parameter summary

| Parameter | Value | Source |
|---|---|---|
| `ATOMIC_UNITS` | 1e12 / NOCT | `emission.rs` |
| `MONEY_SUPPLY` | 1,000,000 NOCT | `emission.rs` |
| `EMISSION_SPEED_FACTOR` | 20 | `emission.rs` |
| `TAIL_EMISSION` | 0.03 NOCT | `emission.rs` |
| `PREMINE_AMOUNT` | 500,000 NOCT (50%) | `block.rs` |
| `GENESIS_TIMESTAMP` | 1,750,000,000 *(placeholder)* | `block.rs` |
| `TARGET_BLOCK_TIME` | 120 s | `pow.rs` |
| `DIFFICULTY_WINDOW` | 720 | `pow.rs` |
| `DIFFICULTY_LAG` | 15 | `pow.rs` |
| `DIFFICULTY_CUT` | 60 / side | `pow.rs` |
| `MAX_DIFFICULTY_STEP` | 2× / block | `pow.rs` |
| `MIN_DIFFICULTY` | 1 | `pow.rs` |
| `RANDOMX_EPOCH_BLOCKS` | 2048 | `pow.rs` |
| `RANDOMX_EPOCH_LAG` | 64 | `pow.rs` |
| `MTP_WINDOW` | 11 | `chain.rs` |
| `FUTURE_TIME_LIMIT` | 2 h | `chain.rs` |
| `COINBASE_MATURITY` | 60 blocks | `chain.rs` |
| `MAX_REORG_DEPTH` | 100 | `node` |
| `TX_VERSION` | 1 | `tx.rs` |
| `RING_SIZE` | 16, **exact** (1 + 15 decoys) | `chain.rs` |
| `DEFAULT_RING_SIZE` | re-export of `RING_SIZE` | `wallet` |
| `SUBADDRESS_LOOKAHEAD` | 200 | `wallet` |
| `NETWORK_ID` | 0x4E4F4354 | `p2p.rs` |
| Address tags | 0x13/0x14 main, 0x35/0x36 test | `address.rs` |

## Appendix B — Domain-separation strings

| String | Use |
|---|---|
| `"noct_subaddress"` | subaddress offset scalar `m` |
| `"noct_output_mask"` | output commitment blinding mask `y` |
| `"noct_amount"` | amount-encryption one-time pad |
| `b"noct/genesis/randomx/v1"` | RandomX genesis seed *(placeholder)* |
