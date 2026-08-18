//! `noct-core` — cryptographic core of the Noct privacy coin.
//!
//! Layers are built bottom-up, each independently testable:
//!
//! 1. [`hash`] — original Keccak-256 and `H_s` (hash-to-scalar).
//! 2. [`keys`] — private/public keys and dual-key accounts.
//! 3. [`address`] — Base58 tagged, checksummed addresses.
//! 4. [`stealth`] — one-time (stealth) output addresses.
//! 5. [`amounts`] — Pedersen commitments + Bulletproofs+ range proofs.
//! 6. [`ring`] — CLSAG ring signatures + key images.
//! 7. [`tx`] — transaction assembly & verification.
//! 8. [`emission`] / [`pow`] / [`block`] — emission curve, proof of work,
//!    difficulty, blocks, and coinbase.
//! 9. [`chain`] — chain state: output set, global double-spend prevention,
//!    difficulty retarget, decoy selection, block validation, fork choice.
//!
//! Cryptographic primitives are never hand-rolled: edwards25519 arithmetic comes
//! from `curve25519-dalek`, and range proofs from the Monero-compatible
//! `monero-bulletproofs` crate (Bulletproofs+ over ed25519).
//!
//! "noct" is a placeholder name.

pub mod address;
pub mod amounts;
pub mod block;
pub mod chain;
pub mod emission;
pub mod hash;
pub mod keys;
pub mod mempool;
pub mod params;
pub mod p2p;
pub mod pow;
pub mod ring;
pub mod stealth;
pub mod subaddress;
pub mod tx;
pub mod wire;
