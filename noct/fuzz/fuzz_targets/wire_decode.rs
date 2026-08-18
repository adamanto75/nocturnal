//! Coverage-guided fuzzing of the wire decoders — the boundary where untrusted
//! bytes first enter a node.
//!
//! Properties asserted on **every** input:
//!
//! * **No panic.** A decoder must return `Ok`/`Err` for arbitrary bytes: no
//!   out-of-bounds slicing, no arithmetic overflow, no allocation driven by an
//!   attacker-supplied length.
//! * **Canonicality.** If bytes decode, re-encoding the value must reproduce
//!   those bytes exactly. A violation means two distinct byte strings decode to
//!   the same object — a malleable encoding, the root of identifier-substitution
//!   bugs.
//! * **Protocol bounds hold after decoding.** In particular the
//!   `additional_tx_public` vector never exceeds `MAX_COMMITMENTS` (security
//!   review F16: an unbounded vector was a relayed CPU-exhaustion DoS).
//!
//! Run with a nightly toolchain:
//!
//! ```text
//! cargo +nightly fuzz run wire_decode
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use noct_core::amounts::MAX_COMMITMENTS;
use noct_core::wire::{
    decode_block, decode_message, decode_transaction, encode_block, encode_message,
    encode_transaction,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = decode_transaction(data) {
        assert!(
            tx.additional_tx_public.len() <= MAX_COMMITMENTS,
            "decoded transaction exceeded the additional-key bound"
        );
        assert_eq!(encode_transaction(&tx), data, "non-canonical transaction encoding");
    }

    if let Ok(block) = decode_block(data) {
        assert_eq!(encode_block(&block), data, "non-canonical block encoding");
    }

    if let Ok(msg) = decode_message(data) {
        assert_eq!(encode_message(&msg), data, "non-canonical message encoding");
    }
});
