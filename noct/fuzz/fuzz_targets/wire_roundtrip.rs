//! Coverage-guided fuzzing of **identifier stability** across the codec.
//!
//! A transaction's id is `Keccak256(to_bytes)` and a block's id covers its
//! header and contents, so both are functions of an encoding. If a decoded
//! object could re-encode to different bytes, its identifier would depend on
//! *which* byte string a peer happened to send — the malleability class flagged
//! as F5 in the security review, and the reason ring signatures bind a
//! recomputed message rather than raw input.
//!
//! For every input that decodes, this target asserts the decode → encode →
//! decode cycle is a fixed point:
//!
//! * re-encoding is stable (`encode(decode(encode(x))) == encode(x)`), and
//! * the identifier is unchanged across that cycle.
//!
//! Run with a nightly toolchain:
//!
//! ```text
//! cargo +nightly fuzz run wire_roundtrip
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use noct_core::wire::{decode_block, decode_transaction, encode_block, encode_transaction};

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = decode_transaction(data) {
        let id = tx.hash();
        let bytes = encode_transaction(&tx);

        // Re-decoding our own encoding must always succeed …
        let again = decode_transaction(&bytes).expect("re-encoded transaction must decode");
        // … and be a fixed point in both bytes and identity.
        assert_eq!(encode_transaction(&again), bytes, "transaction encoding is not stable");
        assert_eq!(again.hash(), id, "transaction id changed across a round trip");
    }

    if let Ok(block) = decode_block(data) {
        let id = block.id();
        let bytes = encode_block(&block);

        let again = decode_block(&bytes).expect("re-encoded block must decode");
        assert_eq!(encode_block(&again), bytes, "block encoding is not stable");
        assert_eq!(again.id(), id, "block id changed across a round trip");
    }
});
