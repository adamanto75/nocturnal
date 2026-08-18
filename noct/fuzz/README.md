# Fuzzing the Noct wire codec

Coverage-guided (libFuzzer) targets for the wire decoders — the boundary where
untrusted bytes from peers and RPC clients first enter a node. Prepared for the
professional audit; every internal security review pass has listed
coverage-guided fuzzing as outstanding work.

> **Status: written, not executed here.** `cargo-fuzz` requires a **nightly**
> toolchain, and this project is deliberately pinned to stable **1.82** (no
> `rustup` in the development environment). These targets have therefore not been
> run — treat them as ready-to-run, not as passing. The properties they assert
> *are* exercised on stable by
> `wire::tests::mutational_fuzz_decoders_are_panic_free_and_canonical`
> in `core/src/wire.rs`, which is part of the normal suite.

## Targets

| target | asserts |
|---|---|
| `wire_decode` | decoders never panic on arbitrary bytes; anything that decodes **re-encodes to the identical bytes** (canonicality — no malleable encodings); `additional_tx_public` never exceeds `MAX_COMMITMENTS` (security review **F16**) |
| `wire_roundtrip` | decode → encode → decode is a fixed point, and the **transaction id / block id are unchanged** across it (identifier stability — the concern behind **F5**) |

Why canonicality matters: a transaction id is `Keccak256(to_bytes)`. If two
distinct byte strings could decode to the same object, an object's identity would
depend on which encoding a peer happened to send.

## Running

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run wire_decode
```

Both targets ship with a seed corpus in `corpus/<target>/`. Seeds matter a great
deal here: a random buffer essentially never survives the point-decompression and
length checks, so fuzzing from scratch explores almost nothing. Regenerate them
from the current codec at any time with:

```bash
cargo test -p noct-core -- --ignored generate_fuzz_corpus
```

Useful invocations:

```bash
# longer campaign, 4 workers
cargo +nightly fuzz run wire_decode -- -max_total_time=3600 -workers=4

# reproduce and minimise a crash
cargo +nightly fuzz run wire_decode fuzz/artifacts/wire_decode/crash-<hash>
cargo +nightly fuzz tmin wire_decode fuzz/artifacts/wire_decode/crash-<hash>

# line coverage over the corpus
cargo +nightly fuzz coverage wire_decode
```

## Notes

- This crate is **excluded from the workspace** (see the root `Cargo.toml`) so the
  stable build and `cargo test` are unaffected by the nightly-only dependency.
- The release profile here keeps `debug-assertions` and `overflow-checks` on:
  fuzzing should trip internal invariants, not silently wrap.
- Worthwhile targets to add next: the `p2p`/`transport` message handler
  (stateful, so it needs a structure-aware harness) and `Blockchain::add_block`
  against mutated blocks.
