# serai mirror crate backup

Offline copies of the four `-mirror` crates Noct's RingCT cryptography depends
on (serai's Monero implementation, republished on crates.io). The maintainer
intends to **delete these from crates.io**, which would break a fresh dependency
fetch. These backups guarantee the exact reviewed bytes remain available until
the dependencies are repinned to upstream serai.

See [`../../docs/DEPENDENCIES.md`](../../docs/DEPENDENCIES.md) for the full
provenance, risk analysis, and the repin plan.

## Files

| file | crate | version |
|------|-------|---------|
| `monero-primitives-mirror-0.1.0.crate`   | `monero-primitives-mirror`   | 0.1.0 |
| `monero-bulletproofs-mirror-0.1.0.crate` | `monero-bulletproofs-mirror` | 0.1.0 |
| `monero-clsag-mirror-0.1.0.crate`        | `monero-clsag-mirror`        | 0.1.0 |
| `monero-generators-mirror-0.4.0.crate`   | `monero-generators-mirror`   | 0.4.0 |

Each is a standard `.crate` (a gzipped tar). Their SHA-256 checksums match the
`checksum` fields pinned in the workspace `Cargo.lock`, so they are byte-for-byte
what the build compiles today.

## Verify integrity

```bash
sha256sum *.crate
# Compare against the checksum lines for these crates in ../../Cargo.lock
```

## Restore if the crates are deleted from crates.io

If a fresh `cargo build` can no longer fetch a mirror crate, seed the local
registry cache from these backups (they already carry the correct checksum, so
`--locked` still verifies):

```bash
# Windows path shown; adjust the registry cache dir for your machine.
CACHE="$HOME/.cargo/registry/cache/index.crates.io-6f17d22bba15001f"
cp *.crate "$CACHE/"
cargo build --locked   # verifies checksums against Cargo.lock
```

Inspect the source of any crate without installing it:

```bash
tar -xzf monero-clsag-mirror-0.1.0.crate   # -> monero-clsag-mirror-0.1.0/
```

This is an interim availability safeguard only. The durable fix is to repin to
upstream serai (or serai's own audited crates) — see the plan doc.
