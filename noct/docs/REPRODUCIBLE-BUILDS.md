# Reproducible builds

Every Nocturnal release so far has told you the same uncomfortable thing: the
published checksum proves your download arrived intact, **not** that the binary
was built from the published source. Between those two claims sits the author,
and you have had to take his word for it.

This document is how you stop.

## Current status, stated exactly

| Release | Reproducible? |
|---|---|
| v0.1.0 – v0.1.3 | **No.** Built before this existed. The binaries are what they are; nobody can independently confirm they match the tags. |
| v0.1.4 onward | **Yes**, for Linux x86_64. Built by `deploy/reproducible-build.sh`. |
| Windows | **Not yet.** MSVC build determinism is a separate problem and has not been solved here. |

Retrofitting the earlier releases is not possible: re-publishing different bytes
under an existing tag would break the checksums people already recorded, which
is worse than an honest "no".

## Verifying a release

On Debian 12 (bookworm) x86_64, with Rust 1.82.0, cmake and a C++ toolchain:

```bash
git clone https://github.com/adamanto75/nocturnal
./nocturnal/noct/deploy/reproducible-build.sh v0.1.4-testnet
```

It prints a SHA-256 for each binary. Download the release's Linux archive,
extract it, and compare file by file:

```bash
tar xzf nocturnal-v0.1.4-testnet-linux-x64.tar.gz
sha256sum nocturnal-v0.1.4-testnet/*
```

Every binary should match. If one does not, **say so publicly** — a mismatch
either means the environment differs (see below) or that a published binary does
not correspond to its source, and only one of those is harmless.

## Why the archive hash will not match

The release ships a `.tar.gz`, and its hash covers archive metadata — file
timestamps and ordering — which is not yet made deterministic. Compare the
**binaries inside**, not the archive.

That is a real remaining gap, not a technicality to wave away. It means the
published `SHA256SUMS.txt` cannot itself be reproduced, only the contents it
refers to.

## What makes the build reproducible

Rust writes absolute paths into binaries, for debug info and panic messages. The
same source built in two directories therefore produces two different files —
measured on this project, `/root/repro-a` and `/root/repro-b` gave `a9af23e6…`
and `0772736e…` from byte-identical source.

Two changes remove it:

* **A fixed build path** (`/build`), so there is nothing varying to leak.
* **`--remap-path-prefix`** for the dependency sources under `$CARGO_HOME`,
  which still live in your home directory.

With both, two builds at different original paths produced identical binaries,
including `noctd` and `noct-miner`, whose RandomX dependency compiles C++
through cmake.

## What is part of the input

Reproducibility is always relative to an environment. These are inputs, and
changing any of them changes the output without anything being wrong:

* **Rust 1.82.0** — the pinned toolchain
* **Debian 12 (bookworm), x86_64** — a different distribution links a different
  libc
* **cmake and the C++ compiler**, for RandomX

A mismatch is only evidence of a problem once the environment matches.

## What this does and does not prove

It proves a binary corresponds to a specific commit. It says nothing about
whether that commit is *safe* — reproducibility and correctness are unrelated
properties. The code remains unaudited.
