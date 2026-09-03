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

## The archive is reproducible too

It was not, until `deploy/package-release.sh` existed. The release ships a
`.tar.gz`, and a tar records far more than its contents: the order operands were
given in, the order a directory walk returned, every file's mtime, owner and group
names, pax headers carrying atime/ctime, and a gzip header holding the source
filename and the time it was compressed. Any one of those varying gives a
different hash from identical files.

`package-release.sh` pins all of them, so the published `SHA256SUMS.txt` can be
reproduced rather than merely its contents checked by hand:

```
SOURCE_DATE_EPOCH=1 deploy/package-release.sh nocturnal-vX.Y.Z.tar.gz noctd noct-cli ...
```

The one that is easy to miss is operand order: `--sort=name` orders what tar
finds when it walks a *directory*, and does not reorder paths listed explicitly
on the command line. Packaging the same three files as `f1 f2 f3` and `f3 f1 f2`
produced two different archives until the script sorted them itself. It was
caught by testing exactly that, along with changing every file's mtime — both
now produce the same bytes.

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
