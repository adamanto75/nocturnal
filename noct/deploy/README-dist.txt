Nocturnal VERSION — command-line tools
=======================================

THIS IS NOT THE DESKTOP WALLET.

If you wanted a window with your balance in it, you want the installer:

    Nocturnal-Wallet-Setup-INSTALLER.exe

from https://nocturnalcoin.com/downloads — the same release page this
archive came from. What you have here is the command-line tools, for
running a node, a pool, or a wallet without a graphical interface.


WHAT EACH PROGRAM IS
--------------------

  noctd         The node. Validates the chain and talks to other nodes.
                Everything else here needs one of these running.

  noct-cli      The wallet, at a terminal: balance, send, history, and
                creating or restoring a key.

  noct-walletd  The same wallet, served as a local web page, so you can
                use a browser instead of a terminal. Nothing leaves the
                machine; it binds to localhost.

  noct-miner    Mines. Point it at a pool, or at your own node.

  noct-poold    Runs a mining pool.


START HERE
----------

  1.  noctd --network testnet

      Leave it running. The first start takes a few minutes: it loads the
      chain and builds the RandomX cache before it listens. That is not a
      hang.

  2.  noct-cli new --wallet wallet.key --network testnet

      Write down the 24 words it prints, on paper, before going further.
      They are the only way back to this wallet. Nobody can recover it
      for you.

  3.  noct-cli balance --wallet wallet.key --network testnet

For the wallet as a web page instead:

      noct-walletd --network testnet --wallet wallet.key

and open the address it prints.

Every command takes --help.


WHAT THIS NETWORK IS
--------------------

Testnet. These coins have no value, and the chain will be reset before
mainnet. Do not buy NOCT from anyone: there is nothing to buy.

Mainnet HAS NOT LAUNCHED. A node started with --network mainnet has no
seeds, no network to join, and will quietly mine a private chain of its
own — anything it produces is worthless and will be discarded when a real
mainnet exists. The node says so on startup. Use testnet.


CHECKING WHAT YOU DOWNLOADED
----------------------------

SHA256SUMS.txt in the release covers the archive you downloaded.
LINUX-BINARY-SHA256SUMS.txt covers the Linux binaries individually, and
you can reproduce those yourself:

    noct/deploy/reproducible-build.sh VERSION

on Rust 1.85.1. The Windows binaries are not reproducible and are not
code-signed, so SmartScreen will warn about them.

This software is UNAUDITED.
