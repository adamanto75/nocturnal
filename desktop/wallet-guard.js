// Guards against the desktop app showing a wallet it cannot verify.
//
// Three things have to be true before a balance is put in front of someone:
//
//  1. the key on disk is the wallet this app opened last time (`checkPin`);
//  2. no *other* daemon is serving the wallet port (`servesWallet` on the
//     pre-launch probe) — a leftover one would display its own wallet;
//  3. whatever finally answers is serving the key we loaded (`servesWallet`
//     again, after our own daemon starts).
//
// The failure they exist to prevent is the same in every case: the window shows
// a different wallet, with a zero balance, which is indistinguishable from the
// person's coins having disappeared.
//
// These helpers live outside `main.js` so they can be tested without Electron:
// `node test-wallet-guard.js`.

const http = require('http');
const nodePath = require('path');

/// Ask whatever is serving `url` for its wallet state. Resolves `null` when
/// nothing answers, the request times out, or the reply is not JSON — callers
/// treat all of those the same way: "no verified wallet service here".
function fetchState(url, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get(url + '/api/state', (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (_) {
          resolve(null);
        }
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

/// Is `state` a wallet service serving exactly the address we loaded?
///
/// Deliberately strict: a missing or differing address is a mismatch. Showing
/// the wrong balance is worse than showing nothing, so this never guesses.
function servesWallet(state, expectedAddress) {
  return Boolean(state) && typeof state.address === 'string' && state.address === expectedAddress;
}

/// Per-network storage layout: which data directory, chain and pin home a given
/// network uses.
///
/// The networks must share **nothing**. A testnet key opened against mainnet
/// shows a zero balance, which is indistinguishable from the "my coins are gone"
/// failure this whole guard exists to prevent; and a shared pin would make simply
/// switching networks look like a replaced wallet.
///
/// Mainnet keeps the original, unsuffixed paths, so an existing install is
/// untouched by the introduction of other networks.
function networkDirs(root, localAppData, network) {
  const suffix = network === 'mainnet' || !network ? '' : '-' + network;
  const data = suffix ? nodePath.join(root, 'net' + suffix) : root;
  return {
    network: network || 'mainnet',
    data,
    chain: nodePath.join(data, 'node'),
    altPin: nodePath.join(localAppData || root, 'Noct' + suffix),
  };
}

/// Where the expected-wallet pin is recorded.
///
/// Deliberately **two** locations, in different folders. The pin proves "this app
/// has opened a wallet before", and one that lives only beside the key is useless
/// in the case that actually bit us: if the data folder reads as empty at launch,
/// the key *and* the pin appear gone together, the app concludes it is a first
/// run, and mints a brand-new empty wallet. A pin somewhere else survives that.
function pinPaths(dataDir, altDir) {
  const paths = [nodePath.join(dataDir, 'wallet.address')];
  if (altDir) {
    paths.push(nodePath.join(altDir, 'wallet.address'));
  }
  return paths;
}

/// The first pin that can be read, or `null` if none exists.
function readPin(fs, paths) {
  for (const p of paths) {
    try {
      if (fs.existsSync(p)) {
        const value = fs.readFileSync(p, 'utf8').trim();
        if (value) return value;
      }
    } catch (_) {
      // Unreadable is not the same as absent — keep looking.
    }
  }
  return null;
}

/// Record `address` in every pin location. Failing to write one is not fatal; it
/// only weakens the next check.
function writePins(fs, paths, address) {
  for (const p of paths) {
    try {
      fs.mkdirSync(nodePath.dirname(p), { recursive: true });
      fs.writeFileSync(p, address + '\n');
    } catch (_) {}
  }
}

/// Has this app opened a wallet here before?
///
/// When it has, a missing key file is a fault to report — never a reason to
/// create a new wallet.
function hasOpenedBefore(fs, paths) {
  return readPin(fs, paths) !== null;
}

/// Compare the wallet about to be opened against the pinned one.
///
/// This catches what the daemon checks cannot: the **key itself** being replaced,
/// restored from a backup, or newly minted because the folder looked empty.
///
/// Returns `'ok'` (matches, or first run — pin written) or `'mismatch'`.
function checkPin(fs, paths, address) {
  const pinned = readPin(fs, paths);
  if (!pinned) {
    writePins(fs, paths, address); // first run: remember this wallet
    return 'ok';
  }
  if (pinned !== address) {
    return 'mismatch';
  }
  // Re-write, so a pin lost from one location is restored from the other.
  writePins(fs, paths, address);
  return 'ok';
}

/// Explanation for a launch refused because the key on disk is not the wallet
/// this app has been using.
function pinMismatchMessage(pinned, found) {
  return (
    'The wallet key on disk is NOT the wallet this app has been using.\n\n' +
    'Previously:  ' + pinned + '\n' +
    'Key file is: ' + found + '\n\n' +
    'Noct Wallet did NOT open. Opening would show the balance of a different ' +
    'wallet — which looks exactly like funds going missing, and could lead you to ' +
    'believe the original wallet is empty.\n\n' +
    'Your coins live in the key that produced the first address above. Restore ' +
    'that key file, or recover it from its 24-word seed phrase, then start Noct ' +
    'Wallet again. If you deliberately replaced the wallet, delete the ' +
    '"wallet.address" files to accept the new one.'
  );
}

/// Explanation for a launch refused because the key is missing but this app has
/// opened a wallet here before.
function missingKeyMessage(pinned, dataDir) {
  return (
    'The wallet key could not be found in:\n' + dataDir + '\n\n' +
    'but this app has opened a wallet here before:\n' + pinned + '\n\n' +
    'A new wallet was NOT created. Creating one would have shown you an empty ' +
    'balance as though your coins had disappeared — they have not; they belong to ' +
    'the key above.\n\n' +
    'If the folder is simply unavailable right now (antivirus, backup or sync ' +
    'software can hide it briefly), close this and start Noct Wallet again. ' +
    'Otherwise restore wallet.key, or recover it from your 24-word seed phrase.'
  );
}

/// Operator-facing explanation for a refused launch.
function wrongWalletMessage(expected, actual) {
  return (
    'A Noct wallet service is already running on this machine, and it is using a ' +
    'different wallet than the one on disk.\n\n' +
    'Your wallet:   ' + expected + '\n' +
    'Being served:  ' + (actual || '(unknown)') + '\n\n' +
    'Noct Wallet did NOT open, because showing you the wrong balance would be ' +
    'misleading — this is not a sign that anything happened to your coins.\n\n' +
    'Close any other Noct Wallet window, or end leftover "noct-walletd.exe" and ' +
    '"noctd.exe" processes in Task Manager, then start Noct Wallet again.'
  );
}

module.exports = {
  fetchState,
  servesWallet,
  networkDirs,
  pinPaths,
  readPin,
  writePins,
  hasOpenedBefore,
  checkPin,
  pinMismatchMessage,
  missingKeyMessage,
  wrongWalletMessage,
};
