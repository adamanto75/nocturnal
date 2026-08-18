// Tests for the wallet guard — the check that stopped the desktop app from
// displaying a wallet it had not verified.
//
//   node test-wallet-guard.js
//
// No framework: this ships with an Electron shim, not a JS project.

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  fetchState,
  servesWallet,
  wrongWalletMessage,
  networkDirs,
  checkPin,
  pinMismatchMessage,
  missingKeyMessage,
  pinPaths,
  readPin,
  hasOpenedBefore,
} = require('./wallet-guard');

const MINE = 'C4do37CzzKCV3XJHDinLAoL7MaEtRU5oHgGTWLVb8JBY5zEDayjqYqHG';
const THEIRS = 'CTUNucoMow4mw8tTGwtH5NUzUhyC1hHd8j1pRDa49RXrVKuGbDmfUD2o';

// Serve one canned body on a free port; resolves with { url, close }.
function serve(body) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(body);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

async function run() {
  // 1. A service serving *our* wallet is accepted.
  {
    const s = await serve(JSON.stringify({ ok: true, address: MINE, balance: '500000' }));
    const state = await fetchState(s.url);
    assert(state, 'state should parse');
    assert(servesWallet(state, MINE), 'our own wallet must be accepted');
    s.close();
  }

  // 2. THE BUG: a leftover daemon serving a *different* wallet is refused.
  //    Previously the app would have shown this wallet's (empty) balance as if
  //    it were yours.
  {
    const s = await serve(JSON.stringify({ ok: true, address: THEIRS, balance: '0' }));
    const state = await fetchState(s.url);
    assert(state, 'state should parse');
    assert(!servesWallet(state, MINE), 'a different wallet must be refused');
    const msg = wrongWalletMessage(MINE, state.address);
    assert(msg.includes(MINE) && msg.includes(THEIRS), 'the message names both wallets');
    assert(msg.includes('did NOT open'), 'the message explains nothing was opened');
    s.close();
  }

  // 3. A reply with no address at all is refused — never guess.
  {
    const s = await serve(JSON.stringify({ ok: false, error: 'node unreachable' }));
    const state = await fetchState(s.url);
    assert(!servesWallet(state, MINE), 'a reply without an address must be refused');
    s.close();
  }

  // 4. Junk that is not JSON yields "nothing there" rather than throwing.
  {
    const s = await serve('<html>not the wallet</html>');
    const state = await fetchState(s.url);
    assert.strictEqual(state, null, 'non-JSON must resolve to null');
    assert(!servesWallet(state, MINE), 'null is never a match');
    s.close();
  }

  // 5. Nothing listening resolves to null (the normal first-launch path), and
  //    must not hang.
  {
    const started = Date.now();
    const state = await fetchState('http://127.0.0.1:1', 800);
    assert.strictEqual(state, null, 'a closed port must resolve to null');
    assert(Date.now() - started < 5000, 'must not hang on a closed port');
  }

  // 6. The wallet is pinned on first run, and a *replaced key file* is caught.
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'noct-pin-'));
    const alt = fs.mkdtempSync(path.join(os.tmpdir(), 'noct-alt-'));
    const pins = pinPaths(dir, alt);

    assert.strictEqual(checkPin(fs, pins, MINE), 'ok', 'first run pins the wallet');
    assert.strictEqual(readPin(fs, pins), MINE, 'the pin is recorded');
    assert.strictEqual(checkPin(fs, pins, MINE), 'ok', 'the same wallet still opens');
    assert.strictEqual(checkPin(fs, pins, THEIRS), 'mismatch', 'a replaced key is refused');

    const msg = pinMismatchMessage(MINE, THEIRS);
    assert(msg.includes(MINE) && msg.includes(THEIRS), 'the message names both wallets');
    assert(msg.includes('did NOT open'), 'it is explicit that nothing was opened');

    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(alt, { recursive: true, force: true });
  }

  // 7. THE FAILURE THAT KEPT HAPPENING: the data folder reads as empty at
  //    launch, so the key AND the pin beside it both look gone. A pin kept only
  //    next to the key would let the app conclude "first run" and mint a new,
  //    empty wallet — presenting it as the user's own. The second pin survives.
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'noct-gone-'));
    const alt = fs.mkdtempSync(path.join(os.tmpdir(), 'noct-alt2-'));
    const pins = pinPaths(dir, alt);
    checkPin(fs, pins, MINE); // establish the wallet

    // The whole data folder becomes unreadable/empty.
    fs.rmSync(dir, { recursive: true, force: true });

    assert(
      hasOpenedBefore(fs, pins),
      'the surviving pin still proves a wallet was opened here before'
    );
    assert.strictEqual(readPin(fs, pins), MINE, 'and it names the right wallet');
    const msg = missingKeyMessage(MINE, dir);
    assert(msg.includes(MINE), 'the refusal names the wallet the coins belong to');
    assert(msg.includes('NOT created'), 'and states that no new wallet was made');

    // With BOTH pins gone it is a genuine first run, and creating is correct.
    fs.rmSync(alt, { recursive: true, force: true });
    assert(!hasOpenedBefore(fs, pins), 'no pins anywhere means a real first run');
  }

  // 8. The networks must share NOTHING on disk. A testnet key opened against
  //    mainnet shows a zero balance — the exact failure this guard exists for.
  {
    const root = path.join('C:', 'Users', 'x', 'AppData', 'Roaming', 'noct-wallet-desktop');
    const lad = path.join('C:', 'Users', 'x', 'AppData', 'Local');
    const main = networkDirs(root, lad, 'mainnet');
    const test = networkDirs(root, lad, 'testnet');

    // Mainnet must be byte-identical to the pre-testnet layout, or every
    // existing install would look like a brand-new one and mint a wallet.
    assert.strictEqual(main.data, root, 'mainnet data dir must be unchanged');
    assert.strictEqual(main.altPin, path.join(lad, 'Noct'), 'mainnet pin unchanged');
    assert.strictEqual(networkDirs(root, lad).data, root, 'no network defaults to mainnet');

    for (const k of ['data', 'chain', 'altPin']) {
      assert.notStrictEqual(main[k], test[k], k + ' must differ between networks');
    }
    // And their pin files must not collide either.
    const mp = pinPaths(main.data, main.altPin);
    const tp = pinPaths(test.data, test.altPin);
    for (const a of mp) {
      assert(!tp.includes(a), 'pin path ' + a + ' is shared between networks');
    }
  }

  console.log('wallet-guard: all 8 checks passed');
}

run().catch((e) => {
  console.error('FAILED:', e.message);
  process.exit(1);
});
