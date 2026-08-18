// End-to-end test of the recovery flow, against a REAL Electron app.
//
//   node test-e2e-setup.js
//
// The unit tests cover the phrase handling and the window's own logic, but they
// stub the bridge between them. This exercises the parts nothing else does: the
// preload's context bridge, the IPC channels, and `noct-cli` actually being
// spawned with the phrase on stdin.
//
// It runs in dev mode, so the wallet under test is the throwaway `demo` wallet —
// never a wallet holding real funds. The demo key is moved aside and restored
// again at the end, whatever happens.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { _electron: electron } = require('playwright-core');

const ROOT = path.join(__dirname, '..');
const DEMO = path.join(ROOT, 'demo');
const KEY = path.join(DEMO, 'wallet.key');
const PIN = path.join(DEMO, 'wallet.address');
const CLI = path.join(ROOT, 'noct', 'target', 'release', 'noct-cli.exe');

const aside = (p) => p + '.e2e-aside';

function moveAside(p) {
  if (fs.existsSync(p)) fs.renameSync(p, aside(p));
}
function moveBack(p) {
  if (fs.existsSync(aside(p))) {
    if (fs.existsSync(p)) fs.rmSync(p);
    fs.renameSync(aside(p), p);
  }
}

async function run() {
  assert(fs.existsSync(KEY), 'the demo wallet must exist to run this test');
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');

  // The wallet we will lose and recover, and its phrase. Never printed.
  const expected = execFileSync(CLI, ['address', '--wallet', KEY]).toString().trim();
  const phrase = execFileSync(CLI, ['seed', '--wallet', KEY]).toString().trim();
  assert.strictEqual(phrase.split(/\s+/).length, 24, 'expected a 24-word phrase');

  // Simulate what kept happening: the key is gone, but the pin proves a wallet
  // was opened here. The app must offer recovery, not mint a new wallet.
  fs.writeFileSync(PIN, expected + '\n');
  moveAside(KEY);
  assert(!fs.existsSync(KEY), 'the key must be gone for this test to mean anything');

  let app;
  try {
    app = await electron.launch({ args: [__dirname], cwd: __dirname, timeout: 60000 });
    const win = await app.firstWindow({ timeout: 60000 });
    await win.waitForLoadState('domcontentloaded');

    // 1. It opened the SETUP window, not the wallet, and did not create a key.
    assert.strictEqual(await win.title(), 'Noct Wallet — Setup', 'the setup window must open');
    assert(!fs.existsSync(KEY), 'no wallet may be created while the pin says one exists');

    // 2. It names the wallet whose coins are at stake.
    await win.waitForSelector('#pinnedBox:not(.hide)', { timeout: 15000 });
    const pinnedShown = await win.textContent('#pinnedAddr');
    assert.strictEqual(pinnedShown.trim(), expected, 'the pinned wallet must be named');

    // 3. Enter a phrase that is 24 valid words but NOT this wallet's, and check
    //    the app says so rather than quietly opening an empty wallet.
    const otherPhrase = (() => {
      const tmp = path.join(os.tmpdir(), 'noct-e2e-other-' + process.pid + '.key');
      execFileSync(CLI, ['new', '--wallet', tmp]);
      const p = execFileSync(CLI, ['seed', '--wallet', tmp]).toString().trim();
      fs.rmSync(tmp);
      return p;
    })();

    await win.click('#goRestore');
    await win.fill('#phrase', otherPhrase);
    await win.click('#check');
    await win.waitForSelector('#warnBox:not(.hide)', { timeout: 20000 });
    const warn = await win.textContent('#warnBox');
    assert(warn.includes(expected), 'the warning names the wallet that was expected');
    assert(!fs.existsSync(KEY), 'checking a phrase must never write a key');

    // 4. Now the RIGHT phrase: preview shows the expected wallet, no warning.
    await win.fill('#phrase', phrase);
    await win.click('#check');
    await win.waitForSelector('#previewBox:not(.hide)', { timeout: 20000 });
    const preview = (await win.textContent('#previewAddr')).trim();
    assert.strictEqual(preview, expected, 'the preview must name the wallet being recovered');
    assert(await win.isHidden('#warnBox'), 'the expected wallet must not warn');
    assert(!fs.existsSync(KEY), 'a preview must still not have written anything');

    // 5. Commit. The key appears and is the wallet we lost.
    await win.click('#confirm');
    for (let i = 0; i < 100 && !fs.existsSync(KEY); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    assert(fs.existsSync(KEY), 'the key must exist after restoring');
    const restored = execFileSync(CLI, ['address', '--wallet', KEY]).toString().trim();
    assert.strictEqual(restored, expected, 'the restored wallet must be the one we lost');
    assert.strictEqual(fs.readFileSync(PIN, 'utf8').trim(), expected, 'the pin must name it too');

    console.log('e2e: recovery flow passed — setup window shown, wrong phrase warned,');
    console.log('     preview wrote nothing, restore reproduced the wallet.');
  } finally {
    if (app) { try { await app.close(); } catch (_) {} }
    // Whatever happened, put the demo wallet back exactly as it was.
    if (fs.existsSync(aside(KEY))) {
      if (fs.existsSync(KEY)) fs.rmSync(KEY);
      moveBack(KEY);
    }
  }
}

run().catch((e) => {
  console.error('FAILED:', e && e.message ? e.message : e);
  process.exit(1);
});
