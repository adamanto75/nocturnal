// End-to-end test that switching networks happens **in place**, against a REAL
// Electron app.
//
//   node test-e2e-network-switch.js
//
// The first version of the Network menu relaunched the app. Nothing about a
// different chain needs a new process — each network already has its own data
// directory, key, pins and ports — and a wallet that restarts itself when you
// change a view is a wallet people will not change the view on.
//
// So: the same process, the same window, and the page really serving the other
// chain afterwards. The process id and the window are what make this a test of
// "in place" rather than of "it eventually showed testnet".

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { _electron: electron } = require('playwright-core');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'noct', 'target', 'release', 'noct-cli.exe');

/// Both networks need a wallet already, or the switch opens the setup window —
/// which is correct behaviour and a different test.
function ensureWallet(network) {
  const dir = path.join(ROOT, network === 'mainnet' ? 'demo' : 'demo-testnet');
  fs.mkdirSync(dir, { recursive: true });
  const key = path.join(dir, 'wallet.key');
  if (!fs.existsSync(key)) execFileSync(CLI, ['new', '--wallet', key, '--network', network]);
  const address = execFileSync(CLI, ['address', '--wallet', key, '--network', network])
    .toString()
    .trim();
  fs.writeFileSync(path.join(dir, 'wallet.address'), address + '\n');
  return address;
}

const netOf = (app) =>
  app.evaluate(({ Menu }) => {
    const n = Menu.getApplicationMenu().items.find((i) => i.label === 'Network');
    const on = n.submenu.items.find((s) => s.checked);
    return on ? on.label.toLowerCase() : null;
  });

async function run() {
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');
  const mainnetAddress = ensureWallet('mainnet');
  const testnetAddress = ensureWallet('testnet');
  assert.notStrictEqual(mainnetAddress, testnetAddress, 'the two wallets must be different');

  let app;
  try {
    app = await electron.launch({ args: [__dirname], cwd: __dirname, timeout: 60000 });
    const win = await app.firstWindow({ timeout: 60000 });
    const pidBefore = await app.evaluate(() => process.pid);

    assert.strictEqual(await netOf(app), 'mainnet', 'it must start on mainnet');
    await win.waitForSelector('#balance', { timeout: 300000 });
    assert.strictEqual(
      (await win.textContent('#address')).trim(),
      mainnetAddress,
      'the page must be serving the mainnet wallet'
    );

    // Switch, the way the menu item and the banner button both do.
    await app.evaluate(() => globalThis.__switch('testnet'));

    // **Same process.** This is the whole point: no relaunch.
    assert.strictEqual(await app.evaluate(() => process.pid), pidBefore, 'it must not restart');
    assert.strictEqual(await netOf(app), 'testnet', 'the menu must follow');

    // And the page is really serving the other chain, not the old one still up.
    await win.waitForFunction(
      (want) => {
        const el = document.getElementById('address');
        return el && el.textContent.trim() === want;
      },
      testnetAddress,
      { timeout: 300000 }
    );
    assert.strictEqual(
      (await win.textContent('#address')).trim(),
      testnetAddress,
      'the page must now serve the testnet wallet'
    );
    assert(/testnet/i.test(await win.title()), 'and the title must say so: ' + (await win.title()));

    // Back again, because a switch you cannot undo is a trap.
    await app.evaluate(() => globalThis.__switch('mainnet'));
    assert.strictEqual(await app.evaluate(() => process.pid), pidBefore, 'still no restart');
    await win.waitForFunction(
      (want) => {
        const el = document.getElementById('address');
        return el && el.textContent.trim() === want;
      },
      mainnetAddress,
      { timeout: 300000 }
    );
    assert.strictEqual(await netOf(app), 'mainnet', 'and the menu is back on mainnet');
  } finally {
    if (app) await app.close().catch(() => {});
  }
  console.log('e2e network switch: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
