// The network switch must be visible **in the wallet page** and must work when
// clicked, against a REAL Electron app.
//
//   node test-e2e-network-toggle.js
//
// The switch started life as an item in the application menu bar. Three separate
// reports of "there is no way to toggle between mainnet and testnet" later, that
// is a settled question: a control nobody finds is not a control. It is now a
// labelled pair of buttons at the top of the wallet itself, and this clicks
// them rather than calling the function behind them — the gap between those two
// is exactly where "the menu is there, it just does nothing for me" lives.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { _electron: electron } = require('playwright-core');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'noct', 'target', 'release', 'noct-cli.exe');

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

async function run() {
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');
  const mainnetAddress = ensureWallet('mainnet');
  const testnetAddress = ensureWallet('testnet');

  let app;
  try {
    app = await electron.launch({ args: [__dirname, '--mainnet'], cwd: __dirname, timeout: 60000 });
    const win = await app.firstWindow({ timeout: 60000 });
    const pid = await app.evaluate(() => process.pid);

    // Wait for the wallet page itself, not the starting page.
    await win.waitForSelector('#balance', { timeout: 300000 });

    // 1. **It is on screen.** Not behind a menu, not behind Alt.
    await win.waitForSelector('#netpick.show', { timeout: 30000 });
    assert(await win.isVisible('#netMainnet'), 'the Mainnet button must be visible');
    assert(await win.isVisible('#netTestnet'), 'the Testnet button must be visible');

    // 2. It marks the one you are on, and that one is not clickable.
    assert(
      await win.locator('#netMainnet').evaluate((b) => b.classList.contains('on')),
      'mainnet must be marked as current'
    );
    assert(await win.locator('#netMainnet').isDisabled(), 'the current network is not a button');
    assert(await win.locator('#netTestnet').isEnabled(), 'the other one is');

    // 3. **Clicking it works.** This is the claim that kept being wrong.
    await win.click('#netTestnet');
    await win.waitForFunction(
      (want) => {
        const el = document.getElementById('address');
        return el && el.textContent.trim() === want;
      },
      testnetAddress,
      { timeout: 300000 }
    );
    assert.strictEqual(await app.evaluate(() => process.pid), pid, 'and without restarting');
    assert(
      await win.locator('#netTestnet').evaluate((b) => b.classList.contains('on')),
      'the switch must now mark testnet'
    );
    assert(/testnet/i.test(await win.title()), 'title follows: ' + (await win.title()));

    // 4. And back, because a one-way switch is a trap.
    await win.click('#netMainnet');
    await win.waitForFunction(
      (want) => {
        const el = document.getElementById('address');
        return el && el.textContent.trim() === want;
      },
      mainnetAddress,
      { timeout: 300000 }
    );
    assert(
      await win.locator('#netMainnet').evaluate((b) => b.classList.contains('on')),
      'and back to mainnet'
    );
  } finally {
    if (app) await app.close().catch(() => {});
  }
  console.log('e2e network toggle: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
