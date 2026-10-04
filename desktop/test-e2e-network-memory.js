// The network you chose must still be the network you get after a restart.
//
//   node test-e2e-network-memory.js
//
// This is a regression test for something I broke. The Network menu originally
// relaunched the app with `--testnet`, and the flag on the new command line was
// the only thing carrying the choice. Making the switch happen in place — the
// right fix for a different complaint — removed it, so every restart went back
// to mainnet and the menu looked like it did nothing at all.
//
// Nothing about that was visible in a test, because every test launched the app
// once.

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

const netOf = (app) =>
  app.evaluate(({ Menu }) => {
    const n = Menu.getApplicationMenu().items.find((i) => i.label === 'Network');
    const on = n.submenu.items.find((s) => s.checked);
    return on ? on.label.toLowerCase() : null;
  });

/// Launch with no network flag at all, which is what a desktop shortcut does.
const launch = () => electron.launch({ args: [__dirname], cwd: __dirname, timeout: 60000 });

async function run() {
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');
  ensureWallet('mainnet');
  ensureWallet('testnet');

  // Start from a known state: nothing remembered, so the default applies.
  let app = await launch();
  // Ask only for the directory: `app.evaluate` runs in a context with no
  // `require`, so the joining happens on this side.
  const userData = await app.evaluate(({ app: a }) => a.getPath('userData'));
  const memoryFile = path.join(userData, 'network.txt');
  await app.close();
  fs.rmSync(memoryFile, { force: true });

  // 1. With nothing remembered, a flagless launch opens the default.
  app = await launch();
  try {
    await app.firstWindow({ timeout: 60000 });
    assert.strictEqual(await netOf(app), 'mainnet', 'the default is still mainnet');

    // 2. Switch, as the menu item does.
    await app.evaluate(() => globalThis.__switch('testnet'));
    assert.strictEqual(await netOf(app), 'testnet', 'the switch takes effect');
  } finally {
    await app.close().catch(() => {});
  }

  assert.strictEqual(
    fs.readFileSync(memoryFile, 'utf8').trim(),
    'testnet',
    'and it is written down, not merely held in memory'
  );

  // 3. **The point of the test.** Launch again with no flag — the way a shortcut
  //    does — and it must still be testnet.
  app = await launch();
  try {
    await app.firstWindow({ timeout: 60000 });
    assert.strictEqual(
      await netOf(app),
      'testnet',
      'a restart must open the network that was chosen, not the default'
    );

    // 4. And switching back is remembered just the same, or the trap is only
    //    moved rather than removed.
    await app.evaluate(() => globalThis.__switch('mainnet'));
  } finally {
    await app.close().catch(() => {});
  }
  assert.strictEqual(fs.readFileSync(memoryFile, 'utf8').trim(), 'mainnet', 'and back again');

  // 5. An explicit flag still wins over what was remembered — otherwise the
  //    remembered value becomes impossible to override.
  app = await electron.launch({ args: [__dirname, '--testnet'], cwd: __dirname, timeout: 60000 });
  try {
    await app.firstWindow({ timeout: 60000 });
    assert.strictEqual(await netOf(app), 'testnet', '--testnet must beat the remembered mainnet');
  } finally {
    await app.close().catch(() => {});
  }

  console.log('e2e network memory: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
