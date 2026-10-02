// End-to-end test of the Network menu, against a REAL Electron app.
//
//   node test-e2e-network-menu.js
//
// The menu exists because until mainnet launches there is no mainnet network to
// join, and the app opens mainnet by default — so the chain where anything
// actually happens was reachable only by editing a shortcut. A menu nobody can
// reach would be no better, so this checks the menu is really there, that the
// radio marks the network actually open, and that each item is wired to a
// switch. The relaunch itself is not exercised: it ends the process under test.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { _electron: electron } = require('playwright-core');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'noct', 'target', 'release', 'noct-cli.exe');

/// Read the application menu as the main process sees it.
async function menu(app) {
  return app.evaluate(({ Menu }) => {
    const m = Menu.getApplicationMenu();
    if (!m) return null;
    return m.items.map((i) => ({
      label: i.label,
      submenu: (i.submenu ? i.submenu.items : []).map((s) => ({
        label: s.label,
        type: s.type,
        checked: s.checked,
        enabled: s.enabled,
      })),
    }));
  });
}

async function openOn(network, demoDir) {
  fs.mkdirSync(demoDir, { recursive: true });
  const key = path.join(demoDir, 'wallet.key');
  if (!fs.existsSync(key)) {
    execFileSync(CLI, ['new', '--wallet', key, '--network', network]);
  }
  const address = execFileSync(CLI, ['address', '--wallet', key, '--network', network])
    .toString()
    .trim();
  fs.writeFileSync(path.join(demoDir, 'wallet.address'), address + '\n');

  const args = [__dirname];
  if (network === 'testnet') args.push('--testnet');
  return electron.launch({ args, cwd: __dirname, timeout: 60000 });
}

async function run() {
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');

  for (const network of ['testnet', 'mainnet']) {
    const demo = path.join(ROOT, network === 'mainnet' ? 'demo' : 'demo-testnet');
    let app;
    try {
      app = await openOn(network, demo);
      await app.firstWindow({ timeout: 60000 });

      const m = await menu(app);
      assert(m, 'there must be an application menu at all');

      const net = m.find((x) => x.label === 'Network');
      assert(net, 'a Network menu must exist: ' + JSON.stringify(m.map((x) => x.label)));

      const labels = net.submenu.map((s) => s.label);
      assert.deepStrictEqual(labels, ['Mainnet', 'Testnet'], 'both chains must be offered');

      // **The radio must mark the network actually open.** A menu that says
      // Mainnet while serving testnet would be worse than no menu: it would be
      // the app telling you which chain your balance is on, wrongly.
      for (const item of net.submenu) {
        const expected = item.label.toLowerCase() === network;
        assert.strictEqual(item.type, 'radio', item.label + ' must be a radio item');
        assert.strictEqual(
          item.checked,
          expected,
          `with ${network} open, ${item.label} should be ${expected ? 'checked' : 'unchecked'}`
        );
        assert.strictEqual(item.enabled, true, item.label + ' must be clickable');
      }

      // And the window agrees with the menu about which chain this is —
      // **including while the status page is up**, which is every launch and
      // minutes of it after a state-format change. A testnet window that does
      // not say testnet is how a test wallet gets mistaken for a real one.
      const win = await app.firstWindow();
      const title = await win.title();
      const says = network === 'mainnet' ? !/testnet/i.test(title) : /testnet/i.test(title);
      assert(says, `the window title must name the chain while starting (${network}): ${title}`);
    } finally {
      if (app) await app.close().catch(() => {});
    }
  }
  console.log('e2e network menu: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
