// Smoke test of the **packaged** app — the artifact people actually install.
//
//   npm run dist && node test-e2e-packaged.js
//
// Every other end-to-end test here runs `electron .` from the source directory.
// That is a different program in the ways that have actually broken:
//
//   * binaries come from `process.resourcesPath/bin`, not `../noct/target/release`
//   * data lives in `app.getPath('userData')`, not `../demo`
//   * every file the app loads must be *inside the asar*, and `build.files` in
//     package.json is an allow-list — a new file that nobody adds to it is
//     missing only in the packaged build
//
// A missing `status.html` would have shown here as a blank window and nowhere
// else. So this checks the packaged bundle starts, shows something, builds its
// menu, and spawns its daemons **out of the bundle**.
//
// It deliberately does not wait for the wallet to come up: that needs the node
// ports, and this must be safe to run while a real wallet is open. What it
// asserts is everything that happens before the daemons matter, which is where
// the packaging faults live.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { _electron: electron } = require('playwright-core');

const PACKAGED = path.join(__dirname, 'dist', 'win-unpacked', 'Nocturnal Wallet.exe');
const ASAR = path.join(__dirname, 'dist', 'win-unpacked', 'resources', 'app.asar');

/// Files `main.js` loads by path. Each one has to be in the asar, and the only
/// thing standing between them and absence is a hand-maintained list.
const MUST_BE_PACKAGED = [
  'main.js',
  'wallet-guard.js',
  'wallet-setup.js',
  'setup.html',
  'setup-preload.js',
  'status.html',
  'status-preload.js',
];

async function run() {
  assert(fs.existsSync(PACKAGED), 'build it first: npm run dist');

  // 1. Everything the app loads is actually in the bundle.
  // The library rather than the `.cmd` shim: `execFileSync` on a `.cmd` is
  // EINVAL on current Node without a shell, and reaching for a shell to list the
  // contents of a file is more moving parts than the job needs.
  const listed = require('@electron/asar')
    .listPackage(ASAR)
    .map((l) => l.replace(/^[\\/]/, '').replace(/\\/g, '/'));
  for (const f of MUST_BE_PACKAGED) {
    assert(listed.includes(f), `${f} is missing from the asar — add it to build.files`);
  }

  // A scratch profile, so running this never touches a real wallet.
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'noct-packaged-'));

  let app;
  try {
    app = await electron.launch({
      executablePath: PACKAGED,
      args: ['--user-data-dir=' + profile],
      timeout: 90000,
    });

    // 2. It opens a window and stays open. An app that exits during startup —
    //    which is what a missing file or an unhandled spawn error does — fails
    //    here rather than in front of somebody.
    const win = await app.firstWindow({ timeout: 90000 });
    await win.waitForLoadState('domcontentloaded');
    assert(/Nocturnal Wallet/i.test(await win.title()), 'window title: ' + (await win.title()));

    // 3. It is showing *something*: either the startup page or the wallet. A
    //    blank window is the failure this test exists for.
    const showing = await win.evaluate(() => document.body.innerText.trim().length);
    assert(showing > 0, 'the window must not be blank');

    // 4. The menu is built.
    const net = await app.evaluate(({ Menu }) => {
      const m = Menu.getApplicationMenu();
      const n = m && m.items.find((i) => i.label === 'Network');
      return n ? n.submenu.items.map((s) => s.label) : null;
    });
    assert.deepStrictEqual(net, ['Mainnet', 'Testnet'], 'the Network menu must exist');

    // 5. **The daemons come out of the bundle.** In dev they come from the cargo
    //    target directory, so this is the one assertion that can only be made
    //    here — and `resources/bin` resolving wrongly is invisible until an
    //    install is in somebody's hands.
    const bin = await app.evaluate(() => {
      const path2 = process.resourcesPath;
      return path2;
    });
    const expected = path.join(__dirname, 'dist', 'win-unpacked', 'resources');
    assert.strictEqual(bin, expected, 'resourcesPath must point into the bundle');
    for (const exe of ['noctd.exe', 'noct-walletd.exe', 'noct-cli.exe']) {
      assert(
        fs.existsSync(path.join(bin, 'bin', exe)),
        exe + ' must be bundled under resources/bin'
      );
    }
  } finally {
    if (app) await app.close().catch(() => {});
    fs.rmSync(profile, { recursive: true, force: true });
  }
  console.log('e2e packaged app: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
