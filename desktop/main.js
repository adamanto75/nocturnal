// Noct desktop wallet — a native window that manages the node + wallet daemon.
//
// On launch it: ensures a wallet key exists, starts `noctd` (mining to that
// wallet) and `noct-walletd` (which serves the wallet UI + API), waits for the
// daemon to come up, then shows it in a real desktop window. On quit it stops
// both child processes.

const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const { spawn, execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');
const {
  fetchState,
  servesWallet,
  wrongWalletMessage,
  checkPin,
  pinMismatchMessage,
  pinPaths,
  readPin,
  writePins,
  networkDirs,
} = require("./wallet-guard");
const {
  normalizePhrase,
  restoreArgs,
  parseAddress,
  restoreErrorMessage,
  differentWalletWarning,
  phraseLooksComplete,
  phraseProblem,
} = require('./wallet-setup');

const ICON = path.join(__dirname, 'build', 'icon.ico');

// --- networks ----------------------------------------------------------------
// Ports mirror the daemons' own defaults (noct_core::params), so mainnet and
// testnet can run side by side without colliding.
const NETWORKS = {
  mainnet: { rpc: '127.0.0.1:9334', walletPort: 9340 },
  testnet: { rpc: '127.0.0.1:19334', walletPort: 19340 },
};

/// Window title, naming the network unless it is mainnet. Shared by both windows
/// so they can never disagree about which chain is open.
function windowTitle(network) {
  return network && network !== 'mainnet' ? 'Nocturnal Wallet — ' + network : 'Nocturnal Wallet';
}

/// Which network to open. `--testnet` (or NOCT_NETWORK=testnet) selects it;
/// mainnet is the default, so an existing install keeps behaving exactly as
/// before and nobody lands on a test chain by accident.
function selectedNetwork() {
  const fromArgs = process.argv.includes('--testnet') ? 'testnet' : null;
  const fromEnv = (process.env.NOCT_NETWORK || '').toLowerCase() === 'testnet' ? 'testnet' : null;
  return fromArgs || fromEnv || 'mainnet';
}

// --- where things live ------------------------------------------------------
// Installed: binaries are bundled in resources/bin, data lives in the app's
// userData folder (self-contained). Dev (`npm start`): binaries come from the
// cargo target dir and data reuses the project's demo folder.
//
// **Every network gets its own data directory, key and pins.** They must never
// share: a testnet wallet loaded against mainnet would show a zero balance and
// look exactly like the "my coins are gone" failure, and a shared pin would make
// switching networks read as a wallet mismatch. Mainnet keeps the original,
// unsuffixed paths so existing installs are untouched.
function paths(network = selectedNetwork()) {
  if (app.isPackaged) {
    const bin = path.join(process.resourcesPath, "bin");
    const root = app.getPath("userData");
    // The pin gets a second home outside `data`, per network.
    return { bin, ...networkDirs(root, process.env.LOCALAPPDATA, network) };
  }
  const suffix = network === "mainnet" ? "" : "-" + network;
  const coin = path.join(__dirname, '..', 'noct', 'target');
  const rel = path.join(coin, 'release');
  const bin = fs.existsSync(path.join(rel, 'noctd.exe')) ? rel : path.join(coin, 'debug');
  return {
    network,
    bin,
    data: path.join(__dirname, '..', 'demo' + suffix),
    chain: path.join(process.env.LOCALAPPDATA || app.getPath('userData'), 'Noct' + suffix, 'node'),
    altPin: path.join(__dirname, '..', 'demo' + suffix),
  };
}

let noctd = null;
let walletd = null;

/// Look for the key, tolerating a folder that is briefly unreadable.
///
/// Antivirus, backup and sync tools can make a directory read as empty for a
/// moment. Concluding "no wallet" on the first glance is how the app ended up
/// minting a fresh, empty wallet and presenting it as the user's own.
function findKey(fs, key, attempts = 6, waitMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try {
      if (fs.existsSync(key)) return true;
    } catch (_) {}
    if (i < attempts - 1) {
      // Synchronous wait: this runs before any window is shown.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, waitMs);
    }
  }
  return false;
}

/// What we know about the wallet on disk, before anything is created.
///
/// `first-run`  nothing here, and nothing ever was — offer create or restore.
/// `missing`    the key is gone but a pin proves a wallet was opened here —
///              never create over it; offer recovery from the seed phrase.
/// `ready`      the key is present.
function walletStatus(P) {
  fs.mkdirSync(P.data, { recursive: true });
  const key = path.join(P.data, 'wallet.key');
  const pins = pinPaths(P.data, P.altPin);
  if (findKey(fs, key)) return { state: 'ready', key, pins, pinned: readPin(fs, pins) };
  const pinned = readPin(fs, pins);
  return { state: pinned ? 'missing' : 'first-run', key, pins, pinned };
}

function walletAddress(P, key) {
  // Without --network this derives a MAINNET-tagged address, which noctd would
  // then refuse as belonging to the wrong network.
  return execFileSync(path.join(P.bin, "noct-cli.exe"), ["address", "--wallet", key, "--network", P.network])
    .toString()
    .trim();
}

// --- first-run / recovery setup ---------------------------------------------

/// Run `noct-cli`, handing `input` to it on **stdin**.
///
/// A seed phrase must never appear in `args`: command-line arguments are readable
/// from the process list by anything else running on the machine.
function runCli(cli, args, input) {
  try {
    return { ok: true, out: execFileSync(cli, args, { input, encoding: 'utf8' }) };
  } catch (e) {
    return { ok: false, stderr: String(e.stderr || '') || String(e.message || e) };
  }
}

// Set while the setup window is open; the IPC handlers below act on it.
let setupCtx = null;

function registerSetupHandlers() {
  ipcMain.handle('setup:info', () => ({ pinned: (setupCtx && setupCtx.status.pinned) || null }));

  ipcMain.handle('setup:problem', (_e, phrase) => phraseProblem(phrase));

  ipcMain.handle('setup:preview', (_e, raw) => {
    if (!setupCtx) return { ok: false, error: 'Setup is not open.' };
    const phrase = normalizePhrase(raw);
    if (!phraseLooksComplete(phrase)) return { ok: false, error: 'A recovery phrase is 24 words.' };
    const { P, status } = setupCtx;
    const r = runCli(path.join(P.bin, 'noct-cli.exe'), restoreArgs(status.key, { dryRun: true, network: P.network }), phrase);
    if (!r.ok) return { ok: false, error: restoreErrorMessage(r.stderr) };
    const address = parseAddress(r.out);
    if (!address) return { ok: false, error: 'The wallet tool did not report an address.' };
    return { ok: true, address, warning: differentWalletWarning(address, status.pinned) };
  });

  ipcMain.handle('setup:restore', (_e, raw) => {
    if (!setupCtx) return { ok: false, error: 'Setup is not open.' };
    const phrase = normalizePhrase(raw);
    const { P, status } = setupCtx;
    const r = runCli(path.join(P.bin, 'noct-cli.exe'), restoreArgs(status.key, { network: P.network }), phrase);
    if (!r.ok) return { ok: false, error: restoreErrorMessage(r.stderr) };
    const address = parseAddress(r.out) || walletAddress(P, status.key);
    // An explicit restore is a deliberate choice of wallet, so it becomes the
    // pinned one — including when it replaces a different pin, which the window
    // warned about before this point.
    writePins(fs, status.pins, address);
    setupCtx.finish({ key: status.key, address, pins: status.pins });
    return { ok: true, address };
  });

  ipcMain.handle('setup:create', () => {
    if (!setupCtx) return { ok: false, error: 'Setup is not open.' };
    const { P, status } = setupCtx;
    const r = runCli(path.join(P.bin, 'noct-cli.exe'), ["new", "--wallet", status.key, "--network", P.network]);
    if (!r.ok) return { ok: false, error: restoreErrorMessage(r.stderr) };
    const address = parseAddress(r.out) || walletAddress(P, status.key);
    writePins(fs, status.pins, address);
    setupCtx.finish({ key: status.key, address, pins: status.pins });
    return { ok: true, address };
  });
}

/// Show the setup window and resolve with the wallet once one exists, or `null`
/// if the window was closed without making one.
function runSetup(P, status) {
  return new Promise((resolve) => {
    const win = new BrowserWindow({
      width: 620,
      height: 760,
      minWidth: 460,
      minHeight: 560,
      backgroundColor: '#0e1114',
      title: windowTitle(P.network),
      icon: ICON,
      autoHideMenuBar: true,
      webPreferences: {
        // This window handles seed phrases: keep every isolation default on and
        // let it reach the main process only through the preload's channels.
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        preload: path.join(__dirname, 'setup-preload.js'),
      },
    });
    let settled = false;
    setupCtx = {
      P,
      status,
      finish: (wallet) => {
        settled = true;
        setupCtx = null;
        win.close();
        resolve(wallet);
      },
    };
    win.on('closed', () => {
      if (!settled) { setupCtx = null; resolve(null); }
    });
    win.loadFile(path.join(__dirname, 'setup.html'));
  });
}

function startDaemons(P, key, address) {
  fs.mkdirSync(P.chain, { recursive: true });
  // Mining is opt-in from the wallet UI (the "Start mining" toggle). We do NOT
  // pass --mine here: RandomX mining builds a ~2 GB dataset and pins CPU cores,
  // which shouldn't happen just because someone opened their wallet.
  const net = NETWORKS[P.network];
  // Both daemons are told the network explicitly. Without it they default to
  // mainnet and would serve a mainnet chain from the testnet data dir.
  noctd = spawn(
    path.join(P.bin, "noctd.exe"),
    ["--network", P.network, "--data-dir", P.chain, "--miner-address", address],
    { stdio: "ignore", windowsHide: true }
  );
  walletd = spawn(
    path.join(P.bin, "noct-walletd.exe"),
    ["--network", P.network, "--wallet", key, "--node", net.rpc,
     "--listen", "127.0.0.1:" + net.walletPort],
    { stdio: "ignore", windowsHide: true }
  );
}

function stopDaemons() {
  for (const p of [walletd, noctd]) {
    if (p && !p.killed) {
      try { p.kill(); } catch (_) {}
    }
  }
  walletd = noctd = null;
}

// Poll the wallet daemon until it responds, resolving with its state (or `null`
// after ~30s).
function walletUrl(P) {
  return "http://127.0.0.1:" + NETWORKS[P.network].walletPort;
}

function waitForWallet(url) {
  return new Promise((resolve) => {
    const tryOnce = async (n) => {
      const state = await fetchState(url);
      if (state) return resolve(state);
      if (n > 60) return resolve(null);
      setTimeout(() => tryOnce(n + 1), 500);
    };
    tryOnce(0);
  });
}

function createWindow(url, network) {
  const win = new BrowserWindow({
    width: 720,
    height: 900,
    minWidth: 460,
    minHeight: 640,
    backgroundColor: '#0e1114',
    title: windowTitle(network),
    icon: ICON,
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true },
  });
  win.loadURL(url);
  return win;
}

app.whenReady().then(async () => {
  const P = paths();
  registerSetupHandlers();

  let wallet;
  try {
    const status = walletStatus(P);
    if (status.state === 'ready') {
      wallet = { key: status.key, address: walletAddress(P, status.key), pins: status.pins };
    } else {
      // Either a genuine first run, or the key is missing where a wallet was
      // opened before. Both are answered by the same window — the difference is
      // that recovery says whose coins are at stake and never creates over them.
      wallet = await runSetup(P, status);
      if (!wallet) { app.quit(); return; }
    }
  } catch (e) {
    dialog.showErrorBox(
      'Nocturnal Wallet',
      'Could not find or create the wallet.\n\nExpected the Noct binaries under:\n' +
        P.bin +
        '\n\n(When running from source, build them with:  cargo build --release)\n\n' +
        String(e)
    );
    app.quit();
    return;
  }

  // Is the key on disk still the wallet this app has been opening? This catches
  // a replaced or restored key file, which no amount of checking the *daemon*
  // would notice.
  if (checkPin(fs, wallet.pins, wallet.address) === 'mismatch') {
    dialog.showErrorBox(
      'Nocturnal Wallet',
      pinMismatchMessage(readPin(fs, wallet.pins), wallet.address)
    );
    app.quit();
    return;
  }

  // A daemon left over from an earlier run may still hold the wallet port. If we
  // simply spawned ours, it would fail to bind and the window would quietly show
  // whatever wallet the *old* one has — which looks exactly like your coins
  // having vanished. So check what is already there before starting anything.
  const existing = await fetchState(walletUrl(P));
  if (existing) {
    if (!servesWallet(existing, wallet.address)) {
      dialog.showErrorBox('Nocturnal Wallet', wrongWalletMessage(wallet.address, existing.address));
      app.quit();
      return;
    }
    // Same wallet: reuse the running service instead of starting a duplicate
    // (and leave it running on quit, since we did not start it).
    createWindow(walletUrl(P), P.network);
    return;
  }

  startDaemons(P, wallet.key, wallet.address);
  const win = createWindow(walletUrl(P), P.network);
  const state = await waitForWallet(walletUrl(P));
  if (!state) {
    win.loadURL(
      'data:text/html,' +
        encodeURIComponent(
          '<body style="background:#0e1114;color:#e7edf3;font-family:sans-serif;padding:40px">' +
            '<h2>Nocturnal Wallet</h2><p>The wallet service did not start. Check the Noct binaries ' +
            'under <code>' + P.bin + '</code>.</p></body>'
        )
    );
    return;
  }
  // Belt and braces: whatever ended up answering must be serving the key we
  // loaded. Never display an unverified wallet.
  if (!servesWallet(state, wallet.address)) {
    dialog.showErrorBox('Nocturnal Wallet', wrongWalletMessage(wallet.address, state.address));
    stopDaemons();
    app.quit();
  }
});

app.on('window-all-closed', () => {
  stopDaemons();
  app.quit();
});
app.on('before-quit', stopDaemons);
process.on('exit', stopDaemons);
