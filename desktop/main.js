// Noct desktop wallet — a native window that manages the node + wallet daemon.
//
// On launch it: ensures a wallet key exists, starts `noctd` (mining to that
// wallet) and `noct-walletd` (which serves the wallet UI + API), waits for the
// daemon to come up, then shows it in a real desktop window. On quit it stops
// both child processes.

const { app, BrowserWindow, Menu, dialog, ipcMain } = require('electron');
const { spawn, execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');
const tcp = require('net');
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

/// Which network to open. `--testnet`/`--mainnet` (or NOCT_NETWORK) select it;
/// mainnet is the default, so an existing install keeps behaving exactly as
/// before and nobody lands on a test chain by accident.
///
/// `--mainnet` is accepted as well as `--testnet` so the Network menu can switch
/// *back*. Relying on "no flag means mainnet" would make that switch depend on
/// the default never changing, which is exactly the kind of thing that changes.
/// The flag beats the environment, because the menu passes a flag and an
/// inherited `NOCT_NETWORK` must not quietly win against something just clicked.
function selectedNetwork() {
  const fromArgs = process.argv.includes('--testnet')
    ? 'testnet'
    : process.argv.includes('--mainnet')
      ? 'mainnet'
      : null;
  const env = (process.env.NOCT_NETWORK || '').toLowerCase();
  const fromEnv = env === 'testnet' || env === 'mainnet' ? env : null;
  return fromArgs || fromEnv || 'mainnet';
}

/// The network currently open. `null` until the app has chosen one, after which
/// it is what `paths()` answers with — so switching is a matter of changing this
/// and reopening, not of restarting the process.
let currentNetwork = null;

/// Guard against a second switch landing on top of one still in progress: the
/// daemons would be started twice and the two races would fight over the ports.
let switching = false;

/// Open the other chain **in place**.
///
/// The first version of this relaunched the app, which was the obvious thing and
/// the wrong one: nothing about a different chain needs a new process. Each
/// network already has its own data directory, key, pins and ports, so switching
/// is stopping two daemons and starting two others — the same work the status
/// page's restart button already does, pointed at different paths.
///
/// Each network's wallet, key and balance are separate, which is exactly what
/// stops a testnet wallet being read as an emptied mainnet one. The window says
/// which chain it is on the whole time: testnet carries a permanent banner,
/// mainnet says it has not launched, and the menu marks the open one. A
/// confirmation dialog on top of all that is friction, not safety, when nothing
/// is destroyed and the way back is one click.
async function switchNetwork(to) {
  if (to !== 'mainnet' && to !== 'testnet') return false;
  if (to === currentNetwork || switching) return false;
  switching = true;
  try {
    const from = currentNetwork;
    stopDaemons();
    currentNetwork = to;
    buildMenu(to);
    return await openNetwork(from);
  } finally {
    switching = false;
  }
}

/// The application menu.
///
/// It exists for one reason: until mainnet launches there is no mainnet network
/// to join, and this app opens mainnet by default — so the chain where anything
/// actually happens was reachable only by editing a shortcut. This is not a
/// change of default; it is a way out of one.
///
/// The menu bar is shown rather than auto-hidden, because a way out nobody can
/// find is not one.
function buildMenu(network) {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: 'Wallet',
        submenu: [
          { role: 'reload' },
          { role: 'toggleDevTools' },
          { type: 'separator' },
          { role: 'quit' },
        ],
      },
      {
        label: 'Network',
        submenu: [
          {
            label: 'Mainnet',
            type: 'radio',
            checked: network === 'mainnet',
            click: () => switchNetwork('mainnet'),
          },
          {
            label: 'Testnet',
            type: 'radio',
            checked: network === 'testnet',
            click: () => switchNetwork('testnet'),
          },
        ],
      },
    ])
  );
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
function paths(network = currentNetwork || selectedNetwork()) {
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

// --- daemon supervision ------------------------------------------------------
// The daemons used to be started with `stdio: 'ignore'` and nothing watching
// them. When one died — a port already held, a crash, something killing it —
// the window carried on showing the last balance it had seen, with two words in
// a corner, and there was no record anywhere of what had happened. A wallet
// showing money it can no longer verify is the same failure this project keeps
// closing, so now: everything they print is kept, and their exit is an event the
// window hears about.

const LOG_LIMIT = 2 * 1024 * 1024; // keep the tail of a long run, not all of it

let stopping = false;    // set while we are killing them, so an expected exit is not reported as a failure
let daemonLogs = {};     // daemon name -> log file
let mainWin = null;      // the window showing the wallet, or the status page
let statusState = null;  // what that page should say
let statusShowing = false; // is the window on the status page rather than the wallet?
let launchPaths = null;  // the paths/wallet a restart would use again

/// Open a daemon's log for appending, trimming first if it has grown past the
/// cap. Trimming keeps the **end** — the lines that explain the last failure.
function openLog(P, name) {
  const dir = path.join(P.data, 'logs');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name + '.log');
  try {
    const size = fs.statSync(file).size;
    if (size > LOG_LIMIT) {
      const keep = Buffer.alloc(Math.floor(LOG_LIMIT / 2));
      const fd = fs.openSync(file, 'r');
      fs.readSync(fd, keep, 0, keep.length, size - keep.length);
      fs.closeSync(fd);
      fs.writeFileSync(file, keep);
    }
  } catch (_) {}
  const out = fs.createWriteStream(file, { flags: 'a' });
  out.write('\n=== ' + new Date().toISOString() + ' — starting ' + name + ' ===\n');
  return { file, out };
}

/// The last `n` non-empty lines of a log, for showing on the stopped page.
function logTail(file, n = 40) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.length).slice(-n).join('\n');
  } catch (_) {
    return '';
  }
}

/// Start one daemon with its output captured and its exit observed.
function spawnDaemon(P, name, args) {
  const { file, out } = openLog(P, name);
  daemonLogs[name] = file;
  const child = spawn(path.join(P.bin, name + '.exe'), args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdout.on('data', (d) => out.write(d));
  child.stderr.on('data', (d) => out.write(d));
  // An unhandled 'error' on a child process throws, which in the main process
  // takes the whole app down — so a missing binary would kill the window rather
  // than explain itself.
  child.on('error', (e) => {
    out.write('\ncould not start ' + name + ': ' + e.message + '\n');
    daemonStopped(name, 'could not be started (' + e.message + ')');
  });
  child.on('exit', (code, signal) => {
    out.write('\n=== ' + name + ' exited: ' + (signal ? 'signal ' + signal : 'code ' + code) + ' ===\n');
    if (child === walletd) walletd = null;
    if (child === noctd) noctd = null;
    daemonStopped(name, signal ? 'was stopped (' + signal + ')' : 'exited with code ' + code);
  });
  return child;
}

function startDaemons(P, key, address) {
  fs.mkdirSync(P.chain, { recursive: true });
  stopping = false;
  // Mining is opt-in from the wallet UI (the "Start mining" toggle). We do NOT
  // pass --mine here: RandomX mining builds a ~2 GB dataset and pins CPU cores,
  // which shouldn't happen just because someone opened their wallet.
  const net = NETWORKS[P.network];
  // Both daemons are told the network explicitly. Without it they default to
  // mainnet and would serve a mainnet chain from the testnet data dir.
  noctd = spawnDaemon(P, 'noctd',
    ["--network", P.network, "--data-dir", P.chain, "--miner-address", address]);
  walletd = spawnDaemon(P, 'noct-walletd',
    ["--network", P.network, "--wallet", key, "--node", net.rpc,
     "--listen", "127.0.0.1:" + net.walletPort]);
}

/// A daemon we started is gone.
///
/// The two matter differently. Losing **noct-walletd** means every figure on
/// screen is the last one that could be checked rather than a current one, and
/// nothing is left that could tell them apart — so the page goes, and what
/// happened takes its place.
///
/// Losing **noctd** leaves the wallet page honest on its own: it cannot sync, it
/// says so on every poll in place of "synced", and the height it shows stops
/// advancing. Throwing away a page somebody may be reading would be the worse
/// answer, so that one is recorded in the log and left to the page to report.
/// (Not by relabelling the title bar, either: the wallet page rewrites its own
/// title on every poll, so a warning put there would vanish within seconds.)
function daemonStopped(name, what) {
  if (stopping) return; // we asked for it
  if (name !== 'noct-walletd') return;
  showStatus({
    state: 'stopped',
    name,
    what,
    network: launchPaths ? launchPaths.P.network : null,
    log: daemonLogs[name] || '',
    tail: logTail(daemonLogs[name]),
  });
}

function stopDaemons() {
  stopping = true;
  for (const p of [walletd, noctd]) {
    if (p && !p.killed) {
      try { p.kill(); } catch (_) {}
    }
  }
  walletd = noctd = null;
}

function walletUrl(P) {
  return "http://127.0.0.1:" + NETWORKS[P.network].walletPort;
}

/// Put the status page on screen with `payload`, or update it if it is already
/// there. Replacing the wallet page is the point: once the service is gone, the
/// figures on it are the last ones that could be checked, not current ones.
function showStatus(payload) {
  statusState = payload;
  if (!mainWin || mainWin.isDestroyed()) return;
  if (statusShowing) {
    // An update sent before the page has finished loading is simply lost, which
    // costs nothing: the page asks for the current payload as soon as it loads.
    mainWin.webContents.send('status:update', payload);
    return;
  }
  // Tracked with a flag rather than by reading the window's URL, because a load
  // in flight still reports the *old* URL — and the ticking updates would then
  // each start the load again, so it would never finish.
  statusShowing = true;
  mainWin.loadFile(path.join(__dirname, 'status.html'));
}

/// Leave the status page for the wallet itself.
function showWallet(url) {
  statusShowing = false;
  if (mainWin && !mainWin.isDestroyed()) mainWin.loadURL(url);
}

function registerStatusHandlers() {
  ipcMain.handle('status:read', () => statusState);
  // The wallet page offers this when it is on a chain with no network to join.
  // `switchNetwork` asks before doing anything, so a stray call cannot move
  // somebody's wallet without them seeing why.
  ipcMain.handle('status:switch', (_e, to) =>
    switchNetwork(to === 'testnet' ? 'testnet' : 'mainnet')
  );
  ipcMain.handle('status:restart', async () => {
    if (!launchPaths) return false;
    const { P, wallet } = launchPaths;
    stopDaemons();
    startDaemons(P, wallet.key, wallet.address);
    await openWallet(P, wallet);
    return true;
  });
}

/// Is something serving this port? Asked before spawning, because the answer
/// decides whether starting our own daemon would be useful or merely fatal.
function portInUse(port) {
  return new Promise((resolve) => {
    const sock = tcp.createConnection({ host: '127.0.0.1', port });
    const done = (yes) => { sock.destroy(); resolve(yes); };
    sock.on('connect', () => done(true));
    sock.on('error', () => resolve(false));
    sock.setTimeout(1000, () => done(false));
  });
}

/// Wait for the wallet daemon to answer, for **as long as it is alive**.
///
/// This used to give up after thirty seconds and report that the service had not
/// started. But a release that changes the wallet's state format makes the first
/// run read the whole chain again before it answers anything — minutes,
/// legitimately — so the message was wrong, and the black rectangle behind it
/// said nothing at all. Declaring a daemon broken because it is busy is how a
/// working wallet gets reported as a dead one.
///
/// `alive` is what ends the wait instead: when the thing we are waiting for is
/// gone, waiting longer is pointless, and the exit handler has already put the
/// reason on screen.
function waitForWallet(url, alive, onTick) {
  return new Promise((resolve) => {
    const started = Date.now();
    const tryOnce = async () => {
      const state = await fetchState(url);
      if (state) return resolve(state);
      if (!(await alive())) return resolve(null);
      if (onTick) onTick(Math.round((Date.now() - started) / 1000));
      setTimeout(tryOnce, 500);
    };
    tryOnce();
  });
}

function createWindow(network) {
  return new BrowserWindow({
    width: 720,
    height: 900,
    minWidth: 460,
    minHeight: 640,
    backgroundColor: '#0e1114',
    title: windowTitle(network),
    icon: ICON,
    // Shown, not auto-hidden: the Network menu is the only way out of a mainnet
    // that has not launched, and a way out behind Alt is one most people will
    // never find. The setup window keeps its menu hidden — nothing in it helps
    // while a seed phrase is being typed.
    autoHideMenuBar: false,
    webPreferences: {
      contextIsolation: true,
      // The status page needs a way to ask what happened and to retry. The
      // preload stays attached when the window moves on to the wallet UI, which
      // is our own page; its whole surface is those two calls.
      preload: path.join(__dirname, 'status-preload.js'),
    },
  });
}

/// Show the wallet once its daemon answers, explaining the wait while it does
/// not. Returns false if it never did — in which case the reason is already on
/// screen.
async function openWallet(P, wallet) {
  const url = walletUrl(P);
  const what = 'Opening ' + windowTitle(P.network) + '.';
  const net = P.network;
  showStatus({ state: 'starting', what, seconds: 0, network: net });
  const state = await waitForWallet(
    url,
    () => walletd !== null,
    (seconds) => showStatus({ state: 'starting', what, seconds, network: net })
  );
  if (!state) return false;
  // Belt and braces: whatever ended up answering must be serving the key we
  // loaded. Never display an unverified wallet.
  if (!servesWallet(state, wallet.address)) {
    dialog.showErrorBox('Nocturnal Wallet', wrongWalletMessage(wallet.address, state.address));
    stopDaemons();
    app.quit();
    return false;
  }
  showWallet(url);
  return true;
}

/// Open whichever network `currentNetwork` names: find or create its wallet,
/// check the pin, start its daemons and show it.
///
/// Called at launch and again on every network switch. It was the body of
/// `whenReady`; switching needed every line of it, and copying them would have
/// been two startup paths to keep in step — which is how one of them quietly
/// stops checking the pin.
async function openNetwork(fallback) {
  const P = paths();
  // Where to land if this network cannot be opened. At launch there is nowhere
  // to go, so a failure quits as it always did. On a switch there is: the chain
  // that was working a second ago. Cancelling the setup window for a network you
  // have never used must not take the wallet you *were* looking at down with it.
  // `fallback` is cleared on the way back, so a second failure ends rather than
  // bouncing between the two for ever.
  const giveUp = async () => {
    if (!fallback) { app.quit(); return false; }
    currentNetwork = fallback;
    buildMenu(currentNetwork);
    return await openNetwork(null);
  };

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
      if (!wallet) return await giveUp();
    }
  } catch (e) {
    dialog.showErrorBox(
      'Nocturnal Wallet',
      'Could not find or create the wallet.\n\nExpected the Noct binaries under:\n' +
        P.bin +
        '\n\n(When running from source, build them with:  cargo build --release)\n\n' +
        String(e)
    );
    return await giveUp();
  }

  // Is the key on disk still the wallet this app has been opening? This catches
  // a replaced or restored key file, which no amount of checking the *daemon*
  // would notice.
  if (checkPin(fs, wallet.pins, wallet.address) === 'mismatch') {
    dialog.showErrorBox(
      'Nocturnal Wallet',
      pinMismatchMessage(readPin(fs, wallet.pins), wallet.address)
    );
    return await giveUp();
  }

  launchPaths = { P, wallet };
  // Reuse the window on a switch. A second one would leave the old chain's page
  // open beside the new one, which is the clearest possible way to show somebody
  // two balances and let them believe both are current.
  if (!mainWin || mainWin.isDestroyed()) mainWin = createWindow(P.network);
  else mainWin.setTitle(windowTitle(P.network));
  const port = NETWORKS[P.network].walletPort;

  // A daemon left over from an earlier run may still hold the wallet port. If we
  // simply spawned ours, it would fail to bind and the window would quietly show
  // whatever wallet the *old* one has — which looks exactly like your coins
  // having vanished. So check what is already there before starting anything.
  //
  // **And a daemon that does not answer is not the same as one that is not
  // there.** The probe waits a second and a half; a daemon in the middle of a
  // re-scan does not answer for minutes. Reading that silence as "nothing is
  // running" is what made this app spawn a pair of daemons onto ports it could
  // not have, watch them exit on the spot, and then show an hour-old balance
  // with nothing at all behind it. So when the port is held, wait for whoever
  // holds it rather than starting a rival.
  let existing = await fetchState(walletUrl(P));
  if (!existing && (await portInUse(port))) {
    showStatus({
      state: 'waiting',
      network: P.network,
      what: 'Something is already using port ' + port + ' and has not answered yet. '
        + 'Waiting for it rather than starting a second one, which could not have the port anyway.',
      seconds: 0,
    });
    existing = await waitForWallet(
      walletUrl(P),
      () => portInUse(port),
      (seconds) => showStatus({ state: 'waiting', what: statusState.what, seconds, network: P.network })
    );
    // Whoever held it is gone without ever answering; fall through and start our
    // own, which can now have the port.
  }
  if (existing) {
    if (!servesWallet(existing, wallet.address)) {
      dialog.showErrorBox('Nocturnal Wallet', wrongWalletMessage(wallet.address, existing.address));
      return await giveUp();
    }
    // Same wallet: reuse the running service instead of starting a duplicate
    // (and leave it running on quit, since we did not start it).
    showWallet(walletUrl(P));
    return true;
  }

  startDaemons(P, wallet.key, wallet.address);
  return await openWallet(P, wallet);
}

// A handle for the end-to-end test, which drives the switch the way the menu
// item and the banner button do. Nothing in the app reads it.
globalThis.__switch = switchNetwork;

app.whenReady().then(async () => {
  registerSetupHandlers();
  registerStatusHandlers();
  currentNetwork = selectedNetwork();
  buildMenu(currentNetwork);
  await openNetwork(null);
});

app.on('window-all-closed', () => {
  stopDaemons();
  app.quit();
});
app.on('before-quit', stopDaemons);
process.on('exit', stopDaemons);
