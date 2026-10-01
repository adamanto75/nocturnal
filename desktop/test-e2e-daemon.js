// End-to-end test of what the app does when its daemons are not there, against
// a REAL Electron app.
//
//   node test-e2e-daemon.js
//
// This exists because of a real failure: the app sat for an hour showing a
// balance of 500,334 NOCT with **neither daemon running**. Nothing was watching
// them, their output went to `stdio: 'ignore'`, and the only sign was the words
// "daemon unreachable" beside the title. The three things asserted here are the
// three that were missing.
//
// It runs on **testnet**, in dev mode, against a throwaway wallet of its own —
// never a wallet holding real funds, and never the mainnet ports.

const assert = require('assert');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { execFileSync } = require('child_process');
const { _electron: electron } = require('playwright-core');

const ROOT = path.join(__dirname, '..');
const DEMO = path.join(ROOT, 'demo-testnet');
const KEY = path.join(DEMO, 'wallet.key');
const CLI = path.join(ROOT, 'noct', 'target', 'release', 'noct-cli.exe');
const WALLET_PORT = 19340; // testnet, so the mainnet wallet is never touched
const LOG = path.join(DEMO, 'logs', 'noct-walletd.log');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// A server that accepts the connection and then says nothing at all — which is
/// exactly what a daemon in the middle of a long re-scan looks like from outside.
function squatter(port) {
  return new Promise((resolve) => {
    const held = [];
    const srv = net.createServer((sock) => held.push(sock));
    srv.listen(port, '127.0.0.1', () =>
      resolve({
        close: () =>
          new Promise((done) => {
            held.forEach((s) => s.destroy());
            srv.close(done);
          }),
      })
    );
  });
}

function pidOn(port) {
  try {
    const out = execFileSync('netstat', ['-ano', '-p', 'TCP']).toString();
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(/127\.0\.0\.1:(\d+)\s+\S+\s+LISTENING\s+(\d+)/);
      if (m && Number(m[1]) === port) return Number(m[2]);
    }
  } catch (_) {}
  return null;
}

async function run() {
  assert(fs.existsSync(CLI), 'build noct-cli first: cargo build --release');
  fs.mkdirSync(DEMO, { recursive: true });
  if (!fs.existsSync(KEY)) {
    execFileSync(CLI, ['new', '--wallet', KEY, '--network', 'testnet']);
  }
  const address = execFileSync(CLI, ['address', '--wallet', KEY, '--network', 'testnet'])
    .toString()
    .trim();
  fs.writeFileSync(path.join(DEMO, 'wallet.address'), address + '\n');

  const squat = await squatter(WALLET_PORT);
  let app;
  let closedSquat = false;
  try {
    app = await electron.launch({
      args: [__dirname],
      cwd: __dirname,
      timeout: 60000,
      env: { ...process.env, NOCT_NETWORK: 'testnet' },
    });
    const win = await app.firstWindow({ timeout: 60000 });

    // 1. The port is held by something that never answers. The app must WAIT for
    //    it and say so — not read the silence as "nothing is running" and spawn
    //    a pair of daemons onto a port they cannot have, which is how it ended
    //    up with no daemons and a stale balance on screen.
    await win.waitForSelector('#busy:not(.hide)', { timeout: 30000 });
    const waiting = await win.textContent('#busyTitle');
    assert.strictEqual(waiting.trim(), 'Waiting for the wallet service', 'it must say it is waiting');
    const why = await win.textContent('#busyWhat');
    assert(why.includes(String(WALLET_PORT)), 'it must name the port it is waiting on: ' + why);

    // 2. It keeps waiting well past the thirty seconds it used to give up after.
    //    An upgrade that changes the state format makes the first run re-scan the
    //    whole chain before it answers anything, so giving up was simply wrong.
    await sleep(32000);
    assert.strictEqual(
      (await win.textContent('#busyTitle')).trim(),
      'Waiting for the wallet service',
      'it must still be waiting after 30s, not have declared the service dead'
    );
    const elapsed = await win.textContent('#elapsed');
    assert(/\d+ seconds so far/.test(elapsed), 'it must show how long it has waited: ' + elapsed);

    // 3. The squatter goes away. Now the app may have the port, and must start
    //    its own daemons and show the wallet.
    await squat.close();
    closedSquat = true;
    await win.waitForSelector('#balance', { timeout: 180000 });
    assert.strictEqual(await win.title(), 'Noct Wallet — testnet', 'the wallet must open');

    // 4. The daemons' output is kept. Without this there was no record anywhere
    //    of why one had stopped.
    assert(fs.existsSync(LOG), 'the wallet daemon must have a log at ' + LOG);
    assert(fs.readFileSync(LOG, 'utf8').length > 0, 'the log must not be empty');

    // 5. Kill the wallet daemon out from under it. The window must stop showing
    //    figures it can no longer check, and say what happened and where to look.
    const pid = pidOn(WALLET_PORT);
    assert(pid, 'could not find the wallet daemon to kill');
    execFileSync('taskkill', ['/F', '/PID', String(pid)]);

    await win.waitForSelector('#bad:not(.hide)', { timeout: 30000 });
    const title = await win.textContent('#badTitle');
    assert(title.includes('noct-walletd'), 'it must name what stopped: ' + title);
    assert(
      (await win.textContent('#logPath')).includes('noct-walletd.log'),
      'it must say where the output is'
    );
    assert.strictEqual(
      await win.locator('#balance').count(),
      0,
      'the balance must be GONE, not dimmed in a corner: nothing can confirm it any more'
    );

    // 6. And it can be started again from there, without restarting the app.
    await win.click('#restart');
    await win.waitForSelector('#balance', { timeout: 180000 });
  } finally {
    if (app) await app.close().catch(() => {});
    if (!closedSquat) await squat.close().catch(() => {});
    // Leave nothing listening behind, whichever way this went.
    for (const port of [WALLET_PORT, 19334]) {
      const pid = pidOn(port);
      if (pid) {
        try {
          execFileSync('taskkill', ['/F', '/PID', String(pid)]);
        } catch (_) {}
      }
    }
  }
  console.log('e2e daemon supervision: all checks passed');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
