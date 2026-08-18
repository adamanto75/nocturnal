// First-run and recovery logic for the desktop wallet: creating a wallet, and
// restoring one from its 24-word seed phrase.
//
// The rules this file encodes, in order of importance:
//
//  1. **A phrase never travels as a command-line argument.** It goes to
//     `noct-cli` on stdin. Arguments are visible in the process list to every
//     other program on the machine — this project read a running process's
//     `--miner-address` out of it, so the exposure is demonstrated, not
//     theoretical.
//  2. **Preview before writing.** A restore is checked with `--dry-run` first,
//     so the person is shown which wallet the phrase opens and can stop before
//     any key file exists.
//  3. **Never overwrite a key.** `noct-cli` refuses, and nothing here works
//     around that.
//
// Kept apart from `main.js` so it can be tested without Electron:
// `node test-wallet-setup.js`.

/// Tidy a pasted seed phrase into the canonical "24 lowercase words" form.
///
/// People paste from wherever they wrote it down: numbered lists, one word per
/// line, with stray punctuation. Numeric tokens are dropped because a BIP39 word
/// is never a number, so "1. abandon 2. ability" and "abandon ability" are the
/// same phrase.
function normalizePhrase(text) {
  return String(text == null ? '' : text)
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w && !/^\d+$/.test(w))
    .join(' ')
    .trim();
}

function wordCount(phrase) {
  const p = normalizePhrase(phrase);
  return p ? p.split(' ').length : 0;
}

/// Is this the right shape to send to `noct-cli`? Only the count is checked
/// here; the wordlist and checksum are the CLI's job, and duplicating that
/// judgement in JavaScript would risk the two disagreeing.
function phraseLooksComplete(phrase) {
  return wordCount(phrase) === 24;
}

/// Explain a phrase that is not yet worth submitting, or `null` if it is.
function phraseProblem(phrase) {
  const n = wordCount(phrase);
  if (n === 0) return 'Enter your 24-word recovery phrase.';
  if (n < 24) return n + ' of 24 words so far.';
  if (n > 24) return 'That is ' + n + ' words — a Noct phrase is exactly 24.';
  return null;
}

/// Arguments for `noct-cli restore`. The phrase is deliberately absent: it is
/// passed to the process on stdin by the caller.
///
/// `network` matters even though the *key* is network-agnostic: the address the
/// CLI reports back is what the app pins and compares against. Derived on the
/// wrong network it would carry the wrong tag, and every later check would read
/// as "this is a different wallet".
function restoreArgs(keyPath, { dryRun, network } = {}) {
  const args = ['restore', '--wallet', keyPath, '--mnemonic-stdin'];
  if (network) args.push('--network', network);
  if (dryRun) args.push('--dry-run');
  return args;
}

/// Pull the address out of `noct-cli`'s output ("address: C…").
function parseAddress(output) {
  const m = /address:\s*(\S+)/.exec(String(output || ''));
  return m ? m[1] : null;
}

/// Turn `noct-cli`'s stderr into something worth showing a person.
function restoreErrorMessage(stderr) {
  const text = String(stderr || '').trim();
  const line = (/error:\s*(.+)/.exec(text) || [])[1];
  if (!line) {
    return 'The wallet could not be restored. ' + (text || 'No further detail was reported.');
  }
  if (/invalid seed phrase/i.test(line)) {
    return 'That phrase was not accepted: a word is misspelled, the words are out of order, ' +
      'or the checksum does not match. Check it against what you wrote down — the order matters.';
  }
  if (/must be 24 words/i.test(line)) {
    return 'A Noct recovery phrase is exactly 24 words.';
  }
  if (/already exists/i.test(line)) {
    return 'There is already a wallet key here, and it will not be overwritten. ' +
      'Move it aside first if you are certain you want to replace it.';
  }
  return line.charAt(0).toUpperCase() + line.slice(1);
}

/// Warning for restoring a wallet that is not the one this app was using.
///
/// Not an error — switching wallets is legitimate — but it is also exactly what
/// a mistyped-but-valid phrase looks like, so it is said plainly before the key
/// is written.
function differentWalletWarning(restored, pinned) {
  if (!pinned || !restored || restored === pinned) return null;
  return (
    'This phrase opens a different wallet than the one this app was using.\n\n' +
    'Was using: ' + pinned + '\n' +
    'This phrase: ' + restored + '\n\n' +
    'If you meant to switch wallets, carry on. If you expected the first address, ' +
    'stop and re-check the phrase — a phrase with words in the wrong order can still ' +
    'be valid, and simply opens a different, empty wallet.'
  );
}

module.exports = {
  normalizePhrase,
  wordCount,
  phraseLooksComplete,
  phraseProblem,
  restoreArgs,
  parseAddress,
  restoreErrorMessage,
  differentWalletWarning,
};
