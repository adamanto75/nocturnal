// Tests for the first-run / recovery logic.
//
//   node test-wallet-setup.js
//
// The end-to-end restore (phrase in, same wallet out) is covered against the
// real binary in the Rust workspace; what matters here is everything around it:
// tidying what a person pastes, keeping the phrase out of argv, and being clear
// when a valid phrase opens the wrong wallet.

const assert = require('assert');
const {
  normalizePhrase,
  wordCount,
  phraseLooksComplete,
  phraseProblem,
  restoreArgs,
  parseAddress,
  restoreErrorMessage,
  differentWalletWarning,
} = require('./wallet-setup');

const W = (n) => Array.from({ length: n }, (_, i) => 'word' + (i + 1)).join(' ');
const MINE = 'C4do37CzzKCV3XJHDinLAoL7MaEtRU5oHgGTWLVb8JBY5zEDayjqYqHG';
const OTHER = 'CTUNucoMow4mw8tTGwtH5NUzUhyC1hHd8j1pRDa49RXrVKuGbDmfUD2o';

// 1. People paste their phrase in whatever shape they wrote it down.
{
  assert.strictEqual(normalizePhrase('  Abandon   Ability\nAble  '), 'abandon ability able');
  // numbered lists — the numbers are not words
  assert.strictEqual(normalizePhrase('1. abandon 2. ability 3. able'), 'abandon ability able');
  assert.strictEqual(normalizePhrase('1) abandon\n2) ability'), 'abandon ability');
  // punctuation and case
  assert.strictEqual(normalizePhrase('Abandon, ability; ABLE.'), 'abandon ability able');
  // nothing at all
  assert.strictEqual(normalizePhrase(''), '');
  assert.strictEqual(normalizePhrase(null), '');
  assert.strictEqual(normalizePhrase(undefined), '');
}

// 2. Counting drives the UI, so it must agree with normalisation.
{
  assert.strictEqual(wordCount(W(24)), 24);
  assert.strictEqual(wordCount('1. ' + W(24)), 24, 'numbering must not inflate the count');
  assert.strictEqual(wordCount(''), 0);
  assert(phraseLooksComplete(W(24)));
  assert(!phraseLooksComplete(W(23)));
  assert(!phraseLooksComplete(W(25)));
}

// 3. Progress messages, including the one-word-short case people actually hit.
{
  assert(/24-word/.test(phraseProblem('')));
  assert.strictEqual(phraseProblem(W(23)), '23 of 24 words so far.');
  assert(/exactly 24/.test(phraseProblem(W(25))));
  assert.strictEqual(phraseProblem(W(24)), null, 'a full phrase has no problem');
}

// 4. THE SECURITY PROPERTY: the phrase is never an argument. Arguments are
//    readable from the process list by anything else on the machine.
{
  const phrase = W(24);
  const args = restoreArgs('C:\\wallets\\wallet.key');
  assert(args.includes('--mnemonic-stdin'), 'the CLI must be told to read stdin');
  assert(!args.includes('--mnemonic'), 'the literal flag must not be used');
  for (const a of args) {
    assert(!a.includes('word1'), 'no argument may contain any part of the phrase');
    assert(a !== phrase, 'the phrase must not be an argument');
  }
  assert.deepStrictEqual(
    restoreArgs("k.key", { dryRun: true }),
    ["restore", "--wallet", "k.key", "--mnemonic-stdin", "--dry-run"]
  );

  // The network must reach the CLI, or the address it reports back carries the
  // wrong tag and every later pin comparison reads as a different wallet.
  assert.deepStrictEqual(
    restoreArgs("k.key", { network: "testnet" }),
    ["restore", "--wallet", "k.key", "--mnemonic-stdin", "--network", "testnet"]
  );
  assert.deepStrictEqual(
    restoreArgs("k.key", { dryRun: true, network: "testnet" }),
    ["restore", "--wallet", "k.key", "--mnemonic-stdin", "--network", "testnet", "--dry-run"]
  );
  // Omitting it must stay clean, so mainnet behaviour is byte-identical to before.
  assert(!restoreArgs("k.key").includes("--network"), "no network flag when unspecified");
}

// 5. Reading the address back out of the CLI.
{
  assert.strictEqual(parseAddress('restored wallet: x.key\naddress: ' + MINE + '\n'), MINE);
  assert.strictEqual(parseAddress('address: ' + MINE), MINE);
  assert.strictEqual(parseAddress('nothing useful'), null);
  assert.strictEqual(parseAddress(''), null);
  assert.strictEqual(parseAddress(null), null);
}

// 6. CLI failures become something a person can act on.
{
  const bad = restoreErrorMessage('error: invalid seed phrase (a word is misspelled, out of order, or the checksum failed)');
  assert(/misspelled/.test(bad) && /order matters/.test(bad), 'explains what to re-check');

  const exists = restoreErrorMessage('error: wallet.key already exists — refusing to overwrite a key');
  assert(/will not be overwritten/.test(exists), 'never implies the old key was replaced');

  assert(/24 words/.test(restoreErrorMessage('error: seed phrase must be 24 words')));
  // an unrecognised failure is still surfaced, not swallowed
  assert(/Disk full/.test(restoreErrorMessage('error: disk full')));
  assert(/could not be restored/.test(restoreErrorMessage('')));
}

// 7. A valid phrase for the WRONG wallet is the dangerous case: it succeeds, and
//    shows an empty balance. Say so before the key is written.
{
  assert.strictEqual(differentWalletWarning(MINE, MINE), null, 'the expected wallet is silent');
  assert.strictEqual(differentWalletWarning(MINE, null), null, 'a first run has nothing to compare');

  const warn = differentWalletWarning(OTHER, MINE);
  assert(warn.includes(MINE) && warn.includes(OTHER), 'names both wallets');
  assert(/wrong order/.test(warn), 'explains how a valid phrase can still be the wrong one');
}

console.log('wallet-setup: all 7 checks passed');
