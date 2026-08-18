// Bridge for the setup window.
//
// The window runs sandboxed, with context isolation on and no Node access, so it
// cannot touch the filesystem or spawn anything itself. It gets exactly these
// five calls, and the seed phrase travels no further than the main process,
// which hands it to `noct-cli` on stdin.
//
// Everything here goes through `ipcRenderer`. A sandboxed preload cannot
// `require` project modules — only `electron` and a few Node built-ins are
// available — so even the word count is answered by the main process rather than
// duplicated on this side.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('noct', {
  /// What the window should show: the pinned wallet, if this is a recovery.
  info: () => ipcRenderer.invoke('setup:info'),
  /// Validate a phrase and report the address it opens. Writes nothing.
  preview: (phrase) => ipcRenderer.invoke('setup:preview', phrase),
  /// Commit: write the key file for this phrase.
  restore: (phrase) => ipcRenderer.invoke('setup:restore', phrase),
  /// Generate a brand-new wallet.
  create: () => ipcRenderer.invoke('setup:create'),
  /// Word-count feedback while typing.
  problem: (phrase) => ipcRenderer.invoke('setup:problem', phrase),
});
