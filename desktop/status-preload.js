// Bridge for the status window — the page shown while the wallet service is
// starting, and the one shown when it has stopped.
//
// It is deliberately tiny: the page reads what the main process knows, listens
// for updates, and can ask for a restart. Nothing here touches the filesystem or
// spawns anything, and context isolation stays on.
//
// This preload is attached to the wallet window as well, because a preload is a
// property of the window and that window later navigates to the wallet UI. The
// three calls below are the entire surface, and none of them can be used to do
// anything the app does not already do on its own.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('noctStatus', {
  /// What the main process currently knows: `{ state, ... }`.
  read: () => ipcRenderer.invoke('status:read'),
  /// Start the daemons again after a failure.
  restart: () => ipcRenderer.invoke('status:restart'),
  /// Updates pushed while this page is open.
  onUpdate: (fn) => ipcRenderer.on('status:update', (_e, payload) => fn(payload)),
});
