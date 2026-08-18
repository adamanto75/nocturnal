//! On-disk block storage: an append-only log so a node keeps its chain across
//! restarts instead of re-syncing from genesis.
//!
//! Format: each accepted block is one length-prefixed frame — `u32` little-endian
//! length, then `wire::encode_message(Wire::Block(block, txs))`. Append-only means
//! writes are simple and a crash can only ever damage the *last* frame, which
//! [`BlockStore::load_all`] detects and discards (the chain simply resumes from
//! the last complete block; anything missing is re-fetched from peers by the
//! normal initial block download).
//!
//! Blocks are **re-validated** when replayed on startup — the on-disk log is
//! treated as untrusted input like any other. That costs CPU proportional to the
//! chain length; skipping revalidation for locally-accepted blocks would be a
//! meaningful optimization but needs care, since it bypasses every consensus
//! check, so it is deliberately not done here.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

use noct_core::block::Block;
use noct_core::p2p::Wire;
use noct_core::tx::Transaction;
use noct_core::wire;

/// Reject any stored frame larger than this (guards a corrupt length prefix).
const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// An append-only block log.
pub struct BlockStore {
    writer: BufWriter<File>,
    path: PathBuf,
}

impl BlockStore {
    /// Open (creating if needed) the log at `path` for appending.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(BlockStore { writer: BufWriter::new(file), path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one block and its transactions, flushing to the OS immediately so
    /// an accepted block is not lost on a crash.
    pub fn append(&mut self, block: &Block, txs: &[Transaction]) -> io::Result<()> {
        let bytes = wire::encode_message(&Wire::Block(block.clone(), txs.to_vec()));
        self.writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.writer.write_all(&bytes)?;
        self.writer.flush()
    }

    /// Replace the entire log with `blocks`.
    ///
    /// Append-only is not enough once reorgs exist: after switching branches the
    /// log still holds the discarded blocks, and a restart would replay the wrong
    /// chain. Rewriting from the new canonical chain keeps disk and memory in
    /// agreement. The new log is staged in a temporary file and renamed over the
    /// old one, so a crash mid-rewrite leaves the previous log intact rather than
    /// a half-written one.
    pub fn rewrite<'a>(
        &mut self,
        blocks: impl Iterator<Item = (&'a Block, &'a [Transaction])>,
    ) -> io::Result<()> {
        let tmp = self.path.with_extension("dat.tmp");
        {
            let file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(file);
            for (block, txs) in blocks {
                let bytes = wire::encode_message(&Wire::Block(block.clone(), txs.to_vec()));
                w.write_all(&(bytes.len() as u32).to_le_bytes())?;
                w.write_all(&bytes)?;
            }
            w.flush()?;
        }
        // Drop our handle on the old file before replacing it (Windows will not
        // rename over an open file).
        self.writer = BufWriter::new(OpenOptions::new().create(true).append(true).open(&tmp)?);
        std::fs::rename(&tmp, &self.path)?;
        // Re-open the (now renamed) log for further appends.
        self.writer = BufWriter::new(OpenOptions::new().create(true).append(true).open(&self.path)?);
        Ok(())
    }

    /// Read every complete frame from the log at `path`, in order.
    ///
    /// A truncated trailing frame (crash mid-append) is discarded rather than
    /// treated as an error. A missing file yields an empty log.
    pub fn load_all(path: impl AsRef<Path>) -> io::Result<Vec<(Block, Vec<Transaction>)>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;

        let mut out = Vec::new();
        let mut cur: &[u8] = &data;
        loop {
            if cur.len() < 4 {
                break; // no more frames (or a torn length prefix)
            }
            let len = u32::from_le_bytes(cur[..4].try_into().unwrap()) as usize;
            if len > MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: corrupt frame length {len}", path.display()),
                ));
            }
            if cur.len() < 4 + len {
                break; // truncated final frame — discard it
            }
            let frame = &cur[4..4 + len];
            match wire::decode_message(frame) {
                Ok(Wire::Block(block, txs)) => out.push((block, txs)),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: unexpected message in block log", path.display()),
                    ))
                }
                // A decodable-length but malformed frame means real corruption,
                // not a torn write — surface it rather than silently truncating.
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: malformed block in log ({e:?})", path.display()),
                    ))
                }
            }
            cur = &cur[4 + len..];
        }
        Ok(out)
    }
}

/// Command sent to the background writer.
enum StoreCmd {
    Append(Block, Vec<Transaction>),
    Rewrite(Vec<(Block, Vec<Transaction>)>),
}

/// A block store whose disk writes run on a **background thread**.
///
/// Persisting a block must never block consensus: the write happens while the
/// node holds its state lock, and a stalled write — a slow disk, an antivirus
/// scan, or a cloud-sync tool (OneDrive/Dropbox) holding the file — would
/// otherwise freeze the whole node. Here `append`/`rewrite` just hand work to a
/// dedicated writer over a channel and return immediately; only that one thread
/// ever waits on the disk.
///
/// Dropping the store closes the channel and joins the writer, so a clean
/// shutdown flushes everything still queued.
pub struct AsyncStore {
    tx: Option<Sender<StoreCmd>>,
    handle: Option<JoinHandle<()>>,
}

impl AsyncStore {
    /// Open the log at `path` and spawn its writer thread.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut store = BlockStore::open(path)?;
        let (tx, rx) = mpsc::channel::<StoreCmd>();
        let handle = std::thread::spawn(move || {
            for cmd in rx {
                let result = match cmd {
                    StoreCmd::Append(block, txs) => store.append(&block, &txs),
                    StoreCmd::Rewrite(blocks) => {
                        store.rewrite(blocks.iter().map(|(b, t)| (b, t.as_slice())))
                    }
                };
                if let Err(e) = result {
                    eprintln!("WARNING: block store write failed: {e}");
                }
            }
        });
        Ok(AsyncStore { tx: Some(tx), handle: Some(handle) })
    }

    /// Queue a block to be appended (returns immediately).
    pub fn append(&self, block: &Block, txs: &[Transaction]) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(StoreCmd::Append(block.clone(), txs.to_vec()));
        }
    }

    /// Queue a full rewrite of the log from the canonical chain (after a reorg).
    pub fn rewrite(&self, blocks: Vec<(Block, Vec<Transaction>)>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(StoreCmd::Rewrite(blocks));
        }
    }
}

impl Drop for AsyncStore {
    fn drop(&mut self) {
        // Close the channel so the writer drains and exits, then wait for it.
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeState;
    use noct_core::address::Network;
    use noct_wallet::Wallet;
    use rand_core::OsRng;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("noct-store-{tag}-{nanos}.dat"))
    }

    // Mine `n` blocks on a fresh node, returning them.
    fn mined(n: usize) -> Vec<(Block, Vec<Transaction>)> {
        let w = Wallet::random(&mut OsRng, Network::Mainnet);
        let mut node = NodeState::new(w.address());
        (0..n).map(|_| node.mine_block(&mut OsRng).unwrap()).collect()
    }

    #[test]
    fn appends_and_loads_blocks_in_order() {
        let path = temp_path("roundtrip");
        let blocks = mined(3);
        {
            let mut store = BlockStore::open(&path).unwrap();
            for (b, txs) in &blocks {
                store.append(b, txs).unwrap();
            }
        }
        let loaded = BlockStore::load_all(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        for (i, (b, _)) in loaded.iter().enumerate() {
            assert_eq!(b.id(), blocks[i].0.id());
            // Mined blocks start at height 1 — genesis is block 0.
            assert_eq!(b.coinbase.height, i as u64 + 1);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_log_is_empty_not_an_error() {
        let path = temp_path("missing");
        assert!(BlockStore::load_all(&path).unwrap().is_empty());
    }

    #[test]
    fn async_store_persists_after_drop() {
        let path = temp_path("async");
        let blocks = mined(3);
        {
            let store = AsyncStore::open(&path).unwrap();
            for (b, txs) in &blocks {
                store.append(b, txs); // non-blocking; writer thread does the I/O
            }
            // Dropping the store joins the writer, flushing everything queued.
        }
        let loaded = BlockStore::load_all(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[2].0.id(), blocks[2].0.id());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_trailing_frame_is_discarded() {
        let path = temp_path("torn");
        let blocks = mined(2);
        {
            let mut store = BlockStore::open(&path).unwrap();
            for (b, txs) in &blocks {
                store.append(b, txs).unwrap();
            }
        }
        // Simulate a crash mid-append: lop bytes off the end.
        let mut data = std::fs::read(&path).unwrap();
        data.truncate(data.len() - 10);
        std::fs::write(&path, &data).unwrap();

        // The first block survives; the torn one is dropped, not an error.
        let loaded = BlockStore::load_all(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0.id(), blocks[0].0.id());
        let _ = std::fs::remove_file(&path);
    }
}
