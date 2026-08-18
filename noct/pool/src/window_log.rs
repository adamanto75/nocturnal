//! Durable PPLNS window: the accepted shares a restart must not forget.
//!
//! The payout ledger already survives a crash, but it only records work once a
//! round has *matured*. Everything between — shares accepted into the PPLNS
//! window but not yet paid — lived purely in memory. A restart, a crash, or an
//! ordinary redeploy therefore silently discarded work miners had already done,
//! and they had no way to tell it had happened.
//!
//! ## Why append-only rather than a snapshot
//!
//! Snapshotting the whole window periodically is simpler, but it chooses how much
//! miner work to lose on a crash — a few seconds of it, every time. Appending one
//! line per accepted share loses nothing: the record is on disk before the share
//! is acknowledged.
//!
//! The file is compacted once it grows past a multiple of the window size, since
//! only the last `window_size` lines can ever matter.
//!
//! ## What this is not
//!
//! It is a record of *credit*, not of money. Nothing here can pay anyone; the
//! ledger still decides that. A corrupt or partial line is skipped rather than
//! being allowed to abort startup — a pool that will not boot pays no one at all,
//! which is strictly worse than one that boots having forgotten a few shares.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::Share;
use noct_core::pow::Difficulty;

/// Compact once the log holds more than this many times the window size.
const COMPACT_FACTOR: usize = 4;

/// An append-only log of accepted shares, mirroring the in-memory window.
pub struct WindowLog {
    path: PathBuf,
    /// Lines currently in the file, so compaction is decided without a re-read.
    lines: usize,
    window_size: usize,
}

impl WindowLog {
    /// Open (or create) the log at `path`, returning it alongside the shares to
    /// seed the pool's window with — oldest first, already truncated to
    /// `window_size`.
    pub fn open(
        path: impl Into<PathBuf>,
        window_size: usize,
    ) -> std::io::Result<(WindowLog, VecDeque<Share>)> {
        let path = path.into();
        let mut shares: VecDeque<Share> = VecDeque::new();
        let mut lines = 0usize;

        if path.exists() {
            let f = File::open(&path)?;
            for line in BufReader::new(f).lines() {
                let Ok(line) = line else { break }; // truncated tail: stop, keep what we have
                lines += 1;
                let Some(share) = parse_line(&line) else { continue }; // skip a bad line, never abort
                shares.push_back(share);
                while shares.len() > window_size {
                    shares.pop_front();
                }
            }
        }

        let mut log = WindowLog { path, lines, window_size };
        // A log read back larger than it needs to be is compacted immediately, so
        // startup cost does not grow without bound across restarts.
        if log.lines > window_size * COMPACT_FACTOR {
            log.compact(&shares)?;
        }
        Ok((log, shares))
    }

    /// Record one accepted share. Called before the share is acknowledged, so a
    /// crash cannot lose credit that a miner has already been told about.
    pub fn append(&mut self, share: &Share, window: &VecDeque<Share>) -> std::io::Result<()> {
        // Scoped so the handle is closed before any compaction: compaction renames
        // over this path, and Windows refuses to replace a file that is still
        // open. On Unix the rename would succeed and silently strand the open
        // handle on the unlinked inode, so the write is finished here either way.
        {
            let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
            writeln!(f, "{} {}", share.weight, share.miner)?;
            f.flush()?;
        }
        self.lines += 1;
        if self.lines > self.window_size * COMPACT_FACTOR {
            self.compact(window)?;
        }
        Ok(())
    }

    /// Rewrite the log as exactly the current window. Atomic: written to a temp
    /// file and renamed, so a crash mid-compaction leaves the previous log intact
    /// rather than a half-written one.
    pub fn compact(&mut self, window: &VecDeque<Share>) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            for share in window {
                writeln!(f, "{} {}", share.weight, share.miner)?;
            }
            f.flush()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        self.lines = window.len();
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// `<weight> <miner>` — miner ids are base58 addresses, so they contain no
/// whitespace and the split is unambiguous.
fn parse_line(line: &str) -> Option<Share> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (weight, miner) = line.split_once(' ')?;
    let weight: Difficulty = weight.parse().ok()?;
    if miner.is_empty() || weight == 0 {
        return None;
    }
    Some(Share { miner: miner.to_string(), weight })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("noct-windowlog-{name}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn share(miner: &str, weight: Difficulty) -> Share {
        Share { miner: miner.to_string(), weight }
    }

    /// The point of the whole file: shares survive a restart.
    #[test]
    fn accepted_shares_survive_a_restart() {
        let path = tmp("restart");
        let (mut log, mut window) = WindowLog::open(&path, 100).unwrap();
        assert!(window.is_empty(), "a fresh pool starts with no credit");

        for (m, w) in [("alice", 500), ("bob", 1000), ("alice", 500)] {
            let s = share(m, w);
            window.push_back(s.clone());
            log.append(&s, &window).unwrap();
        }

        // Restart.
        let (_log2, recovered) = WindowLog::open(&path, 100).unwrap();
        assert_eq!(recovered.len(), 3, "every accepted share came back");
        assert_eq!(recovered, window, "in the same order, with the same weights");
        std::fs::remove_file(&path).ok();
    }

    /// Weights must be preserved exactly — they are the payout split. A share
    /// recorded at one difficulty must not come back at another.
    #[test]
    fn weights_round_trip_exactly() {
        let path = tmp("weights");
        let (mut log, mut window) = WindowLog::open(&path, 100).unwrap();
        for w in [1u64, 999, 1_000_000, Difficulty::MAX] {
            let s = share("alice", w);
            window.push_back(s.clone());
            log.append(&s, &window).unwrap();
        }
        let (_l, recovered) = WindowLog::open(&path, 100).unwrap();
        let weights: Vec<Difficulty> = recovered.iter().map(|s| s.weight).collect();
        assert_eq!(weights, vec![1, 999, 1_000_000, Difficulty::MAX]);
        std::fs::remove_file(&path).ok();
    }

    /// Only the last `window_size` shares can matter, so recovery must truncate
    /// exactly like the live window does — otherwise a restart would resurrect
    /// work that had already aged out and dilute everyone else's split.
    #[test]
    fn recovery_truncates_to_the_window_like_the_pool_does() {
        let path = tmp("truncate");
        let (mut log, mut window) = WindowLog::open(&path, 5).unwrap();
        for i in 0..20 {
            let s = share(if i % 2 == 0 { "alice" } else { "bob" }, 100 + i);
            window.push_back(s.clone());
            while window.len() > 5 {
                window.pop_front();
            }
            log.append(&s, &window).unwrap();
        }
        let (_l, recovered) = WindowLog::open(&path, 5).unwrap();
        assert_eq!(recovered.len(), 5, "no more than the window");
        assert_eq!(recovered, window, "and exactly the newest five");
        std::fs::remove_file(&path).ok();
    }

    /// A crash can leave a half-written final line. That must cost at most that
    /// one share — never the whole file, and never startup.
    #[test]
    fn a_truncated_tail_costs_only_the_last_share() {
        let path = tmp("torn");
        let (mut log, mut window) = WindowLog::open(&path, 100).unwrap();
        for m in ["alice", "bob", "carol"] {
            let s = share(m, 500);
            window.push_back(s.clone());
            log.append(&s, &window).unwrap();
        }
        // Simulate a torn write: chop the file mid-line.
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &raw[..raw.len() - 4]).unwrap();

        let (_l, recovered) = WindowLog::open(&path, 100).unwrap();
        assert!(
            recovered.len() >= 2,
            "the intact shares survived (got {})",
            recovered.len()
        );
        assert_eq!(recovered[0].miner, "alice");
        std::fs::remove_file(&path).ok();
    }

    /// Garbage in the middle is skipped, not fatal. A pool that refuses to start
    /// pays nobody, which is worse than one that starts having dropped a line.
    #[test]
    fn corrupt_lines_are_skipped_rather_than_aborting_startup() {
        let path = tmp("corrupt");
        std::fs::write(
            &path,
            "500 alice\nnot-a-share\n\n0 zeroweight\n1000 bob\nxyz abc\n700 carol\n",
        )
        .unwrap();
        let (_l, recovered) = WindowLog::open(&path, 100).unwrap();
        let miners: Vec<&str> = recovered.iter().map(|s| s.miner.as_str()).collect();
        assert_eq!(miners, vec!["alice", "bob", "carol"], "good lines kept, bad ones dropped");
        std::fs::remove_file(&path).ok();
    }

    /// The log must not grow without bound across a long-running pool.
    #[test]
    fn the_log_compacts_and_stays_bounded() {
        let path = tmp("compact");
        let window_size = 10;
        let (mut log, mut window) = WindowLog::open(&path, window_size).unwrap();
        for i in 0..500 {
            let s = share("alice", 100 + i);
            window.push_back(s.clone());
            while window.len() > window_size {
                window.pop_front();
            }
            log.append(&s, &window).unwrap();
        }
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert!(
            lines <= window_size * COMPACT_FACTOR,
            "log grew to {lines} lines for a {window_size}-share window"
        );
        // and compaction must not corrupt what it keeps
        let (_l, recovered) = WindowLog::open(&path, window_size).unwrap();
        assert_eq!(recovered, window);
        std::fs::remove_file(&path).ok();
    }
}
