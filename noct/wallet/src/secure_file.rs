//! Writing files that must stay private to their owner.
//!
//! `std::fs::write` creates a file with the process's default mode, which under
//! the usual umask is 0644: readable by every account on the machine. For a
//! wallet key that is the whole wallet. Everything the wallet writes that is
//! secret, or that reveals what the wallet owns, goes through here instead.
//!
//! On Windows a new file takes its ACL from the directory it is created in, and
//! a user's profile is already private to them, so there is nothing further to
//! set there.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Options for a brand-new file readable and writable by its owner only.
///
/// `create_new` matters as much as the mode: opening a file that already exists
/// keeps whatever permissions it already had, so a file that is merely
/// truncated and rewritten can stay world-readable.
fn private_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Create `path` holding `bytes`, owner-only, and flush it to disk.
///
/// Refuses if anything already exists at `path`. A key must never be
/// overwritten, and checking beforehand is not enough: the file could appear
/// between the check and the write.
pub fn create_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_options().open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Replace `path` with `bytes`, owner-only and atomically.
///
/// The bytes go to a sibling temporary file, which is flushed to disk and then
/// renamed over the target. A crash at any point leaves either the old contents
/// or the new, never a torn mix of the two.
pub fn replace_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = with_suffix(path, ".tmp");
    // A leftover from an interrupted write. Remove it rather than write through
    // it, since reopening it would keep whatever mode it was created with.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let written = (|| {
        let mut file = private_options().open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    sync_parent(path);
    Ok(())
}

/// True when `path` is readable or writable by accounts other than its owner.
#[cfg(unix)]
pub fn is_exposed(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o077 != 0).unwrap_or(false)
}

/// Always false off unix, where access is governed by ACLs this does not read.
#[cfg(not(unix))]
pub fn is_exposed(_path: &Path) -> bool {
    false
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Make the rename itself durable, not just the bytes. Best effort; directories
/// cannot be opened this way off unix.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("noct-secure-file-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Losing a key to an accidental overwrite is losing the wallet.
    #[test]
    fn creating_never_overwrites() {
        let dir = scratch("create");
        let path = dir.join("key");
        create_private(&path, b"first").unwrap();
        assert!(create_private(&path, b"second").is_err(), "must refuse an existing file");
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replacing_swaps_the_contents_and_leaves_nothing_behind() {
        let dir = scratch("replace");
        let path = dir.join("state");
        replace_private(&path, b"old").unwrap();
        replace_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert!(!with_suffix(&path, ".tmp").exists(), "the temporary file must not survive");

        // A stale temporary from a crash must not block, or leak into, the next write.
        std::fs::write(with_suffix(&path, ".tmp"), b"torn").unwrap();
        replace_private(&path, b"newer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"newer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The defect this module exists for: key files came out 0644.
    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let key = dir.join("key");
        let state = dir.join("state");
        create_private(&key, b"k").unwrap();
        replace_private(&state, b"s").unwrap();
        for p in [&key, &state] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", p.display());
            assert!(!is_exposed(p));
        }
        // And the check recognises the old behaviour for what it was.
        let loose = dir.join("loose");
        std::fs::write(&loose, b"x").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(is_exposed(&loose));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
