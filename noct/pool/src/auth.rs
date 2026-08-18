//! Optional per-miner credentials for the pool.
//!
//! ## What this is for, and what it is not for
//!
//! A public pool identifies a miner by the payout address it sends with its
//! work. That is the right answer for deciding *who to pay* — and every real
//! Monero-family pool works this way — but it is not authentication:
//!
//! * anyone who can reach the port can attach, so the only thing standing
//!   between the pool and an anonymous stranger is the rate limiter;
//! * one miner can claim another's address. That is not theft (submitting valid
//!   work under someone else's address *gives* them the work) but it does let an
//!   attacker interfere with a victim's **vardiff**, since a target is retuned
//!   from the measured rate of whoever is submitting under that identity;
//! * an operator cannot revoke one miner. The only lever is banning an IP, which
//!   also removes everyone else behind the same router.
//!
//! Credentials are therefore **opt-in**, for a private, solo, or invite-only
//! pool. A public pool leaves them off and keeps working exactly as before. What
//! they add when enabled is the property that matters:
//!
//! > **the credential decides the payout address, not the request.**
//!
//! A miner cannot mine to an address the operator did not register, and cannot
//! be confused with another miner, because there is nothing self-declared left
//! to confuse.
//!
//! ## Why tokens and not passwords
//!
//! A password would need a slow KDF (argon2, bcrypt) to be stored safely,
//! because people choose guessable passwords. A 256-bit random token has no such
//! problem: it cannot be guessed and needs no stretching, so it is stored and
//! compared directly. This is the same choice already made for the node's RPC
//! token, and reusing it means a miner's existing `--token-file` flag works
//! against a pool with no new plumbing.
//!
//! Tokens are secrets in transit, so an authenticated pool should also be
//! serving TLS — see `noct-tls`. The daemon says so loudly at startup if it is
//! not.

use std::collections::HashSet;
use std::path::Path;

use noct_core::address::Address;

/// Longest credentials file we will read. A credential list is small; anything
/// larger is a wrong path or a mistake, and reading it into memory unbounded
/// would be a self-inflicted denial of service.
const MAX_FILE: u64 = 4 * 1024 * 1024;

/// Shortest token accepted. Anything a human would type is too short to resist
/// guessing, and accepting it would make the whole mechanism decorative.
const MIN_TOKEN_LEN: usize = 32;

/// A registered miner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Where this miner is paid. **From the file, never from the request.**
    pub payout: String,
    /// Operator's name for this miner, for logs and `/stats`.
    pub label: String,
}

/// The registered miners, if the operator configured any.
#[derive(Debug, Default)]
pub struct MinerAuth {
    entries: Vec<(String, Registration)>,
}

impl MinerAuth {
    /// Read a credentials file.
    ///
    /// One miner per line: `<token> <payout-address> [label]`. Blank lines and
    /// `#` comments are ignored.
    ///
    /// Every problem here is fatal rather than skipped. A silently dropped line
    /// means a miner that mines and is never paid, and it would be discovered
    /// only by someone eventually noticing they earned nothing.
    pub fn load(path: &Path) -> Result<MinerAuth, String> {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?
            .len();
        if size > MAX_FILE {
            return Err(format!("{} is {size} bytes — that is not a credentials file", path.display()));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

        let mut entries: Vec<(String, Registration)> = Vec::new();
        let mut seen_tokens: HashSet<String> = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |what: &str| format!("{}:{}: {what}", path.display(), n + 1);

            let mut parts = line.split_whitespace();
            let token = parts.next().ok_or_else(|| at("expected <token> <address> [label]"))?;
            let payout = parts.next().ok_or_else(|| at("no payout address after the token"))?;
            let label = parts.collect::<Vec<_>>().join(" ");

            if token.len() < MIN_TOKEN_LEN {
                return Err(at(&format!(
                    "token is {} characters; at least {MIN_TOKEN_LEN} are needed. \
                     Generate one with `noct-poold --add-miner <ADDRESS> --miner-auth <FILE>`",
                    token.len()
                )));
            }
            // An address that does not decode would take work and never be
            // payable — the same defect as F27, and here it is catchable at
            // startup instead of at settlement.
            if Address::decode(payout).is_err() {
                return Err(at("payout address does not decode"));
            }
            // Two miners sharing a token cannot be told apart, and revoking one
            // would revoke the other. Almost always a copy-paste slip.
            if !seen_tokens.insert(token.to_string()) {
                return Err(at("this token is already used by another miner"));
            }

            let label = if label.is_empty() {
                format!("miner-{}", entries.len() + 1)
            } else {
                label
            };
            entries.push((token.to_string(), Registration { payout: payout.to_string(), label }));
        }

        if entries.is_empty() {
            // Starting with an empty list would authenticate nobody and refuse
            // every miner — a pool that silently does nothing.
            return Err(format!("{} registers no miners", path.display()));
        }
        Ok(MinerAuth { entries })
    }

    /// The miner this token belongs to, if any.
    ///
    /// Every entry is compared, in constant time, even after a match is found.
    /// Neither the time taken nor the number of comparisons reveals which
    /// tokens exist or how close a guess was. A hash-map lookup would be the
    /// obvious implementation and would leak both. The cost is trivial — a few
    /// dozen fixed-size comparisons against a list that has one entry per miner.
    pub fn lookup(&self, presented: &str) -> Option<&Registration> {
        let mut found: Option<&Registration> = None;
        for (token, reg) in &self.entries {
            if constant_time_eq(token.as_bytes(), presented.as_bytes()) {
                found = Some(reg);
            }
        }
        found
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compare two byte strings without an early exit.
///
/// Lengths are compared too, and unequal lengths still walk the longer input, so
/// a token's length is not recoverable from the response time either.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u32;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0xff);
        diff |= (x ^ y) as u32;
    }
    diff == 0
}

/// A fresh credential for a new miner: 32 random bytes, hex-encoded.
pub fn new_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Normalise a worker name supplied by a miner.
///
/// Worker names exist so one person's several rigs are metered separately —
/// under a single payout address they would otherwise share one vardiff
/// assignment, and a blended target suits neither a fast rig nor a slow one.
///
/// The name is attacker-controlled and ends up in `/stats` JSON and in logs, so
/// it is restricted to an unmistakably safe alphabet and a short length rather
/// than escaped and hoped for. Anything else is dropped, not rejected: a bad
/// worker name should cost a miner its per-rig statistics, never its earnings.
pub fn clean_worker(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(24)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// The identity a miner's *session* is metered under: its payout address, plus
/// its worker name when it gave one.
///
/// Deliberately distinct from the payout identity. Money is accounted per
/// address and nothing here touches that; this only decides whose share rate is
/// measured together for vardiff, and what `/stats` reports per rig.
pub fn session_id(payout: &str, worker: Option<&str>) -> String {
    match worker {
        Some(w) => format!("{payout}.{w}"),
        None => payout.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const ALICE: &str = "XpFhRq1RhDJBzFz2LTvKXJUPJaMruVS7iLHWPKPiJNwYJE2387xqiEH1gD9F3U74Poxc7tWNifGhNmTZxDKS5RJh6hb17i";
    const BOB: &str = "CTWi92gyQjPBRFzuyck69w7Zfvg7USJMLQTh1sipSHYD9dW3uxfWYdBzrVt3pQRUJYtRHScT9EAEA5BGWE7o7tHp7wAUCY";

    fn write_file(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("noct-auth-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("miners.txt");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn a_registered_token_names_its_miner() {
        let t1 = new_token();
        let t2 = new_token();
        let p = write_file(
            "ok",
            &format!("# my miners\n\n{t1} {ALICE} alice-rig\n{t2} {BOB}\n"),
        );
        let auth = MinerAuth::load(&p).unwrap();
        assert_eq!(auth.len(), 2);

        let a = auth.lookup(&t1).unwrap();
        assert_eq!(a.payout, ALICE);
        assert_eq!(a.label, "alice-rig");
        // A missing label gets a usable default rather than an empty string.
        assert_eq!(auth.lookup(&t2).unwrap().label, "miner-2");

        // Anything not registered is nobody — including near misses.
        assert!(auth.lookup("").is_none());
        assert!(auth.lookup(&new_token()).is_none());
        let mut nearly = t1.clone();
        nearly.pop();
        assert!(auth.lookup(&nearly).is_none(), "a truncated token must not match");
        assert!(auth.lookup(&format!("{t1}x")).is_none(), "an extended token must not match");
    }

    /// Every one of these is a real operator mistake that would otherwise cost a
    /// miner its earnings silently, so each must stop the pool at startup.
    #[test]
    fn a_malformed_credentials_file_is_refused_at_startup() {
        let t = new_token();

        // Too short to resist guessing.
        let p = write_file("short", &format!("hunter2 {ALICE}\n"));
        assert!(MinerAuth::load(&p).unwrap_err().contains("characters"));

        // An address that will not decode is unpayable — catch it now, not at
        // settlement time when the work is already done (cf. F27).
        let p = write_file("badaddr", &format!("{t} not-an-address\n"));
        assert!(MinerAuth::load(&p).unwrap_err().contains("does not decode"));

        // Two miners on one token cannot be told apart or revoked separately.
        let p = write_file("dup", &format!("{t} {ALICE}\n{t} {BOB}\n"));
        assert!(MinerAuth::load(&p).unwrap_err().contains("already used"));

        // No address at all.
        let p = write_file("noaddr", &format!("{t}\n"));
        assert!(MinerAuth::load(&p).is_err());

        // A file registering nobody would refuse every miner and look like a
        // network fault.
        let p = write_file("empty", "# nobody here\n\n");
        assert!(MinerAuth::load(&p).unwrap_err().contains("no miners"));

        // The error must say where, or a long file is unfixable.
        let p = write_file("line", &format!("{t} {ALICE}\nhunter2 {BOB}\n"));
        assert!(MinerAuth::load(&p).unwrap_err().contains(":2:"));
    }

    #[test]
    fn tokens_are_unguessable_and_distinct() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "32 bytes, hex");
        assert!(a.len() >= MIN_TOKEN_LEN);
    }

    #[test]
    fn constant_time_eq_still_compares_correctly() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    /// A worker name reaches `/stats` JSON and the logs, so the alphabet is
    /// restricted rather than escaped. Dropping the name must never drop the
    /// miner: earnings do not depend on it.
    #[test]
    fn worker_names_are_reduced_to_something_safe() {
        assert_eq!(clean_worker(Some("rig-1")).unwrap(), "rig-1");
        assert_eq!(clean_worker(Some("  Rig_2  ")).unwrap(), "Rig_2");
        // Quotes, backslashes and control characters cannot survive into JSON.
        assert_eq!(clean_worker(Some("a\"b\\c")).unwrap(), "abc");
        assert_eq!(clean_worker(Some("x\ny")).unwrap(), "xy");
        // Bounded, so a miner cannot bloat every stats response.
        assert_eq!(clean_worker(Some(&"w".repeat(500))).unwrap().len(), 24);
        // Nothing usable left, and nothing given, are the same thing.
        assert_eq!(clean_worker(Some("!!!")), None);
        assert_eq!(clean_worker(Some("   ")), None);
        assert_eq!(clean_worker(None), None);
    }

    /// The separation that keeps this safe: worker names change how a rate is
    /// *measured*, never who is *paid*.
    #[test]
    fn a_worker_name_refines_the_session_but_not_the_payee() {
        let one = session_id(ALICE, Some("rig-1"));
        let two = session_id(ALICE, Some("rig-2"));
        assert_ne!(one, two, "two rigs must be metered apart");
        assert!(one.starts_with(ALICE) && two.starts_with(ALICE));
        assert_eq!(session_id(ALICE, None), ALICE);
    }
}
