//! BIP39 mnemonic seed phrases for wallet backup.
//!
//! A NOCT wallet is a single 32-byte spend secret. Written as a standard BIP39
//! English **24-word phrase** (256-bit entropy + checksum), it is far safer to
//! record and restore than a bare 64-char hex string: the checksum catches a
//! mistyped or swapped word, and words are much harder to transcribe wrong.
//!
//! The phrase encodes the spend-secret bytes *directly* (not via BIP39's PBKDF2
//! seed stretching), so restoring yields exactly the same key — no passphrase, no
//! derivation path. Only spend secrets that are canonical ed25519 scalars are
//! accepted on restore, which every NOCT-generated wallet is.

use bip39::Mnemonic;
use curve25519_dalek::scalar::Scalar;
use noct_core::keys::PrivateKey;

/// Why a phrase could not be turned back into a spend key.
#[derive(Debug, PartialEq, Eq)]
pub enum MnemonicError {
    /// Failed BIP39 parsing or checksum (a mistyped/misordered word).
    Invalid,
    /// Not a 24-word phrase (does not encode 32 bytes).
    WrongLength,
    /// The bytes are not a canonical ed25519 scalar — not a NOCT spend key.
    NotCanonical,
}

/// The 24-word BIP39 phrase for a 32-byte spend secret.
pub fn to_phrase(spend_secret: &[u8; 32]) -> String {
    // `from_entropy` only errors on a bad length; 32 bytes is always valid.
    Mnemonic::from_entropy(spend_secret)
        .expect("32 bytes is valid BIP39 entropy")
        .to_string()
}

/// The phrase for a wallet's spend key.
pub fn phrase_for(secret: &PrivateKey) -> String {
    to_phrase(&secret.to_bytes())
}

/// Recover the 32-byte spend secret from a BIP39 phrase, validating the checksum
/// and that the result is a canonical NOCT spend key.
pub fn from_phrase(phrase: &str) -> Result<[u8; 32], MnemonicError> {
    let mnemonic = Mnemonic::parse(phrase.trim()).map_err(|_| MnemonicError::Invalid)?;
    let (entropy, len) = mnemonic.to_entropy_array();
    if len != 32 {
        return Err(MnemonicError::WrongLength);
    }
    let bytes: [u8; 32] = entropy[..32].try_into().expect("checked len == 32");
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).is_none() {
        return Err(MnemonicError::NotCanonical);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noct_core::keys::Account;
    use rand_core::OsRng;

    #[test]
    fn phrase_round_trips_a_generated_wallet_key() {
        for _ in 0..20 {
            let account = Account::random(&mut OsRng);
            let secret = account.spend_secret.to_bytes();
            let phrase = to_phrase(&secret);
            // A 24-word BIP39 phrase.
            assert_eq!(phrase.split_whitespace().count(), 24);
            // Restores to exactly the same key.
            assert_eq!(from_phrase(&phrase).unwrap(), secret);
        }
    }

    #[test]
    fn a_mistyped_word_is_rejected_by_the_checksum() {
        let secret = Account::random(&mut OsRng).spend_secret.to_bytes();
        let phrase = to_phrase(&secret);
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        // Swap the first word for a different valid BIP39 word → checksum fails
        // (extremely likely; 255/256 of checksums differ).
        words[0] = if words[0] == "zoo" { "abandon" } else { "zoo" };
        let tampered = words.join(" ");
        assert_eq!(from_phrase(&tampered), Err(MnemonicError::Invalid));
    }

    #[test]
    fn garbage_and_wrong_length_are_rejected() {
        assert_eq!(from_phrase("not a real phrase"), Err(MnemonicError::Invalid));
        // A valid 12-word phrase encodes 16 bytes, not a 32-byte spend key.
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(from_phrase(twelve), Err(MnemonicError::WrongLength));
    }
}
