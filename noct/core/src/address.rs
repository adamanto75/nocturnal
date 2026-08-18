//! Public addresses.
//!
//! An address is the Base58 encoding of:
//!
//! ```text
//!   [ tag (1) ‖ spend_pub (32) ‖ view_pub (32) ‖ checksum (4) ]
//! ```
//!
//! where `checksum = keccak256(tag ‖ spend_pub ‖ view_pub)[..4]`.
//!
//! The `tag` byte encodes both the network and whether this is the wallet's
//! main address or a [subaddress](crate::subaddress): a subaddress carries the
//! subaddress spend/view keys `(D, C)` and a distinct tag, so the sender knows
//! to derive its outputs with `R = r·D`.
//!
//! Note: this uses plain `bs58` (Bitcoin alphabet, no block chunking), *not*
//! Monero's block-Base58. That is a deliberate, self-consistent choice for
//! Noct; interop with Monero tooling is a non-goal.

use crate::hash::keccak256;
use crate::keys::PublicKey;

/// Network/address-type tag byte. Distinguishes mainnet/testnet and future
/// address kinds (subaddresses, integrated addresses) in one leading byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Tag for a standard (main) address on this network.
    pub fn tag(self) -> u8 {
        match self {
            Network::Mainnet => 0x13, // arbitrary, stable placeholder
            Network::Testnet => 0x35,
        }
    }

    /// Tag for a subaddress on this network.
    pub fn subaddress_tag(self) -> u8 {
        match self {
            Network::Mainnet => 0x14,
            Network::Testnet => 0x36,
        }
    }

    /// Resolve a tag byte to its `(network, is_subaddress)`.
    fn from_tag(tag: u8) -> Option<(Self, bool)> {
        match tag {
            0x13 => Some((Network::Mainnet, false)),
            0x14 => Some((Network::Mainnet, true)),
            0x35 => Some((Network::Testnet, false)),
            0x36 => Some((Network::Testnet, true)),
            _ => None,
        }
    }
}

/// A decoded address: its network, the two public keys, and whether it is a
/// subaddress. For a subaddress the keys are `(D, C = a·D)`; sending to it uses
/// a per-output transaction key `R = r·D`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    pub network: Network,
    pub spend_public: PublicKey,
    pub view_public: PublicKey,
    pub is_subaddress: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    Base58,
    Length,
    UnknownTag,
    BadChecksum,
    BadPoint,
}

impl Address {
    /// A standard (main) address.
    pub fn new(network: Network, spend_public: PublicKey, view_public: PublicKey) -> Self {
        Address { network, spend_public, view_public, is_subaddress: false }
    }

    /// A subaddress, carrying its `(D, C = a·D)` keys.
    pub fn new_subaddress(network: Network, spend_public: PublicKey, view_public: PublicKey) -> Self {
        Address { network, spend_public, view_public, is_subaddress: true }
    }

    /// The tag byte for this address (network + main/subaddress).
    fn tag(&self) -> u8 {
        if self.is_subaddress {
            self.network.subaddress_tag()
        } else {
            self.network.tag()
        }
    }

    /// The 69 raw bytes `tag ‖ spend ‖ view ‖ checksum` before Base58.
    fn to_raw(&self) -> [u8; 69] {
        let mut raw = [0u8; 69];
        raw[0] = self.tag();
        raw[1..33].copy_from_slice(&self.spend_public.to_bytes());
        raw[33..65].copy_from_slice(&self.view_public.to_bytes());
        let checksum = keccak256(&raw[..65]);
        raw[65..69].copy_from_slice(&checksum[..4]);
        raw
    }

    /// Encode to a Base58 address string.
    pub fn encode(&self) -> String {
        bs58::encode(self.to_raw()).into_string()
    }

    /// Decode and fully validate an address string (checksum + curve points).
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let raw = bs58::decode(s).into_vec().map_err(|_| AddressError::Base58)?;
        if raw.len() != 69 {
            return Err(AddressError::Length);
        }
        let (network, is_subaddress) = Network::from_tag(raw[0]).ok_or(AddressError::UnknownTag)?;

        let checksum = keccak256(&raw[..65]);
        if checksum[..4] != raw[65..69] {
            return Err(AddressError::BadChecksum);
        }

        let mut spend = [0u8; 32];
        let mut view = [0u8; 32];
        spend.copy_from_slice(&raw[1..33]);
        view.copy_from_slice(&raw[33..65]);
        let spend_public = PublicKey::from_bytes(spend).ok_or(AddressError::BadPoint)?;
        let view_public = PublicKey::from_bytes(view).ok_or(AddressError::BadPoint)?;

        Ok(Address { network, spend_public, view_public, is_subaddress })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Account;
    use rand_core::OsRng;

    fn sample() -> Address {
        let acct = Account::random(&mut OsRng);
        Address::new(Network::Mainnet, acct.spend_public, acct.view_public)
    }

    #[test]
    fn roundtrip() {
        let addr = sample();
        let decoded = Address::decode(&addr.encode()).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn subaddress_roundtrips_and_flags() {
        use crate::subaddress::{self, SubaddressIndex};
        let acct = Account::random(&mut OsRng);
        let sub = SubaddressIndex::new(1, 7);
        let addr = Address::new_subaddress(
            Network::Mainnet,
            subaddress::spend_public(&acct, sub),
            subaddress::view_public(&acct, sub),
        );
        assert!(addr.is_subaddress);
        let decoded = Address::decode(&addr.encode()).unwrap();
        assert_eq!(addr, decoded);
        assert!(decoded.is_subaddress);
        // A subaddress string differs from the main address, and is not confused
        // for one.
        let main = Address::new(Network::Mainnet, acct.spend_public, acct.view_public);
        assert_ne!(addr.encode(), main.encode());
        assert!(!Address::decode(&main.encode()).unwrap().is_subaddress);
    }

    #[test]
    fn testnet_tag_differs() {
        let acct = Account::random(&mut OsRng);
        let m = Address::new(Network::Mainnet, acct.spend_public, acct.view_public);
        let t = Address::new(Network::Testnet, acct.spend_public, acct.view_public);
        assert_ne!(m.encode(), t.encode());
        assert_eq!(Address::decode(&t.encode()).unwrap().network, Network::Testnet);
    }

    #[test]
    fn corrupted_checksum_is_rejected() {
        let addr = sample();
        let mut s = addr.encode();
        // Flip the last character to a different Base58 digit.
        let last = s.pop().unwrap();
        let repl = if last == 'A' { 'B' } else { 'A' };
        s.push(repl);
        assert!(matches!(
            Address::decode(&s),
            Err(AddressError::BadChecksum) | Err(AddressError::BadPoint) | Err(AddressError::Base58)
        ));
    }
}
