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

    /// Tag for a **shielded** (Orchard) address on this network.
    ///
    /// A separate tag, and a separate length, so a shielded address cannot be
    /// pasted where a ring address is expected or the other way round: either
    /// decoder refuses the other's string outright rather than reading part of
    /// it. Money sent to the wrong pool's parser would not be recoverable, so
    /// this is not a nicety.
    pub fn shielded_tag(self) -> u8 {
        match self {
            Network::Mainnet => 0x15,
            Network::Testnet => 0x37,
        }
    }

    /// Resolve a shielded tag byte to its network.
    fn from_shielded_tag(tag: u8) -> Option<Self> {
        match tag {
            0x15 => Some(Network::Mainnet),
            0x37 => Some(Network::Testnet),
            _ => None,
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

/// A **shielded** receiving address: an Orchard address, plus the network it
/// belongs to.
///
/// Encoded the same way as [`Address`] — `tag ‖ payload ‖ 4-byte checksum`, in
/// Base58 — because one convention is easier to get right than two, and because
/// the tag is what keeps the two kinds apart. The payload is Orchard's own 43
/// raw address bytes (11-byte diversifier ‖ 32-byte `pk_d`), so this format adds
/// nothing to the cryptography and takes nothing away: it is a wrapper that says
/// which network and carries a checksum.
///
/// It is 48 bytes raw against [`Address`]'s 69, so the two never even reach a
/// tag comparison when confused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedAddress {
    pub network: Network,
    inner: orchard::Address,
}

impl ShieldedAddress {
    /// Wrap an Orchard address for `network`.
    pub fn new(network: Network, inner: orchard::Address) -> Self {
        ShieldedAddress { network, inner }
    }

    /// The Orchard address itself, for handing to a bundle builder.
    pub fn inner(&self) -> orchard::Address {
        self.inner
    }

    /// The 48 raw bytes `tag ‖ orchard address ‖ checksum` before Base58.
    fn to_raw(&self) -> [u8; 48] {
        let mut raw = [0u8; 48];
        raw[0] = self.network.shielded_tag();
        raw[1..44].copy_from_slice(&self.inner.to_raw_address_bytes());
        let checksum = keccak256(&raw[..44]);
        raw[44..48].copy_from_slice(&checksum[..4]);
        raw
    }

    /// Encode to a Base58 address string.
    pub fn encode(&self) -> String {
        bs58::encode(self.to_raw()).into_string()
    }

    /// Decode and fully validate a shielded address string.
    ///
    /// `pk_d` is checked to be a valid Pallas point of the right order by
    /// Orchard's own decoder, which is why this returns [`AddressError::BadPoint`]
    /// rather than accepting 43 arbitrary bytes.
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let raw = bs58::decode(s).into_vec().map_err(|_| AddressError::Base58)?;
        if raw.len() != 48 {
            return Err(AddressError::Length);
        }
        let network = Network::from_shielded_tag(raw[0]).ok_or(AddressError::UnknownTag)?;

        let checksum = keccak256(&raw[..44]);
        if checksum[..4] != raw[44..48] {
            return Err(AddressError::BadChecksum);
        }

        let mut bytes = [0u8; 43];
        bytes.copy_from_slice(&raw[1..44]);
        let inner = orchard::Address::from_raw_address_bytes(&bytes)
            .into_option()
            .ok_or(AddressError::BadPoint)?;
        Ok(ShieldedAddress { network, inner })
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

    fn sample_shielded(network: Network) -> ShieldedAddress {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        let sk = SpendingKey::from_bytes([7u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        ShieldedAddress::new(network, fvk.address_at(0u32, Scope::External))
    }

    /// **Neither kind of address may be readable as the other.** A ring address
    /// pasted where a shielded one is expected, or the reverse, has to be refused
    /// outright: value sent to the wrong pool's parser would not be recoverable,
    /// and a partial read is the way that happens.
    #[test]
    fn a_shielded_address_and_a_ring_address_cannot_be_confused() {
        let ring = sample();
        let shielded = sample_shielded(Network::Mainnet);

        assert_eq!(Address::decode(&shielded.encode()), Err(AddressError::Length));
        assert_eq!(ShieldedAddress::decode(&ring.encode()), Err(AddressError::Length));

        // And the round trips are unaffected by each other's existence.
        assert_eq!(ShieldedAddress::decode(&shielded.encode()), Ok(shielded));
        assert_eq!(Address::decode(&ring.encode()), Ok(ring));
    }

    /// The networks are separate too, so a testnet address cannot be paid on
    /// mainnet — the mistake that costs real money.
    #[test]
    fn a_shielded_address_carries_its_network() {
        let main = sample_shielded(Network::Mainnet);
        let test = sample_shielded(Network::Testnet);
        assert_ne!(main.encode(), test.encode());
        assert_eq!(ShieldedAddress::decode(&main.encode()).unwrap().network, Network::Mainnet);
        assert_eq!(ShieldedAddress::decode(&test.encode()).unwrap().network, Network::Testnet);
        // Same recipient, different network: the Orchard address is identical and
        // only the wrapper differs, which is exactly what the tag is for.
        assert_eq!(main.inner(), test.inner());
    }

    /// A single flipped character must be refused, not silently paid to nobody.
    #[test]
    fn a_damaged_shielded_address_is_refused() {
        let addr = sample_shielded(Network::Mainnet).encode();
        let mut chars: Vec<char> = addr.chars().collect();
        // Base58 has no '1' ambiguity with 'l'; swap a digit for another valid one.
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let damaged: String = chars.into_iter().collect();
        assert!(ShieldedAddress::decode(&damaged).is_err());
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
