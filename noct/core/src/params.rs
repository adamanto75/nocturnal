//! Per-network chain parameters.
//!
//! Everything that makes one Noct network a *different chain* from another lives
//! here: the peer-to-peer magic, the default ports, and the genesis block's
//! contents. Two networks must be unable to touch each other, and the separation
//! is deliberately belt-and-braces:
//!
//!  * the **p2p magic** differs, so a handshake from the wrong network is
//!    rejected before anything else is read;
//!  * the **genesis id** differs (different timestamp *and* different premine),
//!    so even a peer that somehow passed the magic check is rejected as a foreign
//!    chain;
//!  * the **address tag** differs ([`Network::spend_tag`]), so a testnet address
//!    cannot be pasted into a mainnet wallet, or the reverse;
//!  * the **default ports** differ, so both can run on one machine.
//!
//! The testnet deliberately uses the *same code path* as mainnet — same genesis
//! construction, same premine mechanism, same emission — and varies only these
//! constants. A testnet that exercised different code would not be testing what
//! actually launches.

use crate::address::Network;

/// The constants that define a network's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub network: Network,
    /// Sent in the p2p handshake; a mismatch drops the connection immediately.
    pub p2p_magic: u32,
    pub default_p2p_port: u16,
    pub default_rpc_port: u16,
    /// Baked into the genesis header, and therefore into the chain's identity.
    pub genesis_timestamp: u64,
    pub premine_amount: u64,
    pub premine_spend_public: [u8; 32],
    pub premine_view_public: [u8; 32],
    /// The published one-time secret `r` for the genesis stealth output. Public
    /// on purpose: it only links the (already public) premine to its address —
    /// spending still needs the private spend key.
    pub genesis_tx_secret: [u8; 32],
}

/// Mainnet — the chain that carries real value. These values are fixed forever;
/// changing any of them creates a different chain.
pub const MAINNET: ChainParams = ChainParams {
    network: Network::Mainnet,
    // "NOCT" in ASCII.
    p2p_magic: 0x4E4F4354,
    default_p2p_port: 9333,
    default_rpc_port: 9334,
    genesis_timestamp: crate::block::GENESIS_TIMESTAMP,
    premine_amount: crate::block::PREMINE_AMOUNT,
    premine_spend_public: crate::block::PREMINE_SPEND_PUBLIC,
    premine_view_public: crate::block::PREMINE_VIEW_PUBLIC,
    genesis_tx_secret: crate::block::GENESIS_TX_SECRET,
};

/// Testnet — coins here are **worthless by design**.
///
/// The premine is addressed to a wallet whose seed phrase is published in
/// `docs/TESTNET.md`, so anyone can spend it. That is intentional: it makes the
/// premine independently verifiable and gives the network a faucet, and it
/// guarantees nobody mistakes testnet coins for value.
pub const TESTNET: ChainParams = ChainParams {
    network: Network::Testnet,
    // "TNCT" in ASCII — distinct from mainnet in every byte position that a
    // truncated or byte-swapped read would confuse.
    p2p_magic: 0x544E4354,
    default_p2p_port: 19333,
    default_rpc_port: 19334,
    // Deliberately different from mainnet's, so the genesis ids cannot collide
    // even if every other field somehow matched.
    genesis_timestamp: 1_760_000_000,
    // A tenth of mainnet's premine: enough to fund testing, and visibly not a
    // mirror of the real allocation.
    premine_amount: 50_000 * crate::emission::ATOMIC_UNITS,
    premine_spend_public: TESTNET_PREMINE_SPEND_PUBLIC,
    premine_view_public: TESTNET_PREMINE_VIEW_PUBLIC,
    genesis_tx_secret: TESTNET_GENESIS_TX_SECRET,
};

// Derived from the published testnet seed phrase; see `docs/TESTNET.md` and the
// `print_testnet_genesis_params` generator at the bottom of this file.
pub const TESTNET_PREMINE_SPEND_PUBLIC: [u8; 32] = [
    0x47, 0x43, 0x51, 0xb2, 0x40, 0x22, 0x63, 0x81, 0x7e, 0x6e, 0xa8, 0xd0, 0x18, 0xcf, 0x21, 0x7e,
    0x99, 0x6a, 0x2c, 0xfa, 0x8a, 0xc1, 0x3b, 0xa3, 0xaf, 0x0d, 0xda, 0x40, 0xe3, 0x60, 0xae, 0x83,
];
pub const TESTNET_PREMINE_VIEW_PUBLIC: [u8; 32] = [
    0x8d, 0xc9, 0x37, 0x8c, 0x6f, 0xb1, 0x5e, 0xe5, 0xf5, 0xea, 0x40, 0x32, 0x9e, 0x8f, 0xb9, 0x95,
    0x89, 0x3b, 0x38, 0x8d, 0xfe, 0xc3, 0x2b, 0xaf, 0x37, 0x9d, 0xa6, 0x77, 0x2b, 0x04, 0x8a, 0xeb,
];
pub const TESTNET_GENESIS_TX_SECRET: [u8; 32] = [
    0xd1, 0xa1, 0x49, 0x36, 0xa1, 0x7e, 0x6f, 0x5b, 0x02, 0x7f, 0x56, 0x0a, 0xef, 0x72, 0xc9, 0x7b,
    0x73, 0x86, 0x60, 0xa9, 0x85, 0x0e, 0xdb, 0x21, 0x0a, 0xcc, 0xed, 0x48, 0x7c, 0x97, 0xad, 0x0a,
];

impl Network {
    /// The chain parameters for this network.
    pub const fn params(self) -> &'static ChainParams {
        match self {
            Network::Mainnet => &MAINNET,
            Network::Testnet => &TESTNET,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_networks_cannot_be_confused_for_each_other() {
        assert_ne!(MAINNET.p2p_magic, TESTNET.p2p_magic);
        assert_ne!(MAINNET.genesis_timestamp, TESTNET.genesis_timestamp);
        assert_ne!(MAINNET.default_p2p_port, TESTNET.default_p2p_port);
        assert_ne!(MAINNET.default_rpc_port, TESTNET.default_rpc_port);
        // Ports must not collide across networks either — both run on one host.
        for a in [MAINNET.default_p2p_port, MAINNET.default_rpc_port] {
            for b in [TESTNET.default_p2p_port, TESTNET.default_rpc_port] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(MAINNET.premine_spend_public, TESTNET.premine_spend_public);
    }

    #[test]
    fn params_round_trip_through_the_network_enum() {
        assert_eq!(Network::Mainnet.params(), &MAINNET);
        assert_eq!(Network::Testnet.params(), &TESTNET);
        assert_eq!(MAINNET.network, Network::Mainnet);
        assert_eq!(TESTNET.network, Network::Testnet);
    }

    /// Regenerate the testnet genesis constants from the published seed phrase.
    ///
    ///   cargo test -p noct-core print_testnet_genesis_params -- --ignored --nocapture
    ///
    /// Kept as a test so the constants above are reproducible rather than
    /// magic: anyone can re-run this and confirm they match.
    #[test]
    #[ignore]
    fn print_testnet_genesis_params() {
        use crate::address::Address;

        // The published testnet founder address (see docs/TESTNET.md).
        let addr = std::env::var("NOCT_TESTNET_ADDRESS")
            .expect("set NOCT_TESTNET_ADDRESS to the testnet founder address");
        let decoded = Address::decode(addr.trim()).expect("a valid address");

        let hex = |b: &[u8; 32]| {
            b.iter()
                .map(|x| format!("0x{x:02x}"))
                .collect::<Vec<_>>()
                .chunks(16)
                .map(|c| c.join(", "))
                .collect::<Vec<_>>()
                .join(",\n    ")
        };
        println!("TESTNET_PREMINE_SPEND_PUBLIC: [u8; 32] = [\n    {}\n];", hex(&decoded.spend_public.to_bytes()));
        println!("TESTNET_PREMINE_VIEW_PUBLIC: [u8; 32] = [\n    {}\n];", hex(&decoded.view_public.to_bytes()));

        // A canonical scalar for the genesis one-time secret, derived
        // deterministically from the address so this is reproducible. Reducing
        // through `hash_to_scalar` guarantees canonicality, which
        // `PrivateKey::from_canonical_bytes` will later require.
        let r = crate::keys::PrivateKey(crate::hash::hash_to_scalar(
            format!("noct_testnet_genesis_r:{}", addr.trim()).as_bytes(),
        ));
        println!("TESTNET_GENESIS_TX_SECRET: [u8; 32] = [\n    {}\n];", hex(&r.to_bytes()));
    }
}

#[cfg(test)]
mod separation_tests {
    use super::*;
    use crate::block::Block;
    use crate::chain::Blockchain;
    use crate::pow::KeccakPow;

    /// The property the whole module exists for: the two networks are different
    /// chains, and nothing about them can be confused.
    #[test]
    fn a_testnet_chain_is_not_a_mainnet_chain() {
        let main = Blockchain::for_network(Network::Mainnet, KeccakPow);
        let test = Blockchain::for_network(Network::Testnet, KeccakPow);

        // Different genesis => different chain identity. This is what a peer
        // checks in the handshake, so it is the check that actually separates
        // two live networks.
        assert_ne!(main.genesis_id(), test.genesis_id());

        // And the magic differs, so a foreign peer is dropped before its chain
        // is even considered.
        assert_ne!(main.params().p2p_magic, test.params().p2p_magic);
    }

    #[test]
    fn the_default_chain_is_still_mainnet() {
        // `new` must keep meaning mainnet: every existing caller relies on it,
        // and a silent switch would be catastrophic.
        let default = Blockchain::new(KeccakPow);
        let main = Blockchain::for_network(Network::Mainnet, KeccakPow);
        assert_eq!(default.genesis_id(), main.genesis_id());
        assert_eq!(default.genesis_id(), Block::genesis().id());
        assert_eq!(default.network(), Network::Mainnet);
    }

    #[test]
    fn each_networks_premine_pays_its_own_address_tag() {
        // A premine paid to the wrong tag would be unspendable by that network's
        // wallets — and on testnet would look like a mainnet payout.
        for net in [Network::Mainnet, Network::Testnet] {
            let p = net.params();
            let spend = crate::keys::PublicKey::from_bytes(p.premine_spend_public).unwrap();
            let view = crate::keys::PublicKey::from_bytes(p.premine_view_public).unwrap();
            let addr = crate::address::Address::new(net, spend, view);
            let decoded = crate::address::Address::decode(&addr.encode()).unwrap();
            assert_eq!(decoded.network, net);
        }
    }

    #[test]
    fn the_testnet_premine_is_smaller_and_separately_owned() {
        // Not a mirror of the real allocation, and not spendable by the founder
        // key: nobody should be able to confuse the two supplies.
        assert!(TESTNET.premine_amount < MAINNET.premine_amount);
        assert_ne!(TESTNET.premine_spend_public, MAINNET.premine_spend_public);
        assert_ne!(TESTNET.genesis_tx_secret, MAINNET.genesis_tx_secret);
    }
}

/// The mainnet premine address, published so that the allocation is legible
/// rather than merely derivable.
///
/// This is a **public** value in every sense: the founder's public spend and
/// view keys are already baked into [`crate::block`], and the genesis one-time
/// secret is published beside them, so this address has always been derivable
/// from the source. Writing it down changes nothing about what is knowable — it
/// removes the step of deriving it, which is the difference between a fact being
/// technically available and actually checkable.
///
/// **Be precise about what publishing an address does and does not give you on
/// a chain like this one.** Because the genesis transaction secret `r` is
/// published, anyone can confirm that the genesis output really is addressed
/// here, and that it holds exactly [`crate::block::PREMINE_AMOUNT`]. Nobody can
/// tell when it is *spent*: the spend is a ring signature, and the key image
/// that would reveal it is derived from the output's private key. Watching this
/// address does not watch the money.
///
/// The whitepaper lists four things that would turn "the premine is for the
/// project" from a claim into something checkable. This is the weakest of them,
/// and none of the other three — vesting, multisig, published accounts — exists.
#[cfg(test)]
mod premine_address_tests {
    use crate::address::{Address, Network};
    use crate::block::{PREMINE_SPEND_PUBLIC, PREMINE_VIEW_PUBLIC};
    use crate::keys::PublicKey;

    /// The address published in the README, the whitepaper and the website.
    pub const PUBLISHED_MAINNET_PREMINE_ADDRESS: &str =
        "C4do37CzzKCV3XJHDinLAoL7MaEtRU5oHgGTWLVb8JBY5zEDayjqYqHGoyzGMF3VakXa2QjUgN9UJH7jpDQpMUVuRD1jNA";

    fn derived() -> String {
        let spend = PublicKey::from_bytes(PREMINE_SPEND_PUBLIC).expect("valid point");
        let view = PublicKey::from_bytes(PREMINE_VIEW_PUBLIC).expect("valid point");
        Address::new(Network::Mainnet, spend, view).encode()
    }

    /// A published address that does not match the code is worse than none: it
    /// invites people to watch the wrong thing while believing they are
    /// checking something. This pins the two together, so changing the founder
    /// keys without updating every published copy breaks the build.
    #[test]
    fn the_published_address_matches_the_baked_keys() {
        assert_eq!(
            derived(),
            PUBLISHED_MAINNET_PREMINE_ADDRESS,
            "the premine address published to the world no longer matches the genesis constants"
        );
    }

    /// It must be a mainnet address. A testnet tag here would point readers at
    /// a worthless chain while claiming to disclose the real allocation.
    #[test]
    fn it_is_a_mainnet_address() {
        let decoded = Address::decode(PUBLISHED_MAINNET_PREMINE_ADDRESS).expect("decodes");
        assert_eq!(decoded.network, Network::Mainnet);
        assert!(!decoded.is_subaddress, "the premine is paid to the main address");
    }

    /// The premine output's key image, as published in the whitepaper.
    ///
    /// It cannot be re-derived here — that needs the founder's private key,
    /// which is deliberately not in this repository and never will be. So this
    /// pins what it *can*: that the published value is a structurally valid key
    /// image rather than a typo or a truncation. A malformed commitment would be
    /// worse than none, because it can never appear on-chain and so can never be
    /// falsified — it would look like a promise while being unfalsifiable.
    pub const PUBLISHED_PREMINE_KEY_IMAGE: &str =
        "06f1c57958aea772c2a687cd456121fea003af3b84238767d2429a5d2795db16";

    #[test]
    fn the_published_key_image_is_a_well_formed_one() {
        let raw = hex::decode(PUBLISHED_PREMINE_KEY_IMAGE).expect("valid hex");
        let bytes: [u8; 32] = raw.as_slice().try_into().expect("32 bytes");
        assert!(
            crate::ring::KeyImage::from_bytes(bytes).is_some(),
            "the published key image must decode as a canonical, torsion-free point —              a malformed one is a promise that can never be checked"
        );
    }

    /// And it must not be confusable with the address published beside it.
    #[test]
    fn the_key_image_is_not_the_address() {
        assert_ne!(PUBLISHED_PREMINE_KEY_IMAGE, PUBLISHED_MAINNET_PREMINE_ADDRESS);
        assert_eq!(PUBLISHED_PREMINE_KEY_IMAGE.len(), 64, "32 bytes as hex");
    }

    /// And it must be the address the genesis block actually pays.
    #[test]
    fn the_genesis_block_pays_this_address() {
        use crate::block::{Block, PREMINE_AMOUNT};
        let g = Block::genesis();
        assert_eq!(g.coinbase.outputs.len(), 1);
        assert_eq!(g.coinbase.outputs[0].amount, PREMINE_AMOUNT);
        let spend = PublicKey::from_bytes(PREMINE_SPEND_PUBLIC).expect("valid point");
        let view = PublicKey::from_bytes(PREMINE_VIEW_PUBLIC).expect("valid point");
        let addr = Address::new(Network::Mainnet, spend, view);
        assert_eq!(
            g.coinbase.outputs[0].one_time_key,
            crate::stealth::derive_output(
                &crate::keys::PrivateKey::from_canonical_bytes(crate::params::MAINNET.genesis_tx_secret)
                    .expect("canonical"),
                &addr,
                0
            ),
            "the genesis output must be payable to the published address"
        );
    }
}
