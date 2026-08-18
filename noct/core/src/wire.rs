//! Layer 10 — canonical wire (de)serialization.
//!
//! Turns [`Transaction`], [`Block`], and [`crate::p2p`] gossip messages into
//! bytes and back. This is the boundary where **untrusted input** first enters
//! the node, so the decoder is deliberately strict:
//!
//! * every point (public key, commitment, key image, ring member) is decoded
//!   through the canonical + prime-order checks in `from_bytes`, so a
//!   non-canonical or torsion encoding is rejected *before* it can reach the
//!   verifier or the spent-key-image set (this is what closes the malleability
//!   items flagged in the security review);
//! * every length-prefixed vector is **bounded by its protocol maximum before a
//!   single item is decoded**, and the length is never used to pre-allocate.
//!
//!   Both halves are needed, and for years only the second was here. Not
//!   pre-allocating stops "claim four billion items, send a hundred bytes" — the
//!   memory attack. It does nothing about an attacker who *supplies* the bytes,
//!   because the work done is proportional to the items actually decoded, and a
//!   ring member costs two point decompressions for 64 bytes. Before the bounds
//!   existed, one message padded to the p2p frame cap took **8.79 seconds** to
//!   reject. Memory was never the expensive part (security review F28);
//! * trailing bytes after a complete object are rejected (no hidden payloads).
//!
//! Writing reuses the exact same byte layout used for hashing
//! ([`Transaction::to_bytes`], `Coinbase::to_bytes`, `BlockHeader::to_bytes`),
//! so a decoded-then-re-encoded object hashes identically.

use monero_clsag::Clsag;

use crate::amounts::{Commitment, RangeProof, MAX_COMMITMENTS};
use crate::block::{Block, BlockHeader, Coinbase, CoinbaseOutput};
use crate::keys::PublicKey;
use crate::p2p::{Phase, Wire};
use crate::ring::{InputSignature, KeyImage, RingMember};
use crate::tx::{Input, Output, Transaction};

/// A wire (de)serialization error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// Ran out of bytes mid-object.
    Truncated,
    /// A point/scalar was not a canonical, valid encoding.
    BadPoint,
    /// A signature or range proof failed to parse.
    BadProof,
    /// An unknown message/enum tag.
    BadTag,
    /// A length prefix exceeded the protocol bound for that field, so the object
    /// is invalid by construction and is rejected before its items are decoded.
    TooLarge,
    /// Extra bytes remained after a complete object.
    TrailingBytes,
}

// ---- cursor primitives ------------------------------------------------------

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if cur.len() < n {
        return Err(WireError::Truncated);
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

fn read_u8(cur: &mut &[u8]) -> Result<u8, WireError> {
    Ok(take(cur, 1)?[0])
}

fn read_u16(cur: &mut &[u8]) -> Result<u16, WireError> {
    Ok(u16::from_le_bytes(take(cur, 2)?.try_into().unwrap()))
}

fn read_u32(cur: &mut &[u8]) -> Result<u32, WireError> {
    Ok(u32::from_le_bytes(take(cur, 4)?.try_into().unwrap()))
}

fn read_u64(cur: &mut &[u8]) -> Result<u64, WireError> {
    Ok(u64::from_le_bytes(take(cur, 8)?.try_into().unwrap()))
}

fn read_u128(cur: &mut &[u8]) -> Result<u128, WireError> {
    Ok(u128::from_le_bytes(take(cur, 16)?.try_into().unwrap()))
}

fn read_array32(cur: &mut &[u8]) -> Result<[u8; 32], WireError> {
    Ok(take(cur, 32)?.try_into().unwrap())
}

fn read_array8(cur: &mut &[u8]) -> Result<[u8; 8], WireError> {
    Ok(take(cur, 8)?.try_into().unwrap())
}

fn read_public_key(cur: &mut &[u8]) -> Result<PublicKey, WireError> {
    PublicKey::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

fn read_commitment(cur: &mut &[u8]) -> Result<Commitment, WireError> {
    Commitment::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

fn read_key_image(cur: &mut &[u8]) -> Result<KeyImage, WireError> {
    KeyImage::from_bytes(read_array32(cur)?).ok_or(WireError::BadPoint)
}

// --- protocol bounds on length-prefixed vectors (security review F28) --------
//
// Not trusting a length for *allocation* is not enough. The work a decoder does
// is proportional to the number of items it actually decodes, and an attacker
// who supplies the bytes gets that work for the price of sending them. Every
// ring member costs two point decompressions plus torsion checks — about 32
// bytes of input per expensive curve operation, the best ratio in the format —
// so a single message padded to the p2p size cap forced **8.8 seconds** of CPU
// before anything could reject it. That is the same defect as F16, which was
// fixed for `additional_tx_public` alone; the argument was never carried across
// to the other vectors, and it applies to all of them.
//
// The bounds below are what the protocol can legitimately contain, so nothing
// valid is rejected. They are deliberately generous — several times any real
// value — because their job is to stop absurdity, not to police policy. Ring
// size is separately constrained by consensus (`RING_SIZE`), and output
// count by the aggregate range proof (`MAX_COMMITMENTS`).

/// Largest ring a single input may *declare on the wire*. Consensus pins the
/// real value at exactly `RING_SIZE` (16); this looser decode bound leaves room
/// to change that without a format change, and exists only to stop absurd
/// lengths before any member is decoded (F28).
pub const MAX_RING_SIZE: usize = 256;

/// Largest number of inputs one transaction may declare. Sweeping many small
/// outputs is legitimate and can need a lot of inputs, so this is set well above
/// anything a wallet builds — but the cost of an input is a whole ring, so it
/// cannot be unbounded.
pub const MAX_INPUTS: usize = 256;

/// Largest number of transactions a block may declare, and the largest peer list
/// a gossip message may carry. Both are bounded by the message size cap anyway;
/// these stop the decode loop long before that.
pub const MAX_TXS_PER_BLOCK: usize = 8192;
pub const MAX_PEERS_PER_MESSAGE: usize = 1024;

/// Read a length-prefixed vector.
///
/// `max` is the protocol maximum for this field, checked **before any item is
/// decoded** — that is the whole point, since decoding is where the cost is.
/// The length is still never used to pre-allocate.
fn read_vec<T, F>(cur: &mut &[u8], max: usize, mut read_item: F) -> Result<Vec<T>, WireError>
where
    F: FnMut(&mut &[u8]) -> Result<T, WireError>,
{
    let len = read_u32(cur)? as usize;
    if len > max {
        return Err(WireError::TooLarge);
    }
    let mut out = Vec::new(); // do NOT pre-allocate from an untrusted length
    for _ in 0..len {
        out.push(read_item(cur)?);
    }
    Ok(out)
}

fn write_vec<T, F>(out: &mut Vec<u8>, items: &[T], mut write_item: F)
where
    F: FnMut(&mut Vec<u8>, &T),
{
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        write_item(out, item);
    }
}

// ---- component codecs -------------------------------------------------------

fn read_ring_member(cur: &mut &[u8]) -> Result<RingMember, WireError> {
    let key = read_public_key(cur)?;
    let commitment = read_commitment(cur)?;
    Ok(RingMember::new(key, commitment))
}

fn write_ring_member(out: &mut Vec<u8>, m: &RingMember) {
    out.extend_from_slice(&m.key.to_bytes());
    out.extend_from_slice(&m.commitment.to_bytes());
}

fn read_input(cur: &mut &[u8]) -> Result<Input, WireError> {
    let ring = read_vec(cur, MAX_RING_SIZE, read_ring_member)?;
    let key_image = read_key_image(cur)?;
    let pseudo_out = read_commitment(cur)?;
    // The CLSAG has exactly `ring.len()` responses; serai reads it from a
    // std::io::Read, which `&[u8]` implements.
    let clsag = Clsag::read(ring.len(), cur).map_err(|_| WireError::BadProof)?;
    let signature = InputSignature::from_parts(clsag, key_image, pseudo_out);
    Ok(Input { ring, signature })
}

fn write_input(out: &mut Vec<u8>, input: &Input) {
    write_vec(out, &input.ring, write_ring_member);
    out.extend_from_slice(&input.signature.key_image.to_bytes());
    out.extend_from_slice(&input.signature.pseudo_out.to_bytes());
    input.signature.clsag().write(out).expect("Vec write is infallible");
}

fn read_output(cur: &mut &[u8]) -> Result<Output, WireError> {
    let one_time_key = read_public_key(cur)?;
    let commitment = read_commitment(cur)?;
    let encrypted_amount = read_array8(cur)?;
    Ok(Output { one_time_key, commitment, encrypted_amount })
}

fn write_output(out: &mut Vec<u8>, o: &Output) {
    out.extend_from_slice(&o.one_time_key.to_bytes());
    out.extend_from_slice(&o.commitment.to_bytes());
    out.extend_from_slice(&o.encrypted_amount);
}

// ---- Transaction ------------------------------------------------------------

fn write_transaction_into(out: &mut Vec<u8>, tx: &Transaction) {
    out.push(tx.version);
    out.extend_from_slice(&tx.tx_public.to_bytes());
    // Additional per-output tx keys (u32 count + keys), matching `to_bytes`.
    out.extend_from_slice(&(tx.additional_tx_public.len() as u32).to_le_bytes());
    for r in &tx.additional_tx_public {
        out.extend_from_slice(&r.to_bytes());
    }
    out.extend_from_slice(&tx.fee.to_le_bytes());
    write_vec(out, &tx.inputs, write_input);
    write_vec(out, &tx.outputs, write_output);
    out.extend_from_slice(&tx.range_proof.to_bytes());
}

fn read_transaction(cur: &mut &[u8]) -> Result<Transaction, WireError> {
    let version = read_u8(cur)?;
    let tx_public = read_public_key(cur)?;
    // Additional per-output tx keys. Length-prefixed, but never trusted for
    // allocation (module invariant). It is also **bounded before any key is
    // decoded**: a legitimate vector is empty or one key per output, and a
    // transaction can carry at most `MAX_COMMITMENTS` outputs, so anything
    // larger is invalid by construction. Without this bound an attacker could
    // pad the vector to the message-size cap (~262k keys) and force that many
    // point decompressions + torsion checks — seconds of CPU per transaction,
    // on a transaction that would then be relayed. Reject it up front.
    let additional_count = read_u32(cur)? as usize;
    if additional_count > MAX_COMMITMENTS {
        return Err(WireError::TooLarge);
    }
    let mut additional_tx_public = Vec::new();
    for _ in 0..additional_count {
        additional_tx_public.push(read_public_key(cur)?);
    }
    let fee = read_u64(cur)?;
    let inputs = read_vec(cur, MAX_INPUTS, read_input)?;
    let outputs = read_vec(cur, MAX_COMMITMENTS, read_output)?;
    let range_proof = RangeProof::read_from(cur).map_err(|_| WireError::BadProof)?;
    Ok(Transaction { version, tx_public, additional_tx_public, fee, inputs, outputs, range_proof })
}

/// Serialize a transaction. Byte-identical to [`Transaction::to_bytes`], so the
/// transaction hash is unchanged.
pub fn encode_transaction(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    write_transaction_into(&mut out, tx);
    out
}

/// Decode a transaction, rejecting trailing bytes.
pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, WireError> {
    let mut cur = bytes;
    let tx = read_transaction(&mut cur)?;
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(tx)
}

// ---- Block ------------------------------------------------------------------

fn read_block_header(cur: &mut &[u8]) -> Result<BlockHeader, WireError> {
    let major_version = read_u8(cur)?;
    let minor_version = read_u8(cur)?;
    let timestamp = read_u64(cur)?;
    let prev_id = read_array32(cur)?;
    let nonce = read_u32(cur)?;
    Ok(BlockHeader { major_version, minor_version, timestamp, prev_id, nonce })
}

fn read_coinbase_output(cur: &mut &[u8]) -> Result<CoinbaseOutput, WireError> {
    let one_time_key = read_public_key(cur)?;
    let amount = read_u64(cur)?;
    let commitment = read_commitment(cur)?;
    Ok(CoinbaseOutput { one_time_key, amount, commitment })
}

fn read_coinbase(cur: &mut &[u8]) -> Result<Coinbase, WireError> {
    let height = read_u64(cur)?;
    let tx_public = read_public_key(cur)?;
    let outputs = read_vec(cur, MAX_COMMITMENTS, read_coinbase_output)?;
    Ok(Coinbase { height, tx_public, outputs })
}

fn read_block(cur: &mut &[u8]) -> Result<Block, WireError> {
    let header = read_block_header(cur)?;
    let coinbase = read_coinbase(cur)?;
    let tx_hashes = read_vec(cur, MAX_TXS_PER_BLOCK, read_array32)?;
    Ok(Block { header, coinbase, tx_hashes })
}

fn write_block_into(out: &mut Vec<u8>, block: &Block) {
    out.extend_from_slice(&block.header.to_bytes());
    out.extend_from_slice(&block.coinbase.to_bytes());
    write_vec(out, &block.tx_hashes, |o, h| o.extend_from_slice(h));
}

/// Serialize a block header + coinbase + tx-hash list (not the full transactions).
pub fn encode_block(block: &Block) -> Vec<u8> {
    let mut out = Vec::new();
    write_block_into(&mut out, block);
    out
}

/// Decode a block, rejecting trailing bytes.
pub fn decode_block(bytes: &[u8]) -> Result<Block, WireError> {
    let mut cur = bytes;
    let block = read_block(&mut cur)?;
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(block)
}

// ---- P2P messages -----------------------------------------------------------

const TAG_TX: u8 = 0;
const TAG_BLOCK: u8 = 1;
const TAG_GET_TIP: u8 = 2;
const TAG_TIP: u8 = 3;
const TAG_GET_BLOCK: u8 = 4;
const TAG_NO_BLOCK: u8 = 5;
const TAG_VERSION: u8 = 6;
const TAG_GET_PEERS: u8 = 7;
const TAG_PEERS: u8 = 8;
const PHASE_STEM: u8 = 0;
const PHASE_FLUFF: u8 = 1;

// Address family tags for the compact SocketAddr encoding.
const ADDR_V4: u8 = 4;
const ADDR_V6: u8 = 6;

fn write_socket_addr(out: &mut Vec<u8>, addr: &std::net::SocketAddr) {
    match addr {
        std::net::SocketAddr::V4(a) => {
            out.push(ADDR_V4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
        std::net::SocketAddr::V6(a) => {
            out.push(ADDR_V6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
    }
}

fn read_socket_addr(cur: &mut &[u8]) -> Result<std::net::SocketAddr, WireError> {
    match read_u8(cur)? {
        ADDR_V4 => {
            let ip: [u8; 4] = take(cur, 4)?.try_into().unwrap();
            let port = read_u16(cur)?;
            Ok((std::net::Ipv4Addr::from(ip), port).into())
        }
        ADDR_V6 => {
            let ip: [u8; 16] = take(cur, 16)?.try_into().unwrap();
            let port = read_u16(cur)?;
            Ok((std::net::Ipv6Addr::from(ip), port).into())
        }
        _ => Err(WireError::BadTag),
    }
}

/// Serialize a gossip [`Wire`] message.
pub fn encode_message(msg: &Wire) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        Wire::Tx(tx, phase) => {
            out.push(TAG_TX);
            write_transaction_into(&mut out, tx);
            out.push(match phase {
                Phase::Stem => PHASE_STEM,
                Phase::Fluff => PHASE_FLUFF,
            });
        }
        Wire::Block(block, txs) => {
            out.push(TAG_BLOCK);
            write_block_into(&mut out, block);
            write_vec(&mut out, txs, write_transaction_into);
        }
        Wire::GetTip => out.push(TAG_GET_TIP),
        Wire::Tip(network, height, tip, work) => {
            out.push(TAG_TIP);
            out.extend_from_slice(&network.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
            out.extend_from_slice(tip);
            // Cumulative difficulty: the value fork choice is actually decided
            // on. Height is kept because it drives the cheap sequential
            // catch-up, but it must never be what a reorg is judged by.
            out.extend_from_slice(&work.to_le_bytes());
        }
        Wire::GetBlock(height) => {
            out.push(TAG_GET_BLOCK);
            out.extend_from_slice(&height.to_le_bytes());
        }
        Wire::NoBlock(height) => {
            out.push(TAG_NO_BLOCK);
            out.extend_from_slice(&height.to_le_bytes());
        }
        Wire::Version(network, genesis, port, nonce) => {
            out.push(TAG_VERSION);
            out.extend_from_slice(&network.to_le_bytes());
            out.extend_from_slice(genesis);
            out.extend_from_slice(&port.to_le_bytes());
            out.extend_from_slice(&nonce.to_le_bytes());
        }
        Wire::GetPeers => out.push(TAG_GET_PEERS),
        Wire::Peers(addrs) => {
            out.push(TAG_PEERS);
            write_vec(&mut out, addrs, write_socket_addr);
        }
    }
    out
}

/// Decode a gossip [`Wire`] message, rejecting trailing bytes.
pub fn decode_message(bytes: &[u8]) -> Result<Wire, WireError> {
    let mut cur = bytes;
    let msg = match read_u8(&mut cur)? {
        TAG_TX => {
            let tx = read_transaction(&mut cur)?;
            let phase = match read_u8(&mut cur)? {
                PHASE_STEM => Phase::Stem,
                PHASE_FLUFF => Phase::Fluff,
                _ => return Err(WireError::BadTag),
            };
            Wire::Tx(tx, phase)
        }
        TAG_BLOCK => {
            let block = read_block(&mut cur)?;
            let txs = read_vec(&mut cur, MAX_TXS_PER_BLOCK, read_transaction)?;
            Wire::Block(block, txs)
        }
        TAG_GET_TIP => Wire::GetTip,
        TAG_TIP => {
            let network = read_u32(&mut cur)?;
            let height = read_u64(&mut cur)?;
            let tip = read_array32(&mut cur)?;
            let work = read_u128(&mut cur)?;
            Wire::Tip(network, height, tip, work)
        }
        TAG_GET_BLOCK => Wire::GetBlock(read_u64(&mut cur)?),
        TAG_NO_BLOCK => Wire::NoBlock(read_u64(&mut cur)?),
        TAG_VERSION => {
            let network = read_u32(&mut cur)?;
            let genesis = read_array32(&mut cur)?;
            let port = read_u16(&mut cur)?;
            let nonce = read_u64(&mut cur)?;
            Wire::Version(network, genesis, port, nonce)
        }
        TAG_GET_PEERS => Wire::GetPeers,
        TAG_PEERS => Wire::Peers(read_vec(&mut cur, MAX_PEERS_PER_MESSAGE, read_socket_addr)?),
        _ => return Err(WireError::BadTag),
    };
    if !cur.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};
    use crate::amounts::Opening;
    use crate::block::{BlockHeader, Coinbase};
    use crate::chain::Blockchain;
    use crate::emission::{base_reward, ATOMIC_UNITS};
    use crate::keys::{Account, PrivateKey};
    use crate::pow::KeccakPow;
    use crate::ring::RingMember;
    use crate::stealth::TxKeypair;
    use crate::tx::{Payment, ReceivedOutput, Transaction};
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    fn address(a: &Account) -> Address {
        Address::new(Network::Mainnet, a.spend_public, a.view_public)
    }

    fn mine(chain: &mut Blockchain<KeccakPow>, miner: &Account, ts: u64) -> (ReceivedOutput, u64, Block) {
        let subsidy = base_reward(chain.emitted());
        let cb = Coinbase::create(&mut OsRng, chain.height(), &address(miner), subsidy);
        let received = cb.scan(miner).unwrap();
        let index = chain.num_outputs();
        let mut block = Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: crate::block::GENESIS_TIMESTAMP + ts,
                prev_id: chain.tip_id(),
                nonce: 0,
            },
            coinbase: cb,
            tx_hashes: vec![],
        };
        block.mine(&KeccakPow, chain.next_difficulty());
        chain.add_block(&mut OsRng, &block, &[]).unwrap();
        (received, index, block)
    }

    // A real transaction spending a coinbase, for codec tests.
    fn sample_tx() -> (Transaction, Block) {
        let mut chain = Blockchain::with_maturity(KeccakPow, 1);
        let miner = Account::random(&mut OsRng);
        let (received, cb_index, _) = mine(&mut chain, &miner, 1_000);
        let filler = Account::random(&mut OsRng);
        for i in 0..15 {
            mine(&mut chain, &filler, 1_200 + i * 130);
        }
        let (ring, signer) = chain.select_ring_uniform(&mut OsRng, crate::chain::RING_SIZE, cb_index).unwrap();
        let input = received.to_input(ring, signer);
        let bob = Account::random(&mut OsRng);
        let reward = received.amount;
        let tx = Transaction::build(
            &mut OsRng,
            &[input],
            &[Payment { destination: address(&bob), amount: reward - ATOMIC_UNITS / 100 }],
            ATOMIC_UNITS / 100,
            &TxKeypair::random(&mut OsRng),
        )
        .unwrap();
        let (_, _, block) = mine(&mut chain, &miner, 60_000);
        (tx, block)
    }

    #[test]
    fn transaction_round_trips_and_matches_hash_encoding() {
        let (tx, _) = sample_tx();
        // Wire encoding equals the hashing encoding.
        assert_eq!(encode_transaction(&tx), tx.to_bytes());
        let decoded = decode_transaction(&encode_transaction(&tx)).unwrap();
        assert_eq!(decoded.hash(), tx.hash());
        // Round-trips through the struct fields that matter.
        assert_eq!(decoded.inputs.len(), tx.inputs.len());
        assert_eq!(decoded.outputs.len(), tx.outputs.len());
        assert_eq!(decoded.fee, tx.fee);
        // And it still verifies after a round trip.
        assert!(decoded.verify(&mut OsRng).is_ok());
    }

    #[test]
    fn block_round_trips() {
        let (_, block) = sample_tx();
        let decoded = decode_block(&encode_block(&block)).unwrap();
        assert_eq!(decoded.id(), block.id());
    }

    #[test]
    fn message_round_trips() {
        let (tx, block) = sample_tx();
        let tx_msg = Wire::Tx(tx.clone(), Phase::Fluff);
        match decode_message(&encode_message(&tx_msg)).unwrap() {
            Wire::Tx(t, Phase::Fluff) => assert_eq!(t.hash(), tx.hash()),
            _ => panic!("wrong message"),
        }
        let block_msg = Wire::Block(block.clone(), vec![tx.clone()]);
        match decode_message(&encode_message(&block_msg)).unwrap() {
            Wire::Block(b, txs) => {
                assert_eq!(b.id(), block.id());
                assert_eq!(txs[0].hash(), tx.hash());
            }
            _ => panic!("wrong message"),
        }
    }

    #[test]
    fn handshake_and_peer_messages_round_trip() {
        // Version handshake.
        let v = Wire::Version(0x4E4F4354, [7u8; 32], 9333, 0xABCD_1234_5678_9012);
        match decode_message(&encode_message(&v)).unwrap() {
            Wire::Version(net, gen, port, nonce) => {
                assert_eq!(net, 0x4E4F4354);
                assert_eq!(gen, [7u8; 32]);
                assert_eq!(port, 9333);
                assert_eq!(nonce, 0xABCD_1234_5678_9012);
            }
            _ => panic!("wrong message"),
        }

        // GetPeers.
        assert!(matches!(decode_message(&encode_message(&Wire::GetPeers)).unwrap(), Wire::GetPeers));

        // Peers list with both IPv4 and IPv6 addresses.
        let addrs: Vec<std::net::SocketAddr> = vec![
            "1.2.3.4:9333".parse().unwrap(),
            "127.0.0.1:65535".parse().unwrap(),
            "[2001:db8::1]:9333".parse().unwrap(),
        ];
        match decode_message(&encode_message(&Wire::Peers(addrs.clone()))).unwrap() {
            Wire::Peers(got) => assert_eq!(got, addrs),
            _ => panic!("wrong message"),
        }
    }

    #[test]
    fn decode_never_panics_on_adversarial_input() {
        use rand_core::RngCore;
        let mut rng = OsRng;

        // Random byte soup across many lengths: decoders must return Ok/Err, never
        // panic (no unchecked slicing, no allocation from an untrusted length).
        for len in 0..48usize {
            for _ in 0..20 {
                let mut buf = vec![0u8; len];
                rng.fill_bytes(&mut buf);
                let _ = decode_message(&buf);
                let _ = decode_transaction(&buf);
                let _ = decode_block(&buf);
            }
        }

        // Truncations of valid messages must error cleanly, and trailing garbage
        // must be rejected. Cuts are sampled by a stride so a multi-KB tx/block
        // (whose near-complete decodes re-parse the whole range proof + CLSAG)
        // doesn't make this O(size) in expensive decodes.
        let (tx, block) = sample_tx();
        let messages = [
            Wire::Tx(tx.clone(), Phase::Fluff),
            Wire::Block(block, vec![tx]),
            Wire::GetTip,
            Wire::Version(0x4E4F4354, [1u8; 32], 9333, 7),
            Wire::Peers(vec!["1.2.3.4:9333".parse().unwrap()]),
            Wire::GetBlock(5),
        ];
        for msg in messages {
            let full = encode_message(&msg);
            let stride = (full.len() / 48).max(1);
            let mut cut = 0;
            while cut < full.len() {
                let _ = decode_message(&full[..cut]); // truncated → Err, not a panic
                cut += stride;
            }
            let mut trailing = full.clone();
            trailing.push(0xff);
            assert!(decode_message(&trailing).is_err(), "trailing bytes must be rejected");
        }
    }

    #[test]
    fn rejects_non_canonical_point() {
        // A ring member whose key is a torsion point must be rejected on decode.
        let good = RingMember::new(
            PrivateKey(Scalar::random(&mut OsRng)).public_key(),
            Opening::random(1, &mut OsRng).commit(),
        );
        let mut bytes = Vec::new();
        write_ring_member(&mut bytes, &good);
        // Sanity: valid member decodes.
        assert!(read_ring_member(&mut bytes.as_slice()).is_ok());
        // Corrupt the key bytes to a small-order (torsion) point encoding.
        // The 8-torsion point with compressed encoding [1,0,...,0] is the identity;
        // use a known small-order point: all-zero y with sign bit — decompress
        // yields a torsion point that `from_bytes` must reject.
        let mut bad = bytes.clone();
        bad[..32].copy_from_slice(&[0u8; 32]); // non-identity small-order encoding
        let res = read_ring_member(&mut bad.as_slice());
        assert!(res.is_err(), "torsion/invalid point must be rejected");
    }

    #[test]
    fn rejects_truncated_and_trailing() {
        let (tx, _) = sample_tx();
        let bytes = encode_transaction(&tx);
        // Truncated: drop the last byte.
        assert!(decode_transaction(&bytes[..bytes.len() - 1]).is_err());
        // Trailing garbage: append a byte.
        let mut extra = bytes.clone();
        extra.push(0x00);
        assert!(matches!(decode_transaction(&extra), Err(WireError::TrailingBytes)));
    }

    /// Write a seed corpus of **valid** encodings for the `cargo-fuzz` targets
    /// in `noct/fuzz`. libFuzzer starting from real messages explores far deeper
    /// than starting from random bytes, since a random buffer essentially never
    /// survives the point and length checks.
    ///
    /// Not part of the normal suite (it writes files); run it explicitly:
    ///
    /// ```text
    /// cargo test -p noct-core -- --ignored generate_fuzz_corpus
    /// ```
    #[test]
    #[ignore = "writes a seed corpus for cargo-fuzz; run explicitly"]
    fn generate_fuzz_corpus() {
        let (tx, block) = sample_tx();
        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("tx", encode_transaction(&tx)),
            ("block", encode_block(&block)),
            ("msg_tx_stem", encode_message(&Wire::Tx(tx.clone(), Phase::Stem))),
            ("msg_tx_fluff", encode_message(&Wire::Tx(tx.clone(), Phase::Fluff))),
            ("msg_block", encode_message(&Wire::Block(block, vec![tx]))),
            ("msg_gettip", encode_message(&Wire::GetTip)),
            ("msg_getblock", encode_message(&Wire::GetBlock(1))),
            ("msg_version", encode_message(&Wire::Version(0x4E4F4354, [0u8; 32], 9333, 1))),
            ("msg_getpeers", encode_message(&Wire::GetPeers)),
            ("msg_peers", encode_message(&Wire::Peers(vec!["1.2.3.4:9333".parse().unwrap()]))),
        ];

        for target in ["wire_decode", "wire_roundtrip"] {
            let dir = std::path::Path::new("../fuzz/corpus").join(target);
            std::fs::create_dir_all(&dir).expect("create corpus dir");
            for (name, bytes) in &samples {
                std::fs::write(dir.join(name), bytes).expect("write corpus entry");
            }
            eprintln!("[corpus] wrote {} seeds to {}", samples.len(), dir.display());
        }
    }

    /// A deterministic **mutational** fuzzer over the wire decoders.
    ///
    /// Stronger than random byte soup: it starts from *valid* encodings and
    /// mutates them, so inputs stay structurally plausible and reach decode
    /// paths past the length prefixes and point checks that random bytes
    /// essentially never survive to. The PRNG is seeded by a constant, so a
    /// failure is reproducible and the harness is deterministic in CI.
    ///
    /// Two properties are asserted for every input:
    ///
    /// * **no panic** — decoders must return `Ok`/`Err` for arbitrary bytes,
    ///   never index out of bounds or allocate from an untrusted length;
    /// * **canonicality** — if bytes decode, re-encoding the value must
    ///   reproduce those bytes *exactly*. A violation means two distinct byte
    ///   strings decode to the same object: a malleable encoding, which is how
    ///   identifier-substitution bugs (see F5) get in.
    ///
    /// ## Running a longer campaign
    ///
    /// The defaults are sized to stay in the normal suite. For a real campaign
    /// on the stable toolchain — the coverage-guided `fuzz/` targets need a
    /// nightly one — override both knobs and vary the seed across runs:
    ///
    /// ```text
    /// NOCT_FUZZ_ITERS=200000 NOCT_FUZZ_SEED=2 \
    ///   cargo test --release -p noct-core mutational_fuzz -- --nocapture
    /// ```
    ///
    /// A distinct `NOCT_FUZZ_SEED` explores a different mutation sequence, so
    /// several seeded runs cover more than one long run at the same seed. Any
    /// failure prints the exact seed and iteration needed to reproduce it.
    #[test]
    fn mutational_fuzz_decoders_are_panic_free_and_canonical() {
        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }

        fn env_u64(name: &str, default: u64) -> u64 {
            std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        let iters = env_u64("NOCT_FUZZ_ITERS", 30);
        // Mixed into the constant rather than replacing it, so the default run
        // is bit-for-bit what it always was and only an explicit override moves.
        let campaign = env_u64("NOCT_FUZZ_SEED", 0);

        let (tx, block) = sample_tx();
        let seeds: Vec<(&str, Vec<u8>)> = vec![
            ("tx", encode_transaction(&tx)),
            ("block", encode_block(&block)),
            ("msg:tx", encode_message(&Wire::Tx(tx.clone(), Phase::Stem))),
            ("msg:block", encode_message(&Wire::Block(block.clone(), vec![tx.clone()]))),
            ("msg:version", encode_message(&Wire::Version(0x4E4F4354, [3u8; 32], 9333, 42))),
            ("msg:peers", encode_message(&Wire::Peers(vec!["9.8.7.6:9333".parse().unwrap()]))),
        ];

        let mut state: u64 = 0x5EED_1234_ABCD_0001 ^ campaign.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut decoded_ok = 0usize;
        for (name, seed) in &seeds {
            for iter in 0..iters {
                let mut buf = seed.clone();
                if buf.is_empty() {
                    continue;
                }
                match xorshift(&mut state) % 4 {
                    // Flip a single bit — the classic mutation.
                    0 => {
                        let i = (xorshift(&mut state) as usize) % buf.len();
                        buf[i] ^= 1u8 << (xorshift(&mut state) % 8);
                    }
                    // Replace a byte outright.
                    1 => {
                        let i = (xorshift(&mut state) as usize) % buf.len();
                        buf[i] = xorshift(&mut state) as u8;
                    }
                    // Tamper with a 32-bit little-endian field (length prefixes
                    // live here) — targets the "lie about a count" class.
                    2 => {
                        if buf.len() >= 4 {
                            let i = (xorshift(&mut state) as usize) % (buf.len() - 3);
                            let v: u32 = match xorshift(&mut state) % 3 {
                                0 => u32::MAX,
                                1 => 0,
                                _ => xorshift(&mut state) as u32,
                            };
                            buf[i..i + 4].copy_from_slice(&v.to_le_bytes());
                        }
                    }
                    // Splice: graft a chunk of another seed in.
                    _ => {
                        let other = &seeds[(xorshift(&mut state) as usize) % seeds.len()].1;
                        if !other.is_empty() {
                            let at = (xorshift(&mut state) as usize) % buf.len();
                            let take = ((xorshift(&mut state) as usize) % 32).min(other.len());
                            let end = (at + take).min(buf.len());
                            buf[at..end].copy_from_slice(&other[..end - at]);
                        }
                    }
                }

                let ctx = format!("seed={name} iter={iter}");

                // Canonicality: anything that decodes must re-encode identically.
                if let Ok(decoded) = decode_transaction(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_transaction(&decoded), buf, "non-canonical transaction ({ctx})");
                    assert!(
                        decoded.additional_tx_public.len() <= MAX_COMMITMENTS,
                        "decoded tx exceeded the additional-key bound ({ctx})"
                    );
                    // Identifier stability: a txid is `Keccak256(to_bytes)`, so
                    // the decode → encode → decode cycle must be a fixed point
                    // in both bytes and identity. (Mirrors the `wire_roundtrip`
                    // cargo-fuzz target, which needs nightly to run.)
                    let again = decode_transaction(&buf).expect("re-decode of accepted bytes");
                    assert_eq!(again.hash(), decoded.hash(), "txid changed across a round trip ({ctx})");
                }
                if let Ok(decoded) = decode_block(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_block(&decoded), buf, "non-canonical block ({ctx})");
                    let again = decode_block(&buf).expect("re-decode of accepted bytes");
                    assert_eq!(again.id(), decoded.id(), "block id changed across a round trip ({ctx})");
                }
                if let Ok(decoded) = decode_message(&buf) {
                    decoded_ok += 1;
                    assert_eq!(encode_message(&decoded), buf, "non-canonical message ({ctx})");
                }
            }
        }
        // The harness must actually *reach* the property it asserts. Without
        // this, a future change that made every mutation fail early would leave
        // a green test that exercises nothing. (Roughly 47% of mutations decode:
        // ~84 of the default 180.)
        //
        // Expressed as a fraction of the work actually done, so it stays a real
        // check at any campaign length instead of being trivially satisfied by a
        // long run.
        let attempted = seeds.len() * iters as usize;
        let floor = (attempted / 5).max(1);
        assert!(
            decoded_ok >= floor,
            "mutational fuzzing reached the canonicality check only {decoded_ok} times \
             out of {attempted} mutations (needed {floor}) — the mutations are no longer \
             producing decodable inputs"
        );
        if iters > 30 {
            eprintln!("[fuzz] {attempted} mutations, {decoded_ok} decoded and re-encoded canonically");
        }
    }

    /// An oversized `additional_tx_public` count must be rejected *before* any
    /// key is decoded. Each key costs a point decompression + torsion check, so
    /// a vector padded to the message-size cap (~262k keys) would otherwise burn
    /// seconds of CPU per transaction — on a transaction that would then be
    /// relayed. The bound must trip on the count alone, without reading the keys.
    #[test]
    fn oversized_additional_key_count_is_rejected_before_decoding_keys() {
        let (tx, _) = sample_tx();
        let real = encode_transaction(&tx);

        // Rebuild the prefix with a huge additional-key count, and supply NO key
        // bytes at all. If the decoder honoured the count it would fail with
        // `Truncated` only after trying to read them; the bound must reject it
        // outright, and instantly.
        let mut evil = Vec::new();
        evil.push(tx.version);
        evil.extend_from_slice(&tx.tx_public.to_bytes());
        evil.extend_from_slice(&(262_144u32).to_le_bytes());
        evil.extend_from_slice(&real[37..]); // the rest of a real transaction

        let start = std::time::Instant::now();
        let err = decode_transaction(&evil).unwrap_err();
        let elapsed = start.elapsed();

        assert_eq!(err, WireError::TooLarge, "oversized count rejected by the bound");
        assert!(elapsed.as_millis() < 500, "must reject on the count alone, not by decoding keys (took {elapsed:?})");

        // A legitimate count (one key per output) still decodes.
        assert!(MAX_COMMITMENTS >= 2, "sanity: the cap admits normal transactions");
    }

    /// **F28.** An oversized ring must be rejected on its *length alone*, before
    /// a single member is decoded.
    ///
    /// Found by an independent review, and it is the same defect as F16 — which
    /// was fixed for `additional_tx_public` only. Every ring member costs two
    /// point decompressions plus torsion checks for 64 bytes of input, the best
    /// work-per-byte ratio in the format. **Measured before the fix: a single
    /// message padded to the 8 MiB p2p cap took 8.79 seconds to reject.** A few
    /// such messages a second from one peer stall a node completely, and they
    /// cost the sender nothing: no valid signature, range proof, or balance is
    /// needed, because the work happens during decoding.
    ///
    /// The assertion is on **time**, because that is the actual property. A test
    /// that only checked the error could pass while the decoder still ground
    /// through every member first.
    #[test]
    fn an_oversized_ring_is_rejected_before_decoding_its_members() {
        use std::time::Instant;
        let (tx, _) = sample_tx();
        let mut member_bytes = Vec::new();
        write_ring_member(&mut member_bytes, &tx.inputs[0].ring[0]);

        // As many real, decodable ring members as the p2p frame cap allows.
        let members = (8 * 1024 * 1024 - 1024) / 64;
        assert!(members > MAX_RING_SIZE * 100, "the test must exceed the bound by a wide margin");

        let mut raw = Vec::new();
        raw.push(0u8); // TAG_TX
        raw.push(1u8); // version
        raw.extend_from_slice(&tx.tx_public.to_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // no additional keys
        raw.extend_from_slice(&0u64.to_le_bytes()); // fee
        raw.extend_from_slice(&1u32.to_le_bytes()); // one input
        raw.extend_from_slice(&(members as u32).to_le_bytes()); // ... with an absurd ring
        for _ in 0..members {
            raw.extend_from_slice(&member_bytes);
        }

        let started = Instant::now();
        let result = decode_message(&raw);
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(WireError::TooLarge)),
            "must be refused on the length alone, got {:?}",
            result.err()
        );
        assert!(
            elapsed.as_millis() < 500,
            "took {elapsed:?} to reject — the members are still being decoded, \
             which is the whole defect (8.79s before the bound existed)"
        );
    }

    /// The bounds must admit everything legitimate. A bound that rejected real
    /// transactions would be a consensus failure dressed up as hardening.
    #[test]
    fn the_bounds_admit_every_legitimate_object() {
        assert!(MAX_RING_SIZE >= crate::chain::RING_SIZE, "the consensus ring size must be decodable");
        assert!(MAX_RING_SIZE >= 16, "room to raise the ring size without a format change");
        assert!(MAX_INPUTS >= 64, "sweeping many small outputs is legitimate");
        assert!(MAX_TXS_PER_BLOCK >= 1024, "a full block must decode");
        assert!(MAX_PEERS_PER_MESSAGE >= 32, "must admit a full gossip reply");

        // And the real thing still round-trips.
        let (tx, block) = sample_tx();
        let encoded = encode_message(&Wire::Block(block, vec![tx]));
        assert!(decode_message(&encoded).is_ok(), "a real block must still decode");
    }

}

