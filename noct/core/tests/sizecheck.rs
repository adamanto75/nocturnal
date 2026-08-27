//! What the in-memory representation actually costs.
//!
//! Every curve point is held decompressed: `EdwardsPoint` is four field
//! elements of five `u64` each, so a point costs **160 bytes in memory against
//! 32 on the wire**. A `RingMember` carries two of them, and `RING_SIZE` is 16,
//! so one input's ring occupies ~5 KB resident against ~1 KB serialized.
//!
//! This matters because `Blockchain` keeps every block *and its decoded
//! transactions* in RAM for the life of the process. Measured on the testnet at
//! height 5,248: 33 MB of chain on disk against ~768 MB resident, of which the
//! state actually needed to validate — the output set and the spent key images —
//! was about 4 MB. Almost all of it is retained block bodies, inflated by this
//! expansion.
//!
//! These asserts exist so a change that quietly doubles the cost shows up here
//! rather than as an OOM on a node months later.

use std::mem::size_of;

use noct_core::keys::PublicKey;
use noct_core::ring::{KeyImage, RingMember};

/// A compressed Ed25519 point is 32 bytes; these are the decompressed ones.
const POINT: usize = 160;

#[test]
fn a_curve_point_costs_five_times_its_serialized_size() {
    assert_eq!(size_of::<PublicKey>(), POINT);
    assert_eq!(size_of::<KeyImage>(), POINT);
}

#[test]
fn a_ring_member_is_two_points() {
    assert_eq!(size_of::<RingMember>(), 2 * POINT);
}
