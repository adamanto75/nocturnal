// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title NoctSwap — the Ethereum side of an ETH⇄NOCT atomic swap.
///
/// Native-ETH, one-swap-per-deployment PROTOTYPE, adapted from AthanorLabs'
/// SwapCreator (its ERC-20 and relayer paths are dropped for clarity). Alice
/// holds ETH and wants NOCT; Bob holds NOCT and wants ETH.
///
/// Flow (see docs/eth-atomic-swap.md):
///  1. Bob locks NOCT to the 2-of-2 joint account (noct_wallet::joint).
///  2. Alice deploys+funds this contract with commitments to Bob's and her own
///     secp256k1 public keys. Each commitment is keccak256(x‖y) of the point the
///     cross-group DLEQ (noct_swap) binds to that party's NOCT joint spend half.
///  3. Alice `setReady()` once she has verified the NOCT lock.
///  4. Bob `claim(s_b)` → gets the ETH and *reveals* s_b on-chain; Alice reads
///     it, reconstructs s_a + s_b, and sweeps the NOCT.
///  Refund paths (revealing s_a, letting Bob reclaim his NOCT) cover the aborts.
///
/// The secp256k1 discrete-log check is Vitalik's "abuse ecrecover to do ecmul"
/// trick: recovering from a crafted signature yields address(s·G) for ~3k gas
/// instead of an on-chain scalar multiplication.
contract NoctSwap {
    enum Stage {
        INVALID,
        PENDING,
        READY,
        COMPLETED
    }

    Stage public stage = Stage.PENDING;

    address payable public immutable owner; // Alice — provides the ETH
    address payable public immutable claimer; // Bob — receives the ETH
    bytes32 public immutable claimCommitment; // keccak256(Bob's secp256k1 x‖y)
    bytes32 public immutable refundCommitment; // keccak256(Alice's secp256k1 x‖y)
    uint256 public immutable timeout1;
    uint256 public immutable timeout2;
    uint256 public immutable value;

    // secp256k1 generator x-coordinate and group order, for the ecmul-via-ecrecover check.
    uint256 private constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 private constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    event Ready();
    event Claimed(bytes32 s);
    event Refunded(bytes32 s);

    error BadState();
    error NotOwner();
    error NotClaimer();
    error BadValue();
    error TooEarlyToClaim();
    error TooLateToClaim();
    error NotRefundable();
    error BadSecret();

    constructor(
        address payable _claimer,
        bytes32 _claimCommitment,
        bytes32 _refundCommitment,
        uint256 _timeoutDuration1,
        uint256 _timeoutDuration2
    ) payable {
        if (msg.value == 0) revert BadValue();
        if (_claimer == address(0)) revert NotClaimer();
        owner = payable(msg.sender);
        claimer = _claimer;
        claimCommitment = _claimCommitment;
        refundCommitment = _refundCommitment;
        timeout1 = block.timestamp + _timeoutDuration1;
        timeout2 = block.timestamp + _timeoutDuration1 + _timeoutDuration2;
        value = msg.value;
    }

    /// Alice enables Bob's claim, once she has verified the NOCT is locked.
    function setReady() external {
        if (msg.sender != owner) revert NotOwner();
        if (stage != Stage.PENDING) revert BadState();
        stage = Stage.READY;
        emit Ready();
    }

    /// Bob claims the ETH by revealing his secret `s`. Allowed if Alice set READY
    /// (before timeout1), or during [timeout1, timeout2). Reveals `s` on-chain so
    /// Alice can reconstruct the NOCT joint spend key.
    function claim(bytes32 s) external {
        if (msg.sender != claimer) revert NotClaimer();
        if (stage == Stage.INVALID || stage == Stage.COMPLETED) revert BadState();
        if (block.timestamp < timeout1 && stage != Stage.READY) revert TooEarlyToClaim();
        if (block.timestamp >= timeout2) revert TooLateToClaim();
        if (!mulVerify(uint256(s), uint256(claimCommitment))) revert BadSecret();
        stage = Stage.COMPLETED;
        emit Claimed(s);
        claimer.transfer(value);
    }

    /// Alice refunds by revealing her secret `s`. Allowed before timeout1 (unless
    /// she already set READY), or after timeout2 — i.e. exactly when Bob cannot
    /// claim. `claim` and `refund` are never simultaneously callable.
    function refund(bytes32 s) external {
        if (msg.sender != owner) revert NotOwner();
        if (stage == Stage.INVALID || stage == Stage.COMPLETED) revert BadState();
        if (
            block.timestamp < timeout2 &&
            (block.timestamp > timeout1 || stage == Stage.READY)
        ) revert NotRefundable();
        if (!mulVerify(uint256(s), uint256(refundCommitment))) revert BadSecret();
        stage = Stage.COMPLETED;
        emit Refunded(s);
        owner.transfer(value);
    }

    /// Returns true iff `s·G` on secp256k1 equals the point committed to by
    /// `qKeccak` (= keccak256(x‖y)), compared on the low 160 bits (its Ethereum
    /// address). `ecrecover(0, 27, GX, s·GX mod N)` recovers `address(s·G)`.
    function mulVerify(uint256 s, uint256 qKeccak) public pure returns (bool) {
        address qRes = ecrecover(0, 27, bytes32(GX), bytes32(mulmod(s, GX, N)));
        return uint160(qKeccak) == uint160(qRes);
    }
}
