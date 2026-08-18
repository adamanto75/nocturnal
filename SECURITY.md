# Reporting a vulnerability

Nocturnal is pre-launch and unaudited. If you find a security issue — especially
anything affecting consensus, the wire decoder, key handling, or the privacy
guarantees — please report it privately first.

**Contact:** open a GitHub Security Advisory on this repository
(Security → Report a vulnerability). That channel is private until published.

Please include what you did, what happened, and what you expected. A proof of
concept helps enormously but is not required to file.

## Scope worth attacking

* Consensus rules and reorg handling (`noct/core/src/chain.rs`)
* The wire decoder, which parses attacker-supplied bytes (`noct/core/src/wire.rs`)
* Ring signature / range proof verification and key-image handling
* The node RPC and anything reachable from the public internet
* Emission and the premine accounting

## Known and accepted

These are documented, not news — see `noct/SECURITY-REVIEW.md`:

* Block validity depends on the validating node's wall clock, by design, as in Monero
* Decoy selection is uniform, not gamma-calibrated to the real output distribution
* Mainnet parameters are placeholders
* The mainnet premine is 50% of the supply parameter — a policy decision, not a defect
