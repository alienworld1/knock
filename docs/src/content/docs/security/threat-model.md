---
title: Threat model and limits
description: Security guarantees, fail-closed invariants, metadata visibility, and documented system limits.
---

Knock aims to be honest about what it protects and where every guarantee ends.

## Security invariants tested

| Scenario                                  | Enforced behavior                                                                                                                                                                                                                       |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unapproved requester or scanner           | Door drops unpermitted traffic on `198.19.0.0/28` via `inet knock_ssh`; OpenSSH rejects uncertified keys and wrong principals.                                                                                                          |
| Tampered request, response, or Entry Pass | Canonical CBOR signatures and ciphertext commitments reject altered roles, durations, keys, or Door bindings before granting access.                                                                                                    |
| Malicious or replayed Mailbox delivery    | Duplicate deliveries do not create duplicate reservations or second sessions; wrong-recipient envelopes fail decryption.                                                                                                                |
| Classical-only or stale chain keys        | `knockd` and `KnockRegistry` fail closed unless proven hybrid ML-DSA-87 and ML-KEM-1024 bindings match fresh Diana state.                                                                                                               |
| Compromised static KEM key after session  | Connection responses and 256-bit WireGuard PSKs seal only to the requester's one-time reply key, separating past session secrets from static recipient keys. Note that static-key-encrypted request reasons do not share this property. |
| Chain RPC or Mailbox outage               | New admissions fail closed; existing sessions still expire locally via monotonic timers, nftables timeouts, and systemd `RuntimeMaxSec`.                                                                                                |
| Daemon crash or restart                   | Startup reconciliation locks Knock permits to deny and closes outstanding grants conservatively rather than restoring old credentials.                                                                                                  |
| Former audit group member                 | Epoch rotation prevents removed auditors from decrypting newly sealed Receipts.                                                                                                                                                         |

## Metadata visibility

Knock does not claim anonymity or invisible infrastructure:

- **Mailbox relay:** learns routing `qor1...` account addresses, message sizes, delivery timing, and client IP addresses.
- **QoreChain Diana:** public state reveals Door policy commitments, owner/Door/approver account relationships, metered pass offers and purchases, and session revocation timing.
- **Network observers:** direct WireGuard UDP packets reveal client and Door IP endpoints to observers on the network path, and authorized clients learn the Door's WireGuard endpoint after admission.

## Known limits

1. **Draft cryptography package:** `github.com/qorechain/qoreseal/go` `v0.1.0` is an unaudited draft package. Functional tests verify interoperability and negative cases, not a third-party cryptographic audit.
2. **Trusted RPC observation:** Knock verifies Diana state over TLS to configured endpoints and checks head freshness and bytecode hashes, rather than running an independent consensus light client.
3. **Host root privilege:** `knockd` runs as `root` on the dedicated Door host to manage WireGuard, nftables, and systemd units. Root or host kernel compromise is outside the threat boundary.
4. **Best-effort memory wiping:** Knock clears sensitive byte slices and deletes temporary `/run/knock-ssh` files, but Go garbage collection and tmpfs behavior cannot guarantee physical zeroization.
5. **Audit history retention:** Removing an auditor from a new epoch blocks future Receipts, not historical Receipts or epoch keys that the member already downloaded before rotation.
6. **Direct UDP reachability:** Knock assumes an addressable UDP endpoint for the Door's WireGuard listener and does not provide general NAT traversal.
