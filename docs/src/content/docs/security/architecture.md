---
title: System architecture
description: Component boundaries, canonical CBOR encoding, split-envelope admission, and Linux kernel enforcement.
---

Knock separates message transport, chain authority, human authorization, and host enforcement into narrow components so no single service holds excess privilege.

## Trust boundaries

| Component                     | Holds                                                                                                        | Does not hold or control                                                        |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `knock` CLI and local console | User `.age` identity, temporary session private keys, one-time reply key, verified Door Cards                | Server host enforcement, Door SSH CA, other requesters' keys                    |
| `knockd`                      | Door `.age` identity, host WireGuard key, OpenSSH CA, `bbolt` admission journal, host network/cgroup control | Approvers' private request reasons (on Approval Doors)                          |
| `knockd mailbox`              | Bounded opaque `bbolt` queues (`15m` retention) and public signed cards                                      | Decryption keys, signing keys, authorization decisions                          |
| `KnockRegistry` (Diana)       | Policy commitments, approver sets, metered offers, pass purchases, session revocations                       | Private reasons, connection endpoints, PSKs, SSH certs, audit receipt plaintext |

## Canonical protocol and split envelopes

All off-chain protocol records use deterministic RFC 8949 CBOR encoding (`fxamacker/cbor/v2`) with explicit domain-separation strings (such as `knock-request-manifest-v1`, `knock-entry-pass-v1`, `knock-admission-status-v1`, and `knock-ssh-connection-v1`). Signatures never cover arbitrary JSON or display strings.

When requesting access:

1. The requester builds a canonical `authorization` record bound to `qorechain-diana`, EVM chain `9800`, `KnockRegistry` address, `DoorID`, policy version and commitment hash, random 256-bit `RequestID`, fresh salt, and 5-minute request deadline.
2. The Door payload seals `authorization` plus the requester's temporary WireGuard public key, SSH public key, and one-time QoreSeal reply recipient key to the Door's verified recipient card.
3. For Approval Doors, the Approver payload seals `authorization`, the SHA-256 hash of the Door ciphertext, and the private reason to all configured approvers via multi-recipient QoreSeal encryption.
4. Both envelopes travel inside outer QoreSeal delivery envelopes carrying the requester's signed manifest so the Mailbox never sees identities, roles, or durations inside the payload.

## Ephemeral connection delivery

After verifying the Entry Pass (or finalized Diana pass purchase), fresh chain keys, and revocation status, `knockd` durably reserves the request once before changing host state:

- Generates a cryptographically random 256-bit WireGuard preshared key (PSK) per session.
- Issues a short-lived OpenSSH user certificate bound to the exact session slot principal and absolute deadline (for SSH Doors).
- Seals the Door's WireGuard endpoint, PSK, assigned `/32` tunnel address, server SSH host key, and user certificate solely to the requester's **one-time ephemeral reply key**, signed by the Door's registered ML-DSA-87 key.

Neither approvers, auditors, nor the requester's static ML-KEM key can decrypt the connection response.

## Linux host enforcement

Authorization is enforced locally by the kernel and OpenSSH without relying on client cooperation:

- **WireGuard:** each session gets a distinct `/32` peer address (`198.19.0.0/28`), peer public key, random PSK, and strict `AllowedIPs`.
- **nftables:** `inet knock_ssh` enforces default-deny and grants timed elements keyed by peer IP, destination port, and remaining lease seconds. No generic `established/related` rule bypasses an expired set entry.
- **OpenSSH and systemd:** each SSH session starts an isolated `systemd-run` unit (`KillMode=control-group`, `RuntimeMaxSec`, `LimitCORE=0`) running `sshd` on `198.19.0.1:<slot-port>`, authenticating only host-CA user certificates and forcing `knockd ssh-role`.
- **Independent recovery:** `knockd` writes minimal non-secret cleanup manifests under `/run/knock-ssh/private/sessions` and spawns an independent timer running `knockd expire-ssh` as backup alongside kernel timeouts.
