---
title: Overview
description: A front door for private Linux servers with scoped, time-bounded SSH and metered service tunnels.
---

Knock is a front door for private Linux servers. Instead of sharing server IP addresses, reusable VPN files, or permanent SSH keys, a requester asks for access by Door name. When an operator approves the request or a customer pays for a fixed pass, the server opens a short-lived WireGuard tunnel and scoped session, then tears everything down when time runs out or the session is revoked.

Every interaction follows one sequence:

**Request by name -> Authorize -> Connect -> Close**

## Who uses Knock

Knock is built for small, independent teams running private Linux infrastructure and the outside engineers or customers who occasionally need access:

- **Server operators** running validators, private RPC nodes, staging machines, or small clusters who want servers quiet and locked down.
- **Outside engineers** brought in for 15 minutes to inspect logs or debug a stalled service without a long onboarding ritual.
- **On-call approvers** who check who is asking and why, grant or deny that exact scope, and revoke live access cleanly if needed.
- **Independent service builders** selling short fixed-time access to a private HTTP or RPC endpoint without user accounts or billing portals.
- **Auditors** reviewing signed session history without receiving live login access to the server.

## Two ways to open a Door

Both Door types use the same local identity verification, QoreSeal encryption, host enforcement, and verified cleanup.

| Door type         | Authorization                                                                          | Protected access                                                                                                                                            |
| ----------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Approval Door** | One authorized approver signs an Entry Pass for the exact requested role and duration. | Scoped, non-root SSH (`logs` or `maintenance`) with per-session WireGuard peer, timed nftables permit, OpenSSH certificate, and systemd cgroup containment. |
| **Metered Door**  | Requester purchases a fixed-duration pass on QoreChain Diana testnet.                  | Direct WireGuard tunnel to a private HTTP `/status` service once the Door verifies the finalized purchase itself.                                           |

## Core design principles

1. **Share a name, not a front-door key.** The Door's public record carries no protected IP address or secret. Connection endpoints and keys are delivered only after authorization, encrypted solely to the requester's one-time reply key.
2. **Keep every role's power separate.** Approvers read why someone wants access without seeing WireGuard or SSH credentials. The Mailbox delivers encrypted envelopes without reading them or approving anything. Auditors read sealed receipts without server access.
3. **End access on the host, then verify it.** A hard, non-extendable deadline lives on the Door host in kernel nftables timeouts and systemd units. Knock prints `Closed` only after checking that the peer, permit, listener, and contained processes are actually gone.
4. **Tell the plain truth about state.** A confirmed chain transaction is not host cleanup, and a pending payment is not an active tunnel. If cleanup fails, Knock reports `Cleanup incomplete` and leaves admissions closed.

## What Knock intentionally leaves out

Knock stays small by leaving these out:

- Always-on team VPNs or permanent employee mesh networks (use WireGuard or Tailscale directly).
- Unrestricted root shells or arbitrary port forwarding.
- Hosted cloud control planes, user accounts, or remote servers holding your keys.
- Portfolio screens, token charts, or automated billing portals.
- Overstated claims about absolute security or invisible infrastructure. Knock documents exact cryptographic boundaries and host limits in the [threat model](/knock/security/threat-model/).
