---
title: Session lifecycle
description: How Knock tracks requests, issued grants, active connections, expirations, and verified teardown.
---

Every Knock session moves through an explicit sequence of observed states. Knock separates chain confirmation, credential issuance, active transport, and verified host cleanup so no interface claims success before evidence exists.

## The four stages

1. **Request.** The requester verifies the Door Card and Diana keys, generates fresh ephemeral WireGuard, SSH (if needed), and one-time reply keys, and sends split QoreSeal envelopes through the Mailbox.
2. **Authorize.** Either an authorized approver signs an Entry Pass for the exact request scope, or the requester finalizes a single-use purchase on `KnockRegistry`.
3. **Connect.** The Door verifies the authorization and fresh Diana state, reserves the request once, installs host enforcement, and sends connection details encrypted solely to the requester's ephemeral reply key. The requester brings up WireGuard and authenticates.
4. **Close.** At the fixed deadline or upon Diana revocation, `knockd` removes network permits, stops the per-session OpenSSH unit, terminates contained processes, verifies postconditions, and seals an audit Receipt.

## Session states

| State                 | Meaning                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| `Requested`           | Valid request delivered; no host resources or credentials exist.                                          |
| `Denied`              | Approver rejected the request; no access was provisioned.                                                 |
| `Request expired`     | Request deadline (5 minutes) passed without a valid authorization.                                        |
| `Authorized`          | Entry Pass or purchase verified; host provisioning has not finished.                                      |
| `Provisioning`        | Door is installing WireGuard, nftables, and OpenSSH resources.                                            |
| `Ready`               | Credentials issued; awaiting client connection within the fixed lifetime.                                 |
| `Active`              | Protected SSH authentication or private service request has been observed on the host.                    |
| `Closing`             | Expiry or revocation has triggered host teardown.                                                         |
| `Closed`              | Required teardown checks (peer, permit, listener, and cgroup) passed.                                     |
| `Cleanup incomplete`  | One or more teardown checks failed or could not be verified; admissions stay guarded and cleanup retries. |
| `Provisioning failed` | Host preparation failed; any partial resources are reconciled without opening access.                     |

:::caution
A confirmed revocation transaction on Diana is not proof that the server closed the connection. Wait until `knock sessions show` or the console reports `Closed` (`Revocation enforced`).
:::

## Non-extendable deadlines

Once the Door issues a grant, it records one absolute UTC deadline based on the approved duration (capped by policy `maxDurationSeconds`) and tracks elapsed lifetime monotonically on the host:

- Reconnecting after a network drop never resets or extends the deadline.
- Delay between issuing credentials and opening the SSH connection consumes the issued lifetime.
- Wall-clock jumps cannot extend access.
- If `knockd` restarts or crashes, startup reconciliation denies all Knock permits and closes outstanding grants conservatively instead of restoring them.

## Stale observations and outages

When reading session status (`knock sessions show` or the **Sessions** console view), Knock checks the timestamp and Door signature of the latest `SessionStatus` message:

- If Diana monitoring fails or observations are older than 20 seconds, Knock marks the state `Unknown` (or `Stale` in the console) rather than pretending an expired timer is closed.
- Existing active grants still expire locally on the Door host via kernel nftables element timeouts and systemd `RuntimeMaxSec`, even if both Diana RPC and the Mailbox are unreachable.
- New admissions fail closed whenever chain identity, policy, or revocation state is stale or unreachable.
