---
title: Approval Doors
description: Split-envelope human review with exact scope binding and non-root contained SSH roles.
---

An Approval Door grants short-lived, non-root SSH access after one configured approver reviews and signs the exact request.

## Split-envelope requests

When a requester runs `knock <door> --ssh --role <role> --for <duration> --reason -`, Knock creates two separate QoreSeal envelopes bound together by a signed manifest:

1. **Door envelope.** Encrypted to the Door's registered ML-KEM-1024 and X25519 recipient keys. Contains canonical authorization details, the requester's temporary WireGuard public key, temporary SSH public key, and one-time reply recipient key. It never includes `--reason`.
2. **Approver envelope.** Multi-recipient encrypted to the policy's configured approvers (up to 8). Contains the exact same canonical authorization details, the SHA-256 hash of the Door envelope, and the private `--reason`. It contains no server endpoints or connection keys.

Approvers verify both the requester's registered Diana keys and the binding between the envelopes before deciding.

## Exact scope matching

An approver decides on the exact requested Door, role, and duration:

- There is no silent role narrowing or duration editing during approval. If the scope is wrong, run `knock deny <request-id>` and ask the requester to submit a new request.
- Pending requests expire after 5 minutes (`RequestLifetime`) if no decision arrives.
- One valid decision wins; duplicate or conflicting decisions cannot create a second session.

## Supported SSH roles

Approval Doors restrict SSH sessions via a forced command (`knockd ssh-role`) on dedicated non-root slot accounts (`knockssh`, `knockssh1`, ...), with PAM, agent forwarding, TCP forwarding, X11, TTY, and user RC disabled.

| Role          | Permitted commands                | Intended use                                                                                           |
| ------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `logs`        | `status`, `help`, `quit`          | Read host uptime and verify connectivity in a bounded read-only menu.                                  |
| `maintenance` | `status`, `start`, `help`, `quit` | Includes `start`, which launches one harmless diagnostic workload inside the session's systemd cgroup. |

When the session expires or an authorized operator runs `knock revoke`, systemd terminates the entire control group (`KillMode=control-group`), including detached `setsid` background processes started inside `maintenance`.

## Policy rules

In `door.json`, an Approval Door sets:

- `roles`: subset of `["logs", "maintenance"]`
- `approvers`: 1 to 8 `qor1...` addresses, sorted in ascending order of their 20-byte EVM addresses
- `approversCanRevoke`: whether listed approvers (in addition to the Door `owner`) may revoke active sessions on Diana
- `maxDurationSeconds`: maximum allowed SSH lease length
- `offer`: omitted (`null`)
