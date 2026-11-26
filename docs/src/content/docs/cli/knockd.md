---
title: knockd daemon
description: Subcommands, configuration schema, and runtime flags for the Door daemon and Mailbox relay.
---

`knockd` runs on the Door host (and optionally operates the Mailbox relay). It validates Diana state, decrypts incoming Door requests, manages WireGuard peers and nftables timed permits, spawns per-session OpenSSH units, enforces deadlines, and seals signed audit Receipts.

## Subcommands

```sh
knockd register --config <door.json>
knockd serve --config <door.json>
knockd mailbox --state <mailbox.db> [--listen 127.0.0.1:8180] [--origin http://127.0.0.1:8180]
knockd reconcile --config <door.json>
knockd audit-export --config <door.json> <receipt-id> --recipient <qor1...>
```

| Subcommand     | Purpose                                                                                                                                                                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `register`     | Unlocks `ownerProfile` and `doorProfile` interactively, commits the policy (and optional metered offer) to `KnockRegistry` on Diana, and writes the signed `.card` file into `cards/`.                                                                      |
| `serve`        | Acquires the exclusive host Door lock, reconciles any leftover session state conservatively, unlocks `doorProfile` via `CREDENTIALS_DIRECTORY/door-passphrase` (systemd encrypted credential), verifies Diana keys, and processes requests and revocations. |
| `mailbox`      | Starts the opaque encrypted message relay using a single `0600` bbolt state file inside a `0700` directory. `--origin` binds challenge-response authentication to the public URL clients reach.                                                             |
| `reconcile`    | Closes outstanding Knock sessions and cleans up residual peers, permits, and SSH listeners on a stopped Door.                                                                                                                                               |
| `audit-export` | Exports a locally retained encrypted Receipt from a stopped Door, re-sealed for an auditor already belonging to that Receipt's epoch.                                                                                                                       |

## Door configuration schemas

`door.json` binds local host files to the canonical policy committed on Diana.

### Approval Door (`deploy/door.example.json`)

```json
{
  "registry": {
    "address": "0xd80502c7dfe2a29a087118b81549b9cb267f3b0d",
    "codeHash": "0x..."
  },
  "doorId": "0x...",
  "owner": "qor1...",
  "account": "qor1...",
  "ownerProfile": "owner.age",
  "doorProfile": "door.age",
  "cards": "cards",
  "mailbox": "http://127.0.0.1:8180",
  "wireGuardEndpoint": "198.18.0.1:48001",
  "audit": false,
  "state": "/var/lib/knock/admission.db",
  "policy": {
    "version": 1,
    "enabled": true,
    "maxDurationSeconds": 900,
    "approversCanRevoke": true,
    "approvers": ["qor1..."],
    "roles": ["logs", "maintenance"]
  }
}
```

### Metered Door (`deploy/door.metered.example.json`)

```json
{
  "registry": {
    "address": "0xd80502c7dfe2a29a087118b81549b9cb267f3b0d",
    "codeHash": "0x..."
  },
  "doorId": "0x...",
  "owner": "qor1...",
  "account": "qor1...",
  "ownerProfile": "owner.age",
  "doorProfile": "door.age",
  "cards": "cards",
  "mailbox": "http://127.0.0.1:8180",
  "wireGuardEndpoint": "198.18.0.1:48001",
  "audit": false,
  "state": "/var/lib/knock/admission.db",
  "policy": {
    "version": 1,
    "enabled": true,
    "maxDurationSeconds": 120,
    "approversCanRevoke": false,
    "approvers": [],
    "roles": [],
    "offer": {
      "id": "0x...",
      "service": "private-status",
      "priceUqor": 10000,
      "beneficiary": "qor1..."
    }
  }
}
```

## Policy constraints enforced on registration

- `approvers`: up to 8 `qor1...` addresses, sorted in ascending order of their 20-byte EVM address equivalents. Must be empty when `offer` is set.
- `approversCanRevoke`: must be `false` when `approvers` is empty.
- `offer.duration` (`maxDurationSeconds` for metered Doors): `1` to `3600` seconds.
- `offer.priceUqor`: positive integer in `uqor` (`1 test QOR = 1,000,000 uqor`).
- `owner` and `account` (Door) must be distinct funded accounts; keep `owner.age` off the Door host once `knockd register` completes.
