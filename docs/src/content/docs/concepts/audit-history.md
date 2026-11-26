---
title: Audit history
description: Signed session receipts sealed with QoreSeal group epochs, membership rotation, and offline export.
---

When `"audit": true` is enabled in `door.json`, `knockd` signs a compact Receipt after each session closes and encrypts it to the current authorized audit group using QoreSeal.

## What a Receipt records

A Receipt captures what the Door attested and observed:

- Request and session references
- Requester account, authorization mode (`Approval` or `Metered`), and policy version
- Permitted role or service, requested duration, and actual start/close timestamps
- Termination cause (`Expired`, `Revoked`, or `Door restarted`) and verified cleanup postconditions
- Relevant Diana transaction references for metered passes or revocations

Receipts deliberately omit private request reasons, WireGuard PSKs, SSH private keys, raw terminal output, and host IP endpoints. If cleanup initially failed and succeeded on a later retry, `knockd` seals a linked follow-up Receipt without altering the original signed record.

## Publish auditor keys and set epoch 1

Each auditor must register on Diana and publish their recipient card to the Door's Mailbox before being added:

```sh
knock --profile auditor.age --mailbox http://127.0.0.1:8180 identity publish
```

The Door owner starts or rotates membership from epoch `0` (or the current epoch) to a new member list:

```sh
knock --profile owner.age --network network.json --cards cards \
  audit rotate --door validator-ops --epoch 0 --member qor1auditor1...,qor1auditor2...
```

To pause new audit receipts without leaving stale members active, pass `--clear` instead of `--member`.

## Read verified Receipts

Authorized auditors can inspect receipts from the Mailbox via CLI or the console **History** view:

```sh
knock --profile auditor.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 history list --door validator-ops
knock --profile auditor.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 history show --door validator-ops "$receipt_id"
```

## Export from a stopped Door

Mailbox queues have bounded retention. Because `knockd` retains the sealed receipt archive locally, an administrator can export an encrypted receipt directly from a stopped Door and inspect it offline:

```sh
sudo knockd --config /etc/knock/door.json audit-export "$receipt_id" \
  --recipient qor1auditor1... > receipt.sealed
knock --profile auditor.age --network network.json --cards cards \
  history show --door validator-ops --from receipt.sealed "$receipt_id"
```

## Backup and rotation boundaries

- Always back up the Door's state database (`admission.db`) alongside its `.audit.age` key file (`admission.db.audit.age`).
- Rotating to a new epoch prevents removed members from decrypting future receipts.
- Encryption cannot erase old epoch keys or plaintext receipts that a former member already retrieved prior to rotation.
