---
title: Mailbox service
description: Operate knockd mailbox as a replaceable, untrusted transport queue for sealed envelopes and recipient cards.
---

`knockd mailbox` is a single Go HTTP service backed by one `bbolt` database. It delivers opaque QoreSeal messages between requesters, approvers, Doors, and auditors without holding decryption keys or authorization power.

## Start the Mailbox

```sh
bin/knockd mailbox \
  --listen 127.0.0.1:8180 \
  --origin http://127.0.0.1:8180 \
  --state "$HOME/.config/knock/mailbox/mailbox.db"
```

- `--listen`: loopback HTTP bind address (defaults to `127.0.0.1:8180`).
- `--origin`: public scheme and host bound into challenge-response signatures (defaults to `http://127.0.0.1:8180`).
- `--state`: path to the `bbolt` database inside a `0700` directory; the file itself must remain `0600`.

## Remote deployment behind TLS

By default, `knockd mailbox` listens on loopback. When requesters, approvers, and the Door run on separate machines:

1. Place `knockd mailbox` behind an HTTPS reverse proxy (such as Caddy or Nginx) or forward the loopback port over an operator SSH tunnel.
2. Set `--origin` to the exact HTTPS origin clients pass in `door.json` and `--mailbox` (for example `https://mailbox.example.org`). Authentication challenges fail closed if the signed origin mismatches.

## Bounds and retention

- Stored messages have a bounded lifetime (`15 minutes` max retention) and bounded payload size (`MaxEnvelope`).
- Inbox reads return bounded pages (`16` messages per page, `64` queued messages max per inbox) and require account-bound PQ challenge signatures (`POST /v1/auth/challenge`).
- The Mailbox accepts and serves signed public recipient cards (`GET/PUT /v1/cards/{account}`); clients always verify signatures and Diana key bindings independently rather than trusting the directory.

## What the Mailbox can and cannot do

- **Cannot read payloads:** requests, reasons, Entry Passes, connection responses, host status updates, and audit Receipts are all QoreSeal encrypted before leaving client devices.
- **Cannot approve or issue access:** `knockd` verifies signatures and Diana policy independently; a spoofed Mailbox response fails authentication.
- **Can observe metadata:** as a network relay, the Mailbox sees routing `qor1...` accounts, message sizes, delivery timing, and client IP addresses. It can delay, drop, or duplicate messages, so idempotency checks and request deadlines handle replay and loss safely.
