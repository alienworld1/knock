---
title: Quickstart
description: Initialize Diana identities, register a Door, approve an SSH request, purchase a metered pass, and read encrypted audit receipts.
---

This guide walks through a working setup on QoreChain Diana testnet using `bin/knock` and `bin/knockd`.

## 1. Initialize and fund identities

Create encrypted identity profiles in `0700` directories for each actor: owner, Door, approver, and requester (plus an optional auditor).

```sh
bin/knock --profile owner.age identity init
bin/knock --profile door.age identity init
bin/knock --profile approver.age identity init
bin/knock --profile requester.age identity init
```

Each command prints a `qor1...` address. Fund each address with test QOR from the [Diana faucet](https://dashboard.qorechain.io/faucet), then register its ML-DSA-87 signing key and ML-KEM-1024 recipient key on Diana:

```sh
bin/knock --profile owner.age identity register
bin/knock --profile door.age identity register
bin/knock --profile approver.age identity register
bin/knock --profile requester.age identity register
```

## 2. Deploy KnockRegistry

Compile the contract and deploy it with the owner profile, saving the pinned registry address and bytecode hash to `network.json`:

```sh
forge build --root contracts
go run ./contracts/cmd/deploy --profile owner.age > network.json
```

## 3. Configure and register an Approval Door

Copy `deploy/door.example.json` to `door.json`. Fill in:

- `registry` from `network.json`
- A random 32-byte `doorId` (`0x$(openssl rand -hex 32)`)
- `owner`, `account` (Door address), `ownerProfile`, and `doorProfile`
- `approvers` sorted in ascending order of EVM address bytes
- `wireGuardEndpoint` reachable from the requester
- `mailbox` origin and `state` path (on a `0700` directory)

Commit policy version 1 on Diana and publish the signed Door Card:

```sh
bin/knockd register --config door.json
```

Door Cards expire after 24 hours. Copy `network.json` and the generated `cards/` directory to the requester and approver machines, then have the requester verify and save the Door account as a local alias:

```sh
bin/knock --network network.json --cards cards door trust qor1door... --alias validator-ops
bin/knock --network network.json --cards cards door show validator-ops
```

## 4. Start the Mailbox and Door

Start the opaque Mailbox relay on loopback (for separate machines, tunnel via SSH or place behind an HTTPS reverse proxy matching `--origin`):

```sh
bin/knockd mailbox --state "$HOME/.config/knock/mailbox/mailbox.db"
```

On the Door host (see [Host setup](/knock/operations/host-setup/) for systemd unit installation and `knockssh` slot creation), start `knockd serve`. Have the approver publish their recipient card to the Mailbox:

```sh
bin/knock --profile approver.age --mailbox http://127.0.0.1:8180 identity publish
```

## 5. Request, approve, and revoke SSH access

The requester submits an encrypted request (`--reason -` prompts privately so the reason stays out of shell history):

```sh
bin/knock --profile requester.age --network network.json --cards cards \
  validator-ops --ssh --role logs --for 5m --reason -
```

In a separate terminal, the approver lists verified requests, inspects the intent, and grants or denies the exact scope:

```sh
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests list
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests show "$request_id"
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 approve "$request_id"
```

Once the Door verifies the Entry Pass, it provisions the WireGuard peer, timed nftables permit, OpenSSH certificate, and systemd unit, then seals connection details to the requester's ephemeral reply key. The requester connects straight into the `logs` menu (`status`, `help`, `quit`).

To end an active session early, publish a revocation on Diana and wait for confirmed host cleanup:

```sh
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 sessions list --door validator-ops
bin/knock --profile approver.age --network network.json --cards cards \
  revoke --door validator-ops "$session_id"
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 sessions show --door validator-ops "$session_id"
```

## 6. Run the local operator console

Approvers, owners, and auditors can also review requests, active sessions, and decrypted receipts in a local browser:

```sh
bin/knock --profile approver.age --network network.json --cards cards console
```

Unlock the profile in the terminal and open the printed one-time loopback URL. Press `Ctrl+C` in the terminal to stop the console.

## 7. Try a Metered Door

Configure a second Door from `deploy/door.metered.example.json` (`roles: []`, `approvers: []`, `approversCanRevoke: false`, `maxDurationSeconds <= 3600`, and an `offer` with unique 32-byte `id`, lowercase `service`, positive `priceUqor` where `1 test QOR = 1,000,000 uqor`, and `beneficiary`).

Trust the metered Door, request a paid pass, and reconcile interrupted purchases if needed:

```sh
bin/knock --network network.json --cards cards door trust qor1metered... --alias private-status
bin/knock --profile requester.age --network network.json --cards cards \
  private-status --tunnel --pay 2m
bin/knock --profile requester.age payment show "$pass_reference"
```
