---
title: Metered Doors
description: Fixed-duration passes for private HTTP services verified directly against QoreChain Diana purchases.
---

A Metered Door sells fixed-duration access to a private HTTP `/status` endpoint without requiring a human approver in the loop.

## How Metered Doors differ

Metered Doors reuse the same identity verification, QoreSeal encryption, WireGuard tunnel provisioning, kernel nftables timeouts, and audit Receipts as Approval Doors. Only the authorization step changes:

- There is no approver envelope and no `--reason` flag.
- Policy configures `roles: []`, `approvers: []`, `approversCanRevoke: false`, and `maxDurationSeconds <= 3600`.
- Policy defines an `offer` object with a unique 32-byte `id`, lowercase `service` name, positive `priceUqor`, and `beneficiary` address.

## Units and pricing

On Diana, `1 test QOR = 1,000,000 uqor` (`10^12` wei per `uqor` on EVM). Configure `priceUqor` in `uqor`; `knockd register` converts it to EVM wei automatically and rejects zero or non-aligned values in `KnockRegistry`.

## Buying and opening a tunnel

```sh
knock private-status --tunnel --pay 2m
```

Knock performs these checks before spending any funds:

1. Resolves `private-status` and verifies the Door Card, policy version, and offer terms against Diana.
2. Checks that `--pay` matches the Door's fixed `maxDurationSeconds`.
3. Displays the exact Door, service, duration, and price in test QOR (`uqor`) and prompts for confirmation. For scripts or non-interactive runs, pass `--price-uqor <amount>` to assert the exact expected price.
4. Sends the signed request manifest to the Door and submits `purchasePass` on `KnockRegistry`, bound to the unique request commitment, buyer, offer, policy version, and redemption deadline.
5. Waits for the Door to verify the finalized purchase, call `consumePass`, open the WireGuard tunnel, and verify `/status`.

## Reconciling interrupted payments

Do not blindly submit a second payment if your terminal closes or a network timeout happens after broadcasting a purchase. Every purchase attempt writes a local payment record before sending the transaction.

Inspect its on-chain and fulfillment state first:

```sh
knock payment show <pass-reference>
```

`payment show` checks Diana for the transaction receipt, whether `KnockRegistry` recorded the purchase, whether the Door consumed it, and any Mailbox status from the Door. If a purchase was finalized on-chain but host provisioning failed, `knock` reports the unfulfilled purchase and transaction reference without silently charging you again.
