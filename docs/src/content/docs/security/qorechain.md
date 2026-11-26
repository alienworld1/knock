---
title: QoreChain integration
description: How Knock uses QoreSeal, QoreSign, native registries, and KnockRegistry on QoreChain Diana testnet.
---

QoreChain Diana (`qorechain-diana`, EVM chain ID `9800`) supplies Knock's identity bindings, post-quantum encryption and signatures, policy commitments, metered pass purchases, and authoritative session revocations.

## Libraries and chain endpoints

| Integration                                          | Role in Knock                                                                                                                                                                                                           |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/qorechain/qoreseal/go`                   | Hybrid ML-KEM-1024 + X25519 registered-recipient encryption for Door/Approver envelopes, one-time direct-recipient response sealing, and group-epoch audit Receipts.                                                    |
| `github.com/qorechain/qoresign/go` & `qorechain-pqc` | Registered hybrid ML-DSA-87 + secp256k1 account bindings, native hybrid transactions, signed Door Cards, manifests, Entry Passes, and host status messages.                                                             |
| Diana REST / RPC / EVM endpoints                     | `https://api-testnet.qore.host`, `https://rpc-testnet.qore.host`, and `https://evm-testnet.qore.host`. `knockd` verifies chain ID, block freshness (`<= 30s`), and pinned registry bytecode hash before trusting reads. |

## KnockRegistry (`contracts/src/KnockRegistry.sol`)

`KnockRegistry` is an immutable Solidity `0.8.28` contract deployed on Diana EVM (`9800`). Every security-sensitive mutation (`register`, `updatePolicy`, `revoke`, `setOffer`, `purchasePass`, `consumePass`) verifies a domain-separated (`knock-registry-v1`) ML-DSA-87 signature directly on-chain using QoreChain's native precompiles:

- `pqcKeyStatus` at `0x0000000000000000000000000000000000000a02`: verifies that the signer has a registered, possession-proven ML-DSA-87 public key (`2592` bytes, `algorithmId == 1`).
- `pqcVerify` at `0x0000000000000000000000000000000000000a01`: verifies the `4627`-byte ML-DSA-87 signature over the ABI-encoded action, chain ID, contract address, signer, `doorId`, action details, per-signer nonce, and deadline.

Classical ECDSA `msg.sender` alone cannot register a Door, update policy, revoke a session, set an offer, purchase a pass, or consume a pass.

| Method         | Who signs                  | Purpose                                                                                                                                                       |
| -------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `register`     | Owner + Door account       | Binds `doorId`, owner, Door account, and policy v1 commitment.                                                                                                |
| `updatePolicy` | Owner                      | Advances policy version monotonically and updates commitment and approvers.                                                                                   |
| `revoke`       | Owner or eligible approver | Permanently marks `(doorId, sessionRef)` revoked.                                                                                                             |
| `setOffer`     | Owner (metered Door)       | Publishes fixed duration (`<= 3600s`), price in wei (`% 1e12 == 0`), and beneficiary.                                                                         |
| `purchasePass` | Buyer (`payable`)          | Escrows exact `msg.value`, records non-transferable purchase bound to request commitment, and transfers funds to beneficiary via checks-effects-interactions. |
| `consumePass`  | Door account               | Atomically marks purchase `sessionRef` before connection issuance so a purchase can never be redeemed twice.                                                  |

## Verified Diana testnet deployment

Both Approval and Metered Doors are verified against `KnockRegistry` on QoreChain Diana at `0xd80502c7dfe2a29a087118b81549b9cb267f3b0d`. Select **Testnet** in the QoreChain Dashboard to inspect these transactions:

- [Contract deployment](https://dashboard.qorechain.io/explorer/tx/0xa015ceec6fbcc969d9117df573fb852fe5686a49772009003619b95ecd31757b)
- [SSH session revocation](https://dashboard.qorechain.io/explorer/tx/0xf8cdcd6e6a1f3eba3a2ec93fb55b2f1c7190ef003f2f0838f9a2b0458e781336)
- [Metered pass purchase](https://dashboard.qorechain.io/explorer/tx/0xa49e42248906a06288346cd6f9cea97ef60356941f2f8dff4682c0e7b398942f)
- [Metered pass consumption](https://dashboard.qorechain.io/explorer/tx/0xce70c936ddc0863fd51522b102b014a81f41a52a55f5d43c5d7c9108ef8d973f)
