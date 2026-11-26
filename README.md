# Knock

Knock grants temporary, identity-bound access to private Linux infrastructure without exposing service endpoints before authorization. Requesters identify a resource by its verified QoreChain Diana account or trusted local alias, follow **request by name → authorize → connect → close**, and connect only after the host independently validates the decision and issues a short-lived tunnel and credential.

Two authorization policies share one host enforcement and audit lifecycle:

- **Approval Door:** grants scoped, non-root SSH (`logs` or `maintenance`) with per-session WireGuard peers, timed nftables permits, OpenSSH certificates, and systemd cgroup process containment.
- **Metered Door:** grants fixed-duration access to a private HTTP status service after verifying a finalized single-use test QOR purchase on Diana.

## How Knock uses QoreChain

| Integration | Role in Knock | Implementation |
| --- | --- | --- |
| QoreSeal (`github.com/qorechain/qoreseal/go`) | Client-side hybrid ML-KEM-1024 + X25519 recipient encryption for split request/approver envelopes, one-time ephemeral reply key for the 256-bit WireGuard PSK, and epoch-rotated encrypted audit receipts | [crypto.go](internal/admission/crypto.go), [request.go](internal/admission/request.go), [audit_epoch.go](internal/admission/audit_epoch.go) |
| QoreSign (`github.com/qorechain/qoresign/go`) & `qorechain-pqc` | Registered hybrid ML-DSA-87 + secp256k1 account bindings, signed Door Cards, canonical CBOR request manifests, Entry Passes, signed host status, and scoped EVM authorization windows | [native.go](internal/chain/native.go), [evm.go](internal/chain/evm.go), [protocol.go](internal/protocol/protocol.go) |
| `KnockRegistry` (Diana EVM chain `9800`) | On-chain Door policy commitments, single-use metered passes, and session revocations verified via `pqcKeyStatus` (`0x...a02`) and `pqcVerify` (`0x...a01`) precompiles | [KnockRegistry.sol](contracts/src/KnockRegistry.sol), [registry.go](internal/chain/registry.go) |

## Diana testnet verification

Both Approval and Metered Doors are verified on QoreChain Diana with `KnockRegistry` deployed at `0xd80502c7dfe2a29a087118b81549b9cb267f3b0d`.

- [Contract deployment](https://explore.qore.network/tx/0xa015ceec6fbcc969d9117df573fb852fe5686a49772009003619b95ecd31757b)
- [SSH session revocation](https://explore.qore.network/tx/0xf8cdcd6e6a1f3eba3a2ec93fb55b2f1c7190ef003f2f0838f9a2b0458e781336)
- [Metered pass purchase](https://explore.qore.network/tx/0xa49e42248906a06288346cd6f9cea97ef60356941f2f8dff4682c0e7b398942f)
- [Metered pass consumption](https://explore.qore.network/tx/0xce70c936ddc0863fd51522b102b014a81f41a52a55f5d43c5d7c9108ef8d973f)

## Build and check

Use Go 1.26.6, Node.js 24, pnpm, Foundry (`be350a64be9178a71a6ff029a72dc4455dcffcb1`), Make, and Python 3. The registry targets Solidity `0.8.28`.

```sh
pnpm --dir web/console install --frozen-lockfile
make build
pnpm --dir web/console exec playwright install chromium
make check
```

`make check` builds `bin/knock` and `bin/knockd` with the embedded console, runs Prettier, Vitest, and Playwright accessibility/E2E tests, runs `go vet` and `go test`, checks Solidity formatting and Foundry unit/fuzz tests, and verifies `KnockRegistry` ABI parity.

## Register and inspect a Door

1. Create separate owner, Door, approver, and requester profiles with `bin/knock --profile /path/to/identity.age identity init`. Keep each encrypted profile in a directory with permissions `0700`.
2. Fund the printed addresses with test QOR from the [Diana faucet](https://dashboard.qorechain.io/faucet), then run `bin/knock --profile /path/to/identity.age identity register` for each actor. Registration writes a public recipient card to stdout.
3. Build and deploy `KnockRegistry`, saving the pinned registry address and code hash:

```sh
forge build --root contracts
go run ./contracts/cmd/deploy --profile /path/to/owner.age > network.json
```

4. Copy [the approval Door example](deploy/door.example.json) to `door.json`. Set the pinned registry, actor addresses and profiles, and a unique 32-byte Door ID (`0x$(openssl rand -hex 32)`). Sort multiple approvers by their EVM address bytes.
5. Run `bin/knockd register --config door.json` to commit policy version 1 and publish the signed Card. Increment the policy version to update policy, or re-run with the same policy to refresh a Card before its 24-hour expiry.

Give the requester the public Card and `network.json`, and verify the Door account over a trusted channel:

```sh
bin/knock --network network.json --cards cards door trust qor1... --alias validator-ops
bin/knock --network network.json --cards cards door show validator-ops
```

## Request and review access

Start the opaque Mailbox on a loopback address:

```sh
bin/knockd mailbox --state "$HOME/.config/knock/mailbox/mailbox.db"
```

Set `mailbox` and `state` in `door.json` and republish the Door Card with `bin/knockd register --config door.json`. Give the updated Card and `network.json` to the requester and approver. For separate VMs, forward the loopback port over management SSH or front the Mailbox with an HTTPS reverse proxy (`--origin https://...`).

Publish the approver's registered recipient card once, then submit a request and review it from separate terminals:

```sh
bin/knock --profile approver.age --mailbox http://127.0.0.1:8180 identity publish

bin/knock --profile requester.age --network network.json --cards cards \
  validator-ops --ssh --role logs --for 5m --reason -

bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests list
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests show "$request_id"
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 approve "$request_id"
```

Use `deny` to decline. Enter reasons with `--reason -` so plaintext intent stays out of shell history. After approval, `knock` establishes the temporary WireGuard tunnel, connects with the host-issued SSH certificate, and prints the UTC deadline. The `logs` role supports `status`, `help`, and `quit`; `maintenance` adds `start` to launch one cgroup-contained diagnostic workload. The Door ends access and stops contained workloads at expiry even if the requester or Mailbox disconnects.

## Use the operator console

Launch the local-only console with your operator profile, registry pin, and Door Cards:

```sh
bin/knock --profile approver.age --network network.json --cards cards console
```

Unlock the profile in the terminal and open the one-time loopback link printed to stdout. Review decrypted requests under **Doors**, track signed host observations and revocations under **Sessions**, and inspect locally decrypted receipts or request audit membership rotation under **History**. Press `Ctrl+C` in the terminal to close the console.

## Buy a service pass

Configure a second Door using [the metered Door example](deploy/door.metered.example.json) with its own profile, state, and Ubuntu VM. Leave `roles` and `approvers` empty, set `approversCanRevoke` to `false`, set `maxDurationSeconds` to the fixed pass duration (up to 3600 seconds), and configure `offer` with a unique 32-byte hex `id`, lowercase `service` name, positive integer `priceUqor` (`1 test QOR = 1,000,000 uqor`), and `beneficiary` account.

Verify the Door Card first with `door trust`, then inspect and purchase the pass:

```sh
bin/knock --network network.json --cards cards door show private-status
bin/knock --network network.json --cards cards private-status --tunnel --pay 2m
bin/knock payment show "$pass_reference"
```

Knock displays the exact Diana testnet price before prompting (pass `--price-uqor` for non-interactive verification). After confirming the pass and verifying a response from the protected `/status` endpoint, it prints the private URL and holds the tunnel open until expiry or disconnect. Use `payment show` with the pass reference to reconcile interrupted purchases before paying again.

## Check or revoke a session

Publish the owner's recipient card before granting access if the owner will inspect session status. Both the Door owner and eligible approvers (when `approversCanRevoke` is enabled) can revoke on Diana:

```sh
bin/knock --network network.json --cards cards --mailbox http://127.0.0.1:8180 sessions list --door validator-ops
bin/knock --network network.json --cards cards revoke --door validator-ops "$session_id"
bin/knock --network network.json --cards cards --mailbox http://127.0.0.1:8180 sessions show --door validator-ops "$session_id"
```

The Door polls Diana directly even if the Mailbox goes offline. Wait for the Door's signed closure status (`Closed` / `Revocation enforced`) to verify host enforcement; a confirmed registry transaction alone is not proof of host cleanup.

## Read audit history

Set `"audit": true` in the Door configuration and publish each auditor's recipient card to the Door's Mailbox. Back up the Door's state database and its adjacent `.audit.age` file together.

Rotate membership as the Door owner (starting from `--epoch 0`):

```sh
bin/knock --profile owner.age --network network.json --cards cards audit rotate --door validator-ops --epoch 0 --member qor1...,qor1...
bin/knock --profile auditor.age --network network.json --cards cards --mailbox http://127.0.0.1:8180 history list --door validator-ops
bin/knock --profile auditor.age --network network.json --cards cards --mailbox http://127.0.0.1:8180 history show --door validator-ops "$receipt_id"
```

Rotate from the current epoch with an updated `--member` list to remove an auditor, or pass `--clear` to remove all auditors and pause receipt issuance. If Mailbox delivery expires, export the encrypted receipt from a stopped Door and verify it locally:

```sh
sudo knockd --config /etc/knock/door.json audit-export "$receipt_id" --recipient "$auditor" > receipt.sealed
bin/knock --profile auditor.age --network network.json --cards cards history show --door validator-ops --from receipt.sealed "$receipt_id"
```

## Run a Door

Use a dedicated, always-on Ubuntu 24.04 x86-64 host (2 GiB RAM, cgroup v2, WireGuard, nftables, time sync enabled, suspend disabled) with management SSH on a separate interface. Knock reserves the `knockdoor` interface, the `knock_ssh` nftables table, `198.19.0.0/28`, and TCP ports `2222`–`2229` on `198.19.0.1`.

Set `wireGuardEndpoint` in `/etc/knock/door.json` to the reachable numeric address and UDP port (such as `198.18.0.1:48001` in the lab) and allow only that UDP port externally. For an Approval Door, install OpenSSH and create non-root session slot accounts (`knockssh`, `knockssh1`, up to `knockssh7`):

```sh
sudo install -m 0755 bin/knockd /usr/local/bin/knockd
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh1
sudo install -d -m 0755 /run/sshd /etc/systemd/system/knockd.service.d
systemd-ask-password 'Door passphrase' |
  sudo systemd-creds encrypt --name=door-passphrase --with-key=host - /etc/knock/door.cred
sudo install -m 0644 deploy/systemd/knockd.service /etc/systemd/system/knockd.service
sudo install -m 0644 deploy/systemd/10-ssh.conf /etc/systemd/system/knockd.service.d/10-ssh.conf
sudo systemctl daemon-reload
sudo systemctl start knockd
```

On the requester Linux VM, install `bin/knock` at `/usr/local/bin/knock`, install WireGuard tools and OpenSSH, and configure [the tunnel sudoers rule](deploy/knock-tunnel.sudoers) with `sudo visudo -f /etc/sudoers.d/knock-tunnel` for the requester's non-root group. Once installed globally, run `knock` and `knockd` directly. To manually clean up outstanding sessions on a stopped Door, run `sudo knockd reconcile --config /etc/knock/door.json`.

## Check the Linux lab

On a host with KVM, QEMU, xorriso, OpenSSH, and Python 3, download the pinned Ubuntu 24.04 amd64 cloud image dated `2026-10-17` ([Ubuntu cloud images](https://cloud-images.ubuntu.com/noble/20261017/)), verify its signed manifest, and run the lab probe:

```sh
deploy/lab/start.sh noble-server-cloudimg-amd64.img /tmp/knock-lab
deploy/lab/probe.sh /tmp/knock-lab
deploy/lab/stop.sh /tmp/knock-lab
```

`probe.sh` creates the `door`, `requester`, `outsider`, and `requester2` guests and independently verifies pre-admission service isolation, certificate principal enforcement, kernel nftables timeout expiry independent of `sshd`, and cgroup descendant termination.

## Security model and known limits

- **Recipient isolation:** Approvers decrypt request intent without receiving WireGuard/SSH keys or connection endpoints; the Door verifies semantic agreement without seeing the private approval reason; connection responses and PSKs are sealed solely to the requester's one-time ephemeral key.
- **Fail-closed enforcement:** Stale chain state, mismatched keys/policies, replay attempts, and incomplete teardown fail closed; active sessions still expire locally via kernel nftables timeouts and systemd `RuntimeMaxSec`.
- **Metadata visibility:** The Mailbox sees routing accounts, message sizes, timing, and expiry; Diana reveals registered policies, metered purchases, and session revocations; direct WireGuard traffic reveals peer endpoints to network observers.
- **Cryptography and trust limits:** `qoreseal` v0.1.0 is a draft package pending external audit; chain checks rely on trusted Diana TLS RPC endpoints rather than a verifying light client; `knockd` runs as root on a dedicated Door host; Go/tmpfs secret wiping is best-effort; removed audit members retain historical receipts and epoch keys already delivered to them.

## Dependencies and credits

Licensed under [Apache-2.0](LICENSE). Built with:

- [QoreChain](https://github.com/qorechain) (`qoreseal`, `qoresign`, `qorechain-pqc`) for post-quantum hybrid recipient encryption and signing
- [go-ethereum](https://github.com/ethereum/go-ethereum), [Foundry](https://getfoundry.sh/), [age](https://filippo.io/age), [bbolt](https://go.etcd.io/bbolt), [fxamacker/cbor](https://github.com/fxamacker/cbor), and [Cobra](https://github.com/spf13/cobra)
- Linux WireGuard, OpenSSH, nftables, and systemd
- [React](https://react.dev/), [React Router](https://reactrouter.com/), [Tailwind CSS](https://tailwindcss.com/), [Vite](https://vitejs.dev/), [Phosphor Icons](https://phosphoricons.com/), [Playwright](https://playwright.dev/), and [axe-core](https://github.com/dequelabs/axe-core) (bundled third-party license text is served by the console at `/assets/licenses.txt`)
