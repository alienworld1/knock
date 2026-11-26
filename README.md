# Knock

Knock is a front door for private Linux servers. Requesters ask for access by Door name (**request by name → authorize → connect → close**), and the server opens a short-lived WireGuard tunnel and scoped session only after independently verifying the decision on QoreChain Diana.

- **Approval Door:** grants scoped, non-root SSH (`logs` or `maintenance`) with per-session WireGuard peers, timed nftables permits, OpenSSH certificates, and systemd cgroup process containment.
- **Metered Door:** grants fixed-duration access to a private HTTP `/status` service after verifying a finalized single-use test QOR purchase on Diana.

```sh
knock validator-ops --ssh --role logs --for 15m --reason -
knock private-status --tunnel --pay 2m
knock console
```

## How Knock uses QoreChain

| Integration | Role in Knock | Implementation |
| --- | --- | --- |
| QoreSeal (`github.com/qorechain/qoreseal/go`) | Client-side hybrid ML-KEM-1024 + X25519 recipient encryption for split request/approver envelopes, one-time ephemeral reply key for the 256-bit WireGuard PSK, and epoch-rotated audit receipts | [crypto.go](internal/admission/crypto.go), [request.go](internal/admission/request.go), [audit_epoch.go](internal/admission/audit_epoch.go) |
| QoreSign (`github.com/qorechain/qoresign/go`) & `qorechain-pqc` | Registered hybrid ML-DSA-87 + secp256k1 account bindings, signed Door Cards, canonical CBOR request manifests, Entry Passes, signed host status, and scoped EVM authorization windows | [native.go](internal/chain/native.go), [evm.go](internal/chain/evm.go), [protocol.go](internal/protocol/protocol.go) |
| `KnockRegistry` (Diana EVM chain `9800`) | On-chain Door policy commitments, single-use metered passes, and session revocations verified via `pqcKeyStatus` (`0x...a02`) and `pqcVerify` (`0x...a01`) precompiles | [KnockRegistry.sol](contracts/src/KnockRegistry.sol), [registry.go](internal/chain/registry.go) |

## Diana testnet verification

Both Approval and Metered Doors are verified on QoreChain Diana with `KnockRegistry` deployed at `0xd80502c7dfe2a29a087118b81549b9cb267f3b0d`.

Select **Testnet** in the QoreChain Dashboard to view these transactions.

- [Contract deployment](https://dashboard.qorechain.io/explorer/tx/0xa015ceec6fbcc969d9117df573fb852fe5686a49772009003619b95ecd31757b)
- [SSH session revocation](https://dashboard.qorechain.io/explorer/tx/0xf8cdcd6e6a1f3eba3a2ec93fb55b2f1c7190ef003f2f0838f9a2b0458e781336)
- [Metered pass purchase](https://dashboard.qorechain.io/explorer/tx/0xa49e42248906a06288346cd6f9cea97ef60356941f2f8dff4682c0e7b398942f)
- [Metered pass consumption](https://dashboard.qorechain.io/explorer/tx/0xce70c936ddc0863fd51522b102b014a81f41a52a55f5d43c5d7c9108ef8d973f)

## Build and check

Requires Go `1.26.6`, Node.js `24`, `pnpm`, Foundry (`be350a64be9178a71a6ff029a72dc4455dcffcb1`), Make, and Python 3 (`KnockRegistry` targets Solidity `0.8.28`).

```sh
pnpm --dir web/console install --frozen-lockfile
make build
pnpm --dir web/console exec playwright install chromium
make check
```

`make check` builds `bin/knock` and `bin/knockd` with the embedded console, runs Prettier, Vitest, and Playwright WCAG AA accessibility/E2E tests, runs `go vet` and `go test`, checks Solidity formatting and Foundry unit/fuzz tests, and verifies `KnockRegistry` ABI parity.

## Quickstart

### 1. Identities and Door registration

1. Initialize encrypted profiles in `0700` directories for owner, Door, approver, and requester: `bin/knock --profile /path/to/identity.age identity init`.
2. Fund each address with test QOR from the [Diana faucet](https://dashboard.qorechain.io/faucet), then register keys with `bin/knock --profile /path/to/identity.age identity register`.
3. Build and deploy `KnockRegistry`, saving the pinned address and code hash:

```sh
forge build --root contracts
go run ./contracts/cmd/deploy --profile /path/to/owner.age > network.json
```

4. Copy [the approval Door example](deploy/door.example.json) to `door.json`. Set the pinned registry, actor addresses and profiles, a unique 32-byte `doorId` (`0x$(openssl rand -hex 32)`), and `approvers` sorted by EVM address bytes.
5. Run `bin/knockd register --config door.json` to commit policy v1 and publish the signed Door Card (Cards expire after 24 hours). Give the requester the Card and `network.json`, and trust the Door account over a verified channel:

```sh
bin/knock --network network.json --cards cards door trust qor1... --alias validator-ops
bin/knock --network network.json --cards cards door show validator-ops
```

### 2. Request, approve, and revoke

Start the opaque Mailbox on loopback (for separate hosts, tunnel via SSH or front with an HTTPS reverse proxy matching `--origin`), set `mailbox` and `state` in `door.json`, and republish the Door Card:

```sh
bin/knockd mailbox --state "$HOME/.config/knock/mailbox/mailbox.db"
```

With the Door running (see [Host setup](#host-setup)), publish the approver's recipient card, request access (`--reason -` avoids shell history), and approve or deny:

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

Use `deny` to decline. `logs` allows `status`, `help`, and `quit`; `maintenance` adds `start` to launch one cgroup-contained workload. Check signed host status or revoke on Diana (wait for `Closed` / `Revocation enforced`—a confirmed transaction alone is not proof of cleanup):

```sh
bin/knock --network network.json --cards cards --mailbox http://127.0.0.1:8180 sessions list --door validator-ops
bin/knock --network network.json --cards cards revoke --door validator-ops "$session_id"
bin/knock --network network.json --cards cards --mailbox http://127.0.0.1:8180 sessions show --door validator-ops "$session_id"
```

### 3. Operator console

```sh
bin/knock --profile approver.age --network network.json --cards cards console
```

Unlock in the terminal and open the private one-time loopback link (`Ctrl+C` closes the console). Review incoming requests under **Doors**, inspect active deadlines and revocations under **Sessions**, and read locally decrypted receipts or request audit membership rotation under **History**.

### 4. Metered service pass

Configure a second Door from [the metered Door example](deploy/door.metered.example.json) (`roles: []`, `approvers: []`, `approversCanRevoke: false`, `maxDurationSeconds <= 3600`, and `offer` with unique 32-byte `id`, lowercase `service`, positive `priceUqor` where `1 test QOR = 1,000,000 uqor`, and `beneficiary`).

```sh
bin/knock --network network.json --cards cards door trust qor1... --alias private-status
bin/knock --network network.json --cards cards private-status --tunnel --pay 2m
bin/knock payment show "$pass_reference"
```

Knock displays the exact price before prompting (`--price-uqor` for non-interactive checks), verifies the `/status` response, and holds the tunnel until expiry or disconnect. Use `payment show` to reconcile interrupted purchases before paying again.

### 5. Encrypted audit history

Enable `"audit": true` in `door.json`, publish each auditor's recipient card, and back up the Door's state database alongside its `.audit.age` file. Rotate membership as the Door owner (pass `--clear` to pause receipts) and read locally decrypted receipts as an auditor:

```sh
bin/knock --profile owner.age --network network.json --cards cards audit rotate --door validator-ops --epoch 0 --member qor1...,qor1...
bin/knock --profile auditor.age --network network.json --cards cards --mailbox http://127.0.0.1:8180 history list --door validator-ops
bin/knock --profile auditor.age --network network.json --cards cards --mailbox http://127.0.0.1:8180 history show --door validator-ops "$receipt_id"
```

If Mailbox delivery expires, export a receipt from a stopped Door and inspect it locally:

```sh
sudo knockd --config /etc/knock/door.json audit-export "$receipt_id" --recipient "$auditor" > receipt.sealed
bin/knock --profile auditor.age --network network.json --cards cards history show --door validator-ops --from receipt.sealed "$receipt_id"
```

## Host setup

Run the Door on a dedicated Ubuntu 24.04 x86-64 host (2 GiB RAM, cgroup v2, WireGuard, nftables, time sync enabled, suspend disabled) with management SSH on a separate interface. Knock reserves the `knockdoor` interface, `knock_ssh` nftables table, `198.19.0.0/28`, and TCP ports `2222`–`2229` on `198.19.0.1`. Allow the `wireGuardEndpoint` UDP port on the external interface, keep `/etc/knock` (`0700`) and the Door profile (`0600`) root-owned, and keep the owner profile off the Door host.

For an Approval Door, install OpenSSH and create non-root session slot accounts (`knockssh`, `knockssh1`, …):

```sh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh1
sudo install -d -m 0755 /run/sshd
```

Install `knockd` and its systemd credential and drop-in:

```sh
sudo install -m 0755 bin/knockd /usr/local/bin/knockd
sudo install -d -m 0755 /etc/systemd/system/knockd.service.d
systemd-ask-password 'Door passphrase' |
  sudo systemd-creds encrypt --name=door-passphrase --with-key=host - /etc/knock/door.cred
sudo install -m 0644 deploy/systemd/knockd.service /etc/systemd/system/knockd.service
sudo install -m 0644 deploy/systemd/10-ssh.conf /etc/systemd/system/knockd.service.d/10-ssh.conf
sudo systemctl daemon-reload
sudo systemctl start knockd
```

On the requester Linux VM, install `bin/knock` at `/usr/local/bin/knock`, install WireGuard tools and OpenSSH, and install [the tunnel sudoers rule](deploy/knock-tunnel.sudoers) with `sudo visudo -f /etc/sudoers.d/knock-tunnel`. To clean up orphaned sessions on a stopped Door manually, run `sudo knockd reconcile --config /etc/knock/door.json`.

## Linux lab verification

With KVM, QEMU, xorriso, OpenSSH, and Python 3, download the pinned Ubuntu 24.04 amd64 cloud image dated `2026-10-17` ([Ubuntu cloud images](https://cloud-images.ubuntu.com/noble/20261017/)), verify its signed manifest, and run the lab probe:

```sh
deploy/lab/start.sh noble-server-cloudimg-amd64.img /tmp/knock-lab
deploy/lab/probe.sh /tmp/knock-lab
deploy/lab/stop.sh /tmp/knock-lab
```

`start.sh` boots isolated `door`, `requester`, `outsider`, and `requester2` guests; `probe.sh` verifies pre-admission isolation, SSH certificate principals, nftables expiry independent of `sshd`, and cgroup process cleanup.

## Security model and known limits

- **Recipient isolation:** Approvers read request intent without receiving WireGuard/SSH keys or connection endpoints; the Door enforces policy without seeing the approval reason; connection replies and PSKs seal solely to the requester's one-time ephemeral key.
- **Fail-closed enforcement:** Stale chain state, mismatched keys or policies, replay attempts, and incomplete teardown fail closed; active sessions expire locally via kernel nftables timeouts and systemd `RuntimeMaxSec`.
- **Metadata visibility:** The Mailbox sees routing accounts, message sizes, timing, and expiry; Diana reveals registered policies, metered purchases, and revocations; direct WireGuard packets reveal peer endpoints to network observers.
- **Known limits:** `qoreseal` `v0.1.0` is an unaudited draft package; chain verification relies on trusted Diana TLS RPC endpoints rather than a light client; `knockd` runs as root on the Door host; Go/tmpfs secret wiping is best-effort; removed auditors keep historical receipts and epoch keys already delivered to them.

## License and credits

Licensed under [Apache-2.0](LICENSE). Built with:

- [QoreChain](https://github.com/qorechain) (`qoreseal`, `qoresign`, `qorechain-pqc`)
- [go-ethereum](https://github.com/ethereum/go-ethereum), [Foundry](https://getfoundry.sh/), [age](https://filippo.io/age), [bbolt](https://go.etcd.io/bbolt), [fxamacker/cbor](https://github.com/fxamacker/cbor), and [Cobra](https://github.com/spf13/cobra)
- Linux WireGuard, OpenSSH, nftables, and systemd
- [React](https://react.dev/), [React Router](https://reactrouter.com/), [Tailwind CSS](https://tailwindcss.com/), [Vite](https://vitejs.dev/), [Phosphor Icons](https://phosphoricons.com/), [Playwright](https://playwright.dev/), and [axe-core](https://github.com/dequelabs/axe-core) (third-party licenses are served by the console at `/assets/licenses.txt`)
