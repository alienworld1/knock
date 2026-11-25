# Knock

Knock registers private service identities on QoreChain Diana. An operator publishes a signed Approval Door Card. A requester verifies the Card and current policy, then saves a trusted alias. This checkpoint keeps the service closed.

## Build

Use Go 1.26.6, Foundry, Make, and Python 3. The registry uses Solidity 0.8.28. The checks ran with Foundry commit `be350a64be9178a71a6ff029a72dc4455dcffcb1`.

```sh
make build
make check
```

## Register and inspect a Door

1. Create separate owner, Door, and approver profiles with `bin/knock --profile /path/to/identity.age identity init`. Keep each encrypted profile in a directory with permissions `0700`.
2. Fund the printed addresses with test QOR, then run `bin/knock --profile /path/to/identity.age identity register` for each actor. Registration writes a public recipient card to stdout. [Diana faucet](https://dashboard.qorechain.io/faucet)
3. Run `forge build --root contracts` and deploy with `go run ./contracts/cmd/deploy --profile /path/to/owner.age > network.json`. Keep the resulting registry address and code hash with your trusted configuration.
4. Copy [the example](deploy/door.example.json) to `door.json`. Set the pinned registry, the actor addresses and profiles, and a unique 32-byte Door ID. Generate a Door ID with `openssl rand -hex 32` and prefix it with `0x`. If you configure multiple approvers, sort them by their EVM address bytes.
5. Run `bin/knockd register --config door.json` to commit policy version 1 and publish the signed Card. Run the same command with the next policy version to update it. Run it with the same policy to refresh a Card before its 24-hour expiry.

Give the requester the public Card and registry pin, and confirm the Door account over a trusted channel.

```sh
bin/knock --network network.json --cards cards door trust qor1... --alias validator-ops
bin/knock --network network.json --cards cards door show validator-ops
```

An owner or eligible approver can call `knock revoke --door validator-ops <session-id>` with the same registry and Card options. Use `door show --revocation <session-id>` to read the finalized registry state. Session references are opaque 32-byte hex values prefixed with `0x`.

## Run a closed Door

Install `knockd` at `/usr/local/bin/knockd` and create the unprivileged `knock` user and group. Place `door.json`, the signed Card, and the Door's age profile under `/etc/knock` with paths matching the configuration. The profile must be readable only by `knock` with permissions `0600`. Keep the owner's profile on the operator machine.

```sh
systemd-ask-password 'Door passphrase' |
  sudo systemd-creds encrypt --name=door-passphrase --with-key=host - /etc/knock/door.cred
sudo install -m 0644 deploy/systemd/knockd.service /etc/systemd/system/knockd.service
sudo systemctl daemon-reload
sudo systemctl start knockd
```

The host credential key and the encrypted credential require storage protection against full disk access. Registry and key verification use trusted Diana endpoints. QoreSeal is a draft pending external review. [QoreSeal documentation](https://docs.qorechain.io/developer-tools/qoreseal/)

## Check the Linux lab

Use a host with KVM, QEMU, xorriso, OpenSSH, and Python 3. Download the Ubuntu 24.04 amd64 image dated 2026-10-17. Verify the signed Ubuntu manifest. The lab script checks the pinned image checksum and opens management SSH ports on loopback. [Ubuntu cloud images](https://cloud-images.ubuntu.com/noble/20261017/)

```sh
deploy/lab/start.sh noble-server-cloudimg-amd64.img /tmp/knock-lab
deploy/lab/probe.sh /tmp/knock-lab
deploy/lab/stop.sh /tmp/knock-lab
```

The probe uses separate Door, requester, and outsider guests to check the closed service, WireGuard, SSH certificate restrictions, timed nftables membership, and systemd cgroup cleanup. Use a new lab directory for a clean run.

Verified on Diana with registry `0x1c334C21920CD88fB9E372Acd78a1772D2A32a78`. [Deployment](https://explore.qore.network/tx/0x0719fc5668e0c2772d800a322df5ec96a51dc323627c6ccbd8a48f89207b53cb), [Door registration](https://explore.qore.network/tx/0x2766c0a4e8111703bb8f8927b8fd51fac87ca8e55099a22caa1b751ca8dbf97d), [policy update](https://explore.qore.network/tx/0xdfa0f058aaa11a72cead637c982b84600d8a940b593b2494ffa8aba8f5e96a85), [revocation](https://explore.qore.network/tx/0x3d44b99f2e731a7f54192d92c375e54fd195ac70fd7c1735ae2a18cb061b7eea).

Apache-2.0.
